# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""SubprocessSandbox — runs tool calls in an isolated subprocess.

Implementation notes
--------------------
* Uses ``multiprocessing.Process`` + ``multiprocessing.Pipe`` for clean
  bidirectional communication between parent and child.
* The child applies POSIX resource limits (memory via RLIMIT_AS/RLIMIT_RSS,
  CPU time via RLIMIT_CPU) before executing the function.
* On timeout the child is sent SIGTERM then SIGKILL.
* Exceptions raised inside the child are pickled and re-raised in the parent.
* Async callables are handled by running ``asyncio.run(func(*args, **kwargs))``
  inside the subprocess worker.
* Non-picklable functions raise a clear ``TypeError`` at call time.

"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import multiprocessing
import os
import platform
import signal
import sys
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import Callable
    from multiprocessing.connection import Connection

from enforcecore.sandbox.config import SandboxConfig, SandboxStrategy
from enforcecore.sandbox.errors import (
    SandboxMemoryError,
    SandboxTimeoutError,
    SandboxViolationError,
)

logger = structlog.get_logger("enforcecore.sandbox")

_IS_WINDOWS = platform.system() == "Windows"
_IS_POSIX = not _IS_WINDOWS

try:
    import resource as _resource

    _HAS_RESOURCE = True
except ImportError:  # pragma: no cover — Windows
    _resource = None  # type: ignore[assignment]
    _HAS_RESOURCE = False


# ---------------------------------------------------------------------------
# Subprocess worker (runs in the child process)
# ---------------------------------------------------------------------------


def _apply_resource_limits(config: SandboxConfig) -> None:
    """Apply POSIX resource limits in the subprocess.

    Called at the start of every sandbox worker before the tool runs.
    No-op on Windows or when the ``resource`` module is unavailable.
    """
    if not _HAS_RESOURCE or _resource is None:
        return  # pragma: no cover — Windows

    plat = platform.system()

    # Memory limit
    if config.max_memory_mb is not None:
        max_bytes = config.max_memory_mb * 1024 * 1024
        try:
            if plat == "Linux":
                _soft, hard = _resource.getrlimit(_resource.RLIMIT_AS)
                new_soft = min(max_bytes, hard) if hard != _resource.RLIM_INFINITY else max_bytes
                _resource.setrlimit(_resource.RLIMIT_AS, (new_soft, hard))
            elif plat == "Darwin":
                _soft, hard = _resource.getrlimit(_resource.RLIMIT_RSS)
                new_soft = min(max_bytes, hard) if hard != _resource.RLIM_INFINITY else max_bytes
                _resource.setrlimit(_resource.RLIMIT_RSS, (new_soft, hard))
        except (OSError, ValueError):
            pass  # Best-effort — don't crash the worker

    # CPU time limit (POSIX only, converts wall-clock to CPU seconds as a proxy)
    if config.max_cpu_seconds is not None:
        cpu_seconds = int(config.max_cpu_seconds) + 1  # +1 for rounding
        try:
            _soft, hard = _resource.getrlimit(_resource.RLIMIT_CPU)
            new_soft = min(cpu_seconds, hard) if hard != _resource.RLIM_INFINITY else cpu_seconds
            _resource.setrlimit(_resource.RLIMIT_CPU, (new_soft, hard))
        except (OSError, ValueError):
            pass  # Best-effort


def _restrict_environment(allowed_vars: list[str]) -> None:
    """Restrict os.environ to only the allowed variable names."""
    allowed_set = set(allowed_vars)
    keys_to_remove = [k for k in os.environ if k not in allowed_set]
    for key in keys_to_remove:
        del os.environ[key]


def _sandbox_worker(
    conn: Connection,
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    config: SandboxConfig,
) -> None:
    """Worker function executed in the sandboxed subprocess.

    Applies resource limits, restricts the environment, optionally changes
    the working directory, then executes *func*.  Sends the result (or
    exception) back via *conn* and closes it.
    """
    try:
        # Apply POSIX resource limits first — before any user code runs
        _apply_resource_limits(config)

        # Restrict environment variables
        _restrict_environment(config.allowed_env_vars)

        # Set working directory
        if config.working_directory is not None:
            try:
                os.chdir(config.working_directory)
            except OSError as exc:
                conn.send(
                    {
                        "status": "error",
                        "exception": SandboxViolationError(
                            f"Cannot set working directory '{config.working_directory}': {exc}"
                        ),
                    }
                )
                conn.close()
                return

        # Execute — handle both sync and async callables
        if inspect.iscoroutinefunction(func):
            result = asyncio.run(func(*args, **kwargs))
        else:
            result = func(*args, **kwargs)

        conn.send({"status": "ok", "result": result})

    except MemoryError:
        # Convert MemoryError (from RLIMIT_AS) to SandboxMemoryError
        conn.send(
            {
                "status": "error",
                "exception": SandboxMemoryError(
                    config.max_memory_mb or 0,
                ),
            }
        )
    except Exception as exc:
        conn.send({"status": "error", "exception": exc})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# SubprocessSandbox
# ---------------------------------------------------------------------------


class SubprocessSandbox:
    """Executes callables in an isolated subprocess with resource limits.

    Provides true process isolation: the tool runs in a fresh Python
    process with a restricted environment, optional memory and CPU time
    limits, and an optional working directory.

    The subprocess is killed on timeout (SIGTERM → SIGKILL) and the parent
    raises :exc:`SandboxTimeoutError`.  Exceptions from the subprocess are
    re-raised in the parent process.

    **Limitations:**
    - The tool function and all arguments must be picklable.
    - Resource limits (memory, CPU time) are POSIX-only (Linux/macOS).
      On Windows, process isolation still works but limits are not applied.
    - ``asyncio.run()`` is used for async tools in the subprocess — the
      subprocess gets its own event loop.

    Example::

        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=256,
            max_cpu_seconds=10.0,
        )
        sandbox = SubprocessSandbox(config)
        result = sandbox.run(my_tool, "arg", key="value")

    """

    def __init__(self, config: SandboxConfig) -> None:
        """Initialize the sandbox.

        Args:
            config: Sandbox configuration.  If ``config.strategy`` is
                ``NONE``, :meth:`run` executes the function in-process.
        """
        self.config = config

    # -- Sync interface -------------------------------------------------------

    def run(
        self,
        func: Callable[..., Any],
        *args: Any,
        tool_name: str = "",
        policy_name: str = "",
        **kwargs: Any,
    ) -> Any:
        """Execute *func* with sandbox isolation.

        If :attr:`config.strategy` is ``NONE``, runs in-process.
        If ``SUBPROCESS``, runs in an isolated subprocess.

        Args:
            func: The callable to execute.
            *args: Positional arguments passed to *func*.
            tool_name: Used in error messages.
            policy_name: Used in error messages.
            **kwargs: Keyword arguments passed to *func*.

        Returns:
            The return value of *func*.

        Raises:
            SandboxTimeoutError: If the subprocess exceeds the time limit.
            SandboxMemoryError: If the subprocess exceeds the memory limit.
            SandboxViolationError: For other sandbox failures.
            Any exception raised by *func* itself.

        """
        if self.config.strategy == SandboxStrategy.NONE:
            if inspect.iscoroutinefunction(func):
                return asyncio.run(func(*args, **kwargs))
            return func(*args, **kwargs)

        return self._run_subprocess(
            func, args, kwargs, tool_name=tool_name, policy_name=policy_name
        )

    # -- Async interface ------------------------------------------------------

    async def run_async(
        self,
        func: Callable[..., Any],
        *args: Any,
        tool_name: str = "",
        policy_name: str = "",
        **kwargs: Any,
    ) -> Any:
        """Execute *func* asynchronously with sandbox isolation.

        For ``SUBPROCESS`` strategy, runs the subprocess in a thread pool
        to avoid blocking the event loop.

        For ``NONE`` strategy, awaits the coroutine directly (or calls
        the sync function in a thread).

        """
        if self.config.strategy == SandboxStrategy.NONE:
            if inspect.iscoroutinefunction(func):
                return await func(*args, **kwargs)
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, func, *args)

        # Run the subprocess in a thread to avoid blocking the event loop
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None,
            self._run_subprocess,
            func,
            args,
            kwargs,
            tool_name,
            policy_name,
        )

    # -- Internal subprocess execution ----------------------------------------

    def _run_subprocess(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        tool_name: str = "",
        policy_name: str = "",
    ) -> Any:
        """Execute *func* in an isolated subprocess.

        Uses ``multiprocessing.Pipe`` for result/exception transport.
        Applies wall-clock timeout via ``Process.join(timeout)``.
        """
        # Verify picklability early — give a clear error before forking
        try:
            import pickle

            pickle.dumps(func)
            pickle.dumps(args)
            pickle.dumps(kwargs)
        except (pickle.PicklingError, TypeError, AttributeError) as exc:
            raise TypeError(
                f"SubprocessSandbox requires picklable function and arguments. "
                f"'{getattr(func, '__name__', func)}' cannot be pickled: {exc}"
            ) from exc

        result_conn, worker_conn = multiprocessing.Pipe(duplex=False)

        process = multiprocessing.Process(
            target=_sandbox_worker,
            args=(worker_conn, func, args, kwargs, self.config),
            daemon=True,
        )
        process.start()
        worker_conn.close()  # Parent doesn't write to this end

        timeout = self.config.max_cpu_seconds
        try:
            if result_conn.poll(timeout):
                outcome = result_conn.recv()
            else:
                # Timeout: kill the process
                _terminate_process(process)
                raise SandboxTimeoutError(
                    timeout or 0,
                    tool_name=tool_name,
                    policy_name=policy_name,
                )
        finally:
            result_conn.close()
            if process.is_alive():
                _terminate_process(process)
            process.join(timeout=5)

        logger.debug(
            "sandbox_subprocess_complete",
            tool=tool_name,
            status=outcome.get("status"),
            pid=process.pid,
            exitcode=process.exitcode,
        )

        if outcome["status"] == "ok":
            return outcome["result"]

        # Re-raise exception from subprocess
        subprocess_exc: BaseException | None = outcome.get("exception")
        if isinstance(subprocess_exc, SandboxMemoryError):
            raise SandboxMemoryError(
                subprocess_exc.limit_mb,
                tool_name=tool_name,
                policy_name=policy_name,
            )
        if isinstance(subprocess_exc, SandboxViolationError):
            raise SandboxViolationError(
                str(subprocess_exc),
                tool_name=tool_name,
                policy_name=policy_name,
            )
        if isinstance(subprocess_exc, BaseException):
            raise subprocess_exc

        raise SandboxViolationError(
            f"Subprocess returned unexpected outcome: {outcome}",
            tool_name=tool_name,
            policy_name=policy_name,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _terminate_process(process: multiprocessing.Process) -> None:
    """Terminate a subprocess gracefully, then forcibly if needed."""
    if not process.is_alive():
        return
    try:
        process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            if _IS_POSIX:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(process.pid, signal.SIGKILL)  # type: ignore[arg-type]
            else:  # pragma: no cover — Windows
                process.kill()
            process.join(timeout=2)
    except Exception:
        pass  # Best-effort — don't shadow the timeout error


def platform_info() -> dict[str, Any]:
    """Return platform support information for the subprocess sandbox.

    Returns:
        A dict describing which features are available on the current platform.

    """
    return {
        "platform": platform.system(),
        "subprocess_isolation": True,
        "resource_limits": _HAS_RESOURCE and _IS_POSIX,
        "memory_limits": _HAS_RESOURCE and _IS_POSIX,
        "cpu_time_limits": _HAS_RESOURCE and _IS_POSIX,
        "env_restriction": True,
        "wasm_sandbox": False,  # Reserved for v1.4+
        "python_version": sys.version,
    }

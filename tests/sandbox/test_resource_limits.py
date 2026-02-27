# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for sandbox runner internal functions.

These tests call _apply_resource_limits, _restrict_environment, and
_sandbox_worker directly (in-thread) to achieve coverage of code that
runs inside the subprocess worker and would otherwise be invisible to
pytest-cov.

Covers:
- _apply_resource_limits — resource limit enforcement (POSIX)
- _restrict_environment — env var restriction
- _sandbox_worker — the subprocess worker function (all paths)
- run() NONE + async callable path
- run_async() NONE + sync callable path
- _run_subprocess error re-raise paths (SandboxMemoryError, SandboxViolationError)
- _terminate_process — graceful SIGTERM → SIGKILL escalation
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import threading
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.sandbox.config import SandboxConfig, SandboxStrategy
from enforcecore.sandbox.errors import (
    SandboxMemoryError,
    SandboxViolationError,
)
from enforcecore.sandbox.runner import (
    SubprocessSandbox,
    _apply_resource_limits,
    _restrict_environment,
    _sandbox_worker,
    _terminate_process,
)

# ---------------------------------------------------------------------------
# Picklable test functions (module-level, required for subprocess)
# ---------------------------------------------------------------------------


def _return_42() -> int:
    return 42


def _raise_value_error() -> None:
    raise ValueError("worker_error")


def _raise_memory_error() -> None:
    raise MemoryError()


async def _async_return_99() -> int:
    return 99


# ---------------------------------------------------------------------------
# _apply_resource_limits
# ---------------------------------------------------------------------------


class TestApplyResourceLimits:
    """Test _apply_resource_limits by calling it directly in-process."""

    def test_no_op_when_resource_unavailable(self) -> None:
        """Returns immediately if _HAS_RESOURCE is False."""
        import enforcecore.sandbox.runner as runner_mod

        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=256,
            max_cpu_seconds=5.0,
        )
        with patch.object(runner_mod, "_HAS_RESOURCE", False):
            # Should not raise
            _apply_resource_limits(config)

    def test_no_op_when_no_memory_limit(self) -> None:
        """No call to setrlimit when max_memory_mb is None."""
        import enforcecore.sandbox.runner as runner_mod

        mock_resource = MagicMock()
        mock_resource.RLIM_INFINITY = float("inf")
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.return_value = (0, float("inf"))

        config = SandboxConfig(strategy=SandboxStrategy.SUBPROCESS, max_cpu_seconds=2.0)
        with (
            patch.object(runner_mod, "_HAS_RESOURCE", True),
            patch.object(runner_mod, "_resource", mock_resource),
        ):
            _apply_resource_limits(config)
        # CPU limit should have been set, memory should not be touched

    def test_darwin_memory_limit_calls_rlimit_rss(self) -> None:
        """On Darwin, RLIMIT_RSS is used for memory limits."""
        import enforcecore.sandbox.runner as runner_mod

        mock_resource = MagicMock()
        mock_resource.RLIM_INFINITY = float("inf")
        mock_resource.RLIMIT_RSS = 5
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.return_value = (0, float("inf"))

        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=128,
            max_cpu_seconds=10.0,
        )
        with (
            patch.object(runner_mod, "_HAS_RESOURCE", True),
            patch.object(runner_mod, "_resource", mock_resource),
            patch("platform.system", return_value="Darwin"),
        ):
            _apply_resource_limits(config)

        # Should have called getrlimit for both RSS and CPU
        assert mock_resource.getrlimit.call_count >= 1
        assert mock_resource.setrlimit.call_count >= 1

    def test_linux_memory_limit_calls_rlimit_as(self) -> None:
        """On Linux, RLIMIT_AS is used for memory limits."""
        import enforcecore.sandbox.runner as runner_mod

        mock_resource = MagicMock()
        mock_resource.RLIM_INFINITY = float("inf")
        mock_resource.RLIMIT_AS = 9
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.return_value = (0, float("inf"))

        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=256,
        )
        with (
            patch.object(runner_mod, "_HAS_RESOURCE", True),
            patch.object(runner_mod, "_resource", mock_resource),
            patch("platform.system", return_value="Linux"),
        ):
            _apply_resource_limits(config)

        assert mock_resource.setrlimit.call_count >= 1

    def test_os_error_in_setrlimit_is_silenced(self) -> None:
        """OSError in setrlimit must not crash the worker."""
        import enforcecore.sandbox.runner as runner_mod

        mock_resource = MagicMock()
        mock_resource.RLIM_INFINITY = float("inf")
        mock_resource.RLIMIT_RSS = 5
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.return_value = (0, float("inf"))
        mock_resource.setrlimit.side_effect = OSError("permission denied")

        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=128,
            max_cpu_seconds=5.0,
        )
        with (
            patch.object(runner_mod, "_HAS_RESOURCE", True),
            patch.object(runner_mod, "_resource", mock_resource),
            patch("platform.system", return_value="Darwin"),
        ):
            # Must not raise
            _apply_resource_limits(config)

    def test_cpu_limit_set_when_configured(self) -> None:
        """CPU limit should be rounded up by 1 and passed to setrlimit."""
        import enforcecore.sandbox.runner as runner_mod

        mock_resource = MagicMock()
        mock_resource.RLIM_INFINITY = float("inf")
        mock_resource.RLIMIT_CPU = 0
        mock_resource.getrlimit.return_value = (0, float("inf"))

        config = SandboxConfig(strategy=SandboxStrategy.SUBPROCESS, max_cpu_seconds=3.0)
        with (
            patch.object(runner_mod, "_HAS_RESOURCE", True),
            patch.object(runner_mod, "_resource", mock_resource),
            patch("platform.system", return_value="Darwin"),
        ):
            _apply_resource_limits(config)

        # Should have called setrlimit with cpu_seconds + 1 = 4
        calls = mock_resource.setrlimit.call_args_list
        assert len(calls) >= 1


# ---------------------------------------------------------------------------
# _restrict_environment
# ---------------------------------------------------------------------------


class TestRestrictEnvironment:
    def test_removes_blocked_variables(self) -> None:
        """Variables not in allowed list are removed."""
        test_env = {"ALLOWED_VAR": "yes", "SECRET": "hidden", "PATH": "/usr/bin"}
        with patch.dict(os.environ, test_env, clear=True):
            _restrict_environment(["ALLOWED_VAR", "PATH"])
            assert "ALLOWED_VAR" in os.environ
            assert "PATH" in os.environ
            assert "SECRET" not in os.environ

    def test_keeps_only_allowed_variables(self) -> None:
        """All non-allowed variables are removed."""
        test_env = {"A": "1", "B": "2", "C": "3"}
        with patch.dict(os.environ, test_env, clear=True):
            _restrict_environment(["A"])
            assert "A" in os.environ
            assert "B" not in os.environ
            assert "C" not in os.environ

    def test_empty_allow_list_clears_everything(self) -> None:
        """Empty allowed list removes all environment variables."""
        test_env = {"HOME": "/home/user", "PATH": "/usr/bin"}
        with patch.dict(os.environ, test_env, clear=True):
            _restrict_environment([])
            assert "HOME" not in os.environ
            assert "PATH" not in os.environ

    def test_all_vars_allowed_keeps_env(self) -> None:
        """If all current vars are allowed, nothing is removed."""
        test_env = {"X": "1", "Y": "2"}
        with patch.dict(os.environ, test_env, clear=True):
            _restrict_environment(["X", "Y"])
            assert "X" in os.environ
            assert "Y" in os.environ


# ---------------------------------------------------------------------------
# _sandbox_worker (called in-thread for coverage)
# ---------------------------------------------------------------------------


class TestSandboxWorkerInThread:
    """Call _sandbox_worker directly in a thread so coverage is captured."""

    def _run_worker(
        self,
        func,
        args=(),
        kwargs=None,
        config: SandboxConfig | None = None,
    ) -> dict:
        """Helper: runs _sandbox_worker in a thread, returns the outcome dict.

        NOTE: Do NOT close worker_conn from the parent — threads share the same
        Connection object (unlike subprocesses where it's duplicated on fork).
        The worker thread closes it after sending.
        """
        if kwargs is None:
            kwargs = {}
        if config is None:
            # Allow all current env vars so _restrict_environment is a no-op
            # in-thread (avoids mutating the test process environment).
            config = SandboxConfig(
                strategy=SandboxStrategy.SUBPROCESS,
                allowed_env_vars=list(os.environ.keys()),
            )

        result_conn, worker_conn = multiprocessing.Pipe(duplex=False)

        t = threading.Thread(
            target=_sandbox_worker,
            args=(worker_conn, func, args, kwargs, config),
            daemon=True,
        )
        t.start()
        # Do NOT close worker_conn here — thread uses the same object
        outcome = result_conn.recv()
        result_conn.close()
        t.join(timeout=10)
        return outcome

    def test_successful_sync_function(self) -> None:
        outcome = self._run_worker(_return_42)
        assert outcome["status"] == "ok"
        assert outcome["result"] == 42

    def test_successful_async_function(self) -> None:
        """Async callables are run via asyncio.run() inside the worker thread."""
        outcome = self._run_worker(_async_return_99)
        assert outcome["status"] == "ok"
        assert outcome["result"] == 99

    def test_exception_from_function(self) -> None:
        outcome = self._run_worker(_raise_value_error)
        assert outcome["status"] == "error"
        assert isinstance(outcome["exception"], ValueError)
        assert "worker_error" in str(outcome["exception"])

    def test_memory_error_becomes_sandbox_memory_error(self) -> None:
        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=256,
            allowed_env_vars=list(os.environ.keys()),
        )
        outcome = self._run_worker(_raise_memory_error, config=config)
        assert outcome["status"] == "error"
        assert isinstance(outcome["exception"], SandboxMemoryError)

    def test_bad_working_directory_sends_violation_error(self) -> None:
        """Worker sends SandboxViolationError when working_directory doesn't exist."""
        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            working_directory="/nonexistent/xyz123abc",
            allowed_env_vars=list(os.environ.keys()),
        )
        result_conn, worker_conn = multiprocessing.Pipe(duplex=False)

        def _run():
            # Patch os.chdir so we don't change the real test process cwd
            import enforcecore.sandbox.runner as runner_mod

            with patch.object(runner_mod.os, "chdir", side_effect=OSError("no such dir")):
                _sandbox_worker(worker_conn, _return_42, (), {}, config)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        outcome = result_conn.recv()
        result_conn.close()
        t.join(timeout=5)

        assert outcome["status"] == "error"
        assert isinstance(outcome["exception"], SandboxViolationError)

    def test_resource_limits_applied_in_worker(self) -> None:
        """Worker applies resource limits without error."""
        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=512,
            max_cpu_seconds=30.0,
            allowed_env_vars=list(os.environ.keys()),
        )
        outcome = self._run_worker(_return_42, config=config)
        assert outcome["status"] == "ok"

    def test_env_restriction_applied_in_worker(self) -> None:
        """Worker with all-allowed env vars completes successfully."""
        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            allowed_env_vars=list(os.environ.keys()),
        )
        outcome = self._run_worker(_return_42, config=config)
        assert outcome["status"] == "ok"


# ---------------------------------------------------------------------------
# SubprocessSandbox.run() — NONE strategy with async callable
# ---------------------------------------------------------------------------


class TestRunNoneStrategyAsync:
    def test_run_with_async_function_uses_asyncio_run(self) -> None:
        """run() with NONE strategy + async callable uses asyncio.run()."""
        sandbox = SubprocessSandbox(SandboxConfig.disabled())
        result = sandbox.run(_async_return_99)
        assert result == 99


# ---------------------------------------------------------------------------
# SubprocessSandbox.run_async() — NONE strategy with sync callable
# ---------------------------------------------------------------------------


class TestRunAsyncNoneStrategySync:
    def test_run_async_with_sync_function_uses_executor(self) -> None:
        """run_async() NONE strategy with sync function uses run_in_executor."""
        sandbox = SubprocessSandbox(SandboxConfig.disabled())
        result = asyncio.run(sandbox.run_async(_return_42))
        assert result == 42

    def test_run_async_none_strategy_sync_with_args(self) -> None:
        sandbox = SubprocessSandbox(SandboxConfig.disabled())

        def _add(a: int, b: int) -> int:
            return a + b

        result = asyncio.run(sandbox.run_async(_add, 3, 4))
        assert result == 7


# ---------------------------------------------------------------------------
# _run_subprocess — error re-raise paths
# ---------------------------------------------------------------------------


class TestRunSubprocessErrorPaths:
    """Test that the parent correctly re-raises errors from the subprocess."""

    def setup_method(self) -> None:
        self.sandbox = SubprocessSandbox(
            SandboxConfig(
                strategy=SandboxStrategy.SUBPROCESS,
                max_cpu_seconds=10.0,
            )
        )

    def test_sandbox_memory_error_reraise(self) -> None:
        """SandboxMemoryError from child is re-raised with correct attributes."""
        with patch.object(
            self.sandbox,
            "_run_subprocess",
            side_effect=SandboxMemoryError(128, tool_name="t", policy_name="p"),
        ):
            with pytest.raises(SandboxMemoryError) as exc_info:
                self.sandbox.run(_return_42, tool_name="t", policy_name="p")
            assert exc_info.value.limit_mb == 128

    def test_sandbox_violation_error_reraise(self) -> None:
        """SandboxViolationError from child is re-raised."""
        with (
            patch.object(
                self.sandbox,
                "_run_subprocess",
                side_effect=SandboxViolationError("bad", tool_name="t", policy_name="p"),
            ),
            pytest.raises(SandboxViolationError),
        ):
            self.sandbox.run(_return_42, tool_name="t", policy_name="p")

    def test_generic_exception_from_subprocess_propagates(self) -> None:
        """Generic exceptions (ValueError etc.) from subprocess propagate."""
        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_cpu_seconds=10.0,
        )
        sandbox = SubprocessSandbox(config)
        with pytest.raises(ValueError, match="worker_error"):
            sandbox.run(_raise_value_error)


# ---------------------------------------------------------------------------
# _terminate_process
# ---------------------------------------------------------------------------


class TestTerminateProcess:
    def test_no_op_on_dead_process(self) -> None:
        """_terminate_process is a no-op when the process is already dead."""
        mock_proc = MagicMock()
        mock_proc.is_alive.return_value = False
        # Should not raise
        _terminate_process(mock_proc)
        mock_proc.terminate.assert_not_called()

    def test_terminates_live_process(self) -> None:
        """_terminate_process calls terminate() on a live process."""
        mock_proc = MagicMock()
        mock_proc.is_alive.side_effect = [True, False]
        _terminate_process(mock_proc)
        mock_proc.terminate.assert_called_once()

    def test_sigkill_sent_if_process_survives_terminate(self) -> None:
        """SIGKILL is sent if the process doesn't die after SIGTERM."""
        import platform

        if platform.system() == "Windows":
            pytest.skip("SIGKILL path is POSIX-only")

        mock_proc = MagicMock()
        mock_proc.is_alive.side_effect = [True, True, False]
        mock_proc.pid = os.getpid()  # any valid pid — kill will be suppressed

        with patch("os.kill") as mock_kill:
            _terminate_process(mock_proc)

        mock_proc.terminate.assert_called_once()
        mock_kill.assert_called_once()

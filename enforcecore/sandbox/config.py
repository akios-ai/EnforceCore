# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Sandbox configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class SandboxStrategy(StrEnum):
    """Execution isolation strategy for sandboxed tool calls."""

    NONE = "none"
    """No subprocess isolation — run in-process (default).

    Equivalent to the pre-v1.3.0 behavior.  Use this when you don't need
    post-execution isolation or when the tool is not picklable.
    """

    SUBPROCESS = "subprocess"
    """Run tool in an isolated subprocess.

    The tool is serialized with pickle, executed in a fresh Python process
    with restricted environment variables and resource limits, and the
    result is returned via a pipe.

    **Requirements:**
    - The tool function and its arguments must be picklable.
    - Works on Linux and macOS.  On Windows, resource limits are not applied
      but isolation (separate process) still works.
    """


# Default allowed environment variables when running in subprocess mode.
# Conservative default: only PATH and PYTHONPATH for interpreter to work.
_DEFAULT_ALLOWED_ENV_VARS: list[str] = [
    "PATH",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
]


@dataclass
class SandboxConfig:
    """Configuration for subprocess sandbox execution.

    Controls how tool calls are isolated when
    :attr:`strategy` is ``SandboxStrategy.SUBPROCESS``.

    Example::

        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=256,
            max_cpu_seconds=30.0,
            allowed_env_vars=["PATH", "HOME"],
        )
        sandbox = SubprocessSandbox(config)
        result = sandbox.run(my_tool, "arg1")

    """

    strategy: SandboxStrategy = SandboxStrategy.NONE
    """Isolation strategy. Default is ``NONE`` (in-process, backward-compatible)."""

    max_memory_mb: int | None = None
    """Maximum memory the subprocess may use (megabytes).

    Enforced via ``RLIMIT_AS`` on Linux and ``RLIMIT_RSS`` on macOS.
    Not enforced on Windows.  ``None`` means unlimited.
    """

    max_cpu_seconds: float | None = None
    """Maximum wall-clock time the subprocess may run (seconds).

    The subprocess is killed with SIGTERM (then SIGKILL) when this limit
    is reached.  ``None`` means unlimited (still bounded by the caller's
    own ``max_call_duration_seconds`` resource limit).
    """

    allowed_env_vars: list[str] = field(default_factory=lambda: list(_DEFAULT_ALLOWED_ENV_VARS))
    """Environment variables passed to the subprocess.

    All other variables are stripped.  Defaults to a conservative set:
    ``PATH``, ``PYTHONPATH``, ``VIRTUAL_ENV``, ``HOME``, and temp dir vars.
    """

    working_directory: str | None = None
    """Working directory for the subprocess.

    ``None`` inherits the caller's cwd.  Set this to ``"/tmp/sandbox"`` or
    similar for stricter filesystem isolation.
    """

    @classmethod
    def disabled(cls) -> SandboxConfig:
        """Return a no-op config (strategy=NONE).

        This is the default — all enforcement stays in-process.
        """
        return cls(strategy=SandboxStrategy.NONE)

    @classmethod
    def subprocess_default(cls) -> SandboxConfig:
        """Return a subprocess config with safe defaults.

        - 512MB memory limit
        - 60 second wall-clock limit
        - Minimal environment (PATH, PYTHONPATH, HOME)
        - Inherits working directory
        """
        return cls(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=512,
            max_cpu_seconds=60.0,
        )

    @property
    def enabled(self) -> bool:
        """Whether sandbox isolation is active."""
        return self.strategy != SandboxStrategy.NONE

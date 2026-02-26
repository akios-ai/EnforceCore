# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for SubprocessSandbox execution.

Tests cover:
- NONE strategy (in-process, backward-compat)
- SUBPROCESS strategy (isolated process)
- Sync and async callables
- Exception propagation from subprocess
- Timeout enforcement
- Non-picklable function detection
- platform_info()
"""

import asyncio
import time

import pytest

from enforcecore.sandbox.config import SandboxConfig, SandboxStrategy
from enforcecore.sandbox.errors import SandboxTimeoutError
from enforcecore.sandbox.runner import SubprocessSandbox, platform_info

# ---------------------------------------------------------------------------
# Simple picklable functions for use in tests
# ---------------------------------------------------------------------------


def _add(a: int, b: int) -> int:
    return a + b


def _raises_value_error() -> None:
    raise ValueError("expected error from subprocess")


def _return_string(s: str) -> str:
    return f"hello {s}"


def _sleep_forever() -> str:
    time.sleep(9999)
    return "done"


def _compute_dict(x: int) -> dict[str, int]:
    return {"squared": x * x, "cubed": x * x * x}


async def _async_add(a: int, b: int) -> int:
    return a + b


async def _async_raises() -> None:
    raise RuntimeError("async error")


# ---------------------------------------------------------------------------
# NONE strategy (in-process)
# ---------------------------------------------------------------------------


class TestSubprocessSandboxNoneStrategy:
    """NONE strategy must be zero-overhead and fully backward-compatible."""

    def setup_method(self) -> None:
        self.sandbox = SubprocessSandbox(SandboxConfig.disabled())

    def test_run_sync(self) -> None:
        result = self.sandbox.run(_add, 2, 3)
        assert result == 5

    def test_run_async(self) -> None:
        result = asyncio.run(self.sandbox.run_async(_async_add, 10, 20))
        assert result == 30

    def test_run_sync_exception_propagates(self) -> None:
        with pytest.raises(ValueError, match="expected error"):
            self.sandbox.run(_raises_value_error)

    def test_run_async_exception_propagates(self) -> None:
        with pytest.raises(RuntimeError, match="async error"):
            asyncio.run(self.sandbox.run_async(_async_raises))

    def test_run_with_kwargs(self) -> None:
        result = self.sandbox.run(_return_string, s="world")
        assert result == "hello world"

    def test_none_strategy_runs_async_in_place(self) -> None:
        """NONE strategy should await coroutines directly."""

        async def _inner() -> str:
            return "direct"

        result = asyncio.run(self.sandbox.run_async(_inner))
        assert result == "direct"


# ---------------------------------------------------------------------------
# SUBPROCESS strategy
# ---------------------------------------------------------------------------


class TestSubprocessSandboxSubprocessStrategy:
    """Subprocess strategy tests — run in an isolated process."""

    def setup_method(self) -> None:
        self.sandbox = SubprocessSandbox(
            SandboxConfig(
                strategy=SandboxStrategy.SUBPROCESS,
                max_cpu_seconds=10.0,
            )
        )

    def test_basic_run(self) -> None:
        result = self.sandbox.run(_add, 5, 7)
        assert result == 12

    def test_run_with_string_result(self) -> None:
        result = self.sandbox.run(_return_string, "subprocess")
        assert result == "hello subprocess"

    def test_exception_propagates_from_subprocess(self) -> None:
        with pytest.raises(ValueError, match="expected error from subprocess"):
            self.sandbox.run(_raises_value_error)

    def test_async_callable_in_subprocess(self) -> None:
        """Async callables are run with asyncio.run() in the subprocess."""
        result = self.sandbox.run(_async_add, 3, 4)
        assert result == 7

    def test_run_async_interface(self) -> None:
        """run_async dispatches subprocess in a thread pool."""
        result = asyncio.run(self.sandbox.run_async(_add, 1, 2, tool_name="test_tool"))
        assert result == 3

    def test_tool_name_and_policy_name_passed(self) -> None:
        """tool_name and policy_name are accepted without error."""
        result = self.sandbox.run(_add, 10, 10, tool_name="my_tool", policy_name="strict")
        assert result == 20

    def test_non_picklable_raises_type_error(self) -> None:
        """Non-picklable functions must raise TypeError immediately, not hang."""

        class _Local:
            pass

        # Local lambda / locally-defined classes cannot be pickled on most platforms
        with pytest.raises(TypeError, match="picklable"):
            self.sandbox.run(lambda: "nope")

    def test_timeout_raises_sandbox_timeout_error(self) -> None:
        """When the subprocess exceeds the timeout, SandboxTimeoutError is raised."""
        fast_sandbox = SubprocessSandbox(
            SandboxConfig(
                strategy=SandboxStrategy.SUBPROCESS,
                max_cpu_seconds=0.5,  # very short
            )
        )
        with pytest.raises(SandboxTimeoutError) as exc_info:
            fast_sandbox.run(_sleep_forever, tool_name="sleeper")
        assert exc_info.value.limit_seconds == 0.5
        assert exc_info.value.tool_name == "sleeper"

    def test_subprocess_result_is_clean(self) -> None:
        """Result from subprocess is the same as calling the function directly."""
        result = self.sandbox.run(_compute_dict, 4)
        assert result == {"squared": 16, "cubed": 64}


# ---------------------------------------------------------------------------
# platform_info()
# ---------------------------------------------------------------------------


class TestPlatformInfo:
    def test_returns_dict(self) -> None:
        info = platform_info()
        assert isinstance(info, dict)

    def test_required_keys(self) -> None:
        info = platform_info()
        expected_keys = {
            "platform",
            "subprocess_isolation",
            "resource_limits",
            "memory_limits",
            "cpu_time_limits",
            "env_restriction",
            "wasm_sandbox",
            "python_version",
        }
        assert expected_keys.issubset(info.keys())

    def test_subprocess_isolation_always_true(self) -> None:
        info = platform_info()
        assert info["subprocess_isolation"] is True

    def test_wasm_sandbox_false(self) -> None:
        # WASM is reserved for v1.4+
        info = platform_info()
        assert info["wasm_sandbox"] is False

    def test_env_restriction_always_true(self) -> None:
        info = platform_info()
        assert info["env_restriction"] is True


# ---------------------------------------------------------------------------
# Public API imports
# ---------------------------------------------------------------------------


class TestPublicAPIImports:
    def test_imports_from_enforcecore(self) -> None:
        from enforcecore import (
            SandboxConfig,
            SandboxMemoryError,
            SandboxStrategy,
            SandboxTimeoutError,
            SandboxViolationError,
            SubprocessSandbox,
        )

        assert SandboxConfig is not None
        assert SandboxStrategy is not None
        assert SubprocessSandbox is not None
        assert SandboxViolationError is not None
        assert SandboxTimeoutError is not None
        assert SandboxMemoryError is not None

    def test_imports_from_submodule(self) -> None:
        from enforcecore.sandbox import (
            SandboxConfig,
            SandboxStrategy,
            SubprocessSandbox,
        )

        assert SandboxConfig is not None
        assert SandboxStrategy is not None
        assert SubprocessSandbox is not None

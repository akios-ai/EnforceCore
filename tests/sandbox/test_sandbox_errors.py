# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for sandbox error types."""

import pytest

from enforcecore.sandbox.errors import (
    SandboxMemoryError,
    SandboxTimeoutError,
    SandboxViolationError,
)


class TestSandboxViolationError:
    def test_basic(self) -> None:
        exc = SandboxViolationError("test error")
        assert "test error" in str(exc)
        assert exc.tool_name == ""
        assert exc.policy_name == ""

    def test_with_tool_info(self) -> None:
        exc = SandboxViolationError("error", tool_name="my_tool", policy_name="strict")
        assert exc.tool_name == "my_tool"
        assert exc.policy_name == "strict"

    def test_is_enforcecore_error(self) -> None:
        from enforcecore.core.types import EnforceCoreError

        exc = SandboxViolationError("test")
        assert isinstance(exc, EnforceCoreError)

    def test_is_exception(self) -> None:
        exc = SandboxViolationError("test")
        assert isinstance(exc, Exception)
        with pytest.raises(SandboxViolationError):
            raise exc


class TestSandboxTimeoutError:
    def test_basic(self) -> None:
        exc = SandboxTimeoutError(30.0)
        assert "30.0" in str(exc)
        assert exc.limit_seconds == 30.0

    def test_with_tool_info(self) -> None:
        exc = SandboxTimeoutError(10.0, tool_name="code_runner", policy_name="strict")
        assert exc.tool_name == "code_runner"
        assert exc.policy_name == "strict"
        assert exc.limit_seconds == 10.0
        assert "code_runner" in str(exc)

    def test_is_sandbox_violation(self) -> None:
        exc = SandboxTimeoutError(5.0)
        assert isinstance(exc, SandboxViolationError)


class TestSandboxMemoryError:
    def test_basic(self) -> None:
        exc = SandboxMemoryError(256)
        assert "256" in str(exc)
        assert exc.limit_mb == 256

    def test_with_tool_info(self) -> None:
        exc = SandboxMemoryError(512, tool_name="heavy_tool", policy_name="production")
        assert exc.tool_name == "heavy_tool"
        assert exc.policy_name == "production"
        assert exc.limit_mb == 512
        assert "heavy_tool" in str(exc)

    def test_is_sandbox_violation(self) -> None:
        exc = SandboxMemoryError(256)
        assert isinstance(exc, SandboxViolationError)

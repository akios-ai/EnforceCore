# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Sandbox error types."""

from __future__ import annotations

from enforcecore.core.types import EnforceCoreError


class SandboxViolationError(EnforceCoreError):
    """Base class for sandbox violations.

    Raised when a tool call violates a sandbox constraint — memory limit,
    CPU time limit, or subprocess failure.

    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a sandbox violation.

        Args:
            message: Human-readable description of the violation.
            tool_name: The tool that triggered the violation.
            policy_name: The policy under which the tool was running.
        """
        super().__init__(message)
        self.tool_name = tool_name
        self.policy_name = policy_name


class SandboxTimeoutError(SandboxViolationError):
    """Raised when a sandboxed tool call exceeds the configured CPU time limit."""

    def __init__(
        self,
        limit_seconds: float,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a sandbox timeout error.

        Args:
            limit_seconds: The CPU time limit that was exceeded.
            tool_name: The tool that timed out.
            policy_name: The policy under which the tool was running.
        """
        super().__init__(
            f"Sandbox timeout: tool '{tool_name}' exceeded {limit_seconds}s CPU time limit",
            tool_name=tool_name,
            policy_name=policy_name,
        )
        self.limit_seconds = limit_seconds


class SandboxMemoryError(SandboxViolationError):
    """Raised when a sandboxed tool call exceeds the configured memory limit."""

    def __init__(
        self,
        limit_mb: int,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a sandbox memory error.

        Args:
            limit_mb: The memory limit in megabytes that was exceeded.
            tool_name: The tool that exceeded the limit.
            policy_name: The policy under which the tool was running.
        """
        super().__init__(
            f"Sandbox memory limit: tool '{tool_name}' exceeded {limit_mb}MB",
            tool_name=tool_name,
            policy_name=policy_name,
        )
        self.limit_mb = limit_mb

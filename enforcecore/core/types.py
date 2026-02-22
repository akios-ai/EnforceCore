# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Shared types, exceptions, enums, and dataclasses for EnforceCore.

This module has ZERO external dependencies — only stdlib.
All other enforcecore modules depend on this one.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Decision(enum.StrEnum):
    """The outcome of a policy evaluation."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REDACTED = "redacted"


class ViolationType(enum.StrEnum):
    """Categories of policy violations."""

    TOOL_DENIED = "tool_denied"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    DOMAIN_DENIED = "domain_denied"
    CONTENT_VIOLATION = "content_violation"
    RATE_LIMIT = "rate_limit"
    COST_LIMIT = "cost_limit"
    RESOURCE_LIMIT = "resource_limit"
    OUTPUT_SIZE = "output_size"
    POLICY_ERROR = "policy_error"


class ViolationAction(enum.StrEnum):
    """What to do when a violation occurs."""

    BLOCK = "block"
    LOG = "log"
    REDACT = "redact"


class RedactionStrategy(enum.StrEnum):
    """How to redact detected PII."""

    MASK = "mask"
    HASH = "hash"
    REMOVE = "remove"
    PLACEHOLDER = "placeholder"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallContext:
    """Immutable context for a single enforced call.

    Created by the Enforcer before policy evaluation and passed through
    the entire enforcement pipeline.
    """

    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = ""
    args: tuple[Any, ...] = field(default_factory=tuple)
    kwargs: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class EnforcementResult:
    """Metadata from an enforced call.

    Returned alongside (or instead of) the tool call result so the caller
    can inspect what the enforcer did.
    """

    call_id: str
    tool_name: str
    policy_name: str
    decision: Decision
    violation_type: ViolationType | None = None
    violation_reason: str | None = None
    overhead_ms: float = 0.0
    call_duration_ms: float = 0.0
    redactions_input: int = 0
    redactions_output: int = 0
    audit_entry_id: str | None = None


@dataclass(frozen=True)
class RedactionEvent:
    """Record of a single PII entity that was redacted."""

    entity_type: str
    start: int
    end: int
    strategy: RedactionStrategy
    replacement: str


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class EnforceCoreError(Exception):
    """Base exception for all EnforceCore errors."""


class PolicyError(EnforceCoreError):
    """Errors related to policy loading, validation, or evaluation."""


class PolicyLoadError(PolicyError):
    """Policy file not found or not parseable."""


class PolicyValidationError(PolicyError):
    """Policy does not conform to the expected schema."""


class EnforcementViolation(EnforceCoreError):  # noqa: N818 — intentionally named Violation, not Error
    """A call was blocked due to a policy violation.

    This is raised when ``on_violation`` is ``block`` (the default).
    Contains enough context for the caller to understand *why*.
    """

    def __init__(
        self,
        message: str,
        *,
        tool_name: str = "",
        policy_name: str = "",
        violation_type: ViolationType = ViolationType.POLICY_ERROR,
        reason: str = "",
    ) -> None:
        """Initialize an enforcement violation.

        Args:
            message: Human-readable error message.
            tool_name: Name of the tool that was blocked.
            policy_name: Name of the policy that blocked the call.
            violation_type: Category of the violation.
            reason: Machine-readable reason string.
        """
        super().__init__(message)
        self.tool_name = tool_name
        self.policy_name = policy_name
        self.violation_type = violation_type
        self.reason = reason


class ToolDeniedError(EnforcementViolation):
    """Tool is explicitly denied or not in the allowed list."""

    def __init__(
        self,
        tool_name: str,
        *,
        policy_name: str = "",
        reason: str = "",
    ) -> None:
        """Initialize a tool-denied error.

        Args:
            tool_name: Name of the denied tool.
            policy_name: Name of the policy that denied the tool.
            reason: Why the tool was denied.
        """
        super().__init__(
            f"Tool '{tool_name}' is denied by policy '{policy_name}': {reason}",
            tool_name=tool_name,
            policy_name=policy_name,
            violation_type=ViolationType.TOOL_DENIED,
            reason=reason,
        )


class DomainDeniedError(EnforcementViolation):
    """Network domain is not allowed by policy."""

    def __init__(
        self,
        domain: str,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a domain-denied error.

        Args:
            domain: The denied domain name.
            tool_name: Name of the tool that attempted the request.
            policy_name: Name of the policy that blocked the domain.
        """
        super().__init__(
            f"Domain '{domain}' is denied by policy '{policy_name}'",
            tool_name=tool_name,
            policy_name=policy_name,
            violation_type=ViolationType.DOMAIN_DENIED,
            reason=f"domain '{domain}' not in allowed list",
        )


class ContentViolationError(EnforcementViolation):
    """Content rule violation detected in arguments or output."""

    def __init__(
        self,
        rule_name: str,
        description: str,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a content violation error.

        Args:
            rule_name: Name of the content rule that was violated.
            description: Human-readable description of the violation.
            tool_name: Name of the tool whose content was inspected.
            policy_name: Name of the policy that contains the rule.
        """
        super().__init__(
            f"Content rule '{rule_name}' violated: {description}",
            tool_name=tool_name,
            policy_name=policy_name,
            violation_type=ViolationType.CONTENT_VIOLATION,
            reason=f"content rule '{rule_name}': {description}",
        )


class CostLimitError(EnforcementViolation):
    """Cumulative cost exceeds the budget."""

    def __init__(
        self,
        current_cost: float,
        budget: float,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a cost limit error.

        Args:
            current_cost: The current cumulative cost in USD.
            budget: The configured budget in USD.
            tool_name: Name of the tool that triggered the limit.
            policy_name: Name of the policy with the budget.
        """
        super().__init__(
            f"Cost limit exceeded: ${current_cost:.2f} >= ${budget:.2f} budget",
            tool_name=tool_name,
            policy_name=policy_name,
            violation_type=ViolationType.COST_LIMIT,
            reason=f"cumulative cost ${current_cost:.2f} exceeds budget ${budget:.2f}",
        )


class ResourceLimitError(EnforcementViolation):
    """Resource limit (time, memory) exceeded."""

    def __init__(
        self,
        resource: str,
        limit: str,
        *,
        tool_name: str = "",
        policy_name: str = "",
    ) -> None:
        """Initialize a resource limit error.

        Args:
            resource: The resource that was exceeded (e.g., ``"time"``, ``"memory"``).
            limit: Human-readable description of the limit.
            tool_name: Name of the tool that exceeded the limit.
            policy_name: Name of the policy with the resource limits.
        """
        super().__init__(
            f"Resource limit exceeded: {resource} > {limit}",
            tool_name=tool_name,
            policy_name=policy_name,
            violation_type=ViolationType.RESOURCE_LIMIT,
            reason=f"{resource} exceeded limit {limit}",
        )


class RedactionError(EnforceCoreError):
    """Error during PII redaction. Fails closed — call is blocked."""


class AuditError(EnforceCoreError):
    """Error writing an audit entry. Fails closed — call is blocked."""


class GuardError(EnforceCoreError):
    """Error in the resource guard."""

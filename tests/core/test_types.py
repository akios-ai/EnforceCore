# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.core.types — enums, dataclasses, and exceptions."""

from __future__ import annotations

import pytest

from enforcecore.core.types import (
    CallContext,
    CostLimitError,
    Decision,
    DomainDeniedError,
    EnforceCoreError,
    EnforcementResult,
    EnforcementViolation,
    PolicyError,
    PolicyLoadError,
    PolicyValidationError,
    RedactionError,
    RedactionEvent,
    RedactionStrategy,
    ResourceLimitError,
    ToolDeniedError,
    ViolationAction,
    ViolationType,
)

# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------


class TestDecision:
    def test_values(self) -> None:
        assert Decision.ALLOWED == "allowed"
        assert Decision.BLOCKED == "blocked"
        assert Decision.REDACTED == "redacted"

    def test_string_comparison(self) -> None:
        assert Decision.ALLOWED == "allowed"
        assert Decision("blocked") == Decision.BLOCKED


class TestViolationType:
    def test_all_types_exist(self) -> None:
        expected = {
            "tool_denied",
            "tool_not_allowed",
            "domain_denied",
            "content_violation",
            "rate_limit",
            "cost_limit",
            "resource_limit",
            "output_size",
            "policy_error",
        }
        actual = {v.value for v in ViolationType}
        assert actual == expected


class TestViolationAction:
    def test_actions(self) -> None:
        assert ViolationAction.BLOCK == "block"
        assert ViolationAction.LOG == "log"
        assert ViolationAction.REDACT == "redact"


class TestRedactionStrategy:
    def test_strategies(self) -> None:
        assert RedactionStrategy.MASK == "mask"
        assert RedactionStrategy.HASH == "hash"
        assert RedactionStrategy.REMOVE == "remove"
        assert RedactionStrategy.PLACEHOLDER == "placeholder"


# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


class TestCallContext:
    def test_defaults(self) -> None:
        ctx = CallContext()
        assert ctx.tool_name == ""
        assert ctx.args == ()
        assert ctx.kwargs == {}
        assert ctx.call_id  # UUID should be non-empty
        assert ctx.timestamp is not None

    def test_custom_values(self) -> None:
        ctx = CallContext(tool_name="search", args=(1, 2), kwargs={"q": "test"})
        assert ctx.tool_name == "search"
        assert ctx.args == (1, 2)
        assert ctx.kwargs == {"q": "test"}

    def test_frozen(self) -> None:
        ctx = CallContext(tool_name="test")
        with pytest.raises(AttributeError):
            ctx.tool_name = "changed"  # type: ignore[misc]

    def test_unique_ids(self) -> None:
        c1 = CallContext()
        c2 = CallContext()
        assert c1.call_id != c2.call_id


class TestEnforcementResult:
    def test_creation(self) -> None:
        result = EnforcementResult(
            call_id="test-id",
            tool_name="search",
            policy_name="default",
            decision=Decision.ALLOWED,
        )
        assert result.decision == Decision.ALLOWED
        assert result.violation_type is None
        assert result.overhead_ms == 0.0

    def test_violation_result(self) -> None:
        result = EnforcementResult(
            call_id="test-id",
            tool_name="shell",
            policy_name="strict",
            decision=Decision.BLOCKED,
            violation_type=ViolationType.TOOL_DENIED,
            violation_reason="tool is in denied list",
        )
        assert result.decision == Decision.BLOCKED
        assert result.violation_type == ViolationType.TOOL_DENIED


class TestRedactionEvent:
    def test_creation(self) -> None:
        event = RedactionEvent(
            entity_type="EMAIL",
            start=10,
            end=30,
            strategy=RedactionStrategy.PLACEHOLDER,
            replacement="<EMAIL>",
        )
        assert event.entity_type == "EMAIL"
        assert event.start == 10
        assert event.end == 30

    def test_frozen(self) -> None:
        event = RedactionEvent(
            entity_type="EMAIL",
            start=0,
            end=10,
            strategy=RedactionStrategy.MASK,
            replacement="****",
        )
        with pytest.raises(AttributeError):
            event.entity_type = "PHONE"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Exception hierarchy tests
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_base_exception(self) -> None:
        assert issubclass(EnforceCoreError, Exception)

    def test_policy_errors(self) -> None:
        assert issubclass(PolicyError, EnforceCoreError)
        assert issubclass(PolicyLoadError, PolicyError)
        assert issubclass(PolicyValidationError, PolicyError)

    def test_violation_errors(self) -> None:
        assert issubclass(EnforcementViolation, EnforceCoreError)
        assert issubclass(ToolDeniedError, EnforcementViolation)
        assert issubclass(DomainDeniedError, EnforcementViolation)
        assert issubclass(CostLimitError, EnforcementViolation)
        assert issubclass(ResourceLimitError, EnforcementViolation)

    def test_other_errors(self) -> None:
        assert issubclass(RedactionError, EnforceCoreError)


class TestToolDeniedError:
    def test_message(self) -> None:
        err = ToolDeniedError("shell", policy_name="strict", reason="in denied list")
        assert "shell" in str(err)
        assert "strict" in str(err)
        assert err.tool_name == "shell"
        assert err.policy_name == "strict"
        assert err.violation_type == ViolationType.TOOL_DENIED

    def test_catchable_as_violation(self) -> None:
        with pytest.raises(EnforcementViolation):
            raise ToolDeniedError("shell", policy_name="strict", reason="denied")

    def test_catchable_as_base(self) -> None:
        with pytest.raises(EnforceCoreError):
            raise ToolDeniedError("shell", policy_name="strict", reason="denied")


class TestCostLimitError:
    def test_message(self) -> None:
        err = CostLimitError(15.50, 10.00, tool_name="gpt4", policy_name="budget")
        assert "$15.50" in str(err)
        assert "$10.00" in str(err)
        assert err.violation_type == ViolationType.COST_LIMIT


class TestDomainDeniedError:
    def test_message(self) -> None:
        err = DomainDeniedError("evil.com", tool_name="fetch", policy_name="strict")
        assert "evil.com" in str(err)
        assert err.violation_type == ViolationType.DOMAIN_DENIED


class TestResourceLimitError:
    def test_message(self) -> None:
        err = ResourceLimitError("memory 512MB", "256MB", tool_name="heavy")
        assert "512MB" in str(err)
        assert err.violation_type == ViolationType.RESOURCE_LIMIT

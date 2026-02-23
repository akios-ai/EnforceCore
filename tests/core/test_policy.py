# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.core.policy — Policy models and PolicyEngine."""

from __future__ import annotations

import warnings
from typing import TYPE_CHECKING

import pytest

from enforcecore.core.policy import (
    PIIRedactionConfig,
    Policy,
    PolicyEngine,
    PolicyRules,
    ResourceLimits,
    load_policy,
)
from enforcecore.core.types import (
    CallContext,
    Decision,
    PolicyLoadError,
    PolicyValidationError,
    RedactionStrategy,
    ToolDeniedError,
    ViolationAction,
    ViolationType,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Policy model tests
# ---------------------------------------------------------------------------


class TestPolicyFromFile:
    def test_load_allow_all(self, fixtures_dir: Path) -> None:
        policy = Policy.from_file(fixtures_dir / "allow_all.yaml")
        assert policy.name == "allow-all"
        assert policy.version == "1.0"
        assert policy.rules.allowed_tools is None
        assert policy.rules.denied_tools == []
        assert policy.on_violation == ViolationAction.BLOCK

    def test_load_deny_all(self, fixtures_dir: Path) -> None:
        policy = Policy.from_file(fixtures_dir / "deny_all.yaml")
        assert policy.name == "deny-all"
        assert policy.rules.allowed_tools == []

    def test_load_specific_tools(self, fixtures_dir: Path) -> None:
        policy = Policy.from_file(fixtures_dir / "specific_tools.yaml")
        assert policy.name == "specific-tools"
        assert "search_web" in (policy.rules.allowed_tools or [])
        assert "calculator" in (policy.rules.allowed_tools or [])
        assert "execute_shell" in policy.rules.denied_tools
        assert policy.rules.resource_limits.max_call_duration_seconds == 10
        assert policy.rules.resource_limits.max_cost_usd == 5.00

    def test_load_log_only(self, fixtures_dir: Path) -> None:
        policy = Policy.from_file(fixtures_dir / "log_only.yaml")
        assert policy.on_violation == ViolationAction.LOG

    def test_file_not_found(self) -> None:
        with pytest.raises(PolicyLoadError, match="not found"):
            Policy.from_file("/nonexistent/path/policy.yaml")

    def test_broken_yaml(self, fixtures_dir: Path) -> None:
        with pytest.raises(PolicyLoadError, match="Invalid YAML"):
            Policy.from_file(fixtures_dir / "broken_yaml.yaml")

    def test_invalid_policy_schema(self, fixtures_dir: Path) -> None:
        with pytest.raises((PolicyValidationError, PolicyLoadError)):
            Policy.from_file(fixtures_dir / "invalid_policy.yaml")

    def test_directory_not_file(self, fixtures_dir: Path) -> None:
        with pytest.raises(PolicyLoadError, match="not a file"):
            Policy.from_file(fixtures_dir)


class TestPolicyFromDict:
    def test_minimal(self) -> None:
        policy = Policy.from_dict({"name": "test", "rules": {}})
        assert policy.name == "test"
        assert policy.version == "1.0"
        assert policy.on_violation == ViolationAction.BLOCK

    def test_full(self) -> None:
        policy = Policy.from_dict(
            {
                "name": "full-test",
                "version": "2.0",
                "rules": {
                    "allowed_tools": ["a", "b"],
                    "denied_tools": ["c"],
                    "pii_redaction": {"enabled": True, "strategy": "mask"},
                    "resource_limits": {"max_cost_usd": 10.0},
                },
                "on_violation": "log",
            }
        )
        assert policy.name == "full-test"
        assert policy.version == "2.0"
        assert policy.rules.allowed_tools == ["a", "b"]
        assert policy.rules.denied_tools == ["c"]
        assert policy.rules.pii_redaction.enabled is True
        assert policy.rules.pii_redaction.strategy == RedactionStrategy.MASK
        assert policy.rules.resource_limits.max_cost_usd == 10.0
        assert policy.on_violation == ViolationAction.LOG

    def test_empty_name_rejected(self) -> None:
        with pytest.raises(PolicyValidationError):
            Policy.from_dict({"name": "", "rules": {}})

    def test_invalid_on_violation(self) -> None:
        with pytest.raises(PolicyValidationError):
            Policy.from_dict({"name": "test", "on_violation": "explode"})

    def test_missing_name(self) -> None:
        with pytest.raises(PolicyValidationError):
            Policy.from_dict({"rules": {}})

    def test_flat_rule_keys_hoisted_with_warning(self) -> None:
        """Flat rule keys (denied_tools, allowed_tools, etc.) are automatically
        hoisted into ``rules`` with a DeprecationWarning."""
        with pytest.warns(DeprecationWarning, match="hoisted"):
            p = Policy.from_dict(
                {"name": "hoist-test", "denied_tools": ["shell"], "allowed_tools": ["read"]}
            )
        assert p.rules.denied_tools == ["shell"]
        assert p.rules.allowed_tools == ["read"]

    def test_flat_rule_keys_do_not_overwrite_nested(self) -> None:
        """When both flat and nested keys exist, nested takes precedence."""
        with pytest.warns(DeprecationWarning, match="hoisted"):
            p = Policy.from_dict(
                {
                    "name": "precedence",
                    "denied_tools": ["flat_deny"],
                    "rules": {"denied_tools": ["nested_deny"]},
                }
            )
        # nested wins (setdefault keeps the existing value)
        assert p.rules.denied_tools == ["nested_deny"]

    def test_flat_dict_enforce_blocks_denied_tool(self) -> None:
        """Regression: flat denied_tools must actually block, not be silently dropped."""
        from enforcecore import ToolDeniedError, enforce

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            policy = Policy.from_dict({"name": "block-test", "denied_tools": ["bad"]})

        @enforce(policy=policy)
        def bad() -> str:
            return "should not reach"

        with pytest.raises(ToolDeniedError):
            bad()


class TestPolicyValidateFile:
    def test_valid_file(self, fixtures_dir: Path) -> None:
        errors = Policy.validate_file(fixtures_dir / "allow_all.yaml")
        assert errors == []

    def test_invalid_file(self, fixtures_dir: Path) -> None:
        errors = Policy.validate_file(fixtures_dir / "broken_yaml.yaml")
        assert len(errors) > 0

    def test_nonexistent_file(self) -> None:
        errors = Policy.validate_file("/nonexistent.yaml")
        assert len(errors) > 0


class TestLoadPolicyFunction:
    def test_convenience_function(self, fixtures_dir: Path) -> None:
        policy = load_policy(fixtures_dir / "allow_all.yaml")
        assert policy.name == "allow-all"


class TestPolicyModels:
    def test_pii_redaction_defaults(self) -> None:
        config = PIIRedactionConfig()
        assert config.enabled is False
        assert "email" in config.categories
        assert config.strategy == RedactionStrategy.PLACEHOLDER

    def test_resource_limits_defaults(self) -> None:
        limits = ResourceLimits()
        assert limits.max_call_duration_seconds is None
        assert limits.max_memory_mb is None
        assert limits.max_cost_usd is None

    def test_policy_rules_defaults(self) -> None:
        rules = PolicyRules()
        assert rules.allowed_tools is None  # None means all allowed
        assert rules.denied_tools == []
        assert rules.max_output_size_bytes is None
        assert rules.redact_output is True


# ---------------------------------------------------------------------------
# PolicyEngine tests
# ---------------------------------------------------------------------------


class TestPolicyEnginePreCall:
    def test_allow_all_allows_any_tool(self, allow_all_policy: Policy) -> None:
        engine = PolicyEngine(allow_all_policy)
        ctx = CallContext(tool_name="anything")
        result = engine.evaluate_pre_call(ctx)
        assert result.is_allowed
        assert result.decision == Decision.ALLOWED

    def test_deny_all_blocks_any_tool(self, deny_all_policy: Policy) -> None:
        engine = PolicyEngine(deny_all_policy)
        ctx = CallContext(tool_name="anything")
        result = engine.evaluate_pre_call(ctx)
        assert not result.is_allowed
        assert result.decision == Decision.BLOCKED
        assert result.violation_type == ViolationType.TOOL_NOT_ALLOWED

    def test_specific_tools_allows_listed(self, specific_tools_policy: Policy) -> None:
        engine = PolicyEngine(specific_tools_policy)
        ctx = CallContext(tool_name="search_web")
        result = engine.evaluate_pre_call(ctx)
        assert result.is_allowed

    def test_specific_tools_blocks_unlisted(self, specific_tools_policy: Policy) -> None:
        engine = PolicyEngine(specific_tools_policy)
        ctx = CallContext(tool_name="send_email")
        result = engine.evaluate_pre_call(ctx)
        assert not result.is_allowed
        assert result.violation_type == ViolationType.TOOL_NOT_ALLOWED

    def test_explicitly_denied_tool(self, specific_tools_policy: Policy) -> None:
        engine = PolicyEngine(specific_tools_policy)
        ctx = CallContext(tool_name="execute_shell")
        result = engine.evaluate_pre_call(ctx)
        assert not result.is_allowed
        assert result.violation_type == ViolationType.TOOL_DENIED

    def test_denied_takes_priority_over_allowed(self) -> None:
        """If a tool is in both allowed and denied, denied wins."""
        policy = Policy.from_dict(
            {
                "name": "conflict",
                "rules": {
                    "allowed_tools": ["search_web"],
                    "denied_tools": ["search_web"],  # Also denied!
                },
            }
        )
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name="search_web")
        result = engine.evaluate_pre_call(ctx)
        assert not result.is_allowed
        assert result.violation_type == ViolationType.TOOL_DENIED


class TestPolicyEnginePostCall:
    def test_no_output_limit(self, allow_all_policy: Policy) -> None:
        engine = PolicyEngine(allow_all_policy)
        ctx = CallContext(tool_name="test")
        result = engine.evaluate_post_call(ctx, "any output")
        assert result.is_allowed

    def test_output_under_limit(self, output_limit_policy: Policy) -> None:
        engine = PolicyEngine(output_limit_policy)
        ctx = CallContext(tool_name="test")
        result = engine.evaluate_post_call(ctx, "short")
        assert result.is_allowed

    def test_output_over_limit(self, output_limit_policy: Policy) -> None:
        engine = PolicyEngine(output_limit_policy)
        ctx = CallContext(tool_name="test")
        big_output = "x" * 200
        result = engine.evaluate_post_call(ctx, big_output)
        assert not result.is_allowed
        assert result.violation_type == ViolationType.OUTPUT_SIZE


class TestPolicyEngineRaiseIfBlocked:
    def test_allowed_does_not_raise(self, allow_all_policy: Policy) -> None:
        engine = PolicyEngine(allow_all_policy)
        ctx = CallContext(tool_name="test")
        pre = engine.evaluate_pre_call(ctx)
        engine.raise_if_blocked(pre, ctx)  # Should not raise

    def test_blocked_raises_tool_denied(self, deny_all_policy: Policy) -> None:
        engine = PolicyEngine(deny_all_policy)
        ctx = CallContext(tool_name="anything")
        pre = engine.evaluate_pre_call(ctx)
        with pytest.raises(ToolDeniedError) as exc_info:
            engine.raise_if_blocked(pre, ctx)
        assert exc_info.value.tool_name == "anything"

    def test_log_mode_does_not_raise(self, log_only_policy: Policy) -> None:
        engine = PolicyEngine(log_only_policy)
        ctx = CallContext(tool_name="forbidden_tool")
        pre = engine.evaluate_pre_call(ctx)
        # In log mode, violations are logged but not raised
        engine.raise_if_blocked(pre, ctx)  # Should not raise


class TestPolicyEngineFromFile:
    def test_from_file(self, fixtures_dir: Path) -> None:
        engine = PolicyEngine.from_file(fixtures_dir / "specific_tools.yaml")
        assert engine.policy.name == "specific-tools"

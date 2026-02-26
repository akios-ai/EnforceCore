# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for sensitivity label enforcement (v1.4.0)."""

from __future__ import annotations

import pytest

from enforcecore.core.policy import PIIRedactionConfig, PolicyRules, SensitivityLabelConfig
from enforcecore.core.sensitivity import (
    SensitivityEnforcer,
    SensitivityViolation,
    _coerce_label,
    check_tool_schema_sensitivity,
)
from enforcecore.core.types import (
    SensitivityLabel,
    SensitivityViolationError,
    ViolationType,
    sensitivity_level,
)

# ---------------------------------------------------------------------------
# SensitivityLabel enum
# ---------------------------------------------------------------------------


class TestSensitivityLabel:
    def test_all_values_present(self) -> None:
        values = {m.value for m in SensitivityLabel}
        assert values == {"public", "internal", "confidential", "restricted"}

    def test_string_equality(self) -> None:
        # StrEnum — should compare equal to plain strings
        assert SensitivityLabel.PUBLIC == "public"
        assert SensitivityLabel.RESTRICTED == "restricted"


class TestSensitivityLevel:
    def test_ordering(self) -> None:
        assert sensitivity_level(SensitivityLabel.PUBLIC) < sensitivity_level(
            SensitivityLabel.INTERNAL
        )
        assert sensitivity_level(SensitivityLabel.INTERNAL) < sensitivity_level(
            SensitivityLabel.CONFIDENTIAL
        )
        assert sensitivity_level(SensitivityLabel.CONFIDENTIAL) < sensitivity_level(
            SensitivityLabel.RESTRICTED
        )

    def test_public_is_zero(self) -> None:
        assert sensitivity_level(SensitivityLabel.PUBLIC) == 0

    def test_restricted_is_max(self) -> None:
        assert sensitivity_level(SensitivityLabel.RESTRICTED) == 3

    def test_accepts_string(self) -> None:
        assert sensitivity_level("public") == 0
        assert sensitivity_level("restricted") == 3

    def test_unknown_string_defaults_to_public(self) -> None:
        assert sensitivity_level("unknown_label") == 0


# ---------------------------------------------------------------------------
# _coerce_label helper
# ---------------------------------------------------------------------------


class TestCoerceLabel:
    def test_passthrough_label(self) -> None:
        label = SensitivityLabel.CONFIDENTIAL
        assert _coerce_label(label) is label

    def test_string_coercion(self) -> None:
        assert _coerce_label("internal") == SensitivityLabel.INTERNAL
        assert _coerce_label("RESTRICTED") == SensitivityLabel.RESTRICTED

    def test_invalid_string_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid sensitivity label"):
            _coerce_label("super_secret")


# ---------------------------------------------------------------------------
# SensitivityViolation
# ---------------------------------------------------------------------------


class TestSensitivityViolation:
    def test_str_representation(self) -> None:
        v = SensitivityViolation(
            field_name="api_key",
            field_sensitivity=SensitivityLabel.RESTRICTED,
            tool_clearance=SensitivityLabel.PUBLIC,
        )
        s = str(v)
        assert "api_key" in s
        assert "restricted" in s
        assert "public" in s

    def test_frozen(self) -> None:
        v = SensitivityViolation(
            field_name="f",
            field_sensitivity=SensitivityLabel.CONFIDENTIAL,
            tool_clearance=SensitivityLabel.INTERNAL,
        )
        with pytest.raises((AttributeError, TypeError)):
            v.field_name = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# SensitivityEnforcer.check()
# ---------------------------------------------------------------------------


class TestSensitivityEnforcerCheck:
    def test_no_violations_when_all_within_clearance(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.CONFIDENTIAL,
            {
                "field_a": SensitivityLabel.PUBLIC,
                "field_b": SensitivityLabel.INTERNAL,
                "field_c": SensitivityLabel.CONFIDENTIAL,  # equal = OK
            },
        )
        assert enforcer.check() == []

    def test_violation_when_field_exceeds_clearance(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.INTERNAL,
            {
                "api_key": SensitivityLabel.RESTRICTED,
            },
        )
        violations = enforcer.check()
        assert len(violations) == 1
        assert violations[0].field_name == "api_key"
        assert violations[0].field_sensitivity == SensitivityLabel.RESTRICTED
        assert violations[0].tool_clearance == SensitivityLabel.INTERNAL

    def test_multiple_violations(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {
                "name": SensitivityLabel.INTERNAL,
                "ssn": SensitivityLabel.RESTRICTED,
                "subject": SensitivityLabel.PUBLIC,  # OK
            },
        )
        violations = enforcer.check()
        assert len(violations) == 2
        field_names = {v.field_name for v in violations}
        assert field_names == {"name", "ssn"}

    def test_no_fields_no_violations(self) -> None:
        enforcer = SensitivityEnforcer(SensitivityLabel.PUBLIC)
        assert enforcer.check() == []

    def test_empty_fields_dict(self) -> None:
        enforcer = SensitivityEnforcer(SensitivityLabel.INTERNAL, {})
        assert enforcer.check() == []

    def test_string_clearance_accepted(self) -> None:
        enforcer = SensitivityEnforcer("internal", {"key": "restricted"})
        violations = enforcer.check()
        assert len(violations) == 1

    def test_restricted_clearance_allows_all(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.RESTRICTED,
            {
                "a": SensitivityLabel.PUBLIC,
                "b": SensitivityLabel.INTERNAL,
                "c": SensitivityLabel.CONFIDENTIAL,
                "d": SensitivityLabel.RESTRICTED,
            },
        )
        assert enforcer.check() == []


# ---------------------------------------------------------------------------
# SensitivityEnforcer.check_kwargs()
# ---------------------------------------------------------------------------


class TestSensitivityEnforcerCheckKwargs:
    def test_only_present_kwargs_checked(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {
                "to": SensitivityLabel.PUBLIC,
                "body": SensitivityLabel.CONFIDENTIAL,  # high sensitivity
            },
        )
        # Only "to" is in kwargs — "body" not included, no violation
        violations = enforcer.check_kwargs({"to": "recipient@example.com"})
        assert violations == []

    def test_violation_for_high_sensitivity_kwarg(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {"body": SensitivityLabel.CONFIDENTIAL},
        )
        violations = enforcer.check_kwargs({"body": "sensitive content here"})
        assert len(violations) == 1
        assert violations[0].field_name == "body"

    def test_unlabelled_fields_use_default_sensitivity(self) -> None:
        # Default sensitivity = PUBLIC (permissive)
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            default_field_sensitivity=SensitivityLabel.PUBLIC,
        )
        # No label for "unknown_field" — defaults to PUBLIC, within clearance
        violations = enforcer.check_kwargs({"unknown_field": "value"})
        assert violations == []

    def test_unlabelled_fields_with_high_default(self) -> None:
        # Default sensitivity = RESTRICTED (deny-by-default posture)
        enforcer = SensitivityEnforcer(
            SensitivityLabel.INTERNAL,
            default_field_sensitivity=SensitivityLabel.RESTRICTED,
        )
        violations = enforcer.check_kwargs({"any_field": "value"})
        assert len(violations) == 1

    def test_override_labels_take_priority(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {"field": SensitivityLabel.PUBLIC},  # base label = PUBLIC = OK
        )
        # Override label to RESTRICTED — should now trigger violation
        violations = enforcer.check_kwargs(
            {"field": "value"},
            override_labels={"field": SensitivityLabel.RESTRICTED},
        )
        assert len(violations) == 1


# ---------------------------------------------------------------------------
# SensitivityEnforcer.raise_if_violated()
# ---------------------------------------------------------------------------


class TestSensitivityEnforcerRaiseIfViolated:
    def test_no_raise_on_empty_violations(self) -> None:
        enforcer = SensitivityEnforcer(SensitivityLabel.PUBLIC)
        enforcer.raise_if_violated([])  # Should not raise

    def test_raises_sensitivity_violation_error(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {"key": SensitivityLabel.RESTRICTED},
        )
        violations = enforcer.check()
        with pytest.raises(SensitivityViolationError) as exc_info:
            enforcer.raise_if_violated(violations, tool_name="my_tool", policy_name="test_policy")

        err = exc_info.value
        assert err.tool_name == "my_tool"
        assert err.policy_name == "test_policy"
        assert err.field_name == "key"
        assert err.violation_type == ViolationType.SENSITIVITY_VIOLATION

    def test_error_message_describes_violation(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {"secret_key": SensitivityLabel.RESTRICTED},
        )
        violations = enforcer.check()
        with pytest.raises(SensitivityViolationError, match="secret_key"):
            enforcer.raise_if_violated(violations, tool_name="send_data")

    def test_multiple_violations_raises_for_first(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.PUBLIC,
            {
                "alpha": SensitivityLabel.RESTRICTED,
                "beta": SensitivityLabel.CONFIDENTIAL,
            },
        )
        violations = enforcer.check()
        assert len(violations) == 2
        with pytest.raises(SensitivityViolationError):
            enforcer.raise_if_violated(violations)


# ---------------------------------------------------------------------------
# SensitivityEnforcer properties
# ---------------------------------------------------------------------------


class TestSensitivityEnforcerProperties:
    def test_tool_clearance_property(self) -> None:
        enforcer = SensitivityEnforcer(SensitivityLabel.CONFIDENTIAL)
        assert enforcer.tool_clearance == SensitivityLabel.CONFIDENTIAL

    def test_field_labels_returns_copy(self) -> None:
        labels = {"f": SensitivityLabel.INTERNAL}
        enforcer = SensitivityEnforcer(SensitivityLabel.PUBLIC, labels)
        returned = enforcer.field_labels
        returned["injected"] = SensitivityLabel.RESTRICTED
        assert "injected" not in enforcer.field_labels  # copy, not reference

    def test_repr(self) -> None:
        enforcer = SensitivityEnforcer(
            SensitivityLabel.INTERNAL,
            {"a": SensitivityLabel.PUBLIC},
        )
        r = repr(enforcer)
        assert "SensitivityEnforcer" in r
        assert "internal" in r


# ---------------------------------------------------------------------------
# check_tool_schema_sensitivity
# ---------------------------------------------------------------------------


class TestCheckToolSchemaSensitivity:
    def test_no_violations_when_all_within_clearance(self) -> None:
        schema = {
            "name": "safe_tool",
            "clearance": "confidential",
            "parameters": {
                "param_a": {"type": "string", "sensitivity": "low"},
                "param_b": {"type": "string", "sensitivity": "medium"},
            },
        }
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.CONFIDENTIAL)
        assert violations == []

    def test_violation_when_field_exceeds_schema_clearance(self) -> None:
        schema = {
            "name": "send_email",
            "clearance": "public",  # tool sends externally
            "parameters": {
                "body": {"type": "string", "sensitivity": "high"},  # high > public
            },
        }
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.CONFIDENTIAL)
        assert len(violations) == 1
        assert violations[0].field_name == "body"
        assert violations[0].tool_clearance == SensitivityLabel.PUBLIC  # schema clearance wins

    def test_policy_clearance_wins_when_lower(self) -> None:
        """Policy clearance < schema clearance → policy wins (more restrictive)."""
        schema = {
            "name": "internal_tool",
            "clearance": "confidential",
            "parameters": {
                "data": {"type": "string", "sensitivity": "medium"},  # medium = internal
            },
        }
        # Policy says only PUBLIC allowed — stricter than schema
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.PUBLIC)
        assert len(violations) == 1

    def test_no_parameters_no_violations(self) -> None:
        schema = {"name": "noop_tool"}
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.PUBLIC)
        assert violations == []

    def test_parameters_without_sensitivity_not_checked(self) -> None:
        """Parameters without a 'sensitivity' key are not evaluated."""
        schema = {
            "name": "tool",
            "clearance": "public",
            "parameters": {
                "plain_param": {"type": "string"},  # no sensitivity key
            },
        }
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.PUBLIC)
        assert violations == []

    def test_alias_low_maps_to_public(self) -> None:
        schema = {
            "name": "tool",
            "clearance": "confidential",
            "parameters": {
                "field": {"sensitivity": "low"},  # alias for PUBLIC
            },
        }
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.CONFIDENTIAL)
        assert violations == []

    def test_alias_high_maps_to_confidential(self) -> None:
        schema = {
            "name": "tool",
            "clearance": "public",
            "parameters": {
                "field": {"sensitivity": "high"},  # alias for CONFIDENTIAL
            },
        }
        violations = check_tool_schema_sensitivity(schema, SensitivityLabel.PUBLIC)
        assert len(violations) == 1  # CONFIDENTIAL > PUBLIC


# ---------------------------------------------------------------------------
# SensitivityLabelConfig (policy model)
# ---------------------------------------------------------------------------


class TestSensitivityLabelConfig:
    def test_defaults(self) -> None:
        cfg = SensitivityLabelConfig()
        assert cfg.enabled is False
        assert cfg.default_clearance == SensitivityLabel.INTERNAL
        assert cfg.enforce is True
        assert cfg.fallback == "redact"

    def test_enabled_flag(self) -> None:
        cfg = SensitivityLabelConfig(enabled=True)
        assert cfg.enabled is True

    def test_custom_clearance(self) -> None:
        cfg = SensitivityLabelConfig(default_clearance=SensitivityLabel.CONFIDENTIAL)
        assert cfg.default_clearance == SensitivityLabel.CONFIDENTIAL

    def test_string_clearance_accepted(self) -> None:
        cfg = SensitivityLabelConfig(default_clearance="public")  # type: ignore[arg-type]
        assert cfg.default_clearance == SensitivityLabel.PUBLIC


# ---------------------------------------------------------------------------
# PIIRedactionConfig NER fields
# ---------------------------------------------------------------------------


class TestPIIRedactionConfigNER:
    def test_ner_threshold_default(self) -> None:

        cfg = PIIRedactionConfig()
        assert cfg.ner_threshold == 0.8
        assert cfg.ner_fallback_to_regex is True

    def test_ner_threshold_custom(self) -> None:
        from enforcecore.core.types import RedactionStrategy

        cfg = PIIRedactionConfig(
            enabled=True,
            strategy=RedactionStrategy.NER,
            ner_threshold=0.9,
            ner_fallback_to_regex=False,
        )
        assert cfg.ner_threshold == 0.9
        assert cfg.ner_fallback_to_regex is False


# ---------------------------------------------------------------------------
# PolicyRules sensitivity_labels field
# ---------------------------------------------------------------------------


class TestPolicyRulesSensitivityLabels:
    def test_default_sensitivity_labels(self) -> None:
        rules = PolicyRules()
        assert rules.sensitivity_labels.enabled is False

    def test_sensitivity_labels_configurable(self) -> None:
        rules = PolicyRules(
            sensitivity_labels=SensitivityLabelConfig(
                enabled=True,
                default_clearance=SensitivityLabel.CONFIDENTIAL,
            )
        )
        assert rules.sensitivity_labels.enabled is True
        assert rules.sensitivity_labels.default_clearance == SensitivityLabel.CONFIDENTIAL

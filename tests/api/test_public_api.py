# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""API surface compatibility tests.

Guarantees that every symbol in ``enforcecore.__all__`` exists, is importable,
and has the expected kind (class, function, enum, instance, or string).

Any failure here means the public API has changed — intentional changes must
be reflected in ``docs/migration.md`` and the CHANGELOG.

.. versionadded:: 1.0.16
"""

from __future__ import annotations

import enum
import inspect
from typing import ClassVar

import pytest

import enforcecore

# ---------------------------------------------------------------------------
# 1. __all__ completeness — every listed symbol is importable
# ---------------------------------------------------------------------------


class TestAllExportsExist:
    """Every symbol in __all__ must be importable from the top-level package."""

    @pytest.mark.parametrize("symbol", enforcecore.__all__)
    def test_symbol_importable(self, symbol: str) -> None:
        assert hasattr(enforcecore, symbol), f"{symbol} listed in __all__ but not importable"

    def test_all_is_sorted(self) -> None:
        """__all__ should be sorted for readability and merge-friendliness."""
        assert enforcecore.__all__ == sorted(enforcecore.__all__)

    def test_no_duplicates(self) -> None:
        assert len(enforcecore.__all__) == len(set(enforcecore.__all__))


# ---------------------------------------------------------------------------
# 2. Symbol classification — verify expected types
# ---------------------------------------------------------------------------

# Classes (non-exception, non-enum)
EXPECTED_CLASSES: set[str] = {
    "AuditBackend",
    "AuditEntry",
    "AuditRotator",
    "Auditor",
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSuite",
    "CallContext",
    "CallbackBackend",
    "ContentRule",
    "ContentRuleConfig",
    "ContentRulesPolicyConfig",
    "CostTracker",
    "CustomPattern",
    "DetectedEntity",
    "DetectedSecret",
    "DomainChecker",
    "EnforceCoreInstrumentor",
    "EnforceCoreMetrics",
    "EnforcementResult",
    "Enforcer",
    "HookContext",
    "HookRegistry",
    "JsonlBackend",
    "KillSwitch",
    "MultiBackend",
    "NetworkPolicy",
    "NullBackend",
    "PIIRedactionConfig",
    "PatternRegistry",
    "Policy",
    "PolicyEngine",
    "PolicyRules",
    "RateLimit",
    "RateLimitPolicyConfig",
    "RateLimiter",
    "RedactionEvent",
    "RedactionHookContext",
    "RedactionResult",
    "Redactor",
    "ResourceGuard",
    "ResourceLimits",
    "RuleEngine",
    "RuleViolation",
    "Scenario",
    "ScenarioResult",
    "ScenarioRunner",
    "SecretScanner",
    "Settings",
    "SuiteResult",
    "VerificationResult",
    "ViolationHookContext",
    "WebhookDispatcher",
    "WebhookEvent",
}

# Exception classes
EXPECTED_EXCEPTIONS: set[str] = {
    "AuditError",
    "ContentViolationError",
    "CostLimitError",
    "DomainDeniedError",
    "EnforceCoreError",
    "EnforcementDepthError",
    "EnforcementViolation",
    "GuardError",
    "HardeningError",
    "InputTooLargeError",
    "InvalidToolNameError",
    "PolicyError",
    "PolicyLoadError",
    "PolicyValidationError",
    "RateLimitError",
    "RedactionError",
    "ResourceLimitError",
    "ToolDeniedError",
}

# Enum / StrEnum classes
EXPECTED_ENUMS: set[str] = {
    "Decision",
    "RedactionStrategy",
    "ScenarioOutcome",
    "Severity",
    "ThreatCategory",
    "ViolationAction",
    "ViolationType",
}

# Functions (including decorators)
EXPECTED_FUNCTIONS: set[str] = {
    "check_input_size",
    "clear_policy_cache",
    "decode_encoded_pii",
    "deep_redact",
    "enforce",
    "enter_enforcement",
    "exit_enforcement",
    "generate_benchmark_report",
    "generate_report",
    "generate_suite_report",
    "get_all_scenarios",
    "get_builtin_rules",
    "get_enforcement_chain",
    "get_enforcement_depth",
    "get_scenarios_by_category",
    "is_dev_mode",
    "load_policy",
    "load_trail",
    "normalize_homoglyphs",
    "normalize_unicode",
    "on_post_call",
    "on_pre_call",
    "on_redaction",
    "on_violation",
    "prepare_for_detection",
    "require_package",
    "validate_tool_name",
    "verify_trail",
    "wrap_with_policy",
}

# Singleton instances
EXPECTED_INSTANCES: set[str] = {
    "settings",
}

# String constants
EXPECTED_STRINGS: set[str] = {
    "__version__",
}


class TestSymbolTypes:
    """Each exported symbol has the expected kind."""

    @pytest.mark.parametrize("name", sorted(EXPECTED_CLASSES))
    def test_is_class(self, name: str) -> None:
        obj = getattr(enforcecore, name)
        assert inspect.isclass(obj), f"{name} should be a class, got {type(obj)}"
        assert not issubclass(obj, BaseException), f"{name} should not be an exception"

    @pytest.mark.parametrize("name", sorted(EXPECTED_EXCEPTIONS))
    def test_is_exception(self, name: str) -> None:
        obj = getattr(enforcecore, name)
        assert inspect.isclass(obj), f"{name} should be a class"
        assert issubclass(obj, BaseException), f"{name} should be an exception subclass"

    @pytest.mark.parametrize("name", sorted(EXPECTED_ENUMS))
    def test_is_enum(self, name: str) -> None:
        obj = getattr(enforcecore, name)
        assert inspect.isclass(obj), f"{name} should be a class"
        assert issubclass(obj, enum.Enum), f"{name} should be an enum subclass"

    @pytest.mark.parametrize("name", sorted(EXPECTED_FUNCTIONS))
    def test_is_callable(self, name: str) -> None:
        obj = getattr(enforcecore, name)
        assert callable(obj), f"{name} should be callable"

    @pytest.mark.parametrize("name", sorted(EXPECTED_INSTANCES))
    def test_is_instance(self, name: str) -> None:
        obj = getattr(enforcecore, name)
        assert not inspect.isclass(obj), f"{name} should be an instance, not a class"
        assert not callable(obj) or hasattr(obj, "__dict__"), f"{name} should be an instance"

    @pytest.mark.parametrize("name", sorted(EXPECTED_STRINGS))
    def test_is_string(self, name: str) -> None:
        obj = getattr(enforcecore, name)
        assert isinstance(obj, str), f"{name} should be a string"

    def test_all_symbols_classified(self) -> None:
        """Every symbol in __all__ must appear in exactly one category."""
        all_classified = (
            EXPECTED_CLASSES
            | EXPECTED_EXCEPTIONS
            | EXPECTED_ENUMS
            | EXPECTED_FUNCTIONS
            | EXPECTED_INSTANCES
            | EXPECTED_STRINGS
        )
        all_symbols = set(enforcecore.__all__)
        missing = all_symbols - all_classified
        extra = all_classified - all_symbols
        assert not missing, f"Symbols in __all__ but not classified: {missing}"
        assert not extra, f"Symbols classified but not in __all__: {extra}"


# ---------------------------------------------------------------------------
# 3. Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    """Verify the exception inheritance tree is stable."""

    def test_base_exception(self) -> None:
        assert issubclass(enforcecore.EnforceCoreError, Exception)

    @pytest.mark.parametrize(
        "exc_name",
        [
            "PolicyError",
            "EnforcementViolation",
            "RedactionError",
            "AuditError",
            "GuardError",
            "HardeningError",
        ],
    )
    def test_direct_children(self, exc_name: str) -> None:
        exc_cls = getattr(enforcecore, exc_name)
        assert issubclass(exc_cls, enforcecore.EnforceCoreError)

    @pytest.mark.parametrize(
        ("child", "parent"),
        [
            ("PolicyLoadError", "PolicyError"),
            ("PolicyValidationError", "PolicyError"),
            ("ToolDeniedError", "EnforcementViolation"),
            ("DomainDeniedError", "EnforcementViolation"),
            ("ContentViolationError", "EnforcementViolation"),
            ("CostLimitError", "EnforcementViolation"),
            ("ResourceLimitError", "EnforcementViolation"),
            ("InvalidToolNameError", "HardeningError"),
            ("InputTooLargeError", "HardeningError"),
            ("EnforcementDepthError", "HardeningError"),
        ],
    )
    def test_child_parent(self, child: str, parent: str) -> None:
        child_cls = getattr(enforcecore, child)
        parent_cls = getattr(enforcecore, parent)
        assert issubclass(child_cls, parent_cls)


# ---------------------------------------------------------------------------
# 4. Enforcer public interface
# ---------------------------------------------------------------------------


class TestEnforcerInterface:
    """Verify the Enforcer class has the expected public methods."""

    EXPECTED_METHODS: ClassVar[set[str]] = {
        "enforce_sync",
        "enforce_async",
        "from_file",
    }

    EXPECTED_PROPERTIES: ClassVar[set[str]] = {
        "policy",
        "policy_name",
    }

    REMOVED_METHODS: ClassVar[set[str]] = {
        "guard_sync",
        "guard_async",
    }

    @pytest.mark.parametrize("method", sorted(EXPECTED_METHODS))
    def test_has_method(self, method: str) -> None:
        assert hasattr(enforcecore.Enforcer, method)

    @pytest.mark.parametrize("prop", sorted(EXPECTED_PROPERTIES))
    def test_has_property(self, prop: str) -> None:
        assert hasattr(enforcecore.Enforcer, prop)

    @pytest.mark.parametrize("method", sorted(REMOVED_METHODS))
    def test_removed_method(self, method: str) -> None:
        """Deprecated methods must NOT be present."""
        assert not hasattr(enforcecore.Enforcer, method), (
            f"Enforcer.{method} should have been removed in v1.0.16"
        )


# ---------------------------------------------------------------------------
# 5. Policy public interface
# ---------------------------------------------------------------------------


class TestPolicyInterface:
    """Verify the Policy class has the expected construction methods."""

    def test_from_file(self) -> None:
        assert hasattr(enforcecore.Policy, "from_file")

    def test_from_dict(self) -> None:
        assert hasattr(enforcecore.Policy, "from_dict")

    def test_merge(self) -> None:
        assert hasattr(enforcecore.Policy, "merge")

    def test_name_field(self) -> None:
        p = enforcecore.Policy(name="test")
        assert p.name == "test"


# ---------------------------------------------------------------------------
# 6. Enum member stability
# ---------------------------------------------------------------------------


class TestEnumMembers:
    """Verify enum values haven't changed."""

    def test_decision_members(self) -> None:
        assert {"allowed", "blocked"} <= {m.value for m in enforcecore.Decision}

    def test_redaction_strategy_members(self) -> None:
        expected = {"placeholder", "mask", "hash", "remove"}
        assert expected <= {m.value for m in enforcecore.RedactionStrategy}

    def test_violation_type_members(self) -> None:
        members = {m.value for m in enforcecore.ViolationType}
        assert "tool_denied" in members
        assert "domain_denied" in members

    def test_threat_category_members(self) -> None:
        members = {m.value for m in enforcecore.ThreatCategory}
        expected = {
            "tool_abuse",
            "data_exfiltration",
            "resource_exhaustion",
            "policy_evasion",
            "pii_leakage",
            "privilege_escalation",
            "prompt_injection",
            "ransomware",
            "supply_chain",
            "collusion",
        }
        assert expected <= members

    def test_violation_action_members(self) -> None:
        members = {m.value for m in enforcecore.ViolationAction}
        assert "block" in members
        assert "log" in members


# ---------------------------------------------------------------------------
# 7. Submodule re-export consistency
# ---------------------------------------------------------------------------


class TestSubmoduleReExports:
    """Symbols re-exported at root should also be available from submodules."""

    def test_auditor_submodule(self) -> None:
        from enforcecore.auditor import (
            AuditEntry,
            Auditor,
            VerificationResult,
            load_trail,
            verify_trail,
        )

        assert AuditEntry is enforcecore.AuditEntry
        assert Auditor is enforcecore.Auditor
        assert VerificationResult is enforcecore.VerificationResult
        assert load_trail is enforcecore.load_trail
        assert verify_trail is enforcecore.verify_trail

    def test_redactor_submodule(self) -> None:
        from enforcecore.redactor import DetectedEntity, RedactionResult, Redactor

        assert DetectedEntity is enforcecore.DetectedEntity
        assert RedactionResult is enforcecore.RedactionResult
        assert Redactor is enforcecore.Redactor

    def test_guard_submodule(self) -> None:
        from enforcecore.guard import CostTracker, KillSwitch, ResourceGuard

        assert CostTracker is enforcecore.CostTracker
        assert KillSwitch is enforcecore.KillSwitch
        assert ResourceGuard is enforcecore.ResourceGuard

    def test_plugins_submodule(self) -> None:
        from enforcecore.plugins import (
            HookContext,
            HookRegistry,
            on_pre_call,
        )

        assert HookContext is enforcecore.HookContext
        assert HookRegistry is enforcecore.HookRegistry
        assert on_pre_call is enforcecore.on_pre_call

    def test_core_submodule(self) -> None:
        from enforcecore.core import Enforcer, Policy, PolicyEngine, enforce, settings

        assert Enforcer is enforcecore.Enforcer
        assert Policy is enforcecore.Policy
        assert PolicyEngine is enforcecore.PolicyEngine
        assert enforce is enforcecore.enforce
        assert settings is enforcecore.settings

    def test_eval_submodule(self) -> None:
        from enforcecore.eval import BenchmarkRunner, ScenarioRunner

        assert BenchmarkRunner is enforcecore.BenchmarkRunner
        assert ScenarioRunner is enforcecore.ScenarioRunner

    def test_telemetry_submodule(self) -> None:
        from enforcecore.telemetry import EnforceCoreInstrumentor, EnforceCoreMetrics

        assert EnforceCoreInstrumentor is enforcecore.EnforceCoreInstrumentor
        assert EnforceCoreMetrics is enforcecore.EnforceCoreMetrics

    def test_integrations_submodule(self) -> None:
        from enforcecore.integrations import require_package, wrap_with_policy

        assert require_package is enforcecore.require_package
        assert wrap_with_policy is enforcecore.wrap_with_policy


# ---------------------------------------------------------------------------
# 8. py.typed marker (PEP 561)
# ---------------------------------------------------------------------------


class TestPEP561:
    """Package must be PEP 561 compliant."""

    def test_py_typed_exists(self) -> None:
        import importlib.resources as resources

        files = resources.files("enforcecore")
        py_typed = files / "py.typed"
        assert py_typed.is_file(), "enforcecore/py.typed marker is missing"


# ---------------------------------------------------------------------------
# 9. Version string format
# ---------------------------------------------------------------------------


class TestVersionString:
    """Version must follow PEP 440."""

    def test_version_is_string(self) -> None:
        assert isinstance(enforcecore.__version__, str)

    def test_version_format(self) -> None:
        import re

        pattern = r"^\d+\.\d+\.\d+(a\d+|b\d+|rc\d+)?$"
        assert re.match(pattern, enforcecore.__version__), (
            f"Version {enforcecore.__version__!r} does not match PEP 440 pattern"
        )


# ---------------------------------------------------------------------------
# 10. Function signatures — key functions must accept expected args
# ---------------------------------------------------------------------------


class TestFunctionSignatures:
    """Verify that key functions accept the expected parameters."""

    def test_enforce_decorator_params(self) -> None:
        sig = inspect.signature(enforcecore.enforce)
        params = set(sig.parameters)
        assert "policy" in params
        assert "tool_name" in params

    def test_verify_trail_params(self) -> None:
        sig = inspect.signature(enforcecore.verify_trail)
        params = list(sig.parameters)
        assert len(params) >= 1  # at least the path param

    def test_load_trail_params(self) -> None:
        sig = inspect.signature(enforcecore.load_trail)
        params = list(sig.parameters)
        assert len(params) >= 1

    def test_validate_tool_name_params(self) -> None:
        sig = inspect.signature(enforcecore.validate_tool_name)
        params = list(sig.parameters)
        assert "name" in params

    def test_check_input_size_params(self) -> None:
        sig = inspect.signature(enforcecore.check_input_size)
        params = set(sig.parameters)
        assert "args" in params or len(params) >= 1

    def test_load_policy_params(self) -> None:
        sig = inspect.signature(enforcecore.load_policy)
        params = list(sig.parameters)
        assert len(params) >= 1


# ---------------------------------------------------------------------------
# 11. Settings singleton
# ---------------------------------------------------------------------------


class TestSettingsSingleton:
    """Verify settings is a usable singleton."""

    def test_settings_is_settings_instance(self) -> None:
        assert isinstance(enforcecore.settings, enforcecore.Settings)

    def test_settings_has_audit_enabled(self) -> None:
        assert hasattr(enforcecore.settings, "audit_enabled")

    def test_settings_has_fail_open(self) -> None:
        assert hasattr(enforcecore.settings, "fail_open")


# ---------------------------------------------------------------------------
# 12. No accidental private leaks into __all__
# ---------------------------------------------------------------------------


class TestNoPrivateLeaks:
    """No underscore-prefixed symbols should appear in __all__
    (except __version__)."""

    def test_no_private_exports(self) -> None:
        private = [s for s in enforcecore.__all__ if s.startswith("_") and s != "__version__"]
        assert not private, f"Private symbols in __all__: {private}"


# ---------------------------------------------------------------------------
# 13. Integration adapter availability
# ---------------------------------------------------------------------------


class TestIntegrationAdapters:
    """Each adapter module is importable (without framework deps)."""

    def test_langgraph_adapter_importable(self) -> None:
        from enforcecore.integrations import langgraph  # noqa: F401

    def test_crewai_adapter_importable(self) -> None:
        from enforcecore.integrations import crewai  # noqa: F401

    def test_autogen_adapter_importable(self) -> None:
        from enforcecore.integrations import autogen  # noqa: F401

    def test_adapters_export_enforced_tool(self) -> None:
        from enforcecore.integrations import autogen, crewai, langgraph

        assert hasattr(langgraph, "enforced_tool")
        assert hasattr(crewai, "enforced_tool")
        assert hasattr(autogen, "enforced_tool")

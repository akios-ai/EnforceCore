# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""API surface compatibility tests.

Guarantees that every symbol in ``enforcecore.__all__`` exists, is importable,
and has the expected kind (class, function, enum, instance, or string).

As of v1.0.0b1, ``__all__`` contains 30 core symbols (Tier 1).
An additional ~80 symbols (Tier 2) remain importable from the top-level
package but emit a ``DeprecationWarning``.  They are the stable submodule API.

Any failure here means the public API has changed — intentional changes must
be reflected in ``docs/migration.md`` and the CHANGELOG.

.. versionadded:: 1.0.0
.. versionchanged:: 1.0.0a1  Pruned __all__ from 110 to 30.
.. versionchanged:: 1.0.0b1   Tier 2 symbols emit DeprecationWarning.
"""

from __future__ import annotations

import enum
import inspect
import warnings
from typing import ClassVar

import pytest

import enforcecore

# Suppress DeprecationWarnings from Tier 2 access throughout this module.
# The dedicated test_tier2_deprecation_warning test verifies warnings work.
pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

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

    def test_all_count(self) -> None:
        """__all__ should have exactly 58 symbols (Tier 1 public API).

        v1.3.0 added 6 sandbox symbols: SandboxConfig, SandboxMemoryError,
        SandboxStrategy, SandboxTimeoutError, SandboxViolationError, SubprocessSandbox.
        v1.4.0 added 9 NER + sensitivity symbols: NERBackend, SensitivityEnforcer,
        SensitivityLabel, SensitivityLabelConfig, SensitivityViolation,
        SensitivityViolationError, check_tool_schema_sensitivity,
        is_ner_available, sensitivity_level.
        v1.6.0 added 1 multi-tenant symbol: MultiTenantEnforcer.
        v1.7.0 added 2 policy server symbols: PolicyServerClient, PolicyServerError.
        v1.8.0 added 5 compliance symbols: ComplianceError, ComplianceFormat,
        CompliancePeriod, ComplianceReport, ComplianceReporter.
        v1.9.0 added 5 plugin ecosystem symbols: AuditBackendPlugin, GuardPlugin,
        PluginLoadError, PluginManager, RedactorPlugin.
        """
        assert len(enforcecore.__all__) == 58, (
            f"Expected 58 symbols in __all__, got {len(enforcecore.__all__)}"
        )


# ---------------------------------------------------------------------------
# 2. Symbol classification — verify expected types
#    Tier 1: in __all__ (stable public API)
#    Tier 2: importable from top-level, NOT in __all__
# ---------------------------------------------------------------------------

# ── Tier 1: Classes in __all__ ──
TIER1_CLASSES: set[str] = {
    "AuditBackendPlugin",
    "AuditEntry",
    "Auditor",
    "CompliancePeriod",
    "ComplianceReport",
    "ComplianceReporter",
    "CostTracker",
    "EnforcementResult",
    "Enforcer",
    "GuardPlugin",
    "KillSwitch",
    "MultiTenantEnforcer",
    "NERBackend",
    "PluginManager",
    "PolicyServerClient",
    "RateLimiter",
    "RedactionResult",
    "Redactor",
    "RedactorPlugin",
    "Policy",
    "ResourceGuard",
    "SandboxConfig",
    "SecretScanner",
    "SensitivityEnforcer",
    "SensitivityLabelConfig",
    "SensitivityViolation",
    "Settings",
    "SubprocessSandbox",
    "VerificationResult",
}

# ── Tier 1: Exceptions in __all__ ──
TIER1_EXCEPTIONS: set[str] = {
    "ComplianceError",
    "ContentViolationError",
    "CostLimitError",
    "EnforceCoreError",
    "EnforcementViolation",
    "PluginLoadError",
    "PolicyError",
    "PolicyLoadError",
    "PolicyServerError",
    "ResourceLimitError",
    "SandboxMemoryError",
    "SandboxTimeoutError",
    "SandboxViolationError",
    "SensitivityViolationError",
    "ToolDeniedError",
}

# ── Tier 1: Enums in __all__ ──
TIER1_ENUMS: set[str] = {
    "ComplianceFormat",
    "Decision",
    "RedactionStrategy",
    "SandboxStrategy",
    "SensitivityLabel",
}

# ── Tier 1: Functions in __all__ ──
TIER1_FUNCTIONS: set[str] = {
    "check_tool_schema_sensitivity",
    "enforce",
    "is_ner_available",
    "load_policy",
    "load_trail",
    "sensitivity_level",
    "verify_trail",
}

# ── Tier 1: Instances in __all__ ──
TIER1_INSTANCES: set[str] = {
    "settings",
}

# ── Tier 1: Strings in __all__ ──
TIER1_STRINGS: set[str] = {
    "__version__",
}

# ── Tier 2: importable but NOT in __all__ ──
TIER2_CLASSES: set[str] = {
    "AuditBackend",
    "AuditRotator",
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSuite",
    "CallContext",
    "CallbackBackend",
    "ContentRule",
    "ContentRuleConfig",
    "ContentRulesPolicyConfig",
    "CustomPattern",
    "DetectedEntity",
    "DetectedSecret",
    "DomainChecker",
    "EnforceCoreInstrumentor",
    "EnforceCoreMetrics",
    "HookContext",
    "HookRegistry",
    "JsonlBackend",
    "MultiBackend",
    "NetworkPolicy",
    "NullBackend",
    "PIIRedactionConfig",
    "PatternRegistry",
    "PolicyEngine",
    "PolicyRules",
    "RateLimit",
    "RateLimitPolicyConfig",
    "RedactionEvent",
    "RedactionHookContext",
    "ResourceLimits",
    "RuleEngine",
    "RuleViolation",
    "Scenario",
    "ScenarioResult",
    "ScenarioRunner",
    "SuiteResult",
    "ViolationHookContext",
    "WebhookDispatcher",
    "WebhookEvent",
}

TIER2_EXCEPTIONS: set[str] = {
    "AuditError",
    "DomainDeniedError",
    "EnforcementDepthError",
    "GuardError",
    "HardeningError",
    "InputTooLargeError",
    "InvalidToolNameError",
    "PolicyValidationError",
    "RateLimitError",
    "RedactionError",
}

TIER2_ENUMS: set[str] = {
    "ScenarioOutcome",
    "Severity",
    "ThreatCategory",
    "ViolationAction",
    "ViolationType",
}

TIER2_FUNCTIONS: set[str] = {
    "check_input_size",
    "clear_policy_cache",
    "decode_encoded_pii",
    "deep_redact",
    "enter_enforcement",
    "exit_enforcement",
    "generate_benchmark_report",
    "generate_html_report",
    "generate_report",
    "generate_suite_report",
    "get_all_scenarios",
    "get_builtin_rules",
    "get_enforcement_chain",
    "get_enforcement_depth",
    "get_scenarios_by_category",
    "is_dev_mode",
    "normalize_homoglyphs",
    "normalize_unicode",
    "on_post_call",
    "on_pre_call",
    "on_redaction",
    "on_violation",
    "prepare_for_detection",
    "require_package",
    "validate_tool_name",
    "wrap_with_policy",
}

# Combined sets for backwards-compat tests
EXPECTED_CLASSES = TIER1_CLASSES | TIER2_CLASSES
EXPECTED_EXCEPTIONS = TIER1_EXCEPTIONS | TIER2_EXCEPTIONS
EXPECTED_ENUMS = TIER1_ENUMS | TIER2_ENUMS
EXPECTED_FUNCTIONS = TIER1_FUNCTIONS | TIER2_FUNCTIONS
EXPECTED_INSTANCES = TIER1_INSTANCES
EXPECTED_STRINGS = TIER1_STRINGS


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

    def test_tier1_symbols_classified(self) -> None:
        """Every symbol in __all__ must appear in exactly one Tier 1 category."""
        tier1_all = (
            TIER1_CLASSES
            | TIER1_EXCEPTIONS
            | TIER1_ENUMS
            | TIER1_FUNCTIONS
            | TIER1_INSTANCES
            | TIER1_STRINGS
        )
        all_symbols = set(enforcecore.__all__)
        missing = all_symbols - tier1_all
        extra = tier1_all - all_symbols
        assert not missing, f"Symbols in __all__ but not classified in Tier 1: {missing}"
        assert not extra, f"Symbols classified as Tier 1 but not in __all__: {extra}"

    def test_tier2_symbols_importable(self) -> None:
        """Every Tier 2 symbol must be importable but NOT in __all__."""
        tier2_all = TIER2_CLASSES | TIER2_EXCEPTIONS | TIER2_ENUMS | TIER2_FUNCTIONS
        all_symbols = set(enforcecore.__all__)
        leaked = tier2_all & all_symbols
        assert not leaked, f"Tier 2 symbols leaked into __all__: {leaked}"
        for name in tier2_all:
            assert hasattr(enforcecore, name), (
                f"Tier 2 symbol {name} not importable from enforcecore"
            )

    def test_tier2_deprecation_warning(self) -> None:
        """Accessing a Tier 2 symbol must emit DeprecationWarning."""
        # Remove a Tier 2 symbol from cache so __getattr__ fires
        test_name = "NullBackend"
        enforcecore.__dict__.pop(test_name, None)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            obj = getattr(enforcecore, test_name)
        assert obj is not None
        dep_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
        assert len(dep_warnings) == 1
        assert test_name in str(dep_warnings[0].message)
        assert "enforcecore.auditor.backends" in str(dep_warnings[0].message)


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

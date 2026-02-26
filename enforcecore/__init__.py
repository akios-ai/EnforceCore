# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""
EnforceCore — The runtime enforcement layer for agentic AI systems.

Provides mandatory, policy-driven enforcement at every external call boundary
for any Python-based agentic system.

Basic usage::

    from enforcecore import enforce

    @enforce(policy="policies/my_policy.yaml")
    async def search_web(query: str) -> str:
        return await api.search(query)

See https://github.com/akios-ai/EnforceCore for documentation.

**API surface (v1.0.0+):** This package exports 58 core symbols (Tier 1).
Advanced types remain importable for backwards compatibility but emit a
``DeprecationWarning`` — migrate to submodule imports::

    # Core (top-level — stable)
    from enforcecore import enforce, Enforcer, Policy, Redactor, Auditor

    # Advanced (submodule — stable path)
    from enforcecore.auditor.backends import JsonlBackend, MultiBackend
    from enforcecore.plugins.hooks import on_pre_call, on_violation
    from enforcecore.eval import ScenarioRunner, get_all_scenarios
    from enforcecore.telemetry import EnforceCoreInstrumentor

DISCLAIMER: This software is provided "AS IS", without warranty of any kind.
It is a technical enforcement tool, not a compliance certification.
See DISCLAIMER.md and LICENSE for full terms.
"""

# ── Core public API (Tier 1 — stable, in __all__) ────────────────────────
# ── Tier 2 — importable but NOT in __all__ ───────────────────────────────
# These remain importable via `from enforcecore.X.Y import Z` and also via
# `from enforcecore import Z` for backwards compatibility during the alpha
# series.  They are excluded from __all__ to signal they are not part of the
# stable public API contract.
from enforcecore.auditor.backends import (
    AuditBackend as AuditBackend,
)
from enforcecore.auditor.backends import (
    CallbackBackend as CallbackBackend,
)
from enforcecore.auditor.backends import (
    JsonlBackend as JsonlBackend,
)
from enforcecore.auditor.backends import (
    MultiBackend as MultiBackend,
)
from enforcecore.auditor.backends import (
    NullBackend as NullBackend,
)
from enforcecore.auditor.engine import (
    AuditEntry,
    Auditor,
    VerificationResult,
    load_trail,
    verify_trail,
)
from enforcecore.auditor.rotation import AuditRotator as AuditRotator
from enforcecore.compliance.reporter import ComplianceReporter
from enforcecore.compliance.types import (
    ComplianceError,
    ComplianceFormat,
    CompliancePeriod,
    ComplianceReport,
)
from enforcecore.core.config import Settings, settings
from enforcecore.core.enforcer import Enforcer, enforce
from enforcecore.core.enforcer import (
    clear_policy_cache as clear_policy_cache,
)
from enforcecore.core.hardening import (
    EnforcementDepthError as EnforcementDepthError,
)
from enforcecore.core.hardening import (
    HardeningError as HardeningError,
)
from enforcecore.core.hardening import (
    InputTooLargeError as InputTooLargeError,
)
from enforcecore.core.hardening import (
    InvalidToolNameError as InvalidToolNameError,
)
from enforcecore.core.hardening import (
    check_input_size as check_input_size,
)
from enforcecore.core.hardening import (
    deep_redact as deep_redact,
)
from enforcecore.core.hardening import (
    enter_enforcement as enter_enforcement,
)
from enforcecore.core.hardening import (
    exit_enforcement as exit_enforcement,
)
from enforcecore.core.hardening import (
    get_enforcement_chain as get_enforcement_chain,
)
from enforcecore.core.hardening import (
    get_enforcement_depth as get_enforcement_depth,
)
from enforcecore.core.hardening import (
    is_dev_mode as is_dev_mode,
)
from enforcecore.core.hardening import (
    validate_tool_name as validate_tool_name,
)
from enforcecore.core.multitenant import MultiTenantEnforcer
from enforcecore.core.policy import (
    ContentRulesPolicyConfig as ContentRulesPolicyConfig,
)
from enforcecore.core.policy import (
    NetworkPolicy as NetworkPolicy,
)
from enforcecore.core.policy import (
    PIIRedactionConfig as PIIRedactionConfig,
)
from enforcecore.core.policy import Policy, load_policy
from enforcecore.core.policy import (
    PolicyEngine as PolicyEngine,
)
from enforcecore.core.policy import (
    PolicyRules as PolicyRules,
)
from enforcecore.core.policy import (
    RateLimitPolicyConfig as RateLimitPolicyConfig,
)
from enforcecore.core.policy import (
    ResourceLimits as ResourceLimits,
)
from enforcecore.core.policy import (
    SensitivityLabelConfig as SensitivityLabelConfig,
)
from enforcecore.core.policy_server import PolicyServerClient
from enforcecore.core.rules import (
    ContentRule as ContentRule,
)
from enforcecore.core.rules import (
    ContentRuleConfig as ContentRuleConfig,
)
from enforcecore.core.rules import (
    RuleEngine as RuleEngine,
)
from enforcecore.core.rules import (
    RuleViolation as RuleViolation,
)
from enforcecore.core.rules import (
    get_builtin_rules as get_builtin_rules,
)
from enforcecore.core.sensitivity import (
    SensitivityEnforcer as SensitivityEnforcer,
)
from enforcecore.core.sensitivity import (
    SensitivityViolation as SensitivityViolation,
)
from enforcecore.core.sensitivity import (
    check_tool_schema_sensitivity as check_tool_schema_sensitivity,
)
from enforcecore.core.types import (
    AuditError as AuditError,
)
from enforcecore.core.types import (
    CallContext as CallContext,
)
from enforcecore.core.types import (
    ContentViolationError,
    CostLimitError,
    Decision,
    EnforceCoreError,
    EnforcementResult,
    EnforcementViolation,
    PolicyError,
    PolicyLoadError,
    RedactionStrategy,
    ResourceLimitError,
    SensitivityLabel,
    SensitivityViolationError,
    ToolDeniedError,
)
from enforcecore.core.types import (
    DomainDeniedError as DomainDeniedError,
)
from enforcecore.core.types import (
    GuardError as GuardError,
)
from enforcecore.core.types import (
    PolicyServerError as PolicyServerError,
)
from enforcecore.core.types import (
    PolicyValidationError as PolicyValidationError,
)
from enforcecore.core.types import (
    RedactionError as RedactionError,
)
from enforcecore.core.types import (
    RedactionEvent as RedactionEvent,
)
from enforcecore.core.types import (
    ViolationAction as ViolationAction,
)
from enforcecore.core.types import (
    ViolationType as ViolationType,
)
from enforcecore.core.types import (
    sensitivity_level as sensitivity_level,
)
from enforcecore.eval import (
    BenchmarkRunner as BenchmarkRunner,
)
from enforcecore.eval import (
    ScenarioRunner as ScenarioRunner,
)
from enforcecore.eval import (
    generate_benchmark_report as generate_benchmark_report,
)
from enforcecore.eval import (
    generate_report as generate_report,
)
from enforcecore.eval import (
    generate_suite_report as generate_suite_report,
)
from enforcecore.eval import (
    get_all_scenarios as get_all_scenarios,
)
from enforcecore.eval import (
    get_scenarios_by_category as get_scenarios_by_category,
)
from enforcecore.eval.types import (
    BenchmarkResult as BenchmarkResult,
)
from enforcecore.eval.types import (
    BenchmarkSuite as BenchmarkSuite,
)
from enforcecore.eval.types import (
    Scenario as Scenario,
)
from enforcecore.eval.types import (
    ScenarioOutcome as ScenarioOutcome,
)
from enforcecore.eval.types import (
    ScenarioResult as ScenarioResult,
)
from enforcecore.eval.types import (
    Severity as Severity,
)
from enforcecore.eval.types import (
    SuiteResult as SuiteResult,
)
from enforcecore.eval.types import (
    ThreatCategory as ThreatCategory,
)
from enforcecore.guard.engine import CostTracker, KillSwitch, ResourceGuard
from enforcecore.guard.network import DomainChecker as DomainChecker
from enforcecore.guard.ratelimit import (
    RateLimit as RateLimit,
)
from enforcecore.guard.ratelimit import RateLimiter
from enforcecore.guard.ratelimit import (
    RateLimitError as RateLimitError,
)
from enforcecore.integrations._base import (
    require_package as require_package,
)
from enforcecore.integrations._base import (
    wrap_with_policy as wrap_with_policy,
)
from enforcecore.plugins.base import AuditBackendPlugin, GuardPlugin, RedactorPlugin
from enforcecore.plugins.hooks import (
    HookContext as HookContext,
)
from enforcecore.plugins.hooks import (
    HookRegistry as HookRegistry,
)
from enforcecore.plugins.hooks import (
    RedactionHookContext as RedactionHookContext,
)
from enforcecore.plugins.hooks import (
    ViolationHookContext as ViolationHookContext,
)
from enforcecore.plugins.hooks import (
    on_post_call as on_post_call,
)
from enforcecore.plugins.hooks import (
    on_pre_call as on_pre_call,
)
from enforcecore.plugins.hooks import (
    on_redaction as on_redaction,
)
from enforcecore.plugins.hooks import (
    on_violation as on_violation,
)
from enforcecore.plugins.manager import PluginLoadError, PluginManager
from enforcecore.plugins.webhooks import (
    WebhookDispatcher as WebhookDispatcher,
)
from enforcecore.plugins.webhooks import (
    WebhookEvent as WebhookEvent,
)
from enforcecore.redactor.engine import DetectedEntity as DetectedEntity
from enforcecore.redactor.engine import RedactionResult, Redactor
from enforcecore.redactor.ner import (
    NERBackend as NERBackend,
)
from enforcecore.redactor.ner import (
    is_ner_available as is_ner_available,
)
from enforcecore.redactor.patterns import (
    CustomPattern as CustomPattern,
)
from enforcecore.redactor.patterns import (
    PatternRegistry as PatternRegistry,
)
from enforcecore.redactor.secrets import DetectedSecret as DetectedSecret
from enforcecore.redactor.secrets import SecretScanner
from enforcecore.redactor.unicode import (
    decode_encoded_pii as decode_encoded_pii,
)
from enforcecore.redactor.unicode import (
    normalize_homoglyphs as normalize_homoglyphs,
)
from enforcecore.redactor.unicode import (
    normalize_unicode as normalize_unicode,
)
from enforcecore.redactor.unicode import (
    prepare_for_detection as prepare_for_detection,
)
from enforcecore.sandbox import (
    SandboxConfig,
    SandboxMemoryError,
    SandboxStrategy,
    SandboxTimeoutError,
    SandboxViolationError,
    SubprocessSandbox,
)
from enforcecore.telemetry import (
    AuditLogExporter as AuditLogExporter,
)
from enforcecore.telemetry import (
    EnforceCoreInstrumentor as EnforceCoreInstrumentor,
)
from enforcecore.telemetry import (
    EnforceCoreMetrics as EnforceCoreMetrics,
)
from enforcecore.telemetry import (
    EnforceCorePrometheusExporter as EnforceCorePrometheusExporter,
)

__version__ = "1.10.0"

# ── Logging configuration ────────────────────────────────────────────────
# Wire the ENFORCECORE_LOG_LEVEL setting to stdlib logging so structlog
# respects it.  Default is INFO which silences noisy DEBUG output.
import logging as _logging

_logging.getLogger("enforcecore").setLevel(
    getattr(_logging, settings.log_level.upper(), _logging.INFO)
)

# ── Public API contract ──────────────────────────────────────────────────
# Only these symbols are guaranteed stable across minor versions.
# Everything else is importable but may move in future releases.
__all__ = [
    "AuditBackendPlugin",
    "AuditEntry",
    "Auditor",
    "ComplianceError",
    "ComplianceFormat",
    "CompliancePeriod",
    "ComplianceReport",
    "ComplianceReporter",
    "ContentViolationError",
    "CostLimitError",
    "CostTracker",
    "Decision",
    "EnforceCoreError",
    "EnforcementResult",
    "EnforcementViolation",
    "Enforcer",
    "GuardPlugin",
    "KillSwitch",
    "MultiTenantEnforcer",
    "NERBackend",
    "PluginLoadError",
    "PluginManager",
    "Policy",
    "PolicyError",
    "PolicyLoadError",
    "PolicyServerClient",
    "PolicyServerError",
    "RateLimiter",
    "RedactionResult",
    "RedactionStrategy",
    "Redactor",
    "RedactorPlugin",
    "ResourceGuard",
    "ResourceLimitError",
    "SandboxConfig",
    "SandboxMemoryError",
    "SandboxStrategy",
    "SandboxTimeoutError",
    "SandboxViolationError",
    "SecretScanner",
    "SensitivityEnforcer",
    "SensitivityLabel",
    "SensitivityLabelConfig",
    "SensitivityViolation",
    "SensitivityViolationError",
    "Settings",
    "SubprocessSandbox",
    "ToolDeniedError",
    "VerificationResult",
    "__version__",
    "check_tool_schema_sensitivity",
    "enforce",
    "is_ner_available",
    "load_policy",
    "load_trail",
    "sensitivity_level",
    "settings",
    "verify_trail",
]

# ── Tier 2 deprecation machinery ─────────────────────────────────────────
# Tier 2 symbols are still importable via ``from enforcecore import X`` for
# backwards compatibility, but emit a DeprecationWarning directing users to
# the canonical submodule import.  They will be removed from the top-level
# package in v2.0.0.
#
# Implementation: the ``X as X`` imports above eagerly loaded the symbols
# into the module namespace.  We move them into ``_TIER2_IMPORTS`` and pop
# them from ``globals()`` so that ``__getattr__`` fires on access.

import importlib as _importlib
import warnings as _warnings

_TIER2_IMPORTS: dict[str, tuple[str, str]] = {
    # ── auditor.backends ──
    "AuditBackend": ("enforcecore.auditor.backends", "AuditBackend"),
    "CallbackBackend": ("enforcecore.auditor.backends", "CallbackBackend"),
    "JsonlBackend": ("enforcecore.auditor.backends", "JsonlBackend"),
    "MultiBackend": ("enforcecore.auditor.backends", "MultiBackend"),
    "NullBackend": ("enforcecore.auditor.backends", "NullBackend"),
    # ── auditor.rotation ──
    "AuditRotator": ("enforcecore.auditor.rotation", "AuditRotator"),
    # ── core.enforcer ──
    "clear_policy_cache": ("enforcecore.core.enforcer", "clear_policy_cache"),
    # ── core.hardening ──
    "EnforcementDepthError": ("enforcecore.core.hardening", "EnforcementDepthError"),
    "HardeningError": ("enforcecore.core.hardening", "HardeningError"),
    "InputTooLargeError": ("enforcecore.core.hardening", "InputTooLargeError"),
    "InvalidToolNameError": ("enforcecore.core.hardening", "InvalidToolNameError"),
    "check_input_size": ("enforcecore.core.hardening", "check_input_size"),
    "deep_redact": ("enforcecore.core.hardening", "deep_redact"),
    "enter_enforcement": ("enforcecore.core.hardening", "enter_enforcement"),
    "exit_enforcement": ("enforcecore.core.hardening", "exit_enforcement"),
    "get_enforcement_chain": ("enforcecore.core.hardening", "get_enforcement_chain"),
    "get_enforcement_depth": ("enforcecore.core.hardening", "get_enforcement_depth"),
    "is_dev_mode": ("enforcecore.core.hardening", "is_dev_mode"),
    "validate_tool_name": ("enforcecore.core.hardening", "validate_tool_name"),
    # ── core.policy ──
    "ContentRulesPolicyConfig": ("enforcecore.core.policy", "ContentRulesPolicyConfig"),
    "NetworkPolicy": ("enforcecore.core.policy", "NetworkPolicy"),
    "PIIRedactionConfig": ("enforcecore.core.policy", "PIIRedactionConfig"),
    "PolicyEngine": ("enforcecore.core.policy", "PolicyEngine"),
    "PolicyRules": ("enforcecore.core.policy", "PolicyRules"),
    "RateLimitPolicyConfig": ("enforcecore.core.policy", "RateLimitPolicyConfig"),
    "ResourceLimits": ("enforcecore.core.policy", "ResourceLimits"),
    "SensitivityLabelConfig": ("enforcecore.core.policy", "SensitivityLabelConfig"),
    # ── core.rules ──
    "ContentRule": ("enforcecore.core.rules", "ContentRule"),
    "ContentRuleConfig": ("enforcecore.core.rules", "ContentRuleConfig"),
    "RuleEngine": ("enforcecore.core.rules", "RuleEngine"),
    "RuleViolation": ("enforcecore.core.rules", "RuleViolation"),
    "get_builtin_rules": ("enforcecore.core.rules", "get_builtin_rules"),
    # ── core.types ──
    "AuditError": ("enforcecore.core.types", "AuditError"),
    "CallContext": ("enforcecore.core.types", "CallContext"),
    "DomainDeniedError": ("enforcecore.core.types", "DomainDeniedError"),
    "GuardError": ("enforcecore.core.types", "GuardError"),
    "PolicyValidationError": ("enforcecore.core.types", "PolicyValidationError"),
    "RedactionError": ("enforcecore.core.types", "RedactionError"),
    "RedactionEvent": ("enforcecore.core.types", "RedactionEvent"),
    "ViolationAction": ("enforcecore.core.types", "ViolationAction"),
    "ViolationType": ("enforcecore.core.types", "ViolationType"),
    # ── eval ──
    "BenchmarkRunner": ("enforcecore.eval", "BenchmarkRunner"),
    "ScenarioRunner": ("enforcecore.eval", "ScenarioRunner"),
    "generate_benchmark_report": ("enforcecore.eval", "generate_benchmark_report"),
    "generate_html_report": ("enforcecore.eval", "generate_html_report"),
    "generate_report": ("enforcecore.eval", "generate_report"),
    "generate_suite_report": ("enforcecore.eval", "generate_suite_report"),
    "get_all_scenarios": ("enforcecore.eval", "get_all_scenarios"),
    "get_scenarios_by_category": ("enforcecore.eval", "get_scenarios_by_category"),
    # ── eval.types ──
    "BenchmarkResult": ("enforcecore.eval.types", "BenchmarkResult"),
    "BenchmarkSuite": ("enforcecore.eval.types", "BenchmarkSuite"),
    "Scenario": ("enforcecore.eval.types", "Scenario"),
    "ScenarioOutcome": ("enforcecore.eval.types", "ScenarioOutcome"),
    "ScenarioResult": ("enforcecore.eval.types", "ScenarioResult"),
    "Severity": ("enforcecore.eval.types", "Severity"),
    "SuiteResult": ("enforcecore.eval.types", "SuiteResult"),
    "ThreatCategory": ("enforcecore.eval.types", "ThreatCategory"),
    # ── guard.network ──
    "DomainChecker": ("enforcecore.guard.network", "DomainChecker"),
    # ── guard.ratelimit ──
    "RateLimit": ("enforcecore.guard.ratelimit", "RateLimit"),
    "RateLimitError": ("enforcecore.guard.ratelimit", "RateLimitError"),
    # ── integrations._base ──
    "require_package": ("enforcecore.integrations._base", "require_package"),
    "wrap_with_policy": ("enforcecore.integrations._base", "wrap_with_policy"),
    # ── plugins.hooks ──
    "HookContext": ("enforcecore.plugins.hooks", "HookContext"),
    "HookRegistry": ("enforcecore.plugins.hooks", "HookRegistry"),
    "RedactionHookContext": ("enforcecore.plugins.hooks", "RedactionHookContext"),
    "ViolationHookContext": ("enforcecore.plugins.hooks", "ViolationHookContext"),
    "on_post_call": ("enforcecore.plugins.hooks", "on_post_call"),
    "on_pre_call": ("enforcecore.plugins.hooks", "on_pre_call"),
    "on_redaction": ("enforcecore.plugins.hooks", "on_redaction"),
    "on_violation": ("enforcecore.plugins.hooks", "on_violation"),
    # ── plugins.webhooks ──
    "WebhookDispatcher": ("enforcecore.plugins.webhooks", "WebhookDispatcher"),
    "WebhookEvent": ("enforcecore.plugins.webhooks", "WebhookEvent"),
    # ── redactor.engine ──
    "DetectedEntity": ("enforcecore.redactor.engine", "DetectedEntity"),
    # ── redactor.patterns ──
    "CustomPattern": ("enforcecore.redactor.patterns", "CustomPattern"),
    "PatternRegistry": ("enforcecore.redactor.patterns", "PatternRegistry"),
    # ── redactor.secrets ──
    "DetectedSecret": ("enforcecore.redactor.secrets", "DetectedSecret"),
    # ── redactor.unicode ──
    "decode_encoded_pii": ("enforcecore.redactor.unicode", "decode_encoded_pii"),
    "normalize_homoglyphs": ("enforcecore.redactor.unicode", "normalize_homoglyphs"),
    "normalize_unicode": ("enforcecore.redactor.unicode", "normalize_unicode"),
    "prepare_for_detection": ("enforcecore.redactor.unicode", "prepare_for_detection"),
    # ── telemetry ──
    "AuditLogExporter": ("enforcecore.telemetry", "AuditLogExporter"),
    "EnforceCoreInstrumentor": ("enforcecore.telemetry", "EnforceCoreInstrumentor"),
    "EnforceCoreMetrics": ("enforcecore.telemetry", "EnforceCoreMetrics"),
    "EnforceCorePrometheusExporter": ("enforcecore.telemetry", "EnforceCorePrometheusExporter"),
    "make_elastic_sink": ("enforcecore.telemetry", "make_elastic_sink"),
    "make_splunk_hec_sink": ("enforcecore.telemetry", "make_splunk_hec_sink"),
}

# Remove Tier 2 symbols from the module namespace so __getattr__ fires.
for _tier2_name in _TIER2_IMPORTS:
    globals().pop(_tier2_name, None)
del _tier2_name


def __getattr__(name: str) -> object:
    """Lazy accessor for deprecated Tier 2 symbols.

    Emits a ``DeprecationWarning`` on first access, then caches the value
    in ``globals()`` so subsequent accesses are zero-cost.
    """
    if name in _TIER2_IMPORTS:
        mod_path, attr_name = _TIER2_IMPORTS[name]
        mod = _importlib.import_module(mod_path)
        value = getattr(mod, attr_name)
        _warnings.warn(
            f"Importing {name!r} from 'enforcecore' is deprecated and will be "
            f"removed in v2.0.0. Use 'from {mod_path} import {attr_name}' instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        globals()[name] = value
        return value
    msg = f"module 'enforcecore' has no attribute {name!r}"
    raise AttributeError(msg)


def __dir__() -> list[str]:
    """Include both Tier 1 (__all__) and deprecated Tier 2 symbols."""
    return sorted(set(list(globals()) + list(_TIER2_IMPORTS)))

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

**API surface (v1.0.25a1+):** This package exports ~30 core symbols.
Advanced types are available via submodule imports::

    # Core (top-level)
    from enforcecore import enforce, Enforcer, Policy, Redactor, Auditor

    # Advanced (submodule)
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
    ToolDeniedError,
)
from enforcecore.core.types import (
    DomainDeniedError as DomainDeniedError,
)
from enforcecore.core.types import (
    GuardError as GuardError,
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
from enforcecore.plugins.webhooks import (
    WebhookDispatcher as WebhookDispatcher,
)
from enforcecore.plugins.webhooks import (
    WebhookEvent as WebhookEvent,
)
from enforcecore.redactor.engine import DetectedEntity as DetectedEntity
from enforcecore.redactor.engine import RedactionResult, Redactor
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
from enforcecore.telemetry import (
    EnforceCoreInstrumentor as EnforceCoreInstrumentor,
)
from enforcecore.telemetry import (
    EnforceCoreMetrics as EnforceCoreMetrics,
)

__version__ = "1.0.25a1"

# ── Public API contract ──────────────────────────────────────────────────
# Only these ~30 symbols are guaranteed stable across minor versions.
# Everything else is importable but may move in future releases.
__all__ = [
    "AuditEntry",
    # ── Audit ──
    "Auditor",
    "ContentViolationError",
    "CostLimitError",
    "CostTracker",
    # ── Core types ──
    "Decision",
    # ── Errors ──
    "EnforceCoreError",
    "EnforcementResult",
    "EnforcementViolation",
    "Enforcer",
    "KillSwitch",
    # ── Policy ──
    "Policy",
    "PolicyError",
    "PolicyLoadError",
    "RateLimiter",
    "RedactionResult",
    "RedactionStrategy",
    # ── Redaction ──
    "Redactor",
    # ── Guards ──
    "ResourceGuard",
    "ResourceLimitError",
    "SecretScanner",
    # ── Configuration ──
    "Settings",
    "ToolDeniedError",
    "VerificationResult",
    # ── Meta ──
    "__version__",
    # ── Enforcement ──
    "enforce",
    "load_policy",
    "load_trail",
    "settings",
    "verify_trail",
]

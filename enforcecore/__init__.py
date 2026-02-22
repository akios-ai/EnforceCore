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

DISCLAIMER: This software is provided "AS IS", without warranty of any kind.
It is a technical enforcement tool, not a compliance certification.
See DISCLAIMER.md and LICENSE for full terms.
"""

from enforcecore.auditor.backends import (
    AuditBackend,
    CallbackBackend,
    JsonlBackend,
    MultiBackend,
    NullBackend,
)
from enforcecore.auditor.engine import (
    AuditEntry,
    Auditor,
    VerificationResult,
    load_trail,
    verify_trail,
)
from enforcecore.auditor.rotation import AuditRotator
from enforcecore.core.config import Settings, settings
from enforcecore.core.enforcer import Enforcer, clear_policy_cache, enforce
from enforcecore.core.hardening import (
    EnforcementDepthError,
    HardeningError,
    InputTooLargeError,
    InvalidToolNameError,
    check_input_size,
    deep_redact,
    enter_enforcement,
    exit_enforcement,
    get_enforcement_chain,
    get_enforcement_depth,
    is_dev_mode,
    validate_tool_name,
)
from enforcecore.core.policy import (
    ContentRulesPolicyConfig,
    NetworkPolicy,
    PIIRedactionConfig,
    Policy,
    PolicyEngine,
    PolicyRules,
    RateLimitPolicyConfig,
    ResourceLimits,
    load_policy,
)
from enforcecore.core.rules import (
    ContentRule,
    ContentRuleConfig,
    RuleEngine,
    RuleViolation,
    get_builtin_rules,
)
from enforcecore.core.types import (
    AuditError,
    CallContext,
    ContentViolationError,
    CostLimitError,
    Decision,
    DomainDeniedError,
    EnforceCoreError,
    EnforcementResult,
    EnforcementViolation,
    GuardError,
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
from enforcecore.eval import (
    BenchmarkRunner,
    ScenarioRunner,
    generate_benchmark_report,
    generate_report,
    generate_suite_report,
    get_all_scenarios,
    get_scenarios_by_category,
)
from enforcecore.eval.types import (
    BenchmarkResult,
    BenchmarkSuite,
    Scenario,
    ScenarioOutcome,
    ScenarioResult,
    Severity,
    SuiteResult,
    ThreatCategory,
)
from enforcecore.guard.engine import CostTracker, KillSwitch, ResourceGuard
from enforcecore.guard.network import DomainChecker
from enforcecore.guard.ratelimit import RateLimit, RateLimiter, RateLimitError
from enforcecore.integrations._base import require_package, wrap_with_policy
from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
    on_post_call,
    on_pre_call,
    on_redaction,
    on_violation,
)
from enforcecore.plugins.webhooks import WebhookDispatcher, WebhookEvent
from enforcecore.redactor.engine import DetectedEntity, RedactionResult, Redactor
from enforcecore.redactor.patterns import CustomPattern, PatternRegistry
from enforcecore.redactor.secrets import DetectedSecret, SecretScanner
from enforcecore.redactor.unicode import (
    decode_encoded_pii,
    normalize_homoglyphs,
    normalize_unicode,
    prepare_for_detection,
)
from enforcecore.telemetry import EnforceCoreInstrumentor, EnforceCoreMetrics

__version__ = "1.0.19a1"

__all__ = [
    "AuditBackend",
    "AuditEntry",
    "AuditError",
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
    "ContentViolationError",
    "CostLimitError",
    "CostTracker",
    "CustomPattern",
    "Decision",
    "DetectedEntity",
    "DetectedSecret",
    "DomainChecker",
    "DomainDeniedError",
    "EnforceCoreError",
    "EnforceCoreInstrumentor",
    "EnforceCoreMetrics",
    "EnforcementDepthError",
    "EnforcementResult",
    "EnforcementViolation",
    "Enforcer",
    "GuardError",
    "HardeningError",
    "HookContext",
    "HookRegistry",
    "InputTooLargeError",
    "InvalidToolNameError",
    "JsonlBackend",
    "KillSwitch",
    "MultiBackend",
    "NetworkPolicy",
    "NullBackend",
    "PIIRedactionConfig",
    "PatternRegistry",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "PolicyLoadError",
    "PolicyRules",
    "PolicyValidationError",
    "RateLimit",
    "RateLimitError",
    "RateLimitPolicyConfig",
    "RateLimiter",
    "RedactionError",
    "RedactionEvent",
    "RedactionHookContext",
    "RedactionResult",
    "RedactionStrategy",
    "Redactor",
    "ResourceGuard",
    "ResourceLimitError",
    "ResourceLimits",
    "RuleEngine",
    "RuleViolation",
    "Scenario",
    "ScenarioOutcome",
    "ScenarioResult",
    "ScenarioRunner",
    "SecretScanner",
    "Settings",
    "Severity",
    "SuiteResult",
    "ThreatCategory",
    "ToolDeniedError",
    "VerificationResult",
    "ViolationAction",
    "ViolationHookContext",
    "ViolationType",
    "WebhookDispatcher",
    "WebhookEvent",
    "__version__",
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
    "settings",
    "validate_tool_name",
    "verify_trail",
    "wrap_with_policy",
]

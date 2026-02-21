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
from enforcecore.core.config import Settings, settings
from enforcecore.core.enforcer import Enforcer, enforce
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
from enforcecore.core.policy import Policy, PolicyEngine, load_policy
from enforcecore.core.types import (
    AuditError,
    CallContext,
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
    generate_report,
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
from enforcecore.redactor.engine import DetectedEntity, RedactionResult, Redactor
from enforcecore.redactor.patterns import CustomPattern, PatternRegistry
from enforcecore.redactor.secrets import DetectedSecret, SecretScanner
from enforcecore.redactor.unicode import (
    decode_encoded_pii,
    normalize_homoglyphs,
    normalize_unicode,
    prepare_for_detection,
)

__version__ = "1.0.7a1"

__all__ = [
    "AuditBackend",
    "AuditEntry",
    "AuditError",
    "Auditor",
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSuite",
    "CallContext",
    "CallbackBackend",
    "CostLimitError",
    "CostTracker",
    "CustomPattern",
    "Decision",
    "DetectedEntity",
    "DetectedSecret",
    "DomainDeniedError",
    "EnforceCoreError",
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
    "NullBackend",
    "PatternRegistry",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "PolicyLoadError",
    "PolicyValidationError",
    "RedactionError",
    "RedactionEvent",
    "RedactionHookContext",
    "RedactionResult",
    "RedactionStrategy",
    "Redactor",
    "ResourceGuard",
    "ResourceLimitError",
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
    "__version__",
    "check_input_size",
    "decode_encoded_pii",
    "deep_redact",
    "enforce",
    "enter_enforcement",
    "exit_enforcement",
    "generate_report",
    "get_enforcement_chain",
    "get_enforcement_depth",
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

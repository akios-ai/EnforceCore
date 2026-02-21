"""Core enforcement engine — Policy Engine, Enforcer, types, and configuration."""

from enforcecore.core.config import Settings, settings
from enforcecore.core.enforcer import Enforcer, clear_policy_cache, enforce
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

__all__ = [
    # Exceptions
    "AuditError",
    # Types & Enums
    "CallContext",
    "ContentRulesPolicyConfig",
    "CostLimitError",
    "Decision",
    "DomainDeniedError",
    "EnforceCoreError",
    "EnforcementResult",
    "EnforcementViolation",
    # Enforcer
    "Enforcer",
    "GuardError",
    # Policy
    "NetworkPolicy",
    "PIIRedactionConfig",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "PolicyLoadError",
    "PolicyRules",
    "PolicyValidationError",
    "RateLimitPolicyConfig",
    "RedactionError",
    "RedactionEvent",
    "RedactionStrategy",
    "ResourceLimitError",
    "ResourceLimits",
    # Config
    "Settings",
    "ToolDeniedError",
    "ViolationAction",
    "ViolationType",
    "clear_policy_cache",
    "enforce",
    "load_policy",
    "settings",
]

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

from enforcecore.core.config import Settings, settings
from enforcecore.core.enforcer import Enforcer, enforce
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

__version__ = "1.0.0a1"

__all__ = [
    # Exceptions
    "AuditError",
    # Types
    "CallContext",
    "CostLimitError",
    "Decision",
    "DomainDeniedError",
    "EnforceCoreError",
    "EnforcementResult",
    "EnforcementViolation",
    "Enforcer",
    "GuardError",
    # Policy
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "PolicyLoadError",
    "PolicyValidationError",
    "RedactionError",
    "RedactionEvent",
    "RedactionStrategy",
    "ResourceLimitError",
    # Config
    "Settings",
    "ToolDeniedError",
    "ViolationAction",
    "ViolationType",
    # Version
    "__version__",
    # Primary API
    "enforce",
    "load_policy",
    "settings",
]

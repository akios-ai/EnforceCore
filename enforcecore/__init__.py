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

from enforcecore.auditor.engine import (
    AuditEntry,
    Auditor,
    VerificationResult,
    load_trail,
    verify_trail,
)
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
from enforcecore.redactor.engine import DetectedEntity, RedactionResult, Redactor

__version__ = "1.0.5a1"

__all__ = [
    "AuditEntry",
    "AuditError",
    "Auditor",
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSuite",
    "CallContext",
    "CostLimitError",
    "CostTracker",
    "Decision",
    "DetectedEntity",
    "DomainDeniedError",
    "EnforceCoreError",
    "EnforcementResult",
    "EnforcementViolation",
    "Enforcer",
    "GuardError",
    "KillSwitch",
    "Policy",
    "PolicyEngine",
    "PolicyError",
    "PolicyLoadError",
    "PolicyValidationError",
    "RedactionError",
    "RedactionEvent",
    "RedactionResult",
    "RedactionStrategy",
    "Redactor",
    "ResourceGuard",
    "ResourceLimitError",
    "Scenario",
    "ScenarioOutcome",
    "ScenarioResult",
    "ScenarioRunner",
    "Settings",
    "Severity",
    "SuiteResult",
    "ThreatCategory",
    "ToolDeniedError",
    "VerificationResult",
    "ViolationAction",
    "ViolationType",
    "__version__",
    "enforce",
    "generate_report",
    "load_policy",
    "load_trail",
    "require_package",
    "settings",
    "verify_trail",
    "wrap_with_policy",
]

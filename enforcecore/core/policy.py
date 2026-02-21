"""Policy models and evaluation engine.

Policies define what an agent is allowed to do.  They are loaded from YAML
files, validated with Pydantic, and evaluated by the ``PolicyEngine`` before
and after every enforced call.

Example YAML policy::

    name: "my-policy"
    version: "1.0"
    rules:
      allowed_tools: ["search_web", "calculator"]
      denied_tools: ["execute_shell"]
    on_violation: "block"
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml
from pydantic import BaseModel, field_validator

from enforcecore.core.types import (
    CallContext,
    Decision,
    EnforcementViolation,
    PolicyLoadError,
    PolicyValidationError,
    RedactionStrategy,
    ToolDeniedError,
    ViolationAction,
    ViolationType,
)

logger = structlog.get_logger("enforcecore.policy")


# ---------------------------------------------------------------------------
# Policy data models
# ---------------------------------------------------------------------------


class PIIRedactionConfig(BaseModel):
    """Configuration for PII redaction within a policy."""

    enabled: bool = False
    categories: list[str] = ["email", "phone", "ssn", "credit_card", "ip_address"]
    strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER


class ResourceLimits(BaseModel):
    """Resource constraints enforced on each call."""

    max_call_duration_seconds: float | None = None
    max_memory_mb: int | None = None
    max_cost_usd: float | None = None


class NetworkPolicy(BaseModel):
    """Network-level policy (domain allow/deny).

    When ``allowed_domains`` is non-empty and ``deny_all_other`` is True,
    only the listed domains (and their subdomains via wildcards) are allowed.
    ``denied_domains`` blocks specific domains even if otherwise allowed.
    """

    enabled: bool = False
    allowed_domains: list[str] = []
    denied_domains: list[str] = []
    deny_all_other: bool = True


class ContentRulesPolicyConfig(BaseModel):
    """Content rules configuration in a policy.

    Example YAML::

        content_rules:
          enabled: true
          block_patterns:
            - name: shell_injection
            - name: custom_rule
              pattern: "dangerous_pattern"
              action: block
    """

    enabled: bool = False
    block_patterns: list[dict[str, str]] = []


class RateLimitPolicyConfig(BaseModel):
    """Rate limit configuration in a policy.

    Example YAML::

        rate_limits:
          enabled: true
          per_tool:
            search_web:
              max_calls: 10
              window_seconds: 60
          global:
            max_calls: 100
            window_seconds: 60
    """

    enabled: bool = False
    per_tool: dict[str, dict[str, float]] = {}
    global_limit: dict[str, float] | None = None


class PolicyRules(BaseModel):
    """The rule-set that a policy evaluates against.

    When ``allowed_tools`` is ``None``, all tools are allowed unless
    explicitly listed in ``denied_tools``.  When ``allowed_tools`` is a
    list, only those tools are permitted.
    """

    allowed_tools: list[str] | None = None
    denied_tools: list[str] = []
    pii_redaction: PIIRedactionConfig = PIIRedactionConfig()
    resource_limits: ResourceLimits = ResourceLimits()
    network: NetworkPolicy = NetworkPolicy()
    content_rules: ContentRulesPolicyConfig = ContentRulesPolicyConfig()
    rate_limits: RateLimitPolicyConfig = RateLimitPolicyConfig()
    max_output_size_bytes: int | None = None
    redact_output: bool = True


class Policy(BaseModel):
    """A complete EnforceCore policy.

    Policies are normally loaded from YAML files using :meth:`from_file`
    or :func:`load_policy`, but can also be constructed programmatically.
    """

    name: str
    version: str = "1.0"
    rules: PolicyRules = PolicyRules()
    on_violation: ViolationAction = ViolationAction.BLOCK

    @field_validator("name")
    @classmethod
    def _name_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            msg = "Policy name must not be empty"
            raise ValueError(msg)
        return v.strip()

    # -- Factory helpers -----------------------------------------------------

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        """Load and validate a policy from a YAML file.

        Raises:
            PolicyLoadError: If the file cannot be found or parsed.
            PolicyValidationError: If the YAML content is not a valid policy.
        """
        filepath = Path(path)
        if not filepath.exists():
            raise PolicyLoadError(f"Policy file not found: {filepath}")
        if not filepath.is_file():
            raise PolicyLoadError(f"Policy path is not a file: {filepath}")

        try:
            raw = filepath.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            raise PolicyLoadError(f"Invalid YAML in {filepath}: {exc}") from exc

        if not isinstance(data, dict):
            raise PolicyLoadError(
                f"Policy file must contain a YAML mapping, got {type(data).__name__}"
            )

        return cls.from_dict(data, source=str(filepath))

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, source: str = "<dict>") -> Policy:
        """Create a policy from a plain dictionary.

        Raises:
            PolicyValidationError: If the data does not conform to the schema.
        """
        try:
            return cls.model_validate(data)
        except Exception as exc:
            raise PolicyValidationError(f"Policy validation failed ({source}): {exc}") from exc

    @staticmethod
    def validate_file(path: str | Path) -> list[str]:
        """Validate a YAML policy file without loading it.

        Returns:
            A list of error messages.  Empty list means the file is valid.
        """
        errors: list[str] = []
        try:
            Policy.from_file(path)
        except (PolicyLoadError, PolicyValidationError) as exc:
            errors.append(str(exc))
        return errors


# ---------------------------------------------------------------------------
# Policy engine — evaluates policies against call context
# ---------------------------------------------------------------------------


class PreCallResult:
    """Result of pre-call policy evaluation."""

    __slots__ = ("decision", "reason", "violation_type")

    def __init__(
        self,
        decision: Decision,
        violation_type: ViolationType | None = None,
        reason: str = "",
    ) -> None:
        self.decision = decision
        self.violation_type = violation_type
        self.reason = reason

    @property
    def is_allowed(self) -> bool:
        return self.decision == Decision.ALLOWED


class PostCallResult:
    """Result of post-call policy evaluation."""

    __slots__ = ("decision", "reason", "violation_type")

    def __init__(
        self,
        decision: Decision = Decision.ALLOWED,
        violation_type: ViolationType | None = None,
        reason: str = "",
    ) -> None:
        self.decision = decision
        self.violation_type = violation_type
        self.reason = reason

    @property
    def is_allowed(self) -> bool:
        return self.decision == Decision.ALLOWED


class PolicyEngine:
    """Loads and evaluates policies against call contexts.

    The engine is **stateless** — it only reads the policy and context to
    produce a decision.  Thread-safe by design (no mutable state).

    Example::

        engine = PolicyEngine(Policy.from_file("policy.yaml"))
        result = engine.evaluate_pre_call(context)
        if not result.is_allowed:
            raise ToolDeniedError(...)
    """

    __slots__ = ("_policy",)

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        """Create an engine by loading a policy from a YAML file."""
        return cls(Policy.from_file(path))

    @property
    def policy(self) -> Policy:
        """The loaded policy (read-only)."""
        return self._policy

    # -- Pre-call evaluation -------------------------------------------------

    def evaluate_pre_call(self, context: CallContext) -> PreCallResult:
        """Evaluate the policy *before* a tool call executes.

        Checks:
        1. Is the tool explicitly denied?
        2. Is the tool in the allowed list (if an allowed list exists)?
        """
        rules = self._policy.rules
        tool = context.tool_name
        tool_lower = tool.lower()

        # Check explicit deny list first (case-insensitive)
        denied_lower = {t.lower() for t in rules.denied_tools}
        if tool_lower in denied_lower:
            logger.warning(
                "tool_denied",
                tool=tool,
                policy=self._policy.name,
                reason="in denied_tools list",
            )
            return PreCallResult(
                Decision.BLOCKED,
                ViolationType.TOOL_DENIED,
                reason=f"tool '{tool}' is in the denied list",
            )

        # Check allowed list (if specified, case-insensitive)
        if rules.allowed_tools is not None:
            allowed_lower = {t.lower() for t in rules.allowed_tools}
            if tool_lower not in allowed_lower:
                logger.warning(
                    "tool_not_allowed",
                    tool=tool,
                    policy=self._policy.name,
                    reason="not in allowed_tools list",
                )
                return PreCallResult(
                    Decision.BLOCKED,
                    ViolationType.TOOL_NOT_ALLOWED,
                    reason=f"tool '{tool}' is not in the allowed list",
                )

        logger.debug("pre_call_allowed", tool=tool, policy=self._policy.name)
        return PreCallResult(Decision.ALLOWED)

    # -- Post-call evaluation ------------------------------------------------

    def evaluate_post_call(
        self,
        context: CallContext,
        result: Any,
    ) -> PostCallResult:
        """Evaluate the policy *after* a tool call returns.

        Checks:
        1. Output size limit
        """
        rules = self._policy.rules

        # Check output size
        if rules.max_output_size_bytes is not None:
            result_str = str(result)
            size = len(result_str.encode("utf-8"))
            if size > rules.max_output_size_bytes:
                logger.warning(
                    "output_size_exceeded",
                    tool=context.tool_name,
                    size=size,
                    limit=rules.max_output_size_bytes,
                )
                return PostCallResult(
                    Decision.BLOCKED,
                    ViolationType.OUTPUT_SIZE,
                    reason=(
                        f"output size {size} bytes exceeds limit "
                        f"{rules.max_output_size_bytes} bytes"
                    ),
                )

        return PostCallResult(Decision.ALLOWED)

    # -- Violation handling --------------------------------------------------

    def raise_if_blocked(
        self,
        result: PreCallResult | PostCallResult,
        context: CallContext,
    ) -> None:
        """Raise an appropriate exception if the result is BLOCKED and
        the policy's ``on_violation`` is ``block``.

        If ``on_violation`` is ``log``, the violation is logged but the call
        continues.
        """
        if result.is_allowed:
            return

        if self._policy.on_violation == ViolationAction.LOG:
            logger.warning(
                "violation_logged",
                tool=context.tool_name,
                policy=self._policy.name,
                violation_type=result.violation_type,
                reason=result.reason,
            )
            return

        # Block
        if result.violation_type in (
            ViolationType.TOOL_DENIED,
            ViolationType.TOOL_NOT_ALLOWED,
        ):
            raise ToolDeniedError(
                context.tool_name,
                policy_name=self._policy.name,
                reason=result.reason,
            )

        raise EnforcementViolation(
            f"Policy violation: {result.reason}",
            tool_name=context.tool_name,
            policy_name=self._policy.name,
            violation_type=result.violation_type or ViolationType.POLICY_ERROR,
            reason=result.reason,
        )


def load_policy(path: str | Path) -> Policy:
    """Convenience function to load a policy from a YAML file.

    Equivalent to ``Policy.from_file(path)``.
    """
    return Policy.from_file(path)

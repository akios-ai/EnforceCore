# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Main enforcer — the central coordinator for EnforceCore.

This module provides:

* ``@enforce()`` — decorator that wraps any sync or async callable with
  policy enforcement.
* ``Enforcer`` — the class that coordinates policy evaluation, and in
  future releases, redaction, auditing, and resource guarding.

Example::

    from enforcecore import enforce

    @enforce(policy="policies/strict.yaml")
    async def search_web(query: str) -> str:
        return await api.search(query)
"""

from __future__ import annotations

import functools
import inspect
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar, overload

import structlog

from enforcecore.core.config import settings
from enforcecore.core.hardening import (
    _warn_fail_open,
    check_input_size,
    deep_redact,
    enter_enforcement,
    exit_enforcement,
    validate_tool_name,
)
from enforcecore.core.policy import Policy, PolicyEngine
from enforcecore.core.rules import ContentRuleConfig, RuleEngine
from enforcecore.core.types import (
    CallContext,
    ContentViolationError,
    EnforceCoreError,
    EnforcementViolation,
)
from enforcecore.guard.network import DomainChecker
from enforcecore.guard.ratelimit import RateLimitConfig, RateLimiter
from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)
from enforcecore.redactor.engine import Redactor

if TYPE_CHECKING:
    from collections.abc import Callable

    from enforcecore.auditor.engine import Auditor
    from enforcecore.guard.engine import ResourceGuard

logger = structlog.get_logger("enforcecore.enforcer")

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Enforcer class
# ---------------------------------------------------------------------------


class Enforcer:
    """Central coordinator for runtime enforcement.

    The Enforcer coordinates the full enforcement pipeline: policy
    evaluation, PII redaction, content rule checking, rate limiting,
    network enforcement, resource guarding, auditing, and hooks.

    The Enforcer is **thread-safe** -- it holds no mutable per-call state.
    Each call gets its own ``CallContext``.

    Example::

        enforcer = Enforcer(policy=Policy.from_file("policy.yaml"))
        result = await enforcer.enforce_async(my_tool, "arg1", key="val")
    """

    __slots__ = (
        "_auditor",
        "_domain_checker",
        "_engine",
        "_guard",
        "_policy_server",
        "_rate_limiter",
        "_redactor",
        "_rule_engine",
        "_sandbox",
        "_tenant_id",
    )

    def __init__(self, policy: Policy, *, tenant_id: str | None = None) -> None:
        """Initialize the enforcer with a policy.

        Args:
            policy: The :class:`Policy` to enforce on every call.
            tenant_id: Optional tenant identifier. When set, every audit
                entry written by this enforcer will include this value,
                enabling per-tenant filtering of audit trails.
        """
        self._engine = PolicyEngine(policy)
        self._redactor = self._build_redactor(policy)
        self._auditor = self._build_auditor()
        self._guard = self._build_guard()
        self._rule_engine = self._build_rule_engine(policy)
        self._rate_limiter = self._build_rate_limiter(policy)
        self._domain_checker = self._build_domain_checker(policy)
        self._sandbox = self._build_sandbox(policy)
        self._tenant_id = tenant_id
        self._policy_server: object = None  # set by from_server()

    @classmethod
    def from_file(cls, path: str | Path, *, tenant_id: str | None = None) -> Enforcer:
        """Create an enforcer from a YAML policy file.

        Args:
            path: Path to the policy YAML file.
            tenant_id: Optional tenant identifier propagated to audit entries.

        Returns:
            A new :class:`Enforcer` configured with the loaded policy.
        """
        return cls(Policy.from_file(path), tenant_id=tenant_id)

    @classmethod
    def from_server(
        cls,
        url: str,
        token: str,
        *,
        cache_ttl: int = 300,
        verify_signature: bool = True,
        tenant_id: str | None = None,
    ) -> Enforcer:
        """Create an enforcer with a policy fetched from a remote policy server.

        The policy is fetched synchronously at construction time.  A
        :class:`~enforcecore.core.policy_server.PolicyServerClient` is
        stored on the enforcer and is accessible via
        :attr:`policy_server_client` for cache management.

        Example::

            import os
            enforcer = Enforcer.from_server(
                "https://policy.acme.com/agents/chatbot-v2",
                token=os.environ["POLICY_SERVER_TOKEN"],
                cache_ttl=300,
            )

        Args:
            url: Full URL of the policy endpoint.
            token: Bearer token for authentication and (optionally) HMAC
                signature verification.
            cache_ttl: Seconds before the cached policy expires.  Defaults
                to ``300`` (5 minutes).  Pass ``0`` to disable caching.
            verify_signature: When ``True`` (default), the
                ``X-Policy-Signature`` response header is verified.
            tenant_id: Optional tenant identifier propagated to audit entries.

        Returns:
            A new :class:`Enforcer` configured with the policy fetched from
            the server.

        Raises:
            PolicyServerError: If the policy cannot be fetched and no cached
                policy exists.

        .. versionadded:: 1.7.0
        """
        from enforcecore.core.policy_server import PolicyServerClient

        client = PolicyServerClient(
            url, token, cache_ttl=cache_ttl, verify_signature=verify_signature
        )
        policy = client.get_policy()
        enforcer = cls(policy, tenant_id=tenant_id)
        enforcer._policy_server = client
        return enforcer

    @property
    def policy(self) -> Policy:
        return self._engine.policy

    @property
    def policy_name(self) -> str:
        return self._engine.policy.name

    @property
    def tenant_id(self) -> str | None:
        """The tenant identifier for this enforcer, or ``None`` if not set."""
        return self._tenant_id

    @property
    def policy_server_client(self) -> object:
        """The :class:`~enforcecore.core.policy_server.PolicyServerClient` used
        to fetch this enforcer's policy, or ``None`` if the enforcer was created
        via :meth:`from_file` or the constructor.

        Use this to inspect cache state, call :meth:`~enforcecore.core.policy_server.PolicyServerClient.invalidate`,
        or retrieve the server-reported :attr:`~enforcecore.core.policy_server.PolicyServerClient.policy_version`.

        .. versionadded:: 1.7.0
        """
        return self._policy_server

    @property
    def guard(self) -> ResourceGuard:
        """The resource guard for this enforcer."""
        return self._guard

    def record_cost(self, cost_usd: float) -> float:
        """Record a cost for the current enforcer scope.

        Call this after each enforced call to track cumulative cost
        against the configured budget.

        Args:
            cost_usd: The cost in USD for the call that just completed.

        Returns:
            The new cumulative total cost.
        """
        return self._guard.cost_tracker.record(cost_usd)

    @staticmethod
    def _build_guard() -> ResourceGuard:
        """Create a ResourceGuard with cost budget from global settings."""
        from enforcecore.guard.engine import CostTracker
        from enforcecore.guard.engine import ResourceGuard as _Guard

        return _Guard(cost_tracker=CostTracker(budget_usd=settings.cost_budget_usd))

    @staticmethod
    def _build_redactor(policy: Policy) -> Redactor | None:
        """Create a Redactor from the policy's PII config, if enabled."""
        from enforcecore.core.types import RedactionStrategy

        pii_cfg = policy.rules.pii_redaction
        if not pii_cfg.enabled or not settings.redaction_enabled:
            return None

        kwargs: dict[str, object] = {
            "categories": pii_cfg.categories,
            "strategy": pii_cfg.strategy,
        }

        # Pass NER-specific config when the NER strategy is selected
        if pii_cfg.strategy == RedactionStrategy.NER:
            kwargs["threshold"] = pii_cfg.ner_threshold
            if pii_cfg.ner_fallback_to_regex:
                kwargs["fallback"] = RedactionStrategy.REGEX

        return Redactor(**kwargs)  # type: ignore[arg-type]

    @staticmethod
    def _build_rule_engine(policy: Policy) -> RuleEngine | None:
        """Create a RuleEngine from the policy's content rules config."""
        cfg = policy.rules.content_rules
        config = ContentRuleConfig(
            enabled=cfg.enabled,
            block_patterns=cfg.block_patterns,
        )
        return RuleEngine.from_config(config)

    @staticmethod
    def _build_rate_limiter(policy: Policy) -> RateLimiter | None:
        """Create a RateLimiter from the policy's rate limits config."""
        cfg = policy.rules.rate_limits
        config = RateLimitConfig(
            enabled=cfg.enabled,
            per_tool=cfg.per_tool,
            global_limit=cfg.global_limit,
        )
        return RateLimiter.from_config(config)

    @staticmethod
    def _build_domain_checker(policy: Policy) -> DomainChecker | None:
        """Create a DomainChecker from the policy's network config."""
        return DomainChecker.from_policy(policy.rules.network)

    @staticmethod
    def _build_sandbox(policy: Policy) -> Any:
        """Create a SubprocessSandbox from the policy's sandbox config.

        Returns ``None`` when sandbox is disabled (``strategy=none``).

        """
        sandbox_cfg = policy.rules.sandbox.to_sandbox_config()
        if not sandbox_cfg.enabled:
            return None
        from enforcecore.sandbox.runner import SubprocessSandbox

        return SubprocessSandbox(sandbox_cfg)

    def _redact_args(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[tuple[Any, ...], dict[str, Any], int]:
        """Redact string args and kwargs, including nested structures.

        Returns (new_args, new_kwargs, total_redaction_count).
        """
        if self._redactor is None:
            return args, kwargs, 0

        total = 0
        new_args = []
        for a in args:
            redacted, count = deep_redact(a, self._redactor.redact)
            new_args.append(redacted)
            total += count

        new_kwargs: dict[str, Any] = {}
        for k, v in kwargs.items():
            redacted, count = deep_redact(v, self._redactor.redact)
            new_kwargs[k] = redacted
            total += count

        return tuple(new_args), new_kwargs, total

    def _redact_output(self, result: Any) -> tuple[Any, int]:
        """Redact PII from output if it's a string and redact_output is enabled."""
        if self._redactor is None or not isinstance(result, str):
            return result, 0
        if not self._engine.policy.rules.redact_output:
            return result, 0
        res = self._redactor.redact(result)
        return res.text, res.count

    # -- Shared enforcement helpers (M-2 refactor) --------------------------

    def _prepare_call(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        tool_name: str | None,
    ) -> tuple[str, CallContext, HookContext]:
        """Resolve tool name, create call + hook contexts.

        Returns ``(resolved_name, call_ctx, hook_ctx)``.

        .. versionadded:: 1.0.0
        """
        resolved_name = tool_name if tool_name is not None else str(getattr(func, "__name__", func))
        resolved_name = validate_tool_name(resolved_name)
        ctx = CallContext(tool_name=resolved_name, args=args, kwargs=kwargs)
        hook_ctx = HookContext(
            call_id=ctx.call_id,
            tool_name=resolved_name,
            policy_name=self.policy_name,
            args=args,
            kwargs=kwargs,
        )
        return resolved_name, ctx, hook_ctx

    def _validate_pre_call(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        resolved_name: str,
        ctx: CallContext,
    ) -> None:
        """Run all pre-call checks: input size, policy, content rules,
        network, rate limiting.

        Raises on any violation.  All checks are synchronous.

        .. versionadded:: 1.0.0
        """
        check_input_size(args, kwargs)
        pre = self._engine.evaluate_pre_call(ctx)
        self._engine.raise_if_blocked(pre, ctx)

        if self._rule_engine is not None:
            violations = self._rule_engine.check_args(args, kwargs)
            if violations:
                v = violations[0]
                raise ContentViolationError(
                    v.rule_name,
                    v.description,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                )

        if self._domain_checker is not None:
            self._domain_checker.check_args(
                args,
                kwargs,
                tool_name=resolved_name,
                policy_name=self.policy_name,
            )

        if self._rate_limiter is not None:
            self._rate_limiter.acquire(resolved_name, self.policy_name)

    def _redact_and_check_budget(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        resolved_name: str,
    ) -> tuple[tuple[Any, ...], dict[str, Any], int]:
        """Redact inputs and check cost budget.

        Returns ``(r_args, r_kwargs, input_redactions)``.

        .. versionadded:: 1.0.0
        """
        r_args, r_kwargs, input_redactions = self._redact_args(args, kwargs)

        limits = self._engine.policy.rules.resource_limits
        self._guard.cost_tracker.check_budget(
            resolved_name,
            self.policy_name,
            per_call_budget=limits.max_cost_usd,
        )

        return r_args, r_kwargs, input_redactions

    def _process_result(
        self,
        result: Any,
        ctx: CallContext,
        resolved_name: str,
    ) -> tuple[Any, int]:
        """Redact output, check content rules, evaluate post-call policy.

        Returns ``(processed_result, output_redactions)``.

        .. versionadded:: 1.0.0
        """
        result, output_redactions = self._redact_output(result)

        if self._rule_engine is not None and isinstance(result, str):
            out_violations = self._rule_engine.check(result)
            if out_violations:
                v = out_violations[0]
                raise ContentViolationError(
                    v.rule_name,
                    f"output: {v.description}",
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                )

        post = self._engine.evaluate_post_call(ctx, result)
        self._engine.raise_if_blocked(post, ctx)

        return result, output_redactions

    def _log_and_audit_allowed(
        self,
        *,
        resolved_name: str,
        call_id: str,
        t0: float,
        call_duration: float,
        input_redactions: int,
        output_redactions: int,
    ) -> None:
        """Log and audit a successful (allowed) call.

        .. versionadded:: 1.0.0
        """
        overhead = (time.perf_counter() - t0) * 1000 - call_duration

        logger.info(
            "call_enforced",
            tool=resolved_name,
            decision="allowed",
            overhead_ms=round(overhead, 2),
            call_ms=round(call_duration, 2),
            input_redactions=input_redactions,
            output_redactions=output_redactions,
        )

        self._record_audit(
            tool_name=resolved_name,
            call_id=call_id,
            decision="allowed",
            overhead_ms=round(overhead, 2),
            call_duration_ms=round(call_duration, 2),
            input_redactions=input_redactions,
            output_redactions=output_redactions,
        )

    def _handle_enforcement_violation(
        self,
        exc: EnforcementViolation,
        *,
        resolved_name: str,
        call_id: str,
        t0: float,
        input_redactions: int,
    ) -> None:
        """Audit a blocked call.  Does NOT fire hooks (sync/async differ).

        .. versionadded:: 1.0.0
        """
        elapsed = (time.perf_counter() - t0) * 1000
        self._record_audit(
            tool_name=resolved_name,
            call_id=call_id,
            decision="blocked",
            overhead_ms=round(elapsed, 2),
            call_duration_ms=0.0,
            input_redactions=input_redactions,
            output_redactions=0,
            violation_type=exc.violation_type if hasattr(exc, "violation_type") else None,
            violation_reason=exc.reason if hasattr(exc, "reason") else str(exc),
        )

    def _fail_open_redact_fallback(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        """Attempt PII redaction as fail-open fallback.

        If redaction itself fails, replaces all strings with ``[REDACTED]``.

        .. versionadded:: 1.0.0
        """
        try:
            r_args, r_kwargs, _ = self._redact_args(args, kwargs)
        except Exception:
            r_args = tuple("[REDACTED]" if isinstance(a, str) else a for a in args)
            r_kwargs = {k: "[REDACTED]" if isinstance(v, str) else v for k, v in kwargs.items()}
        return r_args, r_kwargs

    @staticmethod
    def _build_auditor() -> Auditor | None:
        """Create an Auditor from global settings, if audit is enabled.

        Reads ``audit_immutable`` and ``audit_witness_file`` from
        :data:`~enforcecore.core.config.settings` so that users can
        enable tamper-evidence hardening via environment variables:

        - ``ENFORCECORE_AUDIT_IMMUTABLE=true``
        - ``ENFORCECORE_AUDIT_WITNESS_FILE=/var/log/ec-witness.jsonl``

        .. versionchanged:: 1.0.0b5
           Now respects ``audit_immutable`` and ``audit_witness_file``.
        """
        if not settings.audit_enabled:
            return None
        from enforcecore.auditor.engine import Auditor as _Auditor

        witness = None
        if settings.audit_witness_file is not None:
            from enforcecore.auditor.witness import FileWitness

            witness = FileWitness(settings.audit_witness_file)

        return _Auditor(
            output_path=settings.audit_path / "trail.jsonl",
            witness=witness,
            immutable=settings.audit_immutable,
        )

    def _record_audit(
        self,
        *,
        tool_name: str,
        call_id: str,
        decision: str,
        overhead_ms: float,
        call_duration_ms: float,
        input_redactions: int,
        output_redactions: int,
        violation_type: str | None = None,
        violation_reason: str | None = None,
    ) -> None:
        """Record an audit entry if the auditor is active."""
        if self._auditor is None:
            return
        try:
            self._auditor.record(
                tool_name=tool_name,
                policy_name=self._engine.policy.name,
                policy_version=self._engine.policy.version,
                decision=decision,
                call_id=call_id,
                violation_type=violation_type,
                violation_reason=violation_reason,
                overhead_ms=overhead_ms,
                call_duration_ms=call_duration_ms,
                input_redactions=input_redactions,
                output_redactions=output_redactions,
                tenant_id=self._tenant_id,
            )
        except Exception:
            logger.error("audit_record_failed", tool=tool_name, exc_info=True)
            if settings.fail_open:
                # A-2 fix: explicitly warn that the audit trail is now incomplete.
                # The call will succeed but there will be no record of it.
                logger.critical(
                    "audit_trail_incomplete",
                    tool=tool_name,
                    call_id=call_id,
                    decision=decision,
                    message=(
                        "SECURITY: fail_open=True allowed this call to proceed "
                        "but the audit entry could not be written. The tamper-proof "
                        "audit trail is now incomplete for this call."
                    ),
                )
            else:
                raise

    # -- Sync enforcement ---------------------------------------------------

    def enforce_sync(
        self,
        func: Callable[..., T],
        *args: Any,
        tool_name: str | None = None,
        **kwargs: Any,
    ) -> T:
        """Enforce a synchronous call.

        Args:
            func: The callable to enforce.
            *args: Positional arguments for *func*.
            tool_name: Override the tool name (defaults to ``func.__name__``).
            **kwargs: Keyword arguments for *func*.

        Returns:
            The return value of *func* if the call is allowed.

        Raises:
            EnforcementViolation: If the call is blocked by policy.

        .. versionchanged:: 1.0.0
           Refactored to use shared enforcement helpers (M-2).
        """
        resolved_name, ctx, hook_ctx = self._prepare_call(func, args, kwargs, tool_name)

        t0 = time.perf_counter()
        hooks = HookRegistry.global_registry()
        input_redactions = 0
        r_args: tuple[Any, ...] = args
        r_kwargs: dict[str, Any] = dict(kwargs)
        redaction_applied = False

        enter_enforcement(resolved_name)
        try:
            # Fire pre-call hooks (sync)
            hooks.fire_pre_call(hook_ctx)
            if hook_ctx.abort:
                raise EnforcementViolation(
                    hook_ctx.abort_reason or "Aborted by pre-call hook",
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                )

            # Shared pre-call validation
            self._validate_pre_call(args, kwargs, resolved_name, ctx)

            # Redact inputs + cost budget
            r_args, r_kwargs, input_redactions = self._redact_and_check_budget(
                args, kwargs, resolved_name
            )
            redaction_applied = True

            # Fire input redaction hooks (sync)
            if input_redactions > 0:
                hooks.fire_redaction(
                    RedactionHookContext(
                        call_id=ctx.call_id,
                        tool_name=resolved_name,
                        direction="input",
                        redaction_count=input_redactions,
                    )
                )

            # Execute with resource guards (+ optional subprocess sandbox)
            limits = self._engine.policy.rules.resource_limits
            call_t0 = time.perf_counter()
            if self._sandbox is not None:
                result: T = self._sandbox.run(
                    func,
                    *r_args,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                    **r_kwargs,
                )
            else:
                result = self._guard.execute_sync(
                    func,
                    r_args,
                    r_kwargs,
                    max_duration_seconds=limits.max_call_duration_seconds,
                    max_memory_mb=limits.max_memory_mb,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                )
            call_duration = (time.perf_counter() - call_t0) * 1000

            # Shared post-call processing
            result, output_redactions = self._process_result(result, ctx, resolved_name)

            # Fire output redaction hooks (sync)
            if output_redactions > 0:
                hooks.fire_redaction(
                    RedactionHookContext(
                        call_id=ctx.call_id,
                        tool_name=resolved_name,
                        direction="output",
                        redaction_count=output_redactions,
                    )
                )

            # Fire post-call hooks (sync)
            hook_ctx.result = result
            hook_ctx.duration_ms = round(call_duration, 2)
            hook_ctx.input_redactions = input_redactions
            hook_ctx.output_redactions = output_redactions
            hook_ctx.overhead_ms = round((time.perf_counter() - t0) * 1000 - call_duration, 2)
            hooks.fire_post_call(hook_ctx)

            # Log + audit
            self._log_and_audit_allowed(
                resolved_name=resolved_name,
                call_id=ctx.call_id,
                t0=t0,
                call_duration=call_duration,
                input_redactions=input_redactions,
                output_redactions=output_redactions,
            )

            return result

        except EnforcementViolation as exc:
            # Fire violation hooks (sync)
            hooks.fire_violation(
                ViolationHookContext(
                    call_id=ctx.call_id,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                    violation_type=exc.violation_type if hasattr(exc, "violation_type") else "",
                    violation_reason=exc.reason if hasattr(exc, "reason") else str(exc),
                )
            )
            self._handle_enforcement_violation(
                exc,
                resolved_name=resolved_name,
                call_id=ctx.call_id,
                t0=t0,
                input_redactions=input_redactions,
            )
            raise
        except EnforceCoreError as exc:
            if settings.fail_open:
                _warn_fail_open(tool_name=resolved_name, error=exc)
                logger.error(
                    "enforcement_error_fail_open",
                    tool=resolved_name,
                    exc_info=True,
                )
                if not redaction_applied:
                    r_args, r_kwargs = self._fail_open_redact_fallback(args, kwargs)
                return func(*r_args, **r_kwargs)
            raise
        finally:
            exit_enforcement()

    # -- Async enforcement --------------------------------------------------

    async def enforce_async(
        self,
        func: Callable[..., Any],
        *args: Any,
        tool_name: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Enforce an asynchronous call.

        Same semantics as :meth:`enforce_sync` but awaits *func*.

        .. versionchanged:: 1.0.0
           Refactored to use shared enforcement helpers (M-2).
        """
        resolved_name, ctx, hook_ctx = self._prepare_call(func, args, kwargs, tool_name)

        t0 = time.perf_counter()
        hooks = HookRegistry.global_registry()
        input_redactions = 0
        r_args: tuple[Any, ...] = args
        r_kwargs: dict[str, Any] = dict(kwargs)
        redaction_applied = False

        enter_enforcement(resolved_name)
        try:
            # Fire pre-call hooks (async)
            await hooks.fire_pre_call_async(hook_ctx)
            if hook_ctx.abort:
                raise EnforcementViolation(
                    hook_ctx.abort_reason or "Aborted by pre-call hook",
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                )

            # Shared pre-call validation
            self._validate_pre_call(args, kwargs, resolved_name, ctx)

            # Redact inputs + cost budget
            r_args, r_kwargs, input_redactions = self._redact_and_check_budget(
                args, kwargs, resolved_name
            )
            redaction_applied = True

            # Fire input redaction hooks (async)
            if input_redactions > 0:
                await hooks.fire_redaction_async(
                    RedactionHookContext(
                        call_id=ctx.call_id,
                        tool_name=resolved_name,
                        direction="input",
                        redaction_count=input_redactions,
                    )
                )

            # Execute with resource guards (+ optional subprocess sandbox)
            limits = self._engine.policy.rules.resource_limits
            call_t0 = time.perf_counter()
            if self._sandbox is not None:
                result = await self._sandbox.run_async(
                    func,
                    *r_args,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                    **r_kwargs,
                )
            else:
                result = await self._guard.execute_async(
                    func,
                    r_args,
                    r_kwargs,
                    max_duration_seconds=limits.max_call_duration_seconds,
                    max_memory_mb=limits.max_memory_mb,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                )
            call_duration = (time.perf_counter() - call_t0) * 1000

            # Shared post-call processing
            result, output_redactions = self._process_result(result, ctx, resolved_name)

            # Fire output redaction hooks (async)
            if output_redactions > 0:
                await hooks.fire_redaction_async(
                    RedactionHookContext(
                        call_id=ctx.call_id,
                        tool_name=resolved_name,
                        direction="output",
                        redaction_count=output_redactions,
                    )
                )

            # Fire post-call hooks (async)
            hook_ctx.result = result
            hook_ctx.duration_ms = round(call_duration, 2)
            hook_ctx.input_redactions = input_redactions
            hook_ctx.output_redactions = output_redactions
            hook_ctx.overhead_ms = round((time.perf_counter() - t0) * 1000 - call_duration, 2)
            await hooks.fire_post_call_async(hook_ctx)

            # Log + audit
            self._log_and_audit_allowed(
                resolved_name=resolved_name,
                call_id=ctx.call_id,
                t0=t0,
                call_duration=call_duration,
                input_redactions=input_redactions,
                output_redactions=output_redactions,
            )

            return result

        except EnforcementViolation as exc:
            # Fire violation hooks (async)
            await hooks.fire_violation_async(
                ViolationHookContext(
                    call_id=ctx.call_id,
                    tool_name=resolved_name,
                    policy_name=self.policy_name,
                    violation_type=exc.violation_type if hasattr(exc, "violation_type") else "",
                    violation_reason=exc.reason if hasattr(exc, "reason") else str(exc),
                )
            )
            self._handle_enforcement_violation(
                exc,
                resolved_name=resolved_name,
                call_id=ctx.call_id,
                t0=t0,
                input_redactions=input_redactions,
            )
            raise
        except EnforceCoreError as exc:
            if settings.fail_open:
                _warn_fail_open(tool_name=resolved_name, error=exc)
                logger.error(
                    "enforcement_error_fail_open",
                    tool=resolved_name,
                    exc_info=True,
                )
                if not redaction_applied:
                    r_args, r_kwargs = self._fail_open_redact_fallback(args, kwargs)
                return await func(*r_args, **r_kwargs)
            raise
        finally:
            exit_enforcement()

    # NOTE: guard_sync() and guard_async() were removed in v1.0.16.
    # They only performed pre-call checks without redaction, audit, or
    # resource guarding.  Use enforce_sync() / enforce_async() instead.


# ---------------------------------------------------------------------------
# @enforce() decorator — the primary public API
# ---------------------------------------------------------------------------

# Cache of loaded policies to avoid re-parsing YAML on every call.
# FIFO-bounded: oldest entry evicted when cache exceeds max size.
# Each entry stores (Policy, mtime) so file changes are detected.
_POLICY_CACHE_MAX_SIZE = 64
_policy_cache: dict[str, tuple[Policy, float]] = {}
_policy_cache_lock = threading.Lock()


def clear_policy_cache() -> int:
    """Clear the policy cache and return the number of evicted entries."""
    with _policy_cache_lock:
        count = len(_policy_cache)
        _policy_cache.clear()
        return count


def _resolve_policy(
    policy: str | Path | Policy | None,
) -> Policy:
    """Resolve a policy argument to a ``Policy`` instance.

    File-backed policies are cached with their ``st_mtime``. If the file
    has been modified since it was cached, the cache entry is evicted and
    the file is re-loaded automatically.

    .. versionchanged:: 1.0.0
       Cache now tracks file mtime; stale entries are evicted on access.
    """
    if isinstance(policy, Policy):
        return policy

    if isinstance(policy, str | Path):
        return _load_and_cache(str(policy))

    # Fall back to default from settings
    if settings.default_policy is not None:
        return _load_and_cache(str(settings.default_policy))

    from enforcecore.core.types import PolicyLoadError

    raise PolicyLoadError(
        "No policy provided and ENFORCECORE_DEFAULT_POLICY is not set. "
        "Pass a policy path to @enforce(policy=...) or set the env var."
    )


def _load_and_cache(key: str) -> Policy:
    """Load a policy from *key* (file path), caching by (path, mtime).

    If the file's ``st_mtime`` has changed since the cached entry was
    stored, the entry is evicted and the file is re-parsed.
    """
    path = Path(key)
    try:
        current_mtime = path.stat().st_mtime
    except OSError:
        # File may not exist yet — let Policy.from_file raise a clear error
        current_mtime = 0.0

    with _policy_cache_lock:
        cached = _policy_cache.get(key)
        if cached is not None:
            cached_policy, cached_mtime = cached
            if cached_mtime == current_mtime:
                return cached_policy
            # mtime changed → evict stale entry
            logger.info(
                "policy_cache_invalidated",
                path=key,
                old_mtime=cached_mtime,
                new_mtime=current_mtime,
            )
            del _policy_cache[key]

        # Load and cache
        if len(_policy_cache) >= _POLICY_CACHE_MAX_SIZE:
            oldest = next(iter(_policy_cache))
            del _policy_cache[oldest]
        loaded = Policy.from_file(key)
        _policy_cache[key] = (loaded, current_mtime)
        return loaded


@overload
def enforce(func: Callable[..., T]) -> Callable[..., T]: ...


@overload
def enforce(
    *,
    policy: str | Path | Policy | None = None,
    tool_name: str | None = None,
) -> Callable[[Callable[..., T]], Callable[..., T]]: ...


def enforce(
    func: Callable[..., T] | None = None,
    *,
    policy: str | Path | Policy | None = None,
    tool_name: str | None = None,
) -> Callable[..., T] | Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator that wraps a callable with policy enforcement.

    Supports both sync and async callables.  Can be used with or without
    arguments::

        # With arguments
        @enforce(policy="policy.yaml")
        async def my_tool(x: int) -> int: ...

        # Without arguments (uses default policy)
        @enforce
        def my_tool(x: int) -> int: ...

    Args:
        func: When used without parentheses (``@enforce``), the function
            to decorate.
        policy: Path to a YAML policy file, or a ``Policy`` instance.
        tool_name: Override the tool name reported in logs and policy
            evaluation.  Defaults to ``func.__name__``.

    Raises:
        EnforcementViolation: If the call is blocked by policy.
        PolicyLoadError: If the policy file cannot be loaded.
    """

    def decorator(fn: Callable[..., T]) -> Callable[..., T]:
        resolved_policy = _resolve_policy(policy)
        enforcer = Enforcer(resolved_policy)
        name = tool_name or getattr(fn, "__name__", str(fn))

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> T:
                return await enforcer.enforce_async(  # type: ignore[no-any-return]
                    fn, *args, tool_name=name, **kwargs
                )

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def sync_wrapper(*args: Any, **kwargs: Any) -> T:
            return enforcer.enforce_sync(fn, *args, tool_name=name, **kwargs)

        return sync_wrapper

    # Handle @enforce (no parentheses)
    if func is not None:
        return decorator(func)

    return decorator

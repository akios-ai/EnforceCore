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
import time
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar, overload

import structlog

from enforcecore.core.config import settings
from enforcecore.core.policy import Policy, PolicyEngine
from enforcecore.core.types import (
    CallContext,
    EnforceCoreError,
    EnforcementViolation,
)
from enforcecore.redactor.engine import Redactor

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable, Iterator

    from enforcecore.auditor.engine import Auditor
    from enforcecore.guard.engine import ResourceGuard

logger = structlog.get_logger("enforcecore.enforcer")

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Enforcer class
# ---------------------------------------------------------------------------


class Enforcer:
    """Central coordinator for runtime enforcement.

    In v1.0.0, the Enforcer only does policy evaluation (pre/post call).
    Future releases (v1.0.1+) will add redaction, auditing, and resource
    guarding through this same coordinator — without changing the public API.

    The Enforcer is **thread-safe** — it holds no mutable per-call state.
    Each call gets its own ``CallContext``.

    Example::

        enforcer = Enforcer(policy=Policy.from_file("policy.yaml"))
        result = await enforcer.enforce_async(my_tool, "arg1", key="val")
    """

    __slots__ = ("_auditor", "_engine", "_guard", "_redactor")

    def __init__(self, policy: Policy) -> None:
        self._engine = PolicyEngine(policy)
        self._redactor = self._build_redactor(policy)
        self._auditor = self._build_auditor()
        self._guard = self._build_guard()

    @classmethod
    def from_file(cls, path: str | Path) -> Enforcer:
        """Create an enforcer from a YAML policy file."""
        return cls(Policy.from_file(path))

    @property
    def policy(self) -> Policy:
        return self._engine.policy

    @property
    def policy_name(self) -> str:
        return self._engine.policy.name

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
        pii_cfg = policy.rules.pii_redaction
        if not pii_cfg.enabled or not settings.redaction_enabled:
            return None
        return Redactor(
            categories=pii_cfg.categories,
            strategy=pii_cfg.strategy,
        )

    def _redact_args(
        self,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> tuple[tuple[Any, ...], dict[str, Any], int]:
        """Redact string args and kwargs. Returns (new_args, new_kwargs, count)."""
        if self._redactor is None:
            return args, kwargs, 0

        total = 0
        new_args = []
        for a in args:
            if isinstance(a, str):
                res = self._redactor.redact(a)
                new_args.append(res.text)
                total += res.count
            else:
                new_args.append(a)

        new_kwargs = {}
        for k, v in kwargs.items():
            if isinstance(v, str):
                res = self._redactor.redact(v)
                new_kwargs[k] = res.text
                total += res.count
            else:
                new_kwargs[k] = v

        return tuple(new_args), new_kwargs, total

    def _redact_output(self, result: Any) -> tuple[Any, int]:
        """Redact PII from output if it's a string."""
        if self._redactor is None or not isinstance(result, str):
            return result, 0
        res = self._redactor.redact(result)
        return res.text, res.count

    @staticmethod
    def _build_auditor() -> Auditor | None:
        """Create an Auditor from global settings, if audit is enabled."""
        if not settings.audit_enabled:
            return None
        from enforcecore.auditor.engine import Auditor as _Auditor

        return _Auditor(output_path=settings.audit_path / "trail.jsonl")

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
            )
        except Exception:
            logger.error("audit_record_failed", tool=tool_name, exc_info=True)
            if not settings.fail_open:
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
        """
        resolved_name = tool_name if tool_name is not None else str(getattr(func, "__name__", func))
        ctx = CallContext(tool_name=resolved_name, args=args, kwargs=kwargs)

        t0 = time.perf_counter()

        try:
            # Pre-call
            pre = self._engine.evaluate_pre_call(ctx)
            self._engine.raise_if_blocked(pre, ctx)

            # Redact inputs
            r_args, r_kwargs, input_redactions = self._redact_args(args, kwargs)

            # Check cost budget before execution
            limits = self._engine.policy.rules.resource_limits
            self._guard.cost_tracker.check_budget(
                resolved_name,
                self.policy_name,
                per_call_budget=limits.max_cost_usd,
            )

            # Execute with resource guards (time/memory limits)
            call_t0 = time.perf_counter()
            result: T = self._guard.execute_sync(
                func,
                r_args,
                r_kwargs,
                max_duration_seconds=limits.max_call_duration_seconds,
                max_memory_mb=limits.max_memory_mb,
                tool_name=resolved_name,
                policy_name=self.policy_name,
            )
            call_duration = (time.perf_counter() - call_t0) * 1000

            # Redact outputs
            result, output_redactions = self._redact_output(result)

            # Post-call
            post = self._engine.evaluate_post_call(ctx, result)
            self._engine.raise_if_blocked(post, ctx)

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

            # Audit
            self._record_audit(
                tool_name=resolved_name,
                call_id=ctx.call_id,
                decision="allowed",
                overhead_ms=round(overhead, 2),
                call_duration_ms=round(call_duration, 2),
                input_redactions=input_redactions,
                output_redactions=output_redactions,
            )

            return result

        except EnforcementViolation as exc:
            # Record blocked calls too
            elapsed = (time.perf_counter() - t0) * 1000
            self._record_audit(
                tool_name=resolved_name,
                call_id=ctx.call_id,
                decision="blocked",
                overhead_ms=round(elapsed, 2),
                call_duration_ms=0.0,
                input_redactions=0,
                output_redactions=0,
                violation_type=exc.violation_type if hasattr(exc, "violation_type") else None,
                violation_reason=exc.reason if hasattr(exc, "reason") else str(exc),
            )
            raise
        except EnforceCoreError:
            # Internal error — fail closed
            if settings.fail_open:
                logger.error(
                    "enforcement_error_fail_open",
                    tool=resolved_name,
                    exc_info=True,
                )
                return func(*args, **kwargs)
            raise

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
        """
        resolved_name = tool_name if tool_name is not None else str(getattr(func, "__name__", func))
        ctx = CallContext(tool_name=resolved_name, args=args, kwargs=kwargs)

        t0 = time.perf_counter()

        try:
            # Pre-call
            pre = self._engine.evaluate_pre_call(ctx)
            self._engine.raise_if_blocked(pre, ctx)

            # Redact inputs
            r_args, r_kwargs, input_redactions = self._redact_args(args, kwargs)

            # Check cost budget before execution
            limits = self._engine.policy.rules.resource_limits
            self._guard.cost_tracker.check_budget(
                resolved_name,
                self.policy_name,
                per_call_budget=limits.max_cost_usd,
            )

            # Execute with resource guards (time/memory limits)
            call_t0 = time.perf_counter()
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

            # Redact outputs
            result, output_redactions = self._redact_output(result)

            # Post-call
            post = self._engine.evaluate_post_call(ctx, result)
            self._engine.raise_if_blocked(post, ctx)

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

            # Audit
            self._record_audit(
                tool_name=resolved_name,
                call_id=ctx.call_id,
                decision="allowed",
                overhead_ms=round(overhead, 2),
                call_duration_ms=round(call_duration, 2),
                input_redactions=input_redactions,
                output_redactions=output_redactions,
            )

            return result

        except EnforcementViolation as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            self._record_audit(
                tool_name=resolved_name,
                call_id=ctx.call_id,
                decision="blocked",
                overhead_ms=round(elapsed, 2),
                call_duration_ms=0.0,
                input_redactions=0,
                output_redactions=0,
                violation_type=exc.violation_type if hasattr(exc, "violation_type") else None,
                violation_reason=exc.reason if hasattr(exc, "reason") else str(exc),
            )
            raise
        except EnforceCoreError:
            if settings.fail_open:
                logger.error(
                    "enforcement_error_fail_open",
                    tool=resolved_name,
                    exc_info=True,
                )
                return await func(*args, **kwargs)
            raise

    # -- Context managers ---------------------------------------------------

    @contextmanager
    def guard_sync(
        self,
        tool_name: str,
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
    ) -> Iterator[CallContext]:
        """Synchronous context manager for enforcement.

        Usage::

            with enforcer.guard_sync("my_tool") as ctx:
                result = do_something()
        """
        ctx = CallContext(
            tool_name=tool_name,
            args=args,
            kwargs=kwargs or {},
        )
        pre = self._engine.evaluate_pre_call(ctx)
        self._engine.raise_if_blocked(pre, ctx)
        yield ctx

    @asynccontextmanager
    async def guard_async(
        self,
        tool_name: str,
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
    ) -> AsyncIterator[CallContext]:
        """Asynchronous context manager for enforcement.

        Usage::

            async with enforcer.guard_async("my_tool") as ctx:
                result = await do_something()
        """
        ctx = CallContext(
            tool_name=tool_name,
            args=args,
            kwargs=kwargs or {},
        )
        pre = self._engine.evaluate_pre_call(ctx)
        self._engine.raise_if_blocked(pre, ctx)
        yield ctx


# ---------------------------------------------------------------------------
# @enforce() decorator — the primary public API
# ---------------------------------------------------------------------------

# Cache of loaded policies to avoid re-parsing YAML on every call.
_policy_cache: dict[str, Policy] = {}


def _resolve_policy(
    policy: str | Path | Policy | None,
) -> Policy:
    """Resolve a policy argument to a ``Policy`` instance."""
    if isinstance(policy, Policy):
        return policy

    if isinstance(policy, (str, Path)):
        key = str(policy)
        if key not in _policy_cache:
            _policy_cache[key] = Policy.from_file(key)
        return _policy_cache[key]

    # Fall back to default from settings
    if settings.default_policy is not None:
        key = str(settings.default_policy)
        if key not in _policy_cache:
            _policy_cache[key] = Policy.from_file(key)
        return _policy_cache[key]

    from enforcecore.core.types import PolicyLoadError

    raise PolicyLoadError(
        "No policy provided and ENFORCECORE_DEFAULT_POLICY is not set. "
        "Pass a policy path to @enforce(policy=...) or set the env var."
    )


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

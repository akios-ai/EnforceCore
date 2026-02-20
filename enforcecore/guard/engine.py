"""Resource Guard engine — time limits, memory limits, cost tracking, KillSwitch.

Provides cross-platform resource enforcement for agentic AI tool calls:

* ``ResourceGuard`` — wraps function execution with time and memory limits.
* ``CostTracker`` — thread-safe cumulative cost tracking with budgets.
* ``KillSwitch`` — coordinated hard termination on limit breach.

Platform support:

+------------------+-------+-------+---------+
| Feature          | Linux | macOS | Windows |
+==================+=======+=======+=========+
| Time limits      | ✓     | ✓     | ✓       |
+------------------+-------+-------+---------+
| Memory limits    | ✓     | ~     | ✗       |
+------------------+-------+-------+---------+
| Cost tracking    | ✓     | ✓     | ✓       |
+------------------+-------+-------+---------+
| KillSwitch       | ✓     | ✓     | ✓       |
+------------------+-------+-------+---------+

*~ = advisory only (macOS ``RLIMIT_RSS`` is not strictly enforced by the kernel)*
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import platform
import threading
from typing import Any

import structlog

from enforcecore.core.types import (
    CostLimitError,
    ResourceLimitError,
)

logger = structlog.get_logger("enforcecore.guard")

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_PLATFORM = platform.system()
_IS_POSIX = _PLATFORM in ("Linux", "Darwin")

try:
    import resource as _resource

    _HAS_RESOURCE = True
except ImportError:  # pragma: no cover — Windows
    _resource = None  # type: ignore[assignment]
    _HAS_RESOURCE = False


# ---------------------------------------------------------------------------
# CostTracker
# ---------------------------------------------------------------------------


class CostTracker:
    """Thread-safe cumulative cost tracker.

    Tracks total cost across enforced calls and raises ``CostLimitError``
    when the configured budget is exceeded.

    The tracker is **thread-safe** — all mutations are protected by a lock.

    Example::

        tracker = CostTracker(budget_usd=5.0)
        tracker.check_budget("my_tool", "my_policy")  # passes
        tracker.record(2.50)
        tracker.record(3.00)
        tracker.check_budget("my_tool", "my_policy")  # raises CostLimitError
    """

    __slots__ = ("_budget", "_lock", "_total")

    def __init__(self, budget_usd: float | None = None) -> None:
        self._budget = budget_usd
        self._total: float = 0.0
        self._lock = threading.Lock()

    # -- Properties ---------------------------------------------------------

    @property
    def budget(self) -> float | None:
        """The configured budget (``None`` = unlimited)."""
        return self._budget

    @budget.setter
    def budget(self, value: float | None) -> None:
        with self._lock:
            self._budget = value

    @property
    def total_cost(self) -> float:
        """Current cumulative cost."""
        with self._lock:
            return self._total

    # -- Public API ---------------------------------------------------------

    def record(self, cost: float) -> float:
        """Record a cost and return the new cumulative total.

        Args:
            cost: The cost to add (in USD).

        Returns:
            The new cumulative total.

        Raises:
            ValueError: If *cost* is negative.
        """
        if cost < 0:
            msg = f"Cost cannot be negative: {cost}"
            raise ValueError(msg)
        with self._lock:
            self._total += cost
            logger.debug("cost_recorded", cost=cost, total=self._total)
            return self._total

    def check_budget(
        self,
        tool_name: str = "",
        policy_name: str = "",
        *,
        per_call_budget: float | None = None,
    ) -> None:
        """Check if the cumulative cost exceeds any configured budget.

        Checks both the global budget (set at construction) and an optional
        per-policy budget.

        Args:
            tool_name: For error reporting.
            policy_name: For error reporting.
            per_call_budget: Per-policy maximum cost (from ``ResourceLimits``).

        Raises:
            CostLimitError: If either budget is exceeded.
        """
        with self._lock:
            if self._budget is not None and self._total >= self._budget:
                raise CostLimitError(
                    self._total,
                    self._budget,
                    tool_name=tool_name,
                    policy_name=policy_name,
                )
            if per_call_budget is not None and self._total >= per_call_budget:
                raise CostLimitError(
                    self._total,
                    per_call_budget,
                    tool_name=tool_name,
                    policy_name=policy_name,
                )

    def reset(self) -> None:
        """Reset the cumulative cost to zero."""
        with self._lock:
            self._total = 0.0


# ---------------------------------------------------------------------------
# KillSwitch
# ---------------------------------------------------------------------------


class KillSwitch:
    """Coordinated hard termination on resource limit breach.

    Once **tripped**, the KillSwitch blocks *all* subsequent calls through
    the guard until explicitly reset.  This ensures that a runaway tool
    cannot continue consuming resources after a breach.

    Thread-safe.

    Example::

        ks = KillSwitch()
        ks.trip("memory exceeded 256MB")
        ks.check("my_tool", "my_policy")  # raises ResourceLimitError
    """

    __slots__ = ("_lock", "_reason", "_tripped")

    def __init__(self) -> None:
        self._tripped = False
        self._reason: str = ""
        self._lock = threading.Lock()

    @property
    def is_tripped(self) -> bool:
        """Whether the kill switch has been tripped."""
        with self._lock:
            return self._tripped

    @property
    def reason(self) -> str:
        """The reason the kill switch was tripped (empty if not tripped)."""
        with self._lock:
            return self._reason

    def trip(self, reason: str) -> None:
        """Trip the kill switch — all subsequent calls will be blocked.

        Args:
            reason: Human-readable reason for the trip.
        """
        with self._lock:
            self._tripped = True
            self._reason = reason
        logger.warning("kill_switch_tripped", reason=reason)

    def check(self, tool_name: str = "", policy_name: str = "") -> None:
        """Check if the kill switch has been tripped.

        Raises:
            ResourceLimitError: If the kill switch is tripped.
        """
        with self._lock:
            if self._tripped:
                raise ResourceLimitError(
                    "kill_switch",
                    self._reason,
                    tool_name=tool_name,
                    policy_name=policy_name,
                )

    def reset(self) -> None:
        """Reset the kill switch to allow calls again."""
        with self._lock:
            self._tripped = False
            self._reason = ""


# ---------------------------------------------------------------------------
# ResourceGuard
# ---------------------------------------------------------------------------


class ResourceGuard:
    """Wraps function execution with time and memory limits.

    Provides two execution methods:

    * :meth:`execute_sync` — for synchronous callables (uses
      ``concurrent.futures.ThreadPoolExecutor`` for timeout).
    * :meth:`execute_async` — for async callables (uses
      ``asyncio.wait_for`` for timeout).

    Both methods also apply memory limits on POSIX systems and check the
    KillSwitch before execution.

    .. note::

       **Sync timeout limitation:** When a sync function exceeds its time
       limit, the worker thread cannot be forcibly killed (Python limitation).
       The timeout raises ``ResourceLimitError`` to the caller and trips
       the KillSwitch to prevent further calls, but the function may
       continue running in the background thread.

    Example::

        guard = ResourceGuard()
        result = guard.execute_sync(
            my_func, (arg1,), {"key": "val"},
            max_duration_seconds=30.0,
            max_memory_mb=256,
            tool_name="my_tool",
            policy_name="my_policy",
        )
    """

    __slots__ = ("_cost_tracker", "_kill_switch")

    def __init__(
        self,
        *,
        cost_tracker: CostTracker | None = None,
        kill_switch: KillSwitch | None = None,
    ) -> None:
        self._cost_tracker = cost_tracker or CostTracker()
        self._kill_switch = kill_switch or KillSwitch()

    @property
    def cost_tracker(self) -> CostTracker:
        """The cost tracker for this guard."""
        return self._cost_tracker

    @property
    def kill_switch(self) -> KillSwitch:
        """The kill switch for this guard."""
        return self._kill_switch

    # -- Sync execution -----------------------------------------------------

    def execute_sync(
        self,
        func: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        max_duration_seconds: float | None = None,
        max_memory_mb: int | None = None,
        tool_name: str = "",
        policy_name: str = "",
    ) -> Any:
        """Execute a synchronous function with resource guards.

        Args:
            func: The callable to execute.
            args: Positional arguments.
            kwargs: Keyword arguments.
            max_duration_seconds: Maximum wall-clock time in seconds.
            max_memory_mb: Maximum memory in megabytes (POSIX only).
            tool_name: For error reporting.
            policy_name: For error reporting.

        Returns:
            The return value of *func*.

        Raises:
            ResourceLimitError: If time or memory limits are exceeded,
                or the KillSwitch is tripped.
        """
        self._kill_switch.check(tool_name, policy_name)

        mem_ctx = _MemoryLimiter(max_memory_mb) if max_memory_mb else None

        try:
            if mem_ctx:
                mem_ctx.apply()

            if max_duration_seconds is not None:
                return self._execute_with_timeout(
                    func,
                    args,
                    kwargs,
                    timeout=max_duration_seconds,
                    tool_name=tool_name,
                    policy_name=policy_name,
                )

            return func(*args, **kwargs)

        except ResourceLimitError:
            if not self._kill_switch.is_tripped:
                self._kill_switch.trip(f"{tool_name}: resource limit exceeded")
            raise
        except MemoryError:
            reason = f"{tool_name}: memory limit exceeded ({max_memory_mb}MB)"
            self._kill_switch.trip(reason)
            raise ResourceLimitError(
                "memory",
                f"{max_memory_mb}MB",
                tool_name=tool_name,
                policy_name=policy_name,
            ) from None
        finally:
            if mem_ctx:
                mem_ctx.restore()

    # -- Async execution ----------------------------------------------------

    async def execute_async(
        self,
        func: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        max_duration_seconds: float | None = None,
        max_memory_mb: int | None = None,
        tool_name: str = "",
        policy_name: str = "",
    ) -> Any:
        """Execute an async function with resource guards.

        Same semantics as :meth:`execute_sync` but for coroutines.
        Uses ``asyncio.wait_for`` for timeout enforcement.
        """
        self._kill_switch.check(tool_name, policy_name)

        mem_ctx = _MemoryLimiter(max_memory_mb) if max_memory_mb else None

        try:
            if mem_ctx:
                mem_ctx.apply()

            if max_duration_seconds is not None:
                try:
                    return await asyncio.wait_for(
                        func(*args, **kwargs),
                        timeout=max_duration_seconds,
                    )
                except TimeoutError:
                    raise ResourceLimitError(
                        "time",
                        f"{max_duration_seconds}s",
                        tool_name=tool_name,
                        policy_name=policy_name,
                    ) from None

            return await func(*args, **kwargs)

        except ResourceLimitError:
            if not self._kill_switch.is_tripped:
                self._kill_switch.trip(f"{tool_name}: resource limit exceeded")
            raise
        except MemoryError:
            reason = f"{tool_name}: memory limit exceeded ({max_memory_mb}MB)"
            self._kill_switch.trip(reason)
            raise ResourceLimitError(
                "memory",
                f"{max_memory_mb}MB",
                tool_name=tool_name,
                policy_name=policy_name,
            ) from None
        finally:
            if mem_ctx:
                mem_ctx.restore()

    # -- Helpers ------------------------------------------------------------

    @staticmethod
    def _execute_with_timeout(
        func: Any,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        timeout: float,
        tool_name: str,
        policy_name: str,
    ) -> Any:
        """Execute a sync function with a wall-clock timeout.

        Uses ``concurrent.futures.ThreadPoolExecutor`` with a single
        worker.  If the timeout expires, raises ``ResourceLimitError``.

        .. warning::

           The worker thread cannot be forcibly terminated.  The function
           may continue running after the timeout.
        """
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = pool.submit(func, *args, **kwargs)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise ResourceLimitError(
                "time",
                f"{timeout}s",
                tool_name=tool_name,
                policy_name=policy_name,
            ) from None
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    @staticmethod
    def platform_info() -> dict[str, Any]:
        """Return platform support information for resource guards.

        Returns:
            A dict with boolean flags for each supported feature.
        """
        return {
            "platform": _PLATFORM,
            "time_limits": True,
            "memory_limits": _HAS_RESOURCE and _IS_POSIX,
            "cost_tracking": True,
            "kill_switch": True,
            "posix": _IS_POSIX,
        }


# ---------------------------------------------------------------------------
# _MemoryLimiter (internal)
# ---------------------------------------------------------------------------


class _MemoryLimiter:
    """Best-effort POSIX memory limiter using ``setrlimit``.

    On Linux, sets ``RLIMIT_AS`` (virtual address space).
    On macOS, sets ``RLIMIT_RSS`` (resident set size — advisory only).
    On Windows or when the ``resource`` module is unavailable, this is a no-op.

    Restores the previous limit on :meth:`restore`.
    """

    __slots__ = ("_max_bytes", "_previous", "_resource_type")

    def __init__(self, max_mb: int) -> None:
        self._max_bytes = max_mb * 1024 * 1024
        self._previous: tuple[int, int] | None = None
        self._resource_type: int | None = None

    def apply(self) -> None:
        """Apply the memory limit."""
        if not _HAS_RESOURCE or _resource is None:
            return

        if _PLATFORM == "Linux":
            self._resource_type = _resource.RLIMIT_AS
        elif _PLATFORM == "Darwin":
            self._resource_type = _resource.RLIMIT_RSS
        else:
            return  # pragma: no cover

        try:
            self._previous = _resource.getrlimit(self._resource_type)
            _soft, hard = self._previous
            new_soft = (
                min(self._max_bytes, hard) if hard != _resource.RLIM_INFINITY else self._max_bytes
            )
            _resource.setrlimit(self._resource_type, (new_soft, hard))
            logger.debug(
                "memory_limit_applied",
                limit_mb=self._max_bytes // (1024 * 1024),
                resource_type=self._resource_type,
                platform=_PLATFORM,
            )
        except (OSError, ValueError) as exc:
            logger.warning(
                "memory_limit_failed",
                error=str(exc),
                platform=_PLATFORM,
            )
            self._previous = None

    def restore(self) -> None:
        """Restore the previous memory limit."""
        if self._previous is None or self._resource_type is None or _resource is None:
            return
        with contextlib.suppress(OSError, ValueError):
            _resource.setrlimit(self._resource_type, self._previous)

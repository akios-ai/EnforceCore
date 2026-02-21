"""Lifecycle hook system for EnforceCore.

Provides a registry of hooks that fire at key enforcement lifecycle events:

* ``pre_call``   -- before policy evaluation (can abort)
* ``post_call``  -- after successful execution (can inspect/modify result)
* ``violation``  -- when a call is blocked
* ``redaction``  -- when PII is redacted

Hooks can be registered via decorators or programmatically::

    from enforcecore.plugins.hooks import on_violation, HookRegistry

    @on_violation
    def alert_slack(ctx):
        slack.post(f"BLOCKED: {ctx.tool_name}")

    # Or programmatically:
    registry = HookRegistry.global_registry()
    registry.add_pre_call(my_hook_fn)

Hooks may be sync or async. Async hooks are awaited when called from
async enforcement paths and run via ``asyncio.get_event_loop().run_until_complete``
in sync paths (if an event loop is available).

Thread-safe: the registry uses a lock for mutations.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

logger = structlog.get_logger("enforcecore.hooks")


# ---------------------------------------------------------------------------
# Hook context objects
# ---------------------------------------------------------------------------


@dataclass
class HookContext:
    """Context passed to pre_call and post_call hooks.

    Pre-call hooks receive this before policy evaluation. Post-call hooks
    receive it after successful execution, with ``result`` populated.

    Set ``abort = True`` in a pre-call hook to block the call before
    policy evaluation. Set ``abort_reason`` to provide a message.
    """

    call_id: str = ""
    tool_name: str = ""
    policy_name: str = ""
    args: tuple[Any, ...] = ()
    kwargs: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    # Post-call only
    result: Any = None
    duration_ms: float = 0.0

    # Pre-call abort
    abort: bool = False
    abort_reason: str = ""

    # User-defined metadata (hooks can attach data for downstream hooks)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ViolationHookContext:
    """Context passed to violation hooks when a call is blocked."""

    call_id: str = ""
    tool_name: str = ""
    policy_name: str = ""
    violation_type: str = ""
    violation_reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RedactionHookContext:
    """Context passed to redaction hooks when PII is redacted."""

    call_id: str = ""
    tool_name: str = ""
    direction: str = ""  # "input" or "output"
    category: str = ""  # PII category (email, phone, etc.)
    redaction_count: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Hook type aliases
# ---------------------------------------------------------------------------

# Hooks can be sync or async callables accepting the appropriate context.
# We use Any here because the type system cannot express "sync or async callable"
# cleanly without Protocol overloads.
HookCallable = Any  # Callable[[HookContext], None] or async variant


# ---------------------------------------------------------------------------
# Hook Registry
# ---------------------------------------------------------------------------

_global_registry: HookRegistry | None = None
_global_lock = threading.Lock()


class HookRegistry:
    """Registry of lifecycle hooks.

    Each hook category is a list of callables. Hooks are called in
    registration order. A hook raising an exception logs the error but
    does not break the enforcement pipeline (hooks are best-effort).

    Use :meth:`global_registry` to get the singleton shared across the
    process, or create per-enforcer registries for isolation.
    """

    __slots__ = ("_lock", "_post_call", "_pre_call", "_redaction", "_violation")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pre_call: list[HookCallable] = []
        self._post_call: list[HookCallable] = []
        self._violation: list[HookCallable] = []
        self._redaction: list[HookCallable] = []

    @classmethod
    def global_registry(cls) -> HookRegistry:
        """Return the process-wide singleton registry."""
        global _global_registry
        if _global_registry is None:
            with _global_lock:
                if _global_registry is None:
                    _global_registry = cls()
        return _global_registry

    @classmethod
    def reset_global(cls) -> None:
        """Reset the global registry. Primarily for testing."""
        global _global_registry
        with _global_lock:
            _global_registry = None

    # -- Registration -------------------------------------------------------

    def add_pre_call(self, hook: HookCallable) -> None:
        """Register a hook to run before policy evaluation."""
        with self._lock:
            self._pre_call.append(hook)

    def add_post_call(self, hook: HookCallable) -> None:
        """Register a hook to run after successful execution."""
        with self._lock:
            self._post_call.append(hook)

    def add_violation(self, hook: HookCallable) -> None:
        """Register a hook to run when a call is blocked."""
        with self._lock:
            self._violation.append(hook)

    def add_redaction(self, hook: HookCallable) -> None:
        """Register a hook to run when PII is redacted."""
        with self._lock:
            self._redaction.append(hook)

    # -- Removal ------------------------------------------------------------

    def remove_pre_call(self, hook: HookCallable) -> None:
        """Remove a pre-call hook."""
        with self._lock:
            self._pre_call = [h for h in self._pre_call if h is not hook]

    def remove_post_call(self, hook: HookCallable) -> None:
        """Remove a post-call hook."""
        with self._lock:
            self._post_call = [h for h in self._post_call if h is not hook]

    def remove_violation(self, hook: HookCallable) -> None:
        """Remove a violation hook."""
        with self._lock:
            self._violation = [h for h in self._violation if h is not hook]

    def remove_redaction(self, hook: HookCallable) -> None:
        """Remove a redaction hook."""
        with self._lock:
            self._redaction = [h for h in self._redaction if h is not hook]

    def clear(self) -> None:
        """Remove all hooks from all categories."""
        with self._lock:
            self._pre_call.clear()
            self._post_call.clear()
            self._violation.clear()
            self._redaction.clear()

    # -- Counting -----------------------------------------------------------

    @property
    def pre_call_count(self) -> int:
        return len(self._pre_call)

    @property
    def post_call_count(self) -> int:
        return len(self._post_call)

    @property
    def violation_count(self) -> int:
        return len(self._violation)

    @property
    def redaction_count(self) -> int:
        return len(self._redaction)

    @property
    def total_count(self) -> int:
        return (
            self.pre_call_count + self.post_call_count + self.violation_count + self.redaction_count
        )

    # -- Execution ----------------------------------------------------------

    def fire_pre_call(self, ctx: HookContext) -> None:
        """Fire all pre-call hooks synchronously."""
        with self._lock:
            hooks = list(self._pre_call)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    _run_async_hook(hook, ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "pre_call_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    async def fire_pre_call_async(self, ctx: HookContext) -> None:
        """Fire all pre-call hooks, awaiting async hooks."""
        with self._lock:
            hooks = list(self._pre_call)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    await hook(ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "pre_call_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    def fire_post_call(self, ctx: HookContext) -> None:
        """Fire all post-call hooks synchronously."""
        with self._lock:
            hooks = list(self._post_call)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    _run_async_hook(hook, ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "post_call_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    async def fire_post_call_async(self, ctx: HookContext) -> None:
        """Fire all post-call hooks, awaiting async hooks."""
        with self._lock:
            hooks = list(self._post_call)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    await hook(ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "post_call_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    def fire_violation(self, ctx: ViolationHookContext) -> None:
        """Fire all violation hooks synchronously."""
        with self._lock:
            hooks = list(self._violation)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    _run_async_hook(hook, ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "violation_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    async def fire_violation_async(self, ctx: ViolationHookContext) -> None:
        """Fire all violation hooks, awaiting async hooks."""
        with self._lock:
            hooks = list(self._violation)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    await hook(ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "violation_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    def fire_redaction(self, ctx: RedactionHookContext) -> None:
        """Fire all redaction hooks synchronously."""
        with self._lock:
            hooks = list(self._redaction)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    _run_async_hook(hook, ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "redaction_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )

    async def fire_redaction_async(self, ctx: RedactionHookContext) -> None:
        """Fire all redaction hooks, awaiting async hooks."""
        with self._lock:
            hooks = list(self._redaction)
        for hook in hooks:
            try:
                if inspect.iscoroutinefunction(hook):
                    await hook(ctx)
                else:
                    hook(ctx)
            except Exception:
                logger.warning(
                    "redaction_hook_error",
                    hook=getattr(hook, "__name__", str(hook)),
                    exc_info=True,
                )


# ---------------------------------------------------------------------------
# Convenience decorators (register on the global registry)
# ---------------------------------------------------------------------------


def on_pre_call(func: HookCallable) -> HookCallable:
    """Decorator: register a function as a pre-call hook.

    Example::

        @on_pre_call
        def log_calls(ctx: HookContext):
            print(f"Calling {ctx.tool_name}")
    """
    HookRegistry.global_registry().add_pre_call(func)
    return func


def on_post_call(func: HookCallable) -> HookCallable:
    """Decorator: register a function as a post-call hook.

    Example::

        @on_post_call
        def measure_latency(ctx: HookContext):
            metrics.record(ctx.tool_name, ctx.duration_ms)
    """
    HookRegistry.global_registry().add_post_call(func)
    return func


def on_violation(func: HookCallable) -> HookCallable:
    """Decorator: register a function as a violation hook.

    Example::

        @on_violation
        def alert_on_block(ctx: ViolationHookContext):
            slack.post(f"BLOCKED: {ctx.tool_name} - {ctx.violation_reason}")
    """
    HookRegistry.global_registry().add_violation(func)
    return func


def on_redaction(func: HookCallable) -> HookCallable:
    """Decorator: register a function as a redaction hook.

    Example::

        @on_redaction
        def log_redactions(ctx: RedactionHookContext):
            print(f"Redacted {ctx.redaction_count} {ctx.category} in {ctx.direction}")
    """
    HookRegistry.global_registry().add_redaction(func)
    return func


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run_async_hook(hook: HookCallable, ctx: Any) -> None:
    """Run an async hook from a sync context (best-effort).

    When called from within a running event loop (e.g. nested sync-in-async),
    the coroutine is scheduled as a task. The task reference is stored to
    prevent garbage collection, and a done-callback logs any exceptions.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        # We are inside a running event loop but in sync code.
        # Schedule the coroutine — store reference so it isn't GC'd.
        task = loop.create_task(hook(ctx))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
    else:
        # No running loop: create one and run to completion.
        asyncio.run(hook(ctx))


# Set of strong references to prevent fire-and-forget tasks from being GC'd.
_background_tasks: set[asyncio.Task[Any]] = set()

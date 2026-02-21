"""Tests for the lifecycle hook system."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

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

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_global_registry():
    """Reset the global HookRegistry before every test."""
    HookRegistry.reset_global()
    yield
    HookRegistry.reset_global()


@pytest.fixture
def registry() -> HookRegistry:
    """Fresh isolated registry for each test."""
    return HookRegistry()


@pytest.fixture
def hook_ctx() -> HookContext:
    return HookContext(
        call_id="test-id",
        tool_name="search_web",
        policy_name="strict",
        args=("hello",),
        kwargs={"limit": 5},
    )


@pytest.fixture
def violation_ctx() -> ViolationHookContext:
    return ViolationHookContext(
        call_id="test-id",
        tool_name="search_web",
        policy_name="strict",
        violation_type="tool_not_allowed",
        violation_reason="Not on allow list",
    )


@pytest.fixture
def redaction_ctx() -> RedactionHookContext:
    return RedactionHookContext(
        call_id="test-id",
        tool_name="search_web",
        direction="input",
        category="email",
        redaction_count=3,
    )


# ---------------------------------------------------------------------------
# HookContext dataclass
# ---------------------------------------------------------------------------


class TestHookContext:
    def test_defaults(self):
        ctx = HookContext()
        assert ctx.call_id == ""
        assert ctx.tool_name == ""
        assert ctx.abort is False
        assert ctx.abort_reason == ""
        assert ctx.result is None
        assert ctx.duration_ms == 0.0
        assert ctx.metadata == {}

    def test_abort_flag(self, hook_ctx: HookContext):
        hook_ctx.abort = True
        hook_ctx.abort_reason = "custom reason"
        assert hook_ctx.abort is True
        assert hook_ctx.abort_reason == "custom reason"

    def test_metadata_attachment(self, hook_ctx: HookContext):
        hook_ctx.metadata["trace_id"] = "abc-123"
        assert hook_ctx.metadata["trace_id"] == "abc-123"


class TestViolationHookContext:
    def test_violation_fields(self, violation_ctx: ViolationHookContext):
        assert violation_ctx.violation_type == "tool_not_allowed"
        assert violation_ctx.violation_reason == "Not on allow list"
        assert violation_ctx.timestamp  # non-empty


class TestRedactionHookContext:
    def test_redaction_fields(self, redaction_ctx: RedactionHookContext):
        assert redaction_ctx.direction == "input"
        assert redaction_ctx.category == "email"
        assert redaction_ctx.redaction_count == 3


# ---------------------------------------------------------------------------
# HookRegistry — registration and counting
# ---------------------------------------------------------------------------


class TestHookRegistryRegistration:
    def test_add_pre_call(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_pre_call(fn)
        assert registry.pre_call_count == 1

    def test_add_post_call(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_post_call(fn)
        assert registry.post_call_count == 1

    def test_add_violation(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_violation(fn)
        assert registry.violation_count == 1

    def test_add_redaction(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_redaction(fn)
        assert registry.redaction_count == 1

    def test_total_count(self, registry: HookRegistry):
        for _ in range(2):
            registry.add_pre_call(MagicMock())
        registry.add_post_call(MagicMock())
        registry.add_violation(MagicMock())
        registry.add_redaction(MagicMock())
        assert registry.total_count == 5

    def test_multiple_hooks_same_category(self, registry: HookRegistry):
        for _ in range(5):
            registry.add_pre_call(MagicMock())
        assert registry.pre_call_count == 5


# ---------------------------------------------------------------------------
# HookRegistry — removal
# ---------------------------------------------------------------------------


class TestHookRegistryRemoval:
    def test_remove_pre_call(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_pre_call(fn)
        registry.remove_pre_call(fn)
        assert registry.pre_call_count == 0

    def test_remove_post_call(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_post_call(fn)
        registry.remove_post_call(fn)
        assert registry.post_call_count == 0

    def test_remove_violation(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_violation(fn)
        registry.remove_violation(fn)
        assert registry.violation_count == 0

    def test_remove_redaction(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_redaction(fn)
        registry.remove_redaction(fn)
        assert registry.redaction_count == 0

    def test_remove_nonexistent_does_not_error(self, registry: HookRegistry):
        registry.remove_pre_call(MagicMock())
        assert registry.pre_call_count == 0

    def test_clear_all_categories(self, registry: HookRegistry):
        registry.add_pre_call(MagicMock())
        registry.add_post_call(MagicMock())
        registry.add_violation(MagicMock())
        registry.add_redaction(MagicMock())
        registry.clear()
        assert registry.total_count == 0


# ---------------------------------------------------------------------------
# HookRegistry — sync execution
# ---------------------------------------------------------------------------


class TestHookRegistryFireSync:
    def test_fire_pre_call(self, registry: HookRegistry, hook_ctx: HookContext):
        fn = MagicMock()
        registry.add_pre_call(fn)
        registry.fire_pre_call(hook_ctx)
        fn.assert_called_once_with(hook_ctx)

    def test_fire_post_call(self, registry: HookRegistry, hook_ctx: HookContext):
        fn = MagicMock()
        registry.add_post_call(fn)
        registry.fire_post_call(hook_ctx)
        fn.assert_called_once_with(hook_ctx)

    def test_fire_violation(self, registry: HookRegistry, violation_ctx: ViolationHookContext):
        fn = MagicMock()
        registry.add_violation(fn)
        registry.fire_violation(violation_ctx)
        fn.assert_called_once_with(violation_ctx)

    def test_fire_redaction(self, registry: HookRegistry, redaction_ctx: RedactionHookContext):
        fn = MagicMock()
        registry.add_redaction(fn)
        registry.fire_redaction(redaction_ctx)
        fn.assert_called_once_with(redaction_ctx)

    def test_hooks_called_in_order(self, registry: HookRegistry, hook_ctx: HookContext):
        call_order: list[int] = []
        for i in range(3):
            registry.add_pre_call(lambda ctx, _i=i: call_order.append(_i))
        registry.fire_pre_call(hook_ctx)
        assert call_order == [0, 1, 2]

    def test_exception_in_hook_does_not_propagate(
        self, registry: HookRegistry, hook_ctx: HookContext
    ):
        def bad_hook(ctx: HookContext) -> None:
            msg = "hook error"
            raise RuntimeError(msg)

        second = MagicMock()
        registry.add_pre_call(bad_hook)
        registry.add_pre_call(second)
        # Should not raise; the second hook should still be called
        registry.fire_pre_call(hook_ctx)
        second.assert_called_once()

    def test_abort_via_pre_call_hook(self, registry: HookRegistry, hook_ctx: HookContext):
        def aborter(ctx: HookContext) -> None:
            ctx.abort = True
            ctx.abort_reason = "blocked by test"

        registry.add_pre_call(aborter)
        registry.fire_pre_call(hook_ctx)
        assert hook_ctx.abort is True
        assert hook_ctx.abort_reason == "blocked by test"

    def test_post_call_receives_result_and_duration(self, registry: HookRegistry):
        ctx = HookContext(
            call_id="id",
            tool_name="tool",
            policy_name="p",
            result="hello",
            duration_ms=42.5,
        )
        captured: list[HookContext] = []
        registry.add_post_call(captured.append)
        registry.fire_post_call(ctx)
        assert captured[0].result == "hello"
        assert captured[0].duration_ms == 42.5


# ---------------------------------------------------------------------------
# HookRegistry — async execution
# ---------------------------------------------------------------------------


class TestHookRegistryFireAsync:
    @pytest.mark.asyncio
    async def test_fire_pre_call_async_sync_hook(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_pre_call(fn)
        ctx = HookContext(call_id="a", tool_name="t", policy_name="p")
        await registry.fire_pre_call_async(ctx)
        fn.assert_called_once_with(ctx)

    @pytest.mark.asyncio
    async def test_fire_pre_call_async_async_hook(self, registry: HookRegistry):
        called = False

        async def async_hook(ctx: HookContext) -> None:
            nonlocal called
            called = True

        registry.add_pre_call(async_hook)
        ctx = HookContext(call_id="a", tool_name="t", policy_name="p")
        await registry.fire_pre_call_async(ctx)
        assert called is True

    @pytest.mark.asyncio
    async def test_fire_post_call_async(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_post_call(fn)
        ctx = HookContext(call_id="a", tool_name="t", policy_name="p")
        await registry.fire_post_call_async(ctx)
        fn.assert_called_once()

    @pytest.mark.asyncio
    async def test_fire_violation_async(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_violation(fn)
        ctx = ViolationHookContext(
            call_id="a",
            tool_name="t",
            policy_name="p",
            violation_type="blocked",
            violation_reason="no",
        )
        await registry.fire_violation_async(ctx)
        fn.assert_called_once()

    @pytest.mark.asyncio
    async def test_fire_redaction_async(self, registry: HookRegistry):
        fn = MagicMock()
        registry.add_redaction(fn)
        ctx = RedactionHookContext(
            call_id="a",
            tool_name="t",
            direction="output",
            redaction_count=1,
        )
        await registry.fire_redaction_async(ctx)
        fn.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_exception_does_not_propagate(self, registry: HookRegistry):
        async def bad_hook(ctx: HookContext) -> None:
            msg = "async error"
            raise RuntimeError(msg)

        second = MagicMock()
        registry.add_pre_call(bad_hook)
        registry.add_pre_call(second)
        ctx = HookContext(call_id="a", tool_name="t", policy_name="p")
        await registry.fire_pre_call_async(ctx)
        second.assert_called_once()

    @pytest.mark.asyncio
    async def test_mixed_sync_async_hooks(self, registry: HookRegistry):
        results: list[str] = []

        def sync_hook(ctx: HookContext) -> None:
            results.append("sync")

        async def async_hook(ctx: HookContext) -> None:
            results.append("async")

        registry.add_pre_call(sync_hook)
        registry.add_pre_call(async_hook)
        ctx = HookContext(call_id="a", tool_name="t", policy_name="p")
        await registry.fire_pre_call_async(ctx)
        assert results == ["sync", "async"]


# ---------------------------------------------------------------------------
# Global registry singleton
# ---------------------------------------------------------------------------


class TestGlobalRegistry:
    def test_singleton_identity(self):
        r1 = HookRegistry.global_registry()
        r2 = HookRegistry.global_registry()
        assert r1 is r2

    def test_reset_creates_new_instance(self):
        r1 = HookRegistry.global_registry()
        HookRegistry.reset_global()
        r2 = HookRegistry.global_registry()
        assert r1 is not r2

    def test_reset_clears_hooks(self):
        reg = HookRegistry.global_registry()
        reg.add_pre_call(MagicMock())
        assert reg.pre_call_count == 1
        HookRegistry.reset_global()
        new_reg = HookRegistry.global_registry()
        assert new_reg.pre_call_count == 0


# ---------------------------------------------------------------------------
# Decorator registration
# ---------------------------------------------------------------------------


class TestDecorators:
    def test_on_pre_call_registers(self):
        @on_pre_call
        def my_hook(ctx: HookContext) -> None:
            pass

        reg = HookRegistry.global_registry()
        assert reg.pre_call_count == 1

    def test_on_post_call_registers(self):
        @on_post_call
        def my_hook(ctx: HookContext) -> None:
            pass

        reg = HookRegistry.global_registry()
        assert reg.post_call_count == 1

    def test_on_violation_registers(self):
        @on_violation
        def my_hook(ctx: ViolationHookContext) -> None:
            pass

        reg = HookRegistry.global_registry()
        assert reg.violation_count == 1

    def test_on_redaction_registers(self):
        @on_redaction
        def my_hook(ctx: RedactionHookContext) -> None:
            pass

        reg = HookRegistry.global_registry()
        assert reg.redaction_count == 1

    def test_decorator_returns_original_function(self):
        @on_pre_call
        def my_hook(ctx: HookContext) -> None:
            pass

        # The decorator should return the original function
        assert callable(my_hook)
        assert my_hook.__name__ == "my_hook"

    def test_decorator_hooks_fire(self):
        called = False

        @on_pre_call
        def my_hook(ctx: HookContext) -> None:
            nonlocal called
            called = True

        reg = HookRegistry.global_registry()
        ctx = HookContext(call_id="a", tool_name="t", policy_name="p")
        reg.fire_pre_call(ctx)
        assert called is True

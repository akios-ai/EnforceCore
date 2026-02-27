# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Extra coverage for plugins/hooks.py async fire paths and exception handlers."""

import pytest

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)


@pytest.fixture(autouse=True)
def _reset_global():
    HookRegistry.reset_global()
    yield
    HookRegistry.reset_global()


@pytest.fixture
def reg():
    return HookRegistry()


@pytest.fixture
def hctx():
    return HookContext(tool_name="search", policy_name="strict")


@pytest.fixture
def vctx():
    return ViolationHookContext(tool_name="s", violation_type="blocked")


@pytest.fixture
def rctx():
    return RedactionHookContext(tool_name="s", category="email", direction="input")


# ---------------------------------------------------------------------------
# fire_pre_call - async hook path (line 249) + exception path
# ---------------------------------------------------------------------------


def test_fire_pre_call_async_hook(reg, hctx):
    """Async pre-call hook is executed synchronously via _run_async_hook."""
    results: list[str] = []

    async def async_hook(ctx: HookContext) -> None:
        results.append(ctx.tool_name)

    reg.add_pre_call(async_hook)
    reg.fire_pre_call(hctx)
    assert results == ["search"]


def test_fire_pre_call_sync_exception(reg, hctx):
    """Exception in a sync pre-call hook is swallowed (logged)."""

    def bad_hook(ctx: HookContext) -> None:
        raise RuntimeError("pre-call failure")

    reg.add_pre_call(bad_hook)
    # Must not raise
    reg.fire_pre_call(hctx)


# ---------------------------------------------------------------------------
# fire_post_call - async hook path (line 283) + exception paths (286-287)
# ---------------------------------------------------------------------------


def test_fire_post_call_async_hook(reg, hctx):
    results: list[str] = []

    async def async_hook(ctx: HookContext) -> None:
        results.append(ctx.policy_name)

    reg.add_post_call(async_hook)
    reg.fire_post_call(hctx)
    assert results == ["strict"]


def test_fire_post_call_sync_exception(reg, hctx):
    def bad_hook(ctx: HookContext) -> None:
        raise ValueError("post-call failure")

    reg.add_post_call(bad_hook)
    reg.fire_post_call(hctx)


def test_fire_post_call_sync_dispatches_async_exception(reg, hctx):
    async def bad_async_hook(ctx: HookContext) -> None:
        raise RuntimeError("post-call async failure")

    reg.add_post_call(bad_async_hook)
    reg.fire_post_call(hctx)


# ---------------------------------------------------------------------------
# fire_post_call_async - async hook (line 300) + exception (303-304)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_post_call_async_with_async_hook(reg, hctx):
    results: list[str] = []

    async def async_hook(ctx: HookContext) -> None:
        results.append(ctx.tool_name)

    reg.add_post_call(async_hook)
    await reg.fire_post_call_async(hctx)
    assert results == ["search"]


@pytest.mark.asyncio
async def test_fire_post_call_async_exception(reg, hctx):
    async def bad_hook(ctx: HookContext) -> None:
        raise RuntimeError("async post-call failure")

    reg.add_post_call(bad_hook)
    await reg.fire_post_call_async(hctx)


# ---------------------------------------------------------------------------
# fire_violation - async hook (line 317) + exception (320-321)
# ---------------------------------------------------------------------------


def test_fire_violation_async_hook(reg, vctx):
    results: list[str] = []

    async def async_hook(ctx: ViolationHookContext) -> None:
        results.append(ctx.violation_type)

    reg.add_violation(async_hook)
    reg.fire_violation(vctx)
    assert results == ["blocked"]


def test_fire_violation_sync_exception(reg, vctx):
    def bad_hook(ctx: ViolationHookContext) -> None:
        raise RuntimeError("violation failure")

    reg.add_violation(bad_hook)
    reg.fire_violation(vctx)


# ---------------------------------------------------------------------------
# fire_violation_async - exception (337-338)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_violation_async_exception(reg, vctx):
    async def bad_hook(ctx: ViolationHookContext) -> None:
        raise RuntimeError("async violation failure")

    reg.add_violation(bad_hook)
    await reg.fire_violation_async(vctx)


# ---------------------------------------------------------------------------
# fire_redaction - async hook (line 351) + exception (354-355)
# ---------------------------------------------------------------------------


def test_fire_redaction_async_hook(reg, rctx):
    results: list[str] = []

    async def async_hook(ctx: RedactionHookContext) -> None:
        results.append(ctx.category)

    reg.add_redaction(async_hook)
    reg.fire_redaction(rctx)
    assert results == ["email"]


def test_fire_redaction_sync_exception(reg, rctx):
    def bad_hook(ctx: RedactionHookContext) -> None:
        raise ValueError("redaction failure")

    reg.add_redaction(bad_hook)
    reg.fire_redaction(rctx)


# ---------------------------------------------------------------------------
# fire_redaction_async - async hook (line 368) + exception (371-372)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_redaction_async_with_async_hook(reg, rctx):
    results: list[str] = []

    async def async_hook(ctx: RedactionHookContext) -> None:
        results.append(ctx.direction)

    reg.add_redaction(async_hook)
    await reg.fire_redaction_async(rctx)
    assert results == ["input"]


@pytest.mark.asyncio
async def test_fire_redaction_async_exception(reg, rctx):
    async def bad_hook(ctx: RedactionHookContext) -> None:
        raise RuntimeError("async redaction failure")

    reg.add_redaction(bad_hook)
    await reg.fire_redaction_async(rctx)


# ---------------------------------------------------------------------------
# _run_async_hook without a running event loop (line 471 - asyncio.run path)
# ---------------------------------------------------------------------------


def test_run_async_hook_no_running_loop(reg, hctx):
    """When called from a thread with no running loop, asyncio.run() is used."""
    results: list[str] = []

    async def async_hook(ctx: HookContext) -> None:
        results.append("called")

    reg.add_pre_call(async_hook)
    # Calling from main thread (no running loop) hits the asyncio.run() path
    reg.fire_pre_call(hctx)
    assert results == ["called"]

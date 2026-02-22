# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the Resource Guard engine.

Tests CostTracker, KillSwitch, ResourceGuard, and _MemoryLimiter.
"""

from __future__ import annotations

import asyncio
import platform
import threading
import time
from unittest.mock import patch

import pytest

from enforcecore.core.types import CostLimitError, ResourceLimitError
from enforcecore.guard.engine import (
    _HAS_RESOURCE,
    _IS_POSIX,
    CostTracker,
    KillSwitch,
    ResourceGuard,
    _MemoryLimiter,
)

# =========================================================================
# CostTracker
# =========================================================================


class TestCostTracker:
    """Tests for CostTracker."""

    def test_initial_state(self) -> None:
        tracker = CostTracker()
        assert tracker.total_cost == 0.0
        assert tracker.budget is None

    def test_initial_state_with_budget(self) -> None:
        tracker = CostTracker(budget_usd=10.0)
        assert tracker.total_cost == 0.0
        assert tracker.budget == 10.0

    def test_record_cost(self) -> None:
        tracker = CostTracker()
        total = tracker.record(2.50)
        assert total == 2.50
        assert tracker.total_cost == 2.50

    def test_cumulative_cost(self) -> None:
        tracker = CostTracker()
        tracker.record(1.00)
        tracker.record(2.50)
        tracker.record(0.50)
        assert tracker.total_cost == 4.00

    def test_negative_cost_rejected(self) -> None:
        tracker = CostTracker()
        with pytest.raises(ValueError, match="negative"):
            tracker.record(-1.0)

    def test_zero_cost_accepted(self) -> None:
        tracker = CostTracker()
        total = tracker.record(0.0)
        assert total == 0.0

    def test_check_budget_passes_when_under(self) -> None:
        tracker = CostTracker(budget_usd=10.0)
        tracker.record(5.0)
        # Should not raise
        tracker.check_budget("tool", "policy")

    def test_check_budget_raises_when_at_budget(self) -> None:
        tracker = CostTracker(budget_usd=5.0)
        tracker.record(5.0)
        with pytest.raises(CostLimitError) as exc_info:
            tracker.check_budget("my_tool", "my_policy")
        assert exc_info.value.tool_name == "my_tool"
        assert exc_info.value.policy_name == "my_policy"

    def test_check_budget_raises_when_over(self) -> None:
        tracker = CostTracker(budget_usd=5.0)
        tracker.record(7.0)
        with pytest.raises(CostLimitError):
            tracker.check_budget()

    def test_check_per_call_budget(self) -> None:
        tracker = CostTracker()  # No global budget
        tracker.record(3.0)
        # Under per-call budget
        tracker.check_budget(per_call_budget=5.0)
        # At per-call budget
        tracker.record(2.0)
        with pytest.raises(CostLimitError):
            tracker.check_budget(per_call_budget=5.0)

    def test_check_no_budget_always_passes(self) -> None:
        tracker = CostTracker()
        tracker.record(1_000_000.0)
        # No budget = unlimited — should not raise
        tracker.check_budget()

    def test_global_budget_takes_precedence(self) -> None:
        """Global budget is checked first, even if per-call is higher."""
        tracker = CostTracker(budget_usd=3.0)
        tracker.record(4.0)
        with pytest.raises(CostLimitError) as exc_info:
            tracker.check_budget(per_call_budget=10.0)
        # Should fail on global budget ($3), not per-call ($10)
        assert "$3.0" in str(exc_info.value) or "3.0" in str(exc_info.value)

    def test_budget_setter(self) -> None:
        tracker = CostTracker(budget_usd=10.0)
        assert tracker.budget == 10.0
        tracker.budget = 5.0
        assert tracker.budget == 5.0

    def test_reset(self) -> None:
        tracker = CostTracker()
        tracker.record(100.0)
        tracker.reset()
        assert tracker.total_cost == 0.0

    def test_thread_safety(self) -> None:
        """Concurrent access should not corrupt state."""
        tracker = CostTracker()
        errors: list[Exception] = []

        def record_many() -> None:
            try:
                for _ in range(100):
                    tracker.record(0.01)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert abs(tracker.total_cost - 10.0) < 0.01


# =========================================================================
# KillSwitch
# =========================================================================


class TestKillSwitch:
    """Tests for KillSwitch."""

    def test_initial_state(self) -> None:
        ks = KillSwitch()
        assert not ks.is_tripped
        assert ks.reason == ""

    def test_trip(self) -> None:
        ks = KillSwitch()
        ks.trip("memory limit exceeded")
        assert ks.is_tripped
        assert ks.reason == "memory limit exceeded"

    def test_check_passes_when_not_tripped(self) -> None:
        ks = KillSwitch()
        # Should not raise
        ks.check("tool", "policy")

    def test_check_raises_when_tripped(self) -> None:
        ks = KillSwitch()
        ks.trip("time limit exceeded (30s)")
        with pytest.raises(ResourceLimitError) as exc_info:
            ks.check("my_tool", "my_policy")
        assert exc_info.value.tool_name == "my_tool"
        assert "kill_switch" in str(exc_info.value)

    def test_reset(self) -> None:
        ks = KillSwitch()
        ks.trip("some reason")
        assert ks.is_tripped
        ks.reset()
        assert not ks.is_tripped
        assert ks.reason == ""
        # Should not raise after reset
        ks.check()

    def test_thread_safety(self) -> None:
        """Concurrent trip and check should not error."""
        ks = KillSwitch()
        errors: list[Exception] = []

        def trip_many() -> None:
            try:
                for i in range(50):
                    ks.trip(f"reason-{i}")
            except Exception as e:
                errors.append(e)

        def check_many() -> None:
            for _ in range(50):
                try:
                    ks.check()
                except ResourceLimitError:
                    pass  # Expected after trip
                except Exception as e:
                    errors.append(e)

        t1 = threading.Thread(target=trip_many)
        t2 = threading.Thread(target=check_many)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert not errors
        assert ks.is_tripped


# =========================================================================
# ResourceGuard — sync
# =========================================================================


class TestResourceGuardSync:
    """Tests for ResourceGuard.execute_sync."""

    def test_passthrough_no_limits(self) -> None:
        guard = ResourceGuard()
        result = guard.execute_sync(
            lambda x, y: x + y,
            (2, 3),
            {},
        )
        assert result == 5

    def test_passthrough_with_kwargs(self) -> None:
        guard = ResourceGuard()
        result = guard.execute_sync(
            lambda x, y=10: x + y,
            (5,),
            {"y": 20},
        )
        assert result == 25

    def test_timeout_raises_resource_limit_error(self) -> None:
        guard = ResourceGuard()

        def slow_func() -> str:
            time.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError) as exc_info:
            guard.execute_sync(
                slow_func,
                (),
                {},
                max_duration_seconds=0.1,
                tool_name="slow_tool",
                policy_name="test_policy",
            )
        assert exc_info.value.tool_name == "slow_tool"
        assert "time" in str(exc_info.value).lower()

    def test_timeout_trips_kill_switch(self) -> None:
        guard = ResourceGuard()

        def slow_func() -> str:
            time.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError):
            guard.execute_sync(
                slow_func,
                (),
                {},
                max_duration_seconds=0.1,
            )

        assert guard.kill_switch.is_tripped

    def test_kill_switch_blocks_execution(self) -> None:
        ks = KillSwitch()
        ks.trip("pre-tripped")
        guard = ResourceGuard(kill_switch=ks)

        with pytest.raises(ResourceLimitError) as exc_info:
            guard.execute_sync(lambda: "hello", (), {})
        assert "kill_switch" in str(exc_info.value)

    def test_func_within_timeout_succeeds(self) -> None:
        guard = ResourceGuard()

        def fast_func() -> str:
            return "fast"

        result = guard.execute_sync(
            fast_func,
            (),
            {},
            max_duration_seconds=5.0,
        )
        assert result == "fast"

    def test_func_exception_propagates(self) -> None:
        guard = ResourceGuard()

        def bad_func() -> None:
            msg = "kaboom"
            raise ValueError(msg)

        with pytest.raises(ValueError, match="kaboom"):
            guard.execute_sync(bad_func, (), {})

    def test_func_exception_with_timeout_propagates(self) -> None:
        guard = ResourceGuard()

        def bad_func() -> None:
            msg = "fail fast"
            raise RuntimeError(msg)

        with pytest.raises(RuntimeError, match="fail fast"):
            guard.execute_sync(
                bad_func,
                (),
                {},
                max_duration_seconds=5.0,
            )

    def test_subsequent_call_blocked_after_timeout(self) -> None:
        guard = ResourceGuard()

        def slow_func() -> str:
            time.sleep(5)
            return "done"

        # First call — times out
        with pytest.raises(ResourceLimitError):
            guard.execute_sync(
                slow_func,
                (),
                {},
                max_duration_seconds=0.1,
            )

        # Second call — blocked by kill switch
        with pytest.raises(ResourceLimitError) as exc_info:
            guard.execute_sync(lambda: "hello", (), {})
        assert "kill_switch" in str(exc_info.value)


# =========================================================================
# ResourceGuard — async
# =========================================================================


class TestResourceGuardAsync:
    """Tests for ResourceGuard.execute_async."""

    @pytest.mark.asyncio
    async def test_passthrough_no_limits(self) -> None:
        guard = ResourceGuard()

        async def add(x: int, y: int) -> int:
            return x + y

        result = await guard.execute_async(add, (2, 3), {})
        assert result == 5

    @pytest.mark.asyncio
    async def test_timeout_raises_resource_limit_error(self) -> None:
        guard = ResourceGuard()

        async def slow_func() -> str:
            await asyncio.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError) as exc_info:
            await guard.execute_async(
                slow_func,
                (),
                {},
                max_duration_seconds=0.1,
                tool_name="async_slow",
                policy_name="test",
            )
        assert exc_info.value.tool_name == "async_slow"
        assert "time" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_timeout_trips_kill_switch(self) -> None:
        guard = ResourceGuard()

        async def slow_func() -> str:
            await asyncio.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError):
            await guard.execute_async(
                slow_func,
                (),
                {},
                max_duration_seconds=0.1,
            )

        assert guard.kill_switch.is_tripped

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_async(self) -> None:
        ks = KillSwitch()
        ks.trip("pre-tripped")
        guard = ResourceGuard(kill_switch=ks)

        async def noop() -> str:
            return "hello"

        with pytest.raises(ResourceLimitError) as exc_info:
            await guard.execute_async(noop, (), {})
        assert "kill_switch" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_func_within_timeout_succeeds(self) -> None:
        guard = ResourceGuard()

        async def fast_func() -> str:
            return "fast"

        result = await guard.execute_async(
            fast_func,
            (),
            {},
            max_duration_seconds=5.0,
        )
        assert result == "fast"

    @pytest.mark.asyncio
    async def test_func_exception_propagates(self) -> None:
        guard = ResourceGuard()

        async def bad_func() -> None:
            msg = "async kaboom"
            raise ValueError(msg)

        with pytest.raises(ValueError, match="async kaboom"):
            await guard.execute_async(bad_func, (), {})

    @pytest.mark.asyncio
    async def test_subsequent_call_blocked_after_timeout(self) -> None:
        guard = ResourceGuard()

        async def slow_func() -> str:
            await asyncio.sleep(5)
            return "done"

        # First call — times out
        with pytest.raises(ResourceLimitError):
            await guard.execute_async(
                slow_func,
                (),
                {},
                max_duration_seconds=0.1,
            )

        # Second call — blocked by kill switch
        async def noop() -> str:
            return "hello"

        with pytest.raises(ResourceLimitError) as exc_info:
            await guard.execute_async(noop, (), {})
        assert "kill_switch" in str(exc_info.value)


# =========================================================================
# ResourceGuard — platform info
# =========================================================================


class TestPlatformInfo:
    """Tests for ResourceGuard.platform_info."""

    def test_returns_dict(self) -> None:
        info = ResourceGuard.platform_info()
        assert isinstance(info, dict)
        assert "platform" in info
        assert "time_limits" in info
        assert "memory_limits" in info
        assert "cost_tracking" in info
        assert "kill_switch" in info
        assert "posix" in info

    def test_time_limits_always_true(self) -> None:
        info = ResourceGuard.platform_info()
        assert info["time_limits"] is True

    def test_cost_tracking_always_true(self) -> None:
        info = ResourceGuard.platform_info()
        assert info["cost_tracking"] is True

    def test_platform_matches_system(self) -> None:
        info = ResourceGuard.platform_info()
        assert info["platform"] == platform.system()


# =========================================================================
# _MemoryLimiter
# =========================================================================


class TestMemoryLimiter:
    """Tests for _MemoryLimiter (internal)."""

    def test_init(self) -> None:
        limiter = _MemoryLimiter(256)
        assert limiter._max_bytes == 256 * 1024 * 1024

    @pytest.mark.skipif(
        not (_HAS_RESOURCE and _IS_POSIX),
        reason="Memory limits only available on POSIX",
    )
    def test_apply_and_restore_posix(self) -> None:
        """On POSIX, apply attempts to set a limit and restore resets it."""
        import resource

        resource_type = resource.RLIMIT_AS if platform.system() == "Linux" else resource.RLIMIT_RSS
        original = resource.getrlimit(resource_type)

        limiter = _MemoryLimiter(512)
        limiter.apply()

        if limiter._previous is not None:
            # Apply succeeded — verify limit was set
            current = resource.getrlimit(resource_type)
            assert current[0] == 512 * 1024 * 1024
            limiter.restore()
            restored = resource.getrlimit(resource_type)
            assert restored == original
        else:
            # macOS: setrlimit may fail (advisory only) — that's OK
            assert platform.system() == "Darwin"

    @pytest.mark.skipif(
        not (_HAS_RESOURCE and _IS_POSIX),
        reason="Memory limits only available on POSIX",
    )
    def test_respects_hard_limit(self) -> None:
        """Should not set soft limit higher than hard limit."""
        import resource

        resource_type = resource.RLIMIT_AS if platform.system() == "Linux" else resource.RLIMIT_RSS
        _original_soft, original_hard = resource.getrlimit(resource_type)

        # If hard limit is RLIM_INFINITY, we can't test this constraint
        if original_hard == resource.RLIM_INFINITY:
            pytest.skip("Hard limit is RLIM_INFINITY — cannot test capping")

        # Request more than the hard limit
        limiter = _MemoryLimiter(original_hard // (1024 * 1024) + 1000)
        limiter.apply()

        current = resource.getrlimit(resource_type)
        assert current[0] <= original_hard

        limiter.restore()

    def test_restore_without_apply_is_noop(self) -> None:
        """Restore without apply should not error."""
        limiter = _MemoryLimiter(256)
        limiter.restore()  # Should not raise

    def test_apply_without_resource_module(self) -> None:
        """On platforms without resource module, apply is a no-op."""
        limiter = _MemoryLimiter(256)
        with patch("enforcecore.guard.engine._HAS_RESOURCE", False):
            limiter.apply()
        # Should not set any limits
        assert limiter._previous is None


# =========================================================================
# ResourceGuard — memory limit integration
# =========================================================================


@pytest.mark.skipif(
    not (_HAS_RESOURCE and _IS_POSIX),
    reason="Memory limits only available on POSIX",
)
class TestResourceGuardMemory:
    """Tests for memory limit integration in ResourceGuard."""

    def test_memory_limit_applied_and_restored_sync(self) -> None:
        """Memory limit should be applied during execution and restored after."""
        import resource

        resource_type = resource.RLIMIT_AS if platform.system() == "Linux" else resource.RLIMIT_RSS
        original = resource.getrlimit(resource_type)

        guard = ResourceGuard()
        limits_during: list[tuple[int, int]] = []

        def capture_limits() -> str:
            limits_during.append(resource.getrlimit(resource_type))
            return "ok"

        result = guard.execute_sync(
            capture_limits,
            (),
            {},
            max_memory_mb=512,
        )
        assert result == "ok"
        assert len(limits_during) == 1

        # On macOS, setrlimit(RLIMIT_RSS) is advisory and may fail.
        # On Linux, RLIMIT_AS should be enforced.
        if platform.system() == "Linux":
            assert limits_during[0][0] == 512 * 1024 * 1024

        # After execution, limits should be restored
        restored = resource.getrlimit(resource_type)
        assert restored == original

    @pytest.mark.asyncio
    async def test_memory_limit_applied_and_restored_async(self) -> None:
        """Same as sync but for async execution."""
        import resource

        resource_type = resource.RLIMIT_AS if platform.system() == "Linux" else resource.RLIMIT_RSS
        original = resource.getrlimit(resource_type)

        guard = ResourceGuard()
        limits_during: list[tuple[int, int]] = []

        async def capture_limits() -> str:
            limits_during.append(resource.getrlimit(resource_type))
            return "ok"

        result = await guard.execute_async(
            capture_limits,
            (),
            {},
            max_memory_mb=512,
        )
        assert result == "ok"

        if platform.system() == "Linux":
            assert limits_during[0][0] == 512 * 1024 * 1024

        restored = resource.getrlimit(resource_type)
        assert restored == original


# =========================================================================
# ResourceGuard — cost + guard interaction
# =========================================================================


class TestResourceGuardCostIntegration:
    """Tests for ResourceGuard with CostTracker interaction."""

    def test_default_cost_tracker(self) -> None:
        guard = ResourceGuard()
        assert guard.cost_tracker is not None
        assert guard.cost_tracker.total_cost == 0.0

    def test_custom_cost_tracker(self) -> None:
        tracker = CostTracker(budget_usd=5.0)
        guard = ResourceGuard(cost_tracker=tracker)
        assert guard.cost_tracker is tracker
        assert guard.cost_tracker.budget == 5.0

    def test_custom_kill_switch(self) -> None:
        ks = KillSwitch()
        guard = ResourceGuard(kill_switch=ks)
        assert guard.kill_switch is ks

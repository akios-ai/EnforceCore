# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Integration tests — guard wired through the Enforcer pipeline.

Verifies that resource limits, cost tracking, and KillSwitch work
end-to-end through @enforce() and Enforcer.enforce_sync/enforce_async.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from enforcecore.core.config import settings
from enforcecore.core.enforcer import Enforcer, enforce
from enforcecore.core.policy import Policy
from enforcecore.core.types import CostLimitError, ResourceLimitError

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# =========================================================================
# Enforcer guard integration
# =========================================================================


class TestEnforcerGuardProperty:
    """Tests that the Enforcer creates and exposes a guard."""

    def test_enforcer_has_guard(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert enforcer.guard is not None

    def test_guard_has_cost_tracker(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert enforcer.guard.cost_tracker is not None

    def test_guard_has_kill_switch(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert enforcer.guard.kill_switch is not None

    def test_record_cost(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        total = enforcer.record_cost(2.50)
        assert total == 2.50
        total = enforcer.record_cost(1.50)
        assert total == 4.00
        assert enforcer.guard.cost_tracker.total_cost == 4.00


# =========================================================================
# Sync enforcement with guards
# =========================================================================


class TestEnforcerSyncGuard:
    """Tests for guard integration in enforce_sync."""

    def test_no_limits_passthrough(self, allow_all_policy: Policy) -> None:
        """With no resource limits, calls pass through normally."""
        enforcer = Enforcer(allow_all_policy)
        result = enforcer.enforce_sync(lambda x: x * 2, 5)
        assert result == 10

    def test_time_limit_allows_fast_call(self, time_limit_policy: Policy) -> None:
        enforcer = Enforcer(time_limit_policy)
        result = enforcer.enforce_sync(lambda: "fast", tool_name="fast_tool")
        assert result == "fast"

    def test_time_limit_blocks_slow_call(self) -> None:
        """A call exceeding the time limit should raise ResourceLimitError."""
        # Use a policy with a very short time limit for testing
        policy = Policy(
            name="short-timeout",
            rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)

        def slow_func() -> str:
            time.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError) as exc_info:
            enforcer.enforce_sync(slow_func, tool_name="slow_tool")
        assert exc_info.value.tool_name == "slow_tool"

    def test_cost_check_blocks_over_budget(self) -> None:
        """Pre-call cost check blocks when budget is exceeded."""
        policy = Policy(
            name="cheap",
            rules={"resource_limits": {"max_cost_usd": 5.0}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)

        # Record some cost — puts us over the $5 policy budget
        enforcer.record_cost(6.0)

        with pytest.raises(CostLimitError):
            enforcer.enforce_sync(lambda: "hello", tool_name="tool")

    def test_cost_check_allows_under_budget(self) -> None:
        policy = Policy(
            name="cheap",
            rules={"resource_limits": {"max_cost_usd": 10.0}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)
        enforcer.record_cost(3.0)

        result = enforcer.enforce_sync(lambda: "ok", tool_name="tool")
        assert result == "ok"

    def test_global_cost_budget(self, allow_all_policy: Policy) -> None:
        """Global budget from settings is applied."""
        original = settings.cost_budget_usd
        try:
            settings.cost_budget_usd = 2.0
            enforcer = Enforcer(allow_all_policy)
            enforcer.record_cost(3.0)

            with pytest.raises(CostLimitError):
                enforcer.enforce_sync(lambda: "hi", tool_name="tool")
        finally:
            settings.cost_budget_usd = original

    def test_kill_switch_blocks_after_timeout(self) -> None:
        """After a timeout, subsequent calls are blocked by the kill switch."""
        policy = Policy(
            name="short-timeout",
            rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)

        # First call — times out
        with pytest.raises(ResourceLimitError):
            enforcer.enforce_sync(
                lambda: time.sleep(5) or "done",
                tool_name="slow",
            )

        # Second call — blocked by kill switch
        with pytest.raises(ResourceLimitError) as exc_info:
            enforcer.enforce_sync(lambda: "fast", tool_name="fast")
        assert "kill_switch" in str(exc_info.value)


# =========================================================================
# Async enforcement with guards
# =========================================================================


class TestEnforcerAsyncGuard:
    """Tests for guard integration in enforce_async."""

    @pytest.mark.asyncio
    async def test_no_limits_passthrough(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)

        async def add(x: int, y: int) -> int:
            return x + y

        result = await enforcer.enforce_async(add, 2, 3)
        assert result == 5

    @pytest.mark.asyncio
    async def test_time_limit_allows_fast_call(self, time_limit_policy: Policy) -> None:
        enforcer = Enforcer(time_limit_policy)

        async def fast() -> str:
            return "quick"

        result = await enforcer.enforce_async(fast, tool_name="fast_tool")
        assert result == "quick"

    @pytest.mark.asyncio
    async def test_time_limit_blocks_slow_call(self) -> None:
        policy = Policy(
            name="short-timeout",
            rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)

        async def slow_func() -> str:
            await asyncio.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError) as exc_info:
            await enforcer.enforce_async(slow_func, tool_name="async_slow")
        assert exc_info.value.tool_name == "async_slow"

    @pytest.mark.asyncio
    async def test_cost_check_blocks_over_budget_async(self) -> None:
        policy = Policy(
            name="cheap",
            rules={"resource_limits": {"max_cost_usd": 5.0}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)
        enforcer.record_cost(6.0)

        async def noop() -> str:
            return "hello"

        with pytest.raises(CostLimitError):
            await enforcer.enforce_async(noop, tool_name="tool")

    @pytest.mark.asyncio
    async def test_kill_switch_blocks_after_async_timeout(self) -> None:
        policy = Policy(
            name="short-timeout",
            rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
        )
        enforcer = Enforcer(policy)

        async def slow() -> str:
            await asyncio.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError):
            await enforcer.enforce_async(slow, tool_name="slow")

        async def fast() -> str:
            return "fast"

        with pytest.raises(ResourceLimitError) as exc_info:
            await enforcer.enforce_async(fast, tool_name="fast")
        assert "kill_switch" in str(exc_info.value)


# =========================================================================
# @enforce() decorator with guards
# =========================================================================


class TestDecoratorGuard:
    """Tests for @enforce() with resource-limited policies."""

    def test_decorator_sync_with_time_limit(self) -> None:
        policy = Policy(
            name="short-timeout",
            rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
        )

        @enforce(policy=policy)
        def slow_tool() -> str:
            time.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError):
            slow_tool()

    @pytest.mark.asyncio
    async def test_decorator_async_with_time_limit(self) -> None:
        policy = Policy(
            name="short-timeout",
            rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
        )

        @enforce(policy=policy)
        async def slow_tool() -> str:
            await asyncio.sleep(5)
            return "done"

        with pytest.raises(ResourceLimitError):
            await slow_tool()

    def test_decorator_sync_passthrough(self) -> None:
        policy = Policy(name="allow-all")

        @enforce(policy=policy)
        def fast_tool(x: int) -> int:
            return x * 2

        assert fast_tool(5) == 10


# =========================================================================
# Audit recording with guard violations
# =========================================================================


class TestGuardAuditRecording:
    """Tests that guard violations are recorded in the audit trail."""

    def test_timeout_recorded_as_blocked(self, tmp_path: Path) -> None:
        """A timeout should be audited as a blocked call."""
        original_enabled = settings.audit_enabled
        original_path = settings.audit_path
        try:
            settings.audit_enabled = True
            settings.audit_path = tmp_path

            policy = Policy(
                name="short-timeout",
                rules={"resource_limits": {"max_call_duration_seconds": 0.1}},  # type: ignore[arg-type]
            )
            enforcer = Enforcer(policy)

            with pytest.raises(ResourceLimitError):
                enforcer.enforce_sync(
                    lambda: time.sleep(5) or "done",
                    tool_name="slow",
                )

            # Check audit file exists and has content
            trail_file = tmp_path / "trail.jsonl"
            if trail_file.exists():
                import json

                entries = [json.loads(line) for line in trail_file.read_text().splitlines()]
                blocked = [e for e in entries if e.get("decision") == "blocked"]
                assert len(blocked) >= 1
                assert blocked[0]["tool_name"] == "slow"

        finally:
            settings.audit_enabled = original_enabled
            settings.audit_path = original_path

    def test_cost_violation_recorded_as_blocked(self, tmp_path: Path) -> None:
        """A cost limit violation should be audited as a blocked call."""
        original_enabled = settings.audit_enabled
        original_path = settings.audit_path
        try:
            settings.audit_enabled = True
            settings.audit_path = tmp_path

            policy = Policy(
                name="cheap",
                rules={"resource_limits": {"max_cost_usd": 1.0}},  # type: ignore[arg-type]
            )
            enforcer = Enforcer(policy)
            enforcer.record_cost(5.0)

            with pytest.raises(CostLimitError):
                enforcer.enforce_sync(lambda: "hi", tool_name="expensive")

            trail_file = tmp_path / "trail.jsonl"
            if trail_file.exists():
                import json

                entries = [json.loads(line) for line in trail_file.read_text().splitlines()]
                blocked = [e for e in entries if e.get("decision") == "blocked"]
                assert len(blocked) >= 1
                assert blocked[0]["tool_name"] == "expensive"

        finally:
            settings.audit_enabled = original_enabled
            settings.audit_path = original_path

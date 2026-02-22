# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for v1.0.22a1 audit fixes.

H-3:  Policy cache now invalidates on file mtime change
H-2:  Shared ThreadPoolExecutor with daemon threads, leaked thread counter
L-4:  Audit resume uses 64 KB window in binary mode with retry
A-3:  _background_tasks capped at 1000 with warning
"""

from __future__ import annotations

import contextlib
import time
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from enforcecore.auditor.engine import AuditEntry, Auditor
from enforcecore.core.enforcer import (
    _load_and_cache,
    _policy_cache,
    _policy_cache_lock,
    clear_policy_cache,
)
from enforcecore.core.types import ResourceLimitError
from enforcecore.guard.engine import ResourceGuard
from enforcecore.plugins.hooks import (
    _MAX_BACKGROUND_TASKS,
    _background_tasks,
    _on_background_task_done,
    _run_async_hook,
)

if TYPE_CHECKING:
    from pathlib import Path


# =========================================================================
# Fixtures
# =========================================================================


@pytest.fixture(autouse=True)
def _clear_policy_cache():
    """Clear the policy cache before and after every test."""
    clear_policy_cache()
    yield
    clear_policy_cache()


# =========================================================================
# H-3: Policy cache mtime invalidation
# =========================================================================


class TestH3PolicyCacheMtime:
    """H-3: Policy cache should detect file changes via st_mtime."""

    def test_cache_hit_same_mtime(self, tmp_path: Path) -> None:
        """Same file, same mtime → cache hit (no re-parse)."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("name: test-policy\nversion: '1.0'\nrules:\n  on_violation: block\n")
        p1 = _load_and_cache(str(policy_file))
        p2 = _load_and_cache(str(policy_file))
        assert p1 is p2  # Same object — cache hit

    def test_cache_invalidation_on_mtime_change(self, tmp_path: Path) -> None:
        """Modified file → cache miss, re-parsed."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("name: original\nversion: '1.0'\nrules:\n  on_violation: block\n")
        p1 = _load_and_cache(str(policy_file))
        assert p1.name == "original"

        # Modify the file — ensure mtime actually changes
        time.sleep(0.05)  # Filesystem mtime resolution
        policy_file.write_text("name: updated\nversion: '2.0'\nrules:\n  on_violation: block\n")
        p2 = _load_and_cache(str(policy_file))
        assert p2.name == "updated"
        assert p1 is not p2  # Different object — re-parsed

    def test_cache_eviction_fifo(self, tmp_path: Path) -> None:
        """When cache is full, oldest entry is evicted."""
        from enforcecore.core import enforcer as enforcer_mod

        original_max = enforcer_mod._POLICY_CACHE_MAX_SIZE
        try:
            enforcer_mod._POLICY_CACHE_MAX_SIZE = 3
            policies = []
            for i in range(4):
                f = tmp_path / f"policy_{i}.yaml"
                f.write_text(f"name: policy-{i}\nversion: '1.0'\nrules:\n  on_violation: block\n")
                policies.append(_load_and_cache(str(f)))

            with _policy_cache_lock:
                assert len(_policy_cache) <= 3
        finally:
            enforcer_mod._POLICY_CACHE_MAX_SIZE = original_max

    def test_clear_cache_returns_count(self, tmp_path: Path) -> None:
        """clear_policy_cache() returns the number of evicted entries."""
        f = tmp_path / "p.yaml"
        f.write_text("name: p\nversion: '1.0'\nrules:\n  on_violation: block\n")
        _load_and_cache(str(f))
        count = clear_policy_cache()
        assert count == 1


# =========================================================================
# H-2 / M-1: Shared ThreadPoolExecutor
# =========================================================================


class TestH2SharedThreadPool:
    """H-2: ResourceGuard uses a shared pool with daemon threads."""

    def test_shared_pool_exists(self) -> None:
        """Guard has a shared pool, not created per-call."""
        guard = ResourceGuard()
        assert guard._pool is not None
        assert guard._pool._max_workers == ResourceGuard._POOL_MAX_WORKERS

    def test_leaked_thread_count_starts_zero(self) -> None:
        guard = ResourceGuard()
        assert guard.leaked_thread_count == 0

    def test_leaked_thread_count_increments_on_timeout(self) -> None:
        """When a call times out, leaked_thread_count increments."""
        guard = ResourceGuard()

        def slow_func() -> str:
            time.sleep(10)
            return "done"

        with pytest.raises(ResourceLimitError):
            guard.execute_sync(
                slow_func,
                (),
                {},
                max_duration_seconds=0.05,
                tool_name="slow",
                policy_name="test",
            )
        assert guard.leaked_thread_count == 1

    def test_normal_call_no_leak(self) -> None:
        """Normal (non-timeout) calls don't increment the counter."""
        guard = ResourceGuard()
        result = guard.execute_sync(
            lambda: 42,
            (),
            {},
            max_duration_seconds=5.0,
            tool_name="fast",
            policy_name="test",
        )
        assert result == 42
        assert guard.leaked_thread_count == 0

    def test_pool_reused_across_calls(self) -> None:
        """The same pool object is reused for multiple calls."""
        guard = ResourceGuard()
        pool_id = id(guard._pool)

        guard.execute_sync(lambda: 1, (), {}, tool_name="a", policy_name="t")
        guard.execute_sync(lambda: 2, (), {}, tool_name="b", policy_name="t")

        assert id(guard._pool) == pool_id  # Same pool

    def test_thread_name_prefix(self) -> None:
        """Pool threads should have the enforcecore-guard prefix."""
        guard = ResourceGuard()
        assert guard._pool._thread_name_prefix == "enforcecore-guard"


# =========================================================================
# L-4: Audit resume window
# =========================================================================


class TestL4AuditResumeWindow:
    """L-4: _resume_chain uses 64 KB binary-mode seek with retry."""

    def test_resume_small_file(self, tmp_path: Path) -> None:
        """Small file reads all lines normally."""
        trail = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=trail)
        auditor.record(tool_name="t1", policy_name="p", decision="allowed")
        auditor.record(tool_name="t2", policy_name="p", decision="allowed")

        # Create new auditor — should resume
        auditor2 = Auditor(output_path=trail)
        assert auditor2.entry_count == 2
        assert auditor2.last_hash != ""

    def test_resume_large_file(self, tmp_path: Path) -> None:
        """File > 64 KB should still find the last entry via binary seek."""
        trail = tmp_path / "trail.jsonl"

        # Write enough entries to exceed 64 KB
        entries: list[AuditEntry] = []
        prev_hash = ""
        for i in range(500):
            e = AuditEntry(
                tool_name=f"tool_{i}",
                policy_name="policy",
                decision="allowed",
                previous_hash=prev_hash,
            )
            e.seal()
            entries.append(e)
            prev_hash = e.entry_hash

        with trail.open("w", encoding="utf-8") as f:
            for e in entries:
                f.write(e.to_json() + "\n")

        # Should be > 64 KB
        assert trail.stat().st_size > 65536

        auditor = Auditor(output_path=trail)
        assert auditor.entry_count == 500
        assert auditor.last_hash == entries[-1].entry_hash

    def test_resume_binary_mode_handles_unicode(self, tmp_path: Path) -> None:
        """Binary mode + UTF-8 decode should handle unicode tool names."""
        trail = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=trail)
        auditor.record(
            tool_name="recherche_hébergement",
            policy_name="sécurité",
            decision="allowed",
        )

        auditor2 = Auditor(output_path=trail)
        assert auditor2.entry_count == 1


# =========================================================================
# A-3: _background_tasks cap
# =========================================================================


class TestA3BackgroundTasksCap:
    """A-3: _background_tasks should be capped at _MAX_BACKGROUND_TASKS."""

    def test_max_constant_is_1000(self) -> None:
        assert _MAX_BACKGROUND_TASKS == 1000

    def test_warning_logged_at_limit(self) -> None:
        """When the set is at capacity, a warning should be logged."""
        import asyncio

        # Temporarily fill the set with dummy tasks
        original = _background_tasks.copy()
        _background_tasks.clear()

        async def _fill_and_test() -> None:
            loop = asyncio.get_event_loop()
            # Add fake tasks up to the limit
            dummy_tasks = []
            for _ in range(_MAX_BACKGROUND_TASKS):

                async def noop() -> None:
                    pass

                t = loop.create_task(noop())
                _background_tasks.add(t)
                dummy_tasks.append(t)

            assert len(_background_tasks) == _MAX_BACKGROUND_TASKS

            # Now try to add one more via _run_async_hook
            call_count = 0

            async def hook_fn(ctx: object) -> None:
                nonlocal call_count
                call_count += 1

            with patch("enforcecore.plugins.hooks.logger") as mock_logger:
                _run_async_hook(hook_fn, None)
                mock_logger.warning.assert_called()
                call_kwargs = mock_logger.warning.call_args
                assert "background_tasks_limit_reached" in str(call_kwargs)

            # Clean up
            for t in dummy_tasks:
                t.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await t

        asyncio.run(_fill_and_test())
        _background_tasks.clear()
        _background_tasks.update(original)

    def test_done_callback_still_cleans_up(self) -> None:
        """_on_background_task_done still removes tasks from the set."""
        import asyncio

        _background_tasks.clear()

        async def _test() -> None:
            async def ok() -> None:
                pass

            task = asyncio.get_event_loop().create_task(ok())
            _background_tasks.add(task)
            task.add_done_callback(_on_background_task_done)
            await task

        asyncio.run(_test())
        assert len(_background_tasks) == 0

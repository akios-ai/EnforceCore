"""Tests for rate limiter (enforcecore.guard.ratelimit)."""

from __future__ import annotations

import threading
import time

import pytest

from enforcecore.guard.ratelimit import (
    RateLimit,
    RateLimitConfig,
    RateLimiter,
    RateLimitError,
    _SlidingWindow,
)

# ---------------------------------------------------------------------------
# SlidingWindow
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_basic_acquire(self) -> None:
        w = _SlidingWindow(max_calls=3, window_seconds=10)
        assert w.try_acquire()
        assert w.try_acquire()
        assert w.try_acquire()
        assert not w.try_acquire()  # 4th should fail

    def test_window_expiry(self) -> None:
        w = _SlidingWindow(max_calls=2, window_seconds=0.1)
        assert w.try_acquire()
        assert w.try_acquire()
        assert not w.try_acquire()
        time.sleep(0.15)
        assert w.try_acquire()  # Window expired

    def test_current_count(self) -> None:
        w = _SlidingWindow(max_calls=5, window_seconds=10)
        assert w.current_count == 0
        w.try_acquire()
        w.try_acquire()
        assert w.current_count == 2

    def test_reset(self) -> None:
        w = _SlidingWindow(max_calls=2, window_seconds=10)
        w.try_acquire()
        w.try_acquire()
        w.reset()
        assert w.current_count == 0
        assert w.try_acquire()

    def test_properties(self) -> None:
        w = _SlidingWindow(max_calls=10, window_seconds=60)
        assert w.max_calls == 10
        assert w.window_seconds == 60

    def test_thread_safety(self) -> None:
        w = _SlidingWindow(max_calls=100, window_seconds=10)
        results: list[bool] = []
        lock = threading.Lock()

        def acquire_many() -> None:
            for _ in range(20):
                result = w.try_acquire()
                with lock:
                    results.append(result)

        threads = [threading.Thread(target=acquire_many) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 100 should succeed, 100 should fail
        assert results.count(True) == 100
        assert results.count(False) == 100


# ---------------------------------------------------------------------------
# RateLimitError
# ---------------------------------------------------------------------------


class TestRateLimitError:
    def test_error_message(self) -> None:
        err = RateLimitError("search_web", 10, 60.0, policy_name="strict")
        assert "search_web" in str(err)
        assert "10" in str(err)
        assert err.max_calls == 10
        assert err.window_seconds == 60.0
        assert err.tool_name == "search_web"
        assert err.policy_name == "strict"


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_no_limits_allows_all(self) -> None:
        limiter = RateLimiter()
        # No limits configured, should not raise
        limiter.acquire("any_tool")

    def test_per_tool_limit(self) -> None:
        limiter = RateLimiter()
        limiter.configure("search_web", max_calls=3, window_seconds=10)
        limiter.acquire("search_web")
        limiter.acquire("search_web")
        limiter.acquire("search_web")
        with pytest.raises(RateLimitError):
            limiter.acquire("search_web")

    def test_per_tool_case_insensitive(self) -> None:
        limiter = RateLimiter()
        limiter.configure("Search_Web", max_calls=2, window_seconds=10)
        limiter.acquire("search_web")
        limiter.acquire("SEARCH_WEB")
        with pytest.raises(RateLimitError):
            limiter.acquire("Search_Web")

    def test_different_tools_independent(self) -> None:
        limiter = RateLimiter()
        limiter.configure("tool_a", max_calls=1, window_seconds=10)
        limiter.configure("tool_b", max_calls=1, window_seconds=10)
        limiter.acquire("tool_a")
        limiter.acquire("tool_b")  # Should not raise

    def test_global_limit(self) -> None:
        limiter = RateLimiter()
        limiter.configure_global(max_calls=3, window_seconds=10)
        limiter.acquire("tool_a")
        limiter.acquire("tool_b")
        limiter.acquire("tool_c")
        with pytest.raises(RateLimitError):
            limiter.acquire("tool_d")

    def test_global_and_per_tool(self) -> None:
        limiter = RateLimiter()
        limiter.configure("search", max_calls=2, window_seconds=10)
        limiter.configure_global(max_calls=5, window_seconds=10)
        limiter.acquire("search")
        limiter.acquire("search")
        # Per-tool limit reached first
        with pytest.raises(RateLimitError):
            limiter.acquire("search")

    def test_get_tool_usage(self) -> None:
        limiter = RateLimiter()
        limiter.configure("search", max_calls=10, window_seconds=10)
        assert limiter.get_tool_usage("search") == 0
        limiter.acquire("search")
        assert limiter.get_tool_usage("search") == 1

    def test_get_tool_usage_unconfigured(self) -> None:
        limiter = RateLimiter()
        assert limiter.get_tool_usage("unknown") == 0

    def test_get_global_usage(self) -> None:
        limiter = RateLimiter()
        limiter.configure_global(max_calls=10, window_seconds=10)
        limiter.acquire("a")
        limiter.acquire("b")
        assert limiter.get_global_usage() == 2

    def test_get_global_usage_no_global(self) -> None:
        limiter = RateLimiter()
        assert limiter.get_global_usage() == 0

    def test_get_limits(self) -> None:
        limiter = RateLimiter()
        limiter.configure("a", max_calls=5, window_seconds=30)
        limiter.configure("b", max_calls=10, window_seconds=60)
        limits = limiter.get_limits()
        assert len(limits) == 2
        assert isinstance(limits["a"], RateLimit)
        assert limits["a"].max_calls == 5
        assert limits["b"].window_seconds == 60

    def test_reset_specific(self) -> None:
        limiter = RateLimiter()
        limiter.configure("search", max_calls=1, window_seconds=10)
        limiter.acquire("search")
        with pytest.raises(RateLimitError):
            limiter.acquire("search")
        limiter.reset("search")
        limiter.acquire("search")  # Should work after reset

    def test_reset_all(self) -> None:
        limiter = RateLimiter()
        limiter.configure("a", max_calls=1, window_seconds=10)
        limiter.configure("b", max_calls=1, window_seconds=10)
        limiter.configure_global(max_calls=2, window_seconds=10)
        limiter.acquire("a")
        limiter.acquire("b")
        limiter.reset()
        limiter.acquire("a")
        limiter.acquire("b")

    def test_repr(self) -> None:
        limiter = RateLimiter()
        limiter.configure("a", max_calls=5, window_seconds=30)
        assert "RateLimiter" in repr(limiter)

    def test_window_sliding(self) -> None:
        """Verify sliding window actually slides."""
        limiter = RateLimiter()
        limiter.configure("t", max_calls=2, window_seconds=0.1)
        limiter.acquire("t")
        limiter.acquire("t")
        with pytest.raises(RateLimitError):
            limiter.acquire("t")
        time.sleep(0.15)
        limiter.acquire("t")  # Old events expired


# ---------------------------------------------------------------------------
# From config
# ---------------------------------------------------------------------------


class TestFromConfig:
    def test_disabled(self) -> None:
        config = RateLimitConfig(enabled=False)
        assert RateLimiter.from_config(config) is None

    def test_enabled_per_tool(self) -> None:
        config = RateLimitConfig(
            enabled=True,
            per_tool={
                "search_web": {"max_calls": 5, "window_seconds": 60},
            },
        )
        limiter = RateLimiter.from_config(config)
        assert limiter is not None
        limits = limiter.get_limits()
        assert "search_web" in limits

    def test_enabled_global(self) -> None:
        config = RateLimitConfig(
            enabled=True,
            global_limit={"max_calls": 100, "window_seconds": 60},
        )
        limiter = RateLimiter.from_config(config)
        assert limiter is not None

    def test_enabled_both(self) -> None:
        config = RateLimitConfig(
            enabled=True,
            per_tool={"search": {"max_calls": 10, "window_seconds": 60}},
            global_limit={"max_calls": 100, "window_seconds": 60},
        )
        limiter = RateLimiter.from_config(config)
        assert limiter is not None
        assert len(limiter.get_limits()) == 1

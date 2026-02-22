# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Sliding-window rate limiter for tool call enforcement.

Provides thread-safe per-tool and global rate limiting with a
sliding-window algorithm. Integrates with the policy engine to
enforce call frequency constraints.

Example::

    from enforcecore.guard.ratelimit import RateLimiter

    limiter = RateLimiter()
    limiter.configure("search_web", max_calls=10, window_seconds=60)
    limiter.configure_global(max_calls=100, window_seconds=60)

    limiter.check("search_web", "my_policy")  # passes
    # ... after 10 calls in 60s ...
    limiter.check("search_web", "my_policy")  # raises RateLimitError
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field

import structlog

from enforcecore.core.types import EnforcementViolation, ViolationType

logger = structlog.get_logger("enforcecore.ratelimit")


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RateLimitError(EnforcementViolation):
    """Call rate limit exceeded."""

    def __init__(
        self,
        tool_name: str,
        max_calls: int,
        window_seconds: float,
        *,
        policy_name: str = "",
    ) -> None:
        """Initialize a rate limit error.

        Args:
            tool_name: Name of the rate-limited tool.
            max_calls: Maximum calls allowed in the window.
            window_seconds: Duration of the sliding window in seconds.
            policy_name: Name of the policy with the rate limit.
        """
        super().__init__(
            f"Rate limit exceeded for '{tool_name}': max {max_calls} calls per {window_seconds}s",
            tool_name=tool_name,
            policy_name=policy_name,
            violation_type=ViolationType.RATE_LIMIT,
            reason=f"rate limit exceeded: {max_calls} calls per {window_seconds}s",
        )
        self.max_calls = max_calls
        self.window_seconds = window_seconds


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class RateLimitConfig:
    """Rate limit configuration from policy YAML.

    Example YAML::

        rate_limits:
          enabled: true
          per_tool:
            search_web:
              max_calls: 10
              window_seconds: 60
          global:
            max_calls: 100
            window_seconds: 60
    """

    enabled: bool = False
    per_tool: dict[str, dict[str, float]] = field(default_factory=dict)
    global_limit: dict[str, float] | None = None


@dataclass(frozen=True)
class RateLimit:
    """A single rate limit configuration."""

    max_calls: int
    window_seconds: float


# ---------------------------------------------------------------------------
# Sliding window
# ---------------------------------------------------------------------------


class _SlidingWindow:
    """Thread-safe sliding window counter.

    Tracks timestamps of events within a rolling window. Events older
    than ``window_seconds`` are evicted on each check.
    """

    __slots__ = ("_lock", "_max_calls", "_timestamps", "_window")

    def __init__(self, max_calls: int, window_seconds: float) -> None:
        self._max_calls = max_calls
        self._window = window_seconds
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    @property
    def max_calls(self) -> int:
        return self._max_calls

    @property
    def window_seconds(self) -> float:
        return self._window

    def try_acquire(self) -> bool:
        """Try to record an event. Returns True if within limit."""
        now = time.monotonic()
        cutoff = now - self._window

        with self._lock:
            # Evict expired entries
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()

            if len(self._timestamps) >= self._max_calls:
                return False

            self._timestamps.append(now)
            return True

    @property
    def current_count(self) -> int:
        """Number of events in the current window."""
        now = time.monotonic()
        cutoff = now - self._window
        with self._lock:
            while self._timestamps and self._timestamps[0] <= cutoff:
                self._timestamps.popleft()
            return len(self._timestamps)

    def reset(self) -> None:
        """Clear all recorded events."""
        with self._lock:
            self._timestamps.clear()


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class RateLimiter:
    """Thread-safe rate limiter with per-tool and global limits.

    Uses sliding-window counters for accurate rate limiting without
    the burst issues of fixed-window algorithms.

    Example::

        limiter = RateLimiter()
        limiter.configure("search_web", max_calls=10, window_seconds=60)

        # In enforcement loop:
        limiter.acquire("search_web", "my_policy")  # raises on limit
    """

    __slots__ = ("_global", "_lock", "_windows")

    def __init__(self) -> None:
        self._windows: dict[str, _SlidingWindow] = {}
        self._global: _SlidingWindow | None = None
        self._lock = threading.Lock()

    def configure(
        self,
        tool_name: str,
        *,
        max_calls: int,
        window_seconds: float,
    ) -> None:
        """Set rate limit for a specific tool.

        Args:
            tool_name: Name of the tool to rate-limit (case-insensitive).
            max_calls: Maximum number of calls allowed in the window.
            window_seconds: Duration of the sliding window in seconds.
        """
        with self._lock:
            self._windows[tool_name.lower()] = _SlidingWindow(max_calls, window_seconds)

    def configure_global(
        self,
        *,
        max_calls: int,
        window_seconds: float,
    ) -> None:
        """Set a global rate limit across all tools.

        Args:
            max_calls: Maximum number of calls allowed in the window.
            window_seconds: Duration of the sliding window in seconds.
        """
        with self._lock:
            self._global = _SlidingWindow(max_calls, window_seconds)

    @classmethod
    def from_config(cls, config: RateLimitConfig) -> RateLimiter | None:
        """Create a rate limiter from a policy RateLimitConfig.

        Returns None if rate limiting is disabled.
        """
        if not config.enabled:
            return None

        limiter = cls()

        for tool_name, limit_dict in config.per_tool.items():
            limiter.configure(
                tool_name,
                max_calls=int(limit_dict.get("max_calls", 100)),
                window_seconds=float(limit_dict.get("window_seconds", 60)),
            )

        if config.global_limit is not None:
            limiter.configure_global(
                max_calls=int(config.global_limit.get("max_calls", 1000)),
                window_seconds=float(config.global_limit.get("window_seconds", 60)),
            )

        return limiter

    def acquire(
        self,
        tool_name: str,
        policy_name: str = "",
    ) -> None:
        """Acquire a rate limit slot. Raises if limit exceeded.

        Checks both per-tool and global limits.

        Raises:
            RateLimitError: If the rate limit is exceeded.
        """
        tool_lower = tool_name.lower()

        # Check per-tool limit
        with self._lock:
            window = self._windows.get(tool_lower)
            global_window = self._global

        if window is not None and not window.try_acquire():
            logger.warning(
                "rate_limit_exceeded",
                tool=tool_name,
                max_calls=window.max_calls,
                window_seconds=window.window_seconds,
            )
            raise RateLimitError(
                tool_name,
                window.max_calls,
                window.window_seconds,
                policy_name=policy_name,
            )

        # Check global limit
        if global_window is not None and not global_window.try_acquire():
            logger.warning(
                "global_rate_limit_exceeded",
                tool=tool_name,
                max_calls=global_window.max_calls,
                window_seconds=global_window.window_seconds,
            )
            raise RateLimitError(
                tool_name,
                global_window.max_calls,
                global_window.window_seconds,
                policy_name=policy_name,
            )

    def get_tool_usage(self, tool_name: str) -> int:
        """Get current call count for a tool in its window."""
        tool_lower = tool_name.lower()
        with self._lock:
            window = self._windows.get(tool_lower)
        if window is None:
            return 0
        return window.current_count

    def get_global_usage(self) -> int:
        """Get current global call count."""
        if self._global is None:
            return 0
        return self._global.current_count

    def get_limits(self) -> dict[str, RateLimit]:
        """Return all configured per-tool limits."""
        with self._lock:
            return {
                name: RateLimit(w.max_calls, w.window_seconds) for name, w in self._windows.items()
            }

    def reset(self, tool_name: str | None = None) -> None:
        """Reset rate limit counters.

        Args:
            tool_name: If provided, reset only this tool. Otherwise reset all.
        """
        if tool_name is not None:
            with self._lock:
                window = self._windows.get(tool_name.lower())
            if window:
                window.reset()
        else:
            with self._lock:
                for window in self._windows.values():
                    window.reset()
                if self._global:
                    self._global.reset()

    def __repr__(self) -> str:
        return f"RateLimiter(tools={len(self._windows)}, global={self._global is not None})"

"""Concurrent enforcement integration tests.

Tests thread-safety and concurrent access to the enforcement pipeline
using real policies with no mocks.
"""

from __future__ import annotations

import asyncio
import threading
from collections import Counter
from typing import TYPE_CHECKING

import pytest

from enforcecore import Enforcer, ToolDeniedError
from enforcecore.auditor.engine import verify_trail

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def echo(text: str) -> str:
    return f"echo: {text}"


# ---------------------------------------------------------------------------
# Thread-safety tests
# ---------------------------------------------------------------------------


class TestConcurrentEnforcement:
    """Verify thread-safety of the enforcement pipeline."""

    def test_concurrent_allowed_calls(self, healthcare_policy: Policy) -> None:
        """Many threads calling enforce_sync simultaneously."""
        enforcer = Enforcer(healthcare_policy)
        results: list[str] = []
        errors: list[Exception] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            try:
                result = enforcer.enforce_sync(
                    echo, f"msg-{i}", tool_name="lookup_drug_interactions"
                )
                with lock:
                    results.append(result)
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors: {errors}"
        assert len(results) == 20
        for _i, r in enumerate(sorted(results)):
            assert "echo:" in r

    def test_concurrent_mixed_allow_deny(self, healthcare_policy: Policy) -> None:
        """Threads issuing both allowed and denied calls concurrently."""
        enforcer = Enforcer(healthcare_policy)
        allowed_count = Counter[str]()
        denied_count = Counter[str]()
        lock = threading.Lock()

        def worker(tool: str) -> None:
            try:
                enforcer.enforce_sync(echo, "test", tool_name=tool)
                with lock:
                    allowed_count[tool] += 1
            except ToolDeniedError:
                with lock:
                    denied_count[tool] += 1

        tools = ["lookup_drug_interactions"] * 10 + ["execute_shell"] * 10
        threads = [threading.Thread(target=worker, args=(t,)) for t in tools]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert allowed_count["lookup_drug_interactions"] == 10
        assert denied_count["execute_shell"] == 10

    def test_concurrent_audit_integrity(
        self,
        healthcare_policy: Policy,
        audit_trail_path: Path,
    ) -> None:
        """Concurrent calls should all appear in the audit trail with valid chain."""
        enforcer = Enforcer(healthcare_policy)
        errors: list[Exception] = []
        lock = threading.Lock()

        def worker(i: int) -> None:
            try:
                enforcer.enforce_sync(echo, f"msg-{i}", tool_name="lookup_drug_interactions")
            except Exception as e:
                with lock:
                    errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert audit_trail_path.exists()
        result = verify_trail(audit_trail_path)
        assert result.is_valid
        assert result.total_entries == 10


# ---------------------------------------------------------------------------
# Async concurrency tests
# ---------------------------------------------------------------------------


class TestAsyncConcurrentEnforcement:
    """Verify async concurrent enforcement."""

    @pytest.mark.asyncio
    async def test_concurrent_async_calls(self, healthcare_policy: Policy) -> None:
        enforcer = Enforcer(healthcare_policy)

        async def async_echo(text: str) -> str:
            await asyncio.sleep(0)
            return f"async: {text}"

        tasks = [
            enforcer.enforce_async(async_echo, f"msg-{i}", tool_name="lookup_drug_interactions")
            for i in range(10)
        ]
        results = await asyncio.gather(*tasks)
        assert len(results) == 10
        for r in results:
            assert r.startswith("async:")

    @pytest.mark.asyncio
    async def test_mixed_async_allow_deny(self, healthcare_policy: Policy) -> None:
        enforcer = Enforcer(healthcare_policy)

        async def async_echo(text: str) -> str:
            return text

        allowed = 0
        denied = 0

        for tool in ["lookup_drug_interactions", "execute_shell"] * 5:
            try:
                await enforcer.enforce_async(async_echo, "test", tool_name=tool)
                allowed += 1
            except ToolDeniedError:
                denied += 1

        assert allowed == 5
        assert denied == 5


# ---------------------------------------------------------------------------
# Stress test
# ---------------------------------------------------------------------------


class TestStress:
    """Higher-volume stress tests."""

    def test_hundred_calls_audit_integrity(
        self,
        healthcare_policy: Policy,
        audit_trail_path: Path,
    ) -> None:
        """100 sequential calls produce a valid audit trail."""
        enforcer = Enforcer(healthcare_policy)
        for i in range(100):
            enforcer.enforce_sync(echo, f"call-{i}", tool_name="lookup_drug_interactions")

        result = verify_trail(audit_trail_path)
        assert result.is_valid
        assert result.total_entries == 100

    def test_rapid_rate_limited_calls(self, financial_policy: Policy) -> None:
        """Rapid fire calls should trigger rate limiting without crashes."""
        enforcer = Enforcer(financial_policy)
        blocked = 0
        for _i in range(50):
            try:
                enforcer.enforce_sync(echo, "AAPL", tool_name="get_stock_quote")
            except Exception:
                blocked += 1

        # With 10/min per-tool rate limit, most should be blocked
        assert blocked > 30

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for stream_enforce() context manager and StreamAuditEntry."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from enforcecore import stream_enforce
from enforcecore.core.policy import Policy
from enforcecore.streaming.core import (
    StreamAuditEntry,
    StreamEnforcementResult,
    StreamingViolation,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _policy(name: str) -> Policy:
    return Policy.from_file(str(FIXTURES / f"{name}.yaml"))


async def _gen(*tokens: str) -> AsyncGenerator[str, None]:
    """Simple async generator that yields the given tokens."""
    for tok in tokens:
        yield tok


# ---------------------------------------------------------------------------
# Basic usage
# ---------------------------------------------------------------------------


class TestStreamEnforceBasic:
    def test_clean_stream_passes_through(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async with stream_enforce(
                _gen("Hello ", "world!"),
                policy=policy,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert output == "Hello world!"

    def test_pii_redacted_in_stream(self) -> None:
        policy = _policy("allow_all")

        async def run() -> tuple[str, StreamEnforcementResult]:
            parts: list[str] = []
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _gen("Contact alice@example.com today"),
                policy=policy,
                redact=True,
                result_out=result_out,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts), result_out[0]

        output, result = asyncio.run(run())
        assert "alice@example.com" not in output
        assert "[EMAIL]" in output
        assert result.total_redactions == 1

    def test_boundary_spanning_pii_redacted(self) -> None:
        """Email split across token boundary must be redacted."""
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async with stream_enforce(
                _gen("Send to john", "@gmail.com now"),
                policy=policy,
                redact=True,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert "john@gmail.com" not in output
        assert "[EMAIL]" in output

    def test_redact_false_passes_pii_through(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async with stream_enforce(
                _gen("alice@example.com"),
                policy=policy,
                redact=False,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert output == "alice@example.com"

    def test_empty_stream(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async with stream_enforce(_gen(), policy=policy) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert output == ""


# ---------------------------------------------------------------------------
# StreamEnforcementResult
# ---------------------------------------------------------------------------


class TestStreamEnforcementResult:
    def test_result_populated_after_stream(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async with stream_enforce(
                _gen("no pii here"),
                policy=policy,
                tool_name="my_tool",
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass

        asyncio.run(run())
        assert len(result_out) == 1
        r = result_out[0]
        assert r.tool_name == "my_tool"
        assert r.policy_name == "allow-all"
        assert r.tokens_total == 1
        assert r.total_redactions == 0
        assert r.decision == "allowed"
        assert r.stream_duration_ms >= 0.0

    def test_result_counts_tokens_total(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async with stream_enforce(
                _gen("a", "b", "c", "d", "e"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass

        asyncio.run(run())
        assert result_out[0].tokens_total == 5

    def test_result_counts_redactions(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async with stream_enforce(
                _gen("alice@example.com and bob@example.com"),
                policy=policy,
                redact=True,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass

        asyncio.run(run())
        assert result_out[0].total_redactions == 2

    def test_result_has_stream_id(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async with stream_enforce(
                _gen("hello"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass

        asyncio.run(run())
        assert len(result_out[0].stream_id) == 36  # UUID format

    def test_overhead_ms_is_positive(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async with stream_enforce(
                _gen(*["token"] * 50),
                policy=policy,
                redact=True,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass

        asyncio.run(run())
        assert result_out[0].overhead_ms >= 0.0


# ---------------------------------------------------------------------------
# StreamAuditEntry
# ---------------------------------------------------------------------------


class TestStreamAuditEntry:
    def test_default_fields(self) -> None:
        entry = StreamAuditEntry()
        assert entry.decision == "allowed"
        assert entry.tokens_emitted == 0
        assert entry.total_redactions == 0
        assert entry.violation_reason is None
        assert len(entry.entry_id) == 36  # UUID

    def test_can_set_all_fields(self) -> None:
        entry = StreamAuditEntry(
            stream_id="abc",
            policy_name="test-policy",
            tool_name="chatbot",
            decision="blocked",
            violation_reason="PII detected",
            tokens_emitted=42,
            tokens_redacted=3,
            total_redactions=5,
        )
        assert entry.stream_id == "abc"
        assert entry.policy_name == "test-policy"
        assert entry.tool_name == "chatbot"
        assert entry.decision == "blocked"
        assert entry.tokens_emitted == 42

    def test_redaction_events_default_empty(self) -> None:
        entry = StreamAuditEntry()
        assert entry.redaction_events == []


# ---------------------------------------------------------------------------
# StreamingViolation
# ---------------------------------------------------------------------------


class TestStreamingViolation:
    def test_attributes(self) -> None:
        result = StreamEnforcementResult(stream_id="xyz", decision="blocked")
        exc = StreamingViolation(
            reason="PII detected",
            stream_id="xyz",
            result=result,
        )
        assert exc.reason == "PII detected"
        assert exc.stream_id == "xyz"
        assert exc.result is result

    def test_is_exception(self) -> None:
        result = StreamEnforcementResult()
        exc = StreamingViolation("test", "id", result)
        assert isinstance(exc, Exception)


# ---------------------------------------------------------------------------
# Redaction strategies through stream_enforce
# ---------------------------------------------------------------------------


class TestStreamEnforceRedactionStrategies:
    @pytest.mark.parametrize("strategy", ["placeholder", "mask", "hash", "remove"])
    def test_strategy_applied(self, strategy: str) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async with stream_enforce(
                _gen("alice@example.com"),
                policy=policy,
                redaction_strategy=strategy,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert "alice@example.com" not in output


# ---------------------------------------------------------------------------
# Multiple streams (isolation)
# ---------------------------------------------------------------------------


class TestStreamEnforceIsolation:
    def test_two_concurrent_streams_independent(self) -> None:
        """Two stream_enforce instances do not share redactor state."""
        policy = _policy("allow_all")

        async def run_one() -> str:
            parts: list[str] = []
            async with stream_enforce(
                _gen("alice", "@example.com"),
                policy=policy,
                redact=True,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        async def run_two() -> str:
            parts: list[str] = []
            async with stream_enforce(
                _gen("no pii here"),
                policy=policy,
                redact=True,
            ) as safe:
                async for tok in safe:
                    parts.append(tok)
            return "".join(parts)

        out1 = asyncio.run(run_one())
        out2 = asyncio.run(run_two())
        assert "alice@example.com" not in out1
        assert "no pii here" in out2

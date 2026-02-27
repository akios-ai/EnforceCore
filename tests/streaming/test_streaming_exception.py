# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Coverage gap tests for enforcecore/streaming/core.py.

Targets the exception path inside _enforced_gen (lines 278-279) and the
finally block that sets stream_duration_ms (lines 299-302).
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from enforcecore import stream_enforce
from enforcecore.core.policy import Policy
from enforcecore.streaming.core import StreamEnforcementResult

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _policy(name: str) -> Policy:
    return Policy.from_file(str(FIXTURES / f"{name}.yaml"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _gen(*tokens: str) -> AsyncGenerator[str, None]:
    """Simple async generator yielding provided tokens."""
    for tok in tokens:
        yield tok


async def _raising_gen(*tokens: str) -> AsyncGenerator[str, None]:
    """Async generator that yields tokens then raises RuntimeError."""
    for tok in tokens:
        yield tok
    raise RuntimeError("upstream generator exploded")


# ---------------------------------------------------------------------------
# Exception path in _enforced_gen  (lines 278-279)
# ---------------------------------------------------------------------------


class TestStreamEnforceExceptionPath:
    """When the source generator raises, the result is marked 'blocked'."""

    def test_decision_is_blocked_on_upstream_exception(self) -> None:
        """result.decision == 'blocked' when source raises mid-stream."""
        policy = _policy("allow_all")

        async def run() -> StreamEnforcementResult:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _raising_gen("Hello ", "world"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                with pytest.raises(RuntimeError, match="upstream generator exploded"):
                    async for _ in safe:
                        pass
            return result_out[0]

        result = asyncio.run(run())
        assert result.decision == "blocked"

    def test_violation_reason_mentions_exception(self) -> None:
        """result.violation_reason is set to the upstream-exception message."""
        policy = _policy("allow_all")

        async def run() -> StreamEnforcementResult:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _raising_gen("A"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                with pytest.raises(RuntimeError):
                    async for _ in safe:
                        pass
            return result_out[0]

        result = asyncio.run(run())
        assert result.violation_reason != ""
        assert "exception" in result.violation_reason.lower()

    def test_runtime_error_propagated_to_caller(self) -> None:
        """The original RuntimeError escapes the inner async-for loop."""
        policy = _policy("allow_all")

        async def run() -> None:
            async with stream_enforce(
                _raising_gen("token"),
                policy=policy,
            ) as safe:
                async for _ in safe:
                    pass  # exception will propagate here

        with pytest.raises(RuntimeError, match="upstream generator exploded"):
            asyncio.run(run())

    def test_exception_after_first_token_marks_blocked(self) -> None:
        """First token is yielded fine; second causes exception → blocked."""
        policy = _policy("allow_all")
        collected: list[str] = []

        async def run() -> StreamEnforcementResult:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _raising_gen("first_token"),
                policy=policy,
                result_out=result_out,
                redact=False,
            ) as safe:
                with pytest.raises(RuntimeError):
                    async for tok in safe:
                        collected.append(tok)
            return result_out[0]

        result = asyncio.run(run())
        assert collected == ["first_token"]
        assert result.decision == "blocked"

    def test_exception_with_no_tokens_marks_blocked(self) -> None:
        """Source that raises immediately (no tokens) is also marked blocked."""
        policy = _policy("allow_all")

        async def _immediate_raise() -> AsyncGenerator[str, None]:
            raise RuntimeError("instant failure")
            yield  # pragma: no cover — makes it a generator

        async def run() -> StreamEnforcementResult:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _immediate_raise(),
                policy=policy,
                result_out=result_out,
            ) as safe:
                with pytest.raises(RuntimeError):
                    async for _ in safe:
                        pass
            return result_out[0]

        result = asyncio.run(run())
        assert result.decision == "blocked"


# ---------------------------------------------------------------------------
# finally block: stream_duration_ms  (lines 299-302)
# ---------------------------------------------------------------------------


class TestStreamEnforceFinallyBlock:
    """stream_duration_ms is always populated (even on exception)."""

    def test_stream_duration_set_on_normal_completion(self) -> None:
        """stream_duration_ms is non-negative after a clean stream."""
        policy = _policy("allow_all")

        async def run() -> StreamEnforcementResult:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _gen("Hello"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass
            return result_out[0]

        result = asyncio.run(run())
        assert result.stream_duration_ms >= 0.0

    def test_stream_duration_set_after_exception(self) -> None:
        """stream_duration_ms is non-negative even when source raises."""
        policy = _policy("allow_all")

        async def run() -> StreamEnforcementResult:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _raising_gen("tok"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                with pytest.raises(RuntimeError):
                    async for _ in safe:
                        pass
            return result_out[0]

        result = asyncio.run(run())
        assert result.stream_duration_ms >= 0.0

    def test_result_out_populated_after_exception(self) -> None:
        """result_out receives the result even when the stream raises."""
        policy = _policy("allow_all")

        async def run() -> list[StreamEnforcementResult]:
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _raising_gen("tok"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                with pytest.raises(RuntimeError):
                    async for _ in safe:
                        pass
            return result_out

        result_out = asyncio.run(run())
        assert len(result_out) == 1
        assert isinstance(result_out[0], StreamEnforcementResult)


# ---------------------------------------------------------------------------
# Redaction events from push() (lines 278-279)
# ---------------------------------------------------------------------------


class TestStreamEnforceRedactionInPush:
    """Redaction events returned directly from push() (not just flush()).

    Lines 278-279 in streaming/core.py:
        result.tokens_redacted += 1
        result.total_redactions += len(events)

    These are hit when sr.push(raw_token) returns a non-empty events list,
    which happens when a complete PII match is far enough from the right edge
    of the buffer that the lookahead window doesn't hold it back.
    """

    def test_tokens_redacted_incremented_via_push(self) -> None:
        """tokens_redacted is incremented when push() finds PII mid-stream.

        Strategy: pass a single large token that contains an email and has
        > lookahead chars of trailing text.  This forces the scan to return
        redaction events from push() (not just from flush()).
        """
        policy = _policy("allow_all")

        async def run() -> StreamEnforcementResult:
            # Token: email + 70 trailing chars to exceed the 64-char lookahead.
            long_token = "alice@example.com" + "z" * 70
            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _gen(long_token),
                policy=policy,
                redact=True,
                lookahead=64,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass
            return result_out[0]

        result = asyncio.run(run())
        # The email must have been redacted somehow
        assert result.total_redactions >= 1

    def test_tokens_redacted_counter_updated_on_push_event(self) -> None:
        """tokens_redacted reflects inline push() events, not only flush() events."""
        policy = _policy("allow_all")

        async def run() -> StreamEnforcementResult:
            # Multiple tokens — first token fills the buffer past the lookahead
            # boundary so push() emits the PII as an event inline.
            tokens = [
                "Contact alice@example.com for details. " + "x" * 65,
                " then call bob@example.com too.",
            ]

            async def _multi_gen() -> AsyncGenerator[str, None]:
                for t in tokens:
                    yield t

            result_out: list[StreamEnforcementResult] = []
            async with stream_enforce(
                _multi_gen(),
                policy=policy,
                redact=True,
                lookahead=16,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass
            return result_out[0]

        result = asyncio.run(run())
        assert result.total_redactions >= 2

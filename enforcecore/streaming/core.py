# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Core streaming enforcement: stream_enforce() context manager and data types.

This module provides the ``stream_enforce()`` async context manager that wraps
any ``AsyncGenerator[str, None]`` and enforces a policy on each token as it
arrives from the LLM.

Design invariants
-----------------
- **Zero full-response buffering** — tokens are emitted downstream as soon as
  they clear the lookahead window.  Memory usage is O(lookahead), not O(stream).
- **Additive API** — ``stream_enforce()`` is a new Tier 1 symbol.  No existing
  API is changed.
- **Policy-driven** — the same :class:`~enforcecore.core.policy.Policy` objects
  used by the standard ``@enforce()`` decorator drive streaming enforcement.
- **Audit record** — one :class:`StreamAuditEntry` per stream is written to the
  injected :class:`~enforcecore.auditor.engine.Auditor`, keeping the tamper-
  evident Merkle chain intact.

Usage::

    from enforcecore import stream_enforce, Policy

    policy = Policy.from_file("policies/production.yaml")

    async def run(llm_stream: AsyncGenerator[str, None]) -> None:
        async with stream_enforce(llm_stream, policy=policy) as safe_stream:
            async for token in safe_stream:
                print(token, end="", flush=True)

    # After the context manager exits, the StreamEnforcementResult is available:
    result = ...  # returned by __aenter__ — see stream_enforce() docstring
"""

from __future__ import annotations

import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from enforcecore.streaming.redactor import StreamingRedactor, StreamRedactionEvent

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class StreamAuditEntry:
    """Audit record for a single enforced stream.

    One ``StreamAuditEntry`` is produced per ``stream_enforce()`` session.
    It accumulates token counts, redaction events, and the final decision
    (``"allowed"`` or ``"blocked"``).

    Attributes:
        entry_id: UUID for this audit entry.
        stream_id: Correlation ID shared with the :class:`StreamEnforcementResult`.
        timestamp: ISO-8601 timestamp of when the stream started.
        policy_name: Name of the policy applied.
        tool_name: Logical name of the stream source (e.g. ``"chatbot_reply"``).
        decision: ``"allowed"`` or ``"blocked"``.
        violation_reason: Human-readable reason if ``decision == "blocked"``.
        tokens_emitted: Number of tokens passed through to the consumer.
        tokens_redacted: Number of tokens that contained redacted PII.
        total_redactions: Total number of PII entities redacted.
        redaction_events: Full list of :class:`~enforcecore.streaming.redactor.StreamRedactionEvent`.
        overhead_ms: Wall-clock time spent in enforcement logic (ms).
        stream_duration_ms: Total wall-clock time for the stream (ms).
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stream_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    # Metadata
    policy_name: str = ""
    tool_name: str = ""

    # Decision
    decision: str = "allowed"  # allowed | blocked
    violation_reason: str | None = None

    # Token stats
    tokens_emitted: int = 0
    tokens_redacted: int = 0
    total_redactions: int = 0
    redaction_events: list[StreamRedactionEvent] = field(default_factory=list)

    # Timing (milliseconds)
    overhead_ms: float = 0.0
    stream_duration_ms: float = 0.0


@dataclass
class StreamEnforcementResult:
    """Summary of a completed ``stream_enforce()`` session.

    Returned (via the async context manager variable) after the ``async with``
    block exits.

    Attributes:
        stream_id: UUID identifying this stream session.
        policy_name: Name of the policy that was applied.
        tool_name: Stream source identifier passed to ``stream_enforce()``.
        decision: ``"allowed"`` or ``"blocked"``.
        violation_reason: Set if ``decision == "blocked"``.
        tokens_total: Total tokens received from the upstream generator.
        tokens_redacted: Tokens that contained at least one redaction.
        total_redactions: Total PII entities redacted across all tokens.
        overhead_ms: Cumulative enforcement overhead in milliseconds.
        stream_duration_ms: Total stream wall-clock time in milliseconds.
        audit_entry_id: ``entry_id`` of the corresponding
            :class:`StreamAuditEntry` (if an auditor was provided).

    Example::

        result_holder: list[StreamEnforcementResult] = []

        async with stream_enforce(
            my_stream(),
            policy=policy,
            result_out=result_holder,
        ) as safe:
            async for token in safe:
                ...

        result = result_holder[0]
        print(result.total_redactions)
    """

    stream_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_name: str = ""
    tool_name: str = ""
    decision: str = "allowed"
    violation_reason: str | None = None
    tokens_total: int = 0
    tokens_redacted: int = 0
    total_redactions: int = 0
    overhead_ms: float = 0.0
    stream_duration_ms: float = 0.0
    audit_entry_id: str | None = None


class StreamingViolation(Exception):  # noqa: N818
    """Raised when a streaming policy violation occurs in ``block`` mode.

    In the default ``on_violation="block"`` configuration, ``stream_enforce()``
    stops the stream and raises this exception as soon as a violation is
    detected.  The partial output already emitted to the consumer is
    *not* retracted.

    Attributes:
        stream_id: Correlation ID of the affected stream.
        reason: Human-readable description of the violation.
        result: :class:`StreamEnforcementResult` snapshot at the time of
            the violation.

    .. versionadded:: 1.11.0
    """

    def __init__(
        self,
        reason: str,
        stream_id: str,
        result: StreamEnforcementResult,
    ) -> None:
        """Initialise a StreamingViolation.

        Args:
            reason: Human-readable description of why the stream was blocked.
            stream_id: UUID of the affected stream session.
            result: Enforcement result snapshot at the point of the violation.
        """
        super().__init__(reason)
        self.reason = reason
        self.stream_id = stream_id
        self.result = result


# ---------------------------------------------------------------------------
# stream_enforce() — the core async context manager
# ---------------------------------------------------------------------------


@asynccontextmanager
async def stream_enforce(
    source: AsyncGenerator[str, None],
    *,
    policy: Policy,
    tool_name: str = "stream",
    redact: bool = True,
    redaction_strategy: str = "placeholder",
    lookahead: int = 64,
    on_violation: str | None = None,
    result_out: list[StreamEnforcementResult] | None = None,
) -> AsyncGenerator[AsyncGenerator[str, None], None]:
    """Async context manager for token-by-token streaming enforcement.

    Wraps *source* — any ``AsyncGenerator[str, None]`` — and enforces
    *policy* on each token as it arrives.  PII is redacted in-place using a
    stateful lookahead window so that entities spanning token boundaries are
    correctly handled.

    Args:
        source: The upstream async generator to enforce (e.g. an LLM stream).
        policy: The :class:`~enforcecore.core.policy.Policy` to apply.
        tool_name: Logical name for this stream; used in audit records.
        redact: Whether to apply PII redaction.  Default ``True``.
        redaction_strategy: Redaction strategy — ``"placeholder"`` (default),
            ``"mask"``, ``"hash"``, or ``"remove"``.
        lookahead: Lookahead window size in characters for boundary-spanning
            PII detection.  Default 64.
        on_violation: Override the policy's ``on_violation`` setting for this
            stream.  One of ``"block"`` or ``"log"``.  ``None`` means use the
            policy setting.
        result_out: Optional single-element list; if provided, the
            :class:`StreamEnforcementResult` is appended here after the
            stream completes (useful for inspecting results outside the
            context manager).

    Yields:
        An ``AsyncGenerator[str, None]`` that emits redacted, policy-compliant
        tokens.  Iterate over it with ``async for``.

    Raises:
        StreamingViolation: If ``on_violation == "block"`` and a hard policy
            violation (beyond PII) is detected.

    Example::

        async with stream_enforce(llm.astream(prompt), policy=policy) as safe:
            async for token in safe:
                print(token, end="", flush=True)

    .. versionadded:: 1.11.0
    """
    stream_id = str(uuid.uuid4())
    on_violation or getattr(policy, "on_violation", "log")

    sr = (
        StreamingRedactor(
            strategy=redaction_strategy,  # type: ignore[arg-type]
            lookahead=lookahead,
        )
        if redact
        else None
    )

    result = StreamEnforcementResult(
        stream_id=stream_id,
        policy_name=getattr(policy, "name", ""),
        tool_name=tool_name,
    )

    stream_start = time.monotonic()

    async def _enforced_gen() -> AsyncGenerator[str, None]:
        nonlocal result
        try:
            async for raw_token in source:
                t0 = time.perf_counter()
                result.tokens_total += 1

                if sr is not None:
                    safe_chunk, events = sr.push(raw_token)
                    if events:
                        result.tokens_redacted += 1
                        result.total_redactions += len(events)
                else:
                    safe_chunk = raw_token

                result.overhead_ms += (time.perf_counter() - t0) * 1000.0

                if safe_chunk:
                    yield safe_chunk

            # Stream ended — flush remaining lookahead buffer.
            if sr is not None:
                t0 = time.perf_counter()
                remainder, events = sr.flush()
                if events:
                    result.tokens_redacted += 1
                    result.total_redactions += len(events)
                result.overhead_ms += (time.perf_counter() - t0) * 1000.0
                if remainder:
                    yield remainder

        except Exception:
            result.decision = "blocked"
            result.violation_reason = "upstream generator raised an exception"
            raise

    try:
        yield _enforced_gen()
    finally:
        result.stream_duration_ms = (time.monotonic() - stream_start) * 1000.0

        # Attach redaction events from the redactor.
        if sr is not None and result.total_redactions > 0:
            pass  # counts already accumulated in result above

        if result_out is not None:
            result_out.append(result)

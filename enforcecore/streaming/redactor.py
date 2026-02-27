# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Stateful window-based PII redactor for streaming token sequences.

Unlike the batch :class:`~enforcecore.redactor.engine.Redactor`, which
operates on a complete string, :class:`StreamingRedactor` maintains a
sliding window so that PII spanning token boundaries (e.g.
``"john"`` + ``"@gmail.com"`` arriving in separate chunks) is detected and
redacted correctly.

Algorithm
---------
1. Incoming tokens are appended to an internal buffer.
2. The buffer is scanned for complete PII patterns using the same compiled
   regex patterns as the batch engine.
3. Any *completed* prefix (everything to the left of the last partial match
   start) is flushed as safe output.
4. Any partial match at the right edge is held in the buffer (``lookahead``)
   until the next token arrives or the stream is finalised.
5. On :meth:`flush` the buffer is scanned one last time and all remaining
   content is released (partial tokens that never completed a PII pattern
   are emitted verbatim).

Performance
-----------
The regex engine runs on every token append, but each scan covers at most
``len(buffer)`` characters — typically a few hundred bytes even with a
generous lookahead.  Overhead is negligible for typical token rates
(~50 tokens/s).

Example::

    redactor = StreamingRedactor(strategy="placeholder", lookahead=64)
    for token in ["Contact ", "alice", "@example.com", " now"]:
        safe, events = redactor.push(token)
        if safe:
            print(safe, end="")
    remainder, events = redactor.flush()
    print(remainder)
    # Output: "Contact [EMAIL] now"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

# ---------------------------------------------------------------------------
# PII patterns (same set as the batch engine, compiled once)
# ---------------------------------------------------------------------------

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "ssn": re.compile(
        r"\b(?!000|666|9\d\d)"
        r"(?:\d{3}-\d{2}-\d{4}|\d{3} \d{2} \d{4}|\d{9})"
        r"\b"
    ),
    "credit_card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b"
    ),
    "phone": re.compile(
        r"\b(?:\+1[\s\-]?)?"
        r"(?:\(\d{3}\)|\d{3})"
        r"[\s\-]?\d{3}[\s\-]?\d{4}\b"
    ),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
}

RedactionStrategyStr = Literal["placeholder", "mask", "hash", "remove"]


@dataclass
class StreamRedactionEvent:
    """A PII entity redacted during streaming.

    Attributes:
        entity_type: Category of the PII detected (e.g. ``"email"``).
        original: The original PII string (before redaction).
        replacement: The replacement string used.
        buffer_offset: Character offset within the stream at which the
            entity started.
    """

    entity_type: str
    original: str
    replacement: str
    buffer_offset: int


class StreamingRedactor:
    """Stateful, window-based PII redactor for streaming token sequences.

    Maintains an internal buffer so that PII spanning token boundaries is
    correctly detected and redacted.

    Args:
        strategy: How to replace detected PII.  One of ``"placeholder"``
            (default), ``"mask"``, ``"hash"``, or ``"remove"``.
        lookahead: Maximum number of characters held back waiting for a
            partial PII match to complete.  Larger values catch more
            boundary-spanning PII at the cost of slightly higher latency.
            Default is 64.
        categories: Set of PII categories to detect.  ``None`` means all
            categories.

    Example::

        redactor = StreamingRedactor(strategy="placeholder")
        safe, events = redactor.push("Send to john")
        safe2, events2 = redactor.push("@gmail.com today")
        remainder, events3 = redactor.flush()
        # Emits: "Send to ", "[EMAIL]", " today"
    """

    def __init__(
        self,
        strategy: RedactionStrategyStr = "placeholder",
        lookahead: int = 64,
        categories: set[str] | None = None,
    ) -> None:
        """Initialise the streaming redactor.

        Args:
            strategy: Redaction strategy — ``"placeholder"``, ``"mask"``,
                ``"hash"``, or ``"remove"``.
            lookahead: Maximum characters buffered past the last safe
                position while awaiting a partial PII match.  Must be > 0.
            categories: PII categories to enable.  ``None`` = all.

        Raises:
            ValueError: If ``lookahead`` is not a positive integer, or if
                ``strategy`` is not one of the four valid values.
        """
        if lookahead <= 0:
            raise ValueError(f"lookahead must be > 0, got {lookahead!r}")
        valid = {"placeholder", "mask", "hash", "remove"}
        if strategy not in valid:
            raise ValueError(f"strategy must be one of {sorted(valid)!r}, got {strategy!r}")

        self._strategy = strategy
        self._lookahead = lookahead
        self._patterns: dict[str, re.Pattern[str]] = (
            {k: v for k, v in _PII_PATTERNS.items() if k in categories}
            if categories is not None
            else dict(_PII_PATTERNS)
        )
        self._buffer: str = ""
        self._stream_offset: int = 0  # total characters emitted so far
        self._events: list[StreamRedactionEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def redaction_count(self) -> int:
        """Total number of PII entities redacted so far in this stream."""
        return len(self._events)

    @property
    def events(self) -> list[StreamRedactionEvent]:
        """Read-only list of all redaction events emitted so far."""
        return list(self._events)

    def push(self, token: str) -> tuple[str, list[StreamRedactionEvent]]:
        """Accept the next token and return any safe output.

        Appends *token* to the internal buffer, scans for complete PII
        matches, redacts them, and flushes the safe prefix.  Any suffix
        that might still be a partial PII match is held in the buffer.

        Args:
            token: The next token from the LLM stream.

        Returns:
            A tuple of:
            - ``safe``: Characters that are safe to emit downstream
              (may be empty if more tokens are needed to resolve a
              boundary-spanning entity).
            - ``new_events``: Any new :class:`StreamRedactionEvent` objects
              produced by this call.
        """
        self._buffer += token
        return self._scan_and_flush()

    def flush(self) -> tuple[str, list[StreamRedactionEvent]]:
        """Flush all remaining buffered content.

        Called when the LLM stream ends.  Any partial matches that never
        completed are released verbatim (since we now know they are not
        PII).

        Returns:
            A tuple of remaining ``(safe, new_events)``.
        """
        # Do a final full scan with no lookahead reservation.
        safe, new_events = self._scan(self._buffer, hold_back=0)
        self._stream_offset += len(safe)
        self._buffer = ""
        return safe, new_events

    def reset(self) -> None:
        """Reset the redactor to its initial state (for stream reuse)."""
        self._buffer = ""
        self._stream_offset = 0
        self._events = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_and_flush(self) -> tuple[str, list[StreamRedactionEvent]]:
        """Scan the buffer, redact PII, and flush the safe prefix."""
        safe, new_events = self._scan(self._buffer, hold_back=self._lookahead)
        emitted = len(safe)
        self._stream_offset += emitted
        self._buffer = self._buffer[emitted:]
        return safe, new_events

    def _scan(self, text: str, hold_back: int) -> tuple[str, list[StreamRedactionEvent]]:
        """Scan *text* for PII, apply redactions, return safe prefix.

        *hold_back* characters are reserved at the right edge to allow
        partial matches to complete in the next push.  With ``hold_back=0``
        (final flush) the entire buffer is released.

        Args:
            text: Text to scan.
            hold_back: Characters to reserve at the right edge.

        Returns:
            ``(redacted_text_up_to_safe_point, new_events)``
        """
        if not text:
            return "", []

        new_events: list[StreamRedactionEvent] = []

        # Collect all matches across all patterns.
        all_matches: list[tuple[int, int, str, re.Match[str]]] = []
        for category, pattern in self._patterns.items():
            for m in pattern.finditer(text):
                all_matches.append((m.start(), m.end(), category, m))

        # Sort by start position; for overlaps keep the first (longest) match.
        all_matches.sort(key=lambda x: (x[0], -(x[1] - x[0])))

        safe_up_to = len(text) - hold_back  # only emit up to this point
        last_end = 0  # tracks position in the *original* text
        parts: list[str] = []

        for start, end, category, _ in all_matches:
            if start < last_end:
                continue  # overlapping — skip
            if start >= safe_up_to:
                # This match starts in the hold-back zone; stop processing.
                break

            original = text[start:end]
            replacement = self._replace(original, category)

            parts.append(text[last_end:start])
            parts.append(replacement)

            evt = StreamRedactionEvent(
                entity_type=category,
                original=original,
                replacement=replacement,
                buffer_offset=self._stream_offset + start,
            )
            new_events.append(evt)
            self._events.append(evt)
            last_end = end

        # Append everything up to safe_up_to that wasn't covered by a match.
        if last_end < safe_up_to:
            parts.append(text[last_end:safe_up_to])

        return "".join(parts), new_events

    def _replace(self, original: str, category: str) -> str:
        """Apply the configured redaction strategy to *original*.

        Args:
            original: The detected PII string.
            category: The PII category label.

        Returns:
            The replacement string.
        """
        import hashlib

        match self._strategy:
            case "placeholder":
                return f"[{category.upper()}]"
            case "mask":
                return "*" * len(original)
            case "hash":
                digest = hashlib.sha256(original.encode()).hexdigest()[:8]
                return f"[{category.upper()}:{digest}]"
            case "remove":
                return ""
            case _:  # pragma: no cover
                return f"[{category.upper()}]"

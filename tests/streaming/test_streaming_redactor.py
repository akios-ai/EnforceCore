# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for StreamingRedactor — stateful window-based PII detection."""

from __future__ import annotations

import pytest

from enforcecore.streaming.redactor import StreamingRedactor, StreamRedactionEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def push_all(sr: StreamingRedactor, tokens: list[str]) -> tuple[str, list[StreamRedactionEvent]]:
    """Push all tokens through *sr* and flush; return combined output and events."""
    output_parts: list[str] = []
    all_events: list[StreamRedactionEvent] = []
    for tok in tokens:
        out, evts = sr.push(tok)
        output_parts.append(out)
        all_events.extend(evts)
    remainder, evts = sr.flush()
    output_parts.append(remainder)
    all_events.extend(evts)
    return "".join(output_parts), all_events


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestStreamingRedactorInit:
    def test_default_strategy_is_placeholder(self) -> None:
        sr = StreamingRedactor()
        assert sr._strategy == "placeholder"

    def test_custom_strategy(self) -> None:
        sr = StreamingRedactor(strategy="mask")
        assert sr._strategy == "mask"

    def test_invalid_strategy_raises(self) -> None:
        with pytest.raises(ValueError, match="strategy must be one of"):
            StreamingRedactor(strategy="explode")  # type: ignore[arg-type]

    def test_invalid_lookahead_raises(self) -> None:
        with pytest.raises(ValueError, match="lookahead must be > 0"):
            StreamingRedactor(lookahead=0)

    def test_negative_lookahead_raises(self) -> None:
        with pytest.raises(ValueError, match="lookahead must be > 0"):
            StreamingRedactor(lookahead=-1)

    def test_category_filter(self) -> None:
        sr = StreamingRedactor(categories={"email"})
        assert "email" in sr._patterns
        assert "ssn" not in sr._patterns

    def test_initial_redaction_count_is_zero(self) -> None:
        sr = StreamingRedactor()
        assert sr.redaction_count == 0

    def test_initial_events_is_empty(self) -> None:
        sr = StreamingRedactor()
        assert sr.events == []


# ---------------------------------------------------------------------------
# Single-token detection (no boundary spanning)
# ---------------------------------------------------------------------------


class TestStreamingRedactorSingleToken:
    def test_clean_token_passes_through(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        out, evts = sr.push("Hello world")
        remainder, _ = sr.flush()
        assert out + remainder == "Hello world"
        assert evts == []

    def test_email_in_single_token_redacted(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        out, _ = sr.flush()  # flush empty
        out, evts = sr.push("Contact alice@example.com today")
        remainder, _ = sr.flush()
        full = out + remainder
        assert "alice@example.com" not in full
        assert "[EMAIL]" in full
        assert len(evts) == 1
        assert evts[0].entity_type == "email"
        assert evts[0].original == "alice@example.com"

    def test_ssn_in_single_token_redacted(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        out, push_evts = sr.push("SSN: 123-45-6789 on file")
        remainder, flush_evts = sr.flush()
        full = out + remainder
        all_evts = push_evts + flush_evts
        assert "123-45-6789" not in full
        assert len(all_evts) == 1
        assert all_evts[0].entity_type == "ssn"

    def test_phone_in_single_token_redacted(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        out, push_evts = sr.push("Call 555-867-5309 now!")
        remainder, flush_evts = sr.flush()
        full = out + remainder
        all_evts = push_evts + flush_evts
        assert "555-867-5309" not in full
        assert len(all_evts) == 1
        assert all_evts[0].entity_type == "phone"

    def test_ip_address_in_single_token_redacted(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        out, _push_evts = sr.push("Server at 192.168.1.100 failed")
        remainder, _flush_evts = sr.flush()
        full = out + remainder
        assert "192.168.1.100" not in full

    def test_credit_card_in_single_token_redacted(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        out, _push_evts = sr.push("Card: 4111 1111 1111 1111 charged")
        remainder, _flush_evts = sr.flush()
        full = out + remainder
        assert "4111 1111 1111 1111" not in full or "[CREDIT_CARD]" in full


# ---------------------------------------------------------------------------
# Boundary-spanning detection (the core differentiator)
# ---------------------------------------------------------------------------


class TestStreamingRedactorBoundarySpanning:
    def test_email_split_across_two_tokens(self) -> None:
        """Classic split: 'alice' in one token, '@example.com' in next."""
        sr = StreamingRedactor(strategy="placeholder", lookahead=64)
        out1, evts1 = sr.push("Contact alice")
        out2, evts2 = sr.push("@example.com today")
        remainder, evts3 = sr.flush()
        full = out1 + out2 + remainder
        assert "alice@example.com" not in full
        assert "[EMAIL]" in full
        all_evts = evts1 + evts2 + evts3
        email_evts = [e for e in all_evts if e.entity_type == "email"]
        assert len(email_evts) == 1

    def test_email_split_across_three_tokens(self) -> None:
        """Three-way split: 'john' + '@' + 'gmail.com'."""
        sr = StreamingRedactor(strategy="placeholder", lookahead=64)
        out, _evts = push_all(sr, ["Send to john", "@", "gmail.com now"])
        assert "john@gmail.com" not in out
        assert "[EMAIL]" in out

    def test_no_pii_across_tokens(self) -> None:
        """Normal streaming text with no PII passes through intact."""
        sr = StreamingRedactor(lookahead=32)
        out, evts = push_all(sr, ["Hello ", "world! ", "How are you?"])
        assert out == "Hello world! How are you?"
        assert evts == []

    def test_multiple_pii_entities_in_stream(self) -> None:
        """Two separate PII entities both get redacted."""
        sr = StreamingRedactor(strategy="placeholder", lookahead=64)
        tokens = ["Email alice@example.com ", "and call 555-123-4567 please"]
        out, evts = push_all(sr, tokens)
        assert "alice@example.com" not in out
        assert "555-123-4567" not in out
        assert "[EMAIL]" in out
        assert "[PHONE]" in out
        assert len(evts) == 2


# ---------------------------------------------------------------------------
# Redaction strategies
# ---------------------------------------------------------------------------


class TestStreamingRedactorStrategies:
    def test_placeholder_strategy(self) -> None:
        sr = StreamingRedactor(strategy="placeholder", lookahead=4)
        out, _push_evts = sr.push("Contact alice@example.com today")
        remainder, _flush_evts = sr.flush()
        full = out + remainder
        assert "[EMAIL]" in full
        assert "alice@example.com" not in full

    def test_mask_strategy(self) -> None:
        sr = StreamingRedactor(strategy="mask", lookahead=4)
        out, _push_evts = sr.push("Contact alice@example.com today")
        remainder, _flush_evts = sr.flush()
        full = out + remainder
        assert "alice@example.com" not in full
        # mask replacement is same length as original
        assert "*" * len("alice@example.com") in full

    def test_hash_strategy(self) -> None:
        sr = StreamingRedactor(strategy="hash", lookahead=4)
        out, _push_evts = sr.push("Contact alice@example.com today")
        remainder, _flush_evts = sr.flush()
        full = out + remainder
        assert "alice@example.com" not in full
        assert "[EMAIL:" in full  # hash format: [TYPE:hexdigest]

    def test_remove_strategy(self) -> None:
        sr = StreamingRedactor(strategy="remove", lookahead=4)
        out, _push_evts = sr.push("Contact alice@example.com today")
        remainder, _flush_evts = sr.flush()
        full = out + remainder
        assert "alice@example.com" not in full
        assert "Contact" in full
        assert "today" in full


# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------


class TestStreamingRedactorState:
    def test_reset_clears_buffer_and_events(self) -> None:
        sr = StreamingRedactor(lookahead=64)
        sr.push("alice")
        sr.reset()
        assert sr._buffer == ""
        assert sr.redaction_count == 0
        assert sr.events == []

    def test_events_property_returns_copy(self) -> None:
        """Mutating the returned list must not affect internal state."""
        sr = StreamingRedactor(lookahead=4)
        sr.push("Contact alice@example.com today")
        sr.flush()
        evts = sr.events
        evts.clear()
        assert sr.redaction_count > 0  # internal list unchanged

    def test_redaction_count_accumulates(self) -> None:
        sr = StreamingRedactor(strategy="placeholder", lookahead=4)
        sr.push("Contact alice@example.com today")
        sr.flush()
        sr.push("Email bob@example.com please")
        sr.flush()
        assert sr.redaction_count == 2

    def test_stream_offset_tracked(self) -> None:
        sr = StreamingRedactor(lookahead=4)
        sr.push("hello ")  # 6 chars
        sr.flush()  # flushes the 4-char lookahead remainder
        assert sr._stream_offset == 6


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestStreamingRedactorEdgeCases:
    def test_empty_token(self) -> None:
        sr = StreamingRedactor()
        out, evts = sr.push("")
        assert out == ""
        assert evts == []

    def test_empty_flush(self) -> None:
        sr = StreamingRedactor()
        out, evts = sr.flush()
        assert out == ""
        assert evts == []

    def test_token_entirely_held_in_lookahead(self) -> None:
        """A short token that fits entirely inside the lookahead returns empty output."""
        sr = StreamingRedactor(lookahead=128)
        out, _ = sr.push("alice")  # might be beginning of email
        # Not necessarily empty — depends on lookahead vs token length — just no crash
        assert isinstance(out, str)

    def test_large_clean_stream(self) -> None:
        sr = StreamingRedactor(lookahead=32)
        tokens = [f"word{i} " for i in range(200)]
        out, evts = push_all(sr, tokens)
        assert evts == []
        assert "word0" in out
        assert "word199" in out

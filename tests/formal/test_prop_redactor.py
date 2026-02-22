# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the Redactor — Hypothesis.

These tests verify that the redactor correctly identifies and removes
PII from arbitrary text inputs.
"""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from enforcecore.core.types import RedactionStrategy
from enforcecore.redactor.engine import Redactor

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Safe text that should NOT contain PII patterns
_safe_chars = string.ascii_letters + string.digits + " \t\n"
_safe_text = st.text(alphabet=_safe_chars, min_size=0, max_size=500)

# Email addresses
_emails = st.from_regex(r"[a-z]{3,10}@[a-z]{3,10}\.[a-z]{2,4}", fullmatch=True)

# US phone numbers (10-digit with optional formatting)
_phones = st.from_regex(r"\d{3}-\d{3}-\d{4}", fullmatch=True)

# US SSN
_ssns = st.from_regex(r"\d{3}-\d{2}-\d{4}", fullmatch=True)

# IPv4
_ipv4 = st.from_regex(
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)){3}",
    fullmatch=True,
)


# ---------------------------------------------------------------------------
# R1: Idempotency — redacting twice gives the same result
# ---------------------------------------------------------------------------


class TestRedactorIdempotency:
    """R1: redact(redact(text)) ≡ redact(text)."""

    @given(text=_safe_text)
    @settings(max_examples=200)
    def test_double_redact_idempotent(self, text: str) -> None:
        """Redacting already-redacted text must not change it further."""
        r = Redactor()
        first = r.redact(text)
        second = r.redact(first.text)
        assert first.text == second.text

    @given(email=_emails, padding=_safe_text)
    @settings(max_examples=100)
    def test_double_redact_with_pii(self, email: str, padding: str) -> None:
        """Redacting text with PII twice yields the same final output."""
        text = f"{padding} {email} {padding}"
        r = Redactor()
        first = r.redact(text)
        second = r.redact(first.text)
        assert first.text == second.text


# ---------------------------------------------------------------------------
# R2: Completeness — known PII is always removed
# ---------------------------------------------------------------------------


class TestRedactorCompleteness:
    """R2: ∀ text with known PII → PII not in redacted output."""

    @given(email=_emails, padding=_safe_text)
    @settings(max_examples=200)
    def test_email_removed(self, email: str, padding: str) -> None:
        """Emails must not appear in redacted output."""
        text = f"{padding} {email} {padding}"
        r = Redactor(categories=["email"])
        result = r.redact(text)
        assert email not in result.text

    @given(phone=_phones, padding=_safe_text)
    @settings(max_examples=200)
    def test_phone_removed(self, phone: str, padding: str) -> None:
        """Phone numbers must not appear in redacted output."""
        text = f"Call me at {phone} please"
        r = Redactor(categories=["phone"])
        result = r.redact(text)
        assert phone not in result.text


# ---------------------------------------------------------------------------
# R3: Safety — clean text is unchanged
# ---------------------------------------------------------------------------


class TestRedactorSafety:
    """R3: ∀ text without PII patterns → redact(text) = text."""

    @given(text=_safe_text)
    @settings(max_examples=200)
    def test_clean_text_unchanged(self, text: str) -> None:
        """Text without PII must pass through unmodified."""
        r = Redactor()
        result = r.redact(text)
        assert result.text == text
        assert result.count == 0

    @given(text=_safe_text)
    @settings(max_examples=100)
    def test_clean_text_no_entities(self, text: str) -> None:
        """Clean text must produce zero detected entities."""
        r = Redactor()
        entities = r.detect(text)
        assert len(entities) == 0


# ---------------------------------------------------------------------------
# R4: Detection consistency — detect() ↔ redact() agree
# ---------------------------------------------------------------------------


class TestDetectRedactConsistency:
    """R4: detect() entity count == redact() entity count."""

    @given(email=_emails, padding=_safe_text)
    @settings(max_examples=100)
    def test_detect_count_matches_redact(self, email: str, padding: str) -> None:
        """Number of detected entities must equal redaction count."""
        text = f"{padding} {email} {padding}"
        r = Redactor(categories=["email"])
        detected = r.detect(text)
        redacted = r.redact(text)
        assert len(detected) == redacted.count


# ---------------------------------------------------------------------------
# R5: Strategy independence — all strategies remove the same PII
# ---------------------------------------------------------------------------


class TestStrategyIndependence:
    """R5: ∀ strategy, detect(text) returns the same entities."""

    @given(email=_emails, padding=_safe_text)
    @settings(max_examples=100)
    def test_strategy_same_detection(self, email: str, padding: str) -> None:
        """Different strategies must detect the same entities."""
        text = f"{padding} {email} {padding}"
        strategies = [
            RedactionStrategy.PLACEHOLDER,
            RedactionStrategy.MASK,
            RedactionStrategy.HASH,
            RedactionStrategy.REMOVE,
        ]
        counts = []
        for strat in strategies:
            r = Redactor(strategy=strat, categories=["email"])
            result = r.redact(text)
            counts.append(result.count)
            # PII must never appear regardless of strategy
            assert email not in result.text

        assert len(set(counts)) == 1, f"Counts differ across strategies: {counts}"

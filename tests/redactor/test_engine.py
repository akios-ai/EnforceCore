# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for the PII redaction engine."""

from __future__ import annotations

import pytest

from enforcecore.core.types import RedactionError, RedactionStrategy
from enforcecore.redactor.engine import DetectedEntity, Redactor

# =========================================================================
# Detection tests — each PII category
# =========================================================================


class TestDetectEmail:
    """Email detection."""

    def test_simple_email(self) -> None:
        r = Redactor(categories=["email"])
        entities = r.detect("contact john@example.com please")
        assert len(entities) == 1
        assert entities[0].category == "email"
        assert entities[0].text == "john@example.com"

    def test_complex_email(self) -> None:
        r = Redactor(categories=["email"])
        entities = r.detect("send to user.name+tag@sub.domain.co.uk now")
        assert len(entities) == 1
        assert entities[0].text == "user.name+tag@sub.domain.co.uk"

    def test_multiple_emails(self) -> None:
        r = Redactor(categories=["email"])
        text = "from a@b.com to c@d.org and e@f.io"
        entities = r.detect(text)
        assert len(entities) == 3
        emails = {e.text for e in entities}
        assert emails == {"a@b.com", "c@d.org", "e@f.io"}

    def test_no_email(self) -> None:
        r = Redactor(categories=["email"])
        entities = r.detect("no email here")
        assert len(entities) == 0


class TestDetectPhone:
    """Phone number detection."""

    def test_us_phone_dashes(self) -> None:
        r = Redactor(categories=["phone"])
        entities = r.detect("call 555-123-4567")
        assert len(entities) == 1
        assert entities[0].category == "phone"

    def test_us_phone_parens(self) -> None:
        r = Redactor(categories=["phone"])
        entities = r.detect("call (555) 123-4567 now")
        assert len(entities) == 1
        assert entities[0].category == "phone"

    def test_us_phone_dots(self) -> None:
        r = Redactor(categories=["phone"])
        entities = r.detect("phone: 555.123.4567")
        assert len(entities) == 1

    def test_phone_with_country_code(self) -> None:
        r = Redactor(categories=["phone"])
        entities = r.detect("call +1-555-123-4567 now")
        assert len(entities) == 1

    def test_no_phone(self) -> None:
        r = Redactor(categories=["phone"])
        entities = r.detect("just a regular sentence")
        assert len(entities) == 0


class TestDetectSSN:
    """SSN detection."""

    def test_ssn_dashes(self) -> None:
        r = Redactor(categories=["ssn"])
        entities = r.detect("SSN: 123-45-6789")
        assert len(entities) == 1
        assert entities[0].category == "ssn"
        assert entities[0].text == "123-45-6789"

    def test_ssn_no_dashes(self) -> None:
        r = Redactor(categories=["ssn"])
        entities = r.detect("SSN 123456789")
        assert len(entities) == 1

    def test_ssn_invalid_prefix_000(self) -> None:
        """SSN starting with 000 should not match (IRS rule)."""
        r = Redactor(categories=["ssn"])
        entities = r.detect("SSN: 000-12-3456")
        assert len(entities) == 0

    def test_ssn_invalid_prefix_666(self) -> None:
        """SSN starting with 666 should not match."""
        r = Redactor(categories=["ssn"])
        entities = r.detect("SSN: 666-12-3456")
        assert len(entities) == 0


class TestDetectCreditCard:
    """Credit card detection."""

    def test_visa(self) -> None:
        r = Redactor(categories=["credit_card"])
        entities = r.detect("card: 4111-1111-1111-1111")
        assert len(entities) == 1
        assert entities[0].category == "credit_card"

    def test_mastercard(self) -> None:
        r = Redactor(categories=["credit_card"])
        entities = r.detect("MC: 5500 0000 0000 0004")
        assert len(entities) == 1

    def test_amex(self) -> None:
        r = Redactor(categories=["credit_card"])
        entities = r.detect("Amex: 3782-8224-6310-005")
        assert len(entities) == 1

    def test_no_card(self) -> None:
        r = Redactor(categories=["credit_card"])
        entities = r.detect("not a card number")
        assert len(entities) == 0


class TestDetectIPAddress:
    """IP address detection."""

    def test_simple_ip(self) -> None:
        r = Redactor(categories=["ip_address"])
        entities = r.detect("server at 192.168.1.100")
        assert len(entities) == 1
        assert entities[0].category == "ip_address"
        assert entities[0].text == "192.168.1.100"

    def test_localhost(self) -> None:
        r = Redactor(categories=["ip_address"])
        entities = r.detect("connect to 127.0.0.1")
        assert len(entities) == 1
        assert entities[0].text == "127.0.0.1"

    def test_invalid_ip_out_of_range(self) -> None:
        """256+ in any octet is not valid."""
        r = Redactor(categories=["ip_address"])
        entities = r.detect("bad IP: 999.999.999.999")
        assert len(entities) == 0

    def test_multiple_ips(self) -> None:
        r = Redactor(categories=["ip_address"])
        entities = r.detect("from 10.0.0.1 to 10.0.0.2")
        assert len(entities) == 2


# =========================================================================
# Redaction strategy tests
# =========================================================================


class TestRedactionStrategies:
    """All four redaction strategies."""

    TEXT = "email: john@example.com"

    def test_placeholder(self) -> None:
        r = Redactor(categories=["email"], strategy=RedactionStrategy.PLACEHOLDER)
        result = r.redact(self.TEXT)
        assert result.text == "email: <EMAIL>"
        assert result.was_redacted is True
        assert result.count == 1

    def test_mask(self) -> None:
        r = Redactor(categories=["email"], strategy=RedactionStrategy.MASK)
        result = r.redact(self.TEXT)
        assert result.text == "email: ****@****.***"

    def test_hash(self) -> None:
        r = Redactor(categories=["email"], strategy=RedactionStrategy.HASH)
        result = r.redact(self.TEXT)
        assert result.text.startswith("email: [SHA256:")
        assert result.text.endswith("]")
        # Hash should be deterministic
        result2 = r.redact(self.TEXT)
        assert result.text == result2.text

    def test_remove(self) -> None:
        r = Redactor(categories=["email"], strategy=RedactionStrategy.REMOVE)
        result = r.redact(self.TEXT)
        assert result.text == "email: "

    def test_phone_mask(self) -> None:
        r = Redactor(categories=["phone"], strategy=RedactionStrategy.MASK)
        result = r.redact("call 555-123-4567")
        assert result.text == "call ***-***-****"

    def test_ssn_placeholder(self) -> None:
        r = Redactor(categories=["ssn"], strategy=RedactionStrategy.PLACEHOLDER)
        result = r.redact("SSN: 123-45-6789")
        assert result.text == "SSN: <SSN>"

    def test_credit_card_mask(self) -> None:
        r = Redactor(categories=["credit_card"], strategy=RedactionStrategy.MASK)
        result = r.redact("card: 4111-1111-1111-1111")
        assert result.text == "card: ****-****-****-****"

    def test_ip_placeholder(self) -> None:
        r = Redactor(categories=["ip_address"], strategy=RedactionStrategy.PLACEHOLDER)
        result = r.redact("server at 192.168.1.1")
        assert result.text == "server at <IP_ADDRESS>"


# =========================================================================
# RedactionResult tests
# =========================================================================


class TestRedactionResult:
    """Result data structure."""

    def test_no_redaction(self) -> None:
        r = Redactor(categories=["email"])
        result = r.redact("no pii here")
        assert result.was_redacted is False
        assert result.count == 0
        assert result.text == "no pii here"
        assert result.original_text == "no pii here"
        assert result.entities == []
        assert result.events == []

    def test_entities_list(self) -> None:
        r = Redactor(categories=["email"])
        result = r.redact("a@b.com and c@d.com")
        assert result.count == 2
        assert all(isinstance(e, DetectedEntity) for e in result.entities)
        # Entities should be in left-to-right order
        assert result.entities[0].start < result.entities[1].start

    def test_events_list(self) -> None:
        r = Redactor(categories=["email"])
        result = r.redact("john@example.com")
        assert len(result.events) == 1
        evt = result.events[0]
        assert evt.entity_type == "email"
        assert evt.strategy == RedactionStrategy.PLACEHOLDER
        assert evt.replacement == "<EMAIL>"

    def test_original_text_preserved(self) -> None:
        r = Redactor(categories=["email"])
        original = "user: john@example.com"
        result = r.redact(original)
        assert result.original_text == original
        assert result.text != original


# =========================================================================
# Edge cases
# =========================================================================


class TestEdgeCases:
    """Edge cases and error handling."""

    def test_empty_string(self) -> None:
        r = Redactor()
        result = r.redact("")
        assert result.text == ""
        assert result.count == 0

    def test_no_pii(self) -> None:
        r = Redactor()
        result = r.redact("The quick brown fox jumps over the lazy dog.")
        assert result.was_redacted is False

    def test_mixed_pii(self) -> None:
        """Multiple PII categories in one string."""
        r = Redactor(categories=["email", "phone"])
        result = r.redact("Contact john@example.com or 555-123-4567")
        assert result.count == 2
        cats = {e.category for e in result.entities}
        assert cats == {"email", "phone"}

    def test_unknown_category_raises(self) -> None:
        with pytest.raises(RedactionError, match="Unknown PII category"):
            Redactor(categories=["fingerprint"])

    def test_default_categories(self) -> None:
        r = Redactor()
        assert set(r.categories) == {"email", "phone", "ssn", "credit_card", "ip_address"}

    def test_default_strategy(self) -> None:
        r = Redactor()
        assert r.strategy == RedactionStrategy.PLACEHOLDER

    def test_person_name_skipped(self) -> None:
        """person_name is accepted as category but skipped in detection."""
        r = Redactor(categories=["person_name"])
        entities = r.detect("John Smith is here")
        # person_name is accepted but detection is skipped (too noisy with regex)
        assert len(entities) == 0

    def test_multiple_same_category(self) -> None:
        """Multiple entities of the same category."""
        r = Redactor(categories=["email"])
        text = "from a@b.com and c@d.com to e@f.com"
        result = r.redact(text)
        assert result.count == 3
        assert "<EMAIL>" in result.text
        assert "@" not in result.text

    def test_pii_at_start(self) -> None:
        r = Redactor(categories=["email"])
        result = r.redact("john@example.com said hi")
        assert result.text == "<EMAIL> said hi"

    def test_pii_at_end(self) -> None:
        r = Redactor(categories=["email"])
        result = r.redact("email is john@example.com")
        assert result.text == "email is <EMAIL>"

    def test_only_pii(self) -> None:
        r = Redactor(categories=["email"])
        result = r.redact("john@example.com")
        assert result.text == "<EMAIL>"


class TestOverlapRemoval:
    """Overlapping entity resolution."""

    def test_ssn_not_confused_with_phone(self) -> None:
        """SSN should not also be detected as phone."""
        r = Redactor(categories=["ssn", "phone"])
        # This is clearly an SSN, not a phone
        result = r.redact("SSN: 123-45-6789")
        # Should have exactly 1 match after overlap removal
        assert result.count == 1


class TestDetectedEntityDataclass:
    """DetectedEntity frozen dataclass properties."""

    def test_frozen(self) -> None:
        e = DetectedEntity(category="email", start=0, end=5, text="a@b.c")
        with pytest.raises(AttributeError):
            e.category = "phone"  # type: ignore[misc]

    def test_fields(self) -> None:
        e = DetectedEntity(category="ssn", start=10, end=21, text="123-45-6789")
        assert e.category == "ssn"
        assert e.start == 10
        assert e.end == 21
        assert e.text == "123-45-6789"


# =========================================================================
# Properties / immutability
# =========================================================================


class TestRedactorProperties:
    """Redactor property accessors."""

    def test_categories_returns_copy(self) -> None:
        r = Redactor(categories=["email"])
        cats = r.categories
        cats.append("phone")
        assert r.categories == ["email"]  # Original not mutated

    def test_strategy_property(self) -> None:
        r = Redactor(strategy=RedactionStrategy.HASH)
        assert r.strategy == RedactionStrategy.HASH

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.redactor.unicode — unicode hardening for PII detection."""

from __future__ import annotations

from enforcecore.redactor.unicode import (
    decode_encoded_pii,
    normalize_homoglyphs,
    normalize_unicode,
    prepare_for_detection,
)

# ---------------------------------------------------------------------------
# normalize_unicode
# ---------------------------------------------------------------------------


class TestNormalizeUnicode:
    """Tests for NFC normalization and zero-width char stripping."""

    def test_plain_ascii_unchanged(self) -> None:
        assert normalize_unicode("hello world") == "hello world"

    def test_strips_zero_width_space(self) -> None:
        assert normalize_unicode("jo\u200bhn") == "john"

    def test_strips_zero_width_joiner(self) -> None:
        assert normalize_unicode("jo\u200dhn") == "john"

    def test_strips_zero_width_non_joiner(self) -> None:
        assert normalize_unicode("jo\u200chn") == "john"

    def test_strips_bom(self) -> None:
        assert normalize_unicode("\ufeffjohn") == "john"

    def test_strips_soft_hyphen(self) -> None:
        assert normalize_unicode("jo\u00adhn") == "john"

    def test_strips_ltr_mark(self) -> None:
        assert normalize_unicode("jo\u200ehn") == "john"

    def test_strips_rtl_mark(self) -> None:
        assert normalize_unicode("jo\u200fhn") == "john"

    def test_strips_multiple_zero_width(self) -> None:
        """Multiple zero-width chars should all be removed."""
        text = "\u200bj\u200co\u200dh\u200en\u200f"
        assert normalize_unicode(text) == "john"

    def test_nfc_normalization(self) -> None:
        """NFD e-acute (e + combining accent) should normalize to NFC."""
        nfd = "caf\u0065\u0301"  # e + combining acute accent
        result = normalize_unicode(nfd)
        assert "\u0301" not in result  # Combining accent should be composed
        assert "caf" in result

    def test_email_with_zero_width(self) -> None:
        """Evasion: zero-width chars injected into email address."""
        text = "john\u200b@\u200bexample\u200b.\u200bcom"
        assert normalize_unicode(text) == "john@example.com"

    def test_empty_string(self) -> None:
        assert normalize_unicode("") == ""

    def test_directional_formatting_stripped(self) -> None:
        """LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI should all be stripped."""
        chars = [
            "\u202a",
            "\u202b",
            "\u202c",
            "\u202d",
            "\u202e",
            "\u2066",
            "\u2067",
            "\u2068",
            "\u2069",
        ]
        text = "".join(chars) + "john"
        assert normalize_unicode(text) == "john"


# ---------------------------------------------------------------------------
# normalize_homoglyphs
# ---------------------------------------------------------------------------


class TestNormalizeHomoglyphs:
    """Tests for confusable character normalization."""

    def test_plain_ascii_unchanged(self) -> None:
        assert normalize_homoglyphs("hello") == "hello"

    def test_cyrillic_lowercase_o(self) -> None:
        """Cyrillic 'o' (U+043E) should map to Latin 'o'."""
        assert normalize_homoglyphs("j\u043ehn") == "john"

    def test_cyrillic_lowercase_a(self) -> None:
        """Cyrillic 'a' (U+0430) should map to Latin 'a'."""
        assert normalize_homoglyphs("\u0430bc") == "abc"

    def test_cyrillic_lowercase_c(self) -> None:
        """Cyrillic 'c' (U+0441) should map to Latin 'c'."""
        assert normalize_homoglyphs("\u0441at") == "cat"

    def test_cyrillic_uppercase_o(self) -> None:
        assert normalize_homoglyphs("\u041ek") == "Ok"

    def test_greek_alpha(self) -> None:
        assert normalize_homoglyphs("\u03b1bc") == "abc"

    def test_greek_omicron(self) -> None:
        assert normalize_homoglyphs("\u03bfk") == "ok"

    def test_fullwidth_digits(self) -> None:
        """Fullwidth digits should map to ASCII."""
        assert normalize_homoglyphs("\uff11\uff12\uff13") == "123"

    def test_fullwidth_at_sign(self) -> None:
        assert normalize_homoglyphs("user\uff20example.com") == "user@example.com"

    def test_fullwidth_dot(self) -> None:
        assert normalize_homoglyphs("example\uff0ecom") == "example.com"

    def test_email_with_cyrillic_evasion(self) -> None:
        """Full evasion scenario: email with Cyrillic chars."""
        # j + Cyrillic-o + hn@example.com
        text = "j\u043ehn\uff20example\uff0ecom"
        result = normalize_homoglyphs(text)
        assert result == "john@example.com"

    def test_phone_with_fullwidth_digits(self) -> None:
        """Phone number with fullwidth digits."""
        text = "\uff15\uff15\uff15-\uff11\uff12\uff13-\uff14\uff15\uff16\uff17"
        result = normalize_homoglyphs(text)
        assert result == "555-123-4567"

    def test_fast_path_no_confusables(self) -> None:
        """Pure ASCII input should take the fast path and return unchanged."""
        text = "hello world 123 test@test.com"
        assert normalize_homoglyphs(text) is text  # Same object (fast path)

    def test_empty_string(self) -> None:
        assert normalize_homoglyphs("") == ""


# ---------------------------------------------------------------------------
# decode_encoded_pii
# ---------------------------------------------------------------------------


class TestDecodeEncodedPII:
    """Tests for URL and HTML entity decoding."""

    def test_plain_text_unchanged(self) -> None:
        assert decode_encoded_pii("hello world") == "hello world"

    def test_url_encoded_at(self) -> None:
        assert decode_encoded_pii("john%40example.com") == "john@example.com"

    def test_url_encoded_dot(self) -> None:
        assert decode_encoded_pii("example%2Ecom") == "example.com"

    def test_url_encoded_full_email(self) -> None:
        result = decode_encoded_pii("john%40example%2Ecom")
        assert result == "john@example.com"

    def test_html_entity_numeric(self) -> None:
        assert decode_encoded_pii("john&#64;example.com") == "john@example.com"

    def test_html_entity_named(self) -> None:
        assert decode_encoded_pii("5 &gt; 3") == "5 > 3"

    def test_html_entity_hex(self) -> None:
        assert decode_encoded_pii("john&#x40;example.com") == "john@example.com"

    def test_mixed_encoding(self) -> None:
        """Text with both URL-encoding and HTML entities."""
        result = decode_encoded_pii("john%40example&#46;com")
        assert result == "john@example.com"

    def test_no_false_positives(self) -> None:
        """Normal text with % and & should not be mangled."""
        text = "50% off & free shipping"
        result = decode_encoded_pii(text)
        assert "50% off" in result  # The % here isn't followed by hex digits

    def test_empty_string(self) -> None:
        assert decode_encoded_pii("") == ""


# ---------------------------------------------------------------------------
# prepare_for_detection (combined pipeline)
# ---------------------------------------------------------------------------


class TestPrepareForDetection:
    """Tests for the full normalization pipeline."""

    def test_plain_text(self) -> None:
        assert prepare_for_detection("hello") == "hello"

    def test_combined_evasion_email(self) -> None:
        """Email with zero-width + Cyrillic + URL-encoding combined."""
        # j + zero-width + Cyrillic-o + hn + fullwidth-@ + URL-encoded domain
        text = "j\u200b\u043ehn\uff20example%2Ecom"
        result = prepare_for_detection(text)
        assert result == "john@example.com"

    def test_combined_evasion_ssn(self) -> None:
        """SSN with fullwidth digits."""
        text = "\uff11\uff12\uff13-\uff14\uff15-\uff16\uff17\uff18\uff19"
        result = prepare_for_detection(text)
        assert result == "123-45-6789"

    def test_zero_width_in_ssn(self) -> None:
        """SSN with zero-width chars injected between digits."""
        text = "1\u200b2\u200b3-4\u200c5-6\u200d7\u200e8\u200f9"
        result = prepare_for_detection(text)
        assert result == "123-45-6789"

    def test_order_matters(self) -> None:
        """Verify that normalization order is correct:
        1. Unicode normalization (zero-width strip)
        2. Homoglyph normalization
        3. Encoded PII decoding
        """
        # This only works if all 3 steps run in order
        text = "\u200bj\u043ehn%40example.com"
        result = prepare_for_detection(text)
        assert result == "john@example.com"

    def test_empty_string(self) -> None:
        assert prepare_for_detection("") == ""

    def test_idempotent(self) -> None:
        """Running prepare_for_detection twice should give same result."""
        text = "j\u043ehn@example.com"
        result1 = prepare_for_detection(text)
        result2 = prepare_for_detection(result1)
        assert result1 == result2


# ---------------------------------------------------------------------------
# M-5: Offset-mapped normalization (v1.0.24a1)
# ---------------------------------------------------------------------------


class TestNormalizationResult:
    """Tests for prepare_for_detection_mapped and NormalizationResult."""

    def test_no_change_identity_map(self) -> None:
        """Plain ASCII text should have identity offset map."""
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        result = prepare_for_detection_mapped("hello world")
        assert result.text == "hello world"
        assert result.length_changed is False
        assert result.offset_map == list(range(11))

    def test_zero_width_stripped_with_offsets(self) -> None:
        """Zero-width chars should be stripped with correct offset mapping."""
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        text = "j\u200bohn@example.com"
        result = prepare_for_detection_mapped(text)
        assert result.text == "john@example.com"
        assert result.length_changed is True
        # 'j' at idx 0 maps to original 0
        # 'o' at idx 1 maps to original 2 (zero-width at 1 was stripped)
        assert result.offset_map[0] == 0
        assert result.offset_map[1] == 2

    def test_url_decode_with_offsets(self) -> None:
        """URL-decoded %40 → @ should have correct offset mapping."""
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        text = "john%40example.com"
        result = prepare_for_detection_mapped(text)
        assert result.text == "john@example.com"
        assert result.length_changed is True

    def test_map_span_roundtrip(self) -> None:
        """map_span should correctly map normalized positions to original."""
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        text = "j\u200bohn@example.com"
        result = prepare_for_detection_mapped(text)
        # The email "john@example.com" starts at 0 in normalized text
        orig_start, orig_end = result.map_span(0, 16)
        assert orig_start == 0
        # Original text has the zero-width char, so end should be 17
        assert orig_end == 17

    def test_homoglyph_preserves_length(self) -> None:
        """Homoglyph replacement is 1:1 so length shouldn't change."""
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        text = "j\u043ehn@example.com"  # Cyrillic o
        result = prepare_for_detection_mapped(text)
        assert result.text == "john@example.com"
        assert result.length_changed is False

    def test_mixed_normalization_with_offsets(self) -> None:
        """Combined zero-width + homoglyph + URL-encode should all work."""
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        text = "\u200bj\u043ehn%40example.com"
        result = prepare_for_detection_mapped(text)
        assert result.text == "john@example.com"
        assert result.length_changed is True

    def test_empty_string(self) -> None:
        from enforcecore.redactor.unicode import prepare_for_detection_mapped

        result = prepare_for_detection_mapped("")
        assert result.text == ""
        assert result.offset_map == []
        assert result.length_changed is False


class TestM5RedactorIntegration:
    """M-5 fix: Redactor should detect PII through unicode evasion."""

    def test_zero_width_email_detected(self) -> None:
        """Email with zero-width chars should still be detected and redacted."""
        from enforcecore.redactor.engine import Redactor

        r = Redactor()
        result = r.redact("Contact j\u200bohn@example.com please")
        assert "john" not in result.text
        assert result.count >= 1

    def test_url_encoded_email_detected(self) -> None:
        """Email with %40 should still be detected."""
        from enforcecore.redactor.engine import Redactor

        r = Redactor()
        result = r.redact("Email john%40example.com")
        assert result.count >= 1

    def test_homoglyph_email_detected(self) -> None:
        """Email with Cyrillic 'o' should still be detected."""
        from enforcecore.redactor.engine import Redactor

        r = Redactor()
        result = r.redact("Email j\u043ehn@example.com")
        assert result.count >= 1

    def test_mixed_evasion_email_detected(self) -> None:
        """Email with zero-width + URL-encode + homoglyph."""
        from enforcecore.redactor.engine import Redactor

        r = Redactor()
        text = "\u200bj\u043ehn%40example.com"
        result = r.redact(text)
        assert result.count >= 1

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Extra coverage for redactor/unicode.py — edge cases for offset mapping."""

from __future__ import annotations

import unicodedata

from enforcecore.redactor.unicode import (
    NormalizationResult,
    prepare_for_detection_mapped,
)

# ---------------------------------------------------------------------------
# NormalizationResult.map_span — end <= 0 branch (lines 170, 174)
# ---------------------------------------------------------------------------


class TestMapSpanEdgeCases:
    """NormalizationResult.map_span with unusual end values."""

    def test_map_span_end_zero_returns_orig_start_twice(self) -> None:
        """end=0 triggers the early-return path at line 170/174."""
        result = NormalizationResult(
            text="abc",
            offset_map=[0, 1, 2],
            length_changed=True,
        )
        orig_start, orig_end = result.map_span(1, 0)
        # When end <= 0, both values should equal orig_start
        assert orig_start == orig_end

    def test_map_span_end_negative_returns_orig_start_twice(self) -> None:
        """end=-1 also triggers the end <= 0 branch."""
        result = NormalizationResult(
            text="xy",
            offset_map=[0, 5],
            length_changed=True,
        )
        orig_start, orig_end = result.map_span(0, -1)
        assert orig_start == orig_end

    def test_map_span_normal_unchanged_passthrough(self) -> None:
        """If length_changed=False, map_span returns inputs unchanged."""
        result = NormalizationResult(
            text="hello",
            offset_map=[0, 1, 2, 3, 4],
            length_changed=False,
        )
        assert result.map_span(1, 3) == (1, 3)


# ---------------------------------------------------------------------------
# prepare_for_detection_mapped — NFC length change (lines 310-317)
# ---------------------------------------------------------------------------


class TestPrepareForDetectionMappedNFC:
    """NFC normalization that changes string length rebuilds offset map."""

    def test_nfc_combining_accent_collapses(self) -> None:
        """e + combining acute (2 codepoints) → é (1 codepoint)."""
        # "e\u0301" is NFD: e followed by combining acute accent.
        # NFC collapses this to a single codepoint é (U+00E9).
        text = "caf\u0065\u0301"  # 5 codepoints in NFD, 4 in NFC
        result = prepare_for_detection_mapped(text)
        nfc = unicodedata.normalize("NFC", text)
        assert result.text == nfc
        # The offset_map should be rebuilt (length changed path executed)
        if result.length_changed:
            assert len(result.offset_map) == len(result.text)

    def test_nfc_devanagari_composition(self) -> None:
        """Devanagari combining sequences collapse under NFC."""
        # क + virama (U+094D) + ष stays same; but some sequences do collapse.
        # Use a simple case: Latin small e + combining grave accent
        text = "e\u0300"  # NFD: e + combining grave → NFC: è (U+00E8)
        result = prepare_for_detection_mapped(text)
        nfc = unicodedata.normalize("NFC", text)
        assert result.text == nfc


# ---------------------------------------------------------------------------
# prepare_for_detection_mapped — HTML entity length change (lines 367-379)
# ---------------------------------------------------------------------------


class TestPrepareForDetectionMappedHTML:
    """HTML entity decoding that changes string length rebuilds offset map."""

    def test_amp_entity_decoded(self) -> None:
        """&amp; (5 chars) → & (1 char): length changes → offset rebuilt."""
        text = "AT&amp;T"
        result = prepare_for_detection_mapped(text)
        assert "&amp;" not in result.text
        assert "&" in result.text

    def test_lt_gt_entities_decoded(self) -> None:
        """&lt; and &gt; decode to < and > (length changes)."""
        text = "&lt;html&gt;"
        result = prepare_for_detection_mapped(text)
        assert "<html>" in result.text

    def test_multiple_entities(self) -> None:
        """Multiple HTML entities, all decoded with offset map rebuilt."""
        text = "a &amp; b &lt; c &gt; d"
        result = prepare_for_detection_mapped(text)
        assert "&amp;" not in result.text
        assert "&lt;" not in result.text
        assert "&gt;" not in result.text
        # offset_map length should match text length
        assert len(result.offset_map) == len(result.text)

    def test_numeric_entity_decoded(self) -> None:
        """&#64; (@ sign as decimal entity) is decoded to @."""
        text = "john&#64;example.com"
        result = prepare_for_detection_mapped(text)
        assert "@" in result.text

    def test_no_html_entities_fast_path(self) -> None:
        """Text without & is not processed for HTML entities."""
        text = "john@example.com"
        result = prepare_for_detection_mapped(text)
        assert result.text == "john@example.com"

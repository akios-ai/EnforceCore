# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Unicode hardening for PII detection.

Provides pre-processing steps to defeat unicode-based PII evasion:

1. **Normalization** -- NFC normalization + zero-width character stripping.
2. **Homoglyph detection** -- Normalizes confusable characters (e.g., Cyrillic
   ``o`` to Latin ``o``) before PII regex matching.
3. **Encoded PII decoding** -- Decodes URL-encoded and HTML-entity-encoded
   content before scanning.

These functions are applied *before* the regex-based PII detection in
:class:`~enforcecore.redactor.engine.Redactor`, hardening it against
adversarial evasion techniques.

.. versionadded:: 1.0.6
.. versionchanged:: 1.0.24
   Added :class:`NormalizationResult` with offset mapping so that entity
   positions on normalized text can be mapped back to the original text.
   The engine no longer falls back to un-normalized text when normalization
   changes string length (M-5 fix).
"""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# ---------------------------------------------------------------------------
# Zero-width and invisible characters
# ---------------------------------------------------------------------------

# Unicode categories that are invisible / zero-width
_ZERO_WIDTH_CHARS = frozenset(
    {
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\u2060",  # Word joiner
        "\ufeff",  # BOM / zero-width no-break space
        "\u00ad",  # Soft hyphen
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u202d",  # Left-to-right override
        "\u202e",  # Right-to-left override
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    }
)

_ZERO_WIDTH_RE = re.compile("[" + re.escape("".join(_ZERO_WIDTH_CHARS)) + "]")

# ---------------------------------------------------------------------------
# Homoglyph map -- confusable characters to ASCII equivalents
# ---------------------------------------------------------------------------

# Covers the most common Cyrillic/Greek/etc. look-alikes used in evasion.
# This is NOT exhaustive.  We focus on characters that appear in email
# addresses, phone numbers, and other PII patterns.
_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic to Latin
    "\u0410": "A",  # Cyrillic A
    "\u0412": "B",  # Cyrillic Ve
    "\u0421": "C",  # Cyrillic Es
    "\u0415": "E",  # Cyrillic Ie
    "\u041d": "H",  # Cyrillic En
    "\u041a": "K",  # Cyrillic Ka
    "\u041c": "M",  # Cyrillic Em
    "\u041e": "O",  # Cyrillic O
    "\u0420": "P",  # Cyrillic Er
    "\u0422": "T",  # Cyrillic Te
    "\u0425": "X",  # Cyrillic Kha
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",  # Cyrillic ie
    "\u043e": "o",  # Cyrillic o
    "\u0440": "p",  # Cyrillic er
    "\u0441": "c",  # Cyrillic es
    "\u0443": "y",  # Cyrillic u
    "\u0445": "x",  # Cyrillic kha
    "\u0456": "i",  # Ukrainian i
    # Greek to Latin
    "\u0391": "A",  # Greek Alpha
    "\u0392": "B",  # Greek Beta
    "\u0395": "E",  # Greek Epsilon
    "\u0397": "H",  # Greek Eta
    "\u0399": "I",  # Greek Iota
    "\u039a": "K",  # Greek Kappa
    "\u039c": "M",  # Greek Mu
    "\u039d": "N",  # Greek Nu
    "\u039f": "O",  # Greek Omicron
    "\u03a1": "P",  # Greek Rho
    "\u03a4": "T",  # Greek Tau
    "\u03a5": "Y",  # Greek Upsilon
    "\u03a7": "X",  # Greek Chi
    "\u03b1": "a",  # Greek alpha
    "\u03bf": "o",  # Greek omicron
    # Fullwidth to ASCII
    "\uff10": "0",  # Fullwidth 0
    "\uff11": "1",  # Fullwidth 1
    "\uff12": "2",  # Fullwidth 2
    "\uff13": "3",  # Fullwidth 3
    "\uff14": "4",  # Fullwidth 4
    "\uff15": "5",  # Fullwidth 5
    "\uff16": "6",  # Fullwidth 6
    "\uff17": "7",  # Fullwidth 7
    "\uff18": "8",  # Fullwidth 8
    "\uff19": "9",  # Fullwidth 9
    "\uff20": "@",  # Fullwidth @
    "\uff0e": ".",  # Fullwidth .
    "\uff0d": "-",  # Fullwidth -
    "\uff0b": "+",  # Fullwidth +
    "\uff08": "(",  # Fullwidth (
    "\uff09": ")",  # Fullwidth )
}

_CONFUSABLE_RE = re.compile("[" + re.escape("".join(_CONFUSABLE_MAP.keys())) + "]")

# ---------------------------------------------------------------------------
# URL-encoded PII pattern (%40 = @, %2E = ., etc.)
# ---------------------------------------------------------------------------

_URL_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


# ---------------------------------------------------------------------------
# Offset-mapped normalization result (M-5)
# ---------------------------------------------------------------------------


@dataclass
class NormalizationResult:
    """Result of unicode normalization with offset mapping.

    The ``offset_map`` allows mapping positions in the normalized text
    back to positions in the original text.  ``offset_map[i]`` is the
    index in the original text that corresponds to ``text[i]``.

    .. versionadded:: 1.0.24
    """

    text: str
    """The normalized text, ready for PII regex matching."""

    offset_map: list[int] = field(default_factory=list)
    """``offset_map[i]`` = original-text index of ``text[i]``."""

    length_changed: bool = False
    """Whether normalization changed the string length."""

    def map_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a span in normalized text back to original text positions.

        Args:
            start: Start index in normalized text.
            end: End index in normalized text (exclusive).

        Returns:
            ``(orig_start, orig_end)`` in original text coordinates.
        """
        if not self.offset_map or not self.length_changed:
            return start, end
        orig_start = self.offset_map[start] if start < len(self.offset_map) else start
        # end is exclusive — map end-1 then +1
        if end <= 0:
            return orig_start, orig_start
        last = min(end - 1, len(self.offset_map) - 1)
        orig_end = self.offset_map[last] + 1
        return orig_start, orig_end


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_unicode(text: str) -> str:
    """Normalize unicode text for PII detection.

    Applies NFC normalization and strips zero-width / invisible characters.
    This defeats evasion via composed vs decomposed forms and invisible
    character insertion.

    Args:
        text: The raw input text.

    Returns:
        Normalized text suitable for PII regex matching.

    Example::

        >>> normalize_unicode("j\\u200bohn@example.com")
        'john@example.com'
    """
    # NFC normalization -- canonical decomposition + composition
    normalized = unicodedata.normalize("NFC", text)
    # Strip zero-width / invisible characters
    return _ZERO_WIDTH_RE.sub("", normalized)


def normalize_homoglyphs(text: str) -> str:
    """Replace confusable characters with their ASCII equivalents.

    Targets Cyrillic, Greek, and fullwidth characters commonly used to
    evade ASCII-based PII regexes.

    Args:
        text: Text that may contain homoglyphs.

    Returns:
        Text with confusable characters replaced.

    Example::

        >>> normalize_homoglyphs("j\\u043ehn@example.com")
        'john@example.com'
    """
    if not _CONFUSABLE_RE.search(text):
        return text  # Fast path: no confusables found
    return _CONFUSABLE_RE.sub(lambda m: _CONFUSABLE_MAP.get(m.group(), m.group()), text)


def decode_encoded_pii(text: str) -> str:
    """Decode URL-encoded and HTML-entity-encoded content.

    This defeats evasion via percent-encoding (``john%40example.com``) or
    HTML entities (``john&#64;example.com``).

    The original text structure is preserved; only encoded sequences
    are decoded.  This function is safe to apply before regex matching.

    Args:
        text: Text that may contain encoded PII.

    Returns:
        Text with encoded sequences decoded.

    Example::

        >>> decode_encoded_pii("john%40example.com")
        'john@example.com'
        >>> decode_encoded_pii("john&#64;example.com")
        'john@example.com'
    """
    # URL-decode if there are any percent-encoded sequences
    if _URL_ENCODED_RE.search(text):
        text = unquote(text)
    # HTML-entity decode
    if "&" in text:
        text = html.unescape(text)
    return text


def prepare_for_detection(text: str) -> str:
    """Apply all normalization steps to prepare text for PII detection.

    Combines :func:`normalize_unicode`, :func:`normalize_homoglyphs`,
    and :func:`decode_encoded_pii` in the correct order.

    Args:
        text: Raw input text.

    Returns:
        Fully normalized text ready for PII regex matching.

    .. deprecated:: 1.0.24
       Use :func:`prepare_for_detection_mapped` for offset-aware normalization.
    """
    text = normalize_unicode(text)
    text = normalize_homoglyphs(text)
    return decode_encoded_pii(text)


def prepare_for_detection_mapped(text: str) -> NormalizationResult:
    """Apply all normalization steps with offset mapping.

    Like :func:`prepare_for_detection` but returns a
    :class:`NormalizationResult` with an ``offset_map`` that allows
    mapping entity positions on the normalized text back to the original.

    This fixes the M-5 vulnerability: the engine can now *always* run
    regex on fully normalized text, even when normalization changes the
    string length (e.g. stripping zero-width chars, URL-decoding
    ``%40`` → ``@``).

    Args:
        text: Raw input text.

    Returns:
        A :class:`NormalizationResult` with normalized text and offset map.

    .. versionadded:: 1.0.24
    """
    # Build identity offset map: offset_map[i] = i
    offset_map = list(range(len(text)))
    current = text

    # Step 1: NFC normalization (usually length-preserving)
    nfc = unicodedata.normalize("NFC", current)
    if len(nfc) != len(current):
        # NFC changed length — rebuild offset map character by character
        new_map: list[int] = []
        for src_idx, _ in enumerate(nfc):
            if src_idx < len(offset_map):
                new_map.append(offset_map[src_idx])
            else:
                # Composition reduced chars — map to last known position
                new_map.append(offset_map[-1] if offset_map else 0)
        offset_map = new_map
    current = nfc

    # Step 2: Strip zero-width / invisible characters
    if _ZERO_WIDTH_RE.search(current):
        new_text: list[str] = []
        new_map = []
        for i, ch in enumerate(current):
            if ch not in _ZERO_WIDTH_CHARS:
                new_text.append(ch)
                new_map.append(offset_map[i] if i < len(offset_map) else i)
        current = "".join(new_text)
        offset_map = new_map

    # Step 3: Homoglyph replacement (1:1, length-preserving)
    if _CONFUSABLE_RE.search(current):
        chars = list(current)
        for i, ch in enumerate(chars):
            replacement = _CONFUSABLE_MAP.get(ch)
            if replacement is not None:
                chars[i] = replacement
        current = "".join(chars)
        # offset_map unchanged — 1:1 replacement

    # Step 4: URL-decode (%XX → single char, 3→1 collapse)
    if _URL_ENCODED_RE.search(current):
        new_text = []
        new_map = []
        i = 0
        while i < len(current):
            if (
                i + 2 < len(current)
                and current[i] == "%"
                and _is_hex(current[i + 1])
                and _is_hex(current[i + 2])
            ):
                # Decode %XX → single character
                decoded = chr(int(current[i + 1 : i + 3], 16))
                new_text.append(decoded)
                new_map.append(offset_map[i] if i < len(offset_map) else i)
                i += 3  # Skip %XX
            else:
                new_text.append(current[i])
                new_map.append(offset_map[i] if i < len(offset_map) else i)
                i += 1
        current = "".join(new_text)
        offset_map = new_map

    # Step 5: HTML entity decode
    if "&" in current:
        decoded_html = html.unescape(current)
        if len(decoded_html) != len(current):
            # HTML entities changed length — approximate offset mapping
            new_map = []
            src_idx = 0
            for _ in decoded_html:
                if src_idx < len(offset_map):
                    new_map.append(offset_map[src_idx])
                else:
                    new_map.append(offset_map[-1] if offset_map else 0)
                src_idx += 1
            offset_map = new_map
        current = decoded_html

    length_changed = len(current) != len(text)
    return NormalizationResult(
        text=current,
        offset_map=offset_map,
        length_changed=length_changed,
    )


def _is_hex(c: str) -> bool:
    """Check if a character is a hexadecimal digit."""
    return c in "0123456789abcdefABCDEF"

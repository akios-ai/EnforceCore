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
"""

from __future__ import annotations

import html
import re
import unicodedata
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
    """
    text = normalize_unicode(text)
    text = normalize_homoglyphs(text)
    return decode_encoded_pii(text)

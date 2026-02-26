# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""PII detection and redaction engine.

Provides two detection tiers:

**Regex tier** (default)
    Pure regex patterns for common PII categories. Fast (~0.03 ms/call),
    portable, and dependency-free (stdlib only). Covers ~90% of typical PII.

**NER tier** (optional — requires ``pip install enforcecore[ner]``)
    Microsoft Presidio NER pipeline. Slower (~5 ms/call) but covers ~98%
    of PII including contextual entities that regex cannot detect (person
    names, organisations, locations). Enable with
    ``strategy=RedactionStrategy.NER``.

Supported categories (regex tier):
- email: Email addresses
- phone: Phone numbers (US/international formats)
- ssn: US Social Security Numbers
- credit_card: Credit card numbers (Visa, MC, Amex, Discover)
- ip_address: IPv4 addresses
- passport: Passport numbers (ICAO Doc 9303 format: 1-2 letters + 6-9 digits)

Additional categories via NER tier:
- person_name: Person names (contextual, requires NER)
- location, organization, date_time, national_id, and more
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import structlog

from enforcecore.core.types import (
    RedactionError,
    RedactionEvent,
    RedactionStrategy,
)
from enforcecore.redactor.patterns import PatternRegistry
from enforcecore.redactor.secrets import (
    SecretScanner,
    get_secret_mask,
    get_secret_placeholder,
)
from enforcecore.redactor.unicode import (
    prepare_for_detection_mapped,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from enforcecore.redactor.ner import NERBackend

logger = structlog.get_logger("enforcecore.redactor")


# ---------------------------------------------------------------------------
# PII patterns — compiled once at import time
# ---------------------------------------------------------------------------

# Order matters: more specific patterns should come first to avoid
# partial matches (e.g. SSN before phone).

_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    "ssn": re.compile(
        r"\b(?!000|666|9\d\d)"
        r"(?:\d{3}-\d{2}-\d{4}"  # dashes: 123-45-6789
        r"|\d{3} \d{2} \d{4}"  # spaces: 123 45 6789
        r"|\d{9})"  # plain:  123456789
        r"\b"
    ),
    "credit_card": re.compile(
        r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))"
        r"[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,4}\b"
    ),
    "phone": re.compile(
        r"(?<!\d)"  # No digit before
        r"(?:\+?1[-.\s]?)?"  # Optional country code
        r"(?:\(?\d{3}\)?[-.\s]?)"  # Area code
        r"\d{3}[-.\s]?\d{4}"  # Number
        r"(?!\d)"  # No digit after
    ),
    "ip_address": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}" r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # Passport numbers — ICAO Doc 9303 format: 1-2 uppercase letters + 6-9 digits
    # Covers US (A12345678), UK/CA (AB123456), EU machine-readable documents
    "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
}

# Placeholder labels for each category
_PLACEHOLDERS: dict[str, str] = {
    "email": "<EMAIL>",
    "phone": "<PHONE>",
    "ssn": "<SSN>",
    "credit_card": "<CREDIT_CARD>",
    "ip_address": "<IP_ADDRESS>",
    "person_name": "<PERSON>",
    "passport": "<PASSPORT>",
}

# Mask characters per category
_MASKS: dict[str, str] = {
    "email": "****@****.***",
    "phone": "***-***-****",
    "ssn": "***-**-****",
    "credit_card": "****-****-****-****",
    "ip_address": "***.***.***.***",
    "person_name": "****",
    "passport": "**-*******",
}


# ---------------------------------------------------------------------------
# Detected entity
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DetectedEntity:
    """A PII entity found in text."""

    category: str
    start: int
    end: int
    text: str


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------


@dataclass
class RedactionResult:
    """Result of a redaction operation."""

    text: str
    original_text: str
    entities: list[DetectedEntity] = field(default_factory=list)
    events: list[RedactionEvent] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.entities)

    @property
    def was_redacted(self) -> bool:
        return self.count > 0

    @property
    def redacted_text(self) -> str:
        """Alias for :attr:`text` — the redacted output string.

        .. versionadded:: 1.1.1
        """
        return self.text


class Redactor:
    """PII detection and redaction engine.

    Supports two detection tiers — regex (default, fast) and NER (optional,
    requires ``enforcecore[ner]``, higher coverage).

    **Regex example** (default, ~0.03 ms/call)::

        redactor = Redactor(categories=["email", "phone"])
        result = redactor.redact("Call me at 555-123-4567 or john@example.com")
        print(result.text)   # "Call me at <PHONE> or <EMAIL>"
        print(result.count)  # 2

    **NER example** (~5 ms/call, requires ``pip install enforcecore[ner]``)::

        from enforcecore import RedactionStrategy
        redactor = Redactor(
            categories=["person_name", "email", "phone"],
            strategy=RedactionStrategy.NER,
            fallback=RedactionStrategy.REGEX,  # use regex if Presidio unavailable
            threshold=0.8,
        )
        result = redactor.redact("Call John Smith at 555-123-4567")
        print(result.text)   # "Call <PERSON> at <PHONE>"
    """

    __slots__ = ("_categories", "_fallback", "_ner_backend", "_secret_scanner", "_strategy")

    def __init__(
        self,
        categories: Sequence[str] | None = None,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
        *,
        secret_detection: bool = False,
        secret_categories: tuple[str, ...] | list[str] | None = None,
        ner_backend: NERBackend | None = None,
        fallback: RedactionStrategy | None = None,
        threshold: float = 0.8,
    ) -> None:
        """Initialize the redactor.

        Args:
            categories: PII categories to detect. Defaults to all regex-supported
                categories.  ``person_name`` requires the NER tier.
            strategy: Detection/redaction strategy. Default: ``placeholder``.
                Use ``RedactionStrategy.NER`` to enable the Presidio NER tier
                (requires ``pip install enforcecore[ner]``).
            secret_detection: Enable secret detection (API keys, tokens, etc.).
            secret_categories: Secret categories to detect. Defaults to all.
            ner_backend: An already-constructed :class:`NERBackend` instance.
                When *strategy* is ``NER`` and this is ``None``, a backend is
                created automatically using *threshold*.  Ignored when
                *strategy* is not ``NER``.
            fallback: Strategy to use when NER is unavailable (Presidio not
                installed or backend construction fails).  Only relevant when
                *strategy* is ``NER``.  Defaults to ``None`` (raise on failure).
            threshold: Minimum Presidio confidence score (0-1) for the NER
                backend.  Ignored when *strategy* is not ``NER``.
        """
        default_cats = ["email", "phone", "ssn", "credit_card", "ip_address"]
        self._categories = list(categories) if categories else default_cats
        self._strategy = strategy
        self._secret_scanner: SecretScanner | None = None
        self._fallback: RedactionStrategy | None = fallback
        self._ner_backend: NERBackend | None = None

        if secret_detection:
            cats = tuple(secret_categories) if secret_categories else None
            self._secret_scanner = SecretScanner(categories=cats)

        # Set up NER backend when strategy is NER
        if strategy == RedactionStrategy.NER:
            if ner_backend is not None:
                self._ner_backend = ner_backend
            else:
                try:
                    from enforcecore.redactor.ner import NERBackend as _NERBackend

                    self._ner_backend = _NERBackend(threshold=threshold)
                except ImportError:
                    if fallback is not None:
                        logger.warning(
                            "ner_backend_unavailable_using_fallback",
                            fallback=fallback.value,
                            reason="presidio-analyzer not installed; "
                            "install with: pip install enforcecore[ner]",
                        )
                        # _ner_backend stays None; detect() will use fallback
                    else:
                        raise

        # Validate categories
        for cat in self._categories:
            if cat == "person_name":
                if self._ner_backend is None and strategy != RedactionStrategy.NER:
                    logger.warning(
                        "person_name_category_requires_ner",
                        reason="person_name detection requires the NER tier. "
                        "Enable it with strategy=RedactionStrategy.NER "
                        "(pip install enforcecore[ner]). Category will be "
                        "ignored in regex mode.",
                    )
                continue
            if cat not in _PII_PATTERNS:
                # Check NER-supported categories when NER is active
                from enforcecore.redactor.ner import _CATEGORY_TO_PRESIDIO

                if self._ner_backend is not None and cat in _CATEGORY_TO_PRESIDIO:
                    continue  # valid NER-only category
                msg = f"Unknown PII category: '{cat}'. Supported (regex): {list(_PII_PATTERNS.keys())}"
                raise RedactionError(msg)

    @property
    def categories(self) -> list[str]:
        return list(self._categories)

    @property
    def strategy(self) -> RedactionStrategy:
        return self._strategy

    @property
    def fallback(self) -> RedactionStrategy | None:
        """The fallback strategy used when NER is unavailable, or ``None``."""
        return self._fallback

    @property
    def ner_backend(self) -> NERBackend | None:
        """The active NER backend, or ``None`` if using regex detection."""
        return self._ner_backend

    def __repr__(self) -> str:
        return (
            f"Redactor(categories={self._categories!r}, "
            f"strategy={self._strategy.value!r}, "
            f"secret_detection={self._secret_scanner is not None}, "
            f"ner={self._ner_backend is not None})"
        )

    # -- Detection -----------------------------------------------------------

    def detect(self, text: str) -> list[DetectedEntity]:
        """Detect PII entities in text without redacting.

        Returns entities sorted by start position (ascending, left-to-right).

        Includes built-in PII patterns, custom patterns from the
        PatternRegistry, and secret patterns if enabled.

        When ``strategy=RedactionStrategy.NER``, uses the Presidio NER
        pipeline for detection (requires ``pip install enforcecore[ner]``).
        If the NER backend is unavailable and a ``fallback`` strategy was
        configured, falls back to regex detection automatically.

        .. versionchanged:: 1.0.0
           Entities now returned in ascending order (was descending).
           Callers that iterate for replacement should use ``reversed()``.
           Now always uses normalized text for detection with offset
           mapping back to original positions (M-5 fix).
        .. versionchanged:: 1.4.0
           Added NER tier support via ``strategy=RedactionStrategy.NER``.
        """
        # Apply unicode normalization with offset mapping (M-5).
        norm = prepare_for_detection_mapped(text)
        use_text = norm.text
        entities: list[DetectedEntity] = []

        # ── NER tier ────────────────────────────────────────────────────────
        # When strategy is NER and a backend is available, delegate detection
        # to Presidio.  If the backend is unavailable and a fallback is
        # configured, drop through to the regex tier below.
        if self._strategy == RedactionStrategy.NER and self._ner_backend is not None:
            ner_cats = set(self._categories)
            for start, end, category, _score in self._ner_backend.analyze(use_text, ner_cats):
                entities.append(
                    DetectedEntity(
                        category=category,
                        start=start,
                        end=end,
                        text=use_text[start:end],
                    )
                )
            # Map positions back and return (skip regex tier when NER active)
            if norm.length_changed:
                entities = [
                    DetectedEntity(
                        category=e.category,
                        start=norm.map_span(e.start, e.end)[0],
                        end=norm.map_span(e.start, e.end)[1],
                        text=text[
                            norm.map_span(e.start, e.end)[0] : norm.map_span(e.start, e.end)[1]
                        ],
                    )
                    for e in entities
                ]
            entities = self._remove_overlaps(entities)
            entities.sort(key=lambda e: e.start)
            return entities
            # NER backend unavailable — fallback configured, use regex tier below

        # ── Regex tier ──────────────────────────────────────────────────────
        # Built-in PII patterns
        for cat in self._categories:
            if cat == "person_name":
                # Skipped in regex mode — warning emitted once at construction time
                continue

            pattern = _PII_PATTERNS.get(cat)
            if pattern is None:
                continue

            for match in pattern.finditer(use_text):
                entities.append(
                    DetectedEntity(
                        category=cat,
                        start=match.start(),
                        end=match.end(),
                        text=match.group(),
                    )
                )

        # Custom patterns from the global registry
        for cat, custom in PatternRegistry.get_all().items():
            for match in custom.regex.finditer(use_text):
                matched_text = match.group()
                # Apply optional validator
                if custom.validator is not None and not custom.validator(matched_text):
                    continue
                entities.append(
                    DetectedEntity(
                        category=cat,
                        start=match.start(),
                        end=match.end(),
                        text=matched_text,
                    )
                )

        # Secret detection
        if self._secret_scanner is not None:
            for secret in self._secret_scanner.detect(use_text):
                entities.append(
                    DetectedEntity(
                        category=secret.category,
                        start=secret.start,
                        end=secret.end,
                        text=secret.text,
                    )
                )

        # Map entity positions from normalized text back to original text
        if norm.length_changed:
            entities = [
                DetectedEntity(
                    category=e.category,
                    start=norm.map_span(e.start, e.end)[0],
                    end=norm.map_span(e.start, e.end)[1],
                    text=text[norm.map_span(e.start, e.end)[0] : norm.map_span(e.start, e.end)[1]],
                )
                for e in entities
            ]

        # Remove overlapping entities (keep longer match)
        entities = self._remove_overlaps(entities)

        # Sort by start position ascending (left-to-right, natural order)
        entities.sort(key=lambda e: e.start)
        return entities

    # -- Redaction ------------------------------------------------------------

    def redact(self, text: str) -> RedactionResult:
        """Detect and redact PII from text.

        Returns a ``RedactionResult`` with the redacted text, detected
        entities, and redaction events.
        """
        entities = self.detect(text)
        if not entities:
            return RedactionResult(
                text=text,
                original_text=text,
            )

        result_text = text
        events: list[RedactionEvent] = []

        # Replace from right to left to preserve positions
        for entity in reversed(entities):
            replacement = self._get_replacement(entity)
            result_text = result_text[: entity.start] + replacement + result_text[entity.end :]
            events.append(
                RedactionEvent(
                    entity_type=entity.category,
                    start=entity.start,
                    end=entity.end,
                    strategy=self._strategy,
                    replacement=replacement,
                )
            )

        logger.info(
            "pii_redacted",
            count=len(entities),
            categories=[e.category for e in entities],
        )

        return RedactionResult(
            text=result_text,
            original_text=text,
            entities=entities,  # Already in ascending order
            events=list(reversed(events)),  # Events in left-to-right order
        )

    # -- Strategy implementation ----------------------------------------------

    def _get_replacement(self, entity: DetectedEntity) -> str:
        """Generate the replacement string for a detected entity."""
        # Check if it's a custom pattern category
        custom = PatternRegistry.get(entity.category)

        # NER and REGEX strategies use PLACEHOLDER replacement style
        if self._strategy in (
            RedactionStrategy.PLACEHOLDER,
            RedactionStrategy.NER,
            RedactionStrategy.REGEX,
        ):
            if custom is not None:
                return custom.placeholder
            return _PLACEHOLDERS.get(entity.category) or get_secret_placeholder(entity.category)

        if self._strategy == RedactionStrategy.MASK:
            if custom is not None:
                return custom.mask
            return _MASKS.get(entity.category) or get_secret_mask(entity.category)

        if self._strategy == RedactionStrategy.HASH:
            h = hashlib.sha256(entity.text.encode()).hexdigest()[:16]
            return f"[SHA256:{h}]"

        if self._strategy == RedactionStrategy.REMOVE:
            return ""

        msg = f"Unknown redaction strategy: {self._strategy!r}"  # pragma: no cover
        raise AssertionError(msg)  # pragma: no cover

    # -- Helpers --------------------------------------------------------------

    @staticmethod
    def _remove_overlaps(entities: list[DetectedEntity]) -> list[DetectedEntity]:
        """Remove overlapping entities, keeping the longer match."""
        if not entities:
            return entities

        # Sort by start, then by length descending
        sorted_entities = sorted(entities, key=lambda e: (e.start, -(e.end - e.start)))
        result: list[DetectedEntity] = [sorted_entities[0]]

        for entity in sorted_entities[1:]:
            last = result[-1]
            if entity.start >= last.end:
                result.append(entity)
            # else: overlapping — skip (we kept the longer one due to sort order)

        return result

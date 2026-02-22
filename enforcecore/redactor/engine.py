# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Lightweight PII detection engine.

Uses regex patterns for common PII categories. Designed to be fast, portable,
and dependency-free (stdlib only). Presidio can be added as an optional
enhanced backend in a future release.

Supported categories:
- email: Email addresses
- phone: Phone numbers (US/international formats)
- ssn: US Social Security Numbers
- credit_card: Credit card numbers (Visa, MC, Amex, Discover)
- ip_address: IPv4 addresses
- person_name: Basic person name patterns (Title Case sequences)

Performance: ~0.1-0.5ms per call (pure regex, no NLP pipeline).
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
from enforcecore.redactor.unicode import prepare_for_detection

if TYPE_CHECKING:
    from collections.abc import Sequence

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
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
}

# Placeholder labels for each category
_PLACEHOLDERS: dict[str, str] = {
    "email": "<EMAIL>",
    "phone": "<PHONE>",
    "ssn": "<SSN>",
    "credit_card": "<CREDIT_CARD>",
    "ip_address": "<IP_ADDRESS>",
    "person_name": "<PERSON>",
}

# Mask characters per category
_MASKS: dict[str, str] = {
    "email": "****@****.***",
    "phone": "***-***-****",
    "ssn": "***-**-****",
    "credit_card": "****-****-****-****",
    "ip_address": "***.***.***.***",
    "person_name": "****",
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


class Redactor:
    """PII detection and redaction engine.

    Uses compiled regex patterns for fast, portable PII detection.
    Supports configurable redaction strategies per category.

    Example::

        redactor = Redactor(categories=["email", "phone"])
        result = redactor.redact("Call me at 555-123-4567 or john@example.com")
        print(result.text)   # "Call me at <PHONE> or <EMAIL>"
        print(result.count)  # 2
    """

    __slots__ = ("_categories", "_secret_scanner", "_strategy")

    def __init__(
        self,
        categories: Sequence[str] | None = None,
        strategy: RedactionStrategy = RedactionStrategy.PLACEHOLDER,
        *,
        secret_detection: bool = False,
        secret_categories: tuple[str, ...] | list[str] | None = None,
    ) -> None:
        """Initialize the redactor.

        Args:
            categories: PII categories to detect. Defaults to all supported.
                Supported: ``email``, ``phone``, ``ssn``, ``credit_card``,
                ``ip_address``.
            strategy: How to redact detected PII. Default: ``placeholder``.
            secret_detection: Enable secret detection (API keys, tokens, etc.).
            secret_categories: Secret categories to detect. Defaults to all.
        """
        default_cats = ["email", "phone", "ssn", "credit_card", "ip_address"]
        self._categories = list(categories) if categories else default_cats
        self._strategy = strategy
        self._secret_scanner: SecretScanner | None = None

        if secret_detection:
            cats = tuple(secret_categories) if secret_categories else None
            self._secret_scanner = SecretScanner(categories=cats)

        # Validate categories
        for cat in self._categories:
            if cat == "person_name":
                logger.warning(
                    "person_name_category_unsupported",
                    reason="pure regex detection is too noisy; "
                    "consider using an NLP pipeline for name detection. "
                    "Category will be ignored.",
                )
                continue
            if cat not in _PII_PATTERNS:
                msg = f"Unknown PII category: '{cat}'. Supported: {list(_PII_PATTERNS.keys())}"
                raise RedactionError(msg)

    @property
    def categories(self) -> list[str]:
        return list(self._categories)

    @property
    def strategy(self) -> RedactionStrategy:
        return self._strategy

    def __repr__(self) -> str:
        return (
            f"Redactor(categories={self._categories!r}, "
            f"strategy={self._strategy.value!r}, "
            f"secret_detection={self._secret_scanner is not None})"
        )

    # -- Detection -----------------------------------------------------------

    def detect(self, text: str) -> list[DetectedEntity]:
        """Detect PII entities in text without redacting.

        Returns entities sorted by start position (descending) for safe
        replacement from right to left.

        Includes built-in PII patterns, custom patterns from the
        PatternRegistry, and secret patterns if enabled.
        """
        # Apply unicode normalization to defeat evasion techniques.
        # If normalization changes text length, fall back to original to
        # avoid position mismatch when slicing for replacement.
        normalized = prepare_for_detection(text)
        use_text = text if len(normalized) != len(text) else normalized
        entities: list[DetectedEntity] = []

        # Built-in PII patterns
        for cat in self._categories:
            if cat == "person_name":
                # Skipped — warning emitted once at construction time
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

        # Remove overlapping entities (keep longer match)
        entities = self._remove_overlaps(entities)

        # Sort by start position descending for safe right-to-left replacement
        entities.sort(key=lambda e: e.start, reverse=True)
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
        for entity in entities:
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
            entities=list(reversed(entities)),  # Return in left-to-right order
            events=list(reversed(events)),
        )

    # -- Strategy implementation ----------------------------------------------

    def _get_replacement(self, entity: DetectedEntity) -> str:
        """Generate the replacement string for a detected entity."""
        # Check if it's a custom pattern category
        custom = PatternRegistry.get(entity.category)

        if self._strategy == RedactionStrategy.PLACEHOLDER:
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

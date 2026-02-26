# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Optional NER-based PII detection backend using Microsoft Presidio.

Provides ~98% PII coverage (vs ~90% for pure regex) by using a named-entity
recognition pipeline. Substantially slower than regex (~5 ms/call vs
~0.03 ms/call) but detects contextual PII that regex cannot:

- Person names (e.g. "call John Smith later")
- Organisations, locations, date/time expressions
- Novel PII patterns beyond the built-in regex library

Requires ``pip install enforcecore[ner]`` which installs:

- ``presidio-analyzer>=2.2``
- ``presidio-anonymizer>=2.2``
- ``spacy>=3.7``

A spaCy English model must also be downloaded separately::

    python -m spacy download en_core_web_lg

If Presidio is not installed, :class:`NERBackend` raises
:class:`ImportError` on instantiation. :class:`~enforcecore.redactor.engine.Redactor`
handles this gracefully by falling back to the configured ``fallback`` strategy.

.. versionadded:: 1.4.0
"""

from __future__ import annotations

import importlib.util
import logging
from typing import Any

logger = logging.getLogger("enforcecore.ner")

# ---------------------------------------------------------------------------
# Availability check
# ---------------------------------------------------------------------------


def is_ner_available() -> bool:
    """Return ``True`` if ``presidio-analyzer`` is installed and importable.

    Does not guarantee a spaCy model is available — that is checked lazily
    on first :class:`NERBackend` instantiation.

    .. versionadded:: 1.4.0
    """
    return importlib.util.find_spec("presidio_analyzer") is not None


# ---------------------------------------------------------------------------
# Entity-type mapping: Presidio ↔ EnforceCore categories
# ---------------------------------------------------------------------------

# Presidio RECOGNIZER_RESULT.entity_type → EnforceCore category name
_PRESIDIO_TO_CATEGORY: dict[str, str] = {
    "EMAIL_ADDRESS": "email",
    "PHONE_NUMBER": "phone",
    "US_SSN": "ssn",
    "CREDIT_CARD": "credit_card",
    "IP_ADDRESS": "ip_address",
    "PERSON": "person_name",
    "US_PASSPORT": "passport",
    "LOCATION": "location",
    "DATE_TIME": "date_time",
    "NRP": "national_id",  # Nationalities, Religious, Political groups
    "MEDICAL_LICENSE": "medical_id",
    "US_DRIVER_LICENSE": "driver_license",
    "IBAN_CODE": "iban",
    "CRYPTO": "crypto_address",
    "US_BANK_NUMBER": "bank_account",
    "US_ITIN": "itin",
    "ORGANIZATION": "organization",
}

# EnforceCore category → Presidio entity type (used to filter analysis scope)
_CATEGORY_TO_PRESIDIO: dict[str, str] = {
    "email": "EMAIL_ADDRESS",
    "phone": "PHONE_NUMBER",
    "ssn": "US_SSN",
    "credit_card": "CREDIT_CARD",
    "ip_address": "IP_ADDRESS",
    "person_name": "PERSON",
    "passport": "US_PASSPORT",
    "location": "LOCATION",
    "date_time": "DATE_TIME",
    "national_id": "NRP",
    "medical_id": "MEDICAL_LICENSE",
    "driver_license": "US_DRIVER_LICENSE",
    "iban": "IBAN_CODE",
    "crypto_address": "CRYPTO",
    "bank_account": "US_BANK_NUMBER",
    "itin": "US_ITIN",
    "organization": "ORGANIZATION",
}


# ---------------------------------------------------------------------------
# Internal factory — isolated so tests can patch it
# ---------------------------------------------------------------------------


def _build_analyzer_engine() -> object:
    """Create and return a ``presidio_analyzer.AnalyzerEngine`` instance.

    Factored out from :class:`NERBackend.__init__` so that tests can patch
    this function instead of fighting with lazy module import mechanics.
    """
    from presidio_analyzer import AnalyzerEngine

    return AnalyzerEngine()


# ---------------------------------------------------------------------------
# NER backend
# ---------------------------------------------------------------------------


class NERBackend:
    """Presidio-powered NER PII detection backend.

    Wraps ``presidio_analyzer.AnalyzerEngine`` for use inside the
    :class:`~enforcecore.redactor.engine.Redactor`. The Presidio engine is
    constructed eagerly at ``__init__`` time — this is intentional so that
    missing models fail fast rather than at first call.

    Requires ``pip install enforcecore[ner]``.

    Args:
        threshold: Minimum Presidio confidence score (0-1) for an entity to
            be returned. Default ``0.8``.
        language: BCP-47 language tag passed to Presidio. Default ``"en"``.

    Raises:
        ImportError: If ``presidio-analyzer`` is not installed or the spaCy
            model cannot be loaded.

    Example::

        from enforcecore.redactor.ner import NERBackend
        backend = NERBackend(threshold=0.85)
        results = backend.analyze("Call John Smith at 555-123-4567", {"person_name", "phone"})
        # → [(5, 15, "person_name", 0.9), (19, 31, "phone", 0.95)]

    .. versionadded:: 1.4.0
    """

    __slots__ = ("_analyzer", "_language", "_threshold")

    def __init__(self, threshold: float = 0.8, language: str = "en") -> None:
        if not is_ner_available():
            raise ImportError(
                "presidio-analyzer is required for NER-based PII detection. "
                "Install it with: pip install enforcecore[ner]\n\n"
                "Then download a spaCy model:\n"
                "    python -m spacy download en_core_web_lg"
            )
        try:
            self._analyzer: Any = _build_analyzer_engine()
        except OSError as exc:
            raise ImportError(
                f"Failed to load spaCy model for Presidio: {exc}\n\n"
                "Download an English model with:\n"
                "    python -m spacy download en_core_web_lg\n"
                "(or en_core_web_sm for a smaller model)"
            ) from exc
        except Exception as exc:  # broad catch: Presidio/spaCy can raise many things
            raise ImportError(
                f"Failed to initialize Presidio AnalyzerEngine: {exc}\n\n"
                "Ensure presidio-analyzer is correctly installed:\n"
                "    pip install enforcecore[ner]"
            ) from exc

        self._threshold = float(threshold)
        self._language = language
        logger.debug(
            "ner_backend_initialized threshold=%.2f language=%s", self._threshold, self._language
        )

    # -- Public API ----------------------------------------------------------

    def analyze(
        self,
        text: str,
        categories: set[str] | None = None,
        *,
        threshold: float | None = None,
    ) -> list[tuple[int, int, str, float]]:
        """Analyze *text* for PII entities using Presidio NER.

        Args:
            text: The text to analyze.
            categories: EnforceCore PII category names to detect.  Pass
                ``None`` (the default) to analyze for all supported entity
                types.
            threshold: Override the backend's configured confidence threshold
                for this call only.

        Returns:
            List of ``(start, end, category, score)`` tuples for each entity
            that meets the confidence threshold, sorted by start position.

        Example::

            results = backend.analyze(
                "Call John at 555-555-1234",
                {"person_name", "phone"},
            )
            # → [(5, 9, "person_name", 0.85), (13, 25, "phone", 0.95)]
        """
        if not text.strip():
            return []

        effective_threshold = threshold if threshold is not None else self._threshold

        # Map EnforceCore categories → Presidio entity types for scoped analysis.
        # If categories is None (or contains categories without a Presidio mapping),
        # we pass entities=None which makes Presidio analyze everything.
        presidio_entities: list[str] | None = None
        if categories:
            mapped = [
                _CATEGORY_TO_PRESIDIO[cat] for cat in categories if cat in _CATEGORY_TO_PRESIDIO
            ]
            if mapped:
                presidio_entities = mapped

        analyzer = self._analyzer
        results = analyzer.analyze(
            text=text,
            language=self._language,
            entities=presidio_entities,
        )

        output: list[tuple[int, int, str, float]] = []
        for result in results:
            if result.score < effective_threshold:
                continue
            category = _PRESIDIO_TO_CATEGORY.get(result.entity_type, result.entity_type.lower())
            # Filter to requested categories if specified
            if categories is not None and category not in categories:
                continue
            output.append((result.start, result.end, category, float(result.score)))

        # Sort by start position for deterministic output
        output.sort(key=lambda t: t[0])
        return output

    # -- Properties ----------------------------------------------------------

    @property
    def threshold(self) -> float:
        """The configured confidence threshold (0-1)."""
        return self._threshold

    @property
    def language(self) -> str:
        """The configured language tag (e.g. ``"en"``)."""
        return self._language

    def __repr__(self) -> str:
        return f"NERBackend(threshold={self._threshold!r}, language={self._language!r})"

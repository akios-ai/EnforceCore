# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for the NER-based PII detection backend (v1.4.0).

Presidio may or may not be installed in the test environment.  All tests
use mocking to avoid requiring the optional dep, except for the
availability-check test.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from enforcecore.core.types import RedactionStrategy
from enforcecore.redactor.engine import Redactor
from enforcecore.redactor.ner import (
    _CATEGORY_TO_PRESIDIO,
    _PRESIDIO_TO_CATEGORY,
    NERBackend,
    is_ner_available,
)

# ---------------------------------------------------------------------------
# Helpers — mock Presidio result object
# ---------------------------------------------------------------------------


def _make_presidio_result(
    entity_type: str,
    start: int,
    end: int,
    score: float = 0.9,
) -> MagicMock:
    """Create a fake Presidio RecognizerResult."""
    r = MagicMock()
    r.entity_type = entity_type
    r.start = start
    r.end = end
    r.score = score
    return r


# ---------------------------------------------------------------------------
# is_ner_available
# ---------------------------------------------------------------------------


class TestIsNerAvailable:
    def test_returns_bool(self) -> None:
        result = is_ner_available()
        assert isinstance(result, bool)

    def test_false_when_presidio_missing(self) -> None:
        with patch("enforcecore.redactor.ner.importlib.util.find_spec", return_value=None):
            assert is_ner_available() is False

    def test_true_when_presidio_present(self) -> None:
        mock_spec = MagicMock()
        with patch("enforcecore.redactor.ner.importlib.util.find_spec", return_value=mock_spec):
            assert is_ner_available() is True


# ---------------------------------------------------------------------------
# Entity-type mappings
# ---------------------------------------------------------------------------


class TestEntityMappings:
    def test_presidio_to_category_covers_core_types(self) -> None:
        required = {
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "US_SSN",
            "CREDIT_CARD",
            "IP_ADDRESS",
            "PERSON",
        }
        assert required.issubset(_PRESIDIO_TO_CATEGORY.keys())

    def test_category_to_presidio_covers_core_categories(self) -> None:
        required = {"email", "phone", "ssn", "credit_card", "ip_address", "person_name"}
        assert required.issubset(_CATEGORY_TO_PRESIDIO.keys())

    def test_person_name_maps_to_presidio_person(self) -> None:
        assert _CATEGORY_TO_PRESIDIO["person_name"] == "PERSON"
        assert _PRESIDIO_TO_CATEGORY["PERSON"] == "person_name"


# ---------------------------------------------------------------------------
# NERBackend
# ---------------------------------------------------------------------------


class TestNERBackendUnavailable:
    """Tests when Presidio is not installed."""

    def test_raises_import_error_when_unavailable(self) -> None:
        with (
            patch("enforcecore.redactor.ner.is_ner_available", return_value=False),
            pytest.raises(ImportError, match="presidio-analyzer"),
        ):
            NERBackend()

    def test_error_message_mentions_install_command(self) -> None:
        with (
            patch("enforcecore.redactor.ner.is_ner_available", return_value=False),
            pytest.raises(ImportError, match="enforcecore\\[ner\\]"),
        ):
            NERBackend()


class TestNERBackendMocked:
    """Tests with a mocked Presidio AnalyzerEngine."""

    def _make_backend(self, threshold: float = 0.8) -> NERBackend:
        """Create a NERBackend with a mocked AnalyzerEngine."""
        mock_engine = MagicMock()
        with (
            patch("enforcecore.redactor.ner.is_ner_available", return_value=True),
            patch(
                "enforcecore.redactor.ner._build_analyzer_engine",
                return_value=mock_engine,
            ),
        ):
            backend = NERBackend(threshold=threshold)
            backend._analyzer = mock_engine
            return backend

    def test_properties(self) -> None:
        backend = self._make_backend(threshold=0.85)
        assert backend.threshold == 0.85
        assert backend.language == "en"

    def test_repr(self) -> None:
        backend = self._make_backend()
        assert "NERBackend" in repr(backend)
        assert "0.8" in repr(backend)

    def test_analyze_empty_text(self) -> None:
        backend = self._make_backend()
        results = backend.analyze("")
        assert results == []

    def test_analyze_whitespace_only(self) -> None:
        backend = self._make_backend()
        results = backend.analyze("   ")
        assert results == []

    def test_analyze_returns_filtered_results(self) -> None:
        backend = self._make_backend(threshold=0.8)
        mock_results = [
            _make_presidio_result("EMAIL_ADDRESS", 5, 20, score=0.95),
            _make_presidio_result("PERSON", 25, 35, score=0.7),  # below threshold
            _make_presidio_result("PHONE_NUMBER", 40, 52, score=0.9),
        ]
        backend._analyzer.analyze.return_value = mock_results  # type: ignore[attr-defined]

        results = backend.analyze(
            "text email address person_name phone",
            {"email", "person_name", "phone"},
        )

        # score=0.7 < threshold=0.8 → filtered out
        assert len(results) == 2
        categories = {r[2] for r in results}
        assert "email" in categories
        assert "phone" in categories
        assert "person_name" not in categories

    def test_analyze_threshold_override(self) -> None:
        backend = self._make_backend(threshold=0.8)
        mock_results = [
            _make_presidio_result("PERSON", 0, 10, score=0.75),
        ]
        backend._analyzer.analyze.return_value = mock_results  # type: ignore[attr-defined]

        # Override threshold to 0.7 — entity should pass
        results = backend.analyze("John Smith text", threshold=0.7)
        assert len(results) == 1

        # Default threshold 0.8 — entity should be filtered
        results = backend.analyze("John Smith text")
        assert len(results) == 0

    def test_analyze_category_filtering(self) -> None:
        """When categories specified, only requested categories returned."""
        backend = self._make_backend()
        mock_results = [
            _make_presidio_result("EMAIL_ADDRESS", 0, 15, score=0.9),
            _make_presidio_result("PERSON", 20, 30, score=0.9),
        ]
        backend._analyzer.analyze.return_value = mock_results  # type: ignore[attr-defined]

        results = backend.analyze("some text", categories={"email"})

        # PERSON maps to person_name — should be filtered since only "email" requested
        categories = {r[2] for r in results}
        assert "email" in categories
        assert "person_name" not in categories

    def test_analyze_none_categories_returns_all(self) -> None:
        """When categories=None, all results are returned."""
        backend = self._make_backend()
        mock_results = [
            _make_presidio_result("EMAIL_ADDRESS", 0, 15, score=0.9),
            _make_presidio_result("PERSON", 20, 30, score=0.9),
        ]
        backend._analyzer.analyze.return_value = mock_results  # type: ignore[attr-defined]

        results = backend.analyze("some text", categories=None)

        assert len(results) == 2

    def test_analyze_sorts_by_start(self) -> None:
        """Results are returned sorted by start position."""
        backend = self._make_backend()
        mock_results = [
            _make_presidio_result("PHONE_NUMBER", 30, 42, score=0.9),
            _make_presidio_result("EMAIL_ADDRESS", 5, 20, score=0.9),
        ]
        backend._analyzer.analyze.return_value = mock_results  # type: ignore[attr-defined]

        results = backend.analyze("text here")

        assert results[0][0] < results[1][0]  # sorted by start

    def test_analyze_unknown_presidio_entity_falls_back_to_lowercase(self) -> None:
        """Unknown Presidio entity types are converted to lowercase category names."""
        backend = self._make_backend()
        mock_results = [
            _make_presidio_result("FUTURE_ENTITY_TYPE", 0, 5, score=0.9),
        ]
        backend._analyzer.analyze.return_value = mock_results  # type: ignore[attr-defined]

        results = backend.analyze("some text", categories=None)

        assert len(results) == 1
        assert results[0][2] == "future_entity_type"


# ---------------------------------------------------------------------------
# Redactor NER integration
# ---------------------------------------------------------------------------


class TestRedactorNERStrategy:
    """Tests for Redactor with strategy=NER."""

    def test_raises_import_error_when_no_presidio_no_fallback(self) -> None:
        with (
            patch("enforcecore.redactor.ner.is_ner_available", return_value=False),
            pytest.raises(ImportError),
        ):
            Redactor(
                categories=["email"],
                strategy=RedactionStrategy.NER,
            )

    def test_falls_back_to_regex_when_presidio_unavailable(self) -> None:
        with patch("enforcecore.redactor.ner.is_ner_available", return_value=False):
            r = Redactor(
                categories=["email"],
                strategy=RedactionStrategy.NER,
                fallback=RedactionStrategy.REGEX,
            )
        assert r.ner_backend is None
        assert r.fallback == RedactionStrategy.REGEX

    def test_fallback_regex_still_detects_pii(self) -> None:
        with patch("enforcecore.redactor.ner.is_ner_available", return_value=False):
            r = Redactor(
                categories=["email"],
                strategy=RedactionStrategy.NER,
                fallback=RedactionStrategy.REGEX,
            )
        result = r.redact("Contact us at test@example.com please")
        assert "<EMAIL>" in result.text
        assert "test@example.com" not in result.text

    def test_ner_redactor_uses_placeholder_replacement(self) -> None:
        """NER strategy should produce PLACEHOLDER-style replacements."""
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = [
            _make_presidio_result("EMAIL_ADDRESS", 14, 29, score=0.95),
        ]
        mock_backend = MagicMock(spec=NERBackend)
        mock_backend.analyze.return_value = [(14, 29, "email", 0.95)]

        with (
            patch("enforcecore.redactor.ner.is_ner_available", return_value=True),
            patch("enforcecore.redactor.ner.AnalyzerEngine", return_value=mock_engine, create=True),
        ):
            r = Redactor(
                categories=["email"],
                strategy=RedactionStrategy.NER,
                ner_backend=mock_backend,
            )
        result = r.redact("Contact us at test@example.com please")
        assert "<EMAIL>" in result.text

    def test_ner_backend_passed_directly(self) -> None:
        """An explicit NERBackend can be passed to avoid auto-construction."""
        mock_backend = MagicMock(spec=NERBackend)
        mock_backend.analyze.return_value = []

        r = Redactor(
            categories=["email"],
            strategy=RedactionStrategy.NER,
            ner_backend=mock_backend,
        )
        assert r.ner_backend is mock_backend

    def test_ner_detects_person_name(self) -> None:
        """person_name category should work via NER (not skipped)."""
        mock_backend = MagicMock(spec=NERBackend)
        mock_backend.analyze.return_value = [(5, 15, "person_name", 0.92)]

        r = Redactor(
            categories=["person_name"],
            strategy=RedactionStrategy.NER,
            ner_backend=mock_backend,
        )
        result = r.redact("Call John Smith now")
        assert "<PERSON>" in result.text

    def test_ner_threshold_passed_to_backend(self) -> None:
        """threshold parameter is forwarded to NERBackend on auto-construction."""
        mock_engine = MagicMock()
        mock_engine.analyze.return_value = []

        with (
            patch("enforcecore.redactor.ner.is_ner_available", return_value=True),
            patch(
                "enforcecore.redactor.ner._build_analyzer_engine",
                return_value=mock_engine,
            ),
        ):
            r = Redactor(
                categories=["email"],
                strategy=RedactionStrategy.NER,
                threshold=0.9,
            )
        # Backend should have been constructed
        assert r.ner_backend is not None

    def test_ner_properties(self) -> None:
        mock_backend = MagicMock(spec=NERBackend)
        r = Redactor(
            categories=["email"],
            strategy=RedactionStrategy.NER,
            ner_backend=mock_backend,
            fallback=RedactionStrategy.REGEX,
        )
        assert r.strategy == RedactionStrategy.NER
        assert r.fallback == RedactionStrategy.REGEX
        assert r.ner_backend is mock_backend

    def test_ner_repr_includes_ner_true(self) -> None:
        mock_backend = MagicMock(spec=NERBackend)
        r = Redactor(
            categories=["email"],
            strategy=RedactionStrategy.NER,
            ner_backend=mock_backend,
        )
        assert "ner=True" in repr(r)

    def test_regex_repr_includes_ner_false(self) -> None:
        r = Redactor(categories=["email"])
        assert "ner=False" in repr(r)


# ---------------------------------------------------------------------------
# REGEX strategy
# ---------------------------------------------------------------------------


class TestRedactorREGEXStrategy:
    def test_regex_strategy_identical_to_placeholder(self) -> None:
        r_regex = Redactor(categories=["email"], strategy=RedactionStrategy.REGEX)
        r_placeholder = Redactor(categories=["email"], strategy=RedactionStrategy.PLACEHOLDER)
        text = "Email: user@example.com"
        assert r_regex.redact(text).text == r_placeholder.redact(text).text

    def test_regex_strategy_has_no_ner_backend(self) -> None:
        r = Redactor(categories=["email"], strategy=RedactionStrategy.REGEX)
        assert r.ner_backend is None

    def test_regex_strategy_fallback_is_none(self) -> None:
        r = Redactor(categories=["email"], strategy=RedactionStrategy.REGEX)
        assert r.fallback is None

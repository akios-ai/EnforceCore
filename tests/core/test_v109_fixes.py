# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.0.9 audit fixes and improvements.

Covers:
- H-1: RateLimitError uses ViolationType.RATE_LIMIT
- H-2: Async hook task reference stored (no GC)
- M-1: RuleEngine.remove_rule()
- M-4: Cache comment accuracy (FIFO)
- M-5/L-6: person_name warning at init, not per-call
- L-1: Shared extract_strings utility
- L-2: Unreachable redaction strategy raises AssertionError
- M-8: Test that asserts ViolationType on RateLimitError
- Missing exports: clear_policy_cache, policy models, eval helpers
"""

from __future__ import annotations

import threading

import pytest

from enforcecore.core.rules import ContentRule, RuleEngine
from enforcecore.core.types import ViolationType
from enforcecore.guard.ratelimit import RateLimitError
from enforcecore.redactor.engine import Redactor
from enforcecore.utils import extract_strings

# ---------------------------------------------------------------------------
# H-1: RateLimitError uses correct ViolationType
# ---------------------------------------------------------------------------


class TestH1RateLimitViolationType:
    def test_rate_limit_error_has_correct_type(self) -> None:
        err = RateLimitError("tool", 10, 60.0)
        assert err.violation_type == ViolationType.RATE_LIMIT

    def test_rate_limit_error_not_resource_limit(self) -> None:
        err = RateLimitError("tool", 10, 60.0)
        assert err.violation_type != ViolationType.RESOURCE_LIMIT

    def test_rate_limit_error_attributes(self) -> None:
        err = RateLimitError("search", 5, 30.0, policy_name="p")
        assert err.tool_name == "search"
        assert err.max_calls == 5
        assert err.window_seconds == 30.0
        assert err.policy_name == "p"


# ---------------------------------------------------------------------------
# H-2: Background task storage
# ---------------------------------------------------------------------------


class TestH2AsyncHookTaskStorage:
    def test_background_tasks_set_exists(self) -> None:
        from enforcecore.plugins.hooks import _background_tasks

        assert isinstance(_background_tasks, set)


# ---------------------------------------------------------------------------
# M-1: RuleEngine.remove_rule()
# ---------------------------------------------------------------------------


class TestM1RemoveRule:
    def test_remove_existing_rule(self) -> None:
        engine = RuleEngine()
        engine.add_rule(ContentRule(name="test", pattern=r"bad"))
        assert engine.rule_count == 1
        removed = engine.remove_rule("test")
        assert removed is True
        assert engine.rule_count == 0

    def test_remove_nonexistent_rule(self) -> None:
        engine = RuleEngine()
        removed = engine.remove_rule("nonexistent")
        assert removed is False

    def test_remove_clears_compiled(self) -> None:
        engine = RuleEngine()
        engine.add_rule(ContentRule(name="test", pattern=r"bad"))
        # Should find violations
        assert len(engine.check("bad")) > 0
        engine.remove_rule("test")
        # Should find no violations
        assert len(engine.check("bad")) == 0

    def test_remove_one_of_many(self) -> None:
        engine = RuleEngine()
        engine.add_rule(ContentRule(name="a", pattern=r"alpha"))
        engine.add_rule(ContentRule(name="b", pattern=r"beta"))
        engine.remove_rule("a")
        assert engine.rule_count == 1
        assert len(engine.check("alpha")) == 0
        assert len(engine.check("beta")) > 0


# ---------------------------------------------------------------------------
# M-5/L-6: person_name warning at init, not per-call
# ---------------------------------------------------------------------------


class TestM5PersonNameWarning:
    def test_person_name_does_not_raise(self) -> None:
        """person_name should be accepted but warned, not raise."""
        redactor = Redactor(categories=["email", "person_name"])
        assert "email" in redactor.categories

    def test_person_name_skipped_in_detection(self) -> None:
        """Detect should not crash with person_name category."""
        redactor = Redactor(categories=["email", "person_name"])
        entities = redactor.detect("John Smith at john@example.com")
        # Should find email, but not person_name (skipped)
        categories = {e.category for e in entities}
        assert "email" in categories
        assert "person_name" not in categories


# ---------------------------------------------------------------------------
# L-1: Shared extract_strings utility
# ---------------------------------------------------------------------------


class TestL1SharedExtractStrings:
    def test_basic_strings(self) -> None:
        assert extract_strings(("a", "b", "c")) == ["a", "b", "c"]

    def test_nested_dict(self) -> None:
        result = extract_strings(({"k": "v"},))
        assert result == ["v"]

    def test_nested_list(self) -> None:
        result = extract_strings((["a", "b"],))
        assert result == ["a", "b"]

    def test_non_string_values(self) -> None:
        result = extract_strings((42, 3.14, None))
        assert result == []

    def test_deeply_nested(self) -> None:
        result = extract_strings(({"a": {"b": ["deep"]}},))
        assert result == ["deep"]

    def test_set_support(self) -> None:
        result = extract_strings(({"hello"},))
        assert result == ["hello"]

    def test_max_depth_protection(self) -> None:
        """Should not crash on deeply nested structures."""
        value: dict[str, object] = {"v": "found"}
        for _ in range(30):
            value = {"nested": value}
        result = extract_strings((value,))
        # May or may not find "found" (depth limit), but should not crash
        assert isinstance(result, list)

    def test_backward_compat_rules(self) -> None:
        """Canonical import from utils module."""
        from enforcecore.utils import extract_strings as es

        assert es(("x",)) == ["x"]

    def test_backward_compat_network(self) -> None:
        """Canonical import from utils module."""
        from enforcecore.utils import extract_strings as es

        assert es(("x",)) == ["x"]


# ---------------------------------------------------------------------------
# L-2: Unreachable redaction strategy
# ---------------------------------------------------------------------------


class TestL2UnreachableStrategy:
    def test_all_strategies_work(self) -> None:
        """All strategies should produce valid replacements."""
        from unittest.mock import MagicMock, patch

        from enforcecore.core.types import RedactionStrategy

        for strategy in RedactionStrategy:
            if strategy == RedactionStrategy.NER:
                # NER requires presidio + spaCy; mock the engine to verify wiring
                mock_engine = MagicMock()
                mock_engine.analyze.return_value = []
                with (
                    patch("enforcecore.redactor.ner.is_ner_available", return_value=True),
                    patch(
                        "enforcecore.redactor.ner._build_analyzer_engine",
                        return_value=mock_engine,
                    ),
                ):
                    r = Redactor(categories=["email"], strategy=strategy)
                    r.redact("test@example.com")  # must not crash
            else:
                r = Redactor(categories=["email"], strategy=strategy)
                result = r.redact("test@example.com")
                assert result.text != "test@example.com" or strategy == RedactionStrategy.REMOVE


# ---------------------------------------------------------------------------
# M-8: ViolationType members
# ---------------------------------------------------------------------------


class TestM8ViolationTypes:
    def test_rate_limit_type_exists(self) -> None:
        assert hasattr(ViolationType, "RATE_LIMIT")
        assert ViolationType.RATE_LIMIT.value == "rate_limit"

    def test_content_violation_type_exists(self) -> None:
        assert hasattr(ViolationType, "CONTENT_VIOLATION")
        assert ViolationType.CONTENT_VIOLATION.value == "content_violation"


# ---------------------------------------------------------------------------
# Missing exports
# ---------------------------------------------------------------------------


class TestMissingExports:
    pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

    def test_clear_policy_cache_exported(self) -> None:
        from enforcecore import clear_policy_cache

        assert callable(clear_policy_cache)

    def test_policy_models_exported(self) -> None:
        from enforcecore import (
            ContentRulesPolicyConfig,
            NetworkPolicy,
            PIIRedactionConfig,
            PolicyRules,
            RateLimitPolicyConfig,
            ResourceLimits,
        )

        assert ContentRulesPolicyConfig is not None
        assert NetworkPolicy is not None
        assert PIIRedactionConfig is not None
        assert PolicyRules is not None
        assert RateLimitPolicyConfig is not None
        assert ResourceLimits is not None

    def test_eval_helpers_exported(self) -> None:
        from enforcecore import (
            generate_benchmark_report,
            generate_suite_report,
            get_all_scenarios,
            get_scenarios_by_category,
        )

        assert callable(generate_benchmark_report)
        assert callable(generate_suite_report)
        assert callable(get_all_scenarios)
        assert callable(get_scenarios_by_category)

    def test_total_exports_count(self) -> None:
        import enforcecore

        # v1.4.0: 45 Tier 1 symbols (was 36 in v1.3.0; +9 NER + sensitivity)
        assert len(enforcecore.__all__) == 46


# ---------------------------------------------------------------------------
# extract_strings thread safety
# ---------------------------------------------------------------------------


class TestExtractStringsThreadSafety:
    def test_concurrent_extraction(self) -> None:
        """extract_strings should be safe to call from multiple threads."""
        results: list[list[str]] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                r = extract_strings(({"a": "v1", "b": ["v2", "v3"]},))
                results.append(r)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(results) == 10
        for r in results:
            assert set(r) == {"v1", "v2", "v3"}

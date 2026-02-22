# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for custom PII pattern registry."""

from __future__ import annotations

import pytest

from enforcecore.redactor.patterns import CustomPattern, PatternRegistry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_global_registry():
    """Ensure global registry is clean before and after each test."""
    PatternRegistry.clear()
    yield
    PatternRegistry.clear()


@pytest.fixture
def isolated() -> PatternRegistry:
    """A fresh isolated pattern registry."""
    return PatternRegistry()


# ---------------------------------------------------------------------------
# CustomPattern dataclass
# ---------------------------------------------------------------------------


class TestCustomPattern:
    def test_frozen_immutable(self):
        import re

        p = CustomPattern(category="test", regex=re.compile(r"\d+"))
        with pytest.raises(AttributeError):
            p.category = "changed"  # type: ignore[misc]

    def test_fields(self):
        import re

        v = lambda m: True  # noqa: E731
        p = CustomPattern(
            category="emp_id",
            regex=re.compile(r"EMP-\d{6}"),
            placeholder="<EMP_ID>",
            mask="EMP-******",
            validator=v,
        )
        assert p.category == "emp_id"
        assert p.placeholder == "<EMP_ID>"
        assert p.mask == "EMP-******"
        assert p.validator is v


# ---------------------------------------------------------------------------
# Global (class-level) API
# ---------------------------------------------------------------------------


class TestGlobalRegistry:
    def test_register_and_get(self):
        PatternRegistry.register("employee_id", r"EMP-\d{6}")
        p = PatternRegistry.get("employee_id")
        assert p is not None
        assert p.category == "employee_id"

    def test_default_placeholder(self):
        PatternRegistry.register("customer_id", r"CUST-\d{8}")
        p = PatternRegistry.get("customer_id")
        assert p is not None
        assert p.placeholder == "<CUSTOMER_ID>"

    def test_default_mask(self):
        PatternRegistry.register("customer_id", r"CUST-\d{8}")
        p = PatternRegistry.get("customer_id")
        assert p is not None
        assert p.mask == "********"

    def test_custom_placeholder_and_mask(self):
        PatternRegistry.register(
            "mrn",
            r"MRN-\d{8}",
            placeholder="<MEDICAL_RECORD>",
            mask="MRN-########",
        )
        p = PatternRegistry.get("mrn")
        assert p is not None
        assert p.placeholder == "<MEDICAL_RECORD>"
        assert p.mask == "MRN-########"

    def test_register_with_validator(self):
        PatternRegistry.register(
            "ssn_strict",
            r"\d{3}-\d{2}-\d{4}",
            validator=lambda m: not m.startswith("000"),
        )
        p = PatternRegistry.get("ssn_strict")
        assert p is not None
        assert p.validator is not None
        assert p.validator("123-45-6789") is True
        assert p.validator("000-45-6789") is False

    def test_unregister(self):
        PatternRegistry.register("temp", r"TEMP-\d+")
        assert PatternRegistry.unregister("temp") is True
        assert PatternRegistry.get("temp") is None

    def test_unregister_nonexistent(self):
        assert PatternRegistry.unregister("nope") is False

    def test_get_nonexistent(self):
        assert PatternRegistry.get("nope") is None

    def test_get_all(self):
        PatternRegistry.register("a", r"A\d+")
        PatternRegistry.register("b", r"B\d+")
        all_p = PatternRegistry.get_all()
        assert "a" in all_p
        assert "b" in all_p
        assert len(all_p) == 2

    def test_get_all_returns_copy(self):
        PatternRegistry.register("a", r"A\d+")
        all1 = PatternRegistry.get_all()
        all1["injected"] = None  # type: ignore[assignment]
        assert PatternRegistry.get("injected") is None

    def test_categories(self):
        PatternRegistry.register("x", r"X")
        PatternRegistry.register("y", r"Y")
        cats = PatternRegistry.categories()
        assert set(cats) == {"x", "y"}

    def test_clear(self):
        PatternRegistry.register("a", r"A")
        PatternRegistry.register("b", r"B")
        PatternRegistry.clear()
        assert PatternRegistry.count() == 0

    def test_count(self):
        assert PatternRegistry.count() == 0
        PatternRegistry.register("a", r"A")
        assert PatternRegistry.count() == 1
        PatternRegistry.register("b", r"B")
        assert PatternRegistry.count() == 2

    def test_overwrite_existing_category(self):
        PatternRegistry.register("dup", r"OLD")
        PatternRegistry.register("dup", r"NEW")
        p = PatternRegistry.get("dup")
        assert p is not None
        assert p.regex.pattern == "NEW"


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------


class TestGlobalRegistryValidation:
    def test_empty_category_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            PatternRegistry.register("", r"\d+")

    def test_whitespace_category_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            PatternRegistry.register("   ", r"\d+")

    def test_invalid_regex_raises(self):
        with pytest.raises(ValueError, match="Invalid regex"):
            PatternRegistry.register("bad", r"[unclosed")


# ---------------------------------------------------------------------------
# Instance-level (isolated) API
# ---------------------------------------------------------------------------


class TestIsolatedRegistry:
    def test_add_and_get(self, isolated: PatternRegistry):
        isolated.add("emp", r"EMP-\d+")
        patterns = isolated.get_patterns()
        assert "emp" in patterns

    def test_remove(self, isolated: PatternRegistry):
        isolated.add("emp", r"EMP-\d+")
        assert isolated.remove("emp") is True
        assert isolated.pattern_count == 0

    def test_remove_nonexistent(self, isolated: PatternRegistry):
        assert isolated.remove("nope") is False

    def test_list_categories(self, isolated: PatternRegistry):
        isolated.add("a", r"A")
        isolated.add("b", r"B")
        assert set(isolated.list_categories()) == {"a", "b"}

    def test_clear_all(self, isolated: PatternRegistry):
        isolated.add("a", r"A")
        isolated.add("b", r"B")
        isolated.clear_all()
        assert isolated.pattern_count == 0

    def test_pattern_count(self, isolated: PatternRegistry):
        assert isolated.pattern_count == 0
        isolated.add("a", r"A")
        assert isolated.pattern_count == 1

    def test_isolated_from_global(self, isolated: PatternRegistry):
        """Instance registry does not affect the global registry."""
        isolated.add("local", r"L")
        PatternRegistry.register("global_p", r"G")
        assert "local" not in PatternRegistry.get_all()
        assert "global_p" not in isolated.get_patterns()

    def test_validation_empty_category(self, isolated: PatternRegistry):
        with pytest.raises(ValueError, match="cannot be empty"):
            isolated.add("", r"\d+")

    def test_validation_bad_regex(self, isolated: PatternRegistry):
        with pytest.raises(ValueError, match="Invalid regex"):
            isolated.add("bad", r"[unclosed")

    def test_default_placeholder_and_mask(self, isolated: PatternRegistry):
        isolated.add("order", r"ORD-\d+")
        p = isolated.get_patterns()["order"]
        assert p.placeholder == "<ORDER>"
        assert p.mask == "********"

    def test_custom_placeholder_and_mask(self, isolated: PatternRegistry):
        isolated.add(
            "order",
            r"ORD-\d+",
            placeholder="<ORDER_ID>",
            mask="ORD-####",
        )
        p = isolated.get_patterns()["order"]
        assert p.placeholder == "<ORDER_ID>"
        assert p.mask == "ORD-####"

    def test_validator_in_isolated(self, isolated: PatternRegistry):
        isolated.add(
            "pin",
            r"\d{4}",
            validator=lambda m: m != "0000",
        )
        p = isolated.get_patterns()["pin"]
        assert p.validator is not None
        assert p.validator("1234") is True
        assert p.validator("0000") is False


# ---------------------------------------------------------------------------
# Regex matching
# ---------------------------------------------------------------------------


class TestPatternMatching:
    def test_compiled_regex_matches(self):
        PatternRegistry.register("emp", r"EMP-\d{6}")
        p = PatternRegistry.get("emp")
        assert p is not None
        assert p.regex.search("Employee EMP-123456 is active")
        assert not p.regex.search("Employee EMP-12345 is active")

    def test_case_insensitive_regex(self):

        PatternRegistry.register("code", r"(?i)CODE-[A-Z]{4}")
        p = PatternRegistry.get("code")
        assert p is not None
        assert p.regex.search("code-abcd")
        assert p.regex.search("CODE-WXYZ")

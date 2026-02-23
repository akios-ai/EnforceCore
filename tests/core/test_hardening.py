# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.core.hardening — security hardening utilities."""

from __future__ import annotations

import os
import warnings
from unittest.mock import patch

import pytest

from enforcecore.core.hardening import (
    MAX_ENFORCEMENT_DEPTH,
    MAX_INPUT_SIZE_BYTES,
    MAX_TOOL_NAME_LENGTH,
    EnforcementDepthError,
    HardeningError,
    InputTooLargeError,
    InvalidToolNameError,
    _warn_fail_open,
    check_input_size,
    deep_redact,
    enter_enforcement,
    exit_enforcement,
    get_enforcement_chain,
    get_enforcement_depth,
    is_dev_mode,
    validate_tool_name,
)

# ---------------------------------------------------------------------------
# validate_tool_name
# ---------------------------------------------------------------------------


class TestValidateToolName:
    """Tests for validate_tool_name()."""

    def test_valid_simple(self) -> None:
        assert validate_tool_name("search_web") == "search_web"

    def test_valid_dotted(self) -> None:
        assert validate_tool_name("my.tool.v2") == "my.tool.v2"

    def test_valid_hyphens(self) -> None:
        assert validate_tool_name("my-tool") == "my-tool"

    def test_valid_colons(self) -> None:
        assert validate_tool_name("namespace:tool") == "namespace:tool"

    def test_valid_angle_brackets(self) -> None:
        """Python auto-generated names like <lambda> should be valid."""
        assert validate_tool_name("<lambda>") == "<lambda>"

    def test_valid_mixed(self) -> None:
        assert validate_tool_name("ns:my_tool.v2-beta") == "ns:my_tool.v2-beta"

    def test_strips_whitespace(self) -> None:
        assert validate_tool_name("  my_tool  ") == "my_tool"

    def test_empty_raises(self) -> None:
        with pytest.raises(InvalidToolNameError, match="must not be empty"):
            validate_tool_name("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(InvalidToolNameError, match="must not be empty"):
            validate_tool_name("   ")

    def test_too_long_raises(self) -> None:
        name = "a" * (MAX_TOOL_NAME_LENGTH + 1)
        with pytest.raises(InvalidToolNameError, match="exceeds maximum length"):
            validate_tool_name(name)

    def test_max_length_ok(self) -> None:
        name = "a" * MAX_TOOL_NAME_LENGTH
        assert validate_tool_name(name) == name

    def test_invalid_chars_raises(self) -> None:
        with pytest.raises(InvalidToolNameError, match="invalid characters"):
            validate_tool_name("my tool!")

    def test_slash_rejected(self) -> None:
        with pytest.raises(InvalidToolNameError, match="invalid characters"):
            validate_tool_name("path/to/tool")

    def test_semicolon_rejected(self) -> None:
        with pytest.raises(InvalidToolNameError, match="invalid characters"):
            validate_tool_name("tool;drop")

    def test_exception_is_hardening_error(self) -> None:
        with pytest.raises(HardeningError):
            validate_tool_name("")


# ---------------------------------------------------------------------------
# check_input_size
# ---------------------------------------------------------------------------


class TestCheckInputSize:
    """Tests for check_input_size()."""

    def test_small_input_ok(self) -> None:
        size = check_input_size(("hello",), {"key": "value"})
        assert size == len(b"hello") + len(b"value")

    def test_empty_input(self) -> None:
        size = check_input_size((), {})
        assert size == 0

    def test_bytes_counted(self) -> None:
        size = check_input_size((b"data",), {})
        assert size == 4

    def test_non_string_ignored(self) -> None:
        size = check_input_size((42, 3.14, None, True), {"x": [1, 2, 3]})
        assert size == 0

    def test_mixed_types(self) -> None:
        size = check_input_size(("hello", 42, b"world"), {"k": "val"})
        assert size == len(b"hello") + 5 + len(b"val")

    def test_exceeds_limit_raises(self) -> None:
        big = "x" * 200
        with pytest.raises(InputTooLargeError, match="exceeds limit"):
            check_input_size((big,), {}, max_bytes=100)

    def test_min_floor_zero_raises(self) -> None:
        """A-5: max_bytes=0 should raise HardeningError, not silently pass."""
        with pytest.raises(HardeningError, match="below the minimum floor"):
            check_input_size((), {}, max_bytes=0)

    def test_min_floor_negative_raises(self) -> None:
        """A-5: max_bytes=-1 should raise HardeningError."""
        with pytest.raises(HardeningError, match="below the minimum floor"):
            check_input_size((), {}, max_bytes=-1)

    def test_min_floor_63_raises(self) -> None:
        """A-5: max_bytes=63 (just below floor) should raise."""
        with pytest.raises(HardeningError, match="below the minimum floor"):
            check_input_size((), {}, max_bytes=63)

    def test_min_floor_64_ok(self) -> None:
        """A-5: max_bytes=64 (exactly at floor) should work."""
        size = check_input_size(("hello",), {}, max_bytes=64)
        assert size == 5

    def test_exactly_at_limit_ok(self) -> None:
        data = "x" * 100
        size = check_input_size((data,), {}, max_bytes=100)
        assert size == 100

    def test_default_limit_is_10mb(self) -> None:
        assert MAX_INPUT_SIZE_BYTES == 10 * 1024 * 1024

    def test_unicode_counts_utf8_bytes(self) -> None:
        """Multi-byte UTF-8 chars should be counted by byte length."""
        emoji = "\U0001f600"  # 4 bytes in UTF-8
        size = check_input_size((emoji,), {})
        assert size == 4


# ---------------------------------------------------------------------------
# deep_redact
# ---------------------------------------------------------------------------


class TestDeepRedact:
    """Tests for deep_redact()."""

    class _MockResult:
        """Simulate a RedactionResult for testing."""

        def __init__(self, text: str, count: int) -> None:
            self.text = text
            self.count = count

    @staticmethod
    def _mock_redact(text: str) -> TestDeepRedact._MockResult:
        """Replace 'SECRET' with '[REDACTED]'."""
        count = text.count("SECRET")
        return TestDeepRedact._MockResult(
            text=text.replace("SECRET", "[REDACTED]"),
            count=count,
        )

    def test_string_leaf(self) -> None:
        result, count = deep_redact("has SECRET here", self._mock_redact)
        assert result == "has [REDACTED] here"
        assert count == 1

    def test_no_redaction(self) -> None:
        result, count = deep_redact("clean text", self._mock_redact)
        assert result == "clean text"
        assert count == 0

    def test_dict_values(self) -> None:
        data = {"name": "SECRET", "age": 30, "email": "not-SECRET"}
        result, count = deep_redact(data, self._mock_redact)
        assert result["name"] == "[REDACTED]"
        assert result["age"] == 30
        assert result["email"] == "not-[REDACTED]"
        assert count == 2

    def test_nested_dict(self) -> None:
        data = {"outer": {"inner": "SECRET"}}
        result, count = deep_redact(data, self._mock_redact)
        assert result["outer"]["inner"] == "[REDACTED]"
        assert count == 1

    def test_list(self) -> None:
        data = ["SECRET", "clean", "SECRET"]
        result, count = deep_redact(data, self._mock_redact)
        assert result == ["[REDACTED]", "clean", "[REDACTED]"]
        assert count == 2

    def test_tuple(self) -> None:
        data = ("SECRET", "clean")
        result, count = deep_redact(data, self._mock_redact)
        assert result == ("[REDACTED]", "clean")
        assert isinstance(result, tuple)
        assert count == 1

    def test_set(self) -> None:
        data = {"SECRET", "clean"}
        result, count = deep_redact(data, self._mock_redact)
        assert isinstance(result, set)
        assert "[REDACTED]" in result
        assert "clean" in result
        assert count == 1

    def test_deeply_nested(self) -> None:
        data = {"a": [{"b": ("SECRET",)}]}
        result, count = deep_redact(data, self._mock_redact)
        assert result["a"][0]["b"] == ("[REDACTED]",)
        assert count == 1

    def test_max_depth_stops_recursion(self) -> None:
        """Values beyond max_depth are returned unmodified."""
        data = {"level1": {"level2": "SECRET"}}
        result, count = deep_redact(data, self._mock_redact, max_depth=1)
        # At depth 0 we enter the outer dict; at depth 1 we enter inner dict
        # At depth 2 we'd process the string — but max_depth=1 stops us
        assert result["level1"]["level2"] == "SECRET"
        assert count == 0

    def test_non_container_passthrough(self) -> None:
        assert deep_redact(42, self._mock_redact) == (42, 0)
        assert deep_redact(3.14, self._mock_redact) == (3.14, 0)
        assert deep_redact(None, self._mock_redact) == (None, 0)
        assert deep_redact(True, self._mock_redact) == (True, 0)


# ---------------------------------------------------------------------------
# Enforcement scope (enter/exit/depth/chain)
# ---------------------------------------------------------------------------


class TestEnforcementScope:
    """Tests for enforcement scope tracking."""

    def setup_method(self) -> None:
        """Reset scope before each test."""
        # Force-clear the context var
        while get_enforcement_depth() > 0:
            exit_enforcement()

    def test_initial_depth_zero(self) -> None:
        assert get_enforcement_depth() == 0

    def test_initial_chain_empty(self) -> None:
        assert get_enforcement_chain() == []

    def test_enter_increments_depth(self) -> None:
        depth = enter_enforcement("tool_a")
        assert depth == 1
        assert get_enforcement_depth() == 1
        exit_enforcement()

    def test_enter_exit_returns_to_zero(self) -> None:
        enter_enforcement("tool_a")
        exit_enforcement()
        assert get_enforcement_depth() == 0

    def test_nested_depth(self) -> None:
        enter_enforcement("tool_a")
        enter_enforcement("tool_b")
        assert get_enforcement_depth() == 2
        exit_enforcement()
        assert get_enforcement_depth() == 1
        exit_enforcement()
        assert get_enforcement_depth() == 0

    def test_chain_tracks_tools(self) -> None:
        enter_enforcement("tool_a")
        enter_enforcement("tool_b")
        assert get_enforcement_chain() == ["tool_a", "tool_b"]
        exit_enforcement()
        assert get_enforcement_chain() == ["tool_a"]
        exit_enforcement()
        assert get_enforcement_chain() == []

    def test_max_depth_exceeded_raises(self) -> None:
        for i in range(MAX_ENFORCEMENT_DEPTH):
            enter_enforcement(f"tool_{i}")

        with pytest.raises(EnforcementDepthError, match="exceeds maximum"):
            enter_enforcement("one_too_many")

        # Clean up
        for _ in range(MAX_ENFORCEMENT_DEPTH + 1):
            exit_enforcement()

    def test_custom_max_depth(self) -> None:
        enter_enforcement("a", max_depth=2)
        enter_enforcement("b", max_depth=2)
        with pytest.raises(EnforcementDepthError):
            enter_enforcement("c", max_depth=2)
        exit_enforcement()
        exit_enforcement()
        exit_enforcement()

    def test_exit_without_enter_is_safe(self) -> None:
        """exit_enforcement() when no scope exists should not raise."""
        exit_enforcement()  # Should be a no-op

    def test_chain_returns_copy(self) -> None:
        enter_enforcement("tool_a")
        chain = get_enforcement_chain()
        chain.append("tampered")
        assert get_enforcement_chain() == ["tool_a"]
        exit_enforcement()


# ---------------------------------------------------------------------------
# Dev mode and fail-open warning
# ---------------------------------------------------------------------------


class TestDevMode:
    """Tests for is_dev_mode() and _warn_fail_open()."""

    def test_dev_mode_off_by_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            assert is_dev_mode() is False

    def test_dev_mode_on_with_1(self) -> None:
        with patch.dict(os.environ, {"ENFORCECORE_DEV_MODE": "1"}):
            assert is_dev_mode() is True

    def test_dev_mode_on_with_true(self) -> None:
        with patch.dict(os.environ, {"ENFORCECORE_DEV_MODE": "true"}):
            assert is_dev_mode() is True

    def test_dev_mode_on_with_yes(self) -> None:
        with patch.dict(os.environ, {"ENFORCECORE_DEV_MODE": "yes"}):
            assert is_dev_mode() is True

    def test_dev_mode_off_with_0(self) -> None:
        with patch.dict(os.environ, {"ENFORCECORE_DEV_MODE": "0"}):
            assert is_dev_mode() is False

    def test_dev_mode_case_insensitive(self) -> None:
        with patch.dict(os.environ, {"ENFORCECORE_DEV_MODE": "TRUE"}):
            assert is_dev_mode() is True

    def test_warn_fail_open_emits_warning(self) -> None:
        """Without dev mode, _warn_fail_open should emit RuntimeWarning."""
        with (
            patch.dict(os.environ, {}, clear=True),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always")
            _warn_fail_open()
            runtime_warns = [w for w in caught if issubclass(w.category, RuntimeWarning)]
            assert len(runtime_warns) >= 1
            assert "SECURITY WARNING" in str(runtime_warns[0].message)

    def test_warn_fail_open_no_warning_in_dev_mode(self) -> None:
        """In dev mode, no RuntimeWarning should be emitted."""
        with (
            patch.dict(os.environ, {"ENFORCECORE_DEV_MODE": "1"}),
            warnings.catch_warnings(record=True) as caught,
        ):
            warnings.simplefilter("always")
            _warn_fail_open()
            runtime_warns = [w for w in caught if issubclass(w.category, RuntimeWarning)]
            assert len(runtime_warns) == 0

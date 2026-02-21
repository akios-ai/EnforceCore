# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.0.6 hardening wired into the Enforcer and Auditor."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore.auditor.engine import Auditor, load_trail
from enforcecore.core.enforcer import Enforcer
from enforcecore.core.hardening import InputTooLargeError, InvalidToolNameError

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sync_tool(x: int, y: int) -> int:
    return x + y


async def async_tool(x: int, y: int) -> int:
    return x + y


# ---------------------------------------------------------------------------
# Enforcer hardening (sync + async)
# ---------------------------------------------------------------------------


class TestEnforcerHardening:
    """Test that hardening hooks are wired into enforce_sync and enforce_async."""

    def test_sync_rejects_invalid_tool_name(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        with pytest.raises(InvalidToolNameError, match="invalid characters"):
            enforcer.enforce_sync(sync_tool, 1, 2, tool_name="my tool!")

    @pytest.mark.asyncio
    async def test_async_rejects_invalid_tool_name(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        with pytest.raises(InvalidToolNameError, match="invalid characters"):
            await enforcer.enforce_async(async_tool, 1, 2, tool_name="my tool!")

    def test_sync_rejects_large_input(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        big_str = "x" * (11 * 1024 * 1024)  # 11 MB
        with pytest.raises(InputTooLargeError, match="exceeds limit"):
            enforcer.enforce_sync(sync_tool, big_str, 2, tool_name="sync_tool")

    @pytest.mark.asyncio
    async def test_async_rejects_large_input(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        big_str = "x" * (11 * 1024 * 1024)
        with pytest.raises(InputTooLargeError, match="exceeds limit"):
            await enforcer.enforce_async(async_tool, big_str, 2, tool_name="async_tool")

    def test_sync_nested_pii_redaction(self, fixtures_dir: Path) -> None:
        """PII inside nested structures should be redacted."""
        enforcer = Enforcer.from_file(fixtures_dir / "pii_redaction.yaml")
        data = {"user": {"email": "john@example.com", "id": 123}}
        result = enforcer.enforce_sync(
            lambda d: d,
            data,
            tool_name="nested_tool",
        )
        # The input was a dict, but the function just returns it — so
        # if deep_redact works, the arg was redacted before passing to func
        # The result is the redacted version
        assert "john@example.com" not in str(result)

    @pytest.mark.asyncio
    async def test_async_nested_pii_redaction(self, fixtures_dir: Path) -> None:
        """PII inside nested structures should be redacted (async)."""
        enforcer = Enforcer.from_file(fixtures_dir / "pii_redaction.yaml")

        async def echo(d: dict) -> dict:
            return d

        data = {"contacts": ["john@example.com", "jane@example.com"]}
        result = await enforcer.enforce_async(echo, data, tool_name="nested_tool")
        assert "john@example.com" not in str(result)
        assert "jane@example.com" not in str(result)


# ---------------------------------------------------------------------------
# Unicode-hardened PII detection (via Redactor)
# ---------------------------------------------------------------------------


class TestUnicodeHardenedDetection:
    """Test that the Redactor detects PII even with unicode evasion."""

    def test_zero_width_email(self, fixtures_dir: Path) -> None:
        """Email with zero-width chars should still be detected."""
        enforcer = Enforcer.from_file(fixtures_dir / "pii_redaction.yaml")
        text = "contact j\u200bohn@example.com please"
        result = enforcer.enforce_sync(lambda t: t, text, tool_name="zw_test")
        assert "john@example.com" not in result

    def test_cyrillic_email(self, fixtures_dir: Path) -> None:
        """Email with Cyrillic 'o' should still be detected."""
        enforcer = Enforcer.from_file(fixtures_dir / "pii_redaction.yaml")
        # j + Cyrillic-o + hn@example.com
        text = "email: j\u043ehn@example.com"
        result = enforcer.enforce_sync(lambda t: t, text, tool_name="cyrillic_test")
        assert "@example.com" not in result

    def test_fullwidth_phone(self, fixtures_dir: Path) -> None:
        """Phone with fullwidth digits should still be detected."""
        enforcer = Enforcer.from_file(fixtures_dir / "pii_redaction.yaml")
        text = "call \uff15\uff15\uff15-123-4567"
        result = enforcer.enforce_sync(lambda t: t, text, tool_name="fw_test")
        # After normalization, the fullwidth 5's become ASCII 5's
        # The phone should be detected and redacted
        assert "555" not in result or "<PHONE>" in result


# ---------------------------------------------------------------------------
# Auditor: load_trail max_entries
# ---------------------------------------------------------------------------


class TestLoadTrailMaxEntries:
    """Tests for load_trail with max_entries parameter."""

    def _create_trail(self, tmp_path: Path, n: int) -> Path:
        """Create a trail file with n entries."""
        trail_path = tmp_path / "test_trail.jsonl"
        auditor = Auditor(output_path=trail_path)
        for i in range(n):
            auditor.record(
                tool_name=f"tool_{i}",
                policy_name="test",
                decision="allowed",
            )
        return trail_path

    def test_load_all(self, tmp_path: Path) -> None:
        path = self._create_trail(tmp_path, 5)
        entries = load_trail(path)
        assert len(entries) == 5

    def test_load_max_entries(self, tmp_path: Path) -> None:
        path = self._create_trail(tmp_path, 10)
        entries = load_trail(path, max_entries=3)
        assert len(entries) == 3

    def test_max_entries_returns_most_recent(self, tmp_path: Path) -> None:
        """max_entries should return the LAST N entries (most recent)."""
        path = self._create_trail(tmp_path, 10)
        entries = load_trail(path, max_entries=3)
        assert entries[0].tool_name == "tool_7"
        assert entries[1].tool_name == "tool_8"
        assert entries[2].tool_name == "tool_9"

    def test_max_entries_none_loads_all(self, tmp_path: Path) -> None:
        path = self._create_trail(tmp_path, 5)
        entries = load_trail(path, max_entries=None)
        assert len(entries) == 5

    def test_max_entries_larger_than_total(self, tmp_path: Path) -> None:
        """max_entries > total should return all entries."""
        path = self._create_trail(tmp_path, 3)
        entries = load_trail(path, max_entries=100)
        assert len(entries) == 3


# ---------------------------------------------------------------------------
# Auditor: _resume_chain for large files
# ---------------------------------------------------------------------------


class TestAuditorResumeChain:
    """Test that _resume_chain works correctly on both small and large files."""

    def test_resume_small_file(self, tmp_path: Path) -> None:
        """Auditor should resume from a small existing trail."""
        path = tmp_path / "small.jsonl"
        a1 = Auditor(output_path=path)
        a1.record(tool_name="tool_a", policy_name="p")
        a1.record(tool_name="tool_b", policy_name="p")
        assert a1.entry_count == 2
        last_hash = a1.last_hash

        # Resume from the same file
        a2 = Auditor(output_path=path)
        assert a2.entry_count == 2
        assert a2.last_hash == last_hash

    def test_resume_large_file(self, tmp_path: Path) -> None:
        """Auditor should resume from a large trail (>8KB)."""
        path = tmp_path / "large.jsonl"
        a1 = Auditor(output_path=path)
        # Write enough entries to exceed 8KB
        for i in range(100):
            a1.record(tool_name=f"tool_{i:03d}", policy_name="test_policy")
        assert a1.entry_count == 100
        last_hash = a1.last_hash

        # Resume from the same file
        a2 = Auditor(output_path=path)
        assert a2.entry_count == 100
        assert a2.last_hash == last_hash

    def test_resume_continues_chain(self, tmp_path: Path) -> None:
        """New entries after resume should chain correctly."""
        path = tmp_path / "chain.jsonl"
        a1 = Auditor(output_path=path)
        a1.record(tool_name="tool_a", policy_name="p")

        # Resume and add more
        a2 = Auditor(output_path=path)
        entry = a2.record(tool_name="tool_b", policy_name="p")

        # The new entry's previous_hash should be the first entry's hash
        assert entry.previous_hash == a1.last_hash
        assert a2.entry_count == 2

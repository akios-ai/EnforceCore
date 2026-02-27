# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for coverage gaps in JSONL and SQLite backends.

Covers the untested lines in:
- enforcecore/auditstore/backends/jsonl.py:
    - get_entry() when file doesn't exist (return None)
    - get_entry() ID not found (return None after loop)
    - list_entries() filter combinations (policy_name, tool_name, decision, time range)
    - list_entries() empty file
    - verify_chain() empty entries list
    - verify_entry() stored entry not found
    - export() unsupported format
- enforcecore/auditstore/backends/sqlite.py:
    - verify_chain() empty chain (return True)
    - verify_chain() missing row in merkle_chain (return False)
    - verify_chain() hash mismatch (return False)
    - verify_chain() parent hash mismatch (return False)
    - verify_entry() entry not found (return False)
    - export() unsupported format
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from enforcecore.auditstore.backends.jsonl import JSONLBackend
from enforcecore.auditstore.backends.sqlite import SQLiteBackend
from enforcecore.auditstore.core import AuditEntry

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(tool_name: str = "search", decision: str = "allowed") -> AuditEntry:
    return AuditEntry.create(
        policy_name="test-policy",
        policy_version="1.0",
        tool_name=tool_name,
        decision=decision,
        call_duration_ms=1.0,
        enforcement_overhead_ms=0.1,
    )


# ---------------------------------------------------------------------------
# JSONL backend coverage gaps
# ---------------------------------------------------------------------------


class TestJSONLBackendGaps:
    def test_get_entry_file_not_exists_returns_none(self, tmp_path) -> None:
        """get_entry() returns None when the file doesn't exist yet."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        result = backend.get_entry("nonexistent-id")
        assert result is None

    def test_get_entry_id_not_found_returns_none(self, tmp_path) -> None:
        """get_entry() returns None when ID is not in the file."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        backend.record(_make_entry(tool_name="search"))
        result = backend.get_entry("does-not-exist")
        assert result is None

    def test_list_entries_file_not_exists_returns_empty(self, tmp_path) -> None:
        """list_entries() returns [] when file doesn't exist."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        assert backend.list_entries() == []

    def test_list_entries_filter_by_policy_name(self, tmp_path) -> None:
        """list_entries(policy_name=...) only returns matching entries."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        e1 = _make_entry(tool_name="a")
        e2 = _make_entry(tool_name="b")
        e2.policy_name = "other-policy"

        backend.record(e1)
        backend.record(e2)

        results = backend.list_entries(policy_name="test-policy")
        assert len(results) == 1
        assert results[0].tool_name == "a"

    def test_list_entries_filter_by_tool_name(self, tmp_path) -> None:
        """list_entries(tool_name=...) filters correctly."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        backend.record(_make_entry(tool_name="search"))
        backend.record(_make_entry(tool_name="delete"))

        results = backend.list_entries(tool_name="delete")
        assert len(results) == 1
        assert results[0].tool_name == "delete"

    def test_list_entries_filter_by_decision(self, tmp_path) -> None:
        """list_entries(decision=...) filters correctly."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        backend.record(_make_entry(decision="allowed"))
        backend.record(_make_entry(decision="blocked"))

        results = backend.list_entries(decision="blocked")
        assert len(results) == 1
        assert results[0].decision == "blocked"

    def test_list_entries_filter_by_start_time(self, tmp_path) -> None:
        """list_entries(start_time=...) filters by timestamp."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)

        # Record first entry
        backend.record(_make_entry(tool_name="early"))
        cutoff = datetime.now(tz=UTC)

        # Record second entry (after cutoff)
        backend.record(_make_entry(tool_name="late"))

        results = backend.list_entries(start_time=cutoff)
        tool_names = {e.tool_name for e in results}
        # late should be included; early may or may not depending on timing
        assert "late" in tool_names

    def test_list_entries_filter_by_end_time(self, tmp_path) -> None:
        """list_entries(end_time=...) filters by timestamp."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        backend.record(_make_entry(tool_name="before"))
        cutoff = datetime.now(tz=UTC)
        backend.record(_make_entry(tool_name="after"))

        results = backend.list_entries(end_time=cutoff)
        tool_names = {e.tool_name for e in results}
        assert "after" not in tool_names

    def test_list_entries_offset_and_limit(self, tmp_path) -> None:
        """list_entries pagination works correctly."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        for i in range(5):
            backend.record(_make_entry(tool_name=f"tool_{i}"))

        page1 = backend.list_entries(limit=2, offset=0)
        page2 = backend.list_entries(limit=2, offset=2)

        assert len(page1) == 2
        assert len(page2) == 2
        # No overlap
        ids1 = {e.entry_id for e in page1}
        ids2 = {e.entry_id for e in page2}
        assert ids1.isdisjoint(ids2)

    def test_verify_chain_empty_file_returns_true(self, tmp_path) -> None:
        """verify_chain() returns True for empty / non-existent file."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        assert backend.verify_chain() is True

    def test_verify_chain_empty_entries_returns_true(self, tmp_path) -> None:
        """verify_chain() returns True when file exists but has no entries."""
        path = str(tmp_path / "audit.jsonl")
        # Create empty file
        open(path, "w").close()
        backend = JSONLBackend(path)
        assert backend.verify_chain() is True

    def test_verify_entry_not_in_store_returns_false(self, tmp_path) -> None:
        """verify_entry() returns False if entry_id is not stored."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        entry = _make_entry()
        # Don't record it — just verify
        assert backend.verify_entry(entry) is False

    def test_export_unsupported_format_raises(self, tmp_path) -> None:
        """export() raises ValueError for unknown format (file must exist)."""
        path = str(tmp_path / "audit.jsonl")
        backend = JSONLBackend(path)
        # Record an entry so the file exists
        backend.record(_make_entry())
        with pytest.raises(ValueError, match="Unsupported export format"):
            backend.export(format="xml")

    def test_export_empty_file_returns_empty_string(self, tmp_path) -> None:
        """export() returns empty string when file doesn't exist."""
        backend = JSONLBackend(str(tmp_path / "nonexistent.jsonl"))
        result = backend.export(format="jsonl")
        assert result == ""


# ---------------------------------------------------------------------------
# SQLite backend coverage gaps
# ---------------------------------------------------------------------------


class TestSQLiteBackendVerifyChainGaps:
    def test_verify_chain_empty_db_returns_true(self, tmp_path) -> None:
        """verify_chain() returns True for an empty database."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        result = backend.verify_chain()
        assert result is True

    def test_verify_chain_valid_single_entry(self, tmp_path) -> None:
        """verify_chain() returns True for a single valid entry."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        backend.record(_make_entry())
        assert backend.verify_chain() is True

    def test_verify_chain_valid_multi_entry(self, tmp_path) -> None:
        """verify_chain() returns True for a valid multi-entry chain."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        for i in range(5):
            backend.record(_make_entry(tool_name=f"tool_{i}"))
        assert backend.verify_chain() is True

    def test_verify_chain_hash_mismatch_returns_false(self, tmp_path) -> None:
        """verify_chain() returns False when a stored hash doesn't match."""
        import sqlite3

        db_path = str(tmp_path / "audit.db")
        backend = SQLiteBackend(db_path)
        for _ in range(3):
            backend.record(_make_entry())

        # Corrupt the merkle hash of the first entry in the DB
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE audit_entries SET merkle_hash = 'aaaa' WHERE chain_index = 0")
        conn.execute("UPDATE merkle_chain SET merkle_hash = 'aaaa' WHERE chain_index = 0")
        conn.commit()
        conn.close()

        assert backend.verify_chain() is False

    def test_verify_chain_parent_hash_mismatch_returns_false(self, tmp_path) -> None:
        """verify_chain() returns False when parent_hash chain is broken."""
        import sqlite3

        db_path = str(tmp_path / "audit.db")
        backend = SQLiteBackend(db_path)
        for _ in range(3):
            backend.record(_make_entry())

        # Corrupt the parent_hash stored in the second entry's chain row
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE merkle_chain SET parent_hash = 'deadbeef' WHERE chain_index = 1")
        conn.commit()
        conn.close()

        assert backend.verify_chain() is False

    def test_verify_chain_missing_row_returns_false(self, tmp_path) -> None:
        """verify_chain() returns False when a chain row is missing."""
        import sqlite3

        db_path = str(tmp_path / "audit.db")
        backend = SQLiteBackend(db_path)
        for _ in range(3):
            backend.record(_make_entry())

        # Delete entry at chain_index=1 from merkle_chain
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM merkle_chain WHERE chain_index = 1")
        conn.commit()
        conn.close()

        assert backend.verify_chain() is False

    def test_verify_entry_not_stored_returns_false(self, tmp_path) -> None:
        """verify_entry() returns False for an entry not in the database."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        entry = _make_entry()
        entry.merkle_hash = "a" * 64
        assert backend.verify_entry(entry) is False

    def test_verify_entry_stored_valid_returns_true(self, tmp_path) -> None:
        """verify_entry() returns True for a correctly stored entry."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        entry = _make_entry()
        recorded = backend.record(entry)
        assert backend.verify_entry(recorded) is True

    def test_export_unsupported_format_raises(self, tmp_path) -> None:
        """export() raises ValueError for unknown formats."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        with pytest.raises(ValueError, match="Unsupported export format"):
            backend.export(format="csv")

    def test_export_jsonl_format(self, tmp_path) -> None:
        """export(format='jsonl') returns JSONL string of all entries."""
        import json

        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        for i in range(3):
            backend.record(_make_entry(tool_name=f"tool_{i}"))

        result = backend.export(format="jsonl")
        lines = [row for row in result.strip().split("\n") if row]
        assert len(lines) == 3
        for line in lines:
            data = json.loads(line)
            assert "entry_id" in data

    def test_list_entries_filter_by_decision(self, tmp_path) -> None:
        """list_entries() decision filter works in SQLite backend."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        backend.record(_make_entry(decision="allowed"))
        backend.record(_make_entry(decision="blocked"))

        results = backend.list_entries(decision="blocked")
        assert len(results) == 1
        assert results[0].decision == "blocked"

    def test_list_entries_time_range(self, tmp_path) -> None:
        """list_entries() time range filtering works."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        backend.record(_make_entry(tool_name="first"))
        start = datetime.now(tz=UTC)
        backend.record(_make_entry(tool_name="second"))

        results = backend.list_entries(start_time=start)
        tool_names = {e.tool_name for e in results}
        assert "second" in tool_names

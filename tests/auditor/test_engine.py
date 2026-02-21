# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Merkle-chained audit trail engine."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from enforcecore.auditor.engine import (
    AuditEntry,
    Auditor,
    VerificationResult,
    load_trail,
    verify_trail,
)
from enforcecore.core.types import AuditError

if TYPE_CHECKING:
    from pathlib import Path


# =========================================================================
# AuditEntry unit tests
# =========================================================================


class TestAuditEntry:
    """AuditEntry dataclass and hashing."""

    def test_default_fields(self) -> None:
        entry = AuditEntry()
        assert entry.entry_id  # UUID generated
        assert entry.timestamp  # Timestamp generated
        assert entry.previous_hash == ""
        assert entry.entry_hash == ""
        assert entry.decision == "allowed"

    def test_seal_computes_hash(self) -> None:
        entry = AuditEntry(tool_name="search", policy_name="strict")
        assert entry.entry_hash == ""
        entry.seal()
        assert entry.entry_hash != ""
        assert len(entry.entry_hash) == 64  # SHA-256 hex

    def test_hash_is_deterministic(self) -> None:
        """Same content produces the same hash."""
        e1 = AuditEntry(
            entry_id="fixed-id",
            call_id="call-1",
            timestamp="2026-01-01T00:00:00",
            tool_name="test",
            policy_name="p",
        )
        e2 = AuditEntry(
            entry_id="fixed-id",
            call_id="call-1",
            timestamp="2026-01-01T00:00:00",
            tool_name="test",
            policy_name="p",
        )
        assert e1.compute_hash() == e2.compute_hash()

    def test_hash_changes_with_content(self) -> None:
        """Different content produces different hashes."""
        e1 = AuditEntry(tool_name="a", entry_id="x", timestamp="t")
        e2 = AuditEntry(tool_name="b", entry_id="x", timestamp="t")
        assert e1.compute_hash() != e2.compute_hash()

    def test_hash_excludes_entry_hash_field(self) -> None:
        """The entry_hash field itself is not included in the hash."""
        entry = AuditEntry(entry_id="id", timestamp="t", tool_name="x", policy_name="p")
        entry.entry_hash = "garbage"
        h = entry.compute_hash()
        entry.entry_hash = "other-garbage"
        assert entry.compute_hash() == h

    def test_hash_includes_previous_hash(self) -> None:
        """Changing previous_hash changes the computed hash (Merkle chain)."""
        e1 = AuditEntry(entry_id="id", timestamp="t", previous_hash="aaa")
        e2 = AuditEntry(entry_id="id", timestamp="t", previous_hash="bbb")
        assert e1.compute_hash() != e2.compute_hash()

    def test_seal_returns_self(self) -> None:
        entry = AuditEntry()
        result = entry.seal()
        assert result is entry

    def test_to_dict(self) -> None:
        entry = AuditEntry(tool_name="test", policy_name="p")
        d = entry.to_dict()
        assert isinstance(d, dict)
        assert d["tool_name"] == "test"
        assert d["policy_name"] == "p"
        assert "entry_id" in d

    def test_from_dict(self) -> None:
        original = AuditEntry(tool_name="search", decision="blocked")
        original.seal()
        d = original.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.tool_name == "search"
        assert restored.decision == "blocked"
        assert restored.entry_hash == original.entry_hash

    def test_from_dict_ignores_unknown_keys(self) -> None:
        """Extra keys in the dict are ignored."""
        d = {"tool_name": "x", "unknown_field": 42, "entry_id": "id", "timestamp": "t"}
        entry = AuditEntry.from_dict(d)
        assert entry.tool_name == "x"

    def test_to_json(self) -> None:
        entry = AuditEntry(tool_name="test")
        entry.seal()
        line = entry.to_json()
        parsed = json.loads(line)
        assert parsed["tool_name"] == "test"
        assert parsed["entry_hash"] == entry.entry_hash


# =========================================================================
# Auditor — writing entries
# =========================================================================


class TestAuditor:
    """Auditor JSONL writer and Merkle chain."""

    def test_creates_file(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="test", policy_name="p")
        assert audit_file.exists()

    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "deep" / "nested" / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="test", policy_name="p")
        assert audit_file.exists()

    def test_single_entry(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        entry = auditor.record(tool_name="search", policy_name="strict")
        assert entry.entry_hash != ""
        assert entry.previous_hash == ""
        assert entry.tool_name == "search"
        assert auditor.entry_count == 1

    def test_chain_links(self, tmp_path: Path) -> None:
        """Each entry's previous_hash is the hash of the prior entry."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        e1 = auditor.record(tool_name="tool1", policy_name="p")
        e2 = auditor.record(tool_name="tool2", policy_name="p")
        e3 = auditor.record(tool_name="tool3", policy_name="p")

        assert e1.previous_hash == ""
        assert e2.previous_hash == e1.entry_hash
        assert e3.previous_hash == e2.entry_hash

    def test_multiple_entries_written(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        for i in range(5):
            auditor.record(tool_name=f"tool_{i}", policy_name="p")

        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 5
        assert auditor.entry_count == 5

    def test_last_hash_updated(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        assert auditor.last_hash == ""
        e1 = auditor.record(tool_name="a", policy_name="p")
        assert auditor.last_hash == e1.entry_hash
        e2 = auditor.record(tool_name="b", policy_name="p")
        assert auditor.last_hash == e2.entry_hash

    def test_output_path_property(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        assert auditor.output_path == audit_file

    def test_record_with_all_fields(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        entry = auditor.record(
            tool_name="search",
            policy_name="strict",
            policy_version="2.0",
            decision="blocked",
            call_id="my-call-id",
            violation_type="tool_denied",
            violation_reason="not in allowed list",
            overhead_ms=1.5,
            call_duration_ms=0.0,
            input_redactions=3,
            output_redactions=1,
        )
        assert entry.decision == "blocked"
        assert entry.violation_type == "tool_denied"
        assert entry.input_redactions == 3
        assert entry.policy_version == "2.0"

    def test_jsonl_format(self, tmp_path: Path) -> None:
        """Each line is valid JSON."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="a", policy_name="p")
        auditor.record(tool_name="b", policy_name="p")

        for line in audit_file.read_text().strip().split("\n"):
            data = json.loads(line)
            assert "entry_hash" in data
            assert "previous_hash" in data


# =========================================================================
# Resume chain from existing file
# =========================================================================


class TestAuditorResume:
    """Resuming the Merkle chain from an existing file."""

    def test_resume_chain(self, tmp_path: Path) -> None:
        """New Auditor picks up where the old one left off."""
        audit_file = tmp_path / "trail.jsonl"

        # First session
        a1 = Auditor(output_path=audit_file)
        a1.record(tool_name="tool1", policy_name="p")
        e2 = a1.record(tool_name="tool2", policy_name="p")

        # Second session — new Auditor, same file
        a2 = Auditor(output_path=audit_file)
        assert a2.last_hash == e2.entry_hash
        assert a2.entry_count == 2

        e3 = a2.record(tool_name="tool3", policy_name="p")
        assert e3.previous_hash == e2.entry_hash

    def test_resume_empty_file(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        audit_file.write_text("")
        auditor = Auditor(output_path=audit_file)
        assert auditor.last_hash == ""
        assert auditor.entry_count == 0

    def test_resume_nonexistent_file(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "nonexistent.jsonl"
        auditor = Auditor(output_path=audit_file)
        assert auditor.last_hash == ""
        assert auditor.entry_count == 0

    def test_resume_corrupt_file_raises(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        audit_file.write_text("this is not json\n")
        with pytest.raises(AuditError, match="Failed to resume"):
            Auditor(output_path=audit_file)


# =========================================================================
# Verification
# =========================================================================


class TestVerifyTrail:
    """Trail verification — Merkle chain integrity checking."""

    def test_valid_trail(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        for i in range(10):
            auditor.record(tool_name=f"tool_{i}", policy_name="p")

        result = verify_trail(audit_file)
        assert result.is_valid is True
        assert result.chain_intact is True
        assert result.total_entries == 10
        assert result.entries_checked == 10
        assert result.error_count == 0
        assert result.root_hash != ""
        assert result.head_hash != ""
        assert result.root_hash != result.head_hash  # Different entries

    def test_empty_file_is_valid(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        audit_file.write_text("")
        result = verify_trail(audit_file)
        assert result.is_valid is True
        assert result.total_entries == 0

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        result = verify_trail(tmp_path / "nope.jsonl")
        assert result.is_valid is False
        assert "not found" in result.errors[0]

    def test_tampered_entry_detected(self, tmp_path: Path) -> None:
        """Modifying an entry's content breaks its hash."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="tool1", policy_name="p")
        auditor.record(tool_name="tool2", policy_name="p")
        auditor.record(tool_name="tool3", policy_name="p")

        # Tamper with line 2 — change the tool name
        lines = audit_file.read_text().strip().split("\n")
        data = json.loads(lines[1])
        data["tool_name"] = "HACKED"
        lines[1] = json.dumps(data, sort_keys=True, separators=(",", ":"))
        audit_file.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_file)
        assert result.is_valid is False
        assert result.chain_intact is False
        assert any("hash mismatch" in e for e in result.errors)

    def test_deleted_entry_detected(self, tmp_path: Path) -> None:
        """Removing an entry breaks the chain linkage."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="tool1", policy_name="p")
        auditor.record(tool_name="tool2", policy_name="p")
        auditor.record(tool_name="tool3", policy_name="p")

        # Delete line 2
        lines = audit_file.read_text().strip().split("\n")
        del lines[1]
        audit_file.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_file)
        assert result.is_valid is False
        assert result.chain_intact is False
        assert any("chain broken" in e for e in result.errors)

    def test_inserted_entry_detected(self, tmp_path: Path) -> None:
        """Inserting a fake entry breaks the chain."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="tool1", policy_name="p")
        auditor.record(tool_name="tool2", policy_name="p")

        # Insert a fake entry between them
        lines = audit_file.read_text().strip().split("\n")
        fake = AuditEntry(tool_name="FAKE", policy_name="evil")
        fake.seal()
        lines.insert(1, fake.to_json())
        audit_file.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_file)
        assert result.is_valid is False

    def test_reordered_entries_detected(self, tmp_path: Path) -> None:
        """Swapping entry order breaks the chain."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="tool1", policy_name="p")
        auditor.record(tool_name="tool2", policy_name="p")
        auditor.record(tool_name="tool3", policy_name="p")

        # Swap lines 1 and 2
        lines = audit_file.read_text().strip().split("\n")
        lines[1], lines[2] = lines[2], lines[1]
        audit_file.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_file)
        assert result.is_valid is False

    def test_single_entry_trail(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        e = auditor.record(tool_name="only", policy_name="p")

        result = verify_trail(audit_file)
        assert result.is_valid is True
        assert result.root_hash == e.entry_hash
        assert result.head_hash == e.entry_hash

    def test_invalid_json_line(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        audit_file.write_text('{"valid": true}\nnot json\n')
        result = verify_trail(audit_file)
        assert result.is_valid is False
        assert any("invalid JSON" in e for e in result.errors)

    def test_root_and_head_hash(self, tmp_path: Path) -> None:
        """Root hash is first entry, head hash is last entry."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        e1 = auditor.record(tool_name="first", policy_name="p")
        _e2 = auditor.record(tool_name="middle", policy_name="p")
        e3 = auditor.record(tool_name="last", policy_name="p")

        result = verify_trail(audit_file)
        assert result.root_hash == e1.entry_hash
        assert result.head_hash == e3.entry_hash


# =========================================================================
# VerificationResult
# =========================================================================


class TestVerificationResult:
    """VerificationResult properties."""

    def test_defaults(self) -> None:
        r = VerificationResult()
        assert r.is_valid is True
        assert r.chain_intact is True
        assert r.error_count == 0

    def test_error_count(self) -> None:
        r = VerificationResult(errors=["e1", "e2"])
        assert r.error_count == 2


# =========================================================================
# load_trail
# =========================================================================


class TestLoadTrail:
    """Loading entries from a trail file."""

    def test_load_entries(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="a", policy_name="p")
        auditor.record(tool_name="b", policy_name="p")
        auditor.record(tool_name="c", policy_name="p")

        entries = load_trail(audit_file)
        assert len(entries) == 3
        assert entries[0].tool_name == "a"
        assert entries[1].tool_name == "b"
        assert entries[2].tool_name == "c"

    def test_load_nonexistent_raises(self, tmp_path: Path) -> None:
        with pytest.raises(AuditError, match="not found"):
            load_trail(tmp_path / "nope.jsonl")

    def test_load_corrupt_raises(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        audit_file.write_text("not json\n")
        with pytest.raises(AuditError, match="Invalid entry"):
            load_trail(audit_file)

    def test_load_empty_file(self, tmp_path: Path) -> None:
        audit_file = tmp_path / "trail.jsonl"
        audit_file.write_text("")
        entries = load_trail(audit_file)
        assert entries == []


# =========================================================================
# Cross-session continuity
# =========================================================================


class TestCrossSession:
    """Verify chain integrity across multiple Auditor sessions."""

    def test_multi_session_chain_verifies(self, tmp_path: Path) -> None:
        """Write across 3 sessions, verify the entire chain."""
        audit_file = tmp_path / "trail.jsonl"

        # Session 1
        a1 = Auditor(output_path=audit_file)
        a1.record(tool_name="s1_tool1", policy_name="p")
        a1.record(tool_name="s1_tool2", policy_name="p")

        # Session 2
        a2 = Auditor(output_path=audit_file)
        a2.record(tool_name="s2_tool1", policy_name="p")

        # Session 3
        a3 = Auditor(output_path=audit_file)
        a3.record(tool_name="s3_tool1", policy_name="p")
        a3.record(tool_name="s3_tool2", policy_name="p")

        result = verify_trail(audit_file)
        assert result.is_valid is True
        assert result.total_entries == 5
        assert result.chain_intact is True

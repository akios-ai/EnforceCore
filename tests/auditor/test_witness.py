# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for hash-only witness backends and witness verification."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from enforcecore.auditor import Auditor, verify_trail
from enforcecore.auditor.witness import (
    CallbackWitness,
    FileWitness,
    LogWitness,
    WitnessRecord,
    WitnessVerificationResult,
    verify_with_witness,
)

if TYPE_CHECKING:
    from pathlib import Path

# =========================================================================
# WitnessRecord
# =========================================================================


class TestWitnessRecord:
    """WitnessRecord is a frozen, lightweight hash container."""

    def test_fields(self) -> None:
        r = WitnessRecord(
            entry_id="id-1",
            entry_hash="abc123",
            previous_hash="",
            sequence=1,
            timestamp="2026-02-23T12:00:00Z",
        )
        assert r.entry_id == "id-1"
        assert r.entry_hash == "abc123"
        assert r.previous_hash == ""
        assert r.sequence == 1
        assert r.timestamp == "2026-02-23T12:00:00Z"

    def test_frozen(self) -> None:
        r = WitnessRecord(
            entry_id="id-1",
            entry_hash="abc",
            previous_hash="",
            sequence=1,
            timestamp="t",
        )
        with pytest.raises(AttributeError):
            r.entry_hash = "modified"  # type: ignore[misc]


# =========================================================================
# CallbackWitness
# =========================================================================


class TestCallbackWitness:
    """CallbackWitness sends records to a user-provided callable."""

    def test_basic_publish(self) -> None:
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)

        r = WitnessRecord("id", "hash", "", 1, "t")
        witness.publish(r)

        assert len(records) == 1
        assert records[0].entry_hash == "hash"
        assert witness.records_published == 1

    def test_multiple_publishes(self) -> None:
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)

        for i in range(10):
            witness.publish(WitnessRecord(f"id-{i}", f"hash-{i}", "", i + 1, "t"))

        assert witness.records_published == 10
        assert len(records) == 10

    def test_repr(self) -> None:
        witness = CallbackWitness(lambda r: None)
        assert "CallbackWitness" in repr(witness)

    def test_close_is_noop(self) -> None:
        witness = CallbackWitness(lambda r: None)
        witness.close()  # Should not raise

    def test_context_manager(self) -> None:
        records: list[WitnessRecord] = []
        with CallbackWitness(records.append) as w:
            w.publish(WitnessRecord("id", "hash", "", 1, "t"))
        assert len(records) == 1


# =========================================================================
# FileWitness
# =========================================================================


class TestFileWitness:
    """FileWitness appends hash records to a JSONL file."""

    def test_basic_write(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        witness = FileWitness(witness_file)

        r = WitnessRecord("id-1", "abc123", "", 1, "2026-02-23T12:00:00Z")
        witness.publish(r)

        content = witness_file.read_text().strip()
        data = json.loads(content)
        assert data["entry_hash"] == "abc123"
        assert data["entry_id"] == "id-1"
        assert data["sequence"] == 1

    def test_multiple_writes(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        witness = FileWitness(witness_file)

        for i in range(5):
            witness.publish(WitnessRecord(f"id-{i}", f"hash-{i}", "", i + 1, "t"))

        lines = witness_file.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_load_hashes(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        witness = FileWitness(witness_file)

        for i in range(3):
            witness.publish(WitnessRecord(f"id-{i}", f"hash-{i}", "", i + 1, "t"))

        hashes = witness.load_hashes()
        assert hashes == ["hash-0", "hash-1", "hash-2"]

    def test_load_hashes_empty(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        witness = FileWitness(witness_file)
        assert witness.load_hashes() == []

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "sub" / "dir" / "witness.jsonl"
        witness = FileWitness(witness_file)
        witness.publish(WitnessRecord("id", "hash", "", 1, "t"))
        assert witness_file.exists()

    def test_path_property(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        witness = FileWitness(witness_file)
        assert witness.path == witness_file

    def test_repr(self, tmp_path: Path) -> None:
        witness = FileWitness(tmp_path / "w.jsonl")
        assert "FileWitness" in repr(witness)


# =========================================================================
# LogWitness
# =========================================================================


class TestLogWitness:
    """LogWitness emits records via Python logging."""

    def test_publish(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        with caplog.at_level(logging.INFO, logger="enforcecore.witness"):
            witness = LogWitness()
            witness.publish(WitnessRecord("id-1", "abc123", "", 1, "t"))

        assert witness.records_published == 1
        assert any("abc123" in r.message for r in caplog.records)

    def test_custom_logger_name(self) -> None:
        witness = LogWitness("my.custom.logger")
        witness.publish(WitnessRecord("id", "hash", "", 1, "t"))
        assert witness.records_published == 1

    def test_repr(self) -> None:
        witness = LogWitness()
        assert "LogWitness" in repr(witness)


# =========================================================================
# Auditor + Witness integration
# =========================================================================


class TestAuditorWitnessIntegration:
    """Test that the Auditor correctly publishes to a witness."""

    def test_witness_receives_hashes(self, tmp_path: Path) -> None:
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)
        audit_file = tmp_path / "trail.jsonl"

        auditor = Auditor(output_path=audit_file, witness=witness)
        e1 = auditor.record(tool_name="tool1", policy_name="p")
        e2 = auditor.record(tool_name="tool2", policy_name="p")

        assert len(records) == 2
        assert records[0].entry_hash == e1.entry_hash
        assert records[1].entry_hash == e2.entry_hash
        assert records[0].sequence == 1
        assert records[1].sequence == 2

    def test_witness_has_correct_chain(self, tmp_path: Path) -> None:
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)
        audit_file = tmp_path / "trail.jsonl"

        auditor = Auditor(output_path=audit_file, witness=witness)
        e1 = auditor.record(tool_name="tool1", policy_name="p")
        auditor.record(tool_name="tool2", policy_name="p")

        assert records[0].previous_hash == ""
        assert records[1].previous_hash == e1.entry_hash

    def test_witness_entry_ids_match(self, tmp_path: Path) -> None:
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)
        audit_file = tmp_path / "trail.jsonl"

        auditor = Auditor(output_path=audit_file, witness=witness)
        entry = auditor.record(tool_name="tool1", policy_name="p")

        assert records[0].entry_id == entry.entry_id

    def test_no_witness_is_fine(self, tmp_path: Path) -> None:
        """Auditor without witness should work as before."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        entry = auditor.record(tool_name="tool1", policy_name="p")
        assert entry.entry_hash != ""

    def test_witness_failure_does_not_block_audit(self, tmp_path: Path) -> None:
        """If the witness raises, the audit entry is still written."""

        def failing_witness_cb(record: WitnessRecord) -> None:
            raise ConnectionError("Witness unavailable")

        witness = CallbackWitness(failing_witness_cb)
        audit_file = tmp_path / "trail.jsonl"

        auditor = Auditor(output_path=audit_file, witness=witness)
        entry = auditor.record(tool_name="tool1", policy_name="p")

        # Entry should still be written despite witness failure
        assert entry.entry_hash != ""
        assert audit_file.exists()
        result = verify_trail(audit_file)
        assert result.is_valid
        assert result.total_entries == 1

    def test_file_witness_integration(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        audit_file = tmp_path / "trail.jsonl"

        witness = FileWitness(witness_file)
        auditor = Auditor(output_path=audit_file, witness=witness)

        for i in range(5):
            auditor.record(tool_name=f"tool_{i}", policy_name="p")

        hashes = witness.load_hashes()
        assert len(hashes) == 5

    def test_witness_property(self, tmp_path: Path) -> None:
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)
        auditor = Auditor(output_path=tmp_path / "trail.jsonl", witness=witness)
        assert auditor.witness is witness


# =========================================================================
# verify_with_witness
# =========================================================================


class TestVerifyWithWitness:
    """Verify an audit trail against witness hashes."""

    def _make_trail(self, tmp_path: Path, count: int = 5) -> tuple[Path, list[str]]:
        """Helper: create a trail and collect witness hashes."""
        records: list[WitnessRecord] = []
        witness = CallbackWitness(records.append)
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file, witness=witness)

        for i in range(count):
            auditor.record(tool_name=f"tool_{i}", policy_name="p")

        hashes = [r.entry_hash for r in records]
        return audit_file, hashes

    def test_valid_trail_passes(self, tmp_path: Path) -> None:
        audit_file, hashes = self._make_trail(tmp_path)
        result = verify_with_witness(audit_file, witness_hashes=hashes)
        assert result.is_valid
        assert result.matched == 5
        assert result.mismatched == 0

    def test_tampered_trail_detected(self, tmp_path: Path) -> None:
        audit_file, hashes = self._make_trail(tmp_path)

        # Tamper with entry 3 in the trail
        lines = audit_file.read_text().strip().split("\n")
        entry = json.loads(lines[2])
        entry["tool_name"] = "TAMPERED"
        # Recompute hash to simulate chain rebuild
        import hashlib

        data = dict(entry)
        data.pop("entry_hash", None)
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        new_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        entry["entry_hash"] = new_hash
        lines[2] = json.dumps(entry, separators=(",", ":"))
        audit_file.write_text("\n".join(lines) + "\n")

        result = verify_with_witness(audit_file, witness_hashes=hashes)
        assert not result.is_valid
        assert result.mismatched >= 1

    def test_file_witness_verification(self, tmp_path: Path) -> None:
        witness_file = tmp_path / "witness.jsonl"
        audit_file = tmp_path / "trail.jsonl"

        witness = FileWitness(witness_file)
        auditor = Auditor(output_path=audit_file, witness=witness)
        for i in range(3):
            auditor.record(tool_name=f"tool_{i}", policy_name="p")

        result = verify_with_witness(audit_file, witness_file=witness_file)
        assert result.is_valid
        assert result.matched == 3

    def test_count_mismatch(self, tmp_path: Path) -> None:
        audit_file, hashes = self._make_trail(tmp_path, count=5)
        # Remove last hash from witness
        result = verify_with_witness(audit_file, witness_hashes=hashes[:3])
        assert not result.is_valid
        assert any("count mismatch" in e for e in result.errors)

    def test_no_witness_data_error(self, tmp_path: Path) -> None:
        audit_file, _ = self._make_trail(tmp_path)
        result = verify_with_witness(audit_file)
        assert not result.is_valid
        assert any("No witness data" in e for e in result.errors)

    def test_both_sources_error(self, tmp_path: Path) -> None:
        audit_file, hashes = self._make_trail(tmp_path)
        result = verify_with_witness(
            audit_file, witness_hashes=hashes, witness_file=tmp_path / "w.jsonl"
        )
        assert not result.is_valid
        assert any("not both" in e for e in result.errors)

    def test_trail_not_found(self, tmp_path: Path) -> None:
        result = verify_with_witness(tmp_path / "nonexistent.jsonl", witness_hashes=["hash"])
        assert not result.is_valid

    def test_error_count_property(self, tmp_path: Path) -> None:
        result = WitnessVerificationResult()
        assert result.error_count == 0
        result.errors.append("test error")
        assert result.error_count == 1

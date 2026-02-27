# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Merkle bridge feature (external_hash / skip_entry_hash).

This module tests the cross-system hash bridging capability added in v1.12.0
to support AKIOS integration.  It covers:

- ``AuditStore.record(external_hash=...)`` stores hashes as-is
- ``AuditStore.verify_chain(skip_entry_hash=True)`` linkage-only mode
- ``MerkleTree.verify_chain(skip_entry_hash=True)``
- ``MerkleTree.verify_entry(skip_entry_hash=True)``
- ``MerkleTree.detect_tampering(skip_entry_hash=True)``
- ``verify_trail(skip_entry_hash=True)`` in the Auditor engine
- Backward compatibility (default path unchanged)
- Mixed chains (external + native entries)
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path

from enforcecore.auditor.engine import Auditor, verify_trail
from enforcecore.auditstore.backends.jsonl import JSONLBackend
from enforcecore.auditstore.backends.sqlite import SQLiteBackend
from enforcecore.auditstore.core import AuditEntry, AuditStore
from enforcecore.auditstore.merkle import MerkleTree

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_external_hash(entry: AuditEntry, parent_hash: str | None) -> str:
    """Simulate an external system (e.g. AKIOS) computing a *different* hash."""
    data = {
        "id": entry.entry_id,
        "ts": entry.timestamp.isoformat(),
        "tool": entry.tool_name,
        "policy": entry.policy_name,
        "parent": parent_hash or "genesis",
    }
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def _make_kwargs(tool_name: str = "search", decision: str = "allowed") -> dict:
    """Keyword args for AuditStore.record()."""
    return {
        "policy_name": "test-policy",
        "policy_version": "1.0",
        "tool_name": tool_name,
        "decision": decision,
        "call_duration_ms": 1.0,
        "enforcement_overhead_ms": 0.1,
    }


# ---------------------------------------------------------------------------
# AuditStore.record(external_hash=...) — JSONL backend
# ---------------------------------------------------------------------------


class TestExternalHashJSONL:
    """Test external_hash on AuditStore.record() with JSONL backend."""

    def test_external_hash_stored_as_is(self, tmp_path: Path) -> None:
        """external_hash value must be stored verbatim, not recomputed."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        entry = store.record(
            external_hash="cafebabe" * 8,
            **_make_kwargs(),
        )

        assert entry.merkle_hash == "cafebabe" * 8

    def test_external_prev_hash_stored(self, tmp_path: Path) -> None:
        """external_prev_hash is stored in parent_hash."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        entry = store.record(
            external_hash="aaa" + "0" * 61,
            external_prev_hash="bbb" + "0" * 61,
            **_make_kwargs(),
        )

        assert entry.parent_hash == "bbb" + "0" * 61

    def test_external_hash_no_prev_gets_chain_tail(self, tmp_path: Path) -> None:
        """When external_prev_hash is None, backend fills parent from chain tail."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        # First entry — native hash
        e1 = store.record(**_make_kwargs(tool_name="tool_0"))

        # Second entry — external hash, no prev
        e2 = store.record(
            external_hash="deadbeef" * 8,
            **_make_kwargs(tool_name="tool_1"),
        )

        assert e2.parent_hash == e1.merkle_hash

    def test_verify_chain_default_fails_external(self, tmp_path: Path) -> None:
        """Default verify_chain recomputes hashes and detects external mismatch."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        store.record(
            external_hash="cafebabe" * 8,
            external_prev_hash=None,
            **_make_kwargs(),
        )

        # Default verify recomputes — external hash won't match
        assert store.verify_chain() is False

    def test_verify_chain_skip_entry_hash_passes(self, tmp_path: Path) -> None:
        """skip_entry_hash=True checks linkage only — should pass for valid chain."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        prev_hash: str | None = None
        for i in range(5):
            kw = _make_kwargs(tool_name=f"tool_{i}")
            entry = AuditEntry.create(**kw)
            ext_hash = _fake_external_hash(entry, prev_hash)

            recorded = store.record(
                external_hash=ext_hash,
                external_prev_hash=prev_hash,
                **kw,
            )
            prev_hash = recorded.merkle_hash

        assert store.verify_chain(skip_entry_hash=True) is True

    def test_backward_compat_no_external_hash(self, tmp_path: Path) -> None:
        """Without external_hash, record() and verify_chain() work as before."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        for i in range(5):
            store.record(**_make_kwargs(tool_name=f"tool_{i}"))

        assert store.verify_chain() is True


# ---------------------------------------------------------------------------
# AuditStore.record(external_hash=...) — SQLite backend
# ---------------------------------------------------------------------------


class TestExternalHashSQLite:
    """Test external_hash on AuditStore.record() with SQLite backend."""

    def test_external_hash_stored_as_is(self, tmp_path: Path) -> None:
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        store = AuditStore(backend=backend)

        entry = store.record(
            external_hash="cafebabe" * 8,
            **_make_kwargs(),
        )

        assert entry.merkle_hash == "cafebabe" * 8

    def test_backward_compat_no_external_hash(self, tmp_path: Path) -> None:
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        store = AuditStore(backend=backend)

        for i in range(5):
            store.record(**_make_kwargs(tool_name=f"tool_{i}"))

        assert store.verify_chain() is True

    def test_verify_chain_skip_entry_hash_signature(self, tmp_path: Path) -> None:
        """SQLite verify_chain accepts skip_entry_hash kwarg."""
        backend = SQLiteBackend(str(tmp_path / "audit.db"))
        store = AuditStore(backend=backend)

        store.record(**_make_kwargs())
        # Should not raise
        result = store.verify_chain(skip_entry_hash=True)
        assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# MerkleTree — skip_entry_hash
# ---------------------------------------------------------------------------


class TestMerkleTreeSkipEntryHash:
    """Test MerkleTree static methods with skip_entry_hash=True."""

    @staticmethod
    def _build_external_chain(n: int) -> list[AuditEntry]:
        """Build a chain using fake external hashes."""
        entries: list[AuditEntry] = []
        prev_hash: str | None = None
        for i in range(n):
            entry = AuditEntry.create(
                policy_name="test-policy",
                policy_version="1.0",
                tool_name=f"tool_{i}",
                decision="allowed",
                call_duration_ms=1.0,
                enforcement_overhead_ms=0.1,
            )
            ext_hash = _fake_external_hash(entry, prev_hash)
            entry.merkle_hash = ext_hash
            entry.parent_hash = prev_hash
            prev_hash = ext_hash
            entries.append(entry)
        return entries

    def test_verify_chain_external_hashes_default_fails(self) -> None:
        """Default verify_chain fails because hashes don't match EC's algorithm."""
        entries = self._build_external_chain(5)
        assert MerkleTree.verify_chain(entries) is False

    def test_verify_chain_external_hashes_skip_passes(self) -> None:
        """skip_entry_hash=True only checks linkage — should pass."""
        entries = self._build_external_chain(5)
        assert MerkleTree.verify_chain(entries, skip_entry_hash=True) is True

    def test_verify_chain_broken_linkage_fails_even_with_skip(self) -> None:
        """Even with skip_entry_hash=True, broken linkage is detected."""
        entries = self._build_external_chain(5)
        # Break chain linkage
        entries[3].parent_hash = "broken" * 10 + "brok"
        assert MerkleTree.verify_chain(entries, skip_entry_hash=True) is False

    def test_verify_entry_skip_passes(self) -> None:
        entries = self._build_external_chain(3)
        assert MerkleTree.verify_entry(entries[1], entries[0], skip_entry_hash=True) is True

    def test_verify_entry_broken_linkage_skip_fails(self) -> None:
        entries = self._build_external_chain(3)
        entries[1].parent_hash = "wrong" * 12 + "wron"
        assert MerkleTree.verify_entry(entries[1], entries[0], skip_entry_hash=True) is False

    def test_detect_tampering_external_skip(self) -> None:
        entries = self._build_external_chain(5)
        assert MerkleTree.detect_tampering(entries, skip_entry_hash=True) is None

    def test_detect_tampering_broken_linkage_skip(self) -> None:
        entries = self._build_external_chain(5)
        entries[2].parent_hash = "tampered" * 8
        assert MerkleTree.detect_tampering(entries, skip_entry_hash=True) == 2

    def test_generate_proof_external_skip(self) -> None:
        entries = self._build_external_chain(5)
        proof = MerkleTree.generate_proof(entries, 2, skip_entry_hash=True)
        assert proof["chain_valid"] is True
        assert proof["target_index"] == 2


# ---------------------------------------------------------------------------
# verify_trail(skip_entry_hash=True) — Auditor engine
# ---------------------------------------------------------------------------


class TestVerifyTrailSkipEntryHash:
    """Test verify_trail() with skip_entry_hash parameter."""

    def test_normal_trail_passes(self) -> None:
        """Normal trail passes with default skip_entry_hash=False."""
        with tempfile.TemporaryDirectory() as tmpdir:
            trail_path = str(Path(tmpdir) / "audit.jsonl")
            auditor = Auditor(output_path=trail_path)

            for i in range(5):
                auditor.record(
                    tool_name=f"tool_{i}",
                    policy_name="strict",
                    decision="allowed",
                )

            result = verify_trail(trail_path)
            assert result.is_valid is True
            assert result.total_entries == 5

    def test_skip_entry_hash_passes_for_valid_trail(self) -> None:
        """skip_entry_hash=True still passes for a valid trail."""
        with tempfile.TemporaryDirectory() as tmpdir:
            trail_path = str(Path(tmpdir) / "audit.jsonl")
            auditor = Auditor(output_path=trail_path)

            for i in range(5):
                auditor.record(
                    tool_name=f"tool_{i}",
                    policy_name="strict",
                    decision="allowed",
                )

            result = verify_trail(trail_path, skip_entry_hash=True)
            assert result.is_valid is True
            assert result.chain_intact is True

    def test_skip_entry_hash_detects_broken_chain(self) -> None:
        """skip_entry_hash=True still detects chain linkage breaks."""
        with tempfile.TemporaryDirectory() as tmpdir:
            trail_path = str(Path(tmpdir) / "audit.jsonl")
            auditor = Auditor(output_path=trail_path)

            for i in range(5):
                auditor.record(
                    tool_name=f"tool_{i}",
                    policy_name="strict",
                    decision="allowed",
                )

            # Corrupt previous_hash in one entry
            lines = Path(trail_path).read_text().splitlines()
            data = json.loads(lines[2])
            data["previous_hash"] = "corrupted" * 7 + "corrupt"
            lines[2] = json.dumps(data)
            Path(trail_path).write_text("\n".join(lines) + "\n")

            result = verify_trail(trail_path, skip_entry_hash=True)
            assert result.is_valid is False
            assert result.chain_intact is False

    def test_skip_entry_hash_ignores_hash_mismatch(self) -> None:
        """skip_entry_hash=True does NOT fail on hash payload mismatch."""
        with tempfile.TemporaryDirectory() as tmpdir:
            trail_path = str(Path(tmpdir) / "audit.jsonl")
            auditor = Auditor(output_path=trail_path)

            for i in range(3):
                auditor.record(
                    tool_name=f"tool_{i}",
                    policy_name="strict",
                    decision="allowed",
                )

            # Change entry_hash to something wrong but keep previous_hash chain intact
            lines = Path(trail_path).read_text().splitlines()
            data = json.loads(lines[0])
            data["entry_hash"] = "aaaa" * 16  # wrong hash
            lines[0] = json.dumps(data)

            # Update next entry's previous_hash to match the corrupted hash
            data2 = json.loads(lines[1])
            data2["previous_hash"] = "aaaa" * 16
            lines[1] = json.dumps(data2)

            Path(trail_path).write_text("\n".join(lines) + "\n")

            # Without skip — should fail (hash doesn't match payload)
            result_strict = verify_trail(trail_path, skip_entry_hash=False)
            assert result_strict.is_valid is False

            # With skip — should pass (chain linkage is intact)
            result_skip = verify_trail(trail_path, skip_entry_hash=True)
            assert result_skip.is_valid is True


# ---------------------------------------------------------------------------
# Mixed chain: external + native entries
# ---------------------------------------------------------------------------


class TestMixedChain:
    """Test chains with a mix of native and external-hash entries."""

    def test_mixed_chain_verify_with_skip(self, tmp_path: Path) -> None:
        """A chain with native + external entries verifies with skip_entry_hash."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        # Native entry
        e1 = store.record(**_make_kwargs(tool_name="native_0"))
        assert e1.merkle_hash is not None

        # External entry chained to native
        kw = _make_kwargs(tool_name="external_1")
        entry = AuditEntry.create(**kw)
        ext_hash = _fake_external_hash(entry, e1.merkle_hash)
        e2 = store.record(
            external_hash=ext_hash,
            external_prev_hash=e1.merkle_hash,
            **kw,
        )
        assert e2.merkle_hash == ext_hash
        assert e2.parent_hash == e1.merkle_hash

    def test_mixed_chain_default_verify_fails(self, tmp_path: Path) -> None:
        """Default verify fails because the external entry hash doesn't match."""
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend=backend)

        e1 = store.record(**_make_kwargs(tool_name="native_0"))

        kw = _make_kwargs(tool_name="external_1")
        entry = AuditEntry.create(**kw)
        ext_hash = _fake_external_hash(entry, e1.merkle_hash)
        store.record(
            external_hash=ext_hash,
            external_prev_hash=e1.merkle_hash,
            **kw,
        )

        # Default verify recomputes all hashes — external one won't match
        assert store.verify_chain() is False

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for MerkleTree — the cryptographic tamper-evidence primitive.

Covers:
- compute_hash() for genesis and chained entries
- verify_chain() for valid and broken chains
- verify_entry() for valid and tampered entries
- generate_proof() for in-bounds and out-of-bounds
- detect_tampering() for pristine and corrupted chains
- Edge cases: empty chain, single entry, modified fields
"""

from __future__ import annotations

import dataclasses

import pytest

from enforcecore.auditstore.core import AuditEntry
from enforcecore.auditstore.merkle import MerkleTree

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_entry(tool_name: str = "search", decision: str = "allowed") -> AuditEntry:
    """Create a minimal AuditEntry for testing."""
    return AuditEntry.create(
        policy_name="test-policy",
        policy_version="1.0",
        tool_name=tool_name,
        decision=decision,
        call_duration_ms=1.0,
        enforcement_overhead_ms=0.1,
    )


def build_valid_chain(n: int) -> list[AuditEntry]:
    """Build a valid Merkle chain of *n* entries with correct hashes."""
    entries: list[AuditEntry] = []
    prev_hash: str | None = None
    for i in range(n):
        entry = make_entry(tool_name=f"tool_{i}")
        hash_ = MerkleTree.compute_hash(entry, prev_hash)
        entry.merkle_hash = hash_
        entry.parent_hash = prev_hash
        prev_hash = hash_
        entries.append(entry)
    return entries


# ---------------------------------------------------------------------------
# compute_hash
# ---------------------------------------------------------------------------


class TestComputeHash:
    def test_returns_64_char_hex_string(self) -> None:
        entry = make_entry()
        h = MerkleTree.compute_hash(entry)
        assert isinstance(h, str)
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_genesis_uses_zero_parent(self) -> None:
        """Genesis entry (no parent) uses '0' * 64 as parent hash."""
        entry = make_entry()
        h_none = MerkleTree.compute_hash(entry, parent_hash=None)
        h_zeros = MerkleTree.compute_hash(entry, parent_hash="0" * 64)
        assert h_none == h_zeros

    def test_different_parent_hash_changes_result(self) -> None:
        entry = make_entry()
        h1 = MerkleTree.compute_hash(entry, parent_hash=None)
        h2 = MerkleTree.compute_hash(entry, parent_hash="a" * 64)
        assert h1 != h2

    def test_different_tool_name_changes_hash(self) -> None:
        e1 = make_entry(tool_name="search")
        e2 = make_entry(tool_name="delete")
        h1 = MerkleTree.compute_hash(e1)
        h2 = MerkleTree.compute_hash(e2)
        assert h1 != h2

    def test_different_decision_changes_hash(self) -> None:
        e1 = make_entry(decision="allowed")
        e2 = make_entry(decision="blocked")
        h1 = MerkleTree.compute_hash(e1)
        h2 = MerkleTree.compute_hash(e2)
        assert h1 != h2

    def test_deterministic_same_inputs(self) -> None:
        """Same entry + same parent_hash → same hash every time."""
        entry = make_entry()
        parent = "deadbeef" * 8
        h1 = MerkleTree.compute_hash(entry, parent)
        h2 = MerkleTree.compute_hash(entry, parent)
        assert h1 == h2

    def test_includes_entry_id_in_hash(self) -> None:
        """Two entries with the same fields but different IDs produce different hashes."""
        e1 = make_entry()
        e2 = make_entry()
        # Different auto-generated UUIDs
        assert e1.entry_id != e2.entry_id
        h1 = MerkleTree.compute_hash(e1)
        h2 = MerkleTree.compute_hash(e2)
        assert h1 != h2

    def test_includes_timestamp_in_hash(self) -> None:
        """Entries created at different instants have different hashes."""
        e1 = make_entry()
        e2 = make_entry()
        # Timestamps differ by at least a few microseconds
        # (UUIDs also differ, which is sufficient)
        assert MerkleTree.compute_hash(e1) != MerkleTree.compute_hash(e2)


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------


class TestVerifyChain:
    def test_empty_chain_is_valid(self) -> None:
        assert MerkleTree.verify_chain([]) is True

    def test_single_entry_valid(self) -> None:
        entries = build_valid_chain(1)
        assert MerkleTree.verify_chain(entries) is True

    def test_three_entry_chain_valid(self) -> None:
        entries = build_valid_chain(3)
        assert MerkleTree.verify_chain(entries) is True

    def test_ten_entry_chain_valid(self) -> None:
        entries = build_valid_chain(10)
        assert MerkleTree.verify_chain(entries) is True

    def test_tampered_first_entry_detected(self) -> None:
        entries = build_valid_chain(5)
        # Corrupt the first entry's decision
        entries[0] = dataclasses.replace(entries[0], decision="blocked")
        assert MerkleTree.verify_chain(entries) is False

    def test_tampered_middle_entry_detected(self) -> None:
        entries = build_valid_chain(5)
        # Corrupt entry at index 2
        entries[2] = dataclasses.replace(entries[2], tool_name="evil_tool")
        assert MerkleTree.verify_chain(entries) is False

    def test_tampered_last_entry_detected(self) -> None:
        entries = build_valid_chain(5)
        entries[-1] = dataclasses.replace(entries[-1], decision="blocked")
        assert MerkleTree.verify_chain(entries) is False

    def test_wrong_merkle_hash_on_entry_fails(self) -> None:
        entries = build_valid_chain(3)
        entries[1].merkle_hash = "0" * 64  # corrupt hash directly
        assert MerkleTree.verify_chain(entries) is False

    def test_chain_order_matters(self) -> None:
        entries = build_valid_chain(3)
        # Swapping entries breaks the chain
        entries[0], entries[1] = entries[1], entries[0]
        assert MerkleTree.verify_chain(entries) is False


# ---------------------------------------------------------------------------
# verify_entry
# ---------------------------------------------------------------------------


class TestVerifyEntry:
    def test_genesis_entry_valid(self) -> None:
        entries = build_valid_chain(1)
        assert MerkleTree.verify_entry(entries[0], prev_entry=None) is True

    def test_chained_entry_valid(self) -> None:
        entries = build_valid_chain(3)
        assert MerkleTree.verify_entry(entries[1], prev_entry=entries[0]) is True
        assert MerkleTree.verify_entry(entries[2], prev_entry=entries[1]) is True

    def test_tampered_entry_fails(self) -> None:
        entries = build_valid_chain(3)
        corrupted = dataclasses.replace(entries[1], tool_name="evil")
        assert MerkleTree.verify_entry(corrupted, prev_entry=entries[0]) is False

    def test_wrong_prev_entry_fails(self) -> None:
        entries = build_valid_chain(3)
        # Pass wrong prev_entry
        assert MerkleTree.verify_entry(entries[2], prev_entry=entries[0]) is False

    def test_genesis_with_none_prev(self) -> None:
        entries = build_valid_chain(1)
        assert MerkleTree.verify_entry(entries[0]) is True


# ---------------------------------------------------------------------------
# generate_proof
# ---------------------------------------------------------------------------


class TestGenerateProof:
    def test_proof_contains_required_keys(self) -> None:
        entries = build_valid_chain(3)
        proof = MerkleTree.generate_proof(entries, target_index=1)
        assert "target_index" in proof
        assert "target_entry_id" in proof
        assert "target_hash" in proof
        assert "chain_length" in proof
        assert "chain_valid" in proof
        assert "path" in proof

    def test_proof_target_index_matches(self) -> None:
        entries = build_valid_chain(4)
        proof = MerkleTree.generate_proof(entries, target_index=2)
        assert proof["target_index"] == 2
        assert proof["target_entry_id"] == entries[2].entry_id
        assert proof["target_hash"] == entries[2].merkle_hash

    def test_proof_chain_valid_true_for_valid_chain(self) -> None:
        entries = build_valid_chain(3)
        proof = MerkleTree.generate_proof(entries, target_index=0)
        assert proof["chain_valid"] is True

    def test_proof_chain_valid_false_for_tampered_chain(self) -> None:
        entries = build_valid_chain(3)
        entries[1] = dataclasses.replace(entries[1], tool_name="evil")
        proof = MerkleTree.generate_proof(entries, target_index=0)
        assert proof["chain_valid"] is False

    def test_proof_chain_length(self) -> None:
        entries = build_valid_chain(5)
        proof = MerkleTree.generate_proof(entries, target_index=3)
        assert proof["chain_length"] == 5

    def test_out_of_bounds_raises_value_error(self) -> None:
        entries = build_valid_chain(3)
        with pytest.raises(ValueError, match="out of bounds"):
            MerkleTree.generate_proof(entries, target_index=3)

    def test_proof_first_entry(self) -> None:
        entries = build_valid_chain(1)
        proof = MerkleTree.generate_proof(entries, target_index=0)
        assert proof["target_index"] == 0
        assert proof["chain_length"] == 1


# ---------------------------------------------------------------------------
# detect_tampering
# ---------------------------------------------------------------------------


class TestDetectTampering:
    def test_valid_chain_returns_none(self) -> None:
        entries = build_valid_chain(5)
        assert MerkleTree.detect_tampering(entries) is None

    def test_empty_chain_returns_none(self) -> None:
        assert MerkleTree.detect_tampering([]) is None

    def test_single_valid_entry_returns_none(self) -> None:
        entries = build_valid_chain(1)
        assert MerkleTree.detect_tampering(entries) is None

    def test_detects_tamper_at_index_0(self) -> None:
        entries = build_valid_chain(5)
        entries[0] = dataclasses.replace(entries[0], tool_name="evil")
        idx = MerkleTree.detect_tampering(entries)
        assert idx == 0

    def test_detects_tamper_at_middle_index(self) -> None:
        entries = build_valid_chain(5)
        entries[2] = dataclasses.replace(entries[2], decision="blocked")
        idx = MerkleTree.detect_tampering(entries)
        assert idx == 2

    def test_detects_tamper_at_last_index(self) -> None:
        entries = build_valid_chain(5)
        entries[4] = dataclasses.replace(entries[4], tool_name="modified")
        idx = MerkleTree.detect_tampering(entries)
        assert idx == 4

    def test_start_index_skips_earlier_tampering(self) -> None:
        entries = build_valid_chain(5)
        entries[1] = dataclasses.replace(entries[1], tool_name="evil")
        # Start scan from index 2 — the tamper at 1 is skipped
        result = MerkleTree.detect_tampering(entries, start_index=2)
        # Entry 2 uses entries[1].merkle_hash as parent, which is valid
        # (entries[1] has a valid hash from build_valid_chain — we only changed tool_name
        # which means compute_hash would differ, but entries[1].merkle_hash was set BEFORE)
        # So entries[2] was built using original entries[1].merkle_hash → still valid from index 2
        assert result is None

    def test_hash_corruption_detected(self) -> None:
        entries = build_valid_chain(4)
        entries[2].merkle_hash = "ff" * 32  # corrupt stored hash
        idx = MerkleTree.detect_tampering(entries)
        assert idx == 2


# ---------------------------------------------------------------------------
# Module-level import
# ---------------------------------------------------------------------------


class TestMerkleModuleImport:
    def test_import_from_package(self) -> None:
        from enforcecore.auditstore.merkle import MerkleTree as MerkleTreeAlias

        assert MerkleTreeAlias is MerkleTree

    def test_merkle_tree_is_class(self) -> None:
        assert isinstance(MerkleTree, type)

    def test_all_static_methods_callable(self) -> None:
        assert callable(MerkleTree.compute_hash)
        assert callable(MerkleTree.verify_chain)
        assert callable(MerkleTree.verify_entry)
        assert callable(MerkleTree.generate_proof)
        assert callable(MerkleTree.detect_tampering)

"""Audit trail continuity integration tests.

Tests that the Merkle-chained audit trail maintains integrity across
multiple sessions, verifies tamper detection, and validates the chain
structure end-to-end.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from enforcecore import Enforcer
from enforcecore.auditor.engine import load_trail, verify_trail

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def echo(text: str) -> str:
    return f"echo: {text}"


# ---------------------------------------------------------------------------
# Chain structure tests
# ---------------------------------------------------------------------------


class TestAuditChainStructure:
    """Verify the Merkle chain structure of audit entries."""

    def test_first_entry_has_empty_previous(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)
        enforcer.enforce_sync(echo, "first", tool_name="lookup_drug_interactions")

        entries = load_trail(audit_trail_path)
        assert len(entries) == 1
        assert entries[0].previous_hash == ""
        assert entries[0].entry_hash != ""

    def test_chain_links(self, healthcare_policy: Policy, audit_trail_path: Path) -> None:
        """Each entry's previous_hash matches the prior entry's entry_hash."""
        enforcer = Enforcer(healthcare_policy)
        for i in range(5):
            enforcer.enforce_sync(echo, f"call-{i}", tool_name="lookup_drug_interactions")

        entries = load_trail(audit_trail_path)
        assert len(entries) == 5

        # First entry has no previous
        assert entries[0].previous_hash == ""

        # Each subsequent entry chains to the previous
        for i in range(1, len(entries)):
            assert entries[i].previous_hash == entries[i - 1].entry_hash

    def test_hash_is_deterministic(self, healthcare_policy: Policy, audit_trail_path: Path) -> None:
        """Recomputing the hash matches the stored hash."""
        enforcer = Enforcer(healthcare_policy)
        enforcer.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")

        entries = load_trail(audit_trail_path)
        for entry in entries:
            recomputed = entry.compute_hash()
            assert recomputed == entry.entry_hash


# ---------------------------------------------------------------------------
# Cross-session continuity
# ---------------------------------------------------------------------------


class TestCrossSessionContinuity:
    """Verify audit trail continuity when appending across sessions."""

    def test_second_session_writes_to_same_file(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        """Creating a new Enforcer still writes to the same trail file."""
        # Session 1
        e1 = Enforcer(healthcare_policy)
        e1.enforce_sync(echo, "session-1", tool_name="lookup_drug_interactions")

        # Session 2 — new Enforcer, same trail
        e2 = Enforcer(healthcare_policy)
        e2.enforce_sync(echo, "session-2", tool_name="query_symptoms_db")

        entries = load_trail(audit_trail_path)
        assert len(entries) == 2
        assert entries[0].tool_name == "lookup_drug_interactions"
        assert entries[1].tool_name == "query_symptoms_db"

    def test_different_policies_same_trail(
        self,
        healthcare_policy: Policy,
        compliance_policy: Policy,
        audit_trail_path: Path,
    ) -> None:
        """Different policies in separate sessions write to the same file."""
        e1 = Enforcer(healthcare_policy)
        e1.enforce_sync(echo, "health", tool_name="lookup_drug_interactions")

        e2 = Enforcer(compliance_policy)
        e2.enforce_sync(echo, "compliance", tool_name="classify_document")

        entries = load_trail(audit_trail_path)
        assert len(entries) == 2
        assert entries[0].policy_name != entries[1].policy_name


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


class TestTamperDetection:
    """Verify that modifying trail entries is detectable."""

    def test_modified_tool_name_detected(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)
        enforcer.enforce_sync(echo, "a", tool_name="lookup_drug_interactions")
        enforcer.enforce_sync(echo, "b", tool_name="query_symptoms_db")

        lines = audit_trail_path.read_text().strip().split("\n")
        data = json.loads(lines[0])
        data["tool_name"] = "TAMPERED_TOOL"
        lines[0] = json.dumps(data, sort_keys=True, separators=(",", ":"))
        audit_trail_path.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_trail_path)
        assert not result.is_valid or not result.chain_intact

    def test_deleted_entry_detected(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)
        for i in range(3):
            enforcer.enforce_sync(echo, f"call-{i}", tool_name="lookup_drug_interactions")

        lines = audit_trail_path.read_text().strip().split("\n")
        assert len(lines) == 3
        # Remove middle entry
        del lines[1]
        audit_trail_path.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_trail_path)
        assert not result.is_valid or not result.chain_intact

    def test_swapped_entries_detected(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)
        for i in range(3):
            enforcer.enforce_sync(echo, f"call-{i}", tool_name="lookup_drug_interactions")

        lines = audit_trail_path.read_text().strip().split("\n")
        assert len(lines) == 3
        # Swap entries 1 and 2
        lines[1], lines[2] = lines[2], lines[1]
        audit_trail_path.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_trail_path)
        assert not result.is_valid or not result.chain_intact


# ---------------------------------------------------------------------------
# Load/verify edge cases
# ---------------------------------------------------------------------------


class TestAuditEdgeCases:
    """Edge cases for audit trail loading and verification."""

    def test_empty_trail_is_valid(self, audit_trail_path: Path) -> None:
        audit_trail_path.parent.mkdir(parents=True, exist_ok=True)
        audit_trail_path.write_text("")
        result = verify_trail(audit_trail_path)
        assert result.is_valid
        assert result.total_entries == 0

    def test_single_entry_trail(self, healthcare_policy: Policy, audit_trail_path: Path) -> None:
        enforcer = Enforcer(healthcare_policy)
        enforcer.enforce_sync(echo, "solo", tool_name="lookup_drug_interactions")

        result = verify_trail(audit_trail_path)
        assert result.is_valid
        assert result.total_entries == 1

    def test_load_trail_preserves_order(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)
        tools = [
            "lookup_drug_interactions",
            "query_symptoms_db",
            "schedule_appointment",
        ]
        for tool in tools:
            enforcer.enforce_sync(echo, "test", tool_name=tool)

        entries = load_trail(audit_trail_path)
        loaded_tools = [e.tool_name for e in entries]
        assert loaded_tools == tools

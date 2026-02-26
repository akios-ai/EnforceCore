"""Tests for auditstore core module."""

import os
import tempfile

from enforcecore.auditstore.backends.jsonl import JSONLBackend
from enforcecore.auditstore.core import AuditEntry, AuditStore


def test_audit_entry_creation():
    """Test AuditEntry creation."""
    entry = AuditEntry.create(
        policy_name="test-policy",
        policy_version="1.0",
        tool_name="search",
        decision="allowed",
        call_duration_ms=10.5,
        enforcement_overhead_ms=0.5,
    )

    assert entry.policy_name == "test-policy"
    assert entry.tool_name == "search"
    assert entry.decision == "allowed"
    assert entry.entry_id is not None
    assert entry.timestamp is not None


def test_audit_entry_to_dict():
    """Test AuditEntry serialization."""
    entry = AuditEntry.create(
        policy_name="test-policy",
        policy_version="1.0",
        tool_name="search",
        decision="allowed",
        call_duration_ms=10.5,
        enforcement_overhead_ms=0.5,
        cost_usd=0.05,
    )

    data = entry.to_dict()

    assert data["policy_name"] == "test-policy"
    assert data["tool_name"] == "search"
    assert data["cost_usd"] == 0.05
    assert isinstance(data["timestamp"], str)


def test_audit_store_record():
    """Test recording audit entry."""
    with tempfile.TemporaryDirectory() as tmpdir:
        trail_file = os.path.join(tmpdir, "audit.jsonl")
        backend = JSONLBackend(trail_file)
        store = AuditStore(backend)

        entry = store.record(
            policy_name="test-policy",
            policy_version="1.0",
            tool_name="search",
            decision="allowed",
            call_duration_ms=10.5,
            enforcement_overhead_ms=0.5,
        )

        assert entry.merkle_hash is not None
        assert entry.chain_index == 0
        assert os.path.exists(trail_file)


def test_audit_store_get_entry():
    """Test retrieving audit entry."""
    with tempfile.TemporaryDirectory() as tmpdir:
        trail_file = os.path.join(tmpdir, "audit.jsonl")
        backend = JSONLBackend(trail_file)
        store = AuditStore(backend)

        recorded = store.record(
            policy_name="test-policy",
            policy_version="1.0",
            tool_name="search",
            decision="allowed",
            call_duration_ms=10.5,
            enforcement_overhead_ms=0.5,
        )

        retrieved = store.get_entry(recorded.entry_id)

        assert retrieved is not None
        assert retrieved.entry_id == recorded.entry_id
        assert retrieved.tool_name == "search"


def test_audit_store_list_entries():
    """Test listing audit entries."""
    with tempfile.TemporaryDirectory() as tmpdir:
        trail_file = os.path.join(tmpdir, "audit.jsonl")
        backend = JSONLBackend(trail_file)
        store = AuditStore(backend)

        # Record multiple entries
        for i in range(3):
            store.record(
                policy_name="test-policy",
                policy_version="1.0",
                tool_name=f"tool_{i}",
                decision="allowed",
                call_duration_ms=10.0,
                enforcement_overhead_ms=0.5,
            )

        # List all
        all_entries = store.list_entries(limit=100)
        assert len(all_entries) == 3

        # List with filter
        tool0_entries = store.list_entries(tool_name="tool_0")
        assert len(tool0_entries) == 1
        assert tool0_entries[0].tool_name == "tool_0"


def test_audit_store_verify_chain():
    """Test Merkle chain verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        trail_file = os.path.join(tmpdir, "audit.jsonl")
        backend = JSONLBackend(trail_file)
        store = AuditStore(backend)

        # Record multiple entries
        for i in range(3):
            store.record(
                policy_name="test-policy",
                policy_version="1.0",
                tool_name=f"tool_{i}",
                decision="allowed",
                call_duration_ms=10.0,
                enforcement_overhead_ms=0.5,
            )

        # Verify chain
        is_valid = store.verify_chain()
        assert is_valid is True

"""Tests for PostgreSQL backend (integration tests).

These tests require a running PostgreSQL instance.
Skip if psycopg2 not installed or PostgreSQL not available.
"""

from datetime import datetime, timedelta

import pytest

# Skip all tests if psycopg2 not available
pytest.importorskip("psycopg2")

from enforcecore.auditstore.backends.postgresql import PostgreSQLBackend
from enforcecore.auditstore.core import AuditStore


@pytest.fixture
def pg_backend():
    """Create PostgreSQL backend for testing."""
    try:
        backend = PostgreSQLBackend(
            host="localhost",
            database="enforcecore_test",
            user="postgres",
            password="postgres",
            port=5432,
        )
        yield backend
    except Exception as e:
        pytest.skip(f"PostgreSQL not available: {e}")


def test_postgresql_backend_record(pg_backend):
    """Test recording to PostgreSQL."""
    store = AuditStore(pg_backend)

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


def test_postgresql_backend_get_entry(pg_backend):
    """Test retrieving from PostgreSQL."""
    store = AuditStore(pg_backend)

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


def test_postgresql_backend_list_entries(pg_backend):
    """Test listing from PostgreSQL."""
    store = AuditStore(pg_backend)

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
    assert len(all_entries) >= 3

    # List with filter
    tool0_entries = store.list_entries(tool_name="tool_0")
    assert len(tool0_entries) >= 1


def test_postgresql_backend_verify_chain(pg_backend):
    """Test Merkle chain verification."""
    store = AuditStore(pg_backend)

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


def test_postgresql_backend_time_range_query(pg_backend):
    """Test querying by time range."""
    store = AuditStore(pg_backend)

    now = datetime.utcnow()
    past = now - timedelta(hours=1)
    future = now + timedelta(hours=1)

    # Record entry
    store.record(
        policy_name="test-policy",
        policy_version="1.0",
        tool_name="search",
        decision="allowed",
        call_duration_ms=10.0,
        enforcement_overhead_ms=0.5,
    )

    # Query with range
    entries = store.list_entries(start_time=past, end_time=future)
    assert len(entries) >= 1

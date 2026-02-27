# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for AuditStoreBackendAdapter coverage gaps.

Covers the untested lines in enforcecore/auditstore/adapters.py:
- Timestamp parse fallback (bad ISO string → datetime.now)
- Write completion state tracking (_last_hash, _entry_count updated)
- Write exception wrapping → AuditError
- Close error logging (warning on backend.close() failure)
- __repr__
"""

from __future__ import annotations

import tempfile
from unittest.mock import MagicMock

import pytest

from enforcecore.auditstore.adapters import AuditStoreBackendAdapter
from enforcecore.auditstore.backends.jsonl import JSONLBackend
from enforcecore.core.types import AuditError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry_dict(**overrides) -> dict:
    base = {
        "entry_id": "test-id-001",
        "timestamp": "2026-02-27T12:00:00+00:00",
        "policy_name": "test-policy",
        "policy_version": "1.0",
        "tool_name": "search",
        "decision": "allowed",
        "call_duration_ms": 5.0,
        "overhead_ms": 0.5,
        "input_redactions": 0,
        "output_redactions": 0,
        "entry_hash": None,
        "previous_hash": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Timestamp parse fallback
# ---------------------------------------------------------------------------


class TestTimestampParseFallback:
    def test_bad_timestamp_string_falls_back_to_now(self) -> None:
        """If the timestamp string is malformed, datetime.now(UTC) is used."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            entry_dict = _make_entry_dict(timestamp="NOT_A_VALID_DATE")
            # Should not raise — fallback to now
            adapter.write(entry_dict)
            adapter.close()

    def test_missing_timestamp_key_falls_back_to_now(self) -> None:
        """If 'timestamp' key is absent, datetime.now(UTC) is used."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            entry_dict = _make_entry_dict()
            del entry_dict["timestamp"]
            adapter.write(entry_dict)
            adapter.close()

    def test_z_suffix_timestamp_parsed_correctly(self) -> None:
        """'Z' suffix is normalised to '+00:00' for fromisoformat."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            entry_dict = _make_entry_dict(timestamp="2026-02-27T12:00:00Z")
            adapter.write(entry_dict)
            adapter.close()


# ---------------------------------------------------------------------------
# Write completion state tracking
# ---------------------------------------------------------------------------


class TestWriteCompletionTracking:
    def test_entry_count_incremented_after_write(self) -> None:
        """_entry_count is updated after each successful write."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            assert adapter._entry_count == 0
            adapter.write(_make_entry_dict(entry_id="id-1"))
            assert adapter._entry_count == 1
            adapter.write(_make_entry_dict(entry_id="id-2"))
            assert adapter._entry_count == 2
            adapter.close()

    def test_last_hash_updated_after_write(self) -> None:
        """_last_hash is updated to the recorded entry's merkle_hash."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            assert adapter._last_hash == ""
            adapter.write(_make_entry_dict(entry_id="id-1"))
            # After write, _last_hash should be a non-empty hash
            assert isinstance(adapter._last_hash, str)
            adapter.close()

    def test_repr_shows_backend_and_count(self) -> None:
        """__repr__ includes backend class name and entry count."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)
            adapter.write(_make_entry_dict(entry_id="id-1"))

            r = repr(adapter)
            assert "JSONLBackend" in r
            assert "1" in r
            adapter.close()


# ---------------------------------------------------------------------------
# Write exception wrapping → AuditError
# ---------------------------------------------------------------------------


class TestWriteExceptionWrapping:
    def test_backend_exception_wrapped_as_audit_error(self) -> None:
        """If the underlying backend raises, AuditError is raised instead."""
        mock_backend = MagicMock()
        mock_backend.record.side_effect = RuntimeError("disk full")

        adapter = AuditStoreBackendAdapter(mock_backend)

        with pytest.raises(AuditError, match="Failed to write"):
            adapter.write(_make_entry_dict())

    def test_audit_error_message_includes_original_error(self) -> None:
        """The AuditError message contains the original exception text."""
        mock_backend = MagicMock()
        mock_backend.record.side_effect = ValueError("connection lost")

        adapter = AuditStoreBackendAdapter(mock_backend)

        with pytest.raises(AuditError) as exc_info:
            adapter.write(_make_entry_dict())

        assert "connection lost" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Close error logging
# ---------------------------------------------------------------------------


class TestCloseErrorLogging:
    def test_close_error_is_logged_not_raised(self) -> None:
        """If backend.close() raises, a warning is logged, not re-raised."""
        mock_backend = MagicMock()
        mock_backend.close.side_effect = RuntimeError("close failed")

        adapter = AuditStoreBackendAdapter(mock_backend)

        # Should not raise — error is swallowed with a warning log
        adapter.close()

    def test_backend_without_close_method_is_fine(self) -> None:
        """If backend has no close() method, adapter.close() still works."""
        mock_backend = MagicMock(spec=[])  # no methods at all
        adapter = AuditStoreBackendAdapter(mock_backend)
        adapter.close()  # should not raise


# ---------------------------------------------------------------------------
# End-to-end: real backend integration
# ---------------------------------------------------------------------------


class TestAdapterEndToEnd:
    def test_write_then_read_via_auditor(self) -> None:
        """Full round-trip: write via adapter, read back via backend."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            entry_dict = _make_entry_dict(
                entry_id="round-trip-001",
                tool_name="calculator",
                decision="allowed",
                timestamp="2026-02-27T10:00:00+00:00",
            )
            adapter.write(entry_dict)

            entries = backend.list_entries()
            assert len(entries) == 1
            assert entries[0].tool_name == "calculator"
            adapter.close()

    def test_multiple_writes_form_chain(self) -> None:
        """Multiple writes should increment chain index."""
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = JSONLBackend(f"{tmpdir}/audit.jsonl")
            adapter = AuditStoreBackendAdapter(backend)

            for i in range(3):
                adapter.write(_make_entry_dict(entry_id=f"id-{i}", tool_name=f"tool_{i}"))

            entries = backend.list_entries()
            assert len(entries) == 3
            adapter.close()

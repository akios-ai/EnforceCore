"""Tests for pluggable audit backends."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from enforcecore.auditor.backends import (
    AuditBackend,
    CallbackBackend,
    JsonlBackend,
    MultiBackend,
    NullBackend,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_ENTRY: dict[str, Any] = {
    "tool_name": "search_web",
    "policy_name": "strict",
    "decision": "allowed",
    "call_id": "abc-123",
    "entry_hash": "hash1",
    "previous_hash": "hash0",
    "timestamp": "2025-01-01T00:00:00Z",
}


@pytest.fixture
def sample_entry() -> dict[str, Any]:
    return dict(SAMPLE_ENTRY)


# ---------------------------------------------------------------------------
# AuditBackend ABC
# ---------------------------------------------------------------------------


class TestAuditBackendABC:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            AuditBackend()  # type: ignore[abstract]

    def test_subclass_must_implement_write(self):
        class Incomplete(AuditBackend):
            def close(self) -> None:
                pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_subclass_must_implement_close(self):
        class Incomplete(AuditBackend):
            def write(self, entry_dict: dict[str, Any]) -> None:
                pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_concrete_subclass_works(self):
        class Custom(AuditBackend):
            def write(self, entry_dict: dict[str, Any]) -> None:
                pass

            def close(self) -> None:
                pass

        c = Custom()
        c.write({"test": True})
        c.close()

    def test_context_manager(self):
        class Custom(AuditBackend):
            closed = False

            def write(self, entry_dict: dict[str, Any]) -> None:
                pass

            def close(self) -> None:
                self.closed = True

        with Custom() as c:
            c.write({"test": True})
        assert c.closed is True


# ---------------------------------------------------------------------------
# JsonlBackend
# ---------------------------------------------------------------------------


class TestJsonlBackend:
    def test_creates_parent_directory(self, tmp_path: Path):
        path = tmp_path / "sub" / "dir" / "audit.jsonl"
        backend = JsonlBackend(path)
        assert path.parent.exists()
        assert backend.path == path

    def test_write_single_entry(self, tmp_path: Path, sample_entry: dict[str, Any]):
        path = tmp_path / "audit.jsonl"
        backend = JsonlBackend(path)
        backend.write(sample_entry)
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["tool_name"] == "search_web"

    def test_write_multiple_entries(self, tmp_path: Path, sample_entry: dict[str, Any]):
        path = tmp_path / "audit.jsonl"
        backend = JsonlBackend(path)
        for i in range(5):
            entry = dict(sample_entry, call_id=f"id-{i}")
            backend.write(entry)
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 5

    def test_append_mode(self, tmp_path: Path, sample_entry: dict[str, Any]):
        """New writes append to existing file."""
        path = tmp_path / "audit.jsonl"
        b1 = JsonlBackend(path)
        b1.write(sample_entry)
        b1.close()

        b2 = JsonlBackend(path)
        b2.write(dict(sample_entry, call_id="second"))
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_close_is_no_op(self, tmp_path: Path):
        backend = JsonlBackend(tmp_path / "audit.jsonl")
        backend.close()  # Should not raise

    def test_repr(self, tmp_path: Path):
        backend = JsonlBackend(tmp_path / "audit.jsonl")
        assert "JsonlBackend" in repr(backend)

    def test_compact_json(self, tmp_path: Path, sample_entry: dict[str, Any]):
        """Entries are written with compact separators (no spaces)."""
        path = tmp_path / "audit.jsonl"
        backend = JsonlBackend(path)
        backend.write(sample_entry)
        line = path.read_text().strip()
        # Compact separators: no spaces after , or :
        assert ": " not in line
        assert ", " not in line

    def test_context_manager_usage(self, tmp_path: Path, sample_entry: dict[str, Any]):
        path = tmp_path / "audit.jsonl"
        with JsonlBackend(path) as backend:
            backend.write(sample_entry)
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1


# ---------------------------------------------------------------------------
# NullBackend
# ---------------------------------------------------------------------------


class TestNullBackend:
    def test_discards_entries(self, sample_entry: dict[str, Any]):
        backend = NullBackend()
        backend.write(sample_entry)
        backend.write(sample_entry)
        backend.write(sample_entry)
        # No error, no output

    def test_entries_discarded_counter(self, sample_entry: dict[str, Any]):
        backend = NullBackend()
        assert backend.entries_discarded == 0
        backend.write(sample_entry)
        assert backend.entries_discarded == 1
        backend.write(sample_entry)
        assert backend.entries_discarded == 2

    def test_close_is_no_op(self):
        backend = NullBackend()
        backend.close()

    def test_repr(self):
        backend = NullBackend()
        assert "NullBackend" in repr(backend)


# ---------------------------------------------------------------------------
# CallbackBackend
# ---------------------------------------------------------------------------


class TestCallbackBackend:
    def test_sends_to_callback(self, sample_entry: dict[str, Any]):
        entries: list[dict[str, Any]] = []
        backend = CallbackBackend(entries.append)
        backend.write(sample_entry)
        assert len(entries) == 1
        assert entries[0]["tool_name"] == "search_web"

    def test_entries_sent_counter(self, sample_entry: dict[str, Any]):
        backend = CallbackBackend(lambda e: None)
        assert backend.entries_sent == 0
        backend.write(sample_entry)
        assert backend.entries_sent == 1

    def test_callback_error_without_handler_raises(self, sample_entry: dict[str, Any]):
        def bad_callback(entry: dict[str, Any]) -> None:
            msg = "callback broke"
            raise RuntimeError(msg)

        backend = CallbackBackend(bad_callback)
        with pytest.raises(RuntimeError, match="callback broke"):
            backend.write(sample_entry)

    def test_callback_error_with_handler(self, sample_entry: dict[str, Any]):
        def bad_callback(entry: dict[str, Any]) -> None:
            msg = "callback broke"
            raise RuntimeError(msg)

        errors: list[tuple[Exception, dict[str, Any]]] = []

        def error_handler(exc: Exception, entry: dict[str, Any]) -> None:
            errors.append((exc, entry))

        backend = CallbackBackend(bad_callback, on_error=error_handler)
        backend.write(sample_entry)  # Should not raise
        assert len(errors) == 1
        assert isinstance(errors[0][0], RuntimeError)

    def test_close_is_no_op(self):
        backend = CallbackBackend(lambda e: None)
        backend.close()

    def test_repr(self):
        backend = CallbackBackend(lambda e: None)
        assert "CallbackBackend" in repr(backend)

    def test_context_manager(self, sample_entry: dict[str, Any]):
        entries: list[dict[str, Any]] = []
        with CallbackBackend(entries.append) as backend:
            backend.write(sample_entry)
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# MultiBackend
# ---------------------------------------------------------------------------


class TestMultiBackend:
    def test_empty_backends_raises(self):
        with pytest.raises(ValueError, match="at least one"):
            MultiBackend([])

    def test_fan_out_to_multiple(self, tmp_path: Path, sample_entry: dict[str, Any]):
        entries: list[dict[str, Any]] = []
        jsonl_path = tmp_path / "audit.jsonl"
        multi = MultiBackend(
            [
                JsonlBackend(jsonl_path),
                CallbackBackend(entries.append),
            ]
        )
        multi.write(sample_entry)

        # Both backends should have received the entry
        assert len(entries) == 1
        lines = jsonl_path.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_error_in_one_does_not_break_others(self, sample_entry: dict[str, Any]):
        entries: list[dict[str, Any]] = []

        def bad_callback(entry: dict[str, Any]) -> None:
            msg = "fail"
            raise RuntimeError(msg)

        multi = MultiBackend(
            [
                CallbackBackend(bad_callback, on_error=lambda e, d: None),
                CallbackBackend(entries.append),
            ]
        )
        # The first backend will log an error but the second should still work
        multi.write(sample_entry)
        assert len(entries) == 1

    def test_close_all(self):
        closed: list[bool] = []

        class TrackClose(AuditBackend):
            def write(self, entry_dict: dict[str, Any]) -> None:
                pass

            def close(self) -> None:
                closed.append(True)

        multi = MultiBackend([TrackClose(), TrackClose(), TrackClose()])
        multi.close()
        assert len(closed) == 3

    def test_backend_count(self):
        multi = MultiBackend([NullBackend(), NullBackend()])
        assert multi.backend_count == 2

    def test_repr(self):
        multi = MultiBackend([NullBackend()])
        assert "MultiBackend" in repr(multi)

    def test_write_to_null_and_jsonl(self, tmp_path: Path, sample_entry: dict[str, Any]):
        """Combine NullBackend and JsonlBackend in a MultiBackend."""
        null = NullBackend()
        jsonl = JsonlBackend(tmp_path / "audit.jsonl")
        multi = MultiBackend([null, jsonl])

        for i in range(3):
            multi.write(dict(sample_entry, call_id=f"id-{i}"))

        assert null.entries_discarded == 3
        lines = (tmp_path / "audit.jsonl").read_text().strip().split("\n")
        assert len(lines) == 3


# ---------------------------------------------------------------------------
# Auditor integration with backends
# ---------------------------------------------------------------------------


class TestAuditorBackendIntegration:
    def test_auditor_with_jsonl_backend(self, tmp_path: Path):
        from enforcecore.auditor.engine import Auditor

        path = tmp_path / "audit.jsonl"
        backend = JsonlBackend(path)
        auditor = Auditor(backend=backend)

        auditor.record(
            tool_name="test_tool",
            policy_name="test_policy",
            policy_version="1.0",
            decision="allowed",
            call_id="test-call-1",
            overhead_ms=1.5,
            call_duration_ms=10.0,
            input_redactions=0,
            output_redactions=0,
        )

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["tool_name"] == "test_tool"
        assert entry["decision"] == "allowed"

    def test_auditor_with_null_backend(self):
        from enforcecore.auditor.engine import Auditor

        backend = NullBackend()
        auditor = Auditor(backend=backend)

        auditor.record(
            tool_name="test_tool",
            policy_name="test_policy",
            policy_version="1.0",
            decision="allowed",
            call_id="test-call-1",
            overhead_ms=1.5,
            call_duration_ms=10.0,
            input_redactions=0,
            output_redactions=0,
        )

        assert backend.entries_discarded == 1

    def test_auditor_with_callback_backend(self):
        from enforcecore.auditor.engine import Auditor

        entries: list[dict[str, Any]] = []
        backend = CallbackBackend(entries.append)
        auditor = Auditor(backend=backend)

        auditor.record(
            tool_name="test_tool",
            policy_name="test_policy",
            policy_version="1.0",
            decision="blocked",
            call_id="test-call-1",
            violation_type="tool_not_allowed",
            violation_reason="Not permitted",
            overhead_ms=0.5,
            call_duration_ms=0.0,
            input_redactions=0,
            output_redactions=0,
        )

        assert len(entries) == 1
        assert entries[0]["decision"] == "blocked"
        assert entries[0]["violation_type"] == "tool_not_allowed"

    def test_auditor_requires_path_or_backend(self):
        from enforcecore.auditor.engine import Auditor
        from enforcecore.core.types import AuditError

        with pytest.raises(AuditError, match="Either output_path or backend"):
            Auditor()

    def test_auditor_backend_property(self):
        from enforcecore.auditor.engine import Auditor

        backend = NullBackend()
        auditor = Auditor(backend=backend)
        assert auditor.backend is backend

    def test_auditor_chain_integrity_with_backend(self):
        from enforcecore.auditor.engine import Auditor

        entries: list[dict[str, Any]] = []
        backend = CallbackBackend(entries.append)
        auditor = Auditor(backend=backend)

        # Write 3 entries
        for i in range(3):
            auditor.record(
                tool_name=f"tool_{i}",
                policy_name="policy",
                policy_version="1.0",
                decision="allowed",
                call_id=f"call-{i}",
                overhead_ms=1.0,
                call_duration_ms=5.0,
                input_redactions=0,
                output_redactions=0,
            )

        assert len(entries) == 3
        # Each entry should have a hash chain
        assert entries[0]["previous_hash"] is not None
        for i in range(1, 3):
            assert entries[i]["previous_hash"] == entries[i - 1]["entry_hash"]

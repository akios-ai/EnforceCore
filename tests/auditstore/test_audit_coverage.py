# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Coverage gap tests for auditor/engine.py, auditstore/reports, and queries."""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.auditor.engine import (
    AuditEntry,
    Auditor,
    load_trail,
    verify_trail,
)
from enforcecore.auditstore.backends.jsonl import JSONLBackend
from enforcecore.auditstore.backends.sqlite import SQLiteBackend
from enforcecore.auditstore.core import AuditEntry as StoreEntry
from enforcecore.auditstore.core import AuditStore
from enforcecore.auditstore.queries.eu_ai_act import EUAIActQueries
from enforcecore.auditstore.reports.generator import Report, ReportGenerator
from enforcecore.core.types import AuditError

# ──────────────────────────────────────────────────────────────────────────────
# AuditEntry.to_dict() — non-JSON-safe error path (engine.py lines 125-126)
# ──────────────────────────────────────────────────────────────────────────────


class TestAuditEntryToDictError:
    def test_non_json_safe_raises_audit_error(self) -> None:
        """to_dict() raises AuditError when entry contains non-serialisable data."""
        entry = AuditEntry(tool_name="t", policy_name="p")
        entry.seal()
        with (
            patch(
                "enforcecore.auditor.engine.json.dumps",
                side_effect=TypeError("not serializable"),
            ),
            pytest.raises(AuditError, match="non-JSON-safe"),
        ):
            entry.to_dict()


# ──────────────────────────────────────────────────────────────────────────────
# Auditor.log() — convenience wrapper (engine.py line 480)
# ──────────────────────────────────────────────────────────────────────────────


class TestAuditorLog:
    def test_log_is_alias_for_record(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=trail)
        entry = auditor.log("my_tool", "my_policy", decision="allowed")
        assert entry.tool_name == "my_tool"
        assert entry.policy_name == "my_policy"
        assert trail.exists()


# ──────────────────────────────────────────────────────────────────────────────
# Auditor.verify() (engine.py lines 501-505)
# ──────────────────────────────────────────────────────────────────────────────


class TestAuditorVerify:
    def test_verify_without_output_path_raises(self) -> None:
        """verify() raises AuditError when no output_path configured."""
        from enforcecore.auditstore import AuditStoreBackendAdapter
        from enforcecore.auditstore.backends import JSONLBackend as StoreJSONL

        with tempfile.TemporaryDirectory() as tmpdir:
            backend = StoreJSONL(str(Path(tmpdir) / "a.jsonl"))
            adapter = AuditStoreBackendAdapter(backend)
            auditor = Auditor(backend=adapter)
            with pytest.raises(AuditError, match="backend"):
                auditor.verify()

    def test_verify_with_output_path_returns_result(self, tmp_path: Path) -> None:
        """verify() returns a VerificationResult for a valid trail."""
        trail = tmp_path / "verify_trail.jsonl"
        auditor = Auditor(output_path=trail)
        auditor.record(tool_name="search", policy_name="strict")
        result = auditor.verify()
        assert result.is_valid
        assert result.total_entries == 1


# ──────────────────────────────────────────────────────────────────────────────
# _apply_immutable() exception paths (engine.py lines 345-357)
# ──────────────────────────────────────────────────────────────────────────────


class TestApplyImmutable:
    def test_append_only_error_is_logged_as_warning(self, tmp_path: Path) -> None:
        """AppendOnlyError is caught and logged; recording continues."""
        from enforcecore.auditor.immutable import AppendOnlyError

        trail = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=trail)
        with patch(
            "enforcecore.auditor.immutable.protect_append_only",
            side_effect=AppendOnlyError("chflags failed"),
        ):
            # Should not raise; warning is issued internally
            entry = auditor.record(tool_name="tool", policy_name="policy")
        assert entry.tool_name == "tool"

    def test_unexpected_exception_is_logged_as_warning(self, tmp_path: Path) -> None:
        """Unexpected Exception in _apply_immutable is caught and logged."""
        trail = tmp_path / "trail2.jsonl"
        auditor = Auditor(output_path=trail)
        with patch(
            "enforcecore.auditor.immutable.protect_append_only",
            side_effect=OSError("unexpected OS error"),
        ):
            entry = auditor.record(tool_name="tool", policy_name="policy")
        assert entry.policy_name == "policy"


# ──────────────────────────────────────────────────────────────────────────────
# load_trail() edge cases (engine.py lines 687, 695-696)
# ──────────────────────────────────────────────────────────────────────────────


class TestLoadTrail:
    def _make_trail(self, path: Path, n: int) -> list[AuditEntry]:
        auditor = Auditor(output_path=path)
        entries = []
        for i in range(n):
            entries.append(auditor.record(tool_name=f"tool_{i}", policy_name="policy"))
        return entries

    def test_invalid_json_raises_audit_error(self, tmp_path: Path) -> None:
        trail = tmp_path / "bad.jsonl"
        trail.write_text('{"entry_id": "abc"}\nNOT JSON\n')
        with pytest.raises(AuditError, match="Invalid entry"):
            load_trail(trail)

    def test_max_entries_slices_to_last_n(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        self._make_trail(trail, 5)
        entries = load_trail(trail, max_entries=3)
        assert len(entries) == 3
        # Should be the last 3 entries (most recent)
        assert entries[-1].tool_name == "tool_4"

    def test_nonexistent_file_raises_audit_error(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.jsonl"
        with pytest.raises(AuditError, match="not found"):
            load_trail(missing)


# ──────────────────────────────────────────────────────────────────────────────
# verify_trail() error paths (engine.py lines 597, 604-642)
# ──────────────────────────────────────────────────────────────────────────────


class TestVerifyTrail:
    def _write_entries(self, path: Path, n: int = 2) -> None:
        auditor = Auditor(output_path=path)
        for i in range(n):
            auditor.record(tool_name=f"tool_{i}", policy_name="policy")

    def test_hash_mismatch_detected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        self._write_entries(trail, 2)

        # Corrupt the entry_hash in the second line
        lines = trail.read_text().splitlines()
        data = json.loads(lines[0])
        data["entry_hash"] = "0" * 64  # forge the hash
        lines[0] = json.dumps(data)
        trail.write_text("\n".join(lines) + "\n")

        result = verify_trail(trail)
        assert not result.is_valid
        assert any("hash mismatch" in e for e in result.errors)

    def test_chain_broken_detected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        self._write_entries(trail, 2)

        # Corrupt the previous_hash in the second entry
        lines = trail.read_text().splitlines()
        data = json.loads(lines[1])
        data["previous_hash"] = "a" * 64  # wrong prev hash
        # Re-compute entry_hash for this line so hash check passes but chain check fails
        # Actually, just leave the wrong previous_hash and forged entry_hash won't match
        # The hash mismatch will fire first, which also sets chain_intact=False
        # So instead let's fix the entry_hash to match the corrupted content
        import hashlib

        payload = json.dumps({k: v for k, v in data.items() if k != "entry_hash"}, sort_keys=True)
        data["entry_hash"] = hashlib.sha256(payload.encode()).hexdigest()
        lines[1] = json.dumps(data)
        trail.write_text("\n".join(lines) + "\n")

        result = verify_trail(trail)
        assert not result.is_valid
        assert not result.chain_intact

    def test_blank_lines_are_skipped(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        self._write_entries(trail, 1)
        # Append a blank line
        with trail.open("a") as f:
            f.write("\n\n")
        result = verify_trail(trail)
        assert result.is_valid
        assert result.total_entries == 1

    def test_invalid_json_line_recorded_as_error(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        self._write_entries(trail, 1)
        with trail.open("a") as f:
            f.write("INVALID JSON\n")
        result = verify_trail(trail)
        assert not result.is_valid
        assert any("invalid JSON" in e for e in result.errors)


# ──────────────────────────────────────────────────────────────────────────────
# Report.save / __str__ / render  (generator.py lines 22, 26-27, 31)
# ──────────────────────────────────────────────────────────────────────────────


class TestReport:
    def test_render_returns_content(self) -> None:
        r = Report("My Title", "<h1>hello</h1>", format="html")
        assert r.render() == "<h1>hello</h1>"

    def test_save_writes_file(self, tmp_path: Path) -> None:
        r = Report("My Title", "body text", format="html")
        out = tmp_path / "report.html"
        r.save(str(out))
        assert out.read_text() == "body text"

    def test_str_representation(self) -> None:
        r = Report("My Title", "x", format="json")
        s = str(r)
        assert "My Title" in s
        assert "json" in s


# ──────────────────────────────────────────────────────────────────────────────
# ReportGenerator unsupported format (generator.py line 83)
# ──────────────────────────────────────────────────────────────────────────────


class TestReportGeneratorUnsupportedFormat:
    def test_unsupported_format_raises_value_error(self, tmp_path: Path) -> None:
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend)
        gen = ReportGenerator(store)
        with pytest.raises(ValueError, match="Unsupported format"):
            gen.generate_eu_ai_act_report("AcmeCorp", "Q1 2026", format="xml")


# ──────────────────────────────────────────────────────────────────────────────
# _parse_period() fallback (generator.py lines 349-353)
# ──────────────────────────────────────────────────────────────────────────────


class TestParsePeriodFallback:
    def test_unknown_period_string_falls_back_to_30_days(self, tmp_path: Path) -> None:
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        store = AuditStore(backend)
        gen = ReportGenerator(store)
        # "custom" is not a recognised period string → falls back to last 30 days
        report = gen.generate_eu_ai_act_report("AcmeCorp", "custom-period", format="json")
        data = json.loads(report.content)
        # The date range should span roughly 30 days
        start = datetime.fromisoformat(data["start_date"])
        end = datetime.fromisoformat(data["end_date"])
        assert (end - start).days >= 29


# ──────────────────────────────────────────────────────────────────────────────
# EUAIActQueries.pii_exposure_summary with redacted_categories (line 147)
# ──────────────────────────────────────────────────────────────────────────────


class TestPiiExposureSummary:
    def _make_store(self, tmp_path: Path) -> AuditStore:
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        return AuditStore(backend)

    def test_redacted_categories_aggregated(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        now = datetime.now(tz=UTC)
        # Insert entries directly via backend to control redacted_categories
        e1 = StoreEntry.create(
            policy_name="p",
            policy_version="1.0",
            tool_name="t",
            decision="redacted",
            call_duration_ms=1.0,
            enforcement_overhead_ms=0.1,
            input_redactions=2,
            output_redactions=1,
            redacted_categories=["email", "phone"],
        )
        e2 = StoreEntry.create(
            policy_name="p",
            policy_version="1.0",
            tool_name="t",
            decision="redacted",
            call_duration_ms=1.0,
            enforcement_overhead_ms=0.1,
            input_redactions=1,
            output_redactions=0,
            redacted_categories=["email"],
        )
        store.backend.record(e1)
        store.backend.record(e2)

        queries = EUAIActQueries(store)
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)
        result = queries.pii_exposure_summary(start, end)

        assert result["redactions_by_category"]["email"] == 2
        assert result["redactions_by_category"]["phone"] == 1
        assert result["total_pii_redactions"] == 4  # (2+1) + (1+0)


# ──────────────────────────────────────────────────────────────────────────────
# EUAIActQueries.cost_analysis with cost_usd (lines 205-207)
# ──────────────────────────────────────────────────────────────────────────────


class TestCostAnalysis:
    def _make_store(self, tmp_path: Path) -> AuditStore:
        backend = JSONLBackend(str(tmp_path / "audit.jsonl"))
        return AuditStore(backend)

    def test_cost_aggregated_per_tool(self, tmp_path: Path) -> None:
        store = self._make_store(tmp_path)
        now = datetime.now(tz=UTC)
        e1 = StoreEntry.create(
            policy_name="p",
            policy_version="1.0",
            tool_name="search",
            decision="allowed",
            call_duration_ms=5.0,
            enforcement_overhead_ms=0.2,
            cost_usd=0.01,
        )
        e2 = StoreEntry.create(
            policy_name="p",
            policy_version="1.0",
            tool_name="search",
            decision="allowed",
            call_duration_ms=5.0,
            enforcement_overhead_ms=0.2,
            cost_usd=0.02,
        )
        e3 = StoreEntry.create(
            policy_name="p",
            policy_version="1.0",
            tool_name="llm",
            decision="allowed",
            call_duration_ms=10.0,
            enforcement_overhead_ms=0.3,
            cost_usd=0.05,
        )
        store.backend.record(e1)
        store.backend.record(e2)
        store.backend.record(e3)

        queries = EUAIActQueries(store)
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)
        result = queries.cost_analysis(start, end)

        assert result["total_cost_usd"] == pytest.approx(0.08, abs=1e-6)
        assert result["cost_by_tool"]["search"] == pytest.approx(0.03, abs=1e-6)
        assert result["cost_by_tool"]["llm"] == pytest.approx(0.05, abs=1e-6)
        assert result["entries_tracked"] == 3


# ---------------------------------------------------------------------------
# AuditEntry.to_dict() — non-JSON-safe data path
# ---------------------------------------------------------------------------


class TestAuditEntryToDict:
    """Tests for AuditEntry.to_dict() error path (lines 125-126)."""

    def test_to_dict_non_json_safe_raises(self) -> None:
        """AuditEntry.to_dict() raises AuditError when dict is not JSON-safe."""
        entry = AuditEntry(tool_name="test", policy_name="p")
        # Patch json.dumps inside engine.py to simulate a non-JSON-safe dict
        with (
            patch(
                "enforcecore.auditor.engine.json.dumps",
                side_effect=TypeError("not serializable"),
            ),
            pytest.raises(AuditError, match="non-JSON-safe"),
        ):
            entry.to_dict()

    def test_to_dict_value_error_in_json(self) -> None:
        """AuditEntry.to_dict() wraps ValueError from json.dumps."""
        entry = AuditEntry(tool_name="test", policy_name="p")
        with (
            patch("enforcecore.auditor.engine.json.dumps", side_effect=ValueError("bad value")),
            pytest.raises(AuditError, match="non-JSON-safe"),
        ):
            entry.to_dict()

    def test_to_dict_normal_works(self) -> None:
        """AuditEntry.to_dict() returns a dict for normal entries."""
        entry = AuditEntry(tool_name="tool", policy_name="pol", decision="allowed")
        d = entry.to_dict()
        assert d["tool_name"] == "tool"
        assert d["policy_name"] == "pol"


# ---------------------------------------------------------------------------
# Auditor.log() convenience wrapper (line 480)
# ---------------------------------------------------------------------------


class TestAuditorLogExtended:
    """Tests for Auditor.log() method (line 480)."""

    def test_log_calls_record(self, tmp_path: Path) -> None:
        """Auditor.log() is a convenience wrapper around record()."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        entry = auditor.log(tool_name="search_web", policy_name="strict")
        assert entry.tool_name == "search_web"
        assert entry.policy_name == "strict"
        assert entry.decision == "allowed"  # default

    def test_log_with_blocked_decision(self, tmp_path: Path) -> None:
        """Auditor.log() passes kwargs to record()."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        entry = auditor.log(
            tool_name="run_sql",
            policy_name="strict",
            decision="blocked",
            violation_reason="injection detected",
        )
        assert entry.decision == "blocked"
        assert entry.violation_reason == "injection detected"


# ---------------------------------------------------------------------------
# Auditor.verify() (lines 501-505)
# ---------------------------------------------------------------------------


class TestAuditorVerifyExtended:
    """Tests for Auditor.verify() — lines 501-505."""

    def test_verify_without_output_path_raises(self) -> None:
        """verify() raises AuditError when no output_path is configured."""
        backend = MagicMock()
        auditor = Auditor(backend=backend)
        with pytest.raises(AuditError, match="Cannot verify"):
            auditor.verify()

    def test_verify_with_output_path_works(self, tmp_path: Path) -> None:
        """verify() delegates to verify_trail() when output_path is set."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="tool", policy_name="pol")
        result = auditor.verify()
        assert result.is_valid
        assert result.total_entries == 1


# ---------------------------------------------------------------------------
# _apply_immutable — exception paths (lines 345-353)
# ---------------------------------------------------------------------------


class TestApplyImmutableExtended:
    """Tests for _apply_immutable exception handling."""

    def test_append_only_error_logged_not_raised(self, tmp_path: Path) -> None:
        """AppendOnlyError in _apply_immutable is logged, not re-raised."""
        from enforcecore.auditor.immutable import AppendOnlyError

        audit_file = tmp_path / "trail.jsonl"
        with patch(
            "enforcecore.auditor.immutable.protect_append_only",
            side_effect=AppendOnlyError("no perm"),
        ):
            # Should not raise — just log a warning
            auditor = Auditor(output_path=audit_file, immutable=True)
        # The Auditor should still work
        entry = auditor.record(tool_name="t", policy_name="p")
        assert entry.entry_hash != ""

    def test_unexpected_error_in_apply_immutable_logged(self, tmp_path: Path) -> None:
        """Unexpected Exception in _apply_immutable is logged, not re-raised."""
        audit_file = tmp_path / "trail.jsonl"
        with patch(
            "enforcecore.auditor.immutable.protect_append_only",
            side_effect=RuntimeError("unexpected"),
        ):
            auditor = Auditor(output_path=audit_file, immutable=True)
        assert auditor is not None


# ---------------------------------------------------------------------------
# load_trail() edge cases (lines 687, 695-696)
# ---------------------------------------------------------------------------


class TestLoadTrailExtended:
    """Tests for load_trail() edge cases."""

    def test_load_trail_invalid_json_raises(self, tmp_path: Path) -> None:
        """load_trail() raises AuditError on invalid JSON line."""
        bad_file = tmp_path / "bad.jsonl"
        bad_file.write_text('{"valid": "line"}\nnot json at all\n')
        with pytest.raises(AuditError, match="Invalid entry at line"):
            load_trail(bad_file)

    def test_load_trail_with_max_entries(self, tmp_path: Path) -> None:
        """load_trail() with max_entries returns only the last N entries."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        for i in range(5):
            auditor.record(tool_name=f"tool_{i}", policy_name="pol")

        all_entries = load_trail(audit_file)
        assert len(all_entries) == 5

        last_three = load_trail(audit_file, max_entries=3)
        assert len(last_three) == 3
        assert last_three[0].tool_name == "tool_2"
        assert last_three[-1].tool_name == "tool_4"

    def test_load_trail_nonexistent_raises(self, tmp_path: Path) -> None:
        """load_trail() raises AuditError when file does not exist."""
        with pytest.raises(AuditError, match="not found"):
            load_trail(tmp_path / "nonexistent.jsonl")


# ---------------------------------------------------------------------------
# verify_trail() error paths (lines 597, 640-642)
# ---------------------------------------------------------------------------


class TestVerifyTrailExtended:
    """Tests for verify_trail() — hash mismatch, chain broken, OSError."""

    def test_hash_mismatch_detected(self, tmp_path: Path) -> None:
        """verify_trail() detects when stored hash doesn't match computed hash."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="t", policy_name="p")

        # Corrupt the stored hash in the file
        lines = audit_file.read_text().splitlines()
        data = json.loads(lines[0])
        data["entry_hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        audit_file.write_text(json.dumps(data) + "\n")

        result = verify_trail(audit_file)
        assert not result.is_valid
        assert any("hash mismatch" in e for e in result.errors)

    def test_chain_broken_detected(self, tmp_path: Path) -> None:
        """verify_trail() detects when previous_hash linkage is broken."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="t1", policy_name="p")
        auditor.record(tool_name="t2", policy_name="p")

        # Corrupt the previous_hash of the second entry
        lines = audit_file.read_text().splitlines()
        assert len(lines) == 2
        data1 = json.loads(lines[0])
        data2 = json.loads(lines[1])
        # Recompute entry2 with wrong previous_hash
        data2["previous_hash"] = "deadbeef" * 8
        data2["entry_hash"] = "0000" * 16  # also mangle so chain check fires
        audit_file.write_text(json.dumps(data1) + "\n" + json.dumps(data2) + "\n")

        result = verify_trail(audit_file)
        assert not result.is_valid

    def test_empty_lines_skipped(self, tmp_path: Path) -> None:
        """verify_trail() skips blank lines gracefully (line 597)."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="t", policy_name="p")
        # Append blank lines
        with audit_file.open("a") as f:
            f.write("\n\n\n")

        result = verify_trail(audit_file)
        assert result.is_valid
        assert result.total_entries == 1

    def test_invalid_json_line_in_trail(self, tmp_path: Path) -> None:
        """verify_trail() marks trail as invalid when a line is not JSON."""
        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file)
        auditor.record(tool_name="t", policy_name="p")
        with audit_file.open("a") as f:
            f.write("this is not json\n")

        result = verify_trail(audit_file)
        assert not result.is_valid
        assert any("invalid JSON" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Report.save() and Report.__str__() (lines 22, 26-27, 31)
# ---------------------------------------------------------------------------


class TestReportExtended:
    """Tests for Report.save() and Report.__str__()."""

    def test_report_save(self, tmp_path: Path) -> None:
        """Report.save() writes content to a file."""
        report = Report(title="Test Report", content="hello world", format="html")
        output = tmp_path / "report.html"
        report.save(str(output))
        assert output.read_text() == "hello world"

    def test_report_str(self) -> None:
        """Report.__str__() returns a descriptive string."""
        report = Report(title="EU AI Act Report", content="...", format="json")
        s = str(report)
        assert "EU AI Act Report" in s
        assert "json" in s

    def test_report_render(self) -> None:
        """Report.render() returns the content string."""
        report = Report(title="T", content="content here", format="html")
        assert report.render() == "content here"


# ---------------------------------------------------------------------------
# ReportGenerator — unsupported format ValueError (line 83)
# ---------------------------------------------------------------------------


class TestReportGeneratorErrors:
    """Tests for ReportGenerator error paths."""

    def test_unsupported_format_raises(self, tmp_path: Path) -> None:
        """generate_eu_ai_act_report() raises ValueError for unknown format."""
        db_path = tmp_path / "audit.db"
        backend = SQLiteBackend(str(db_path))
        store = AuditStore(backend=backend)
        gen = ReportGenerator(store)
        with pytest.raises(ValueError, match="Unsupported format"):
            gen.generate_eu_ai_act_report(
                organization="Test Org",
                period="Q1 2026",
                format="xml",  # unsupported
            )


# ---------------------------------------------------------------------------
# _parse_period fallback — default 30 days (lines 345-353 in generator)
# ---------------------------------------------------------------------------


class TestParsePeriodFallbackExtended:
    """Tests for ReportGenerator._parse_period fallback path."""

    def test_parse_period_unknown_returns_last_30_days(self, tmp_path: Path) -> None:
        """Unknown period string falls back to last 30 days."""
        db_path = tmp_path / "audit.db"
        backend = SQLiteBackend(str(db_path))
        store = AuditStore(backend=backend)
        gen = ReportGenerator(store)
        # A period string that doesn't match any known format
        start, end = gen._parse_period("Random Period 2026")
        # Should be about 30 days apart
        delta = end - start
        assert abs(delta.days - 30) <= 1


# ---------------------------------------------------------------------------
# EUAIActQueries — pii_exposure_summary with redacted_categories (line 147)
# and cost_analysis with cost_usd (lines 205-207)
# ---------------------------------------------------------------------------


class TestEUAIActQueriesCoverage:
    """Coverage tests for EU AI Act query methods with populated fields."""

    def _make_store_with_entries(self, tmp_path: Path) -> AuditStore:
        db_path = tmp_path / "audit.db"
        backend = SQLiteBackend(str(db_path))
        return AuditStore(backend=backend)

    def test_pii_exposure_summary_with_redacted_categories(self, tmp_path: Path) -> None:
        """pii_exposure_summary processes entries with non-empty redacted_categories (line 147)."""
        store = self._make_store_with_entries(tmp_path)
        # Add entries with redacted_categories populated
        entry = StoreEntry.create(
            tool_name="scan_docs",
            policy_name="pii-policy",
            policy_version="1.0",
            decision="redacted",
            call_duration_ms=1.0,
            enforcement_overhead_ms=0.1,
            input_redactions=2,
            output_redactions=0,
            redacted_categories=["EMAIL", "PHONE"],
        )
        store.backend.record(entry)

        entry2 = StoreEntry.create(
            tool_name="scan_docs",
            policy_name="pii-policy",
            policy_version="1.0",
            decision="redacted",
            call_duration_ms=1.0,
            enforcement_overhead_ms=0.1,
            input_redactions=1,
            output_redactions=0,
            redacted_categories=["EMAIL"],
        )
        store.backend.record(entry2)

        queries = EUAIActQueries(store)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        end = datetime(2030, 1, 1, tzinfo=UTC)
        result = queries.pii_exposure_summary(start, end)

        assert result["total_pii_redactions"] == 3
        # The category loop (line 147) should have populated this
        assert "EMAIL" in result["redactions_by_category"]
        assert result["redactions_by_category"]["EMAIL"] == 2
        assert "PHONE" in result["redactions_by_category"]
        assert result["redactions_by_category"]["PHONE"] == 1

    def test_cost_analysis_with_cost_usd(self, tmp_path: Path) -> None:
        """cost_analysis handles entries with cost_usd set (lines 205-207)."""
        store = self._make_store_with_entries(tmp_path)
        entry = StoreEntry.create(
            tool_name="gpt4_call",
            policy_name="cost-policy",
            policy_version="1.0",
            decision="allowed",
            call_duration_ms=10.0,
            enforcement_overhead_ms=0.5,
            cost_usd=0.05,
        )
        store.backend.record(entry)

        entry2 = StoreEntry.create(
            tool_name="gpt4_call",
            policy_name="cost-policy",
            policy_version="1.0",
            decision="allowed",
            call_duration_ms=10.0,
            enforcement_overhead_ms=0.5,
            cost_usd=0.10,
        )
        store.backend.record(entry2)

        queries = EUAIActQueries(store)
        start = datetime(2020, 1, 1, tzinfo=UTC)
        end = datetime(2030, 1, 1, tzinfo=UTC)
        result = queries.cost_analysis(start, end)

        assert result["total_cost_usd"] == pytest.approx(0.15, abs=0.001)
        assert "gpt4_call" in result["cost_by_tool"]
        assert result["entries_tracked"] == 2

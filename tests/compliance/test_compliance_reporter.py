# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.8.0 Compliance Reporting features.

Covers:
- CompliancePeriod.from_label — quarterly, half-year, full-year
- CompliancePeriod.from_dates — explicit dates, validation
- CompliancePeriod.contains — in / out of range
- ComplianceFormat — StrEnum values
- ComplianceReport — serialization (to_dict, to_json)
- ComplianceReport — __str__
- ComplianceReporter.__init__ — with and without trail_path
- ComplianceReporter.export — empty trail (no file)
- ComplianceReporter.export — zero entries (period mismatch)
- ComplianceReporter.export — eu-ai-act narratives populated
- ComplianceReporter.export — soc2 narratives populated
- ComplianceReporter.export — gdpr narratives populated
- ComplianceReporter.export — violations counted correctly
- ComplianceReporter.export — pii_redactions summed correctly
- ComplianceReporter.export — policy_versions collected
- ComplianceReporter.export — tool_names collected
- ComplianceReporter.export — tenant_ids collected
- ComplianceReporter.export — compliance_score = (total - violations) / total
- ComplianceReporter.export — compliance_score = 1.0 for zero calls
- ComplianceReporter.export_json — writes valid JSON file
- ComplianceReporter.export_html — writes HTML file with key sections
- ComplianceReporter.export_json — bad output path raises ComplianceError
- ComplianceReporter.send_webhook — success (mock HTTP server)
- ComplianceReporter.send_webhook — HTTP 4xx raises ComplianceError
- ComplianceReporter.send_webhook — network error raises ComplianceError
- ComplianceReporter.__repr__
- ComplianceError — exception hierarchy
- ComplianceError in enforcecore.__all__
- ComplianceFormat in enforcecore.__all__
- CompliancePeriod in enforcecore.__all__
- ComplianceReport in enforcecore.__all__
- ComplianceReporter in enforcecore.__all__
- ComplianceReporter — entries without timestamp included
- ComplianceReporter — malformed JSON lines skipped
- ComplianceReporter — entries outside period excluded
- ComplianceReporter — unreadable trail raises ComplianceError
- CLI: audit export command registered
- CLI: audit export --format eu-ai-act --period 2026-Q4 stdout output
- CLI: audit export invalid format exits with code 1
- CLI: audit export invalid period exits with code 1
- CLI: audit export --output writes file
- CLI: audit export --html --output writes HTML file
"""

from __future__ import annotations

import http.server
import json
import threading
from datetime import UTC, datetime
from http import HTTPStatus
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path

import enforcecore
from enforcecore.compliance.reporter import ComplianceReporter
from enforcecore.compliance.types import (
    ComplianceError,
    ComplianceFormat,
    CompliancePeriod,
    ComplianceReport,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
    *,
    decision: str = "allowed",
    tool_name: str = "search_web",
    policy_name: str = "default",
    policy_version: str = "1.0",
    input_redactions: int = 0,
    output_redactions: int = 0,
    timestamp: str | None = None,
    tenant_id: str | None = None,
) -> dict:
    if timestamp is None:
        timestamp = "2026-11-15T10:00:00+00:00"
    entry: dict = {
        "entry_id": "fake-entry-id",
        "call_id": "fake-call-id",
        "timestamp": timestamp,
        "tool_name": tool_name,
        "policy_name": policy_name,
        "policy_version": policy_version,
        "decision": decision,
        "input_redactions": input_redactions,
        "output_redactions": output_redactions,
    }
    if tenant_id:
        entry["tenant_id"] = tenant_id
    return entry


def _write_trail(path: Path, entries: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for e in entries:
            fh.write(json.dumps(e) + "\n")


# ---------------------------------------------------------------------------
# CompliancePeriod
# ---------------------------------------------------------------------------


class TestCompliancePeriodFromLabel:
    def test_quarterly_q1(self) -> None:
        p = CompliancePeriod.from_label("2026-Q1")
        assert p.start == datetime(2026, 1, 1, tzinfo=UTC)
        assert p.end == datetime(2026, 3, 31, 23, 59, 59, tzinfo=UTC)
        assert p.label == "2026-Q1"

    def test_quarterly_q4(self) -> None:
        p = CompliancePeriod.from_label("2026-Q4")
        assert p.start == datetime(2026, 10, 1, tzinfo=UTC)
        assert p.end == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)

    def test_half_year_h1(self) -> None:
        p = CompliancePeriod.from_label("2026-H1")
        assert p.start == datetime(2026, 1, 1, tzinfo=UTC)
        assert p.end == datetime(2026, 6, 30, 23, 59, 59, tzinfo=UTC)

    def test_half_year_h2(self) -> None:
        p = CompliancePeriod.from_label("2026-H2")
        assert p.start == datetime(2026, 7, 1, tzinfo=UTC)
        assert p.end == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)

    def test_full_year(self) -> None:
        p = CompliancePeriod.from_label("2026")
        assert p.start == datetime(2026, 1, 1, tzinfo=UTC)
        assert p.end == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)

    def test_invalid_format_raises(self) -> None:
        with pytest.raises(ValueError, match="Unrecognized"):
            CompliancePeriod.from_label("2026-M03")

    def test_invalid_quarter_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid quarter"):
            CompliancePeriod.from_label("2026-Q5")

    def test_invalid_half_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid half"):
            CompliancePeriod.from_label("2026-H3")

    def test_invalid_year_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid period"):
            CompliancePeriod.from_label("notayear-Q1")

    def test_label_whitespace_stripped(self) -> None:
        p = CompliancePeriod.from_label("  2026-Q2  ")
        assert p.label == "2026-Q2"


class TestCompliancePeriodFromDates:
    def test_from_dates_basic(self) -> None:
        start = datetime(2026, 4, 1, tzinfo=UTC)
        end = datetime(2026, 6, 30, tzinfo=UTC)
        p = CompliancePeriod.from_dates(start, end, label="2026-Q2-custom")
        assert p.start == start
        assert p.end == end
        assert p.label == "2026-Q2-custom"

    def test_from_dates_auto_label(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=UTC)
        end = datetime(2026, 3, 31, tzinfo=UTC)
        p = CompliancePeriod.from_dates(start, end)
        assert "2026-01-01" in p.label
        assert "2026-03-31" in p.label

    def test_from_dates_end_before_start_raises(self) -> None:
        start = datetime(2026, 6, 1, tzinfo=UTC)
        end = datetime(2026, 1, 1, tzinfo=UTC)
        with pytest.raises(ValueError, match="end must be"):
            CompliancePeriod.from_dates(start, end)


class TestCompliancePeriodContains:
    def test_contains_in_range(self) -> None:
        p = CompliancePeriod.from_label("2026-Q4")
        ts = datetime(2026, 11, 15, tzinfo=UTC)
        assert p.contains(ts) is True

    def test_contains_before_range(self) -> None:
        p = CompliancePeriod.from_label("2026-Q4")
        ts = datetime(2026, 9, 30, tzinfo=UTC)
        assert p.contains(ts) is False

    def test_contains_after_range(self) -> None:
        p = CompliancePeriod.from_label("2026-Q4")
        ts = datetime(2027, 1, 1, tzinfo=UTC)
        assert p.contains(ts) is False

    def test_str_is_label(self) -> None:
        p = CompliancePeriod.from_label("2026-Q4")
        assert str(p) == "2026-Q4"


# ---------------------------------------------------------------------------
# ComplianceFormat
# ---------------------------------------------------------------------------


class TestComplianceFormat:
    def test_eu_ai_act_value(self) -> None:
        assert ComplianceFormat.EU_AI_ACT == "eu-ai-act"

    def test_soc2_value(self) -> None:
        assert ComplianceFormat.SOC2 == "soc2"

    def test_gdpr_value(self) -> None:
        assert ComplianceFormat.GDPR == "gdpr"

    def test_from_string(self) -> None:
        assert ComplianceFormat("eu-ai-act") == ComplianceFormat.EU_AI_ACT

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            ComplianceFormat("iso27001")


# ---------------------------------------------------------------------------
# ComplianceReport
# ---------------------------------------------------------------------------


class TestComplianceReport:
    def _make_report(self) -> ComplianceReport:
        period = CompliancePeriod.from_label("2026-Q4")
        return ComplianceReport(
            format=ComplianceFormat.EU_AI_ACT,
            period=period,
            total_calls=100,
            violations=3,
            pii_redactions=47,
            compliance_score=0.97,
            policy_versions=["1.0"],
            tool_names=["search_web"],
            narratives=["Test narrative."],
        )

    def test_to_dict_has_required_keys(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        for key in (
            "format",
            "period",
            "generated_at",
            "total_calls",
            "violations",
            "pii_redactions",
            "compliance_score",
            "narratives",
        ):
            assert key in d

    def test_to_dict_format_is_string(self) -> None:
        report = self._make_report()
        assert report.to_dict()["format"] == "eu-ai-act"

    def test_to_dict_period_is_dict(self) -> None:
        report = self._make_report()
        p = report.to_dict()["period"]
        assert isinstance(p, dict)
        assert "label" in p and "start" in p and "end" in p

    def test_to_json_is_valid_json(self) -> None:
        report = self._make_report()
        parsed = json.loads(report.to_json())
        assert parsed["total_calls"] == 100

    def test_to_json_indent_none(self) -> None:
        report = self._make_report()
        s = report.to_json(indent=None)
        assert "\n" not in s

    def test_str_contains_score(self) -> None:
        report = self._make_report()
        assert "97.0%" in str(report)


# ---------------------------------------------------------------------------
# ComplianceReporter — export
# ---------------------------------------------------------------------------


class TestComplianceReporterExport:
    def test_export_no_trail_file_returns_empty(self) -> None:
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert report.total_calls == 0
        assert report.violations == 0
        assert report.compliance_score == 1.0

    def test_export_nonexistent_trail_returns_empty(self, tmp_path: Path) -> None:
        reporter = ComplianceReporter(trail_path=tmp_path / "no_such_file.jsonl")
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert report.total_calls == 0

    def test_export_entries_in_period(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [_make_entry(timestamp="2026-11-15T10:00:00+00:00") for _ in range(5)]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert report.total_calls == 5

    def test_export_entries_outside_period_excluded(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [
            _make_entry(timestamp="2026-06-15T10:00:00+00:00"),  # Q2 — excluded
            _make_entry(timestamp="2026-11-01T10:00:00+00:00"),  # Q4 — included
        ]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert report.total_calls == 1

    def test_export_violations_counted(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [
            _make_entry(decision="allowed"),
            _make_entry(decision="blocked"),
            _make_entry(decision="blocked"),
        ]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.GDPR, period)
        assert report.violations == 2
        assert report.total_calls == 3

    def test_export_pii_redactions_summed(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [
            _make_entry(input_redactions=3, output_redactions=1),
            _make_entry(input_redactions=2, output_redactions=0),
        ]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert report.pii_redactions == 6

    def test_export_compliance_score(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [_make_entry(decision="allowed")] * 9 + [_make_entry(decision="blocked")]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert report.compliance_score == pytest.approx(0.9)

    def test_export_compliance_score_perfect(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        _write_trail(trail, [_make_entry(decision="allowed")])
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert report.compliance_score == 1.0

    def test_export_policy_versions_collected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [
            _make_entry(policy_version="1.0"),
            _make_entry(policy_version="1.1"),
            _make_entry(policy_version="1.0"),
        ]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.GDPR, period)
        assert report.policy_versions == ["1.0", "1.1"]

    def test_export_tool_names_collected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [
            _make_entry(tool_name="search_web"),
            _make_entry(tool_name="send_email"),
            _make_entry(tool_name="search_web"),
        ]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert report.tool_names == ["search_web", "send_email"]

    def test_export_tenant_ids_collected(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entries = [
            _make_entry(tenant_id="acme"),
            _make_entry(tenant_id="globex"),
        ]
        _write_trail(trail, entries)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.GDPR, period)
        assert "acme" in report.tenant_ids
        assert "globex" in report.tenant_ids

    def test_export_eu_ai_act_narratives(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        _write_trail(trail, [_make_entry()])
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert len(report.narratives) == 3
        assert "Article 13" in report.narratives[0]

    def test_export_soc2_narratives(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        _write_trail(trail, [_make_entry()])
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert len(report.narratives) == 4
        assert "SOC2" in report.narratives[0]

    def test_export_gdpr_narratives(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        _write_trail(trail, [_make_entry()])
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.GDPR, period)
        assert len(report.narratives) == 3
        assert "GDPR" in report.narratives[0]

    def test_export_malformed_lines_skipped(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        with open(trail, "w", encoding="utf-8") as fh:
            fh.write("not json at all\n")
            fh.write(json.dumps(_make_entry()) + "\n")
            fh.write("{broken\n")
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert report.total_calls == 1

    def test_export_entry_without_timestamp_included(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        entry = _make_entry()
        del entry["timestamp"]
        _write_trail(trail, [entry])
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert report.total_calls == 1

    def test_export_unreadable_trail_raises(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        trail.write_text("data\n")
        trail.chmod(0o000)
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        try:
            with pytest.raises(ComplianceError, match="Cannot read"):
                reporter.export(ComplianceFormat.EU_AI_ACT, period)
        finally:
            trail.chmod(0o644)


# ---------------------------------------------------------------------------
# ComplianceReporter — export_json / export_html
# ---------------------------------------------------------------------------


class TestComplianceReporterExportFiles:
    def test_export_json_writes_file(self, tmp_path: Path) -> None:
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        out = tmp_path / "report.json"
        reporter.export_json(ComplianceFormat.EU_AI_ACT, period, out)
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert "total_calls" in parsed

    def test_export_json_creates_parent_dirs(self, tmp_path: Path) -> None:
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        out = tmp_path / "subdir" / "deep" / "report.json"
        reporter.export_json(ComplianceFormat.SOC2, period, out)
        assert out.exists()

    def test_export_html_writes_file(self, tmp_path: Path) -> None:
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        out = tmp_path / "report.html"
        reporter.export_html(ComplianceFormat.GDPR, period, out)
        assert out.exists()
        content = out.read_text()
        assert "<!DOCTYPE html>" in content
        assert "EnforceCore" in content

    def test_export_html_contains_score(self, tmp_path: Path) -> None:
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        out = tmp_path / "report.html"
        reporter.export_html(ComplianceFormat.EU_AI_ACT, period, out)
        assert "100.0%" in out.read_text()


# ---------------------------------------------------------------------------
# ComplianceReporter — send_webhook
# ---------------------------------------------------------------------------


class _WebhookHandler(http.server.BaseHTTPRequestHandler):
    """Captures POST body and sets result on the server."""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        self.server.captured_body = body  # type: ignore[attr-defined]
        self.server.captured_auth = self.headers.get("Authorization", "")  # type: ignore[attr-defined]
        self.send_response(HTTPStatus.OK)
        self.end_headers()

    def log_message(self, *args: object) -> None:  # pragma: no cover
        pass  # suppress server log noise


class _ErrorWebhookHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.end_headers()

    def log_message(self, *args: object) -> None:  # pragma: no cover
        pass


class TestComplianceReporterWebhook:
    def _make_report(self) -> ComplianceReport:
        period = CompliancePeriod.from_label("2026-Q4")
        return ComplianceReport(
            format=ComplianceFormat.EU_AI_ACT,
            period=period,
            total_calls=10,
            violations=0,
            compliance_score=1.0,
            narratives=["Test."],
        )

    def _start_server(self, handler_class: type) -> tuple[http.server.HTTPServer, int]:
        server = http.server.HTTPServer(("127.0.0.1", 0), handler_class)
        port = server.server_address[1]
        t = threading.Thread(target=server.handle_request, daemon=True)
        t.start()
        return server, port

    def test_send_webhook_success(self) -> None:
        server, port = self._start_server(_WebhookHandler)
        reporter = ComplianceReporter()
        report = self._make_report()
        reporter.send_webhook(
            report,
            url=f"http://127.0.0.1:{port}/upload",
            token="test-token",
        )
        assert server.captured_body  # type: ignore[attr-defined]
        parsed = json.loads(server.captured_body)  # type: ignore[attr-defined]
        assert parsed["format"] == "eu-ai-act"
        assert "Bearer test-token" in server.captured_auth  # type: ignore[attr-defined]

    def test_send_webhook_http_error_raises(self) -> None:
        _server, port = self._start_server(_ErrorWebhookHandler)
        reporter = ComplianceReporter()
        report = self._make_report()
        with pytest.raises(ComplianceError, match="401"):
            reporter.send_webhook(
                report,
                url=f"http://127.0.0.1:{port}/upload",
                token="bad-token",
            )

    def test_send_webhook_network_error_raises(self) -> None:
        reporter = ComplianceReporter()
        report = self._make_report()
        with pytest.raises(ComplianceError, match="failed"):
            reporter.send_webhook(
                report,
                url="http://127.0.0.1:1/nonexistent",
                token="tok",
                timeout=0.5,
            )


# ---------------------------------------------------------------------------
# ComplianceReporter misc
# ---------------------------------------------------------------------------


class TestComplianceReporterMisc:
    def test_repr_with_path(self, tmp_path: Path) -> None:
        trail = tmp_path / "trail.jsonl"
        r = ComplianceReporter(trail_path=trail)
        assert "trail.jsonl" in repr(r)

    def test_repr_no_path(self) -> None:
        r = ComplianceReporter()
        assert "none" in repr(r)


# ---------------------------------------------------------------------------
# ComplianceError
# ---------------------------------------------------------------------------


class TestComplianceError:
    def test_is_exception(self) -> None:
        err = ComplianceError("test")
        assert isinstance(err, Exception)

    def test_message_preserved(self) -> None:
        err = ComplianceError("trail missing")
        assert str(err) == "trail missing"

    def test_can_raise_and_catch(self) -> None:
        with pytest.raises(ComplianceError):
            raise ComplianceError("boom")


# ---------------------------------------------------------------------------
# Public API surface
# ---------------------------------------------------------------------------


class TestPublicAPICompliance:
    def test_compliance_error_in_all(self) -> None:
        assert "ComplianceError" in enforcecore.__all__

    def test_compliance_format_in_all(self) -> None:
        assert "ComplianceFormat" in enforcecore.__all__

    def test_compliance_period_in_all(self) -> None:
        assert "CompliancePeriod" in enforcecore.__all__

    def test_compliance_report_in_all(self) -> None:
        assert "ComplianceReport" in enforcecore.__all__

    def test_compliance_reporter_in_all(self) -> None:
        assert "ComplianceReporter" in enforcecore.__all__

    def test_compliance_reporter_importable(self) -> None:
        from enforcecore import ComplianceReporter as ComplianceReporterAlias

        assert ComplianceReporterAlias is ComplianceReporter

    def test_compliance_format_importable(self) -> None:
        from enforcecore import ComplianceFormat as ComplianceFormatAlias

        assert ComplianceFormatAlias is ComplianceFormat

    def test_compliance_error_importable(self) -> None:
        from enforcecore import ComplianceError as ComplianceErrorAlias

        assert ComplianceErrorAlias is ComplianceError


# ---------------------------------------------------------------------------
# CLI — audit export
# ---------------------------------------------------------------------------


def _extract_json_from_output(output: str) -> str:
    """Extract the JSON block from CLI output (strips leading structlog lines)."""
    # Find the first '{' which starts the JSON object
    idx = output.find("{")
    if idx == -1:
        return output  # let the caller fail with a clear parse error
    return output[idx:]


class TestCLIAuditExport:
    """Smoke-tests for the 'enforcecore audit export' CLI command."""

    def test_audit_export_stdout_valid_json(self) -> None:
        """enforcecore audit export --format eu-ai-act --period 2026-Q4 prints JSON."""
        from typer.testing import CliRunner

        from enforcecore.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app, ["audit", "export", "--format", "eu-ai-act", "--period", "2026-Q4"]
        )
        assert result.exit_code == 0
        parsed = json.loads(_extract_json_from_output(result.output))
        assert parsed["format"] == "eu-ai-act"

    def test_audit_export_soc2_stdout(self) -> None:
        from typer.testing import CliRunner

        from enforcecore.cli.main import app

        runner = CliRunner()
        result = runner.invoke(app, ["audit", "export", "--format", "soc2", "--period", "2026"])
        assert result.exit_code == 0
        parsed = json.loads(_extract_json_from_output(result.output))
        assert parsed["format"] == "soc2"

    def test_audit_export_invalid_format_exits_1(self) -> None:
        from typer.testing import CliRunner

        from enforcecore.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app, ["audit", "export", "--format", "iso27001", "--period", "2026-Q4"]
        )
        assert result.exit_code == 1

    def test_audit_export_invalid_period_exits_1(self) -> None:
        from typer.testing import CliRunner

        from enforcecore.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app, ["audit", "export", "--format", "soc2", "--period", "bad-period"]
        )
        assert result.exit_code == 1

    def test_audit_export_writes_json_file(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from enforcecore.cli.main import app

        out = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            app,
            ["audit", "export", "--format", "gdpr", "--period", "2026-Q4", "--output", str(out)],
        )
        assert result.exit_code == 0
        assert out.exists()
        parsed = json.loads(out.read_text())
        assert parsed["format"] == "gdpr"

    def test_audit_export_writes_html_file(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from enforcecore.cli.main import app

        out = tmp_path / "report.html"
        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "audit",
                "export",
                "--format",
                "eu-ai-act",
                "--period",
                "2026-Q4",
                "--html",
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        assert "<!DOCTYPE html>" in out.read_text()

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Extra coverage for compliance/reporter.py — edge-case paths."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.compliance.reporter import ComplianceReporter
from enforcecore.compliance.types import (
    ComplianceError,
    ComplianceFormat,
    CompliancePeriod,
    ComplianceReport,
)

if TYPE_CHECKING:
    from pathlib import Path


def _make_report() -> ComplianceReport:
    period = CompliancePeriod.from_label("2026-Q4")
    return ComplianceReport(
        format=ComplianceFormat.EU_AI_ACT,
        period=period,
        total_calls=5,
        violations=0,
        compliance_score=1.0,
        narratives=["Test narrative."],
    )


# ---------------------------------------------------------------------------
# export_json — OSError path (lines 197-198)
# ---------------------------------------------------------------------------


class TestExportJsonOSError:
    def test_export_json_oserror_raises_compliance_error(self, tmp_path: Path) -> None:
        """OSError on write is wrapped in ComplianceError."""
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        out = tmp_path / "report.json"

        with (
            patch("pathlib.Path.write_text", side_effect=OSError("disk full")),
            pytest.raises(ComplianceError, match="Failed to write JSON report"),
        ):
            reporter.export_json(ComplianceFormat.EU_AI_ACT, period, out)


# ---------------------------------------------------------------------------
# export_html — OSError path (lines 224-225)
# ---------------------------------------------------------------------------


class TestExportHtmlOSError:
    def test_export_html_oserror_raises_compliance_error(self, tmp_path: Path) -> None:
        """OSError on HTML write is wrapped in ComplianceError."""
        reporter = ComplianceReporter()
        period = CompliancePeriod.from_label("2026-Q4")
        out = tmp_path / "report.html"

        with (
            patch("pathlib.Path.write_text", side_effect=OSError("no space")),
            pytest.raises(ComplianceError, match="Failed to write HTML report"),
        ):
            reporter.export_html(ComplianceFormat.GDPR, period, out)


# ---------------------------------------------------------------------------
# send_webhook — non-2xx status (line 273)
# ---------------------------------------------------------------------------


class TestSendWebhookNon2xx:
    def test_send_webhook_non2xx_status_raises(self) -> None:
        """urlopen succeeds (no HTTPError) but returns a non-2xx status."""
        reporter = ComplianceReporter()
        report = _make_report()

        # Build a fake context-manager response with status=302
        mock_resp = MagicMock()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.status = 302

        with (
            patch("urllib.request.urlopen", return_value=mock_resp),
            pytest.raises(ComplianceError, match="non-2xx status 302"),
        ):
            reporter.send_webhook(report, url="http://example.com/hook", token="tok")


# ---------------------------------------------------------------------------
# _load_entries — blank line → continue (line 291)
# ---------------------------------------------------------------------------


class TestLoadEntriesEdgeCases:
    def test_blank_line_in_trail_is_skipped(self, tmp_path: Path) -> None:
        """Blank lines in the trail file are silently skipped."""
        trail = tmp_path / "trail.jsonl"
        entry = {
            "tool_name": "search",
            "decision": "allowed",
            "timestamp": "2026-10-15T10:00:00+00:00",
        }
        trail.write_text(
            "\n"  # blank line first → triggers `continue` at line 291
            + json.dumps(entry)
            + "\n\n",  # trailing blank lines too
            encoding="utf-8",
        )
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.SOC2, period)
        assert report.total_calls == 1

    def test_naive_timestamp_added_utc(self, tmp_path: Path) -> None:
        """Entry with a timezone-naive timestamp is treated as UTC (line 302)."""
        trail = tmp_path / "trail.jsonl"
        entry = {
            "tool_name": "search",
            "decision": "allowed",
            # No UTC offset → naive datetime → triggers ts.replace(tzinfo=UTC)
            "timestamp": "2026-10-15T10:00:00",
        }
        trail.write_text(json.dumps(entry) + "\n", encoding="utf-8")
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.EU_AI_ACT, period)
        assert report.total_calls == 1

    def test_invalid_timestamp_entry_skipped(self, tmp_path: Path) -> None:
        """Entry with an unparseable timestamp is skipped (lines 303-304)."""
        trail = tmp_path / "trail.jsonl"
        valid_entry = {
            "tool_name": "search",
            "decision": "allowed",
            "timestamp": "2026-10-15T10:00:00+00:00",
        }
        invalid_ts_entry = {
            "tool_name": "blocked_tool",
            "decision": "blocked",
            "timestamp": "not-a-valid-datetime",  # ValueError → continue
        }
        trail.write_text(
            json.dumps(valid_entry) + "\n" + json.dumps(invalid_ts_entry) + "\n",
            encoding="utf-8",
        )
        reporter = ComplianceReporter(trail_path=trail)
        period = CompliancePeriod.from_label("2026-Q4")
        report = reporter.export(ComplianceFormat.GDPR, period)
        # Only the valid entry should be counted
        assert report.total_calls == 1

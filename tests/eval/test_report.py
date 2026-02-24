# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.eval.report — Markdown report generator."""

from __future__ import annotations

from enforcecore.eval.report import (
    generate_benchmark_report,
    generate_html_report,
    generate_report,
    generate_suite_report,
)
from enforcecore.eval.types import (
    BenchmarkResult,
    BenchmarkSuite,
    ScenarioOutcome,
    ScenarioResult,
    Severity,
    SuiteResult,
    ThreatCategory,
)


def _make_suite() -> SuiteResult:
    """Create a sample suite result for testing."""
    return SuiteResult(
        policy_name="test-policy",
        total_duration_ms=42.5,
        results=[
            ScenarioResult(
                scenario_id="s-1",
                scenario_name="Tool Abuse Test",
                category=ThreatCategory.TOOL_ABUSE,
                severity=Severity.HIGH,
                outcome=ScenarioOutcome.CONTAINED,
                duration_ms=1.2,
                exception_type="ToolDeniedError",
                exception_message="blocked",
                details="Tool was denied",
            ),
            ScenarioResult(
                scenario_id="s-2",
                scenario_name="PII Leak Test",
                category=ThreatCategory.PII_LEAKAGE,
                severity=Severity.CRITICAL,
                outcome=ScenarioOutcome.ESCAPED,
                duration_ms=0.8,
                details="PII was not redacted",
            ),
            ScenarioResult(
                scenario_id="s-3",
                scenario_name="Skipped Test",
                category=ThreatCategory.PRIVILEGE_ESCALATION,
                severity=Severity.MEDIUM,
                outcome=ScenarioOutcome.SKIPPED,
                duration_ms=0.1,
            ),
        ],
    )


def _make_benchmark_suite() -> BenchmarkSuite:
    """Create a sample benchmark suite for testing."""
    return BenchmarkSuite(
        results=[
            BenchmarkResult(
                name="policy_pre_call",
                iterations=1000,
                mean_ms=0.015,
                median_ms=0.012,
                p50_ms=0.012,
                p95_ms=0.025,
                p99_ms=0.040,
                p999_ms=0.060,
                min_ms=0.008,
                max_ms=0.150,
                std_dev_ms=0.005,
                total_ms=15.0,
            ),
            BenchmarkResult(
                name="enforcer_e2e",
                iterations=1000,
                mean_ms=0.250,
                median_ms=0.200,
                p50_ms=0.200,
                p95_ms=0.500,
                p99_ms=0.800,
                p999_ms=1.200,
                min_ms=0.100,
                max_ms=2.000,
                std_dev_ms=0.100,
                total_ms=250.0,
            ),
        ],
        total_duration_ms=265.0,
        python_version="3.14.2",
        platform="macOS arm64",
    )


# ---------------------------------------------------------------------------
# Suite report
# ---------------------------------------------------------------------------


class TestSuiteReport:
    """Tests for the suite report generator."""

    def test_report_contains_header(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "# EnforceCore Evaluation Report" in report

    def test_report_contains_policy_name(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "test-policy" in report

    def test_report_contains_summary_table(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "Total Scenarios" in report
        assert "Contained" in report
        assert "Escaped" in report

    def test_report_contains_containment_rate(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "Containment Rate" in report

    def test_report_contains_category_sections(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "Tool Abuse" in report
        assert "Pii Leakage" in report

    def test_report_contains_detailed_results(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "Tool Abuse Test" in report
        assert "PII Leak Test" in report

    def test_report_shows_exception_info(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "ToolDeniedError" in report

    def test_report_shows_emojis(self) -> None:
        report = generate_suite_report(_make_suite())
        assert "🟢" in report  # contained
        assert "🔴" in report  # escaped or critical

    def test_empty_suite_report(self) -> None:
        report = generate_suite_report(SuiteResult())
        assert "Containment Rate" in report


# ---------------------------------------------------------------------------
# Benchmark report
# ---------------------------------------------------------------------------


class TestBenchmarkReport:
    """Tests for the benchmark report generator."""

    def test_report_contains_header(self) -> None:
        report = generate_benchmark_report(_make_benchmark_suite())
        assert "# EnforceCore Benchmark Report" in report

    def test_report_contains_platform_info(self) -> None:
        report = generate_benchmark_report(_make_benchmark_suite())
        assert "Python" in report
        assert "3.14.2" in report
        assert "macOS" in report

    def test_report_contains_summary_table(self) -> None:
        report = generate_benchmark_report(_make_benchmark_suite())
        assert "Performance Summary" in report
        assert "policy_pre_call" in report
        assert "enforcer_e2e" in report

    def test_report_contains_ops_per_second(self) -> None:
        report = generate_benchmark_report(_make_benchmark_suite())
        assert "Ops/s" in report

    def test_report_contains_detailed_results(self) -> None:
        report = generate_benchmark_report(_make_benchmark_suite())
        assert "Detailed Results" in report
        assert "Iterations" in report
        assert "P95" in report
        assert "P99" in report


# ---------------------------------------------------------------------------
# Combined report
# ---------------------------------------------------------------------------


class TestCombinedReport:
    """Tests for the combined report generator."""

    def test_combined_report_both(self) -> None:
        report = generate_report(_make_suite(), _make_benchmark_suite())
        assert "Evaluation Report" in report
        assert "Benchmark Report" in report

    def test_combined_report_suite_only(self) -> None:
        report = generate_report(suite=_make_suite())
        assert "Evaluation Report" in report
        assert "Benchmark Report" not in report

    def test_combined_report_bench_only(self) -> None:
        report = generate_report(benchmarks=_make_benchmark_suite())
        assert "Benchmark Report" in report
        assert "Evaluation Report" not in report

    def test_combined_report_none(self) -> None:
        report = generate_report()
        assert "No results to report" in report


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------


class TestHtmlReport:
    """Tests for the HTML report generator."""

    def test_html_report_is_valid_html(self) -> None:
        report = generate_html_report(suite=_make_suite())
        assert report.startswith("<!DOCTYPE html>")
        assert "</html>" in report

    def test_html_report_contains_policy_name(self) -> None:
        report = generate_html_report(suite=_make_suite())
        assert "test-policy" in report

    def test_html_report_contains_containment(self) -> None:
        report = generate_html_report(suite=_make_suite())
        assert "Containment" in report

    def test_html_report_contains_scenario_names(self) -> None:
        report = generate_html_report(suite=_make_suite())
        assert "Tool Abuse Test" in report
        assert "PII Leak Test" in report

    def test_html_report_contains_categories(self) -> None:
        report = generate_html_report(suite=_make_suite())
        assert "Tool Abuse" in report

    def test_html_report_benchmark_only(self) -> None:
        report = generate_html_report(benchmarks=_make_benchmark_suite())
        assert "Performance Benchmarks" in report
        assert "policy_pre_call" in report

    def test_html_report_combined(self) -> None:
        report = generate_html_report(_make_suite(), _make_benchmark_suite())
        assert "Containment" in report
        assert "Performance Benchmarks" in report

    def test_html_report_empty(self) -> None:
        report = generate_html_report()
        assert "No results to report" in report

    def test_html_report_escapes_special_chars(self) -> None:
        suite = SuiteResult(policy_name="<script>alert(1)</script>")
        report = generate_html_report(suite=suite)
        assert "<script>" not in report
        assert "&lt;script&gt;" in report

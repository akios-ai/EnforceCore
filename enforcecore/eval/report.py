"""Report generator — Markdown reports for evaluation results.

Generates human-readable Markdown reports from :class:`SuiteResult` and
:class:`BenchmarkSuite` data.  Reports include summary tables, per-category
breakdowns, and benchmark comparisons.

Usage::

    from enforcecore.eval.report import generate_report

    report = generate_report(suite_result, benchmark_suite)
    print(report)  # or write to file
"""

from __future__ import annotations

from enforcecore.eval.types import (
    BenchmarkSuite,
    ScenarioOutcome,
    SuiteResult,
    ThreatCategory,
)


def _outcome_emoji(outcome: ScenarioOutcome) -> str:
    """Map an outcome to an emoji for the report."""
    return {
        ScenarioOutcome.CONTAINED: "🟢",
        ScenarioOutcome.ESCAPED: "🔴",
        ScenarioOutcome.ERROR: "🟡",
        ScenarioOutcome.SKIPPED: "⚪",
    }.get(outcome, "❓")


def _severity_badge(severity: str) -> str:
    """Format a severity as a badge-style string."""
    return {
        "low": "🟢 Low",
        "medium": "🟡 Medium",
        "high": "🟠 High",
        "critical": "🔴 Critical",
    }.get(severity, severity)


def _containment_emoji(rate: float) -> str:
    """Select an emoji based on containment rate."""
    if rate >= 1.0:
        return "🛡️"
    if rate >= 0.8:
        return "⚠️"
    return "🚨"


# ---------------------------------------------------------------------------
# Suite report
# ---------------------------------------------------------------------------


def generate_suite_report(suite: SuiteResult) -> str:
    """Generate a Markdown report from a suite result.

    Args:
        suite: The evaluation suite results.

    Returns:
        A Markdown-formatted string.
    """
    lines: list[str] = []

    # Header
    lines.append("# EnforceCore Evaluation Report")
    lines.append("")
    lines.append(f"**Policy:** `{suite.policy_name}`  ")
    lines.append(f"**Run ID:** `{suite.run_id}`  ")
    lines.append(f"**Timestamp:** {suite.timestamp}  ")
    lines.append(f"**Duration:** {suite.total_duration_ms:.1f}ms  ")
    lines.append("")

    # Summary
    emoji = _containment_emoji(suite.containment_rate)
    lines.append("## Summary")
    lines.append("")
    lines.append(f"{emoji} **Containment Rate: {suite.containment_rate:.0%}**")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total Scenarios | {suite.total} |")
    lines.append(f"| 🟢 Contained | {suite.contained} |")
    lines.append(f"| 🔴 Escaped | {suite.escaped} |")
    lines.append(f"| 🟡 Errors | {suite.errors} |")
    lines.append(f"| ⚪ Skipped | {suite.skipped} |")
    lines.append("")

    # Per-category breakdown
    lines.append("## Results by Category")
    lines.append("")

    by_cat = suite.by_category()
    for cat in ThreatCategory:
        results = by_cat.get(cat, [])
        if not results:
            continue

        contained = sum(1 for r in results if r.outcome == ScenarioOutcome.CONTAINED)
        total = len(results)

        lines.append(f"### {cat.value.replace('_', ' ').title()} ({contained}/{total})")
        lines.append("")
        lines.append("| Scenario | Outcome | Severity | Duration |")
        lines.append("|----------|---------|----------|----------|")
        for r in results:
            emoji_out = _outcome_emoji(r.outcome)
            sev = _severity_badge(r.severity)
            lines.append(
                f"| {r.scenario_name} | {emoji_out} {r.outcome.value} | {sev} | {r.duration_ms:.1f}ms |"
            )
        lines.append("")

    # Detailed results
    lines.append("## Detailed Results")
    lines.append("")
    for r in suite.results:
        emoji_out = _outcome_emoji(r.outcome)
        lines.append(f"### {emoji_out} {r.scenario_name}")
        lines.append("")
        lines.append(f"- **ID:** `{r.scenario_id}`")
        lines.append(f"- **Category:** {r.category.value}")
        lines.append(f"- **Severity:** {_severity_badge(r.severity)}")
        lines.append(f"- **Outcome:** {r.outcome.value}")
        lines.append(f"- **Duration:** {r.duration_ms:.2f}ms")
        if r.exception_type:
            lines.append(f"- **Exception:** `{r.exception_type}: {r.exception_message}`")
        if r.details:
            lines.append(f"- **Details:** {r.details}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Benchmark report
# ---------------------------------------------------------------------------


def generate_benchmark_report(suite: BenchmarkSuite) -> str:
    """Generate a Markdown report from benchmark results.

    Args:
        suite: The benchmark suite results.

    Returns:
        A Markdown-formatted string.
    """
    lines: list[str] = []

    lines.append("# EnforceCore Benchmark Report")
    lines.append("")
    lines.append(f"**Python:** {suite.python_version}  ")
    lines.append(f"**Platform:** {suite.platform}  ")
    lines.append(f"**Timestamp:** {suite.timestamp}  ")
    lines.append(f"**Total Duration:** {suite.total_duration_ms:.1f}ms  ")
    lines.append("")

    # Summary table
    lines.append("## Performance Summary")
    lines.append("")
    lines.append("| Component | Mean | Median | P95 | P99 | Ops/s |")
    lines.append("|-----------|------|--------|-----|-----|-------|")

    for r in suite.results:
        lines.append(
            f"| {r.name} | {r.mean_ms:.3f}ms | {r.median_ms:.3f}ms | "
            f"{r.p95_ms:.3f}ms | {r.p99_ms:.3f}ms | {r.ops_per_second:,.0f} |"
        )
    lines.append("")

    # Detailed benchmarks
    lines.append("## Detailed Results")
    lines.append("")

    for r in suite.results:
        lines.append(f"### {r.name}")
        lines.append("")
        lines.append(f"- **Iterations:** {r.iterations:,}")
        lines.append(f"- **Mean:** {r.mean_ms:.4f}ms")
        lines.append(f"- **Median:** {r.median_ms:.4f}ms")
        lines.append(f"- **P95:** {r.p95_ms:.4f}ms")
        lines.append(f"- **P99:** {r.p99_ms:.4f}ms")
        lines.append(f"- **Min:** {r.min_ms:.4f}ms")
        lines.append(f"- **Max:** {r.max_ms:.4f}ms")
        lines.append(f"- **Total:** {r.total_ms:.2f}ms")
        lines.append(f"- **Ops/sec:** {r.ops_per_second:,.0f}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Combined report
# ---------------------------------------------------------------------------


def generate_report(
    suite: SuiteResult | None = None,
    benchmarks: BenchmarkSuite | None = None,
) -> str:
    """Generate a combined evaluation + benchmark report.

    Args:
        suite: Evaluation suite results (optional).
        benchmarks: Benchmark suite results (optional).

    Returns:
        A Markdown-formatted string with both sections.
    """
    parts: list[str] = []

    if suite is not None:
        parts.append(generate_suite_report(suite))

    if benchmarks is not None:
        if parts:
            parts.append("\n---\n")
        parts.append(generate_benchmark_report(benchmarks))

    if not parts:
        return "# EnforceCore Evaluation Report\n\nNo results to report.\n"

    return "\n".join(parts)

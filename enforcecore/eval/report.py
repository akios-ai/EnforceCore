# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
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


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EnforceCore Evaluation Report</title>
<style>
:root {{
  --green: #22c55e; --red: #ef4444; --yellow: #eab308; --gray: #94a3b8;
  --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8;
  --border: #334155; --accent: #3b82f6;
}}
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; }}
.container {{ max-width: 1100px; margin: 0 auto; }}
h1 {{ font-size: 1.8rem; margin-bottom: 0.25rem; }}
.subtitle {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 2rem; }}
.badge {{ display: inline-block; padding: 0.3rem 1rem; border-radius: 999px;
          font-weight: 700; font-size: 1.5rem; margin: 1rem 0; }}
.badge-green {{ background: rgba(34,197,94,0.15); color: var(--green); border: 2px solid var(--green); }}
.badge-yellow {{ background: rgba(234,179,8,0.15); color: var(--yellow); border: 2px solid var(--yellow); }}
.badge-red {{ background: rgba(239,68,68,0.15); color: var(--red); border: 2px solid var(--red); }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
.stat {{ background: var(--card); padding: 1rem; border-radius: 8px; text-align: center;
         border: 1px solid var(--border); }}
.stat .num {{ font-size: 1.8rem; font-weight: 700; }}
.stat .label {{ color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.85rem; }}
th {{ color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; }}
.section {{ margin: 2.5rem 0; }}
.section h2 {{ font-size: 1.2rem; margin-bottom: 1rem; padding-bottom: 0.5rem;
               border-bottom: 1px solid var(--border); }}
.outcome-contained {{ color: var(--green); }}
.outcome-escaped {{ color: var(--red); }}
.outcome-error {{ color: var(--yellow); }}
.outcome-skipped {{ color: var(--gray); }}
.sev-low {{ color: var(--green); }}
.sev-medium {{ color: var(--yellow); }}
.sev-high {{ color: #f97316; }}
.sev-critical {{ color: var(--red); }}
.cat-bar {{ height: 6px; border-radius: 3px; background: var(--border); margin-top: 0.5rem; overflow: hidden; }}
.cat-bar-fill {{ height: 100%; border-radius: 3px; }}
footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
          color: var(--muted); font-size: 0.75rem; text-align: center; }}
</style>
</head>
<body>
<div class="container">
{content}
<footer>Generated by EnforceCore &middot; <a href="https://github.com/akios-ai/EnforceCore" style="color:var(--accent)">github.com/akios-ai/EnforceCore</a></footer>
</div>
</body>
</html>"""


def _html_escape(text: str) -> str:
    """Minimal HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _outcome_class(outcome: ScenarioOutcome) -> str:
    return f"outcome-{outcome.value}"


def _severity_class(severity: str) -> str:
    return f"sev-{severity}"


def generate_html_report(
    suite: SuiteResult | None = None,
    benchmarks: BenchmarkSuite | None = None,
) -> str:
    """Generate a self-contained HTML report with inline CSS.

    Args:
        suite: Evaluation suite results (optional).
        benchmarks: Benchmark suite results (optional).

    Returns:
        A complete HTML document as a string.
    """
    parts: list[str] = []

    if suite is not None:
        # --- Header ---
        parts.append("<h1>EnforceCore Evaluation Report</h1>")
        parts.append(
            f'<div class="subtitle">Policy: {_html_escape(suite.policy_name)} &middot; '
            f"Run: {_html_escape(suite.run_id)} &middot; {_html_escape(suite.timestamp)}</div>"
        )

        # --- Containment badge ---
        rate = suite.containment_rate
        badge_cls = "badge-green" if rate >= 1.0 else ("badge-yellow" if rate >= 0.8 else "badge-red")
        parts.append(f'<div class="badge {badge_cls}">{rate:.0%} Containment</div>')

        # --- Summary grid ---
        parts.append('<div class="grid">')
        for label, val, color in [
            ("Total", suite.total, "var(--text)"),
            ("Contained", suite.contained, "var(--green)"),
            ("Escaped", suite.escaped, "var(--red)"),
            ("Errors", suite.errors, "var(--yellow)"),
            ("Skipped", suite.skipped, "var(--gray)"),
        ]:
            parts.append(
                f'<div class="stat"><div class="num" style="color:{color}">{val}</div>'
                f'<div class="label">{label}</div></div>'
            )
        parts.append("</div>")

        # --- Per-category breakdown ---
        parts.append('<div class="section"><h2>Results by Category</h2>')
        by_cat = suite.by_category()
        for cat in ThreatCategory:
            results = by_cat.get(cat, [])
            if not results:
                continue
            contained = sum(1 for r in results if r.outcome == ScenarioOutcome.CONTAINED)
            total = len(results)
            pct = contained / total if total else 0
            bar_color = "var(--green)" if pct >= 1.0 else ("var(--yellow)" if pct >= 0.5 else "var(--red)")
            cat_title = _html_escape(cat.value.replace("_", " ").title())
            parts.append(
                f"<div><strong>{cat_title}</strong> — {contained}/{total}"
                f'<div class="cat-bar"><div class="cat-bar-fill" '
                f'style="width:{pct:.0%};background:{bar_color}"></div></div></div>'
            )
        parts.append("</div>")

        # --- Scenario table ---
        parts.append('<div class="section"><h2>Scenario Details</h2>')
        parts.append("<table><thead><tr><th>Scenario</th><th>Category</th>"
                      "<th>Severity</th><th>Outcome</th><th>Duration</th>"
                      "<th>Details</th></tr></thead><tbody>")
        for r in suite.results:
            parts.append(
                f'<tr><td>{_html_escape(r.scenario_name)}</td>'
                f"<td>{_html_escape(r.category.value)}</td>"
                f'<td class="{_severity_class(r.severity)}">{r.severity.upper()}</td>'
                f'<td class="{_outcome_class(r.outcome)}">{r.outcome.value.upper()}</td>'
                f"<td>{r.duration_ms:.1f}ms</td>"
                f"<td>{_html_escape(r.details or '')}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    if benchmarks is not None:
        parts.append('<div class="section"><h2>Performance Benchmarks</h2>')
        parts.append(
            f'<div class="subtitle">Python {_html_escape(benchmarks.python_version)} &middot; '
            f"{_html_escape(benchmarks.platform)} &middot; {benchmarks.total_duration_ms:.1f}ms total</div>"
        )
        parts.append("<table><thead><tr><th>Component</th><th>Mean</th><th>Median</th>"
                      "<th>P95</th><th>P99</th><th>Ops/s</th></tr></thead><tbody>")
        for br in benchmarks.results:
            parts.append(
                f"<tr><td>{_html_escape(br.name)}</td>"
                f"<td>{br.mean_ms:.3f}ms</td><td>{br.median_ms:.3f}ms</td>"
                f"<td>{br.p95_ms:.3f}ms</td><td>{br.p99_ms:.3f}ms</td>"
                f"<td>{br.ops_per_second:,.0f}</td></tr>"
            )
        parts.append("</tbody></table></div>")

    if not parts:
        parts.append("<h1>EnforceCore Evaluation Report</h1><p>No results to report.</p>")

    content = "\n".join(parts)
    return _HTML_TEMPLATE.format(content=content)

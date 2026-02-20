"""Example: Using EnforceCore's Evaluation Suite.

Demonstrates:
1. Running adversarial scenarios against a policy
2. Running performance benchmarks
3. Generating Markdown reports

Run::

    python examples/evaluation_suite.py
"""

from __future__ import annotations

from enforcecore.core.policy import PIIRedactionConfig, Policy, PolicyRules
from enforcecore.core.types import RedactionStrategy
from enforcecore.eval import (
    BenchmarkRunner,
    ScenarioRunner,
    ThreatCategory,
    generate_report,
)


def main() -> None:
    """Run the evaluation suite example."""
    # ── 1. Define a strict policy ────────────────────────────────────────
    policy = Policy(
        name="example-strict",
        version="1.0.0",
        rules=PolicyRules(
            allowed_tools=["search_web", "calculator", "get_weather"],
            denied_tools=["execute_shell", "delete_file", "send_email"],
            max_output_size_bytes=1024,
            pii_redaction=PIIRedactionConfig(
                enabled=True,
                categories=["email", "phone", "ssn"],
                strategy=RedactionStrategy.MASK,
            ),
        ),
    )

    # ── 2. Run adversarial scenarios ─────────────────────────────────────
    print("=" * 60)
    print("  EnforceCore Evaluation Suite")
    print("=" * 60)
    print()

    runner = ScenarioRunner(policy)

    # List available scenarios
    scenarios = runner.list_scenarios()
    print(f"📋 Available scenarios: {len(scenarios)}")
    for s in scenarios:
        print(f"   • [{s.severity}] {s.name} ({s.category})")
    print()

    # Run all scenarios
    print("▶ Running all adversarial scenarios...")
    suite = runner.run_all()
    print()

    # Display results
    print(f"🛡️  Containment Rate: {suite.containment_rate:.0%}")
    print(f"   Total:     {suite.total}")
    print(f"   Contained: {suite.contained}")
    print(f"   Escaped:   {suite.escaped}")
    print(f"   Errors:    {suite.errors}")
    print(f"   Skipped:   {suite.skipped}")
    print(f"   Duration:  {suite.total_duration_ms:.1f}ms")
    print()

    # Per-category breakdown
    print("📊 Results by Category:")
    for cat, results in suite.by_category().items():
        contained = sum(1 for r in results if r.is_contained)
        total = len(results)
        status = "✅" if contained == total else "⚠️"
        print(f"   {status} {cat.value}: {contained}/{total} contained")
    print()

    # Filter by category
    print("▶ Running tool abuse scenarios only...")
    tool_abuse_suite = runner.run_all(category=ThreatCategory.TOOL_ABUSE)
    print(f"   Tool abuse containment: {tool_abuse_suite.containment_rate:.0%}")
    print()

    # ── 3. Run performance benchmarks ────────────────────────────────────
    print("▶ Running performance benchmarks (100 iterations)...")
    bench_runner = BenchmarkRunner(policy=policy)
    benchmarks = bench_runner.run_all(iterations=100)
    print()

    print("⚡ Benchmark Results:")
    for r in benchmarks.results:
        print(
            f"   {r.name:30s} "
            f"mean={r.mean_ms:.3f}ms  "
            f"p95={r.p95_ms:.3f}ms  "
            f"ops/s={r.ops_per_second:,.0f}"
        )
    print()

    # ── 4. Generate Markdown report ──────────────────────────────────────
    report = generate_report(suite, benchmarks)
    report_path = "results/eval_report.md"

    import os

    os.makedirs("results", exist_ok=True)
    with open(report_path, "w") as f:
        f.write(report)
    print(f"📝 Report written to {report_path}")
    print()

    # ── 5. Show a snippet of the report ──────────────────────────────────
    print("─" * 60)
    print("Report preview (first 30 lines):")
    print("─" * 60)
    for line in report.split("\n")[:30]:
        print(f"  {line}")
    print("  ...")


if __name__ == "__main__":
    main()

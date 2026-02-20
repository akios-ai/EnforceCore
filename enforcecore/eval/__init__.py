"""EnforceCore evaluation suite — adversarial scenarios, benchmarks, reports.

Provides a comprehensive evaluation framework for testing EnforceCore's
enforcement capabilities against adversarial threat scenarios.

Modules:

* :mod:`~enforcecore.eval.types` — Type definitions (Scenario, Results, etc.)
* :mod:`~enforcecore.eval.scenarios` — 13 adversarial scenarios across 7 threat
  categories
* :mod:`~enforcecore.eval.runner` — Test harness / scenario runner
* :mod:`~enforcecore.eval.benchmarks` — Per-component performance benchmarks
* :mod:`~enforcecore.eval.report` — Markdown report generator

Quick start::

    from enforcecore.eval import ScenarioRunner, BenchmarkRunner, generate_report
    from enforcecore.core.policy import Policy

    policy = Policy.from_file("policies/strict.yaml")

    # Run adversarial scenarios
    runner = ScenarioRunner(policy)
    suite = runner.run_all()
    print(f"Containment: {suite.containment_rate:.0%}")

    # Run benchmarks
    bench = BenchmarkRunner()
    benchmarks = bench.run_all(iterations=1000)

    # Generate Markdown report
    report = generate_report(suite, benchmarks)
"""

from enforcecore.eval.benchmarks import BenchmarkRunner
from enforcecore.eval.report import (
    generate_benchmark_report,
    generate_report,
    generate_suite_report,
)
from enforcecore.eval.runner import ScenarioRunner
from enforcecore.eval.scenarios import (
    get_all_scenarios,
    get_scenarios_by_category,
)
from enforcecore.eval.types import (
    BenchmarkResult,
    BenchmarkSuite,
    Scenario,
    ScenarioOutcome,
    ScenarioResult,
    Severity,
    SuiteResult,
    ThreatCategory,
)

__all__ = [
    "BenchmarkResult",
    "BenchmarkRunner",
    "BenchmarkSuite",
    "Scenario",
    "ScenarioOutcome",
    "ScenarioResult",
    "ScenarioRunner",
    "Severity",
    "SuiteResult",
    "ThreatCategory",
    "generate_benchmark_report",
    "generate_report",
    "generate_suite_report",
    "get_all_scenarios",
    "get_scenarios_by_category",
]

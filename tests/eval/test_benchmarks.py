"""Tests for enforcecore.eval.benchmarks — performance benchmarks."""

from __future__ import annotations

import pytest

from enforcecore.eval.benchmarks import BenchmarkRunner, _measure
from enforcecore.eval.types import BenchmarkResult, BenchmarkSuite

# ---------------------------------------------------------------------------
# _measure helper
# ---------------------------------------------------------------------------


class TestMeasure:
    """Tests for the _measure helper function."""

    def test_measure_returns_result(self) -> None:
        result = _measure(lambda: None, iterations=100)
        assert isinstance(result, BenchmarkResult)
        assert result.iterations == 100
        assert result.mean_ms >= 0
        assert result.total_ms >= 0

    def test_measure_stats_correct(self) -> None:
        result = _measure(lambda: None, iterations=50)
        assert result.min_ms <= result.mean_ms <= result.max_ms
        assert result.min_ms <= result.median_ms <= result.max_ms
        assert result.p95_ms <= result.max_ms
        assert result.p99_ms <= result.max_ms

    def test_measure_not_callable(self) -> None:
        with pytest.raises(TypeError, match="Expected callable"):
            _measure("not a callable", iterations=10)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------


class TestBenchmarkRunner:
    """Tests for the BenchmarkRunner class."""

    @pytest.fixture()
    def runner(self) -> BenchmarkRunner:
        return BenchmarkRunner()

    def test_bench_policy_pre_call(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_policy_pre_call(iterations=50)
        assert result.name == "policy_pre_call"
        assert result.iterations == 50
        assert result.mean_ms > 0

    def test_bench_policy_post_call(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_policy_post_call(iterations=50)
        assert result.name == "policy_post_call"
        assert result.iterations == 50

    def test_bench_pii_redaction(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_pii_redaction(iterations=50)
        assert result.name == "pii_redaction"
        assert result.iterations == 50
        assert result.mean_ms > 0

    def test_bench_audit_record(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_audit_record(iterations=50)
        assert result.name == "audit_record"
        assert result.iterations == 50

    def test_bench_guard_overhead(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_guard_overhead(iterations=50)
        assert result.name == "guard_overhead"
        assert result.iterations == 50

    def test_bench_enforcer_e2e(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_enforcer_e2e(iterations=50)
        assert result.name == "enforcer_e2e"
        assert result.iterations == 50

    def test_bench_enforcer_with_pii(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_enforcer_with_pii(iterations=50)
        assert result.name == "enforcer_e2e_with_pii"
        assert result.iterations == 50


# ---------------------------------------------------------------------------
# Full suite
# ---------------------------------------------------------------------------


class TestBenchmarkSuiteRun:
    """Tests for running the full benchmark suite."""

    def test_run_all(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=20)
        assert isinstance(suite, BenchmarkSuite)
        assert len(suite.results) == 7
        assert suite.total_duration_ms > 0
        assert suite.python_version
        assert suite.platform

    def test_run_all_benchmark_names(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        names = {r.name for r in suite.results}
        expected = {
            "policy_pre_call",
            "policy_post_call",
            "pii_redaction",
            "audit_record",
            "guard_overhead",
            "enforcer_e2e",
            "enforcer_e2e_with_pii",
        }
        assert names == expected

    def test_all_benchmarks_have_positive_ops(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        for r in suite.results:
            assert r.ops_per_second > 0, f"{r.name} has zero ops/s"

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.eval.benchmarks — performance benchmarks."""

from __future__ import annotations

import json

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

    def test_measure_p50_equals_median(self) -> None:
        result = _measure(lambda: None, iterations=100)
        assert result.p50_ms == result.median_ms

    def test_measure_p999(self) -> None:
        result = _measure(lambda: None, iterations=200)
        assert result.p999_ms >= result.p99_ms
        assert result.p999_ms <= result.max_ms

    def test_measure_std_dev(self) -> None:
        result = _measure(lambda: None, iterations=100)
        assert result.std_dev_ms >= 0

    def test_measure_warmup(self) -> None:
        counter = {"total": 0}

        def counted() -> None:
            counter["total"] += 1

        result = _measure(counted, iterations=50, warmup=20)
        assert result.warmup_iterations == 20
        assert counter["total"] == 50 + 20  # iterations + warmup

    def test_measure_warmup_zero(self) -> None:
        result = _measure(lambda: None, iterations=50, warmup=0)
        assert result.warmup_iterations == 0


# ---------------------------------------------------------------------------
# BenchmarkRunner — core benchmarks
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
# BenchmarkRunner — new scalability benchmarks
# ---------------------------------------------------------------------------


class TestNewBenchmarks:
    """Tests for newly added benchmarks in v1.0.14."""

    @pytest.fixture()
    def runner(self) -> BenchmarkRunner:
        return BenchmarkRunner()

    def test_policy_large_allowlist(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_policy_large_allowlist(num_tools=50, iterations=30)
        assert result.name == "policy_allowlist_50"
        assert result.iterations == 30
        assert result.details["num_tools"] == 50

    def test_pii_long_text(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_pii_long_text(iterations=30)
        assert result.name == "pii_long_text"
        assert result.details["text_length"] > 0

    def test_pii_clean_text(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_pii_clean_text(iterations=30)
        assert result.name == "pii_clean_text"

    def test_audit_verify(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_audit_verify(chain_length=10, iterations=5)
        assert result.name == "audit_verify_10"
        assert result.details["chain_length"] == 10

    def test_rate_limiter(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_rate_limiter(iterations=30)
        assert result.name == "rate_limiter"
        assert result.ops_per_second > 0

    def test_secret_detection(self, runner: BenchmarkRunner) -> None:
        result = runner.bench_secret_detection(iterations=30)
        assert result.name == "secret_detection"
        assert result.mean_ms > 0


# ---------------------------------------------------------------------------
# BenchmarkResult — serialization
# ---------------------------------------------------------------------------


class TestBenchmarkResultSerialization:
    """Tests for BenchmarkResult to_dict and to_row methods."""

    @pytest.fixture()
    def result(self) -> BenchmarkResult:
        return BenchmarkResult(
            name="test_bench",
            iterations=100,
            mean_ms=1.5,
            median_ms=1.4,
            p50_ms=1.4,
            p95_ms=2.0,
            p99_ms=2.5,
            p999_ms=3.0,
            min_ms=0.8,
            max_ms=4.0,
            std_dev_ms=0.3,
            total_ms=150.0,
            warmup_iterations=10,
            details={"key": "value"},
        )

    def test_to_dict_keys(self, result: BenchmarkResult) -> None:
        d = result.to_dict()
        expected_keys = {
            "name",
            "iterations",
            "warmup_iterations",
            "mean_ms",
            "median_ms",
            "p50_ms",
            "p95_ms",
            "p99_ms",
            "p999_ms",
            "min_ms",
            "max_ms",
            "std_dev_ms",
            "total_ms",
            "ops_per_second",
            "details",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self, result: BenchmarkResult) -> None:
        d = result.to_dict()
        assert d["name"] == "test_bench"
        assert d["iterations"] == 100
        assert d["warmup_iterations"] == 10
        assert d["p50_ms"] == 1.4
        assert d["p999_ms"] == 3.0
        assert d["std_dev_ms"] == 0.3
        assert d["ops_per_second"] > 0

    def test_to_row_markdown(self, result: BenchmarkResult) -> None:
        row = result.to_row()
        assert row.startswith("|")
        assert "test_bench" in row
        assert "1.5000" in row  # mean
        assert "1.4000" in row  # p50


# ---------------------------------------------------------------------------
# BenchmarkSuite — serialization and export
# ---------------------------------------------------------------------------


class TestBenchmarkSuiteExport:
    """Tests for BenchmarkSuite to_dict, to_json, and to_markdown."""

    @pytest.fixture()
    def suite(self) -> BenchmarkSuite:
        r = BenchmarkResult(
            name="dummy",
            iterations=10,
            mean_ms=0.5,
            median_ms=0.5,
            p50_ms=0.5,
            p95_ms=0.8,
            p99_ms=0.9,
            p999_ms=1.0,
            min_ms=0.3,
            max_ms=1.1,
            std_dev_ms=0.1,
            total_ms=5.0,
            warmup_iterations=5,
        )
        return BenchmarkSuite(
            results=[r],
            total_duration_ms=5.0,
            python_version="3.12.0",
            platform="Darwin arm64",
            cpu="Apple M1",
            machine="arm64",
            enforcecore_version="1.0.14a1",
        )

    def test_to_dict_structure(self, suite: BenchmarkSuite) -> None:
        d = suite.to_dict()
        assert "metadata" in d
        assert "results" in d
        assert d["metadata"]["python_version"] == "3.12.0"
        assert d["metadata"]["cpu"] == "Apple M1"
        assert d["metadata"]["enforcecore_version"] == "1.0.14a1"
        assert len(d["results"]) == 1

    def test_to_json_valid(self, suite: BenchmarkSuite) -> None:
        j = suite.to_json()
        parsed = json.loads(j)
        assert "metadata" in parsed
        assert "results" in parsed
        assert parsed["metadata"]["machine"] == "arm64"

    def test_to_markdown_format(self, suite: BenchmarkSuite) -> None:
        md = suite.to_markdown()
        assert "## Benchmark Results" in md
        assert "Python:" in md
        assert "CPU:" in md
        assert "EnforceCore:" in md
        assert "| dummy |" in md
        assert "Total duration:" in md


# ---------------------------------------------------------------------------
# Full suite
# ---------------------------------------------------------------------------


class TestBenchmarkSuiteRun:
    """Tests for running the full benchmark suite."""

    def test_run_all(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        assert isinstance(suite, BenchmarkSuite)
        assert len(suite.results) == 15
        assert suite.total_duration_ms > 0
        assert suite.python_version
        assert suite.platform
        assert suite.cpu
        assert suite.machine
        assert suite.enforcecore_version

    def test_run_all_benchmark_names(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        names = {r.name for r in suite.results}
        expected = {
            "policy_pre_call",
            "policy_post_call",
            "pii_redaction",
            "pii_clean_text",
            "pii_long_text",
            "audit_record",
            "audit_verify_100",
            "guard_overhead",
            "rate_limiter",
            "secret_detection",
            "policy_allowlist_100",
            "policy_allowlist_1000",
            "policy_allowlist_10000",
            "enforcer_e2e",
            "enforcer_e2e_with_pii",
        }
        assert names == expected

    def test_all_benchmarks_have_positive_ops(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        for r in suite.results:
            assert r.ops_per_second > 0, f"{r.name} has zero ops/s"

    def test_suite_json_export(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        data = json.loads(suite.to_json())
        assert data["metadata"]["python_version"]
        assert len(data["results"]) == 15

    def test_suite_markdown_export(self) -> None:
        runner = BenchmarkRunner()
        suite = runner.run_all(iterations=10)
        md = suite.to_markdown()
        assert "| policy_pre_call |" in md
        assert "| secret_detection |" in md


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


class TestBenchmarkCLI:
    """Tests for the benchmark CLI entry point."""

    def test_cli_markdown_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        from benchmarks.run import main

        main(["--iterations", "10", "--format", "markdown"])
        out = capsys.readouterr().out
        assert "## Benchmark Results" in out

    def test_cli_json_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        import logging

        from benchmarks.run import main

        # Suppress structlog output that leaks to stdout
        logging.disable(logging.CRITICAL)
        try:
            main(["--iterations", "10", "--format", "json"])
        finally:
            logging.disable(logging.NOTSET)
        out = capsys.readouterr().out
        # Extract the JSON object from potential surrounding log lines
        start = out.index("{")
        data = json.loads(out[start:])
        assert "metadata" in data

    def test_cli_output_dir(self, tmp_path: object) -> None:
        from pathlib import Path

        from benchmarks.run import main

        out_dir = Path(str(tmp_path)) / "bench_results"
        main(["--iterations", "10", "--format", "all", "--output", str(out_dir)])
        assert (out_dir / "benchmark_results.json").exists()
        assert (out_dir / "benchmark_results.md").exists()

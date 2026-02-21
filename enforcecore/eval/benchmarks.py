"""Benchmark suite — measures per-component overhead and end-to-end latency.

Provides reproducible, deterministic benchmarks for:

* **Policy evaluation** — pre-call and post-call checks
* **PII redaction** — regex-based scanning
* **Audit recording** — Merkle-hash chained log entries
* **Resource guard** — guard overhead on allowed calls
* **End-to-end** — full enforcement pipeline

All benchmarks use in-memory / no-I/O configurations to measure pure
computation overhead.  Results include mean, median, P95, P99, min, max,
and ops/second.

Usage::

    from enforcecore.eval.benchmarks import BenchmarkRunner

    runner = BenchmarkRunner()
    suite = runner.run_all(iterations=1000)
    for r in suite.results:
        print(f"{r.name}: {r.mean_ms:.3f}ms avg ({r.ops_per_second:.0f} ops/s)")
"""

from __future__ import annotations

import platform
import statistics
import sys
import time

import structlog

from enforcecore.core.config import settings
from enforcecore.core.enforcer import Enforcer
from enforcecore.core.policy import PIIRedactionConfig, Policy, PolicyEngine, PolicyRules
from enforcecore.core.types import CallContext, RedactionStrategy
from enforcecore.eval.types import BenchmarkResult, BenchmarkSuite
from enforcecore.redactor.engine import Redactor

logger = structlog.get_logger("enforcecore.eval.benchmarks")

# ---------------------------------------------------------------------------
# Default policies for benchmarks
# ---------------------------------------------------------------------------

_BENCH_POLICY = Policy(
    name="benchmark-policy",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["search_web", "calculate", "translate"],
        denied_tools=["execute_shell", "delete_file"],
        max_output_size_bytes=10_000,
    ),
)

_BENCH_PII_POLICY = Policy(
    name="benchmark-pii-policy",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["search_web"],
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            categories=["email", "phone", "ssn"],
            strategy=RedactionStrategy.MASK,
        ),
    ),
)


def _noop_tool() -> str:
    """A trivial tool used for benchmarking overhead."""
    return "ok"


def _noop_tool_with_args(query: str) -> str:
    """A trivial tool with a string argument."""
    return f"result: {query}"


# ---------------------------------------------------------------------------
# Measurement helper
# ---------------------------------------------------------------------------


def _measure(
    fn: object,
    iterations: int = 1000,
    warmup: int = 100,
) -> BenchmarkResult:
    """Run a callable *iterations* times and collect timing stats.

    Executes a warmup phase first to stabilise JIT/caches, then
    measures *iterations* timed runs.  Reports mean, median, p50,
    p95, p99, p99.9, std deviation, min, and max.

    Args:
        fn: A no-argument callable to benchmark.
        iterations: How many timed iterations to run.
        warmup: How many warmup iterations to run (not measured).

    Returns:
        A :class:`BenchmarkResult` with timing statistics.
    """
    if not callable(fn):
        msg = f"Expected callable, got {type(fn)}"
        raise TypeError(msg)

    # Warmup phase — stabilise caches and JIT
    for _ in range(warmup):
        fn()

    # Timed phase
    timings: list[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        elapsed = (time.perf_counter() - t0) * 1000  # ms
        timings.append(elapsed)

    timings_sorted = sorted(timings)
    n = len(timings_sorted)

    def _percentile(pct: float) -> float:
        idx = min(int(n * pct), n - 1)
        return round(timings_sorted[idx], 4)

    std = round(statistics.stdev(timings), 4) if n > 1 else 0.0

    return BenchmarkResult(
        name="",  # caller fills this in
        iterations=iterations,
        warmup_iterations=warmup,
        mean_ms=round(statistics.mean(timings), 4),
        median_ms=round(statistics.median(timings), 4),
        p50_ms=_percentile(0.50),
        p95_ms=_percentile(0.95),
        p99_ms=_percentile(0.99),
        p999_ms=_percentile(0.999),
        min_ms=round(min(timings), 4),
        max_ms=round(max(timings), 4),
        std_dev_ms=std,
        total_ms=round(sum(timings), 4),
    )


# ---------------------------------------------------------------------------
# BenchmarkRunner
# ---------------------------------------------------------------------------


class BenchmarkRunner:
    """Execute performance benchmarks for each EnforceCore component.

    Each benchmark isolates a single component to measure its
    overhead independently, plus an end-to-end benchmark that
    measures the full enforcement pipeline.
    """

    __slots__ = ("_pii_policy", "_policy")

    def __init__(
        self,
        policy: Policy | None = None,
        pii_policy: Policy | None = None,
    ) -> None:
        """Initialize the benchmark runner.

        Args:
            policy: Policy to use for benchmarks. Defaults to a standard
                benchmark policy with 3 allowed + 2 denied tools.
            pii_policy: Policy with PII redaction enabled. Defaults to
                a benchmark policy detecting email, phone, and SSN.
        """
        self._policy = policy or _BENCH_POLICY
        self._pii_policy = pii_policy or _BENCH_PII_POLICY

    # -- Individual benchmarks -----------------------------------------------

    def bench_policy_pre_call(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark policy pre-call evaluation only.

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        engine = PolicyEngine(self._policy)
        ctx = CallContext(tool_name="search_web", args=("test query",), kwargs={})

        def run() -> None:
            engine.evaluate_pre_call(ctx)

        result = _measure(run, iterations)
        result.name = "policy_pre_call"
        return result

    def bench_policy_post_call(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark policy post-call evaluation only.

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        engine = PolicyEngine(self._policy)
        ctx = CallContext(tool_name="search_web", args=("test query",), kwargs={})

        def run() -> None:
            engine.evaluate_post_call(ctx, "result text")

        result = _measure(run, iterations)
        result.name = "policy_post_call"
        return result

    def bench_pii_redaction(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark PII redaction on a string with mixed PII.

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        redactor = Redactor(
            categories=["email", "phone", "ssn"],
            strategy=RedactionStrategy.MASK,
        )
        sample = (
            "Contact john@example.com or call 555-123-4567. "
            "SSN is 123-45-6789. Another email: alice@test.org"
        )

        def run() -> None:
            redactor.redact(sample)

        result = _measure(run, iterations)
        result.name = "pii_redaction"
        return result

    def bench_audit_record(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark audit record creation (in-memory, no I/O).

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        import os
        import tempfile
        from pathlib import Path

        from enforcecore.auditor.engine import Auditor

        fd, tmp_path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        auditor = Auditor(output_path=Path(tmp_path))

        def run() -> None:
            auditor.record(
                tool_name="search_web",
                policy_name="test-policy",
                policy_version="1.0.0",
                decision="allowed",
                call_id="bench-call",
            )

        try:
            result = _measure(run, iterations)
        finally:
            os.unlink(tmp_path)

        result.name = "audit_record"
        return result

    def bench_guard_overhead(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark resource guard overhead on a trivial call.

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        from enforcecore.guard.engine import CostTracker, ResourceGuard

        guard = ResourceGuard(cost_tracker=CostTracker())

        def run() -> None:
            guard.execute_sync(
                _noop_tool,
                (),
                {},
                tool_name="bench_tool",
                policy_name="bench-policy",
            )

        result = _measure(run, iterations)
        result.name = "guard_overhead"
        return result

    def bench_enforcer_e2e(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark the full enforcement pipeline (no PII redaction).

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        # Ensure audit is disabled for clean benchmark
        original_audit = settings.audit_enabled
        settings.audit_enabled = False

        try:
            enforcer = Enforcer(self._policy)

            def run() -> None:
                enforcer.enforce_sync(
                    _noop_tool_with_args,
                    "test query",
                    tool_name="search_web",
                )

            result = _measure(run, iterations)
        finally:
            settings.audit_enabled = original_audit

        result.name = "enforcer_e2e"
        return result

    def bench_enforcer_with_pii(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark the full enforcement pipeline WITH PII redaction.

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        original_audit = settings.audit_enabled
        original_redaction = settings.redaction_enabled
        settings.audit_enabled = False
        settings.redaction_enabled = True

        try:
            enforcer = Enforcer(self._pii_policy)

            sample = "Contact john@example.com, phone 555-123-4567"

            def run() -> None:
                enforcer.enforce_sync(
                    _noop_tool_with_args,
                    sample,
                    tool_name="search_web",
                )

            result = _measure(run, iterations)
        finally:
            settings.audit_enabled = original_audit
            settings.redaction_enabled = original_redaction

        result.name = "enforcer_e2e_with_pii"
        return result

    # -- Scalability benchmarks -----------------------------------------------

    def bench_policy_large_allowlist(
        self, num_tools: int = 1000, iterations: int = 1000
    ) -> BenchmarkResult:
        """Benchmark policy evaluation with a large allowlist.

        Args:
            num_tools: Number of tools in the allowed list.
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        large_policy = Policy(
            name="large-allowlist",
            version="1.0.0",
            rules=PolicyRules(
                allowed_tools=[f"tool_{i}" for i in range(num_tools)],
                denied_tools=["blocked_tool"],
            ),
        )
        engine = PolicyEngine(large_policy)
        # Use a tool that IS in the list (worst-case: must scan the set)
        ctx = CallContext(tool_name=f"tool_{num_tools - 1}")

        def run() -> None:
            engine.evaluate_pre_call(ctx)

        result = _measure(run, iterations)
        result.name = f"policy_allowlist_{num_tools}"
        result.details["num_tools"] = num_tools
        return result

    def bench_pii_long_text(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark PII redaction on a longer text (~2KB).

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        redactor = Redactor(
            categories=["email", "phone", "ssn"],
            strategy=RedactionStrategy.MASK,
        )
        # ~2KB text with scattered PII
        base = (
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
            "Contact us at user@example.com or call 555-987-6543. "
            "SSN: 987-65-4321. More text follows here to pad the input. "
        )
        sample = base * 8  # ~2KB

        def run() -> None:
            redactor.redact(sample)

        result = _measure(run, iterations)
        result.name = "pii_long_text"
        result.details["text_length"] = len(sample)
        return result

    def bench_pii_clean_text(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark PII redaction on text with no PII (fast-path).

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        redactor = Redactor(
            categories=["email", "phone", "ssn"],
            strategy=RedactionStrategy.MASK,
        )
        sample = (
            "The quick brown fox jumps over the lazy dog. "
            "No personally identifiable information here. "
        ) * 5

        def run() -> None:
            redactor.redact(sample)

        result = _measure(run, iterations)
        result.name = "pii_clean_text"
        return result

    def bench_audit_verify(self, chain_length: int = 100, iterations: int = 100) -> BenchmarkResult:
        """Benchmark audit trail verification.

        Args:
            chain_length: Number of entries in the chain.
            iterations: Number of verification passes.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        import os
        import tempfile
        import uuid
        from pathlib import Path

        from enforcecore.auditor.engine import Auditor, verify_trail

        fd, tmp_path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)
        path = Path(tmp_path)
        auditor = Auditor(output_path=path)
        for i in range(chain_length):
            auditor.record(
                call_id=str(uuid.uuid4()),
                tool_name=f"tool_{i}",
                policy_name="bench",
                policy_version="1.0",
                decision="allowed",
            )

        def run() -> None:
            verify_trail(path)

        try:
            result = _measure(run, iterations, warmup=10)
        finally:
            os.unlink(tmp_path)

        result.name = f"audit_verify_{chain_length}"
        result.details["chain_length"] = chain_length
        return result

    def bench_rate_limiter(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark rate limiter acquire (non-contended).

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        from enforcecore.guard.ratelimit import RateLimiter

        limiter = RateLimiter()
        limiter.configure("bench_tool", max_calls=1_000_000, window_seconds=60)

        def run() -> None:
            limiter.acquire("bench_tool", "bench-policy")

        result = _measure(run, iterations)
        result.name = "rate_limiter"
        return result

    def bench_secret_detection(self, iterations: int = 1000) -> BenchmarkResult:
        """Benchmark secret detection scanning.

        Args:
            iterations: Number of iterations to run.

        Returns:
            A :class:`BenchmarkResult` with timing statistics.
        """
        from enforcecore.redactor.secrets import SecretScanner

        scanner = SecretScanner()
        sample = (
            "AWS key: AKIAIOSFODNN7EXAMPLE and secret "
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
            "plus a github token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01"
        )

        def run() -> None:
            scanner.detect(sample)

        result = _measure(run, iterations)
        result.name = "secret_detection"
        return result

    # -- Run all benchmarks ---------------------------------------------------

    def run_all(self, iterations: int = 1000) -> BenchmarkSuite:
        """Execute all benchmarks and return the suite results.

        Args:
            iterations: Number of iterations per benchmark.

        Returns:
            A :class:`BenchmarkSuite` with all benchmark results.
        """
        import enforcecore

        logger.info("benchmarks_start", iterations=iterations)
        t0 = time.perf_counter()

        results = [
            # Core component benchmarks
            self.bench_policy_pre_call(iterations),
            self.bench_policy_post_call(iterations),
            self.bench_pii_redaction(iterations),
            self.bench_pii_clean_text(iterations),
            self.bench_pii_long_text(iterations),
            self.bench_audit_record(iterations),
            self.bench_audit_verify(chain_length=100, iterations=max(iterations // 10, 10)),
            self.bench_guard_overhead(iterations),
            self.bench_rate_limiter(iterations),
            self.bench_secret_detection(iterations),
            # Scalability
            self.bench_policy_large_allowlist(num_tools=100, iterations=iterations),
            self.bench_policy_large_allowlist(num_tools=1000, iterations=iterations),
            self.bench_policy_large_allowlist(num_tools=10000, iterations=iterations),
            # End-to-end
            self.bench_enforcer_e2e(iterations),
            self.bench_enforcer_with_pii(iterations),
        ]

        total_ms = round((time.perf_counter() - t0) * 1000, 2)

        cpu_info = ""
        try:
            cpu_info = platform.processor() or platform.machine()
        except Exception:
            cpu_info = "unknown"

        suite = BenchmarkSuite(
            results=results,
            total_duration_ms=total_ms,
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            platform=f"{platform.system()} {platform.machine()}",
            cpu=cpu_info,
            machine=platform.machine(),
            enforcecore_version=enforcecore.__version__,
        )

        logger.info(
            "benchmarks_complete",
            total_ms=total_ms,
            benchmark_count=len(results),
        )

        return suite

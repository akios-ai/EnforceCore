# Benchmark Report

EnforceCore includes a reproducible benchmark suite that measures per-component
latency with statistical rigour. All results are generated deterministically
from in-memory workloads (no network, no disk I/O in the hot path) and include
warmup phases to eliminate cold-start bias.

## Methodology

| Parameter | Value |
|-----------|-------|
| Warmup iterations | 100 (not timed) |
| Timed iterations | 1 000 per benchmark |
| Percentiles | P50, P95, P99, P99.9 |
| Statistical measures | Mean, Median, Std Dev, Min, Max |
| Clock | `time.perf_counter()` (nanosecond resolution) |
| Environment | Single-threaded, GC enabled, no external services |

Each benchmark:

1. **Warmup** — runs the function 100 times to populate caches and trigger
   any JIT-level optimisations in the interpreter.
2. **Timed loop** — records wall-clock time for each of the 1 000 iterations.
3. **Statistics** — computes percentiles via linear interpolation, standard
   deviation, and ops/second from the raw latency array.

## Benchmarks

### Core Component Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `policy_pre_call` | Pre-call policy evaluation (3-tool allowlist, 2-tool denylist) |
| `policy_post_call` | Post-call policy evaluation (output size check) |
| `pii_redaction` | PII redaction — email + phone in ~130-char input |
| `pii_clean_text` | PII scan on text with no PII (fast-path) |
| `pii_long_text` | PII redaction on ~2 KB text with scattered entities |
| `audit_record` | Write one Merkle-chained audit entry |
| `audit_verify_100` | Verify a 100-entry Merkle chain |
| `guard_overhead` | Resource guard overhead on an allowed call |
| `rate_limiter` | Rate limiter acquire (non-contended sliding window) |
| `secret_detection` | Scan text for AWS keys, GitHub tokens, bearer tokens |

### Scalability Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `policy_allowlist_100` | Policy eval with 100 allowed tools |
| `policy_allowlist_1000` | Policy eval with 1 000 allowed tools |
| `policy_allowlist_10000` | Policy eval with 10 000 allowed tools |

### End-to-End Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `enforcer_e2e` | Full enforcement pipeline (policy + audit + guard) |
| `enforcer_e2e_with_pii` | Full pipeline including PII redaction |

## Reference Results

> Measured on Apple Silicon (arm64), Python 3.14.2, macOS.
> Your numbers will differ — run the suite locally for your hardware.

| Benchmark | Iterations | Mean (ms) | P50 (ms) | P95 (ms) | P99 (ms) | P99.9 (ms) | StdDev (ms) |
|-----------|------------|-----------|----------|----------|----------|------------|-------------|
| policy_pre_call | 1,000 | 0.0927 | 0.0118 | 0.0196 | 0.2275 | 69.3257 | 2.1955 |
| policy_post_call | 1,000 | 0.0002 | 0.0002 | 0.0003 | 0.0003 | 0.0005 | 0.0000 |
| pii_redaction | 1,000 | 0.0347 | 0.0279 | 0.0357 | 0.2750 | 0.7607 | 0.0498 |
| pii_clean_text | 1,000 | 0.0288 | 0.0282 | 0.0324 | 0.0405 | 0.0858 | 0.0034 |
| pii_long_text | 1,000 | 0.1338 | 0.1286 | 0.1563 | 0.2204 | 0.3584 | 0.0182 |
| audit_record | 1,000 | 0.0786 | 0.0677 | 0.1267 | 0.2324 | 1.5794 | 0.0565 |
| audit_verify_100 | 100 | 1.1387 | 1.1136 | 1.3251 | 1.4568 | 1.4568 | 0.0815 |
| guard_overhead | 1,000 | 0.0002 | 0.0002 | 0.0003 | 0.0003 | 0.0032 | 0.0001 |
| rate_limiter | 1,000 | 0.0004 | 0.0003 | 0.0005 | 0.0016 | 0.0256 | 0.0010 |
| secret_detection | 1,000 | 0.0119 | 0.0117 | 0.0119 | 0.0166 | 0.0655 | 0.0025 |
| policy_allowlist_100 | 1,000 | 0.0251 | 0.0194 | 0.0243 | 0.3412 | 0.9967 | 0.0593 |
| policy_allowlist_1000 | 1,000 | 0.0534 | 0.0503 | 0.0624 | 0.1042 | 0.1875 | 0.0105 |
| policy_allowlist_10000 | 1,000 | 0.4300 | 0.4081 | 0.5582 | 0.7181 | 1.9790 | 0.0858 |
| enforcer_e2e | 1,000 | 0.0951 | 0.0561 | 0.2566 | 0.8919 | 3.1739 | 0.1824 |
| enforcer_e2e_with_pii | 1,000 | 0.1258 | 0.0929 | 0.4322 | 0.8068 | 0.9326 | 0.1277 |

**Total duration:** ~1 400 ms

### Key Observations

* **Policy evaluation** is sub-millisecond even at P99 for typical allowlists
  (≤ 1 000 tools). At 10 000 tools P99 is still under 1 ms.
* **PII redaction** is ~0.03 ms for short text and ~0.13 ms for 2 KB text
  at P50, dominated by regex scanning.
* **Guard overhead** and **rate limiter** are effectively zero-cost at
  < 1 μs per call.
* **End-to-end enforcement** (policy + audit + guard) is < 0.1 ms at P50,
  < 1 ms at P99. Adding PII redaction pushes P50 to ~0.09 ms.
* **Audit chain verification** scales linearly — ~1.1 ms for 100 entries.

## Reproduction

### CLI

```bash
# Default: 1000 iterations, Markdown output
python -m benchmarks.run

# 5000 iterations, JSON output
python -m benchmarks.run --iterations 5000 --format json

# Both formats, written to disk
python -m benchmarks.run --format all --output results/
```

### Python API

```python
from enforcecore.eval.benchmarks import BenchmarkRunner

runner = BenchmarkRunner()
suite = runner.run_all(iterations=1000)

# Markdown report
print(suite.to_markdown())

# JSON export
with open("results.json", "w") as f:
    f.write(suite.to_json())
```

### CI

Benchmarks run in CI on every push. The workflow uses `--format json` to
produce machine-readable output for regression detection. See
`.github/workflows/ci.yml` for configuration.

## Output Formats

### JSON

```json
{
  "metadata": {
    "timestamp": "2026-02-21T15:56:09Z",
    "python_version": "3.14.2",
    "platform": "Darwin arm64",
    "cpu": "arm",
    "machine": "arm64",
    "enforcecore_version": "1.0.23a1",
    "total_duration_ms": 1372.34
  },
  "results": [
    {
      "name": "policy_pre_call",
      "iterations": 1000,
      "warmup_iterations": 100,
      "mean_ms": 0.0927,
      "p50_ms": 0.0118,
      "p95_ms": 0.0196,
      "p99_ms": 0.2275,
      "p999_ms": 69.3257,
      "std_dev_ms": 2.1955
    }
  ]
}
```

### Markdown

The `to_markdown()` method renders a self-contained report section with
environment metadata and a Markdown table, suitable for pasting into
GitHub issues or documentation.

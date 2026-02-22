# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""CLI entry point for the EnforceCore benchmark suite.

Usage::

    python -m benchmarks.run
    python -m benchmarks.run --iterations 5000
    python -m benchmarks.run --output results/
    python -m benchmarks.run --format json
    python -m benchmarks.run --format markdown
    python -m benchmarks.run --format all --output results/

Outputs are written to ``stdout`` by default, or to files in the specified
output directory. When ``--format all`` is used with ``--output``, both
``benchmark_results.json`` and ``benchmark_results.md`` are generated.
"""

from __future__ import annotations

import argparse
from pathlib import Path


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="benchmarks",
        description="Run the EnforceCore reproducible benchmark suite.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Number of timed iterations per benchmark (default: 1000).",
    )
    parser.add_argument(
        "--warmup",
        type=int,
        default=100,
        help="Number of warm-up iterations before timing (default: 100).",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "all"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Directory to write results to. Prints to stdout if omitted.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Run benchmarks and emit results."""
    args = _parse_args(argv)

    # Lazy import so --help is fast
    from enforcecore.eval.benchmarks import BenchmarkRunner

    runner = BenchmarkRunner()
    suite = runner.run_all(iterations=args.iterations)

    out_dir: Path | None = Path(args.output) if args.output else None
    if out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)

    fmt: str = args.format

    if fmt in ("json", "all"):
        json_str = suite.to_json()
        if out_dir:
            dest = out_dir / "benchmark_results.json"
            dest.write_text(json_str, encoding="utf-8")
            print(f"JSON results written to {dest}")
        else:
            print(json_str)

    if fmt in ("markdown", "all"):
        md = suite.to_markdown()
        if out_dir:
            dest = out_dir / "benchmark_results.md"
            dest.write_text(md, encoding="utf-8")
            print(f"Markdown results written to {dest}")
        else:
            print(md)


if __name__ == "__main__":
    main()

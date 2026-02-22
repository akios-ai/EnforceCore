# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry metrics for EnforceCore.

Tracks counters, histograms, and gauges for enforcement operations.
All metrics are namespaced under ``enforcecore.*``.
"""

from __future__ import annotations

import threading
from typing import Any

import structlog

logger = structlog.get_logger("enforcecore.telemetry.metrics")

# ---------------------------------------------------------------------------
# Metric names (constants for consumers)
# ---------------------------------------------------------------------------

CALLS_TOTAL = "enforcecore.calls.total"
BLOCKS_TOTAL = "enforcecore.calls.blocked"
REDACTIONS_TOTAL = "enforcecore.redactions.total"
VIOLATIONS_TOTAL = "enforcecore.violations.total"
LATENCY_HISTOGRAM = "enforcecore.call.duration_ms"
OVERHEAD_HISTOGRAM = "enforcecore.enforcement.overhead_ms"
COST_GAUGE = "enforcecore.cost.accumulated_usd"


class EnforceCoreMetrics:
    """Lightweight metrics collector for EnforceCore.

    When OpenTelemetry is available, delegates to OTel meters.
    Otherwise, maintains in-process counters for programmatic access.

    Thread-safe: all mutations are protected by a lock.
    """

    __slots__ = (
        "_blocks",
        "_calls",
        "_cost_usd",
        "_lock",
        "_otel_counter_blocks",
        "_otel_counter_calls",
        "_otel_counter_redactions",
        "_otel_counter_violations",
        "_otel_histogram_latency",
        "_otel_histogram_overhead",
        "_redactions",
        "_violations",
    )

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: int = 0
        self._blocks: int = 0
        self._redactions: int = 0
        self._violations: int = 0
        self._cost_usd: float = 0.0

        # OTel instruments (set when instrument() is called)
        self._otel_counter_calls: Any = None
        self._otel_counter_blocks: Any = None
        self._otel_counter_redactions: Any = None
        self._otel_counter_violations: Any = None
        self._otel_histogram_latency: Any = None
        self._otel_histogram_overhead: Any = None

    def bind_otel(self, meter: Any) -> None:
        """Bind OpenTelemetry meter instruments.

        Called by :class:`EnforceCoreInstrumentor` during instrumentation.
        """
        self._otel_counter_calls = meter.create_counter(
            CALLS_TOTAL,
            description="Total enforcement calls",
            unit="1",
        )
        self._otel_counter_blocks = meter.create_counter(
            BLOCKS_TOTAL,
            description="Total blocked calls",
            unit="1",
        )
        self._otel_counter_redactions = meter.create_counter(
            REDACTIONS_TOTAL,
            description="Total PII redactions applied",
            unit="1",
        )
        self._otel_counter_violations = meter.create_counter(
            VIOLATIONS_TOTAL,
            description="Total policy violations",
            unit="1",
        )
        self._otel_histogram_latency = meter.create_histogram(
            LATENCY_HISTOGRAM,
            description="Tool call duration",
            unit="ms",
        )
        self._otel_histogram_overhead = meter.create_histogram(
            OVERHEAD_HISTOGRAM,
            description="Enforcement overhead",
            unit="ms",
        )

    # -- Recording methods --------------------------------------------------

    def record_call(
        self,
        *,
        tool_name: str,
        decision: str,
        duration_ms: float = 0.0,
        overhead_ms: float = 0.0,
        input_redactions: int = 0,
        output_redactions: int = 0,
    ) -> None:
        """Record a completed enforcement call.

        Args:
            tool_name: Name of the enforced tool.
            decision: Enforcement decision (``"allowed"`` or ``"blocked"``).
            duration_ms: Tool call duration in milliseconds.
            overhead_ms: Enforcement overhead in milliseconds.
            input_redactions: Number of PII entities redacted from inputs.
            output_redactions: Number of PII entities redacted from outputs.
        """
        attrs = {"tool": tool_name, "decision": decision}
        total_redactions = input_redactions + output_redactions

        with self._lock:
            self._calls += 1
            if decision == "blocked":
                self._blocks += 1
            self._redactions += total_redactions

        # OTel delegation
        if self._otel_counter_calls is not None:
            self._otel_counter_calls.add(1, attrs)
        if decision == "blocked" and self._otel_counter_blocks is not None:
            self._otel_counter_blocks.add(1, attrs)
        if total_redactions > 0 and self._otel_counter_redactions is not None:
            self._otel_counter_redactions.add(total_redactions, attrs)
        if self._otel_histogram_latency is not None and duration_ms > 0:
            self._otel_histogram_latency.record(duration_ms, attrs)
        if self._otel_histogram_overhead is not None and overhead_ms > 0:
            self._otel_histogram_overhead.record(overhead_ms, attrs)

    def record_violation(self, *, tool_name: str, violation_type: str) -> None:
        """Record a policy violation.

        Args:
            tool_name: Name of the tool that was blocked.
            violation_type: Category of the violation (e.g., ``"tool_denied"``).
        """
        with self._lock:
            self._violations += 1

        if self._otel_counter_violations is not None:
            self._otel_counter_violations.add(
                1, {"tool": tool_name, "violation_type": violation_type}
            )

    def record_cost(self, usd: float) -> None:
        """Record accumulated cost.

        Args:
            usd: Cost in USD to add to the running total.
        """
        with self._lock:
            self._cost_usd += usd

    # -- Read accessors (for testing / dashboards) --------------------------

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls

    @property
    def blocks(self) -> int:
        with self._lock:
            return self._blocks

    @property
    def redactions(self) -> int:
        with self._lock:
            return self._redactions

    @property
    def violations(self) -> int:
        with self._lock:
            return self._violations

    @property
    def cost_usd(self) -> float:
        with self._lock:
            return self._cost_usd

    def snapshot(self) -> dict[str, int | float]:
        """Return a snapshot of all metrics."""
        with self._lock:
            return {
                "calls": self._calls,
                "blocks": self._blocks,
                "redactions": self._redactions,
                "violations": self._violations,
                "cost_usd": self._cost_usd,
            }

    def reset(self) -> None:
        """Reset all in-process counters. Does not affect OTel instruments."""
        with self._lock:
            self._calls = 0
            self._blocks = 0
            self._redactions = 0
            self._violations = 0
            self._cost_usd = 0.0

    def __repr__(self) -> str:
        return (
            f"EnforceCoreMetrics(calls={self.calls}, blocks={self.blocks}, "
            f"redactions={self.redactions}, violations={self.violations})"
        )

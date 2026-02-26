# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Prometheus metrics exporter for EnforceCore.

Exports enforcement metrics with standard Prometheus naming conventions.
Requires ``pip install enforcecore[prometheus]`` (installs ``prometheus_client``).

Usage::

    from enforcecore.telemetry.prometheus import EnforceCorePrometheusExporter

    exporter = EnforceCorePrometheusExporter()
    exporter.instrument()  # registers hooks, starts recording

    # Access raw prometheus_client objects for custom dashboards
    print(exporter.calls_counter._metrics)

    # Or start the default HTTP metrics server on port 9090
    exporter.start_http_server(port=9090)

Prometheus metric names follow the ``enforcecore_*_total`` / ``enforcecore_*_seconds``
convention mandated by the OpenMetrics standard.

Alternatively, if you are already using the OpenTelemetry SDK, you can use
the official ``opentelemetry-exporter-prometheus`` bridge — see the
`OpenTelemetry Prometheus docs <https://opentelemetry.io/docs/languages/python/exporters/#prometheus>`_.
"""

from __future__ import annotations

import threading
from typing import Any

import structlog

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)

logger = structlog.get_logger("enforcecore.telemetry.prometheus")

# ---------------------------------------------------------------------------
# Prometheus metric names (Prometheus / OpenMetrics convention)
# ---------------------------------------------------------------------------

PROM_CALLS_TOTAL = "enforcecore_calls_total"
PROM_VIOLATIONS_TOTAL = "enforcecore_violations_total"
PROM_REDACTIONS_TOTAL = "enforcecore_redactions_total"
PROM_OVERHEAD_SECONDS = "enforcecore_overhead_seconds"
PROM_LATENCY_SECONDS = "enforcecore_latency_seconds"

# Standard Prometheus histogram buckets for sub-millisecond enforcement overhead
_OVERHEAD_BUCKETS = (0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)
_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0)


class EnforceCorePrometheusExporter:
    """Exports EnforceCore enforcement decisions as Prometheus metrics.

    Registers hooks into the global :class:`~enforcecore.plugins.hooks.HookRegistry`
    and records the following metrics:

    * ``enforcecore_calls_total`` — counter, labels: ``tool``, ``decision``
    * ``enforcecore_violations_total`` — counter, labels: ``tool``, ``violation_type``
    * ``enforcecore_redactions_total`` — counter, labels: ``tool``, ``direction``
    * ``enforcecore_overhead_seconds`` — histogram of enforcement overhead
    * ``enforcecore_latency_seconds`` — histogram of tool call duration

    Requires ``prometheus_client`` to be installed::

        pip install enforcecore[prometheus]

    If ``prometheus_client`` is not installed, the exporter operates in
    **no-op mode** — hooks are registered but metrics are not recorded.
    This ensures code that calls :meth:`instrument` never raises ImportError.

    Example::

        from enforcecore.telemetry.prometheus import EnforceCorePrometheusExporter

        exp = EnforceCorePrometheusExporter()
        exp.instrument()
        # … run your agent …
        exp.start_http_server(port=9090)   # serves /metrics for Prometheus scraping

    .. versionadded:: 1.5.0
    """

    _instance_lock = threading.Lock()
    _instrumented: bool = False

    def __init__(self, *, registry: Any = None) -> None:
        """Initialise the exporter.

        Args:
            registry: A ``prometheus_client.CollectorRegistry`` to register
                metrics into.  Defaults to the global default registry.
                Pass a fresh ``CollectorRegistry()`` in tests to avoid
                cross-test pollution.
        """
        self._prom_registry = registry  # None → default registry
        self._available = False

        # Prometheus instruments (set in _setup_metrics)
        self._calls_counter: Any = None
        self._violations_counter: Any = None
        self._redactions_counter: Any = None
        self._overhead_histogram: Any = None
        self._latency_histogram: Any = None

        # Hook bound-method references (for add/remove identity)
        self._hook_post = self._on_post_call
        self._hook_violation = self._on_violation
        self._hook_redaction = self._on_redaction

        self._lock = threading.Lock()

        self._setup_metrics()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup_metrics(self) -> None:
        """Create prometheus_client instruments (no-op if not installed)."""
        try:
            import prometheus_client as prom

            kw: dict[str, Any] = {}
            if self._prom_registry is not None:
                kw["registry"] = self._prom_registry

            self._calls_counter = prom.Counter(
                PROM_CALLS_TOTAL,
                "Total enforcement calls, partitioned by tool and decision.",
                ["tool", "decision"],
                **kw,
            )
            self._violations_counter = prom.Counter(
                PROM_VIOLATIONS_TOTAL,
                "Total policy violations, partitioned by tool and violation type.",
                ["tool", "violation_type"],
                **kw,
            )
            self._redactions_counter = prom.Counter(
                PROM_REDACTIONS_TOTAL,
                "Total PII redactions applied, partitioned by tool and direction.",
                ["tool", "direction"],
                **kw,
            )
            self._overhead_histogram = prom.Histogram(
                PROM_OVERHEAD_SECONDS,
                "Enforcement overhead in seconds (time added by EnforceCore).",
                ["tool"],
                buckets=_OVERHEAD_BUCKETS,
                **kw,
            )
            self._latency_histogram = prom.Histogram(
                PROM_LATENCY_SECONDS,
                "Tool call latency in seconds (actual function execution time).",
                ["tool"],
                buckets=_LATENCY_BUCKETS,
                **kw,
            )
            self._available = True
            logger.debug("prometheus_metrics_initialised")
        except ImportError:
            logger.debug("prometheus_client_not_available_running_in_noop_mode")

    # ------------------------------------------------------------------
    # Instrument / uninstrument
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Register hooks and start recording metrics.

        Idempotent: calling :meth:`instrument` multiple times is safe.
        """
        with self._instance_lock:
            if self._instrumented:
                logger.debug("prometheus_already_instrumented")
                return
            registry = HookRegistry.global_registry()
            registry.add_post_call(self._hook_post)
            registry.add_violation(self._hook_violation)
            registry.add_redaction(self._hook_redaction)
            self._instrumented = True
            logger.info("prometheus_instrumentation_enabled")

    def uninstrument(self) -> None:
        """Remove hooks and stop recording metrics.

        Idempotent: calling :meth:`uninstrument` before :meth:`instrument`
        is safe.
        """
        with self._instance_lock:
            if not self._instrumented:
                return
            registry = HookRegistry.global_registry()
            registry.remove_post_call(self._hook_post)
            registry.remove_violation(self._hook_violation)
            registry.remove_redaction(self._hook_redaction)
            self._instrumented = False
            logger.info("prometheus_instrumentation_disabled")

    @property
    def is_instrumented(self) -> bool:
        """``True`` if hooks are currently registered."""
        return self._instrumented

    @property
    def is_available(self) -> bool:
        """``True`` if ``prometheus_client`` is installed and metrics are active."""
        return self._available

    # ------------------------------------------------------------------
    # HTTP server
    # ------------------------------------------------------------------

    def start_http_server(self, port: int = 9090, addr: str = "0.0.0.0") -> None:
        """Start a Prometheus HTTP metrics server.

        Serves the ``/metrics`` endpoint that Prometheus can scrape.

        Args:
            port: TCP port to listen on. Defaults to ``9090``.
            addr: Address to bind to. Defaults to ``"0.0.0.0"`` (all interfaces).

        Raises:
            ImportError: If ``prometheus_client`` is not installed.
        """
        import prometheus_client as prom

        kw: dict[str, Any] = {}
        if self._prom_registry is not None:
            kw["registry"] = self._prom_registry

        prom.start_http_server(port, addr=addr, **kw)
        logger.info("prometheus_http_server_started", port=port, addr=addr)

    # ------------------------------------------------------------------
    # Hook callbacks
    # ------------------------------------------------------------------

    def _on_post_call(self, ctx: HookContext) -> None:
        if not self._available:
            return
        try:
            self._calls_counter.labels(tool=ctx.tool_name, decision="allowed").inc()
            if ctx.duration_ms > 0:
                self._latency_histogram.labels(tool=ctx.tool_name).observe(ctx.duration_ms / 1000.0)
            if ctx.overhead_ms > 0:
                self._overhead_histogram.labels(tool=ctx.tool_name).observe(
                    ctx.overhead_ms / 1000.0
                )
        except Exception:
            logger.debug("prometheus_post_call_error", exc_info=True)

    def _on_violation(self, ctx: ViolationHookContext) -> None:
        if not self._available:
            return
        try:
            self._calls_counter.labels(tool=ctx.tool_name, decision="blocked").inc()
            self._violations_counter.labels(
                tool=ctx.tool_name,
                violation_type=str(ctx.violation_type),
            ).inc()
        except Exception:
            logger.debug("prometheus_violation_error", exc_info=True)

    def _on_redaction(self, ctx: RedactionHookContext) -> None:
        if not self._available:
            return
        try:
            self._redactions_counter.labels(
                tool=ctx.tool_name,
                direction=ctx.direction,
            ).inc(ctx.redaction_count)
        except Exception:
            logger.debug("prometheus_redaction_error", exc_info=True)

    # ------------------------------------------------------------------
    # Accessors (useful for testing without prometheus_client)
    # ------------------------------------------------------------------

    @property
    def calls_counter(self) -> Any:
        """The ``enforcecore_calls_total`` Counter (or ``None`` if unavailable)."""
        return self._calls_counter

    @property
    def violations_counter(self) -> Any:
        """The ``enforcecore_violations_total`` Counter (or ``None`` if unavailable)."""
        return self._violations_counter

    @property
    def redactions_counter(self) -> Any:
        """The ``enforcecore_redactions_total`` Counter (or ``None`` if unavailable)."""
        return self._redactions_counter

    @property
    def overhead_histogram(self) -> Any:
        """The ``enforcecore_overhead_seconds`` Histogram (or ``None`` if unavailable)."""
        return self._overhead_histogram

    @property
    def latency_histogram(self) -> Any:
        """The ``enforcecore_latency_seconds`` Histogram (or ``None`` if unavailable)."""
        return self._latency_histogram

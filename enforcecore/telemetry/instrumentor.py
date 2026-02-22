# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry auto-instrumentor for EnforceCore.

Registers hooks into the global :class:`HookRegistry` to emit
traces and metrics for every enforcement call.

Usage::

    from enforcecore.telemetry import EnforceCoreInstrumentor

    EnforceCoreInstrumentor().instrument()
    # All subsequent @enforce calls will emit OTel spans + metrics.

    EnforceCoreInstrumentor().uninstrument()
    # Hooks are removed, telemetry stops.
"""

from __future__ import annotations

import threading
from typing import Any

import structlog

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    ViolationHookContext,
)
from enforcecore.telemetry.metrics import EnforceCoreMetrics

logger = structlog.get_logger("enforcecore.telemetry")

_SCOPE_NAME = "enforcecore"
_SCOPE_VERSION = "1.0.19a1"


class EnforceCoreInstrumentor:
    """Auto-instruments EnforceCore with OpenTelemetry traces and metrics.

    Registers pre-call and post-call hooks in the global
    :class:`HookRegistry`. Each enforcement call produces:

    - A trace span named ``enforcecore.<tool_name>`` with attributes
      for decision, policy, redaction counts, and timing.
    - Counter and histogram updates via :class:`EnforceCoreMetrics`.

    OpenTelemetry is optional — if not installed, the instrumentor
    still records in-process metrics via the lightweight
    :class:`EnforceCoreMetrics` collector.
    """

    _instance_lock = threading.Lock()
    _instrumented: bool = False

    def __init__(self) -> None:
        self._metrics = EnforceCoreMetrics()
        self._tracer: Any = None
        self._active_spans: dict[str, Any] = {}
        self._lock = threading.Lock()
        # Store bound method refs so add/remove use identical objects
        self._hook_pre = self._on_pre_call
        self._hook_post = self._on_post_call
        self._hook_violation = self._on_violation

    @property
    def metrics(self) -> EnforceCoreMetrics:
        """Access the metrics collector."""
        return self._metrics

    def instrument(
        self,
        *,
        tracer_provider: Any = None,
        meter_provider: Any = None,
    ) -> None:
        """Start instrumentation.

        Args:
            tracer_provider: OpenTelemetry TracerProvider. If ``None``,
                uses the global provider (if OTel is installed) or
                falls back to no-op tracing.
            meter_provider: OpenTelemetry MeterProvider. If ``None``,
                uses the global provider (if OTel is installed) or
                falls back to in-process metrics only.
        """
        with self._instance_lock:
            if self._instrumented:
                logger.debug("already_instrumented")
                return

            # Try to set up OTel tracing
            try:
                from opentelemetry import trace

                provider = tracer_provider or trace.get_tracer_provider()
                self._tracer = provider.get_tracer(_SCOPE_NAME, _SCOPE_VERSION)
                logger.info("otel_tracer_configured")
            except ImportError:
                self._tracer = None
                logger.debug("otel_not_available_tracing_disabled")

            # Try to set up OTel metrics
            try:
                from opentelemetry import metrics as otel_metrics

                provider = meter_provider or otel_metrics.get_meter_provider()
                meter = provider.get_meter(_SCOPE_NAME, _SCOPE_VERSION)
                self._metrics.bind_otel(meter)
                logger.info("otel_meter_configured")
            except ImportError:
                logger.debug("otel_not_available_using_inprocess_metrics")

            # Register hooks
            registry = HookRegistry.global_registry()
            registry.add_pre_call(self._hook_pre)
            registry.add_post_call(self._hook_post)
            registry.add_violation(self._hook_violation)

            self._instrumented = True
            logger.info("instrumentation_enabled")

    def uninstrument(self) -> None:
        """Stop instrumentation and remove hooks."""
        with self._instance_lock:
            if not self._instrumented:
                return

            registry = HookRegistry.global_registry()
            registry.remove_pre_call(self._hook_pre)
            registry.remove_post_call(self._hook_post)
            registry.remove_violation(self._hook_violation)

            # End any active spans
            with self._lock:
                for span in self._active_spans.values():
                    span.end()
                self._active_spans.clear()

            self._instrumented = False
            logger.info("instrumentation_disabled")

    @property
    def is_instrumented(self) -> bool:
        return self._instrumented

    # -- Hook callbacks -----------------------------------------------------

    def _on_pre_call(self, ctx: HookContext) -> None:
        """Start a trace span for this enforcement call."""
        if self._tracer is not None:
            span = self._tracer.start_span(
                f"enforcecore.{ctx.tool_name}",
                attributes={
                    "enforcecore.tool": ctx.tool_name,
                    "enforcecore.policy": ctx.policy_name,
                    "enforcecore.call_id": ctx.call_id,
                },
            )
            with self._lock:
                self._active_spans[ctx.call_id] = span

    def _on_post_call(self, ctx: HookContext) -> None:
        """End the trace span and record metrics."""
        # Record metrics
        self._metrics.record_call(
            tool_name=ctx.tool_name,
            decision="allowed",
            duration_ms=ctx.duration_ms or 0.0,
        )

        # End span
        if self._tracer is not None:
            with self._lock:
                span = self._active_spans.pop(ctx.call_id, None)
            if span is not None:
                span.set_attribute("enforcecore.decision", "allowed")
                if ctx.duration_ms:
                    span.set_attribute("enforcecore.duration_ms", ctx.duration_ms)
                span.end()

    def _on_violation(self, ctx: ViolationHookContext) -> None:
        """Record the violation in metrics and mark the span."""
        self._metrics.record_call(
            tool_name=ctx.tool_name,
            decision="blocked",
        )
        self._metrics.record_violation(
            tool_name=ctx.tool_name,
            violation_type=str(ctx.violation_type),
        )

        # End span with error status
        if self._tracer is not None:
            with self._lock:
                span = self._active_spans.pop(ctx.call_id, None)
            if span is not None:
                span.set_attribute("enforcecore.decision", "blocked")
                span.set_attribute("enforcecore.violation_type", str(ctx.violation_type))
                span.set_attribute("enforcecore.violation_reason", ctx.violation_reason)
                try:
                    from opentelemetry.trace import StatusCode

                    span.set_status(StatusCode.ERROR, ctx.violation_reason)
                except ImportError:
                    pass
                span.end()

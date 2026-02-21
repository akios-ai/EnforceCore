"""OpenTelemetry integration for EnforceCore.

Provides automatic tracing and metrics for enforcement calls when
the ``telemetry`` extra is installed::

    pip install enforcecore[telemetry]

Traces emit one span per enforcement call with tool name, decision,
and duration.  Metrics include counters (calls, blocks, redactions),
histograms (latency), and gauges (cost).

Works with any OpenTelemetry-compatible backend (Jaeger, Datadog,
Grafana Tempo, etc.).

Usage::

    from enforcecore.telemetry import EnforceCoreInstrumentor

    # Auto-instrument — hooks into the global HookRegistry
    EnforceCoreInstrumentor().instrument()

    # Or manually control the tracer/meter providers
    from opentelemetry import trace, metrics
    EnforceCoreInstrumentor().instrument(
        tracer_provider=trace.get_tracer_provider(),
        meter_provider=metrics.get_meter_provider(),
    )
"""

from enforcecore.telemetry.instrumentor import EnforceCoreInstrumentor
from enforcecore.telemetry.metrics import EnforceCoreMetrics

__all__ = [
    "EnforceCoreInstrumentor",
    "EnforceCoreMetrics",
]

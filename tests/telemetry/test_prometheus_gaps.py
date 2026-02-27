# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Coverage gap tests for enforcecore/telemetry/prometheus.py.

Targets _setup_metrics success path, _on_post_call / _on_violation /
_on_redaction with _available=True, start_http_server, and the remaining
property accessors — all exercised via a mocked prometheus_client.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)
from enforcecore.telemetry.prometheus import EnforceCorePrometheusExporter

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_prometheus_client() -> MagicMock:
    """Return a mock that looks enough like prometheus_client for our tests."""
    prom = MagicMock(spec=ModuleType)
    # Counter/Histogram are called as constructors: Counter(name, doc, labels, **kw)
    # Use side_effect so each call returns a DISTINCT MagicMock instance,
    # preventing _calls_counter and _violations_counter from being the same mock.
    prom.Counter = MagicMock(side_effect=lambda *a, **kw: MagicMock())
    prom.Histogram = MagicMock(side_effect=lambda *a, **kw: MagicMock())
    prom.CollectorRegistry = MagicMock(return_value=MagicMock())
    prom.start_http_server = MagicMock()
    return prom


def _make_exporter_with_fake_prom() -> tuple[EnforceCorePrometheusExporter, MagicMock]:
    """Create an EnforceCorePrometheusExporter with a mocked prometheus_client.

    Returns (exporter, fake_prom_module).
    The exporter will have _available=True and real Counter/Histogram mocks.
    """
    fake_prom = _make_fake_prometheus_client()
    # Patch sys.modules BEFORE calling __init__ so _setup_metrics uses our mock
    original = sys.modules.get("prometheus_client")
    sys.modules["prometheus_client"] = fake_prom  # type: ignore[assignment]
    try:
        exp = EnforceCorePrometheusExporter()
    finally:
        if original is None:
            sys.modules.pop("prometheus_client", None)
        else:
            sys.modules["prometheus_client"] = original
    return exp, fake_prom


# ---------------------------------------------------------------------------
# _setup_metrics success path
# ---------------------------------------------------------------------------


class TestSetupMetricsWithFakeProm:
    """_setup_metrics correctly initialises counters/histograms when prom available."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_available_true_when_prom_installed(self) -> None:
        """_available is True after _setup_metrics with mocked prometheus_client."""
        exp, _ = _make_exporter_with_fake_prom()
        assert exp.is_available is True

    def test_counter_created_via_prom_client(self) -> None:
        """prom.Counter was called for calls and violations metrics."""
        fake_prom = _make_fake_prometheus_client()
        original = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = fake_prom  # type: ignore[assignment]
        try:
            EnforceCorePrometheusExporter()
        finally:
            if original is None:
                sys.modules.pop("prometheus_client", None)
            else:
                sys.modules["prometheus_client"] = original

        # Counter must have been constructed at least twice (calls + violations)
        assert fake_prom.Counter.call_count >= 2

    def test_histogram_created_via_prom_client(self) -> None:
        """prom.Histogram was called for overhead and latency metrics."""
        fake_prom = _make_fake_prometheus_client()
        original = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = fake_prom  # type: ignore[assignment]
        try:
            EnforceCorePrometheusExporter()
        finally:
            if original is None:
                sys.modules.pop("prometheus_client", None)
            else:
                sys.modules["prometheus_client"] = original

        assert fake_prom.Histogram.call_count >= 2

    def test_all_metric_properties_non_none(self) -> None:
        """When prom is installed, all metric property accessors return non-None."""
        exp, _ = _make_exporter_with_fake_prom()

        assert exp.calls_counter is not None
        assert exp.violations_counter is not None
        assert exp.redactions_counter is not None
        assert exp.overhead_histogram is not None
        assert exp.latency_histogram is not None

    def test_registry_kwarg_forwarded_to_counter(self) -> None:
        """Custom registry is passed as kwarg to Counter/Histogram constructors."""
        fake_prom = _make_fake_prometheus_client()
        fake_registry = MagicMock()
        original = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = fake_prom  # type: ignore[assignment]
        try:
            EnforceCorePrometheusExporter(registry=fake_registry)
        finally:
            if original is None:
                sys.modules.pop("prometheus_client", None)
            else:
                sys.modules["prometheus_client"] = original

        # Verify registry kwarg was forwarded
        for call_args in fake_prom.Counter.call_args_list:
            _, kwargs = call_args
            assert kwargs.get("registry") is fake_registry


# ---------------------------------------------------------------------------
# _on_post_call with _available=True
# ---------------------------------------------------------------------------


class TestOnPostCallAvailable:
    """_on_post_call increments counters and observes histograms."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_calls_counter_incremented(self) -> None:
        """_on_post_call calls labels(...).inc() on the calls_counter."""
        exp, _ = _make_exporter_with_fake_prom()
        ctx = HookContext(call_id="a", tool_name="search", policy_name="p")
        ctx.duration_ms = 0.0
        ctx.overhead_ms = 0.0
        exp._on_post_call(ctx)

        exp._calls_counter.labels.assert_called_once_with(tool="search", decision="allowed")
        exp._calls_counter.labels.return_value.inc.assert_called_once()

    def test_latency_histogram_observed_when_duration_positive(self) -> None:
        """Latency histogram is observed when duration_ms > 0."""
        exp, _ = _make_exporter_with_fake_prom()
        ctx = HookContext(call_id="b", tool_name="t", policy_name="p")
        ctx.duration_ms = 25.0
        ctx.overhead_ms = 0.0
        exp._on_post_call(ctx)

        exp._latency_histogram.labels.assert_called_once_with(tool="t")
        exp._latency_histogram.labels.return_value.observe.assert_called_once_with(
            pytest.approx(0.025, rel=1e-3)
        )

    def test_overhead_histogram_observed_when_overhead_positive(self) -> None:
        """Overhead histogram is observed when overhead_ms > 0."""
        exp, _ = _make_exporter_with_fake_prom()
        ctx = HookContext(call_id="c", tool_name="t", policy_name="p")
        ctx.duration_ms = 0.0
        ctx.overhead_ms = 2.5
        exp._on_post_call(ctx)

        exp._overhead_histogram.labels.assert_called_once_with(tool="t")
        exp._overhead_histogram.labels.return_value.observe.assert_called_once_with(
            pytest.approx(0.0025, rel=1e-3)
        )

    def test_post_call_exception_swallowed(self) -> None:
        """If counter.labels raises, _on_post_call must not propagate."""
        exp, _ = _make_exporter_with_fake_prom()
        exp._calls_counter.labels.side_effect = RuntimeError("prom internal error")

        ctx = HookContext(call_id="d", tool_name="t", policy_name="p")
        exp._on_post_call(ctx)  # must not raise


# ---------------------------------------------------------------------------
# _on_violation with _available=True
# ---------------------------------------------------------------------------


class TestOnViolationAvailable:
    """_on_violation increments call and violation counters."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_calls_counter_blocked_label(self) -> None:
        """_on_violation increments calls_counter with decision='blocked'."""
        exp, _ = _make_exporter_with_fake_prom()
        ctx = ViolationHookContext(
            call_id="v1",
            tool_name="shell",
            policy_name="p",
            violation_type="TOOL_DENIED",
            violation_reason="not allowed",
        )
        exp._on_violation(ctx)

        exp._calls_counter.labels.assert_called_once_with(tool="shell", decision="blocked")
        exp._calls_counter.labels.return_value.inc.assert_called_once()

    def test_violations_counter_incremented(self) -> None:
        """_on_violation increments violations_counter with tool + violation_type."""
        exp, _ = _make_exporter_with_fake_prom()
        ctx = ViolationHookContext(
            call_id="v2",
            tool_name="shell",
            policy_name="p",
            violation_type="TOOL_DENIED",
            violation_reason="not allowed",
        )
        exp._on_violation(ctx)

        exp._violations_counter.labels.assert_called_once_with(
            tool="shell", violation_type="TOOL_DENIED"
        )
        exp._violations_counter.labels.return_value.inc.assert_called_once()

    def test_violation_exception_swallowed(self) -> None:
        """Exception inside _on_violation is caught and not re-raised."""
        exp, _ = _make_exporter_with_fake_prom()
        exp._calls_counter.labels.side_effect = RuntimeError("counter broken")

        ctx = ViolationHookContext(call_id="v3", tool_name="t", policy_name="p", violation_type="X")
        exp._on_violation(ctx)  # must not raise


# ---------------------------------------------------------------------------
# _on_redaction with _available=True
# ---------------------------------------------------------------------------


class TestOnRedactionAvailable:
    """_on_redaction increments the redactions_counter."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_redactions_counter_incremented_by_count(self) -> None:
        """_on_redaction calls .inc(redaction_count) on the redactions counter."""
        exp, _ = _make_exporter_with_fake_prom()
        ctx = RedactionHookContext(
            call_id="r1", tool_name="t", direction="input", redaction_count=3
        )
        exp._on_redaction(ctx)

        exp._redactions_counter.labels.assert_called_once_with(tool="t", direction="input")
        exp._redactions_counter.labels.return_value.inc.assert_called_once_with(3)

    def test_redaction_exception_swallowed(self) -> None:
        """Exception in _on_redaction is caught and not propagated."""
        exp, _ = _make_exporter_with_fake_prom()
        exp._redactions_counter.labels.side_effect = RuntimeError("broken")

        ctx = RedactionHookContext(
            call_id="r2", tool_name="t", direction="output", redaction_count=1
        )
        exp._on_redaction(ctx)  # must not raise


# ---------------------------------------------------------------------------
# Property accessors (violations_counter, redactions_counter, etc.)
# ---------------------------------------------------------------------------


class TestPropertyAccessors:
    """All five metric property accessors return the underlying instrument."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_violations_counter_property(self) -> None:
        exp, _ = _make_exporter_with_fake_prom()
        assert exp.violations_counter is exp._violations_counter

    def test_redactions_counter_property(self) -> None:
        exp, _ = _make_exporter_with_fake_prom()
        assert exp.redactions_counter is exp._redactions_counter

    def test_overhead_histogram_property(self) -> None:
        exp, _ = _make_exporter_with_fake_prom()
        assert exp.overhead_histogram is exp._overhead_histogram

    def test_latency_histogram_property(self) -> None:
        exp, _ = _make_exporter_with_fake_prom()
        assert exp.latency_histogram is exp._latency_histogram

    def test_calls_counter_property(self) -> None:
        exp, _ = _make_exporter_with_fake_prom()
        assert exp.calls_counter is exp._calls_counter


# ---------------------------------------------------------------------------
# start_http_server
# ---------------------------------------------------------------------------


class TestStartHttpServer:
    """start_http_server delegates to prometheus_client.start_http_server."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_start_http_server_calls_prom(self) -> None:
        """start_http_server invokes prom.start_http_server with port."""
        fake_prom = _make_fake_prometheus_client()
        exp, _ = _make_exporter_with_fake_prom()

        original = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = fake_prom  # type: ignore[assignment]
        try:
            exp.start_http_server(port=9095)
        finally:
            if original is None:
                sys.modules.pop("prometheus_client", None)
            else:
                sys.modules["prometheus_client"] = original

        fake_prom.start_http_server.assert_called_once()
        call_kwargs = fake_prom.start_http_server.call_args
        # First positional arg is the port
        assert call_kwargs[0][0] == 9095

    def test_start_http_server_raises_import_error_when_prom_missing(self) -> None:
        """start_http_server raises ImportError when prometheus_client is absent."""
        exp, _ = _make_exporter_with_fake_prom()

        original = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = None  # type: ignore[assignment]
        try:
            with pytest.raises((ImportError, AttributeError)):
                exp.start_http_server(port=9096)
        finally:
            if original is None:
                sys.modules.pop("prometheus_client", None)
            else:
                sys.modules["prometheus_client"] = original

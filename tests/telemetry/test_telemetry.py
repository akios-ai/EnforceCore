# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for OpenTelemetry integration (enforcecore.telemetry)."""

from __future__ import annotations

from unittest.mock import MagicMock

from enforcecore.plugins.hooks import HookContext, HookRegistry, ViolationHookContext
from enforcecore.telemetry.instrumentor import EnforceCoreInstrumentor
from enforcecore.telemetry.metrics import EnforceCoreMetrics

# ---------------------------------------------------------------------------
# EnforceCoreMetrics
# ---------------------------------------------------------------------------


class TestMetrics:
    def test_initial_state(self) -> None:
        m = EnforceCoreMetrics()
        assert m.calls == 0
        assert m.blocks == 0
        assert m.redactions == 0
        assert m.violations == 0
        assert m.cost_usd == 0.0

    def test_record_call_allowed(self) -> None:
        m = EnforceCoreMetrics()
        m.record_call(tool_name="search", decision="allowed", duration_ms=10.0)
        assert m.calls == 1
        assert m.blocks == 0

    def test_record_call_blocked(self) -> None:
        m = EnforceCoreMetrics()
        m.record_call(tool_name="shell", decision="blocked")
        assert m.calls == 1
        assert m.blocks == 1

    def test_record_redactions(self) -> None:
        m = EnforceCoreMetrics()
        m.record_call(
            tool_name="search",
            decision="allowed",
            input_redactions=3,
            output_redactions=1,
        )
        assert m.redactions == 4

    def test_record_violation(self) -> None:
        m = EnforceCoreMetrics()
        m.record_violation(tool_name="shell", violation_type="TOOL_DENIED")
        assert m.violations == 1

    def test_record_cost(self) -> None:
        m = EnforceCoreMetrics()
        m.record_cost(0.05)
        m.record_cost(0.10)
        assert abs(m.cost_usd - 0.15) < 1e-9

    def test_snapshot(self) -> None:
        m = EnforceCoreMetrics()
        m.record_call(tool_name="t", decision="allowed")
        m.record_call(tool_name="t", decision="blocked")
        snap = m.snapshot()
        assert snap["calls"] == 2
        assert snap["blocks"] == 1

    def test_reset(self) -> None:
        m = EnforceCoreMetrics()
        m.record_call(tool_name="t", decision="allowed")
        m.reset()
        assert m.calls == 0

    def test_repr(self) -> None:
        m = EnforceCoreMetrics()
        assert "EnforceCoreMetrics" in repr(m)

    def test_bind_otel(self) -> None:
        """Bind OTel meter instruments (mock)."""
        m = EnforceCoreMetrics()
        mock_meter = MagicMock()
        m.bind_otel(mock_meter)
        assert mock_meter.create_counter.call_count == 4
        assert mock_meter.create_histogram.call_count == 2

    def test_otel_delegation(self) -> None:
        """OTel counters receive add() calls when bound."""
        m = EnforceCoreMetrics()
        mock_meter = MagicMock()
        m.bind_otel(mock_meter)
        m.record_call(tool_name="t", decision="allowed", duration_ms=5.0)
        mock_meter.create_counter.return_value.add.assert_called()


# ---------------------------------------------------------------------------
# EnforceCoreInstrumentor
# ---------------------------------------------------------------------------


class TestInstrumentor:
    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCoreInstrumentor._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCoreInstrumentor._instrumented = False

    def test_instrument_without_otel(self) -> None:
        """Instrumentor works even without OTel installed."""
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        assert inst.is_instrumented
        inst.uninstrument()
        assert not inst.is_instrumented

    def test_instrument_idempotent(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        inst.instrument()  # No-op
        assert inst.is_instrumented

    def test_uninstrument_idempotent(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.uninstrument()  # No-op before instrument
        assert not inst.is_instrumented

    def test_hooks_registered(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        registry = HookRegistry.global_registry()
        assert len(registry._pre_call) >= 1
        assert len(registry._post_call) >= 1
        assert len(registry._violation) >= 1

    def test_hooks_removed_on_uninstrument(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        inst.uninstrument()
        registry = HookRegistry.global_registry()
        assert len(registry._pre_call) == 0
        assert len(registry._post_call) == 0
        assert len(registry._violation) == 0

    def test_post_call_records_metrics(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        ctx = HookContext(
            call_id="test-123",
            tool_name="search",
            policy_name="p",
        )
        ctx.duration_ms = 5.0
        inst._on_post_call(ctx)
        assert inst.metrics.calls == 1

    def test_violation_records_metrics(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        ctx = ViolationHookContext(
            call_id="test-456",
            tool_name="shell",
            policy_name="p",
            violation_type="TOOL_DENIED",
            violation_reason="not allowed",
        )
        inst._on_violation(ctx)
        assert inst.metrics.blocks == 1
        assert inst.metrics.violations == 1

    def test_metrics_property(self) -> None:
        inst = EnforceCoreInstrumentor()
        assert isinstance(inst.metrics, EnforceCoreMetrics)

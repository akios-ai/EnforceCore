# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for OpenTelemetry integration (enforcecore.telemetry)."""

from __future__ import annotations

import json
import tempfile
from unittest.mock import MagicMock

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)
from enforcecore.telemetry.instrumentor import EnforceCoreInstrumentor
from enforcecore.telemetry.logexport import AuditLogExporter
from enforcecore.telemetry.metrics import EnforceCoreMetrics
from enforcecore.telemetry.prometheus import EnforceCorePrometheusExporter

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

    def test_post_call_uses_redaction_fields(self) -> None:
        """Instrumentor reads input/output_redactions and overhead_ms from HookContext."""
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        ctx = HookContext(
            call_id="test-789",
            tool_name="search",
            policy_name="p",
        )
        ctx.duration_ms = 5.0
        ctx.overhead_ms = 1.2
        ctx.input_redactions = 3
        ctx.output_redactions = 1
        inst._on_post_call(ctx)
        assert inst.metrics.calls == 1
        assert inst.metrics.redactions == 4  # 3+1

    def test_redaction_hook_registered(self) -> None:
        """Instrumentor registers a redaction hook."""
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        registry = HookRegistry.global_registry()
        assert len(registry._redaction) >= 1

    def test_redaction_hook_removed_on_uninstrument(self) -> None:
        inst = EnforceCoreInstrumentor()
        inst.instrument()
        inst.uninstrument()
        registry = HookRegistry.global_registry()
        assert len(registry._redaction) == 0


# ---------------------------------------------------------------------------
# EnforceCorePrometheusExporter
# ---------------------------------------------------------------------------


class TestPrometheusExporter:
    def setup_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        EnforceCorePrometheusExporter._instrumented = False

    def test_init_noop_without_prometheus_client(self, monkeypatch) -> None:
        """Exporter works even when prometheus_client is not installed."""
        import sys

        # Temporarily hide prometheus_client if present
        original = sys.modules.get("prometheus_client")
        sys.modules["prometheus_client"] = None  # type: ignore[assignment]
        try:
            exp = EnforceCorePrometheusExporter()
            assert not exp.is_available
            assert exp.calls_counter is None
        finally:
            if original is None:
                del sys.modules["prometheus_client"]
            else:
                sys.modules["prometheus_client"] = original

    def test_instrument_idempotent(self) -> None:
        exp = EnforceCorePrometheusExporter()
        exp.instrument()
        exp.instrument()
        assert exp.is_instrumented

    def test_uninstrument_idempotent(self) -> None:
        exp = EnforceCorePrometheusExporter()
        exp.uninstrument()
        assert not exp.is_instrumented

    def test_hooks_registered(self) -> None:
        exp = EnforceCorePrometheusExporter()
        exp.instrument()
        registry = HookRegistry.global_registry()
        assert len(registry._post_call) >= 1
        assert len(registry._violation) >= 1
        assert len(registry._redaction) >= 1

    def test_hooks_removed_on_uninstrument(self) -> None:
        exp = EnforceCorePrometheusExporter()
        exp.instrument()
        exp.uninstrument()
        registry = HookRegistry.global_registry()
        assert len(registry._post_call) == 0
        assert len(registry._violation) == 0
        assert len(registry._redaction) == 0

    def test_noop_post_call_no_crash(self) -> None:
        """_on_post_call should not crash when prometheus_client is unavailable."""
        exp = EnforceCorePrometheusExporter()
        exp._available = False
        ctx = HookContext(call_id="x", tool_name="t", policy_name="p")
        ctx.duration_ms = 5.0
        ctx.overhead_ms = 0.5
        exp._on_post_call(ctx)  # must not raise

    def test_noop_violation_no_crash(self) -> None:
        exp = EnforceCorePrometheusExporter()
        exp._available = False
        ctx = ViolationHookContext(
            call_id="x",
            tool_name="t",
            policy_name="p",
            violation_type="TOOL_DENIED",
            violation_reason="nope",
        )
        exp._on_violation(ctx)

    def test_noop_redaction_no_crash(self) -> None:
        exp = EnforceCorePrometheusExporter()
        exp._available = False
        ctx = RedactionHookContext(call_id="x", tool_name="t", direction="input", redaction_count=2)
        exp._on_redaction(ctx)

    def test_with_prometheus_client_if_available(self) -> None:
        """Full Prometheus recording when prometheus_client is installed."""
        pytest = __import__("pytest")
        prom = pytest.importorskip("prometheus_client")

        registry = prom.CollectorRegistry()
        exp = EnforceCorePrometheusExporter(registry=registry)

        if not exp.is_available:
            pytest.skip("prometheus_client not available in this env")

        exp.instrument()

        ctx = HookContext(call_id="a", tool_name="search", policy_name="p")
        ctx.duration_ms = 10.0
        ctx.overhead_ms = 0.5
        ctx.input_redactions = 2
        ctx.output_redactions = 1
        exp._on_post_call(ctx)

        # Check counter was incremented
        total = registry.get_sample_value(
            "enforcecore_calls_total",
            {"tool": "search", "decision": "allowed"},
        )
        assert total == 1.0

        # Redaction hook
        redact_ctx = RedactionHookContext(
            call_id="a", tool_name="search", direction="input", redaction_count=3
        )
        exp._on_redaction(redact_ctx)
        redact_total = registry.get_sample_value(
            "enforcecore_redactions_total",
            {"tool": "search", "direction": "input"},
        )
        assert redact_total == 3.0


# ---------------------------------------------------------------------------
# AuditLogExporter
# ---------------------------------------------------------------------------


class TestAuditLogExporter:
    def setup_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def test_instrument_idempotent(self) -> None:
        exp = AuditLogExporter()
        exp.instrument()
        exp.instrument()
        assert exp.is_instrumented

    def test_uninstrument_idempotent(self) -> None:
        exp = AuditLogExporter()
        exp.uninstrument()
        assert not exp.is_instrumented

    def test_hooks_registered(self) -> None:
        exp = AuditLogExporter()
        exp.instrument()
        registry = HookRegistry.global_registry()
        assert len(registry._post_call) >= 1
        assert len(registry._violation) >= 1

    def test_hooks_removed_on_uninstrument(self) -> None:
        exp = AuditLogExporter()
        exp.instrument()
        exp.uninstrument()
        registry = HookRegistry.global_registry()
        assert len(registry._post_call) == 0
        assert len(registry._violation) == 0

    def test_allowed_record_dispatched_to_sink(self) -> None:
        """Allowed call produces a record with expected fields."""
        records: list[dict] = []
        exp = AuditLogExporter()
        exp.add_sink(records.append)
        exp.instrument()

        ctx = HookContext(call_id="abc", tool_name="search", policy_name="test-policy")
        ctx.duration_ms = 8.0
        ctx.overhead_ms = 0.3
        ctx.input_redactions = 2
        ctx.output_redactions = 0
        exp._on_post_call(ctx)

        assert len(records) == 1
        r = records[0]
        assert r["decision"] == "allowed"
        assert r["tool_name"] == "search"
        assert r["policy_name"] == "test-policy"
        assert r["duration_ms"] == 8.0
        assert r["overhead_ms"] == 0.3
        assert r["input_redactions"] == 2
        assert r["output_redactions"] == 0
        assert r["schema_version"] == "1.5"
        assert r["violation_type"] is None

    def test_blocked_record_dispatched_to_sink(self) -> None:
        records: list[dict] = []
        exp = AuditLogExporter()
        exp.add_sink(records.append)

        ctx = ViolationHookContext(
            call_id="xyz",
            tool_name="shell",
            policy_name="p",
            violation_type="TOOL_DENIED",
            violation_reason="not allowed",
        )
        exp._on_violation(ctx)

        assert len(records) == 1
        r = records[0]
        assert r["decision"] == "blocked"
        assert r["violation_type"] == "TOOL_DENIED"
        assert r["violation_reason"] == "not allowed"

    def test_file_sink(self) -> None:
        """Records are written as newline-delimited JSON to a file."""
        exp = AuditLogExporter()
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        exp.add_sink_file(path)
        exp.instrument()

        ctx = HookContext(call_id="f1", tool_name="tool", policy_name="p")
        exp._on_post_call(ctx)

        with open(path) as fh:
            line = fh.readline()
        record = json.loads(line)
        assert record["decision"] == "allowed"
        assert record["tool_name"] == "tool"

    def test_add_sink_stdout_callable(self, capsys) -> None:
        exp = AuditLogExporter()
        exp.add_sink_stdout()
        ctx = HookContext(call_id="s1", tool_name="t", policy_name="p")
        exp._on_post_call(ctx)
        captured = capsys.readouterr()
        data = json.loads(captured.out.strip())
        assert data["decision"] == "allowed"

    def test_clear_sinks(self) -> None:
        exp = AuditLogExporter()
        exp.add_sink_stdout()
        exp.clear_sinks()
        assert len(exp._sinks) == 0

    def test_multiple_sinks(self) -> None:
        records_a: list[dict] = []
        records_b: list[dict] = []
        exp = AuditLogExporter()
        exp.add_sink(records_a.append)
        exp.add_sink(records_b.append)
        ctx = HookContext(call_id="m1", tool_name="t", policy_name="p")
        exp._on_post_call(ctx)
        assert len(records_a) == 1
        assert len(records_b) == 1


# ---------------------------------------------------------------------------
# HookContext new fields
# ---------------------------------------------------------------------------


class TestHookContextNewFields:
    def test_default_values(self) -> None:
        ctx = HookContext()
        assert ctx.input_redactions == 0
        assert ctx.output_redactions == 0
        assert ctx.overhead_ms == 0.0

    def test_assign_fields(self) -> None:
        ctx = HookContext(call_id="x", tool_name="t", policy_name="p")
        ctx.input_redactions = 5
        ctx.output_redactions = 2
        ctx.overhead_ms = 1.5
        assert ctx.input_redactions == 5
        assert ctx.output_redactions == 2
        assert ctx.overhead_ms == 1.5

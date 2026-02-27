# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Extra coverage for telemetry/instrumentor.py — mock-tracer hook paths."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)
from enforcecore.telemetry.instrumentor import EnforceCoreInstrumentor


@pytest.fixture(autouse=True)
def _reset_hooks():
    HookRegistry.reset_global()
    yield
    HookRegistry.reset_global()


@pytest.fixture
def inst():
    """Fresh instrumentor with a mock OTel tracer pre-installed."""
    i = EnforceCoreInstrumentor()
    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_span.return_value = mock_span
    i._tracer = mock_tracer
    return i


@pytest.fixture
def hctx():
    return HookContext(
        call_id="call-001",
        tool_name="search",
        policy_name="strict",
        duration_ms=12.5,
        overhead_ms=1.2,
        input_redactions=2,
        output_redactions=1,
    )


@pytest.fixture
def vctx():
    return ViolationHookContext(
        call_id="call-001",
        tool_name="search",
        policy_name="strict",
        violation_type="blocked",
        violation_reason="deny list match",
    )


@pytest.fixture
def rctx():
    return RedactionHookContext(
        call_id="call-001",
        tool_name="search",
        direction="input",
        category="email",
        redaction_count=3,
    )


# ---------------------------------------------------------------------------
# _on_pre_call with active tracer (lines 157-167)
# ---------------------------------------------------------------------------


def test_on_pre_call_starts_span(inst, hctx):
    """_on_pre_call creates a span and stores it in _active_spans."""
    inst._on_pre_call(hctx)
    assert "call-001" in inst._active_spans
    inst._tracer.start_span.assert_called_once()


def test_on_pre_call_no_tracer(hctx):
    """_on_pre_call with tracer=None is a no-op."""
    i = EnforceCoreInstrumentor()
    i._tracer = None
    i._on_pre_call(hctx)  # must not raise
    assert "call-001" not in i._active_spans


# ---------------------------------------------------------------------------
# _on_post_call with active tracer + span (lines 183-195)
# ---------------------------------------------------------------------------


def test_on_post_call_ends_span(inst, hctx):
    """_on_post_call ends the active span and pops it from _active_spans."""
    inst._on_pre_call(hctx)  # creates span
    inst._on_post_call(hctx)  # should end and remove span
    assert "call-001" not in inst._active_spans
    mock_span = inst._tracer.start_span.return_value
    mock_span.end.assert_called_once()


def test_on_post_call_no_span_in_dict(inst, hctx):
    """_on_post_call with no active span for the call_id is a no-op."""
    inst._on_post_call(hctx)  # no span was registered
    # Should record metrics and not raise


def test_on_post_call_no_tracer(hctx):
    """_on_post_call with tracer=None still records metrics."""
    i = EnforceCoreInstrumentor()
    i._tracer = None
    i._on_post_call(hctx)  # must not raise


# ---------------------------------------------------------------------------
# _on_violation with active tracer + span (lines 210-232)
# ---------------------------------------------------------------------------


def test_on_violation_with_span(inst, vctx):
    """_on_violation ends the span with ERROR status."""
    # Pre-populate a span to simulate a running call
    mock_span = MagicMock()
    inst._active_spans["call-001"] = mock_span
    inst._on_violation(vctx)
    assert "call-001" not in inst._active_spans
    mock_span.end.assert_called_once()


def test_on_violation_no_span(inst, vctx):
    """_on_violation with no active span just records metrics."""
    inst._on_violation(vctx)  # must not raise


def test_on_violation_no_tracer(vctx):
    """_on_violation with tracer=None records metrics and returns."""
    i = EnforceCoreInstrumentor()
    i._tracer = None
    i._on_violation(vctx)  # must not raise


# ---------------------------------------------------------------------------
# _on_redaction paths
# ---------------------------------------------------------------------------


def test_on_redaction_with_active_span(inst, rctx):
    """_on_redaction adds an event on the active span."""
    mock_span = MagicMock()
    inst._active_spans["call-001"] = mock_span
    inst._on_redaction(rctx)
    mock_span.add_event.assert_called_once()


def test_on_redaction_no_active_span(inst, rctx):
    """_on_redaction with no matching span is a no-op."""
    inst._on_redaction(rctx)  # must not raise


def test_on_redaction_no_tracer(rctx):
    """_on_redaction with tracer=None returns immediately."""
    i = EnforceCoreInstrumentor()
    i._tracer = None
    i._on_redaction(rctx)  # must not raise


# ---------------------------------------------------------------------------
# uninstrument — clears active spans (line 143)
# ---------------------------------------------------------------------------


def test_uninstrument_clears_active_spans():
    """uninstrument() ends and removes all spans in _active_spans."""
    i = EnforceCoreInstrumentor()
    mock_span = MagicMock()
    i._active_spans["call-xyz"] = mock_span
    i._instrumented = True
    # Register hooks so remove works without KeyError
    registry = HookRegistry.global_registry()
    registry.add_pre_call(i._hook_pre)
    registry.add_post_call(i._hook_post)
    registry.add_violation(i._hook_violation)
    registry.add_redaction(i._hook_redaction)
    i.uninstrument()
    assert len(i._active_spans) == 0
    mock_span.end.assert_called_once()


def test_uninstrument_when_not_instrumented():
    """uninstrument() is a no-op when not currently instrumented."""
    i = EnforceCoreInstrumentor()
    i._instrumented = False
    i.uninstrument()  # must not raise


# ---------------------------------------------------------------------------
# instrument() — OTel available path (lines 100-114)
# ---------------------------------------------------------------------------


def test_instrument_already_instrumented():
    """Calling instrument() twice is idempotent."""
    i = EnforceCoreInstrumentor()
    i._instrumented = True
    i.instrument()  # must not raise
    assert i._instrumented is True

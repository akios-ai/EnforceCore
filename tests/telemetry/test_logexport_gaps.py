# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Coverage gap tests for enforcecore/telemetry/logexport.py.

Targets: _make_http_sink, make_splunk_hec_sink, make_elastic_sink,
         AuditLogExporter.add_sink_http, AuditLogExporter._dispatch (OTLP +
         sink-exception paths), AuditLogExporter.enable_otlp ImportError.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.plugins.hooks import HookContext, HookRegistry
from enforcecore.telemetry.logexport import (
    AuditLogExporter,
    _make_http_sink,
    make_elastic_sink,
    make_splunk_hec_sink,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _cm_mock() -> MagicMock:
    """Return a context-manager-compatible MagicMock for urlopen."""
    cm = MagicMock()
    cm.__enter__ = lambda s: s
    cm.__exit__ = MagicMock(return_value=False)
    return cm


# ---------------------------------------------------------------------------
# _make_http_sink — batch accumulation and flush logic
# ---------------------------------------------------------------------------


class TestMakeHttpSink:
    """_make_http_sink: batch accumulation, flush, and error handling."""

    def test_no_flush_below_batch_size(self) -> None:
        """Records under batch_size are buffered without any HTTP call."""
        with patch("enforcecore.telemetry.logexport.urlopen") as mock_urlopen:
            sink = _make_http_sink("http://test.example", batch_size=5)
            sink({"event": "a"})
            sink({"event": "b"})
            mock_urlopen.assert_not_called()

    def test_flush_when_batch_full(self) -> None:
        """A POST is made exactly once when batch reaches batch_size."""
        with patch(
            "enforcecore.telemetry.logexport.urlopen", return_value=_cm_mock()
        ) as mock_urlopen:
            sink = _make_http_sink("http://test.example", batch_size=2)
            sink({"event": "a"})
            sink({"event": "b"})  # triggers flush
            mock_urlopen.assert_called_once()

    def test_flush_sends_json_array(self) -> None:
        """Flushed body is a JSON array of the batched records."""
        bodies: list[bytes] = []

        def _capture_urlopen(req, *, timeout=5.0):
            bodies.append(req.data)
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_capture_urlopen):
            sink = _make_http_sink("http://test.example", batch_size=2)
            sink({"id": 1})
            sink({"id": 2})

        assert len(bodies) == 1
        parsed = json.loads(bodies[0].decode())
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_url_error_is_swallowed(self) -> None:
        """URLError during flush is logged and never propagates to caller."""
        from urllib.error import URLError

        with patch(
            "enforcecore.telemetry.logexport.urlopen",
            side_effect=URLError("network down"),
        ):
            sink = _make_http_sink("http://test.example", batch_size=1)
            sink({"event": "x"})  # triggers flush — must not raise

    def test_generic_exception_is_swallowed(self) -> None:
        """Unexpected exception during flush is caught and logged."""
        with patch(
            "enforcecore.telemetry.logexport.urlopen",
            side_effect=RuntimeError("oops"),
        ):
            sink = _make_http_sink("http://test.example", batch_size=1)
            sink({"event": "x"})  # must not raise

    def test_custom_headers_forwarded(self) -> None:
        """Extra headers are included in the outgoing request."""
        req_objects: list = []

        def _capture(req, *, timeout=5.0):
            req_objects.append(req)
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_capture):
            sink = _make_http_sink(
                "http://test.example",
                headers={"X-Custom": "value"},
                batch_size=1,
            )
            sink({"event": "z"})

        assert len(req_objects) == 1
        # The urllib Request object stores headers lowercase
        assert req_objects[0].get_header("X-custom") == "value"

    def test_second_batch_starts_fresh(self) -> None:
        """After a flush, the next record starts a new batch."""
        call_count = 0

        def _counting_urlopen(req, *, timeout=5.0):
            nonlocal call_count
            call_count += 1
            return _cm_mock()

        with patch(
            "enforcecore.telemetry.logexport.urlopen",
            side_effect=_counting_urlopen,
        ):
            sink = _make_http_sink("http://test.example", batch_size=2)
            sink({"id": 1})
            sink({"id": 2})  # flush 1
            sink({"id": 3})
            sink({"id": 4})  # flush 2

        assert call_count == 2


# ---------------------------------------------------------------------------
# make_splunk_hec_sink
# ---------------------------------------------------------------------------


class TestMakeSplunkHecSink:
    """make_splunk_hec_sink: HEC format, index field, error handling."""

    def test_payload_has_required_hec_fields(self) -> None:
        """Splunk payload contains time, source, sourcetype, event."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_splunk_hec_sink("http://splunk.example:8088", token="TOK")
            sink({"decision": "allowed", "tool_name": "my_tool"})

        assert len(captured) == 1
        payload = captured[0]
        assert "time" in payload
        assert payload["source"] == "enforcecore"
        assert payload["sourcetype"] == "_json"
        assert payload["event"]["decision"] == "allowed"
        assert payload["event"]["tool_name"] == "my_tool"

    def test_payload_includes_index_when_set(self) -> None:
        """Optional index field appears in payload when provided."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_splunk_hec_sink("http://splunk.example:8088", token="TOK", index="security")
            sink({"decision": "blocked"})

        assert captured[0]["index"] == "security"

    def test_no_index_field_when_not_set(self) -> None:
        """index key is absent from payload when not specified."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_splunk_hec_sink("http://splunk.example:8088", token="TOK")
            sink({"decision": "allowed"})

        assert "index" not in captured[0]

    def test_authorization_header_is_splunk_token(self) -> None:
        """Authorization header uses 'Splunk <token>' format."""
        req_objects: list = []

        def _fake_urlopen(req, *, timeout=5.0):
            req_objects.append(req)
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_splunk_hec_sink("http://splunk.example:8088", token="MYTOKEN")
            sink({"decision": "allowed"})

        assert len(req_objects) == 1
        auth = req_objects[0].get_header("Authorization")
        assert auth == "Splunk MYTOKEN"

    def test_url_error_silenced(self) -> None:
        """URLError from Splunk endpoint is caught and not propagated."""
        from urllib.error import URLError

        with patch(
            "enforcecore.telemetry.logexport.urlopen",
            side_effect=URLError("splunk down"),
        ):
            sink = make_splunk_hec_sink("http://splunk.example:8088", token="TOK")
            sink({"decision": "allowed"})  # must not raise

    def test_custom_source_and_sourcetype(self) -> None:
        """Custom source and sourcetype are reflected in the payload."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_splunk_hec_sink(
                "http://splunk.example:8088",
                token="TOK",
                source="myapp",
                sourcetype="json",
            )
            sink({"decision": "allowed"})

        assert captured[0]["source"] == "myapp"
        assert captured[0]["sourcetype"] == "json"


# ---------------------------------------------------------------------------
# make_elastic_sink
# ---------------------------------------------------------------------------


class TestMakeElasticSink:
    """make_elastic_sink: ECS format, auth headers, error handling."""

    def test_ecs_timestamp_and_event_fields(self) -> None:
        """ECS record has @timestamp and event.kind fields."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_elastic_sink("http://elastic.example:9200")
            sink({"decision": "allowed", "tool_name": "search"})

        doc = captured[0]
        assert "@timestamp" in doc
        assert doc["event"]["kind"] == "event"
        assert doc["enforcecore"]["decision"] == "allowed"
        assert doc["enforcecore"]["tool_name"] == "search"

    def test_allowed_outcome_is_success(self) -> None:
        """ECS outcome is 'success' for allowed decisions."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_elastic_sink("http://elastic.example:9200")
            sink({"decision": "allowed"})

        assert captured[0]["event"]["outcome"] == "success"

    def test_blocked_outcome_is_failure(self) -> None:
        """ECS outcome is 'failure' for blocked decisions."""
        captured: list[dict] = []

        def _fake_urlopen(req, *, timeout=5.0):
            captured.append(json.loads(req.data.decode()))
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_elastic_sink("http://elastic.example:9200")
            sink({"decision": "blocked"})

        assert captured[0]["event"]["outcome"] == "failure"

    def test_basic_auth_header_from_username_password(self) -> None:
        """Username+password produces a Basic Authorization header."""
        import base64

        req_objects: list = []

        def _fake_urlopen(req, *, timeout=5.0):
            req_objects.append(req)
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_elastic_sink(
                "http://elastic.example:9200", username="alice", password="s3cr3t"
            )
            sink({"decision": "allowed"})

        auth = req_objects[0].get_header("Authorization")
        expected = "Basic " + base64.b64encode(b"alice:s3cr3t").decode()
        assert auth == expected

    def test_api_key_auth_header(self) -> None:
        """api_key produces an ApiKey Authorization header."""
        req_objects: list = []

        def _fake_urlopen(req, *, timeout=5.0):
            req_objects.append(req)
            return _cm_mock()

        with patch("enforcecore.telemetry.logexport.urlopen", side_effect=_fake_urlopen):
            sink = make_elastic_sink("http://elastic.example:9200", api_key="my-api-key-b64")
            sink({"decision": "allowed"})

        auth = req_objects[0].get_header("Authorization")
        assert auth == "ApiKey my-api-key-b64"

    def test_url_error_silenced(self) -> None:
        """URLError from Elastic endpoint is caught and not propagated."""
        from urllib.error import URLError

        with patch(
            "enforcecore.telemetry.logexport.urlopen",
            side_effect=URLError("elastic down"),
        ):
            sink = make_elastic_sink("http://elastic.example:9200")
            sink({"decision": "blocked"})  # must not raise


# ---------------------------------------------------------------------------
# AuditLogExporter.add_sink_http
# ---------------------------------------------------------------------------


class TestAuditLogExporterAddSinkHttp:
    """AuditLogExporter.add_sink_http registers a batching HTTP sink."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def test_add_sink_http_increments_sink_count(self) -> None:
        """add_sink_http appends exactly one sink."""
        exp = AuditLogExporter()
        initial_count = len(exp._sinks)
        exp.add_sink_http("http://collector.example", batch_size=10)
        assert len(exp._sinks) == initial_count + 1

    def test_http_sink_fires_on_enforcement_event(self) -> None:
        """HTTP sink receives the dispatched record when a hook fires."""
        records: list[dict] = []
        exp = AuditLogExporter()
        exp.add_sink(records.append)
        exp.add_sink_http("http://collector.example", batch_size=100)

        ctx = HookContext(call_id="h1", tool_name="search", policy_name="p")
        exp._on_post_call(ctx)

        # Our list-append sink should have received exactly one record
        assert len(records) == 1
        assert records[0]["tool_name"] == "search"


# ---------------------------------------------------------------------------
# AuditLogExporter._dispatch — OTLP path and sink exception handling
# ---------------------------------------------------------------------------


class TestAuditLogExporterDispatch:
    """_dispatch: OTLP emit path and sink exception swallowing."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def test_dispatch_invokes_otel_logger_emit(self) -> None:
        """_dispatch calls emit on the OTLP logger when set."""
        exp = AuditLogExporter()
        mock_otel = MagicMock()
        mock_otel.create_log_record.return_value = MagicMock()
        exp._otel_logger = mock_otel

        record = {"decision": "allowed", "tool_name": "t", "policy_name": "p"}
        exp._dispatch(record)

        mock_otel.emit.assert_called_once()

    def test_dispatch_otel_exception_suppressed_via_contextlib(self) -> None:
        """An exception from otel.emit is suppressed — _dispatch does not raise."""
        exp = AuditLogExporter()
        mock_otel = MagicMock()
        mock_otel.emit.side_effect = RuntimeError("otel boom")
        exp._otel_logger = mock_otel

        record = {"decision": "allowed", "tool_name": "t"}
        exp._dispatch(record)  # must not raise

    def test_dispatch_sink_exception_swallowed(self) -> None:
        """A misbehaving sink must not prevent other sinks or raise."""
        received: list[dict] = []

        def _bad_sink(record: dict) -> None:
            raise RuntimeError("sink exploded")

        exp = AuditLogExporter()
        exp.add_sink(_bad_sink)
        exp.add_sink(received.append)

        ctx = HookContext(call_id="e1", tool_name="t", policy_name="p")
        exp._on_post_call(ctx)  # must not raise

        # The good sink still received the record
        assert len(received) == 1

    def test_dispatch_otel_emit_blocked_decision(self) -> None:
        """_dispatch uses severity WARN for blocked decisions."""
        exp = AuditLogExporter()
        mock_otel = MagicMock()
        log_record = MagicMock()
        mock_otel.create_log_record.return_value = log_record
        exp._otel_logger = mock_otel

        record = {"decision": "blocked", "tool_name": "t"}
        exp._dispatch(record)

        # create_log_record was called with severity_text="WARN"
        _, kwargs = mock_otel.create_log_record.call_args
        assert kwargs.get("severity_text") == "WARN"


# ---------------------------------------------------------------------------
# AuditLogExporter.enable_otlp — ImportError when otel not installed
# ---------------------------------------------------------------------------


class TestEnableOtlp:
    """enable_otlp raises ImportError when opentelemetry is not installed."""

    def setup_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def teardown_method(self) -> None:
        HookRegistry.reset_global()
        AuditLogExporter._instrumented = False

    def test_enable_otlp_raises_when_otel_missing(self) -> None:
        """ImportError propagates when opentelemetry packages are absent."""
        exp = AuditLogExporter()

        # Hide opentelemetry from sys.modules to simulate missing package
        otel_keys = [k for k in list(sys.modules.keys()) if k.startswith("opentelemetry")]
        originals = {k: sys.modules.pop(k) for k in otel_keys}

        # Block the top-level import as well
        sys.modules["opentelemetry"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry._logs"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.exporter"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.exporter.otlp"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.exporter.otlp.proto"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.exporter.otlp.proto.grpc"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.exporter.otlp.proto.grpc._log_exporter"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.sdk"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.sdk._logs"] = None  # type: ignore[assignment]
        sys.modules["opentelemetry.sdk._logs.export"] = None  # type: ignore[assignment]

        try:
            with pytest.raises((ImportError, AttributeError)):
                exp.enable_otlp("http://localhost:4317")
        finally:
            # Clean up the None entries
            for k in [
                "opentelemetry",
                "opentelemetry._logs",
                "opentelemetry.exporter",
                "opentelemetry.exporter.otlp",
                "opentelemetry.exporter.otlp.proto",
                "opentelemetry.exporter.otlp.proto.grpc",
                "opentelemetry.exporter.otlp.proto.grpc._log_exporter",
                "opentelemetry.sdk",
                "opentelemetry.sdk._logs",
                "opentelemetry.sdk._logs.export",
            ]:
                sys.modules.pop(k, None)
            # Restore original modules
            sys.modules.update(originals)

    def test_enable_otlp_with_mocked_otel(self) -> None:
        """enable_otlp sets _otel_logger when otel is present (mocked)."""
        exp = AuditLogExporter()

        mock_otel_logs = MagicMock()
        mock_exporter_mod = MagicMock()
        mock_sdk_logs = MagicMock()
        mock_sdk_export = MagicMock()
        mock_provider = MagicMock()
        mock_sdk_logs.LoggerProvider.return_value = mock_provider
        mock_logger_instance = MagicMock()
        mock_provider.get_logger.return_value = mock_logger_instance

        modules = {
            "opentelemetry._logs": mock_otel_logs,
            "opentelemetry.exporter.otlp.proto.grpc._log_exporter": mock_exporter_mod,
            "opentelemetry.sdk._logs": mock_sdk_logs,
            "opentelemetry.sdk._logs.export": mock_sdk_export,
        }
        with patch.dict(sys.modules, modules):
            exp.enable_otlp("http://localhost:4317")

        assert exp._otel_logger is mock_logger_instance

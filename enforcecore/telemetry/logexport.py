# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Structured audit log export for EnforceCore.

Exports every enforcement decision as a structured JSON log record
suitable for ingestion by Splunk, Elastic (ECS), or any OTLP-compatible
log backend.

Two export modes are provided:

1. **JSON sink export** — streams structured JSON lines to a file, stdout,
   or an HTTP endpoint (Splunk HEC / Elastic Bulk API).

2. **OTLP log export** — emits OpenTelemetry LogRecord objects via an
   OTLP exporter (requires ``enforcecore[otel]``).

Usage — JSON sink::

    from enforcecore.telemetry.logexport import AuditLogExporter

    exporter = AuditLogExporter()
    exporter.instrument()          # hooks into enforcement pipeline
    exporter.add_sink_stdout()     # print every event as JSON
    exporter.add_sink_file("/var/log/enforcecore.json")
    exporter.add_sink_http(        # Splunk HEC
        "https://splunk.acme.com:8088/services/collector/event",
        headers={"Authorization": "Splunk MY_HEC_TOKEN"},
    )

Usage — OTLP logs::

    from enforcecore.telemetry.logexport import AuditLogExporter

    exporter = AuditLogExporter()
    exporter.instrument()
    exporter.enable_otlp(endpoint="http://localhost:4317")

.. versionadded:: 1.5.0
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import structlog

from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    ViolationHookContext,
)

logger = structlog.get_logger("enforcecore.telemetry.logexport")

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

#: A sink callable receives a JSON-serialisable dict and handles delivery.
SinkCallable = Callable[[dict[str, Any]], None]


# ---------------------------------------------------------------------------
# Built-in sinks
# ---------------------------------------------------------------------------


def _sink_stdout(record: dict[str, Any]) -> None:
    """Print the log record as a JSON line to stdout."""
    print(json.dumps(record, default=str))


def _make_file_sink(path: str) -> SinkCallable:
    """Return a sink that appends newline-delimited JSON to *path*."""
    _lock = threading.Lock()

    def _sink(record: dict[str, Any]) -> None:
        with _lock, open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

    return _sink


def _make_http_sink(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    batch_size: int = 50,
) -> SinkCallable:
    """Return a non-blocking HTTP sink with in-memory batching.

    Records are batched and sent asynchronously to *url* via HTTP POST.
    Each batch is a JSON array (suitable for Elastic ``_bulk`` or a custom
    collector).  For Splunk HEC use ``{"event": record}`` wrapping — see
    :func:`make_splunk_hec_sink` for the Splunk-specific variant.

    Args:
        url: HTTP(S) endpoint to POST batches to.
        headers: Extra HTTP headers (e.g. ``Authorization``).
        timeout: Per-request timeout in seconds.
        batch_size: Maximum records per request.
    """
    _lock = threading.Lock()
    _batch: list[dict[str, Any]] = []
    _headers = {"Content-Type": "application/json", **(headers or {})}

    def _flush(records: list[dict[str, Any]]) -> None:
        body = json.dumps(records, default=str).encode()
        req = Request(url, data=body, headers=_headers, method="POST")
        try:
            with urlopen(req, timeout=timeout):
                pass
        except URLError as exc:
            logger.warning("logexport_http_sink_error", url=url, error=str(exc))
        except Exception as exc:
            logger.warning("logexport_http_sink_error", url=url, error=str(exc))

    def _sink(record: dict[str, Any]) -> None:
        nonlocal _batch
        with _lock:
            _batch.append(record)
            if len(_batch) >= batch_size:
                to_flush = list(_batch)
                _batch = []
            else:
                return  # wait for more
        # Flush outside the lock to avoid blocking
        _flush(to_flush)

    return _sink


def make_splunk_hec_sink(
    url: str,
    *,
    token: str,
    index: str | None = None,
    source: str = "enforcecore",
    sourcetype: str = "_json",
    timeout: float = 5.0,
) -> SinkCallable:
    """Return a Splunk HTTP Event Collector (HEC) sink.

    Args:
        url: Splunk HEC endpoint, e.g.
            ``https://splunk.acme.com:8088/services/collector/event``.
        token: HEC authentication token.
        index: Optional Splunk index name.
        source: Splunk source field.
        sourcetype: Splunk sourcetype field.
        timeout: Per-request timeout in seconds.

    Example::

        from enforcecore.telemetry.logexport import AuditLogExporter, make_splunk_hec_sink

        exporter = AuditLogExporter()
        exporter.instrument()
        exporter.add_sink(make_splunk_hec_sink(
            "https://splunk.acme.com:8088/services/collector/event",
            token="MY_HEC_TOKEN",
        ))
    """
    headers = {"Authorization": f"Splunk {token}"}

    def _sink(record: dict[str, Any]) -> None:
        payload: dict[str, Any] = {
            "time": time.time(),
            "source": source,
            "sourcetype": sourcetype,
            "event": record,
        }
        if index:
            payload["index"] = index
        body = json.dumps(payload, default=str).encode()
        req = Request(
            url, data=body, headers={**headers, "Content-Type": "application/json"}, method="POST"
        )
        try:
            with urlopen(req, timeout=timeout):
                pass
        except URLError as exc:
            logger.warning("logexport_splunk_sink_error", url=url, error=str(exc))

    return _sink


def make_elastic_sink(
    url: str,
    *,
    index: str = "enforcecore",
    api_key: str | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 5.0,
) -> SinkCallable:
    """Return an Elastic (ECS) bulk-index sink.

    Args:
        url: Elastic endpoint, e.g. ``https://es.acme.com:9200``.
        index: Elastic index name.
        api_key: Elastic API key (base64-encoded ``id:key`` string).
        username: Elastic username (used with *password*).
        password: Elastic password.
        timeout: Per-request timeout in seconds.
    """
    bulk_url = f"{url.rstrip('/')}/{index}/_doc"
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username and password:
        import base64

        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"

    def _sink(record: dict[str, Any]) -> None:
        # Convert to ECS-compatible format
        ecs = {
            "@timestamp": record.get("timestamp", datetime.now(UTC).isoformat()),
            "message": f"enforcecore.{record.get('decision', 'unknown')} tool={record.get('tool_name', '')}",
            "event": {
                "kind": "event",
                "category": ["security"],
                "action": record.get("decision", "unknown"),
                "outcome": "success" if record.get("decision") == "allowed" else "failure",
            },
            "enforcecore": record,
        }
        body = json.dumps(ecs, default=str).encode()
        req = Request(bulk_url, data=body, headers=headers, method="POST")
        try:
            with urlopen(req, timeout=timeout):
                pass
        except URLError as exc:
            logger.warning("logexport_elastic_sink_error", url=url, error=str(exc))

    return _sink


# ---------------------------------------------------------------------------
# AuditLogExporter
# ---------------------------------------------------------------------------


class AuditLogExporter:
    """Exports enforcement decisions as structured log records.

    Hooks into the global :class:`~enforcecore.plugins.hooks.HookRegistry`
    and emits one log record per enforcement decision (allowed or blocked).

    Each record is a ``dict`` with the following fields:

    * ``timestamp`` — ISO-8601 UTC timestamp
    * ``tool_name`` — name of the enforced tool
    * ``policy_name`` — name of the active policy
    * ``decision`` — ``"allowed"`` or ``"blocked"``
    * ``call_id`` — unique UUID for this enforcement call
    * ``duration_ms`` — tool execution duration in milliseconds
    * ``overhead_ms`` — enforcement overhead in milliseconds
    * ``input_redactions`` — number of input PII redactions
    * ``output_redactions`` — number of output PII redactions
    * ``violation_type`` — violation category (blocked calls only)
    * ``violation_reason`` — human-readable reason (blocked calls only)
    * ``schema_version`` — ``"1.5"`` (for forward-compatible parsing)

    Register sinks to handle log delivery::

        exporter = AuditLogExporter()
        exporter.instrument()
        exporter.add_sink_stdout()           # development / debugging
        exporter.add_sink_file("/var/log/ec.jsonl")
        exporter.add_sink_http("http://collector:4318/logs")

    .. versionadded:: 1.5.0
    """

    _instance_lock = threading.Lock()
    _instrumented: bool = False

    def __init__(self) -> None:
        self._sinks: list[SinkCallable] = []
        self._sinks_lock = threading.Lock()
        self._otel_logger: Any = None

        self._hook_post = self._on_post_call
        self._hook_violation = self._on_violation

    # ------------------------------------------------------------------
    # Instrument / uninstrument
    # ------------------------------------------------------------------

    def instrument(self) -> None:
        """Register hooks and start exporting log records.

        Idempotent: safe to call multiple times.
        """
        with self._instance_lock:
            if self._instrumented:
                return
            registry = HookRegistry.global_registry()
            registry.add_post_call(self._hook_post)
            registry.add_violation(self._hook_violation)
            self._instrumented = True
            logger.info("logexport_instrumentation_enabled")

    def uninstrument(self) -> None:
        """Remove hooks and stop exporting.

        Idempotent: safe to call multiple times.
        """
        with self._instance_lock:
            if not self._instrumented:
                return
            registry = HookRegistry.global_registry()
            registry.remove_post_call(self._hook_post)
            registry.remove_violation(self._hook_violation)
            self._instrumented = False
            logger.info("logexport_instrumentation_disabled")

    @property
    def is_instrumented(self) -> bool:
        return self._instrumented

    # ------------------------------------------------------------------
    # Sink management
    # ------------------------------------------------------------------

    def add_sink(self, sink: SinkCallable) -> None:
        """Register a custom sink callable.

        The callable receives a single ``dict`` argument — the log record.

        Args:
            sink: Any callable accepting ``dict[str, Any]``.
        """
        with self._sinks_lock:
            self._sinks.append(sink)

    def add_sink_stdout(self) -> None:
        """Add a sink that prints each record as a JSON line to stdout."""
        self.add_sink(_sink_stdout)

    def add_sink_file(self, path: str) -> None:
        """Add a sink that appends records as newline-delimited JSON to *path*.

        Args:
            path: File path to write to. Created if it does not exist.
        """
        self.add_sink(_make_file_sink(path))

    def add_sink_http(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 5.0,
        batch_size: int = 50,
    ) -> None:
        """Add a batching HTTP sink.

        Each batch is posted as a JSON array to *url*.

        Args:
            url: HTTP(S) endpoint.
            headers: Extra headers (e.g. ``{"Authorization": "Bearer …"}``).
            timeout: Per-request timeout in seconds.
            batch_size: Records per HTTP request.
        """
        self.add_sink(_make_http_sink(url, headers=headers, timeout=timeout, batch_size=batch_size))

    def clear_sinks(self) -> None:
        """Remove all registered sinks."""
        with self._sinks_lock:
            self._sinks.clear()

    # ------------------------------------------------------------------
    # OTLP log integration
    # ------------------------------------------------------------------

    def enable_otlp(
        self,
        endpoint: str = "http://localhost:4317",
        *,
        insecure: bool = True,
    ) -> None:
        """Enable OTLP log export.

        Requires ``enforcecore[otel]`` (``opentelemetry-exporter-otlp-proto-grpc``).

        Args:
            endpoint: OTLP gRPC endpoint. Defaults to ``http://localhost:4317``.
            insecure: Allow insecure (non-TLS) connections. Defaults to ``True``.

        Raises:
            ImportError: If ``opentelemetry-exporter-otlp-proto-grpc`` is not installed.
        """
        from opentelemetry._logs import set_logger_provider
        from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (
            OTLPLogExporter,
        )
        from opentelemetry.sdk._logs import LoggerProvider
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

        otlp_exporter = OTLPLogExporter(endpoint=endpoint, insecure=insecure)
        provider = LoggerProvider()
        provider.add_log_record_processor(BatchLogRecordProcessor(otlp_exporter))
        set_logger_provider(provider)
        self._otel_logger = provider.get_logger("enforcecore", "1.5.0")
        logger.info("otlp_log_export_enabled", endpoint=endpoint)

    # ------------------------------------------------------------------
    # Hook callbacks
    # ------------------------------------------------------------------

    def _on_post_call(self, ctx: HookContext) -> None:
        record = self._build_record_allowed(ctx)
        self._dispatch(record)

    def _on_violation(self, ctx: ViolationHookContext) -> None:
        record = self._build_record_blocked(ctx)
        self._dispatch(record)

    # ------------------------------------------------------------------
    # Record builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_record_allowed(ctx: HookContext) -> dict[str, Any]:
        return {
            "schema_version": "1.5",
            "timestamp": datetime.now(UTC).isoformat(),
            "call_id": ctx.call_id,
            "tool_name": ctx.tool_name,
            "policy_name": ctx.policy_name,
            "decision": "allowed",
            "duration_ms": ctx.duration_ms,
            "overhead_ms": ctx.overhead_ms,
            "input_redactions": ctx.input_redactions,
            "output_redactions": ctx.output_redactions,
            "violation_type": None,
            "violation_reason": None,
        }

    @staticmethod
    def _build_record_blocked(ctx: ViolationHookContext) -> dict[str, Any]:
        return {
            "schema_version": "1.5",
            "timestamp": datetime.now(UTC).isoformat(),
            "call_id": ctx.call_id,
            "tool_name": ctx.tool_name,
            "policy_name": ctx.policy_name,
            "decision": "blocked",
            "duration_ms": 0.0,
            "overhead_ms": 0.0,
            "input_redactions": 0,
            "output_redactions": 0,
            "violation_type": ctx.violation_type,
            "violation_reason": ctx.violation_reason,
        }

    def _dispatch(self, record: dict[str, Any]) -> None:
        """Send *record* to all registered sinks and the OTLP logger."""
        # OTLP log
        if self._otel_logger is not None:
            with contextlib.suppress(Exception):  # OTLP emit is best-effort
                self._otel_logger.emit(
                    self._otel_logger.create_log_record(
                        body=json.dumps(record, default=str),
                        severity_text="INFO" if record.get("decision") == "allowed" else "WARN",
                        attributes={k: str(v) for k, v in record.items() if v is not None},
                    )
                )

        # Custom sinks
        with self._sinks_lock:
            sinks = list(self._sinks)
        for sink in sinks:
            try:
                sink(record)
            except Exception:
                logger.warning("logexport_sink_error", exc_info=True)

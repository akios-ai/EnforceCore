# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for webhook event dispatcher."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Any, ClassVar

import pytest

from enforcecore.plugins.hooks import HookRegistry, ViolationHookContext
from enforcecore.plugins.webhooks import WebhookDispatcher, WebhookEvent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _WebhookHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that records requests."""

    received: ClassVar[list[dict[str, Any]]] = []
    status_code: ClassVar[int] = 200

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        _WebhookHandler.received.append(json.loads(body))
        self.send_response(_WebhookHandler.status_code)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        pass  # Suppress logs


@pytest.fixture
def webhook_server():
    """Start a local HTTP server for webhook tests."""
    _WebhookHandler.received = []
    _WebhookHandler.status_code = 200
    server = HTTPServer(("127.0.0.1", 0), _WebhookHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def _reset_hooks():
    HookRegistry.reset_global()
    yield
    HookRegistry.reset_global()


# ---------------------------------------------------------------------------
# WebhookEvent
# ---------------------------------------------------------------------------


class TestWebhookEvent:
    def test_frozen(self) -> None:
        e = WebhookEvent(event_type="violation", tool_name="shell")
        with pytest.raises(AttributeError):
            e.event_type = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        e = WebhookEvent(event_type="violation")
        assert e.tool_name == ""
        assert e.policy_name == ""
        assert e.details == {}
        assert e.timestamp > 0

    def test_custom_fields(self) -> None:
        e = WebhookEvent(
            event_type="cost_threshold",
            tool_name="gpt4",
            details={"cost": 5.0},
        )
        assert e.event_type == "cost_threshold"
        assert e.details["cost"] == 5.0


# ---------------------------------------------------------------------------
# WebhookDispatcher initialization
# ---------------------------------------------------------------------------


class TestDispatcherInit:
    def test_default_state(self) -> None:
        d = WebhookDispatcher()
        assert not d.is_installed
        assert d.sent_count == 0
        assert d.failed_count == 0

    def test_repr(self) -> None:
        d = WebhookDispatcher(on_violation="http://example.com")
        r = repr(d)
        assert "WebhookDispatcher" in r
        assert "✓" in r  # violation has URL

    def test_repr_no_urls(self) -> None:
        d = WebhookDispatcher()
        r = repr(d)
        assert "✗" in r


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------


class TestInstallUninstall:
    def test_install(self) -> None:
        d = WebhookDispatcher(on_violation="http://example.com")
        d.install()
        assert d.is_installed
        registry = HookRegistry.global_registry()
        assert len(registry._violation) >= 1

    def test_install_idempotent(self) -> None:
        d = WebhookDispatcher(on_violation="http://example.com")
        d.install()
        d.install()  # No-op
        assert d.is_installed

    def test_uninstall(self) -> None:
        d = WebhookDispatcher(on_violation="http://example.com")
        d.install()
        d.uninstall()
        assert not d.is_installed
        registry = HookRegistry.global_registry()
        assert len(registry._violation) == 0

    def test_uninstall_before_install(self) -> None:
        d = WebhookDispatcher(on_violation="http://example.com")
        d.uninstall()  # No-op
        assert not d.is_installed


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class TestDispatch:
    def test_dispatch_violation(self, webhook_server: str) -> None:
        d = WebhookDispatcher(
            on_violation=webhook_server,
            retry_attempts=0,
            timeout_seconds=5.0,
        )
        ok = d.dispatch_violation(
            tool_name="shell",
            policy_name="strict",
            violation_type="TOOL_DENIED",
            violation_reason="not allowed",
        )
        assert ok
        assert d.sent_count == 1
        assert len(_WebhookHandler.received) == 1
        payload = _WebhookHandler.received[0]
        assert payload["event_type"] == "violation"
        assert payload["tool_name"] == "shell"
        assert payload["source"] == "enforcecore"

    def test_dispatch_cost_threshold(self, webhook_server: str) -> None:
        d = WebhookDispatcher(
            on_cost_threshold=webhook_server,
            retry_attempts=0,
            timeout_seconds=5.0,
        )
        ok = d.dispatch_cost_threshold(
            tool_name="gpt4",
            current_cost=5.50,
            budget=5.0,
        )
        assert ok
        payload = _WebhookHandler.received[0]
        assert payload["event_type"] == "cost_threshold"
        assert payload["details"]["current_cost_usd"] == 5.50

    def test_dispatch_no_url_configured(self) -> None:
        d = WebhookDispatcher()
        ok = d.dispatch(WebhookEvent(event_type="violation", tool_name="x"))
        assert not ok

    def test_dispatch_unknown_event_type(self) -> None:
        d = WebhookDispatcher(on_violation="http://example.com")
        ok = d.dispatch(WebhookEvent(event_type="unknown_event", tool_name="x"))
        assert not ok


# ---------------------------------------------------------------------------
# Retry and failure
# ---------------------------------------------------------------------------


class TestRetry:
    def test_retry_on_failure(self) -> None:
        d = WebhookDispatcher(
            on_violation="http://127.0.0.1:1",  # Connection refused
            retry_attempts=1,
            timeout_seconds=0.5,
            backoff_base=0.01,
        )
        ok = d.dispatch_violation(
            tool_name="t",
            policy_name="p",
            violation_type="DENIED",
            violation_reason="r",
        )
        assert not ok
        assert d.failed_count == 1

    def test_non_2xx_retries(self, webhook_server: str) -> None:
        _WebhookHandler.status_code = 500
        d = WebhookDispatcher(
            on_violation=webhook_server,
            retry_attempts=1,
            timeout_seconds=5.0,
            backoff_base=0.01,
        )
        ok = d.dispatch_violation(
            tool_name="t",
            policy_name="p",
            violation_type="DENIED",
            violation_reason="r",
        )
        # 500 is still read successfully by urlopen — it returns True for 200-299
        # But our code checks status 200-299 explicitly
        # Server returns 500, first attempt and retry both get 500 → failed
        assert not ok


# ---------------------------------------------------------------------------
# Hook integration
# ---------------------------------------------------------------------------


class TestHookIntegration:
    def test_violation_hook_dispatches(self, webhook_server: str) -> None:
        d = WebhookDispatcher(
            on_violation=webhook_server,
            retry_attempts=0,
            timeout_seconds=5.0,
        )
        d.install()

        ctx = ViolationHookContext(
            call_id="abc",
            tool_name="shell",
            policy_name="strict",
            violation_type="TOOL_DENIED",
            violation_reason="blocked",
        )
        d._handle_violation(ctx)
        assert d.sent_count == 1
        assert len(_WebhookHandler.received) == 1

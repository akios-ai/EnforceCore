# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Event webhooks for EnforceCore.

Sends HTTP callbacks when enforcement events occur (violations,
cost thresholds, audit errors). Supports configurable retry with
exponential backoff.

Usage::

    from enforcecore.plugins.webhooks import WebhookDispatcher

    dispatcher = WebhookDispatcher(
        on_violation="https://hooks.slack.com/services/...",
        on_cost_threshold="https://pagerduty.com/events/...",
    )
    dispatcher.install()  # Registers hooks in the global HookRegistry

    # Or configure via policy YAML::
    #
    #   webhooks:
    #     on_violation: https://hooks.slack.com/services/...
    #     on_cost_threshold: https://pagerduty.com/events/...
    #     retry_attempts: 3
    #     timeout_seconds: 10
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

import structlog

from enforcecore.plugins.hooks import HookRegistry, ViolationHookContext

logger = structlog.get_logger("enforcecore.webhooks")


@dataclass(frozen=True)
class WebhookEvent:
    """An event to be dispatched via webhook."""

    event_type: str  # "violation" | "cost_threshold" | "audit_error"
    tool_name: str = ""
    policy_name: str = ""
    violation_type: str = ""
    violation_reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class WebhookDispatcher:
    """Dispatches enforcement events to HTTP webhook endpoints.

    Supports retry with exponential backoff. Thread-safe.

    Args:
        on_violation: URL to POST when a policy violation occurs.
        on_cost_threshold: URL to POST when cost thresholds are breached.
        on_audit_error: URL to POST on audit trail errors.
        retry_attempts: Number of retries on failure. Default 3.
        timeout_seconds: HTTP request timeout. Default 10.
        backoff_base: Base delay for exponential backoff. Default 1.0s.
        backoff_max: Maximum backoff delay. Default 30.0s.
    """

    __slots__ = (
        "_backoff_base",
        "_backoff_max",
        "_failed_count",
        "_hook_violation_fn",
        "_installed",
        "_lock",
        "_on_audit_error",
        "_on_cost_threshold",
        "_on_violation",
        "_retry_attempts",
        "_sent_count",
        "_timeout",
    )

    def __init__(
        self,
        *,
        on_violation: str | None = None,
        on_cost_threshold: str | None = None,
        on_audit_error: str | None = None,
        retry_attempts: int = 3,
        timeout_seconds: float = 10.0,
        backoff_base: float = 1.0,
        backoff_max: float = 30.0,
    ) -> None:
        """Initialize the webhook dispatcher.

        Args:
            on_violation: URL to POST when a policy violation occurs.
            on_cost_threshold: URL to POST when cost thresholds are breached.
            on_audit_error: URL to POST on audit trail errors.
            retry_attempts: Number of retries on failure. Default 3.
            timeout_seconds: HTTP request timeout in seconds. Default 10.
            backoff_base: Base delay for exponential backoff in seconds.
            backoff_max: Maximum backoff delay in seconds.
        """
        self._on_violation = on_violation
        self._on_cost_threshold = on_cost_threshold
        self._on_audit_error = on_audit_error
        self._retry_attempts = retry_attempts
        self._timeout = timeout_seconds
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._installed = False
        self._lock = threading.Lock()
        self._sent_count = 0
        self._failed_count = 0
        # Store bound method ref so add/remove use identical object
        self._hook_violation_fn = self._handle_violation

    def install(self) -> None:
        """Register hooks in the global HookRegistry."""
        if self._installed:
            return
        registry = HookRegistry.global_registry()
        if self._on_violation:
            registry.add_violation(self._hook_violation_fn)
        self._installed = True
        logger.info(
            "webhooks_installed",
            violation=bool(self._on_violation),
            cost=bool(self._on_cost_threshold),
            audit_error=bool(self._on_audit_error),
        )

    def uninstall(self) -> None:
        """Remove hooks from the global HookRegistry."""
        if not self._installed:
            return
        registry = HookRegistry.global_registry()
        if self._on_violation:
            registry.remove_violation(self._hook_violation_fn)
        self._installed = False

    @property
    def is_installed(self) -> bool:
        return self._installed

    @property
    def sent_count(self) -> int:
        with self._lock:
            return self._sent_count

    @property
    def failed_count(self) -> int:
        with self._lock:
            return self._failed_count

    # -- Event dispatch -----------------------------------------------------

    def dispatch(self, event: WebhookEvent) -> bool:
        """Send an event to the appropriate webhook URL.

        Returns True if the event was sent successfully, False otherwise.
        """
        url = self._url_for_event(event.event_type)
        if url is None:
            return False

        payload = {
            "event_type": event.event_type,
            "tool_name": event.tool_name,
            "policy_name": event.policy_name,
            "violation_type": event.violation_type,
            "violation_reason": event.violation_reason,
            "details": event.details,
            "timestamp": event.timestamp,
            "source": "enforcecore",
        }

        return self._send_with_retry(url, payload)

    def dispatch_violation(
        self,
        *,
        tool_name: str,
        policy_name: str,
        violation_type: str,
        violation_reason: str,
    ) -> bool:
        """Convenience method to dispatch a violation event."""
        return self.dispatch(
            WebhookEvent(
                event_type="violation",
                tool_name=tool_name,
                policy_name=policy_name,
                violation_type=violation_type,
                violation_reason=violation_reason,
            )
        )

    def dispatch_cost_threshold(
        self,
        *,
        tool_name: str,
        current_cost: float,
        budget: float,
    ) -> bool:
        """Convenience method to dispatch a cost threshold event."""
        return self.dispatch(
            WebhookEvent(
                event_type="cost_threshold",
                tool_name=tool_name,
                details={
                    "current_cost_usd": current_cost,
                    "budget_usd": budget,
                },
            )
        )

    # -- Internal -----------------------------------------------------------

    def _url_for_event(self, event_type: str) -> str | None:
        """Get the webhook URL for an event type."""
        mapping: dict[str, str | None] = {
            "violation": self._on_violation,
            "cost_threshold": self._on_cost_threshold,
            "audit_error": self._on_audit_error,
        }
        return mapping.get(event_type)

    def _send_with_retry(self, url: str, payload: dict[str, Any]) -> bool:
        """Send a POST request with exponential backoff retry."""
        data = json.dumps(payload, default=str).encode("utf-8")

        for attempt in range(self._retry_attempts + 1):
            try:
                req = Request(
                    url,
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlopen(req, timeout=self._timeout) as resp:
                    status = resp.status
                    if 200 <= status < 300:
                        with self._lock:
                            self._sent_count += 1
                        logger.debug(
                            "webhook_sent",
                            url=url,
                            status=status,
                            attempt=attempt + 1,
                        )
                        return True
                    logger.warning(
                        "webhook_non_2xx",
                        url=url,
                        status=status,
                        attempt=attempt + 1,
                    )
            except (URLError, OSError, TimeoutError) as exc:
                logger.warning(
                    "webhook_send_failed",
                    url=url,
                    attempt=attempt + 1,
                    error=str(exc),
                )

            # Backoff before retry (but not after last attempt)
            if attempt < self._retry_attempts:
                delay = min(
                    self._backoff_base * (2**attempt),
                    self._backoff_max,
                )
                time.sleep(delay)

        with self._lock:
            self._failed_count += 1
        logger.error(
            "webhook_all_retries_exhausted",
            url=url,
            attempts=self._retry_attempts + 1,
        )
        return False

    def _handle_violation(self, ctx: ViolationHookContext) -> None:
        """Hook callback for violation events."""
        self.dispatch_violation(
            tool_name=ctx.tool_name,
            policy_name=ctx.policy_name,
            violation_type=str(ctx.violation_type),
            violation_reason=ctx.violation_reason,
        )

    def __repr__(self) -> str:
        return (
            f"WebhookDispatcher("
            f"violation={'✓' if self._on_violation else '✗'}, "
            f"cost={'✓' if self._on_cost_threshold else '✗'}, "
            f"audit_error={'✓' if self._on_audit_error else '✗'}, "
            f"sent={self.sent_count}, failed={self.failed_count})"
        )

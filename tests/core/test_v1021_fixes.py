# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for v1.0.21a1 audit fixes.

H-1:  fail_open path now redacts PII even when error occurs before _redact_args()
M-3:  async hook exceptions are logged instead of silently swallowed
L-3:  AuditEntry.from_dict uses public dataclasses.fields() API
A-1:  _warn_fail_open() now includes tool_name and error context
A-2:  Audit recording failure in fail_open mode emits critical log
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import warnings
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.auditor.engine import AuditEntry
from enforcecore.core.config import settings
from enforcecore.core.enforcer import Enforcer
from enforcecore.core.hardening import (
    InputTooLargeError,
    _warn_fail_open,
)
from enforcecore.plugins.hooks import _background_tasks, _on_background_task_done

if TYPE_CHECKING:
    from collections.abc import Iterator

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def identity_tool(*args: object, **kwargs: object) -> str:
    return "ok"


async def async_identity_tool(*args: object, **kwargs: object) -> str:
    await asyncio.sleep(0)
    return "ok"


@pytest.fixture
def _enable_fail_open() -> Iterator[None]:
    """Temporarily enable fail_open for the duration of the test."""
    original = settings.fail_open
    settings.fail_open = True
    yield
    settings.fail_open = original


# =========================================================================
# H-1: fail_open redacts PII before fallback execution
# =========================================================================


class TestH1FailOpenRedaction:
    """H-1: When an EnforceCoreError fires before _redact_args(), the
    fail_open path must still redact arguments before calling func().
    """

    @pytest.mark.usefixtures("_enable_fail_open")
    def test_sync_redacts_before_fail_open(self, pii_redaction_policy: Policy) -> None:
        """Sync path: oversized input with PII triggers InputTooLargeError
        before _redact_args(). The fail_open handler should call
        _redact_args() as recovery and pass redacted args to the tool.
        """
        received_args: list[tuple[object, ...]] = []

        def capturing_tool(*args: object, **kwargs: object) -> str:
            received_args.append(args)
            return "ok"

        enforcer = Enforcer(pii_redaction_policy)
        # PII embedded in oversized input — would be redacted if _redact_args runs
        pii = "my email is test@example.com "
        huge = pii * (10 * 1024 * 1024 // len(pii) + 1)  # > 10 MiB

        result = enforcer.enforce_sync(capturing_tool, huge, tool_name="pii_tool")
        assert result == "ok"
        # The tool should have been called
        assert len(received_args) == 1
        # Verify PII was redacted in the args passed to the tool
        passed_arg = str(received_args[0][0])
        assert "test@example.com" not in passed_arg

    @pytest.mark.usefixtures("_enable_fail_open")
    def test_async_redacts_before_fail_open(self, pii_redaction_policy: Policy) -> None:
        """Async path: same behavior as sync."""
        received_args: list[tuple[object, ...]] = []

        async def capturing_tool(*args: object, **kwargs: object) -> str:
            received_args.append(args)
            return "ok"

        enforcer = Enforcer(pii_redaction_policy)
        pii = "my email is test@example.com "
        huge = pii * (10 * 1024 * 1024 // len(pii) + 1)

        async def _run() -> str:
            return await enforcer.enforce_async(capturing_tool, huge, tool_name="pii_tool")

        result = asyncio.run(_run())
        assert result == "ok"
        assert len(received_args) == 1
        passed_arg = str(received_args[0][0])
        assert "test@example.com" not in passed_arg

    @pytest.mark.usefixtures("_enable_fail_open")
    def test_deep_redact_fallback_on_redaction_failure(self, allow_all_policy: Policy) -> None:
        """If _redact_args itself fails in the except handler, the nuclear
        fallback should replace all string args with [REDACTED].
        """
        received_args: list[tuple[object, ...]] = []

        def capturing_tool(*args: object, **kwargs: object) -> str:
            received_args.append(args)
            return "ok"

        enforcer = Enforcer(allow_all_policy)
        huge = "x" * (10 * 1024 * 1024 + 1)

        # Patch on the class so it affects the instance method lookup
        original = Enforcer._redact_args

        def broken_redact(self: Any, a: Any, k: Any) -> Any:
            msg = "redactor broken"
            raise RuntimeError(msg)

        try:
            Enforcer._redact_args = broken_redact  # type: ignore[assignment]
            result = enforcer.enforce_sync(capturing_tool, huge, tool_name="safe_tool")
            assert result == "ok"
            # Verify the nuclear fallback replaced strings with [REDACTED]
            assert len(received_args) == 1
            assert received_args[0][0] == "[REDACTED]"
        finally:
            Enforcer._redact_args = original  # type: ignore[assignment]


# =========================================================================
# M-3: Async hook exceptions are logged
# =========================================================================


class TestM3AsyncHookExceptionLogging:
    """M-3: _on_background_task_done() should log exceptions from
    fire-and-forget async hook tasks.
    """

    def test_done_callback_logs_exception(self) -> None:
        """When an async hook task fails, the done callback should log it."""

        async def _failing_hook() -> None:
            msg = "hook exploded"
            raise ValueError(msg)

        async def _run() -> asyncio.Task[None]:
            task = asyncio.get_event_loop().create_task(_failing_hook())
            _background_tasks.add(task)
            task.add_done_callback(_on_background_task_done)
            # Wait for the task to complete
            with contextlib.suppress(ValueError):
                await task
            return task

        with patch("enforcecore.plugins.hooks.logger") as mock_logger:
            asyncio.run(_run())
            # The done callback should have fired and logged
            mock_logger.warning.assert_called()
            call_kwargs = mock_logger.warning.call_args
            assert "async_hook_error" in str(call_kwargs)

    def test_done_callback_removes_from_set(self) -> None:
        """Done callback should remove the task from _background_tasks."""

        async def _ok_hook() -> None:
            return

        async def _run() -> asyncio.Task[None]:
            task = asyncio.get_event_loop().create_task(_ok_hook())
            _background_tasks.add(task)
            task.add_done_callback(_on_background_task_done)
            await task
            return task

        asyncio.run(_run())
        # The task should have been removed
        assert len(_background_tasks) == 0

    def test_cancelled_task_no_log(self) -> None:
        """Cancelled tasks should not trigger a warning log."""

        async def _long_hook() -> None:
            await asyncio.sleep(100)

        async def _run() -> asyncio.Task[None]:
            task = asyncio.get_event_loop().create_task(_long_hook())
            _background_tasks.add(task)
            task.add_done_callback(_on_background_task_done)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            return task

        with patch("enforcecore.plugins.hooks.logger") as mock_logger:
            asyncio.run(_run())
            mock_logger.warning.assert_not_called()


# =========================================================================
# L-3: AuditEntry.from_dict uses public dataclasses.fields()
# =========================================================================


class TestL3AuditEntryFromDict:
    """L-3: AuditEntry.from_dict should use dataclasses.fields() instead
    of the private __dataclass_fields__ attribute.
    """

    def test_from_dict_works(self) -> None:
        """Basic round-trip: to_dict -> from_dict."""
        entry = AuditEntry(
            tool_name="search_web",
            policy_name="strict",
            decision="allowed",
        )
        entry.seal()
        d = entry.to_dict()
        restored = AuditEntry.from_dict(d)
        assert restored.tool_name == "search_web"
        assert restored.policy_name == "strict"
        assert restored.entry_hash == entry.entry_hash

    def test_from_dict_ignores_unknown_keys(self) -> None:
        """Extra keys in the dict should be silently ignored."""
        d = {
            "tool_name": "calc",
            "policy_name": "test",
            "unknown_future_field": "should be ignored",
        }
        entry = AuditEntry.from_dict(d)
        assert entry.tool_name == "calc"
        assert not hasattr(entry, "unknown_future_field")

    def test_no_private_api_usage(self) -> None:
        """Verify that the implementation doesn't access __dataclass_fields__
        directly (it should use dataclasses.fields() instead)."""
        import inspect

        source = inspect.getsource(AuditEntry.from_dict)
        assert "__dataclass_fields__" not in source
        # Verify it still lists all fields correctly
        field_names = {f.name for f in dataclasses.fields(AuditEntry)}
        assert "tool_name" in field_names
        assert "entry_hash" in field_names


# =========================================================================
# A-1: _warn_fail_open() includes tool_name and error context
# =========================================================================


class TestA1WarnFailOpenContext:
    """A-1: _warn_fail_open() should accept and log tool_name + error."""

    def test_accepts_tool_name_and_error(self) -> None:
        """Should not raise when given tool_name and error."""
        with patch("enforcecore.core.hardening.is_dev_mode", return_value=True):
            # Should not raise
            _warn_fail_open(tool_name="search_web", error=ValueError("test"))

    def test_warning_includes_tool_name(self) -> None:
        """When not in dev mode, the RuntimeWarning should mention the tool."""
        with (
            patch("enforcecore.core.hardening.is_dev_mode", return_value=False),
            warnings.catch_warnings(record=True) as w,
        ):
            warnings.simplefilter("always")
            _warn_fail_open(tool_name="search_web", error=ValueError("boom"))
            assert len(w) == 1
            assert "search_web" in str(w[0].message)
            assert "ValueError" in str(w[0].message)

    def test_log_includes_tool_and_error_type(self) -> None:
        """Structured log should include tool, error_type, error_message."""
        with (
            patch("enforcecore.core.hardening.is_dev_mode", return_value=True),
            patch("enforcecore.core.hardening.logger") as mock_logger,
        ):
            exc = InputTooLargeError("too big")
            _warn_fail_open(tool_name="big_tool", error=exc)
            mock_logger.warning.assert_called_once()
            call_kwargs = mock_logger.warning.call_args
            # Check structured log fields
            assert call_kwargs.kwargs.get("tool") == "big_tool"
            assert call_kwargs.kwargs.get("error_type") == "InputTooLargeError"

    def test_backwards_compatible_no_args(self) -> None:
        """Calling with no args should still work (backwards compat)."""
        with patch("enforcecore.core.hardening.is_dev_mode", return_value=True):
            _warn_fail_open()  # No args — should not raise


# =========================================================================
# A-2: Audit recording failure in fail_open logs critical
# =========================================================================


class TestA2AuditFailureCriticalLog:
    """A-2: When audit recording fails with fail_open=True, a critical
    warning should be logged about the incomplete audit trail.
    """

    @pytest.mark.usefixtures("_enable_fail_open")
    def test_audit_failure_logs_critical(self, allow_all_policy: Policy) -> None:
        """When the auditor.record() raises and fail_open=True, the enforcer
        should log a critical message about incomplete audit trail.
        """
        # Enable audit so _auditor is created
        original_enabled = settings.audit_enabled
        settings.audit_enabled = True
        try:
            enforcer = Enforcer(allow_all_policy)
            # Sabotage the auditor
            enforcer._auditor = MagicMock()
            enforcer._auditor.record.side_effect = OSError("disk full")

            with patch("enforcecore.core.enforcer.logger") as mock_logger:
                result = enforcer.enforce_sync(identity_tool, "hi", tool_name="test_tool")
                assert result == "ok"  # Call should still succeed
                # Check that critical was logged
                mock_logger.critical.assert_called()
                critical_call = mock_logger.critical.call_args
                assert "audit_trail_incomplete" in str(critical_call)
        finally:
            settings.audit_enabled = original_enabled

    def test_audit_failure_raises_when_fail_closed(self, allow_all_policy: Policy) -> None:
        """When fail_open=False, audit failure should propagate the error."""
        original_enabled = settings.audit_enabled
        original_fail_open = settings.fail_open
        settings.audit_enabled = True
        settings.fail_open = False
        try:
            enforcer = Enforcer(allow_all_policy)
            enforcer._auditor = MagicMock()
            enforcer._auditor.record.side_effect = OSError("disk full")

            with pytest.raises(OSError, match="disk full"):
                enforcer.enforce_sync(identity_tool, "hi", tool_name="test_tool")
        finally:
            settings.audit_enabled = original_enabled
            settings.fail_open = original_fail_open

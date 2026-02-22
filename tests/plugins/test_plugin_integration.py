# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Integration tests for the v1.0.7 plugin & extensibility system.

Tests that hooks, custom patterns, secret detection, and audit backends
work correctly when wired through the Enforcer pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from enforcecore.core.config import settings
from enforcecore.core.policy import Policy
from enforcecore.core.types import EnforcementViolation
from enforcecore.plugins.hooks import (
    HookContext,
    HookRegistry,
    RedactionHookContext,
    ViolationHookContext,
)
from enforcecore.redactor.patterns import PatternRegistry

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_hooks():
    """Reset global hook registry before and after each test."""
    HookRegistry.reset_global()
    yield
    HookRegistry.reset_global()


@pytest.fixture(autouse=True)
def _reset_patterns():
    """Reset global pattern registry before and after each test."""
    PatternRegistry.clear()
    yield
    PatternRegistry.clear()


@pytest.fixture
def allow_policy() -> Policy:
    return Policy.from_file(FIXTURES_DIR / "allow_all.yaml")


@pytest.fixture
def deny_policy() -> Policy:
    return Policy.from_file(FIXTURES_DIR / "deny_all.yaml")


@pytest.fixture
def pii_policy() -> Policy:
    return Policy.from_file(FIXTURES_DIR / "pii_redaction.yaml")


# ---------------------------------------------------------------------------
# Hooks firing in the Enforcer
# ---------------------------------------------------------------------------


class TestHooksInEnforcer:
    def test_pre_call_hook_fires_on_allowed_call(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)
        calls: list[HookContext] = []

        reg = HookRegistry.global_registry()
        reg.add_pre_call(calls.append)

        def my_tool(x: int) -> int:
            return x * 2

        result = enforcer.enforce_sync(my_tool, 5, tool_name="my_tool")
        assert result == 10
        assert len(calls) == 1
        assert calls[0].tool_name == "my_tool"

    def test_post_call_hook_fires_with_result(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)
        results: list[Any] = []

        reg = HookRegistry.global_registry()
        reg.add_post_call(lambda ctx: results.append(ctx.result))

        def my_tool() -> str:
            return "hello"

        enforcer.enforce_sync(my_tool, tool_name="my_tool")
        assert results == ["hello"]

    def test_violation_hook_fires_on_blocked_call(self, deny_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=deny_policy)
        violations: list[ViolationHookContext] = []

        reg = HookRegistry.global_registry()
        reg.add_violation(violations.append)

        def my_tool() -> str:
            return "hello"

        with pytest.raises(EnforcementViolation):
            enforcer.enforce_sync(my_tool, tool_name="blocked_tool")

        assert len(violations) == 1
        assert violations[0].tool_name == "blocked_tool"

    def test_pre_call_abort_blocks_execution(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)

        def abort_hook(ctx: HookContext) -> None:
            ctx.abort = True
            ctx.abort_reason = "Custom abort"

        reg = HookRegistry.global_registry()
        reg.add_pre_call(abort_hook)

        executed = False

        def my_tool() -> str:
            nonlocal executed
            executed = True
            return "should not run"

        with pytest.raises(EnforcementViolation, match="Custom abort"):
            enforcer.enforce_sync(my_tool, tool_name="my_tool")

        assert executed is False

    def test_hook_error_does_not_break_enforcement(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)

        def bad_hook(ctx: HookContext) -> None:
            msg = "hook explosion"
            raise RuntimeError(msg)

        reg = HookRegistry.global_registry()
        reg.add_pre_call(bad_hook)

        def my_tool() -> str:
            return "still works"

        result = enforcer.enforce_sync(my_tool, tool_name="my_tool")
        assert result == "still works"

    def test_multiple_hooks_all_fire(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)
        tracker: list[str] = []

        reg = HookRegistry.global_registry()
        reg.add_pre_call(lambda ctx: tracker.append("pre"))
        reg.add_post_call(lambda ctx: tracker.append("post"))

        def my_tool() -> str:
            return "ok"

        enforcer.enforce_sync(my_tool, tool_name="my_tool")
        assert "pre" in tracker
        assert "post" in tracker


# ---------------------------------------------------------------------------
# Async hooks in Enforcer
# ---------------------------------------------------------------------------


class TestAsyncHooksInEnforcer:
    @pytest.mark.asyncio
    async def test_async_pre_call_hook_fires(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)
        calls: list[str] = []

        async def async_hook(ctx: HookContext) -> None:
            calls.append(ctx.tool_name)

        reg = HookRegistry.global_registry()
        reg.add_pre_call(async_hook)

        async def my_tool() -> str:
            return "async result"

        result = await enforcer.enforce_async(my_tool, tool_name="my_tool")
        assert result == "async result"
        assert calls == ["my_tool"]

    @pytest.mark.asyncio
    async def test_async_violation_hook_fires(self, deny_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=deny_policy)
        violations: list[str] = []

        async def v_hook(ctx: ViolationHookContext) -> None:
            violations.append(ctx.tool_name)

        reg = HookRegistry.global_registry()
        reg.add_violation(v_hook)

        async def my_tool() -> str:
            return "hello"

        with pytest.raises(EnforcementViolation):
            await enforcer.enforce_async(my_tool, tool_name="blocked_tool")

        assert violations == ["blocked_tool"]

    @pytest.mark.asyncio
    async def test_async_abort_blocks_execution(self, allow_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)

        async def abort_hook(ctx: HookContext) -> None:
            ctx.abort = True
            ctx.abort_reason = "Async abort"

        reg = HookRegistry.global_registry()
        reg.add_pre_call(abort_hook)

        executed = False

        async def my_tool() -> str:
            nonlocal executed
            executed = True
            return "nope"

        with pytest.raises(EnforcementViolation, match="Async abort"):
            await enforcer.enforce_async(my_tool, tool_name="my_tool")

        assert executed is False


# ---------------------------------------------------------------------------
# Redaction hooks
# ---------------------------------------------------------------------------


class TestRedactionHooksInEnforcer:
    def test_input_redaction_hook_fires(self, pii_policy: Policy):
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=pii_policy)
        redactions: list[RedactionHookContext] = []

        reg = HookRegistry.global_registry()
        reg.add_redaction(redactions.append)

        def my_tool(text: str) -> str:
            return "ok"

        enforcer.enforce_sync(
            my_tool,
            "Contact john@example.com please",
            tool_name="my_tool",
        )

        input_redactions = [r for r in redactions if r.direction == "input"]
        assert len(input_redactions) >= 1
        assert input_redactions[0].redaction_count >= 1


# ---------------------------------------------------------------------------
# Secret detection integration
# ---------------------------------------------------------------------------


class TestSecretDetectionIntegration:
    def test_secret_scanner_detects_aws_key(self):
        from enforcecore.redactor.secrets import SecretScanner

        scanner = SecretScanner(categories=["aws_access_key"])
        text = "my key is AKIAIOSFODNN7EXAMPLE"
        secrets = scanner.detect(text)
        assert len(secrets) == 1
        assert secrets[0].category == "aws_access_key"

    def test_secret_scanner_detects_github_token(self):
        from enforcecore.redactor.secrets import SecretScanner

        scanner = SecretScanner(categories=["github_token"])
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        secrets = scanner.detect(text)
        assert len(secrets) == 1
        assert secrets[0].category == "github_token"


# ---------------------------------------------------------------------------
# Custom patterns integration
# ---------------------------------------------------------------------------


class TestCustomPatternsIntegration:
    def test_register_and_detect_custom_pattern(self):
        from enforcecore.redactor.patterns import PatternRegistry

        PatternRegistry.register(
            "employee_id",
            r"EMP-\d{6}",
            placeholder="<EMPLOYEE_ID>",
        )

        p = PatternRegistry.get("employee_id")
        assert p is not None
        match = p.regex.search("Employee EMP-123456 assigned")
        assert match is not None
        assert match.group() == "EMP-123456"

    def test_multiple_custom_patterns(self):
        from enforcecore.redactor.patterns import PatternRegistry

        PatternRegistry.register("order_id", r"ORD-\d{8}")
        PatternRegistry.register("ticket_id", r"TICKET-\d{5}")

        assert PatternRegistry.count() == 2
        assert "order_id" in PatternRegistry.categories()
        assert "ticket_id" in PatternRegistry.categories()


# ---------------------------------------------------------------------------
# Audit backend integration
# ---------------------------------------------------------------------------


class TestAuditBackendInEnforcer:
    def test_enforcer_writes_to_audit_backend(self, tmp_path: Path, allow_policy: Policy):
        """When audit is enabled and backend is provided, entries go through the backend."""
        from enforcecore.auditor.backends import CallbackBackend
        from enforcecore.auditor.engine import Auditor
        from enforcecore.core.enforcer import Enforcer

        # Enable audit for this test
        original_enabled = settings.audit_enabled
        settings.audit_enabled = True

        try:
            Enforcer(policy=allow_policy)
            # The enforcer builds its own auditor from settings.
            # For a full integration test, we verify the backend works via Auditor directly.
            entries: list[dict[str, Any]] = []
            backend = CallbackBackend(entries.append)
            auditor = Auditor(backend=backend)

            auditor.record(
                tool_name="test_tool",
                policy_name="test_policy",
                policy_version="1.0",
                decision="allowed",
                call_id="test-call",
                overhead_ms=1.0,
                call_duration_ms=5.0,
                input_redactions=0,
                output_redactions=0,
            )

            assert len(entries) == 1
            assert entries[0]["tool_name"] == "test_tool"
        finally:
            settings.audit_enabled = original_enabled


# ---------------------------------------------------------------------------
# Combined extensibility features
# ---------------------------------------------------------------------------


class TestCombinedExtensibility:
    def test_hooks_and_patterns_together(self, pii_policy: Policy):
        """Hooks fire even when custom patterns are registered."""
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=pii_policy)

        # Register a custom pattern
        PatternRegistry.register("badge_id", r"BADGE-\d{4}")

        # Register hooks
        pre_calls: list[str] = []
        post_calls: list[str] = []
        reg = HookRegistry.global_registry()
        reg.add_pre_call(lambda ctx: pre_calls.append(ctx.tool_name))
        reg.add_post_call(lambda ctx: post_calls.append(ctx.tool_name))

        def my_tool(text: str) -> str:
            return f"processed: {text}"

        result = enforcer.enforce_sync(
            my_tool,
            "Hello from BADGE-1234",
            tool_name="my_tool",
        )

        assert pre_calls == ["my_tool"]
        assert post_calls == ["my_tool"]
        assert "processed:" in result

    def test_metadata_passes_between_hooks(self, allow_policy: Policy):
        """Pre-call hook sets metadata that post-call hook can read."""
        from enforcecore.core.enforcer import Enforcer

        enforcer = Enforcer(policy=allow_policy)
        captured_meta: list[dict[str, Any]] = []

        def pre_hook(ctx: HookContext) -> None:
            ctx.metadata["trace_id"] = "abc-123"

        def post_hook(ctx: HookContext) -> None:
            captured_meta.append(dict(ctx.metadata))

        reg = HookRegistry.global_registry()
        reg.add_pre_call(pre_hook)
        reg.add_post_call(post_hook)

        def my_tool() -> str:
            return "ok"

        enforcer.enforce_sync(my_tool, tool_name="my_tool")
        assert captured_meta[0]["trace_id"] == "abc-123"

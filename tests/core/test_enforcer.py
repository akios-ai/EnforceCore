"""Tests for enforcecore.core.enforcer — Enforcer class and @enforce decorator."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from enforcecore.core.enforcer import Enforcer, _policy_cache, enforce
from enforcecore.core.types import (
    EnforcementViolation,
    ToolDeniedError,
)

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.core.policy import Policy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sync_tool(x: int, y: int) -> int:
    """A simple sync tool for testing."""
    return x + y


async def async_tool(x: int, y: int) -> int:
    """A simple async tool for testing."""
    await asyncio.sleep(0)  # Yield to event loop
    return x + y


def tool_that_raises() -> None:
    """Tool that raises a non-enforcement error."""
    msg = "something broke"
    raise ValueError(msg)


async def async_tool_that_raises() -> None:
    msg = "async broke"
    raise ValueError(msg)


# ---------------------------------------------------------------------------
# Enforcer class tests
# ---------------------------------------------------------------------------


class TestEnforcerSync:
    def test_allowed_call(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        result = enforcer.enforce_sync(sync_tool, 3, 4, tool_name="sync_tool")
        assert result == 7

    def test_denied_call(self, deny_all_policy: Policy) -> None:
        enforcer = Enforcer(deny_all_policy)
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(sync_tool, 3, 4, tool_name="sync_tool")

    def test_specific_tool_allowed(self, specific_tools_policy: Policy) -> None:
        enforcer = Enforcer(specific_tools_policy)
        result = enforcer.enforce_sync(sync_tool, 1, 2, tool_name="search_web")
        assert result == 3

    def test_specific_tool_blocked(self, specific_tools_policy: Policy) -> None:
        enforcer = Enforcer(specific_tools_policy)
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(sync_tool, 1, 2, tool_name="send_email")

    def test_explicitly_denied_tool(self, specific_tools_policy: Policy) -> None:
        enforcer = Enforcer(specific_tools_policy)
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(sync_tool, 1, 2, tool_name="execute_shell")

    def test_tool_name_from_function(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        result = enforcer.enforce_sync(sync_tool, 10, 20)
        assert result == 30

    def test_tool_error_propagates(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        with pytest.raises(ValueError, match="something broke"):
            enforcer.enforce_sync(tool_that_raises, tool_name="tool_that_raises")

    def test_post_call_output_limit(self, output_limit_policy: Policy) -> None:
        def big_output() -> str:
            return "x" * 200

        enforcer = Enforcer(output_limit_policy)
        with pytest.raises(EnforcementViolation):
            enforcer.enforce_sync(big_output, tool_name="big_output")


class TestEnforcerAsync:
    @pytest.mark.asyncio
    async def test_allowed_call(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        result = await enforcer.enforce_async(async_tool, 3, 4, tool_name="async_tool")
        assert result == 7

    @pytest.mark.asyncio
    async def test_denied_call(self, deny_all_policy: Policy) -> None:
        enforcer = Enforcer(deny_all_policy)
        with pytest.raises(ToolDeniedError):
            await enforcer.enforce_async(async_tool, 3, 4, tool_name="async_tool")

    @pytest.mark.asyncio
    async def test_specific_tool_allowed(self, specific_tools_policy: Policy) -> None:
        enforcer = Enforcer(specific_tools_policy)
        result = await enforcer.enforce_async(async_tool, 5, 6, tool_name="calculator")
        assert result == 11

    @pytest.mark.asyncio
    async def test_specific_tool_blocked(self, specific_tools_policy: Policy) -> None:
        enforcer = Enforcer(specific_tools_policy)
        with pytest.raises(ToolDeniedError):
            await enforcer.enforce_async(async_tool, 1, 2, tool_name="delete_file")

    @pytest.mark.asyncio
    async def test_tool_error_propagates(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        with pytest.raises(ValueError, match="async broke"):
            await enforcer.enforce_async(async_tool_that_raises, tool_name="async_tool_that_raises")


class TestEnforcerFromFile:
    def test_from_file(self, fixtures_dir: Path) -> None:
        enforcer = Enforcer.from_file(fixtures_dir / "allow_all.yaml")
        assert enforcer.policy_name == "allow-all"

    def test_properties(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert enforcer.policy is allow_all_policy
        assert enforcer.policy_name == "allow-all"


class TestEnforcerDeprecatedRemoval:
    def test_guard_sync_removed(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert not hasattr(enforcer, "guard_sync")

    def test_guard_async_removed(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert not hasattr(enforcer, "guard_async")


class TestEnforcerLogMode:
    def test_log_mode_allows_denied_tool(self, log_only_policy: Policy) -> None:
        """In log mode, violations are logged but calls proceed."""
        enforcer = Enforcer(log_only_policy)
        # "forbidden_tool" is not in allowed list, but on_violation=log
        result = enforcer.enforce_sync(sync_tool, 1, 2, tool_name="forbidden_tool")
        assert result == 3


# ---------------------------------------------------------------------------
# @enforce() decorator tests
# ---------------------------------------------------------------------------


class TestEnforceDecorator:
    def setup_method(self) -> None:
        """Clear the policy cache before each test."""
        _policy_cache.clear()

    def test_sync_decorator(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "allow_all.yaml"))
        def my_tool(x: int) -> int:
            return x * 2

        assert my_tool(5) == 10

    def test_sync_decorator_blocked(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "deny_all.yaml"))
        def my_tool(x: int) -> int:
            return x * 2

        with pytest.raises(ToolDeniedError):
            my_tool(5)

    @pytest.mark.asyncio
    async def test_async_decorator(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "allow_all.yaml"))
        async def my_async_tool(x: int) -> int:
            return x * 2

        result = await my_async_tool(5)
        assert result == 10

    @pytest.mark.asyncio
    async def test_async_decorator_blocked(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "deny_all.yaml"))
        async def my_async_tool(x: int) -> int:
            return x * 2

        with pytest.raises(ToolDeniedError):
            await my_async_tool(5)

    def test_decorator_with_policy_object(self, allow_all_policy: Policy) -> None:
        @enforce(policy=allow_all_policy)
        def my_tool(x: int) -> int:
            return x + 1

        assert my_tool(10) == 11

    def test_decorator_with_tool_name(self, fixtures_dir: Path) -> None:
        @enforce(
            policy=str(fixtures_dir / "specific_tools.yaml"),
            tool_name="search_web",
        )
        def internal_search(query: str) -> str:
            return f"result for {query}"

        assert internal_search("test") == "result for test"

    def test_decorator_tool_name_mismatch_blocked(self, fixtures_dir: Path) -> None:
        @enforce(
            policy=str(fixtures_dir / "specific_tools.yaml"),
            tool_name="dangerous_tool",
        )
        def safe_looking_function() -> str:
            return "should not execute"

        with pytest.raises(ToolDeniedError):
            safe_looking_function()

    def test_decorator_preserves_function_name(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "allow_all.yaml"))
        def my_tool() -> None:
            """My docstring."""

        assert my_tool.__name__ == "my_tool"
        assert my_tool.__doc__ == "My docstring."

    @pytest.mark.asyncio
    async def test_async_decorator_preserves_function_name(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "allow_all.yaml"))
        async def my_async_tool() -> None:
            """Async docstring."""

        assert my_async_tool.__name__ == "my_async_tool"
        assert my_async_tool.__doc__ == "Async docstring."

    def test_decorator_with_kwargs(self, fixtures_dir: Path) -> None:
        @enforce(policy=str(fixtures_dir / "allow_all.yaml"))
        def my_tool(x: int, y: int = 10) -> int:
            return x + y

        assert my_tool(5, y=20) == 25

    def test_policy_caching(self, fixtures_dir: Path) -> None:
        """Loading the same policy path twice should use the cache."""
        path = str(fixtures_dir / "allow_all.yaml")

        @enforce(policy=path)
        def tool_a() -> str:
            return "a"

        @enforce(policy=path)
        def tool_b() -> str:
            return "b"

        tool_a()
        tool_b()
        # The path should be in cache
        assert path in _policy_cache


class TestEnforceDecoratorNoParens:
    """Test @enforce without parentheses (uses default policy)."""

    def test_no_default_policy_raises_at_decoration(self) -> None:
        """Without a default policy, @enforce raises at decoration time."""
        from enforcecore.core.config import settings
        from enforcecore.core.types import PolicyLoadError

        original = settings.default_policy
        try:
            settings.default_policy = None
            _policy_cache.clear()

            with pytest.raises(PolicyLoadError, match="No policy provided"):

                @enforce
                def my_tool() -> str:
                    return "hello"
        finally:
            settings.default_policy = original

    def test_with_default_policy(self, fixtures_dir: Path) -> None:
        """When a default policy is set, @enforce works without args."""
        from enforcecore.core.config import settings

        original = settings.default_policy
        try:
            settings.default_policy = str(fixtures_dir / "allow_all.yaml")
            _policy_cache.clear()

            @enforce
            def my_tool() -> str:
                return "hello"

            assert my_tool() == "hello"
        finally:
            settings.default_policy = original

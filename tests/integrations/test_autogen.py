# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.integrations.autogen — AutoGen adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore.core.types import ToolDeniedError

if TYPE_CHECKING:
    import types

    from enforcecore.core.policy import Policy

# ---------------------------------------------------------------------------
# Module-level import safety
# ---------------------------------------------------------------------------


class TestModuleImport:
    """Verify the adapter module can be imported without the framework."""

    def test_import_succeeds_without_autogen(self) -> None:
        """Importing the module should work even without autogen-core."""
        import enforcecore.integrations.autogen as mod

        assert hasattr(mod, "enforced_tool")

    def test_enforced_tool_raises_without_autogen(
        self,
        monkeypatch: pytest.MonkeyPatch,
        allow_all_policy: Policy,
    ) -> None:
        """Calling enforced_tool without autogen-core gives a clear error."""
        import sys

        monkeypatch.delitem(sys.modules, "autogen_core", raising=False)
        monkeypatch.delitem(sys.modules, "autogen_core.tools", raising=False)

        from enforcecore.integrations.autogen import enforced_tool

        with pytest.raises(ImportError, match="pip install autogen-core"):

            @enforced_tool(policy=allow_all_policy)
            async def my_tool(x: str) -> str:
                return x


# ---------------------------------------------------------------------------
# enforced_tool — sync
# ---------------------------------------------------------------------------


class TestEnforcedToolSync:
    """Sync tool creation through the AutoGen adapter."""

    def test_creates_function_tool(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Should return a FunctionTool with correct metadata."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=allow_all_policy, description="Add numbers")
        def calculator(a: int, b: int) -> int:
            return a + b

        tool = calculator
        assert tool.name == "calculator"
        assert tool.description == "Add numbers"
        assert tool.func is not None

    def test_enforcement_allows_valid_call(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Allowed tools should execute normally through the adapter."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=allow_all_policy, description="Add")
        def add(a: int, b: int) -> int:
            return a + b

        result = add.func(2, 3)
        assert result == 5

    def test_enforcement_blocks_denied_call(
        self,
        mock_autogen: types.ModuleType,
        deny_all_policy: Policy,
    ) -> None:
        """Denied tools should raise ToolDeniedError."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=deny_all_policy, description="Dangerous")
        def dangerous(cmd: str) -> str:
            return cmd

        with pytest.raises(ToolDeniedError):
            dangerous.func("rm -rf /")

    def test_description_from_docstring(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """If description is not given, use the docstring."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def search(query: str) -> str:
            """Search the web for information."""
            return query

        assert search.description == "Search the web for information."

    def test_description_fallback_to_name(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """If no description and no docstring, use the function name."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def search(query: str) -> str:
            return query

        assert search.description == "search"

    def test_custom_tool_name(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """tool_name should override the function name."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(
            policy=allow_all_policy,
            tool_name="web_search",
            description="Search",
        )
        def search(query: str) -> str:
            return query

        assert search.name == "web_search"


# ---------------------------------------------------------------------------
# enforced_tool — async
# ---------------------------------------------------------------------------


class TestEnforcedToolAsync:
    """Async tool creation through the AutoGen adapter."""

    def test_creates_async_function_tool(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Async functions should be wrapped and passed to FunctionTool."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=allow_all_policy, description="Fetch URL")
        async def fetch(url: str) -> str:
            return f"data from {url}"

        assert fetch.func is not None
        assert fetch.description == "Fetch URL"

    async def test_async_enforcement_allows(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Allowed async tools should execute normally."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=allow_all_policy, description="Fetch")
        async def fetch(url: str) -> str:
            return f"data: {url}"

        result = await fetch.func("https://example.com")
        assert result == "data: https://example.com"

    async def test_async_enforcement_blocks(
        self,
        mock_autogen: types.ModuleType,
        deny_all_policy: Policy,
    ) -> None:
        """Denied async tools should raise ToolDeniedError."""
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=deny_all_policy, description="Dangerous")
        async def fetch(url: str) -> str:
            return url

        with pytest.raises(ToolDeniedError):
            await fetch.func("https://example.com")

    def test_no_parens_decorator(
        self,
        mock_autogen: types.ModuleType,
        allow_all_policy: Policy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """@enforced_tool without parentheses uses the default policy."""
        from enforcecore.core.config import settings
        from enforcecore.integrations.autogen import enforced_tool
        from tests.conftest import FIXTURES_DIR

        monkeypatch.setattr(settings, "default_policy", FIXTURES_DIR / "allow_all.yaml")

        @enforced_tool
        def calculator(a: int, b: int) -> int:
            """Add numbers."""
            return a + b

        assert calculator.name == "calculator"

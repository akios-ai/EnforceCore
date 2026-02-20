"""Tests for enforcecore.integrations.langgraph — LangChain/LangGraph adapter."""

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

    def test_import_succeeds_without_langchain(self) -> None:
        """Importing the module should work even without langchain-core."""
        import enforcecore.integrations.langgraph as mod

        assert hasattr(mod, "enforced_tool")

    def test_enforced_tool_raises_without_langchain(
        self,
        monkeypatch: pytest.MonkeyPatch,
        allow_all_policy: Policy,
    ) -> None:
        """Calling enforced_tool without langchain-core gives a clear error."""
        import sys

        # Ensure langchain_core is NOT in sys.modules
        monkeypatch.delitem(sys.modules, "langchain_core", raising=False)
        monkeypatch.delitem(sys.modules, "langchain_core.tools", raising=False)

        from enforcecore.integrations.langgraph import enforced_tool

        with pytest.raises(ImportError, match="pip install langchain-core"):

            @enforced_tool(policy=allow_all_policy)
            def my_tool(x: str) -> str:
                return x


# ---------------------------------------------------------------------------
# enforced_tool — sync
# ---------------------------------------------------------------------------


class TestEnforcedToolSync:
    """Sync tool creation and enforcement through the LangGraph adapter."""

    def test_creates_structured_tool(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Should return a StructuredTool with correct metadata."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def search(query: str) -> str:
            """Search the web."""
            return f"results for {query}"

        tool = search
        assert tool.name == "search"
        assert tool.description == "Search the web."
        assert tool.func is not None
        assert tool.coroutine is None

    def test_enforcement_allows_valid_call(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Allowed tools should execute normally through the adapter."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def search(query: str) -> str:
            """Search."""
            return f"found: {query}"

        # Call the enforced function directly
        result = search.func("test")
        assert result == "found: test"

    def test_enforcement_blocks_denied_call(
        self,
        mock_langchain: types.ModuleType,
        deny_all_policy: Policy,
    ) -> None:
        """Denied tools should raise ToolDeniedError."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=deny_all_policy)
        def search(query: str) -> str:
            """Search."""
            return query

        with pytest.raises(ToolDeniedError):
            search.func("test")

    def test_custom_name(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """tool_name override should be reflected in the tool."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=allow_all_policy, tool_name="web_search")
        def search(query: str) -> str:
            """Search."""
            return query

        assert search.name == "web_search"

    def test_custom_description(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """description override should replace the docstring."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(
            policy=allow_all_policy,
            description="Custom description for LLM",
        )
        def search(query: str) -> str:
            """Original docstring."""
            return query

        assert search.description == "Custom description for LLM"

    def test_return_direct_flag(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """return_direct should be passed through to StructuredTool."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=allow_all_policy, return_direct=True)
        def search(query: str) -> str:
            """Search."""
            return query

        assert search.return_direct is True

    def test_no_parens_decorator(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """@enforced_tool without parentheses uses the default policy."""
        from enforcecore.core.config import settings
        from enforcecore.integrations.langgraph import enforced_tool

        # Point the default policy at the allow_all fixture
        from tests.conftest import FIXTURES_DIR

        monkeypatch.setattr(settings, "default_policy", FIXTURES_DIR / "allow_all.yaml")

        @enforced_tool
        def calculator(a: int, b: int) -> int:
            """Add numbers."""
            return a + b

        assert calculator.name == "calculator"


# ---------------------------------------------------------------------------
# enforced_tool — async
# ---------------------------------------------------------------------------


class TestEnforcedToolAsync:
    """Async tool creation through the LangGraph adapter."""

    def test_creates_async_structured_tool(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Async functions should be passed as 'coroutine' to StructuredTool."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        async def fetch(url: str) -> str:
            """Fetch a URL."""
            return f"data from {url}"

        tool = fetch
        assert tool.coroutine is not None
        assert tool.func is None
        assert tool.name == "fetch"

    async def test_async_enforcement_allows(
        self,
        mock_langchain: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Allowed async tools should execute normally."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        async def fetch(url: str) -> str:
            """Fetch."""
            return f"data: {url}"

        result = await fetch.coroutine("https://example.com")
        assert result == "data: https://example.com"

    async def test_async_enforcement_blocks(
        self,
        mock_langchain: types.ModuleType,
        deny_all_policy: Policy,
    ) -> None:
        """Denied async tools should raise ToolDeniedError."""
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=deny_all_policy)
        async def fetch(url: str) -> str:
            """Fetch."""
            return url

        with pytest.raises(ToolDeniedError):
            await fetch.coroutine("https://example.com")

"""Tests for enforcecore.integrations.crewai — CrewAI adapter."""

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

    def test_import_succeeds_without_crewai(self) -> None:
        """Importing the module should work even without crewai."""
        import enforcecore.integrations.crewai as mod

        assert hasattr(mod, "enforced_tool")

    def test_enforced_tool_raises_without_crewai(
        self,
        monkeypatch: pytest.MonkeyPatch,
        allow_all_policy: Policy,
    ) -> None:
        """Calling enforced_tool without crewai gives a clear error."""
        import sys

        monkeypatch.delitem(sys.modules, "crewai", raising=False)
        monkeypatch.delitem(sys.modules, "crewai.tools", raising=False)

        from enforcecore.integrations.crewai import enforced_tool

        with pytest.raises(ImportError, match="pip install crewai"):

            @enforced_tool(policy=allow_all_policy)
            def my_tool(x: str) -> str:
                return x


# ---------------------------------------------------------------------------
# enforced_tool
# ---------------------------------------------------------------------------


class TestEnforcedTool:
    """Tool creation and enforcement through the CrewAI adapter."""

    def test_creates_crewai_tool(
        self,
        mock_crewai: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Should return a CrewAI tool with correct metadata."""
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def search(query: str) -> str:
            """Search the web."""
            return f"results for {query}"

        tool = search
        assert tool.name == "search"
        assert tool.func is not None

    def test_enforcement_allows_valid_call(
        self,
        mock_crewai: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Allowed tools should execute normally through the adapter."""
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def calculator(a: int, b: int) -> int:
            """Add numbers."""
            return a + b

        result = calculator.func(2, 3)
        assert result == 5

    def test_enforcement_blocks_denied_call(
        self,
        mock_crewai: types.ModuleType,
        deny_all_policy: Policy,
    ) -> None:
        """Denied tools should raise ToolDeniedError."""
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=deny_all_policy)
        def search(query: str) -> str:
            """Search."""
            return query

        with pytest.raises(ToolDeniedError):
            search.func("test")

    def test_custom_tool_name(
        self,
        mock_crewai: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """tool_name override should be reflected in the tool."""
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=allow_all_policy, tool_name="web_search")
        def search(query: str) -> str:
            """Search."""
            return query

        assert search.name == "web_search"

    def test_callable_tool(
        self,
        mock_crewai: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """CrewAI tools should be callable (delegates to func)."""
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=allow_all_policy)
        def greet(name: str) -> str:
            """Greet someone."""
            return f"Hello, {name}!"

        # MockCrewAITool.__call__ delegates to self.func
        result = greet("World")
        assert result == "Hello, World!"

    def test_no_parens_decorator(
        self,
        mock_crewai: types.ModuleType,
        allow_all_policy: Policy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """@enforced_tool without parentheses uses the default policy."""
        from enforcecore.core.config import settings
        from enforcecore.integrations.crewai import enforced_tool
        from tests.conftest import FIXTURES_DIR

        monkeypatch.setattr(settings, "default_policy", FIXTURES_DIR / "allow_all.yaml")

        @enforced_tool
        def calculator(a: int, b: int) -> int:
            """Add."""
            return a + b

        assert calculator.name == "calculator"

    def test_specific_tools_policy(
        self,
        mock_crewai: types.ModuleType,
        specific_tools_policy: Policy,
    ) -> None:
        """A tool in the allowed list should pass; others should fail."""
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=specific_tools_policy)
        def search_web(query: str) -> str:
            """Allowed tool."""
            return query

        assert search_web.func("test") == "test"

        @enforced_tool(policy=specific_tools_policy)
        def execute_shell(cmd: str) -> str:
            """Not in allowed list."""
            return cmd

        with pytest.raises(ToolDeniedError):
            execute_shell.func("whoami")

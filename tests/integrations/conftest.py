"""Shared fixtures for integration adapter tests.

Provides mock framework modules (langchain_core, crewai, autogen_core)
that simulate the real APIs just enough for our adapter tests to run
without installing any of the actual frameworks.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

# ---------------------------------------------------------------------------
# Mock LangChain / LangGraph
# ---------------------------------------------------------------------------


class MockStructuredTool:
    """Simulates ``langchain_core.tools.StructuredTool``."""

    def __init__(
        self,
        *,
        func: Any = None,
        coroutine: Any = None,
        name: str = "",
        description: str = "",
        args_schema: type | None = None,
        return_direct: bool = False,
    ) -> None:
        self.func = func
        self.coroutine = coroutine
        self.name = name
        self.description = description
        self.args_schema = args_schema
        self.return_direct = return_direct

    @classmethod
    def from_function(
        cls,
        func: Any = None,
        name: str = "",
        description: str = "",
        *,
        coroutine: Any = None,
        args_schema: type | None = None,
        return_direct: bool = False,
        **_kwargs: Any,
    ) -> MockStructuredTool:
        """Factory matching LangChain's ``StructuredTool.from_function``."""
        return cls(
            func=func,
            coroutine=coroutine,
            name=name,
            description=description,
            args_schema=args_schema,
            return_direct=return_direct,
        )


@pytest.fixture
def mock_langchain(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Install a mock ``langchain_core`` into ``sys.modules``."""
    lc = types.ModuleType("langchain_core")
    lc_tools = types.ModuleType("langchain_core.tools")
    lc_tools.StructuredTool = MockStructuredTool  # type: ignore[attr-defined]
    lc.tools = lc_tools  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "langchain_core", lc)
    monkeypatch.setitem(sys.modules, "langchain_core.tools", lc_tools)
    return lc_tools


# ---------------------------------------------------------------------------
# Mock CrewAI
# ---------------------------------------------------------------------------


class MockCrewAITool:
    """Simulates a CrewAI tool returned by ``@tool("name")``."""

    def __init__(self, name: str, func: Any) -> None:
        self.name = name
        self.func = func

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.func(*args, **kwargs)


def _mock_crewai_tool_decorator(name: str) -> Any:
    """Simulates ``crewai.tools.tool("name")``."""

    def decorator(fn: Any) -> MockCrewAITool:
        return MockCrewAITool(name=name, func=fn)

    return decorator


@pytest.fixture
def mock_crewai(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Install a mock ``crewai`` into ``sys.modules``."""
    crewai = types.ModuleType("crewai")
    crewai_tools = types.ModuleType("crewai.tools")
    crewai_tools.tool = _mock_crewai_tool_decorator  # type: ignore[attr-defined]
    crewai.tools = crewai_tools  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "crewai", crewai)
    monkeypatch.setitem(sys.modules, "crewai.tools", crewai_tools)
    return crewai_tools


# ---------------------------------------------------------------------------
# Mock AutoGen
# ---------------------------------------------------------------------------


class MockFunctionTool:
    """Simulates ``autogen_core.tools.FunctionTool``."""

    def __init__(self, func: Any, description: str = "") -> None:
        self.func = func
        self.description = description
        self.name: str = getattr(func, "__name__", "unknown")


@pytest.fixture
def mock_autogen(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Install a mock ``autogen_core`` into ``sys.modules``."""
    ag = types.ModuleType("autogen_core")
    ag_tools = types.ModuleType("autogen_core.tools")
    ag_tools.FunctionTool = MockFunctionTool  # type: ignore[attr-defined]
    ag.tools = ag_tools  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "autogen_core", ag)
    monkeypatch.setitem(sys.modules, "autogen_core.tools", ag_tools)
    return ag_tools

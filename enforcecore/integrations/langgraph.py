# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""LangChain / LangGraph integration adapter.

Provides ``enforced_tool`` — a drop-in replacement for LangChain's ``@tool``
decorator that adds EnforceCore policy enforcement to every invocation.

Requires: ``pip install langchain-core``

Example::

    from enforcecore.integrations.langgraph import enforced_tool

    @enforced_tool(policy="policy.yaml")
    def search(query: str) -> str:
        \"\"\"Search the web for information.\"\"\"
        return web_search(query)

    # Use in LangGraph as normal — enforcement is automatic
    agent = create_react_agent(model, tools=[search])
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from enforcecore.integrations._base import require_package, wrap_with_policy

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from enforcecore.core.policy import Policy

__all__ = ["enforced_tool"]


def enforced_tool(
    func: Callable[..., Any] | None = None,
    *,
    policy: str | Path | Policy | None = None,
    tool_name: str | None = None,
    description: str | None = None,
    args_schema: type | None = None,
    return_direct: bool = False,
) -> Any:
    """Create a LangChain ``StructuredTool`` with EnforceCore enforcement.

    Drop-in replacement for ``@langchain.tools.tool`` that applies
    policy enforcement on every invocation.

    Can be used with or without arguments::

        @enforced_tool(policy="policy.yaml")
        def my_tool(query: str) -> str:
            \"\"\"Search the web.\"\"\"
            ...

        @enforced_tool
        def my_tool(query: str) -> str:
            \"\"\"Uses the default policy from settings.\"\"\"
            ...

    Args:
        func: When used without parentheses, the function to decorate.
        policy: YAML policy path, ``Policy`` object, or ``None`` to use
            the default policy from settings.
        tool_name: Override the tool name for policy evaluation.
            Defaults to ``func.__name__``.
        description: Override the tool description shown to the LLM.
            Defaults to the function's docstring.
        args_schema: Optional Pydantic model for input validation
            (passed through to LangChain's ``StructuredTool``).
        return_direct: Whether the tool output should be returned directly
            to the user instead of being passed back to the LLM.

    Returns:
        A LangChain ``StructuredTool`` with enforcement applied.

    Raises:
        ImportError: If ``langchain-core`` is not installed.
        PolicyLoadError: If the policy cannot be loaded.
    """

    def decorator(fn: Callable[..., Any]) -> Any:
        require_package("langchain_core", pip_name="langchain-core")
        from langchain_core.tools import StructuredTool

        name = tool_name or getattr(fn, "__name__", str(fn))
        enforced_fn = wrap_with_policy(fn, policy=policy, tool_name=name)
        desc = description or getattr(fn, "__doc__", "") or name

        # StructuredTool.from_function distinguishes sync vs async
        if inspect.iscoroutinefunction(fn):
            return StructuredTool.from_function(
                func=None,
                coroutine=enforced_fn,
                name=name,
                description=desc,
                args_schema=args_schema,
                return_direct=return_direct,
            )

        return StructuredTool.from_function(
            func=enforced_fn,
            name=name,
            description=desc,
            args_schema=args_schema,
            return_direct=return_direct,
        )

    if func is not None:
        return decorator(func)
    return decorator

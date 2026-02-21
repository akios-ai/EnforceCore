# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""CrewAI integration adapter.

Provides ``enforced_tool`` — a decorator that creates CrewAI tools with
EnforceCore policy enforcement on every invocation.

Requires: ``pip install crewai``

Example::

    from enforcecore.integrations.crewai import enforced_tool

    @enforced_tool(policy="policy.yaml")
    def search(query: str) -> str:
        \"\"\"Search the web for information.\"\"\"
        return web_search(query)

    # Use in CrewAI as normal — enforcement is automatic
    agent = Agent(tools=[search])
"""

from __future__ import annotations

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
) -> Any:
    """Create a CrewAI tool with EnforceCore enforcement.

    Drop-in replacement for CrewAI's ``@tool`` decorator that applies
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

    Returns:
        A CrewAI tool with enforcement applied.

    Raises:
        ImportError: If ``crewai`` is not installed.
        PolicyLoadError: If the policy cannot be loaded.
    """

    def decorator(fn: Callable[..., Any]) -> Any:
        require_package("crewai")
        from crewai.tools import tool as crewai_tool

        name = tool_name or getattr(fn, "__name__", str(fn))
        enforced_fn = wrap_with_policy(fn, policy=policy, tool_name=name)

        # CrewAI's @tool("name") returns a decorator → apply it
        return crewai_tool(name)(enforced_fn)

    if func is not None:
        return decorator(func)
    return decorator

"""AutoGen integration adapter.

Provides ``enforced_tool`` — a decorator that creates AutoGen ``FunctionTool``
instances with EnforceCore policy enforcement on every invocation.

Targets AutoGen v0.4+ (``autogen-core``).

Requires: ``pip install autogen-core``

Example::

    from enforcecore.integrations.autogen import enforced_tool

    @enforced_tool(policy="policy.yaml", description="Search the web")
    async def search(query: str) -> str:
        return await web_search(query)

    # Use in AutoGen as normal — enforcement is automatic
    agent = AssistantAgent(tools=[search])
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
    description: str | None = None,
) -> Any:
    """Create an AutoGen ``FunctionTool`` with EnforceCore enforcement.

    Drop-in replacement for ``FunctionTool(fn, description=...)`` that
    applies policy enforcement on every invocation.

    Can be used with or without arguments::

        @enforced_tool(policy="policy.yaml", description="Search the web")
        async def search(query: str) -> str: ...

        @enforced_tool
        async def search(query: str) -> str:
            \"\"\"Search the web.\"\"\"
            ...

    Args:
        func: When used without parentheses, the function to decorate.
        policy: YAML policy path, ``Policy`` object, or ``None`` to use
            the default policy from settings.
        tool_name: Override the tool name for policy evaluation.
            Defaults to ``func.__name__``.
        description: Tool description (shown to the LLM).  Defaults to the
            function's docstring or, if absent, the function name.

    Returns:
        An AutoGen ``FunctionTool`` with enforcement applied.

    Raises:
        ImportError: If ``autogen-core`` is not installed.
        PolicyLoadError: If the policy cannot be loaded.
    """

    def decorator(fn: Callable[..., Any]) -> Any:
        require_package("autogen_core", pip_name="autogen-core")
        from autogen_core.tools import FunctionTool

        name = tool_name or getattr(fn, "__name__", str(fn))
        enforced_fn = wrap_with_policy(fn, policy=policy, tool_name=name)
        desc = description or getattr(fn, "__doc__", "") or name

        # Ensure FunctionTool picks up the correct name
        object.__setattr__(enforced_fn, "__name__", name)

        return FunctionTool(enforced_fn, description=desc)

    if func is not None:
        return decorator(func)
    return decorator

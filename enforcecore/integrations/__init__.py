"""Framework integration adapters for EnforceCore.

Each adapter is a standalone module with no required dependencies beyond
EnforceCore itself.  The framework packages (``langchain-core``, ``crewai``,
``autogen-core``) are only imported when you actually *call* an adapter
function — importing the module itself always succeeds.

Available adapters::

    from enforcecore.integrations.langgraph import enforced_tool   # LangChain / LangGraph
    from enforcecore.integrations.crewai import enforced_tool      # CrewAI
    from enforcecore.integrations.autogen import enforced_tool     # AutoGen v0.4+

Shared utilities for custom adapters::

    from enforcecore.integrations import wrap_with_policy, require_package
"""

from enforcecore.integrations._base import require_package, wrap_with_policy

__all__ = [
    "require_package",
    "wrap_with_policy",
]

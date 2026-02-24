# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore x LangGraph — Copy-paste quickstart.

Demonstrates real runtime policy enforcement inside a LangGraph agent loop.
Uses a mock LLM (no API key required) so you can run this file immediately.

Install prerequisites:
    pip install langchain-core langgraph

Run from the repo root:
    python examples/quickstart_langgraph.py
"""

from __future__ import annotations

from enforcecore import Enforcer
from enforcecore.core.policy import PIIRedactionConfig, Policy, PolicyRules
from enforcecore.core.types import RedactionStrategy, ToolDeniedError

# ---------------------------------------------------------------------------
# 1. Define a strict EnforceCore policy
# ---------------------------------------------------------------------------

policy = Policy(
    name="langgraph-demo",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["search_web", "calculate", "get_weather"],
        denied_tools=["execute_shell", "delete_file", "write_to_db"],
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            categories=["email", "phone", "ssn", "credit_card"],
            strategy=RedactionStrategy.MASK,
        ),
        max_output_size_bytes=50_000,
        max_cost_usd=10.0,
        max_call_duration_ms=5_000,
    ),
)

enforcer = Enforcer(policy)


# ---------------------------------------------------------------------------
# 2. Wrap tools with EnforceCore enforcement
# ---------------------------------------------------------------------------
#
# Pattern: pass any callable into enforcer.enforce_sync(fn, *args, tool_name=...)
# Pre-call checks (allow/deny list, resource limits) run before fn executes.
# Post-call checks (PII redaction) run on the return value automatically.


def _raw_search_web(query: str) -> str:
    return f"Top results for '{query}': [EnforceCore docs, PyPI page]"


def _raw_calculate(expression: str) -> str:
    try:
        return str(eval(expression, {"__builtins__": {}}))
    except Exception:
        return "error"


def _raw_execute_shell(cmd: str) -> str:
    return f"$ {cmd}"  # unreachable — enforcer blocks before calling


def _raw_write_to_db(query: str) -> str:
    return f"Executed: {query}"  # unreachable — enforcer blocks before calling


def _raw_search_with_pii(query: str) -> str:
    return f"Found user record: email user@corp.com ssn 123-45-6789 for query '{query}'"


def search_web(query: str) -> str:
    """Enforce + execute — allowed by policy."""
    return enforcer.enforce_sync(_raw_search_web, query, tool_name="search_web")


def calculate(expression: str) -> str:
    """Enforce + execute — allowed by policy."""
    return enforcer.enforce_sync(_raw_calculate, expression, tool_name="calculate")


def execute_shell(cmd: str) -> str:
    """Blocked by deny list — ToolDeniedError raised before fn runs."""
    return enforcer.enforce_sync(_raw_execute_shell, cmd, tool_name="execute_shell")


def write_to_db(query: str) -> str:
    """Blocked by deny list — ToolDeniedError raised before fn runs."""
    return enforcer.enforce_sync(_raw_write_to_db, query, tool_name="write_to_db")


def search_with_pii(query: str) -> str:
    """Allowed tool whose output contains PII — auto-masked by enforcer."""
    return enforcer.enforce_sync(_raw_search_with_pii, query, tool_name="search_web")


# ---------------------------------------------------------------------------
# 3. Simulate a LangGraph-style tool-calling loop
#    (uses a mock "LLM" that emits a fixed plan; no API key needed)
# ---------------------------------------------------------------------------

MOCK_TOOL_PLAN = [
    # (fn, args, description)
    (search_web, {"query": "EnforceCore Python library"}, "Searching the web…"),
    (calculate, {"expression": "42 * 365"}, "Running calculation…"),
    (execute_shell, {"cmd": "rm -rf /"}, "Attempting shell (denied)…"),
    (write_to_db, {"query": "DROP TABLE users"}, "Attempting DB write (denied)…"),
    (search_with_pii, {"query": "EnforceCore user data"}, "Search → output PII auto-masked…"),
]


def run_agent_loop() -> None:
    print("=" * 64)
    print("  EnforceCore x LangGraph Quickstart")
    print("  Policy : langgraph-demo v1.0.0")
    print("  Action : Strict allow/deny + PII masking")
    print("=" * 64)

    blocked_count = 0
    allowed_count = 0

    for fn, args, description in MOCK_TOOL_PLAN:
        print(f"\n── Step: {description}")
        print(f"   Tool : {fn.__name__}({args})")
        try:
            result = fn(**args)
            print(f"   Result: ✓  {result}")
            allowed_count += 1
        except ToolDeniedError as exc:
            print(f"   Result: ✗  BLOCKED — {exc}")
            blocked_count += 1

    print(f"\n── Summary: {allowed_count} allowed, {blocked_count} blocked")
    print(f"   Audit chain: {enforcer._auditor.entry_count} immutable entries")
    print()

    print("LangGraph integration pattern:")
    print("  from enforcecore.integrations.langgraph import enforced_tool")
    print()
    print("  @enforced_tool(policy='policy.yaml')")
    print("  def search_web(query: str) -> str:")
    print('      """Search the web."""')
    print("      return web_search(query)")
    print()
    print("  # Drop into any LangGraph graph as a normal LangChain tool:")
    print("  agent = create_react_agent(llm, tools=[search_web])")


if __name__ == "__main__":
    run_agent_loop()

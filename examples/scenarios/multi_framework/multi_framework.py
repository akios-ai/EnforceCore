# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Multi-Framework — Same policy across LangGraph, CrewAI, AutoGen, and plain Python.

Demonstrates that EnforceCore's enforcement is completely framework-agnostic:
the same YAML policy produces identical behaviour regardless of which agent
framework wraps the tool call.

Run::

    python examples/scenarios/multi_framework/multi_framework.py

Note: Framework adapters are import-guarded. This example always works with
plain @enforce even if LangGraph/CrewAI/AutoGen are not installed.
"""

from __future__ import annotations

from pathlib import Path

from enforcecore import Enforcer, Policy, ToolDeniedError, enforce

POLICY_PATH = Path(__file__).parent / "policy.yaml"


# ---------------------------------------------------------------------------
# Shared tool implementations
# ---------------------------------------------------------------------------


def search_web(query: str) -> str:
    """Simulate a web search."""
    return f"Results for '{query}': [result1, result2, result3]"


def calculator(expression: str) -> str:
    """Simulate a calculator."""
    return f"= 42 (parsed: {expression})"


def execute_shell(cmd: str) -> str:
    """Dangerous tool — blocked by policy."""
    return f"$ {cmd}"


# ---------------------------------------------------------------------------
# 1. Plain @enforce decorator
# ---------------------------------------------------------------------------


def demo_plain_enforce() -> None:
    """Demonstrate plain @enforce decorator."""
    print("\n--- Plain @enforce Decorator ---")

    @enforce(policy=POLICY_PATH, tool_name="search_web")
    def enforced_search(query: str) -> str:
        return search_web(query)

    @enforce(policy=POLICY_PATH, tool_name="execute_shell")
    def enforced_shell(cmd: str) -> str:
        return execute_shell(cmd)

    # Allowed
    result = enforced_search("python best practices")
    print(f"  ✓ search_web: {result}")

    # Denied
    try:
        enforced_shell("rm -rf /")
        print("  ✗ shell should have been blocked")
    except ToolDeniedError:
        print("  ✓ execute_shell: BLOCKED by policy")


# ---------------------------------------------------------------------------
# 2. Enforcer class (direct invocation)
# ---------------------------------------------------------------------------


def demo_enforcer_class() -> None:
    """Demonstrate direct Enforcer class usage."""
    print("\n--- Enforcer Class ---")

    policy = Policy.from_file(POLICY_PATH)
    enforcer = Enforcer(policy)

    # Allowed — with PII in input
    result = enforcer.enforce_sync(
        lambda _pii: search_web("weather"),
        "Contact user@example.com for weather info",
        tool_name="search_web",
    )
    print(f"  ✓ search_web: {result}")

    # Denied
    try:
        enforcer.enforce_sync(
            execute_shell,
            "whoami",
            tool_name="execute_shell",
        )
    except ToolDeniedError:
        print("  ✓ execute_shell: BLOCKED by policy")


# ---------------------------------------------------------------------------
# 3. LangGraph adapter (import-guarded)
# ---------------------------------------------------------------------------


def demo_langgraph() -> None:
    """Try LangGraph adapter if available."""
    print("\n--- LangGraph Adapter ---")
    try:
        from enforcecore.integrations.langgraph import enforced_tool

        @enforced_tool(policy=POLICY_PATH, tool_name="search_web")
        def lg_search(query: str) -> str:
            return search_web(query)

        result = lg_search.invoke({"query": "AI safety"})
        print(f"  ✓ LangGraph search: {result}")
    except ImportError:
        print("  ⊘ langchain-core not installed — skipping")
    except Exception as e:
        print(f"  ⊘ LangGraph demo skipped: {e}")


# ---------------------------------------------------------------------------
# 4. CrewAI adapter (import-guarded)
# ---------------------------------------------------------------------------


def demo_crewai() -> None:
    """Try CrewAI adapter if available."""
    print("\n--- CrewAI Adapter ---")
    try:
        from enforcecore.integrations.crewai import enforced_tool

        @enforced_tool(policy=POLICY_PATH, tool_name="calculator")
        def crew_calc(expression: str) -> str:
            return calculator(expression)

        result = crew_calc("2 + 2")
        print(f"  ✓ CrewAI calc: {result}")
    except ImportError:
        print("  ⊘ crewai not installed — skipping")
    except Exception as e:
        print(f"  ⊘ CrewAI demo skipped: {e}")


# ---------------------------------------------------------------------------
# 5. AutoGen adapter (import-guarded)
# ---------------------------------------------------------------------------


def demo_autogen() -> None:
    """Try AutoGen adapter if available."""
    print("\n--- AutoGen Adapter ---")
    try:
        from enforcecore.integrations.autogen import enforced_tool

        @enforced_tool(policy=POLICY_PATH, tool_name="search_web")
        def ag_search(query: str) -> str:
            return search_web(query)

        result = ag_search("latest research papers")
        print(f"  ✓ AutoGen search: {result}")
    except ImportError:
        print("  ⊘ autogen-core not installed — skipping")
    except Exception as e:
        print(f"  ⊘ AutoGen demo skipped: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    """Run all framework demos."""
    print("=" * 60)
    print("Multi-Framework — Same Policy, Different Frameworks")
    print("=" * 60)

    demo_plain_enforce()
    demo_enforcer_class()
    demo_langgraph()
    demo_crewai()
    demo_autogen()

    print("\n" + "=" * 60)
    print("Multi-framework scenario complete.")
    print("All frameworks enforce the same policy identically.")
    print("=" * 60)


if __name__ == "__main__":
    main()

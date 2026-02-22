# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore Framework Integration Examples.

Demonstrates how to add EnforceCore policy enforcement to popular
AI agent frameworks (LangGraph, CrewAI, AutoGen) with a single decorator.

Prerequisites
-------------
Install the framework you want to try::

    pip install langchain-core       # For LangGraph/LangChain
    pip install crewai               # For CrewAI
    pip install autogen-core         # For AutoGen v0.4+

EnforceCore itself has NO hard dependencies on any framework.

Usage
-----
Run this file directly (framework imports are guarded)::

    python examples/framework_integrations.py
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

# ---------------------------------------------------------------------------
# Shared policy (used by all examples)
# ---------------------------------------------------------------------------

POLICY_PATH = Path(__file__).parent.parent / "tests" / "fixtures" / "allow_all.yaml"
DENY_POLICY = Path(__file__).parent.parent / "tests" / "fixtures" / "deny_all.yaml"


def banner(title: str) -> None:
    """Print a section banner."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


# ===================================================================
# 1. LangGraph / LangChain
# ===================================================================
def demo_langgraph() -> None:
    """Show enforced_tool for LangChain/LangGraph."""
    banner("LangGraph / LangChain Adapter")

    from enforcecore.integrations.langgraph import enforced_tool

    try:
        # --- Create an enforced tool ---
        @enforced_tool(policy=str(POLICY_PATH))
        def search_web(query: str) -> str:
            """Search the web for information."""
            return f"Results for '{query}': EnforceCore is awesome!"

    except ImportError:
        print("  [SKIP] langchain-core not installed")
        print("  Install with: pip install langchain-core")
        return

    print(f"  Tool created: {search_web.name}")
    print(f"  Description:  {search_web.description}")
    print(f"  Type:         {type(search_web).__name__}")

    # Call the tool
    result = search_web.func("EnforceCore framework integrations")
    print(f"  Result:       {result}")

    # --- Demonstrate policy blocking ---
    from enforcecore.core.types import ToolDeniedError

    @enforced_tool(policy=str(DENY_POLICY))
    def blocked_tool(x: str) -> str:
        """This tool will be blocked."""
        return x

    try:
        blocked_tool.func("test")
    except ToolDeniedError as e:
        print(f"  Blocked:      ✓ ({e.violation_type})")

    print()


# ===================================================================
# 2. CrewAI
# ===================================================================
def demo_crewai() -> None:
    """Show enforced_tool for CrewAI."""
    banner("CrewAI Adapter")

    from enforcecore.integrations.crewai import enforced_tool

    try:

        @enforced_tool(policy=str(POLICY_PATH))
        def calculator(expression: str) -> str:
            """Evaluate a math expression."""
            return f"Result: {eval(expression)}"

    except ImportError:
        print("  [SKIP] crewai not installed")
        print("  Install with: pip install crewai")
        return

    print(f"  Tool created: {calculator.name}")
    print(f"  Type:         {type(calculator).__name__}")

    result = calculator("2 + 3")
    print(f"  Result:       {result}")

    # Demonstrate blocking
    from enforcecore.core.types import ToolDeniedError

    @enforced_tool(policy=str(DENY_POLICY))
    def blocked_calc(x: str) -> str:
        """Blocked calculator."""
        return x

    try:
        blocked_calc("1+1")
    except ToolDeniedError as e:
        print(f"  Blocked:      ✓ ({e.violation_type})")

    print()


# ===================================================================
# 3. AutoGen
# ===================================================================
def demo_autogen() -> None:
    """Show enforced_tool for AutoGen."""
    banner("AutoGen Adapter")

    from enforcecore.integrations.autogen import enforced_tool

    try:

        @enforced_tool(policy=str(POLICY_PATH), description="Get the current weather")
        def get_weather(city: str) -> str:
            return f"Weather in {city}: 22°C, sunny"

    except ImportError:
        print("  [SKIP] autogen-core not installed")
        print("  Install with: pip install autogen-core")
        return

    print(f"  Tool created: {get_weather.name}")
    print(f"  Description:  {get_weather.description}")
    print(f"  Type:         {type(get_weather).__name__}")

    result = get_weather.func("San Francisco")
    print(f"  Result:       {result}")

    # Demonstrate blocking
    from enforcecore.core.types import ToolDeniedError

    @enforced_tool(policy=str(DENY_POLICY), description="Blocked")
    def blocked_weather(city: str) -> str:
        return city

    try:
        blocked_weather.func("NYC")
    except ToolDeniedError as e:
        print(f"  Blocked:      ✓ ({e.violation_type})")

    print()


# ===================================================================
# 4. Plain Python (no framework needed)
# ===================================================================
def demo_plain_python() -> None:
    """Show direct @enforce usage — no framework dependency."""
    banner("Plain Python (built-in)")

    from enforcecore import enforce
    from enforcecore.core.types import ToolDeniedError

    @enforce(policy=str(POLICY_PATH))
    def fetch_data(url: str) -> str:
        """Fetch data from a URL."""
        return f"Data from {url}"

    result = fetch_data("https://api.example.com/data")
    print("  Function:  fetch_data")
    print(f"  Result:    {result}")

    @enforce(policy=str(DENY_POLICY))
    def blocked_fn(x: str) -> str:
        return x

    try:
        blocked_fn("test")
    except ToolDeniedError as e:
        print(f"  Blocked:   ✓ ({e.violation_type})")

    print()


# ===================================================================
# 5. Shared utilities
# ===================================================================
def demo_shared_utilities() -> None:
    """Show require_package and wrap_with_policy."""
    banner("Shared Utilities")

    from enforcecore.core.policy import Policy
    from enforcecore.integrations import require_package, wrap_with_policy

    # require_package — check before using optional deps
    print("  require_package('os')    → ", end="")
    try:
        require_package("os")
        print("✓ (installed)")
    except ImportError:
        print("✗ (not installed)")

    print("  require_package('fake')  → ", end="")
    try:
        require_package("fake_package_xyz", pip_name="fake-package")
    except ImportError as e:
        print(f"✗ ({e})")

    # wrap_with_policy — build custom adapters
    policy = Policy.from_file(POLICY_PATH)

    def my_fn(x: int) -> int:
        return x * 2

    wrapped = wrap_with_policy(my_fn, policy=policy)
    print(f"\n  wrap_with_policy(my_fn)  → {wrapped(21)}")
    print()


# ===================================================================
# Main
# ===================================================================
def main() -> None:
    print(
        dedent("""
    ╔══════════════════════════════════════════════════════════╗
    ║  EnforceCore v1.0.4a1 — Framework Integration Examples  ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    )

    demo_plain_python()
    demo_langgraph()
    demo_crewai()
    demo_autogen()
    demo_shared_utilities()

    banner("Summary")
    print("  EnforceCore provides one-line enforcement for any framework.")
    print("  No hard dependencies — adapters use optional imports.")
    print("  Full policy enforcement: tool allow/deny, PII redaction,")
    print("  resource guards, cost tracking, and Merkle audit trails.")
    print()


if __name__ == "__main__":
    main()

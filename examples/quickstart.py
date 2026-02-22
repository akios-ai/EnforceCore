# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore Quickstart — see enforcement in action.

Run from the repo root:

    python examples/quickstart.py

This example demonstrates the two main ways to use EnforceCore:
1. @enforce() decorator (sync + async)
2. Enforcer class (direct invocation)
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from enforcecore import Enforcer, Policy, ToolDeniedError, enforce

# Resolve the example policy shipped in this repo
POLICY_PATH = str(Path(__file__).parent / "policies" / "strict.yaml")


# ---------------------------------------------------------------------------
# 1. @enforce decorator — the simplest API
# ---------------------------------------------------------------------------


@enforce(policy=POLICY_PATH, tool_name="search_web")
def search_web(query: str) -> str:
    """Simulate a web search — allowed by strict.yaml."""
    return f"Results for '{query}': [page1, page2, page3]"


@enforce(policy=POLICY_PATH, tool_name="execute_shell")
def execute_shell(cmd: str) -> str:
    """Simulate shell execution — denied by strict.yaml."""
    return f"$ {cmd}"


@enforce(policy=POLICY_PATH, tool_name="calculator")
async def async_calculator(expr: str) -> str:
    """Simulate an async calculator — allowed by strict.yaml."""
    await asyncio.sleep(0)
    return f"calc({expr}) = 42"


# ---------------------------------------------------------------------------
# 2. Enforcer class — for programmatic control
# ---------------------------------------------------------------------------


def demo_enforcer_class() -> None:
    policy = Policy.from_file(POLICY_PATH)
    enforcer = Enforcer(policy)

    # Allowed call
    result = enforcer.enforce_sync(
        lambda q: f"weather in {q}: 22°C",
        "Paris",
        tool_name="get_weather",
    )
    print(f"  Enforcer.enforce_sync → {result}")


# ---------------------------------------------------------------------------
# Run it
# ---------------------------------------------------------------------------


def main() -> None:
    print("=" * 60)
    print("  EnforceCore Quickstart")
    print("=" * 60)

    print("\n1. @enforce decorator — allowed call:")
    result = search_web("EnforceCore")
    print(f"   → {result}")

    print("\n2. @enforce decorator — blocked call:")
    try:
        execute_shell("rm -rf /")
    except ToolDeniedError as exc:
        print(f"   ✗ Blocked: {exc}")

    print("\n3. @enforce decorator — async call:")
    result = asyncio.run(async_calculator("1+1"))
    print(f"   → {result}")

    print("\n4. Enforcer class — direct invocation:")
    demo_enforcer_class()

    print("\n" + "=" * 60)
    print("  All examples completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()

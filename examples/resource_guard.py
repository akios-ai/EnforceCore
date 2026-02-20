#!/usr/bin/env python3
"""Resource Guard — EnforceCore v1.0.3 demo.

Demonstrates resource limits, cost tracking, KillSwitch, and how
the guard integrates with the enforcement pipeline.

Run::

    python examples/resource_guard.py
"""

from __future__ import annotations

import time

from enforcecore import (
    CostLimitError,
    CostTracker,
    Enforcer,
    KillSwitch,
    ResourceGuard,
    ResourceLimitError,
    enforce,
)
from enforcecore.core.policy import Policy

# ── Divider ──────────────────────────────────────────────────────────────

DIVIDER = "─" * 60


def section(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


# =========================================================================
# 1. CostTracker — standalone usage
# =========================================================================


def demo_cost_tracker() -> None:
    """Demonstrate thread-safe cumulative cost tracking."""
    section("1. CostTracker — standalone usage")

    tracker = CostTracker(budget_usd=5.00)
    print(f"\n  Budget:     ${tracker.budget:.2f}")
    print(f"  Total cost: ${tracker.total_cost:.2f}")

    # Record some costs
    tracker.record(1.50)
    print(f"\n  Recorded $1.50 → total: ${tracker.total_cost:.2f}")

    tracker.record(2.00)
    print(f"  Recorded $2.00 → total: ${tracker.total_cost:.2f}")

    # Still under budget — check passes
    tracker.check_budget("my_tool", "my_policy")
    print("  Budget check: ✓ (under budget)")

    # Go over budget
    tracker.record(2.00)
    print(f"  Recorded $2.00 → total: ${tracker.total_cost:.2f}")

    try:
        tracker.check_budget("my_tool", "my_policy")
    except CostLimitError as e:
        print(f"  Budget check: ✗ ({e})")


# =========================================================================
# 2. KillSwitch — hard termination
# =========================================================================


def demo_kill_switch() -> None:
    """Demonstrate the KillSwitch mechanism."""
    section("2. KillSwitch — hard termination")

    ks = KillSwitch()
    print(f"\n  Tripped: {ks.is_tripped}")

    # Check passes when not tripped
    ks.check("tool", "policy")
    print("  Check:   ✓ (not tripped)")

    # Trip the switch
    ks.trip("memory exceeded 256MB")
    print(f"\n  Tripped: {ks.is_tripped}")
    print(f"  Reason:  {ks.reason}")

    # Check fails when tripped
    try:
        ks.check("tool", "policy")
    except ResourceLimitError as e:
        print(f"  Check:   ✗ ({e})")

    # Reset
    ks.reset()
    ks.check("tool", "policy")
    print("\n  Reset:   ✓ (calls allowed again)")


# =========================================================================
# 3. ResourceGuard — standalone execution with limits
# =========================================================================


def demo_resource_guard() -> None:
    """Demonstrate ResourceGuard with time limits."""
    section("3. ResourceGuard — standalone execution")

    guard = ResourceGuard()

    # Fast function — passes
    result = guard.execute_sync(
        lambda x, y: x + y,
        (21, 21),
        {},
        max_duration_seconds=5.0,
        tool_name="calculator",
    )
    print(f"\n  calculator(21, 21) = {result} ✓")

    # Slow function — times out
    def slow_operation() -> str:
        time.sleep(10)
        return "done"

    try:
        guard.execute_sync(
            slow_operation,
            (),
            {},
            max_duration_seconds=0.2,
            tool_name="slow_op",
        )
    except ResourceLimitError as e:
        print(f"  slow_op(): ✗ ({e})")

    # Kill switch is now tripped
    print(f"\n  KillSwitch tripped: {guard.kill_switch.is_tripped}")
    print(f"  Reason: {guard.kill_switch.reason}")


# =========================================================================
# 4. Enforcer integration — policy-driven resource limits
# =========================================================================


def demo_enforcer_integration() -> None:
    """Demonstrate guard integration through the Enforcer pipeline."""
    section("4. Enforcer — policy-driven resource limits")

    # Create a policy with resource limits
    policy = Policy(
        name="resource-limited",
        rules={  # type: ignore[arg-type]
            "resource_limits": {
                "max_call_duration_seconds": 5.0,
                "max_cost_usd": 3.00,
            }
        },
    )
    enforcer = Enforcer(policy)

    # Fast call — passes
    result = enforcer.enforce_sync(
        lambda x: x.upper(),
        "hello world",
        tool_name="string_tool",
    )
    print(f"\n  string_tool('hello world') = '{result}' ✓")

    # Record costs
    total = enforcer.record_cost(1.50)
    print(f"  Recorded cost: $1.50 → total: ${total:.2f}")

    total = enforcer.record_cost(1.00)
    print(f"  Recorded cost: $1.00 → total: ${total:.2f}")

    # Still under budget — another call works
    result = enforcer.enforce_sync(lambda: 42, tool_name="the_answer")
    print(f"  the_answer() = {result} ✓")

    # Push over the $3.00 per-policy budget
    total = enforcer.record_cost(1.00)
    print(f"  Recorded cost: $1.00 → total: ${total:.2f}")

    try:
        enforcer.enforce_sync(lambda: "blocked", tool_name="over_budget")
    except CostLimitError as e:
        print(f"  over_budget(): ✗ Cost limit hit! ({e})")


# =========================================================================
# 5. @enforce() decorator with resource limits
# =========================================================================


def demo_decorator() -> None:
    """Demonstrate @enforce() decorator with resource-limited policy."""
    section("5. @enforce() — decorator with resource limits")

    policy = Policy(
        name="strict",
        rules={  # type: ignore[arg-type]
            "resource_limits": {
                "max_call_duration_seconds": 0.2,
            }
        },
    )

    @enforce(policy=policy)
    def fast_tool(n: int) -> int:
        return n * n

    result = fast_tool(7)
    print(f"\n  fast_tool(7) = {result} ✓")

    @enforce(policy=policy)
    def slow_tool() -> str:
        time.sleep(10)
        return "done"

    try:
        slow_tool()
    except ResourceLimitError as e:
        print(f"  slow_tool(): ✗ ({e})")


# =========================================================================
# 6. Platform information
# =========================================================================


def demo_platform_info() -> None:
    """Show what resource guards are available on this platform."""
    section("6. Platform support")

    info = ResourceGuard.platform_info()
    print(f"\n  Platform:       {info['platform']}")
    print(f"  Time limits:    {'✓' if info['time_limits'] else '✗'}")
    print(f"  Memory limits:  {'✓' if info['memory_limits'] else '✗'}")
    print(f"  Cost tracking:  {'✓' if info['cost_tracking'] else '✗'}")
    print(f"  KillSwitch:     {'✓' if info['kill_switch'] else '✗'}")
    print(f"  POSIX:          {'✓' if info['posix'] else '✗'}")


# =========================================================================
# Main
# =========================================================================


def main() -> None:
    print("=" * 60)
    print("  EnforceCore v1.0.3 — Resource Guard Demo")
    print("=" * 60)

    demo_cost_tracker()
    demo_kill_switch()
    demo_resource_guard()
    demo_enforcer_integration()
    demo_decorator()
    demo_platform_info()

    print(f"\n{DIVIDER}")
    print("  ✓ All demos complete!")
    print(DIVIDER)


if __name__ == "__main__":
    main()

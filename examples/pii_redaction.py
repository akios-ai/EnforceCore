#!/usr/bin/env python3
# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""PII Redaction — EnforceCore v1.0.1 demo.

Demonstrates automatic PII detection and redaction in the enforcement
pipeline.  Shows all supported PII categories, redaction strategies,
and both standalone and decorator usage patterns.

Run::

    python examples/pii_redaction.py
"""

from __future__ import annotations

from pathlib import Path

from enforcecore import Enforcer, enforce
from enforcecore.core.policy import Policy
from enforcecore.core.types import RedactionStrategy
from enforcecore.redactor.engine import Redactor

POLICY_PATH = Path(__file__).parent / "policies" / "pii_demo.yaml"

# ── Divider ──────────────────────────────────────────────────────────────

DIVIDER = "─" * 60


def section(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


# =========================================================================
# 1. Standalone Redactor — direct usage
# =========================================================================


def demo_standalone_redactor() -> None:
    """Use the Redactor class directly, outside of the Enforcer."""
    section("1. Standalone Redactor")

    text = (
        "Patient John Doe, email john.doe@hospital.com, SSN 123-45-6789, "
        "card 4111-1111-1111-1111, phone (555) 867-5309, server 10.0.0.42"
    )
    print(f"\nOriginal:\n  {text}\n")

    for strategy in RedactionStrategy:
        r = Redactor(strategy=strategy)
        result = r.redact(text)
        print(f"  [{strategy.value:>11}]  {result.text}")
        print(f"               → {result.count} entities redacted\n")


# =========================================================================
# 2. Detection only (no redaction)
# =========================================================================


def demo_detection_only() -> None:
    """Use detect() to find PII without modifying the text."""
    section("2. Detection Only")

    r = Redactor()
    text = "Contact support@acme.com or call 1-800-555-0199"
    entities = r.detect(text)

    print(f"\n  Text: {text}\n")
    for e in sorted(entities, key=lambda x: x.start):
        print(f"  • [{e.category:>12}] chars {e.start}-{e.end}: {e.text!r}")


# =========================================================================
# 3. Selective categories
# =========================================================================


def demo_selective_categories() -> None:
    """Redact only specific PII categories."""
    section("3. Selective Categories (email only)")

    r = Redactor(categories=["email"])
    text = "Email admin@corp.io, SSN 234-56-7890, phone 555-111-2222"
    result = r.redact(text)

    print(f"\n  Before: {text}")
    print(f"  After:  {result.text}")
    print("  → Only email redacted; SSN and phone left intact")


# =========================================================================
# 4. Enforcer pipeline integration
# =========================================================================


def demo_enforcer_pipeline() -> None:
    """PII is redacted automatically in the Enforcer pipeline."""
    section("4. Enforcer Pipeline (auto-redaction)")

    policy = Policy.from_file(POLICY_PATH)
    enforcer = Enforcer(policy)

    # Simulated tool that receives user input and returns a response
    def customer_lookup(query: str) -> str:
        # In production this would hit a database.
        # The enforcer redacts PII *before* the call and *after*.
        return f"Found record for {query}: SSN 321-54-9876, IP 192.168.1.50"

    result = enforcer.enforce_sync(
        customer_lookup,
        "john@example.com",
        tool_name="customer_lookup",
    )

    print("\n  Input was: 'john@example.com'")
    print(f"  Output:    {result}")
    print("  → Email in input AND SSN/IP in output were both redacted")


# =========================================================================
# 5. Decorator usage
# =========================================================================


def demo_decorator() -> None:
    """Use @enforce decorator with PII redaction enabled."""
    section("5. @enforce Decorator")

    @enforce(policy=POLICY_PATH)
    def send_notification(message: str) -> str:
        return f"Sent: {message}"

    result = send_notification("Alert for user admin@internal.net from 10.0.0.1")

    print(f"\n  Result: {result}")
    print("  → PII in the input was redacted before the function ran")


# =========================================================================
# Main
# =========================================================================


if __name__ == "__main__":
    print("\n🛡️  EnforceCore v1.0.1 — PII Redaction Demo")
    print("=" * 60)

    demo_standalone_redactor()
    demo_detection_only()
    demo_selective_categories()
    demo_enforcer_pipeline()
    demo_decorator()

    section("Done")
    print("  All demos completed successfully ✅\n")

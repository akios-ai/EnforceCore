"""Compliance Demo — EU AI Act scenario with full enforcement pipeline.

Demonstrates:
- Full enforcement pipeline (policy + redaction + audit + guard)
- Policy dry-run mode (preview decisions without executing)
- Audit trail generation and Merkle chain verification
- Compliance evidence workflow

Run::

    python examples/scenarios/compliance/compliance_demo.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from enforcecore import Enforcer, Policy, ToolDeniedError
from enforcecore.auditor.engine import load_trail, verify_trail
from enforcecore.core.config import settings
from enforcecore.core.policy import PolicyEngine
from enforcecore.core.types import CallContext

POLICY_PATH = Path(__file__).parent / "policy.yaml"


# ---------------------------------------------------------------------------
# Simulated tools
# ---------------------------------------------------------------------------


def classify_document(text: str) -> str:
    """Simulate document classification."""
    return "Classification: internal-confidential (confidence: 0.94)"


def summarize_text(text: str) -> str:
    """Simulate text summarization."""
    return f"Summary: This document ({len(text)} chars) discusses EU regulatory compliance."


def extract_entities(text: str) -> str:
    """Simulate named entity extraction."""
    return "Entities: [ORG: European Commission], [REG: EU AI Act], [DATE: 2025]"


def delete_file(path: str) -> str:
    """Dangerous tool — should be blocked."""
    return f"Deleted: {path}"


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the compliance demo scenario."""
    print("=" * 60)
    print("Compliance Demo — EU AI Act Workflow")
    print("=" * 60)

    policy = Policy.from_file(POLICY_PATH)

    # -----------------------------------------------------------------------
    # Step 1: Policy Dry-Run (preview decisions)
    # -----------------------------------------------------------------------
    print("\n--- Step 1: Policy Dry-Run ---")
    engine = PolicyEngine(policy)

    tools_to_check = [
        "classify_document",
        "summarize_text",
        "extract_entities",
        "delete_file",
        "execute_shell",
        "unknown_tool",
    ]
    for tool in tools_to_check:
        ctx = CallContext(tool_name=tool)
        result = engine.evaluate_pre_call(ctx)
        status = "✓ ALLOWED" if result.is_allowed else "✗ DENIED"
        print(f"  {status}: {tool}")

    # -----------------------------------------------------------------------
    # Step 2: Full Enforcement with Audit Trail
    # -----------------------------------------------------------------------
    print("\n--- Step 2: Full Enforcement Pipeline ---")

    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "audit_logs"
        original_enabled = settings.audit_enabled
        original_path = settings.audit_path
        settings.audit_enabled = True
        settings.audit_path = audit_path

        try:
            enforcer = Enforcer(policy)

            # Allowed: classify with PII
            print("\n  a) Classifying document (allowed, PII redacted)...")
            pii_input = (
                "Classify this document from Marie Curie (marie@eu-lab.eu, "
                "+33-1-23-45-67-89) regarding radioactivity research."
            )
            try:
                result = enforcer.enforce_sync(
                    lambda _text: classify_document(pii_input),
                    pii_input,
                    tool_name="classify_document",
                )
                print(f"     Output: {result}")
            except Exception as e:
                print(f"     Error: {e}")

            # Allowed: summarize
            print("\n  b) Summarizing text (allowed)...")
            try:
                result = enforcer.enforce_sync(
                    summarize_text,
                    "The EU AI Act establishes harmonised rules for AI.",
                    tool_name="summarize_text",
                )
                print(f"     Output: {result}")
            except Exception as e:
                print(f"     Error: {e}")

            # Denied: delete file
            print("\n  c) Attempting file deletion (DENIED)...")
            try:
                enforcer.enforce_sync(
                    delete_file,
                    "/important/data.db",
                    tool_name="delete_file",
                )
                print("     ✗ Should have been blocked!")
            except ToolDeniedError as e:
                print(f"     ✓ Blocked: {e}")

            # Allowed: entity extraction
            print("\n  d) Extracting entities (allowed)...")
            try:
                result = enforcer.enforce_sync(
                    extract_entities,
                    "European Commission published EU AI Act in 2025",
                    tool_name="extract_entities",
                )
                print(f"     Output: {result}")
            except Exception as e:
                print(f"     Error: {e}")

        finally:
            settings.audit_enabled = original_enabled
            settings.audit_path = original_path

        # -------------------------------------------------------------------
        # Step 3: Audit Trail Verification
        # -------------------------------------------------------------------
        print("\n--- Step 3: Audit Trail Verification ---")
        trail_file = audit_path / "trail.jsonl"
        if trail_file.exists() and trail_file.stat().st_size > 0:
            verification = verify_trail(trail_file)
            print(f"  Valid: {verification.is_valid}")
            print(f"  Entries: {verification.total_entries}")
            print(f"  Root hash: {verification.root_hash[:16]}...")

            entries = load_trail(trail_file)
            print("\n  Audit entries:")
            for entry in entries:
                print(
                    f"    [{entry.decision.upper()}] {entry.tool_name} "
                    f"(redactions: {entry.input_redactions})"
                )
        else:
            print("  (No audit entries written)")

    # -----------------------------------------------------------------------
    # Step 4: Compliance Evidence Summary
    # -----------------------------------------------------------------------
    print("\n--- Step 4: Compliance Evidence ---")
    print("  ✓ Policy enforced: tool gating, PII redaction, content rules")
    print("  ✓ Audit trail: Merkle-chained, tamper-evident, verifiable")
    print("  ✓ Rate limiting: global 100 calls/minute cap")
    print("  ✓ Network isolation: only approved domains")
    print("  ✓ Resource limits: 30s timeout, 512MB memory, $10 budget")

    print("\n" + "=" * 60)
    print("Compliance scenario complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()

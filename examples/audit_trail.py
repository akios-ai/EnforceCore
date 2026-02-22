#!/usr/bin/env python3
# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Merkle-chained Audit Trail — EnforceCore v1.0.2 demo.

Demonstrates the cryptographic audit trail that records every
enforcement decision.  Shows standalone Auditor usage, automatic
audit recording via the Enforcer pipeline, trail verification,
tamper detection, and cross-session chain continuity.

Run::

    python examples/audit_trail.py
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from enforcecore import (
    AuditEntry,
    Auditor,
    Enforcer,
    VerificationResult,
    enforce,
    load_trail,
    verify_trail,
)
from enforcecore.core.config import settings
from enforcecore.core.policy import Policy
from enforcecore.core.types import EnforcementViolation

POLICY_PATH = Path(__file__).parent / "policies" / "default.yaml"

# ── Divider ──────────────────────────────────────────────────────────────

DIVIDER = "─" * 60


def section(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


# =========================================================================
# 1. Standalone Auditor — direct usage
# =========================================================================


def demo_standalone_auditor(work_dir: Path) -> Path:
    """Use the Auditor class directly to build an audit trail."""
    section("1. Standalone Auditor")

    trail_file = work_dir / "standalone.jsonl"
    auditor = Auditor(output_path=trail_file)

    # Record a few entries
    e1 = auditor.record(
        tool_name="search_web",
        policy_name="default",
        policy_version="1.0",
        decision="allowed",
    )
    print(f"\n  Entry 1: {e1.tool_name}")
    print(f"    Hash:          {e1.entry_hash[:24]}…")
    print("    Previous hash: (genesis — no previous)")

    e2 = auditor.record(
        tool_name="execute_shell",
        policy_name="default",
        policy_version="1.0",
        decision="blocked",
        violation_type="ToolDeniedError",
        violation_reason="Tool not in allowed_tools list",
    )
    print(f"\n  Entry 2: {e2.tool_name}")
    print(f"    Hash:          {e2.entry_hash[:24]}…")
    print(f"    Previous hash: {e2.previous_hash[:24]}…")
    print(f"    Chain linked:  {e2.previous_hash == e1.entry_hash} ✓")

    e3 = auditor.record(
        tool_name="calculator",
        policy_name="default",
        policy_version="1.0",
        decision="allowed",
        overhead_ms=1.23,
        call_duration_ms=45.6,
    )
    print(f"\n  Entry 3: {e3.tool_name}")
    print(f"    Hash:          {e3.entry_hash[:24]}…")
    print(f"    Chain linked:  {e3.previous_hash == e2.entry_hash} ✓")

    print(f"\n  Total entries: {auditor.entry_count}")
    print(f"  Trail file:    {trail_file}")

    return trail_file


# =========================================================================
# 2. Audit entry anatomy
# =========================================================================


def demo_entry_anatomy() -> None:
    """Show the full structure of an AuditEntry."""
    section("2. AuditEntry Anatomy")

    entry = AuditEntry(
        tool_name="get_weather",
        policy_name="strict",
        policy_version="2.1",
        decision="allowed",
        overhead_ms=2.5,
        call_duration_ms=120.0,
        input_redactions=1,
        output_redactions=3,
    )
    entry.seal()

    print(f"\n  entry_id:          {entry.entry_id}")
    print(f"  call_id:           {entry.call_id}")
    print(f"  timestamp:         {entry.timestamp}")
    print(f"  tool_name:         {entry.tool_name}")
    print(f"  policy_name:       {entry.policy_name}")
    print(f"  policy_version:    {entry.policy_version}")
    print(f"  decision:          {entry.decision}")
    print(f"  violation_type:    {entry.violation_type}")
    print(f"  violation_reason:  {entry.violation_reason}")
    print(f"  overhead_ms:       {entry.overhead_ms}")
    print(f"  call_duration_ms:  {entry.call_duration_ms}")
    print(f"  input_redactions:  {entry.input_redactions}")
    print(f"  output_redactions: {entry.output_redactions}")
    print(f"  previous_hash:     {entry.previous_hash!r}")
    print(f"  entry_hash:        {entry.entry_hash[:32]}…")

    print("\n  JSON (first 120 chars):")
    print(f"    {entry.to_json()[:120]}…")


# =========================================================================
# 3. Trail verification
# =========================================================================


def demo_verification(trail_file: Path) -> None:
    """Verify an audit trail for integrity."""
    section("3. Trail Verification")

    result: VerificationResult = verify_trail(trail_file)

    print(f"\n  File:            {trail_file}")
    print(f"  Valid:           {result.is_valid} ✓")
    print(f"  Total entries:   {result.total_entries}")
    print(f"  Chain intact:    {result.chain_intact}")
    print(f"  Root hash:       {result.root_hash[:24]}…")
    print(f"  Head hash:       {result.head_hash[:24]}…")
    print(f"  Errors:          {result.error_count}")


# =========================================================================
# 4. Tamper detection
# =========================================================================


def demo_tamper_detection(work_dir: Path) -> None:
    """Demonstrate that tampering with the trail is detected."""
    section("4. Tamper Detection")

    trail_file = work_dir / "tamper_test.jsonl"
    auditor = Auditor(output_path=trail_file)

    # Build a 5-entry chain
    for i in range(5):
        auditor.record(tool_name=f"tool_{i}", policy_name="default")

    # Verify — should be valid
    result = verify_trail(trail_file)
    print(f"\n  Before tampering: valid={result.is_valid} ✓")

    # Now tamper with entry 3 — change its decision
    lines = trail_file.read_text().strip().split("\n")
    entry = json.loads(lines[2])
    entry["decision"] = "HACKED"
    lines[2] = json.dumps(entry)
    trail_file.write_text("\n".join(lines) + "\n")

    # Verify again — should detect the tamper
    result = verify_trail(trail_file)
    print(f"  After tampering:  valid={result.is_valid} ✗")
    print(f"  Errors detected:  {result.error_count}")
    for err in result.errors:
        print(f"    → {err}")


# =========================================================================
# 5. Enforcer pipeline — automatic audit recording
# =========================================================================


def demo_enforcer_pipeline(work_dir: Path) -> None:
    """Audit entries are recorded automatically by the Enforcer."""
    section("5. Enforcer Pipeline (automatic audit)")

    audit_dir = work_dir / "pipeline_audit"

    # Configure audit to use our temp directory
    settings.audit_enabled = True
    settings.audit_path = audit_dir

    policy = Policy.from_file(POLICY_PATH)
    enforcer = Enforcer(policy)

    # --- Allowed call ---
    def search_web(query: str) -> str:
        return f"Results for '{query}'"

    result = enforcer.enforce_sync(search_web, "python merkle trees", tool_name="search_web")
    print(f"\n  Allowed call result: {result}")

    # --- Blocked call ---
    def delete_file(path: str) -> str:
        return f"Deleted {path}"

    try:
        enforcer.enforce_sync(delete_file, "/etc/passwd", tool_name="delete_file")
    except EnforcementViolation as exc:
        print(f"  Blocked call:        {exc.__class__.__name__}: {exc}")

    # --- Another allowed call ---
    result2 = enforcer.enforce_sync(
        lambda q: "2 + 2 = 4",
        "2+2",
        tool_name="calculator",
    )
    print(f"  Allowed call result: {result2}")

    # Verify the trail
    trail_file = audit_dir / "trail.jsonl"
    trail = load_trail(trail_file)

    print(f"\n  Trail entries: {len(trail)}")
    for entry in trail:
        status = "✓" if entry.decision == "allowed" else "✗"
        print(f"    {status} {entry.tool_name:20s} → {entry.decision}")

    verification = verify_trail(trail_file)
    print(f"\n  Trail verified: {verification.is_valid} ✓")
    print(f"  Chain intact:   {verification.chain_intact} ✓")


# =========================================================================
# 6. Cross-session chain continuity
# =========================================================================


def demo_cross_session(work_dir: Path) -> None:
    """The Merkle chain survives across process restarts."""
    section("6. Cross-Session Chain Continuity")

    trail_file = work_dir / "sessions.jsonl"

    # --- Session 1 ---
    a1 = Auditor(output_path=trail_file)
    a1.record(tool_name="session1_tool_a", policy_name="default")
    a1.record(tool_name="session1_tool_b", policy_name="default")
    print(f"\n  Session 1: wrote {a1.entry_count} entries")
    print(f"    Head hash: {a1.last_hash[:24]}…")

    # --- Session 2 (simulates a new process) ---
    a2 = Auditor(output_path=trail_file)
    print(f"\n  Session 2: resumed with {a2.entry_count} existing entries")
    a2.record(tool_name="session2_tool_c", policy_name="default")
    a2.record(tool_name="session2_tool_d", policy_name="default")
    print(f"    Wrote 2 more → total {a2.entry_count} entries")
    print(f"    Head hash: {a2.last_hash[:24]}…")

    # --- Session 3 ---
    a3 = Auditor(output_path=trail_file)
    a3.record(tool_name="session3_tool_e", policy_name="default")
    print(f"\n  Session 3: resumed with {a3.entry_count - 1} existing entries")
    print(f"    Wrote 1 more → total {a3.entry_count} entries")
    print(f"    Head hash: {a3.last_hash[:24]}…")

    # Verify entire chain across all 3 sessions
    result = verify_trail(trail_file)
    print(f"\n  Cross-session verification: valid={result.is_valid} ✓")
    print(f"  Total entries across 3 sessions: {result.total_entries}")
    print(f"  Chain fully intact: {result.chain_intact} ✓")


# =========================================================================
# 7. @enforce decorator with audit
# =========================================================================


def demo_decorator_audit(work_dir: Path) -> None:
    """The @enforce decorator records audit entries automatically."""
    section("7. @enforce Decorator with Audit")

    audit_dir = work_dir / "decorator_audit"
    settings.audit_enabled = True
    settings.audit_path = audit_dir

    @enforce(policy=POLICY_PATH, tool_name="read_file")
    def read_file(path: str) -> str:
        return f"Contents of {path}"

    result = read_file("/tmp/readme.txt")
    print(f"\n  Decorator result: {result}")

    trail_file = audit_dir / "trail.jsonl"
    if trail_file.exists():
        trail = load_trail(trail_file)
        print(f"  Audit entries:    {len(trail)}")
        for entry in trail:
            print(f"    ✓ {entry.tool_name} → {entry.decision}")

        verification = verify_trail(trail_file)
        print(f"  Trail verified:   {verification.is_valid} ✓")


# =========================================================================
# Main
# =========================================================================


def main() -> None:
    print("\n🛡️  EnforceCore v1.0.2 — Merkle-Chained Audit Trail Demo")
    print("=" * 60)

    with tempfile.TemporaryDirectory(prefix="enforcecore_audit_") as tmp:
        work_dir = Path(tmp)

        trail_file = demo_standalone_auditor(work_dir)
        demo_entry_anatomy()
        demo_verification(trail_file)
        demo_tamper_detection(work_dir)
        demo_enforcer_pipeline(work_dir)
        demo_cross_session(work_dir)
        demo_decorator_audit(work_dir)

    section("Done")
    print("  All demos completed successfully ✅")
    print("  (temp files cleaned up automatically)\n")


if __name__ == "__main__":
    main()

"""Healthcare Agent — HIPAA-style PII protection for a medical Q&A agent.

Demonstrates:
- PII redaction (patient names, emails, phones, SSNs)
- Tool gating (only approved medical APIs)
- Audit trail generation and verification
- Content rule enforcement

Run::

    python examples/scenarios/healthcare/healthcare_agent.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from enforcecore import Enforcer, Policy, ToolDeniedError
from enforcecore.auditor.engine import load_trail, verify_trail
from enforcecore.core.config import settings

POLICY_PATH = Path(__file__).parent / "policy.yaml"


# ---------------------------------------------------------------------------
# Simulated medical tools
# ---------------------------------------------------------------------------


def lookup_drug_interactions(drug_a: str, drug_b: str) -> str:
    """Simulate a drug interaction database lookup."""
    return (
        f"Drug interaction report for {drug_a} + {drug_b}: "
        "Moderate interaction — monitor INR levels. "
        "Patient should avoid concurrent use without supervision."
    )


def query_symptoms_db(symptoms: str) -> str:
    """Simulate a symptom checker database query."""
    return (
        f"Symptom analysis for '{symptoms}': "
        "Possible conditions: tension headache (72%), migraine (18%), "
        "cluster headache (10%). Recommend clinical evaluation."
    )


def schedule_appointment(patient_info: str, department: str) -> str:
    """Simulate appointment scheduling."""
    return f"Appointment scheduled in {department} for next available slot."


def execute_shell(cmd: str) -> str:
    """Dangerous tool — should be blocked by policy."""
    return f"$ {cmd}"


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the healthcare agent scenario."""
    print("=" * 60)
    print("Healthcare Agent — HIPAA-Style Enforcement")
    print("=" * 60)

    policy = Policy.from_file(POLICY_PATH)

    # Enable audit for this demo
    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "audit_logs"
        original_enabled = settings.audit_enabled
        original_path = settings.audit_path
        settings.audit_enabled = True
        settings.audit_path = audit_path

        try:
            enforcer = Enforcer(policy)

            # --- Allowed tool: drug interactions (PII in input) ---
            print("\n1. Looking up drug interactions (allowed)...")
            pii_input = (
                "Check interactions for patient John Smith "
                "(john.smith@hospital.org, SSN 123-45-6789) "
                "taking Warfarin and Aspirin"
            )
            try:
                # The args are redacted; the lambda receives the redacted text
                result = enforcer.enforce_sync(
                    lambda _text: lookup_drug_interactions("Warfarin", "Aspirin"),
                    pii_input,
                    tool_name="lookup_drug_interactions",
                )
                print(f"   Result: {result}")
            except Exception as e:
                print(f"   Error: {e}")

            # --- Allowed tool: symptom check with PII in args ---
            print("\n2. Querying symptoms DB (allowed, PII in input)...")
            pii_input = (
                "Patient Jane Doe (jane@example.com, 555-867-5309) "
                "reports: persistent headache, nausea, photophobia"
            )
            try:
                result = enforcer.enforce_sync(
                    lambda _text: query_symptoms_db("headache, nausea, photophobia"),
                    pii_input,
                    tool_name="query_symptoms_db",
                )
                print(f"   Result: {result}")
            except Exception as e:
                print(f"   Error: {e}")

            # --- Denied tool: shell execution ---
            print("\n3. Attempting shell execution (DENIED by policy)...")
            try:
                enforcer.enforce_sync(
                    execute_shell,
                    "rm -rf /",
                    tool_name="execute_shell",
                )
                print("   ✗ Should have been blocked!")
            except ToolDeniedError as e:
                print(f"   ✓ Blocked: {e}")

            # --- Denied tool: unknown tool ---
            print("\n4. Attempting unlisted tool (DENIED — not in allowlist)...")
            try:
                enforcer.enforce_sync(
                    lambda: "sent!",
                    tool_name="send_patient_data_external",
                )
                print("   ✗ Should have been blocked!")
            except ToolDeniedError as e:
                print(f"   ✓ Blocked: {e}")

        finally:
            settings.audit_enabled = original_enabled
            settings.audit_path = original_path

        # --- Audit trail verification ---
        print("\n5. Verifying audit trail integrity...")
        trail_file = audit_path / "trail.jsonl"
        if trail_file.exists() and trail_file.stat().st_size > 0:
            verification = verify_trail(trail_file)
            print(f"   Valid: {verification.is_valid}")
            print(f"   Entries: {verification.total_entries}")
            entries = load_trail(trail_file)
            for entry in entries:
                print(
                    f"   [{entry.decision.upper()}] {entry.tool_name} "
                    f"(redactions: {entry.input_redactions})"
                )
        else:
            print("   (No audit entries written)")

    print("\n" + "=" * 60)
    print("Healthcare scenario complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()

# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Code Agent — Sandboxed code execution assistant.

Demonstrates:
- Content rules blocking dangerous patterns (os.system, subprocess, eval)
- Network enforcement (deny all external domains)
- Resource guards (5s time limit, 64MB memory)
- Tool gating (only safe code tools allowed)
- PII protection in code snippets

Run::

    python examples/scenarios/code_agent/code_agent.py
"""

from __future__ import annotations

from pathlib import Path

from enforcecore import (
    ContentViolationError,
    Enforcer,
    Policy,
    ToolDeniedError,
)

POLICY_PATH = Path(__file__).parent / "policy.yaml"


# ---------------------------------------------------------------------------
# Simulated code tools
# ---------------------------------------------------------------------------


def run_python_sandbox(code: str) -> str:
    """Simulate sandboxed Python execution (not real eval)."""
    return f"Sandbox output: Code executed successfully ({len(code)} chars)"


def explain_code(code: str) -> str:
    """Simulate code explanation."""
    return (
        f"This code ({len(code)} chars) appears to define a function. "
        "It uses standard library utilities for data processing."
    )


def format_code(code: str) -> str:
    """Simulate code formatting."""
    return f"# Formatted\n{code.strip()}"


def execute_shell(cmd: str) -> str:
    """Dangerous tool — should be blocked."""
    return f"$ {cmd}"


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the code agent scenario."""
    print("=" * 60)
    print("Code Agent — Sandboxed Execution")
    print("=" * 60)

    policy = Policy.from_file(POLICY_PATH)
    enforcer = Enforcer(policy)

    # --- Allowed: safe code execution ---
    print("\n1. Running safe code in sandbox (allowed)...")
    safe_code = (
        "def fibonacci(n):\n"
        "    a, b = 0, 1\n"
        "    for _ in range(n):\n"
        "        a, b = b, a+b\n"
        "    return a"
    )
    try:
        result = enforcer.enforce_sync(
            run_python_sandbox,
            safe_code,
            tool_name="run_python_sandbox",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # --- Allowed: code explanation ---
    print("\n2. Explaining code (allowed)...")
    try:
        result = enforcer.enforce_sync(
            explain_code,
            safe_code,
            tool_name="explain_code",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # --- Blocked: content rule violation (os.system) ---
    print("\n3. Code with os.system() (BLOCKED by content rules)...")
    malicious_code = "import os\nos.system('rm -rf /')"
    try:
        enforcer.enforce_sync(
            run_python_sandbox,
            malicious_code,
            tool_name="run_python_sandbox",
        )
        print("   ✗ Should have been blocked!")
    except ContentViolationError as e:
        print(f"   ✓ Blocked by content rule: {e}")
    except Exception as e:
        print(f"   ✓ Blocked: {e}")

    # --- Blocked: content rule violation (subprocess) ---
    print("\n4. Code with subprocess.run() (BLOCKED)...")
    subprocess_code = "import subprocess\nsubprocess.run(['ls', '-la'])"
    try:
        enforcer.enforce_sync(
            run_python_sandbox,
            subprocess_code,
            tool_name="run_python_sandbox",
        )
        print("   ✗ Should have been blocked!")
    except ContentViolationError as e:
        print(f"   ✓ Blocked by content rule: {e}")
    except Exception as e:
        print(f"   ✓ Blocked: {e}")

    # --- Blocked: shell tool denied ---
    print("\n5. Attempting shell execution (DENIED by tool gating)...")
    try:
        enforcer.enforce_sync(
            execute_shell,
            "whoami",
            tool_name="execute_shell",
        )
        print("   ✗ Should have been blocked!")
    except ToolDeniedError as e:
        print(f"   ✓ Blocked: {e}")

    # --- PII in code snippet ---
    print("\n6. Code containing PII (redacted)...")
    pii_code = "user_email = 'patient@hospital.com'\nuser_phone = '555-123-4567'"
    try:
        result = enforcer.enforce_sync(
            explain_code,
            pii_code,
            tool_name="explain_code",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n" + "=" * 60)
    print("Code agent scenario complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()

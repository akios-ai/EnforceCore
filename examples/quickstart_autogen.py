# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore x AutoGen — Copy-paste quickstart.

Demonstrates EnforceCore policy enforcement integrated into an AutoGen v0.4+
agent's tool-calling pipeline. Uses mock agents (no API key required).

Install prerequisites:
    pip install autogen-core          # AutoGen v0.4+
    # or
    pip install pyautogen             # AutoGen v0.2 (legacy)

Run from the repo root:
    python examples/quickstart_autogen.py
"""

from __future__ import annotations

from enforcecore import Enforcer
from enforcecore.core.policy import PIIRedactionConfig, Policy, PolicyRules
from enforcecore.core.types import RedactionStrategy, ToolDeniedError

# ---------------------------------------------------------------------------
# 1. Policy — per-agent scoping example
#    Agent A can search + summarise; Agent B can read local files only.
# ---------------------------------------------------------------------------

AGENT_A_POLICY = Policy(
    name="autogen-agent-a",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["search_web", "summarise", "translate"],
        denied_tools=["execute_shell", "delete_file", "write_to_db", "send_email"],
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            categories=["email", "phone", "ssn", "passport"],
            strategy=RedactionStrategy.PLACEHOLDER,
        ),
        max_output_size_bytes=100_000,
        max_cost_usd=5.0,
        max_call_duration_ms=10_000,
    ),
)

AGENT_B_POLICY = Policy(
    name="autogen-agent-b",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["read_file", "list_dir"],
        denied_tools=["write_file", "delete_file", "execute_shell", "http_request"],
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            categories=["ssn", "credit_card"],
            strategy=RedactionStrategy.MASK,
        ),
        max_output_size_bytes=1_000_000,
        max_cost_usd=1.0,
        max_call_duration_ms=2_000,
    ),
)

enforcer_a = Enforcer(AGENT_A_POLICY)
enforcer_b = Enforcer(AGENT_B_POLICY)


# ---------------------------------------------------------------------------
# 2. Tool implementations using enforce_sync
#    Each raw function contains the actual logic.
#    The enforced wrapper applies pre-call checks + output PII redaction.
# ---------------------------------------------------------------------------


# Agent A tools
def _raw_search(query: str) -> str:
    return f"Search results for '{query}': [doc1, doc2, doc3]"


def _raw_send_email(recipient: str, body: str) -> str:
    return f"Sent to {recipient}: {body}"  # unreachable — blocked


# Agent B tools
def _raw_read_file(path: str) -> str:
    return f"Contents of {path}: [line1 ssn 123-45-6789, line2 cc 4111-1111-1111-1111]"


def _raw_write_file(path: str, content: str) -> str:
    return f"Written to {path}"  # unreachable — blocked


def _raw_http_request(url: str) -> str:
    return f"Response from {url}"  # unreachable — blocked


# Enforced wrappers
def agent_a_search(query: str) -> str:
    return enforcer_a.enforce_sync(_raw_search, query, tool_name="search_web")


def agent_a_send_email(recipient: str, body: str) -> str:
    return enforcer_a.enforce_sync(_raw_send_email, recipient, body, tool_name="send_email")


def agent_b_read_file(path: str) -> str:
    return enforcer_b.enforce_sync(_raw_read_file, path, tool_name="read_file")


def agent_b_write_file(path: str, content: str) -> str:
    return enforcer_b.enforce_sync(_raw_write_file, path, content, tool_name="write_file")


def agent_b_http_request(url: str) -> str:
    return enforcer_b.enforce_sync(_raw_http_request, url, tool_name="http_request")


# ---------------------------------------------------------------------------
# 3. Simulate a two-agent AutoGen conversation with tool calls
# ---------------------------------------------------------------------------

MOCK_CONVERSATION = [
    # (agent, fn, args, step_desc)
    ("Agent A", agent_a_search, {"query": "AI safety enforcement"}, "A searches for context"),
    (
        "Agent A",
        agent_a_send_email,
        {"recipient": "boss@corp.com", "body": "update"},
        "A tries to email (denied)",
    ),
    ("Agent B", agent_b_read_file, {"path": "/data/users.csv"}, "B reads file (PII masked)"),
    (
        "Agent B",
        agent_b_write_file,
        {"path": "/data/users.csv", "content": "hacked"},
        "B tries to write (denied)",
    ),
    (
        "Agent B",
        agent_b_http_request,
        {"url": "https://evil.example.com/exfil"},
        "B tries HTTP (denied)",
    ),
]


def run() -> None:
    print("=" * 64)
    print("  EnforceCore x AutoGen Quickstart")
    print("  Agents  : Agent A (search) + Agent B (file ops)")
    print("  Pattern : Per-agent policy scoping")
    print("=" * 64)

    for agent, fn, args, step_desc in MOCK_CONVERSATION:
        print(f"\n── {agent}: {step_desc}")
        print(f"   Call: {fn.__name__}({args})")
        try:
            result = fn(**args)
            print(f"   Result: ✓  {result}")
        except ToolDeniedError as exc:
            print(f"   Result: ✗  BLOCKED — {exc}")

    # Per-agent audit summary
    for label, enforcer in [("Agent A", enforcer_a), ("Agent B", enforcer_b)]:
        count = enforcer._auditor.entry_count
        print(f"\n── {label} audit: {count} total chain entries")

    print()
    print("AutoGen v0.4 integration pattern:")
    print("  from enforcecore.integrations.autogen import enforced_tool")
    print()
    print("  @enforced_tool(policy='agent_a_policy.yaml')")
    print("  def search_web(query: str) -> str:")
    print('      """Search the web."""')
    print("      return web_search(query)")
    print()
    print("  agent = AssistantAgent('researcher', tools=[search_web])")


if __name__ == "__main__":
    run()

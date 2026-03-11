# Copyright 2025-2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore x LangChain — Copy-paste quickstart.

Demonstrates the ``EnforceCoreCallbackHandler`` — a drop-in LangChain
callback that adds PII redaction, policy enforcement, and Merkle-chained
audit to every LLM call automatically.

No API key needed — uses mock data to show the handler in action.

Install prerequisites:
    pip install langchain-core

Run from the repo root:
    python examples/quickstart_langchain.py
"""

from __future__ import annotations

from enforcecore.core.policy import PIIRedactionConfig, Policy, PolicyRules
from enforcecore.core.types import RedactionStrategy, ToolDeniedError
from enforcecore.redactor.engine import Redactor

# ---------------------------------------------------------------------------
# 1. Define a strict policy
# ---------------------------------------------------------------------------

policy = Policy(
    name="langchain-demo",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["search_web", "calculate", "get_weather"],
        denied_tools=["execute_shell", "delete_file", "write_to_db"],
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            categories=["email", "phone", "ssn", "credit_card"],
            strategy=RedactionStrategy.PLACEHOLDER,
        ),
    ),
)


# ---------------------------------------------------------------------------
# 2. Simulate the callback handler WITHOUT langchain-core installed
#    (Uses the same Redactor + PolicyEngine that the real handler uses)
# ---------------------------------------------------------------------------


def run_demo() -> None:
    """Demonstrate what the EnforceCoreCallbackHandler does internally."""
    from enforcecore.core.policy import PolicyEngine
    from enforcecore.core.types import CallContext

    engine = PolicyEngine(policy)
    redactor = Redactor(
        categories=["email", "phone", "ssn", "credit_card"],
        strategy=RedactionStrategy.PLACEHOLDER,
    )

    print("=" * 64)
    print("  EnforceCore x LangChain Quickstart")
    print("  Policy : langchain-demo v1.0.0")
    print("  Handler: EnforceCoreCallbackHandler")
    print("=" * 64)

    # -- on_llm_start: PII redaction in prompts --
    print("\n── 1. on_llm_start — PII redaction in prompts")
    prompts = [
        "Summarise the profile for alice@example.com",
        "Look up SSN 123-45-6789 and phone 555-867-5309",
        "What is the weather in Paris?",
    ]
    for i, prompt in enumerate(prompts):
        result = redactor.redact(prompt)
        status = f"({result.count} redactions)" if result.was_redacted else "(clean)"
        print(f"   Prompt {i + 1}: {result.text}  {status}")

    # -- on_tool_start: policy enforcement --
    print("\n── 2. on_tool_start — Tool allow/deny")
    tools = [
        ("search_web", "EnforceCore docs"),
        ("calculate", "42 * 365"),
        ("execute_shell", "rm -rf /"),
        ("write_to_db", "DROP TABLE users"),
    ]
    allowed_count = 0
    blocked_count = 0
    for tool_name, tool_input in tools:
        ctx = CallContext(tool_name=tool_name, args=(tool_input,), kwargs={})
        pre = engine.evaluate_pre_call(ctx)
        if pre.decision.value == "blocked":
            print(f"   ✗ {tool_name}({tool_input!r}) → BLOCKED")
            blocked_count += 1
        else:
            print(f"   ✓ {tool_name}({tool_input!r}) → allowed")
            allowed_count += 1

    # -- on_llm_end: PII redaction in responses --
    print("\n── 3. on_llm_end — PII redaction in LLM responses")
    responses = [
        "The user's email is alice@example.com and card 4111-1111-1111-1111",
        "Weather in Paris: 22°C, sunny",
    ]
    for i, resp in enumerate(responses):
        result = redactor.redact(resp)
        status = f"({result.count} redactions)" if result.was_redacted else "(clean)"
        print(f"   Response {i + 1}: {result.text}  {status}")

    # -- Summary --
    print(f"\n── Summary: {allowed_count} allowed, {blocked_count} blocked")

    print()
    print("LangChain integration pattern:")
    print("  from enforcecore.integrations.langchain import EnforceCoreCallbackHandler")
    print("  from langchain_openai import ChatOpenAI")
    print()
    print('  handler = EnforceCoreCallbackHandler(policy="policy.yaml")')
    print("  llm = ChatOpenAI(callbacks=[handler])")
    print('  result = llm.invoke("My SSN is 123-45-6789")')
    print("  # SSN is automatically redacted, audit entry created")


if __name__ == "__main__":
    run_demo()

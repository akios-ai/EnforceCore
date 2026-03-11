# Quick Start

## Installation

```bash
pip install enforcecore
```

Or with all optional extras:

```bash
pip install enforcecore[all]
```

## Create a Policy

Create a file `policies/strict.yaml`:

```yaml
name: "strict-policy"
version: "1.0"
rules:
  allowed_tools:
    - search_web
    - calculator
    - translate
  denied_tools:
    - execute_shell
    - delete_file
  pii_redaction:
    enabled: true
    categories: [email, phone, ssn, credit_card]
    strategy: placeholder
on_violation: block
```

## Enforce a Function

```python
from enforcecore import enforce

@enforce(policy="policies/strict.yaml")
async def search_web(query: str) -> str:
    """This function is now enforced by the policy."""
    return await api.search(query)

# Allowed — search_web is in the allowed list
result = await search_web("Python tutorials")

# Blocked — execute_shell is in the denied list
@enforce(policy="policies/strict.yaml")
async def execute_shell(cmd: str) -> str:
    return await shell.run(cmd)

await execute_shell("ls -la")  # raises EnforcementViolation
```

## Verify the Audit Trail

```python
from enforcecore import verify_trail

result = verify_trail("audit_logs/trail.jsonl")
print(f"Valid: {result.is_valid}")
print(f"Entries: {result.total_entries}")
print(f"Chain intact: {result.chain_intact}")
```

## Use the CLI

```bash
# Validate a policy file
enforcecore validate policies/strict.yaml

# Verify an audit trail
enforcecore verify audit_logs/trail.jsonl

# Inspect policy decisions (dry run)
enforcecore dry-run policies/strict.yaml search_web

# Run the evaluation suite
enforcecore eval policies/strict.yaml
```

## LangChain Integration

Add PII redaction, policy enforcement, and audit to any LangChain LLM with a
single callback — no changes to your chain topology required.

```bash
pip install langchain-core
```

```python
from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

handler = EnforceCoreCallbackHandler(policy="policies/strict.yaml")

# Attach to any LangChain LLM
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(callbacks=[handler])
result = llm.invoke("Contact alice@example.com for details")
# Email is automatically redacted; audit entry written

# Or attach to an entire agent / chain
from langchain.agents import AgentExecutor
agent = AgentExecutor(agent=my_agent, tools=tools, callbacks=[handler])
```

What happens automatically on every call:

- **`on_llm_start`** — PII in prompts is redacted before the LLM sees them
- **`on_llm_end`** — PII in LLM responses is redacted before your code sees them
- **`on_tool_start`** — tool name is checked against `allowed_tools` / `denied_tools`; raises `ToolDeniedError` if blocked
- **`on_chain_start` / `on_chain_end`** — PII in chain inputs/outputs is redacted
- **Audit** — every event is Merkle-chained to `audit_logs/trail.jsonl`

See [`examples/quickstart_langchain.py`](../examples/quickstart_langchain.py) for a fully runnable demo (no API key needed).

## Next Steps

- Read the [Architecture](architecture.md) to understand how enforcement works
- Browse the [API Reference](api/index.md) for detailed documentation
- See the [Developer Guide](dev-guide.md) to contribute

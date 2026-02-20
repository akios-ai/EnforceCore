# EnforceCore

**The runtime enforcement layer for agentic AI systems.**

EnforceCore provides mandatory, policy-driven enforcement at every external call boundary — tool calls, API calls, file access, network access — so that policy violations become structurally impossible, not just discouraged.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Why EnforceCore?

Most agent safety solutions operate at the **prompt level** — they ask the LLM to be safe. This can be bypassed, jailbroken, or simply ignored.

EnforceCore operates at the **runtime boundary** — the moment before a tool or API is actually called. At this layer, enforcement is mandatory, not advisory. If a call violates policy, it doesn't execute. Period.

```python
from enforcecore import enforce

@enforce(policy="policies/strict.yaml")
async def search_web(query: str) -> str:
    """This call is now policy-enforced, PII-redacted, and audit-logged."""
    return await api.search(query)
```

## What It Does

| Component | Purpose |
|---|---|
| **Policy Engine** | Declarative YAML policies — define what's allowed, denied, and how violations are handled |
| **Enforcer** | Intercepts every external call and enforces policies before execution |
| **Redactor** | Real-time PII detection and redaction on inputs and outputs |
| **Auditor** | Tamper-proof Merkle-tree audit trail for every enforced call |
| **Guard** | Resource limits (time, memory, cost) with hard kill switch |

## Quick Start

### Install

```bash
pip install enforcecore
```

### Define a Policy

```yaml
# policies/my_policy.yaml
name: "my-agent-policy"
version: "1.0"

rules:
  allowed_tools:
    - "search_web"
    - "read_file"
    - "calculator"

  pii_redaction:
    enabled: true
    categories: [email, phone, ssn, credit_card]

  resource_limits:
    max_call_duration_seconds: 30
    max_cost_usd: 5.00

on_violation: "block"
```

### Protect a Tool Call

```python
from enforcecore import enforce

@enforce(policy="policies/my_policy.yaml")
async def search_web(query: str) -> str:
    return await external_api.search(query)

# ✅ Allowed tool + PII redacted from query + audit entry recorded
result = await search_web("find info about john@example.com")

# ❌ Blocked — tool not in allowed list
@enforce(policy="policies/my_policy.yaml")
async def send_email(to: str, body: str):
    await smtp.send(to, body)  # Never executes
```

### Verify the Audit Trail

```bash
enforcecore verify audit.jsonl
# ✅ Trail integrity verified: 42 entries, chain intact, root hash: sha256:abc...
```

## Framework Integrations

EnforceCore works with any Python-based agent system:

- **LangGraph** — [example](examples/langgraph_example.py)
- **CrewAI** — [example](examples/crewai_example.py)
- **AutoGen** — [example](examples/autogen_example.py)
- **Plain Python** — just use the `@enforce()` decorator

## Key Design Decisions

- **Async-native** — supports both sync and async from day one
- **Cross-platform** — core enforcement works on Linux, macOS, and Windows
- **Fail closed** — if enforcement logic fails, the call is blocked (never fails open)
- **Zero framework lock-in** — no hard dependencies on any agent framework
- **Honest benchmarks** — real overhead numbers, not marketing claims

## Performance

| Component | Typical Overhead |
|---|---|
| Policy evaluation | < 1ms |
| PII redaction | 5-15ms |
| Audit entry | < 1ms |
| **Total (typical)** | **8-20ms** |

This is negligible compared to tool call latency (100ms-10s for API calls).

## Documentation

| Document | Description |
|---|---|
| [Vision](docs/vision.md) | Why EnforceCore exists and where it's going |
| [Architecture](docs/architecture.md) | Technical architecture and design decisions |
| [Roadmap](docs/roadmap.md) | v1.0.x incremental release plan |
| [API Design](docs/api-design.md) | Public API surface and usage patterns |
| [Tech Stack](docs/tech-stack.md) | Technology choices and rationale |
| [Developer Guide](docs/dev-guide.md) | Setup, coding standards, and workflow |
| [Contributing](docs/contributing.md) | How to contribute |

## Roadmap (v1.0.x)

| Release | Focus | Status |
|---|---|---|
| v1.0.0 | Core Enforcer + Policy Engine | 🔨 In Progress |
| v1.0.1 | PII Redactor | Planned |
| v1.0.2 | Merkle Auditor | Planned |
| v1.0.3 | Resource Guard + KillSwitch | Planned |
| v1.0.4 | Framework Integrations | Planned |
| v1.0.5 | Evaluation Suite | Planned |
| v1.0.6 | Hardening + Polish | Planned |

See [roadmap.md](docs/roadmap.md) for detailed scope of each release.

## License

[Apache 2.0](LICENSE) — use it freely in open-source and commercial projects.

## Contributing

We welcome contributions, especially:
- New adversarial evaluation scenarios
- Framework integration adapters
- PII entity recognizers
- Performance benchmarks

See [contributing.md](docs/contributing.md) for guidelines.

---

**EnforceCore** is developed by [akios-ai](https://github.com/akios-ai) and was born from the enforcement engine inside [AKIOS](https://github.com/akios-ai), a production runtime for secure multi-agent systems.

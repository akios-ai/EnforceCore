# EnforceCore

**The runtime enforcement layer for agentic AI systems.**

EnforceCore provides mandatory, policy-driven enforcement at every external call
boundary for any Python-based agentic system. It ensures that AI agents operate
within defined safety constraints — tool access, PII redaction, cost budgets,
rate limits, content rules, and network controls — with cryptographically
verifiable audit trails.

## Quick Start

```bash
pip install enforcecore
```

```python
from enforcecore import enforce

@enforce(policy="policies/strict.yaml")
async def search_web(query: str) -> str:
    return await api.search(query)
```

## Key Features

| Feature | Description |
|---------|-------------|
| 🔒 **Policy Enforcement** | YAML-defined policies with allow/deny lists, tool gating |
| 🕵️ **PII Redaction** | Regex-based detection of emails, phones, SSNs, credit cards, secrets |
| 📜 **Merkle Audit Trail** | SHA-256 chained, tamper-proof audit logs |
| 💰 **Cost & Resource Guard** | Budget tracking, time limits, memory limits, kill switch |
| 🌐 **Network Control** | Domain allow/deny lists with wildcard support |
| ⚡ **Rate Limiting** | Sliding-window per-tool and global rate limits |
| 🔌 **Framework Integrations** | LangChain callback handler, LangGraph, CrewAI, AutoGen adapters |
| 📊 **OpenTelemetry** | Traces, metrics, and spans for observability |
| 🧪 **Evaluation Suite** | 26 adversarial scenarios across 11 threat categories + benchmarks |
| 🔌 **Plugin Ecosystem** | Custom guards, redactors, and audit backends via PyPI entry-points |
| 📋 **Compliance Reporting** | EU AI Act, SOC2, GDPR compliance exports |
| 🏗️ **Multi-Tenant** | Hierarchical policies with tenant-level isolation |

## Navigation

- **[Getting Started](quickstart.md)** — Installation, first policy, first enforcement
- **[Architecture](architecture.md)** — How EnforceCore works under the hood
- **[API Reference](api/index.md)** — All 58 public API symbols documented
- **[Plugin System](api/plugin-base.md)** — Build custom guards and redactors
- **[Compliance](api/compliance-reporter.md)** — Regulatory export guides
- **[Research](vision.md)** — Vision, related work, and roadmap

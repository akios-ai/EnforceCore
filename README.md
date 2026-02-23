<p align="center">
  <img src="https://raw.githubusercontent.com/akios-ai/EnforceCore/main/.github/assets/logo.svg" alt="EnforceCore" width="280" />
</p>

<h1 align="center">EnforceCore</h1>

<p align="center">
  <strong>The runtime enforcement layer for agentic AI systems.</strong><br />
  Policy-driven · Fail-closed · Tamper-proof audit trails
</p>

<p align="center">
  <a href="https://github.com/akios-ai/EnforceCore/actions"><img src="https://img.shields.io/github/actions/workflow/status/akios-ai/EnforceCore/ci.yml?branch=main&style=flat-square&label=CI" alt="CI" /></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue?style=flat-square" alt="Python" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache_2.0-blue?style=flat-square" alt="License" /></a>
  <img src="https://img.shields.io/badge/coverage-95%25-brightgreen?style=flat-square" alt="Coverage" />
  <img src="https://img.shields.io/badge/tests-1510_passed-brightgreen?style=flat-square" alt="Tests" />
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> ·
  <a href="docs/architecture.md">Architecture</a> ·
  <a href="docs/roadmap.md">Roadmap</a> ·
  <a href="docs/api-design.md">API Reference</a> ·
  <a href="docs/contributing.md">Contributing</a>
</p>

> **⚠️ Disclaimer:** EnforceCore is provided "as is", without warranty of any kind, express or
> implied. It is a technical enforcement tool — **not a compliance certification**. Using EnforceCore
> does not guarantee regulatory compliance with any standard or law.
> See [DISCLAIMER.md](DISCLAIMER.md) and [LICENSE](LICENSE) for full legal terms.

---

## The Problem

Most agent safety solutions operate at the **prompt level** — they *ask* the LLM to be safe. This is fundamentally broken: prompts can be bypassed, jailbroken, or ignored.

**EnforceCore operates at the runtime boundary** — the moment before a tool or API is actually called. At this layer, enforcement is **mandatory**, not advisory. If a call violates policy, it never executes. Period.

```python
from enforcecore import enforce

@enforce(policy="policies/strict.yaml")
async def search_web(query: str) -> str:
    """This call is policy-enforced before execution."""
    return await api.search(query)
```

## Why EnforceCore?

| | Prompt Guardrails | EnforceCore |
|---|---|---|
| **Layer** | Inside the LLM | Runtime call boundary |
| **Bypassable?** | Yes (jailbreaks, prompt injection) | No (code-level enforcement) |
| **Auditable?** | No | Yes (Merkle-chained trails) |
| **Property-tested?** | No | Yes ([22 Hypothesis properties](docs/formal/invariants.md)) |
| **EU AI Act aligned?** | ❌ | ✅ (see [disclaimer](#legal)) |

> **EnforceCore vs. OS-level security:** EnforceCore operates at the
> *application semantic layer* — it understands tool calls, PII, and cost
> budgets. It does not replace SELinux, AppArmor, seccomp, or container
> sandboxing. These are complementary — use both for
> [defense-in-depth](docs/defense-in-depth.md).

---

## Architecture

```
  ┌───────────────────────────────────────────────────────────────┐
  │        Agent  (LangGraph · CrewAI · AutoGen · Python)         │
  └───────────────────────────────┬───────────────────────────────┘
                                  │  tool_call(args)
                                  ▼
                    ┌─────────────────────────┐
                    │   @enforce(policy=…)    │  ← decorator / adapter
                    └─────────────┬───────────┘
                                  │
  ╔═══════════════════════════════▼═══════════════════════════════╗
  ║                           Enforcer                            ║
  ║                                                               ║
  ║  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐  ║
  ║  │  Policy Engine  │  │    Redactor     │  │    Guard    │  ║
  ║  │ ─────────────── │  │ ─────────────── │  │ ─────────── │  ║
  ║  │  YAML rules     │─▶│  PII detect     │─▶│ time · mem  │  ║
  ║  │  allow / deny   │  │  & redact       │  │ cost · kill │  ║
  ║  └─────────────────┘  └─────────────────┘  └──────┬──────┘  ║
  ║                                                    │          ║
  ║  ┌─────────────────────────────────────────────────▼───────┐ ║
  ║  │                       Audit Trail                       │ ║
  ║  │          Merkle chain · tamper-proof · always logs      │ ║
  ║  └─────────────────────────────────────────────────────────┘ ║
  ╚═══════════════════════════════════════════════════════════════╝
                                  │
               ┌──────────────────┴──────────────────┐
               ▼                                     ▼
       ✅  allowed                             ❌  blocked
        → execute tool                      → raise PolicyViolation
```

<table>
<tr><td><strong>Policy Engine</strong></td><td>Declarative YAML policies — allowed tools, denied tools, violation handling</td></tr>
<tr><td><strong>Enforcer</strong></td><td>Intercepts every call, evaluates policy, blocks or allows</td></tr>
<tr><td><strong>Redactor</strong></td><td>Real-time PII detection and redaction on inputs &amp; outputs</td></tr>
<tr><td><strong>Auditor</strong></td><td>Tamper-proof Merkle-tree audit trail for every enforced call</td></tr>
<tr><td><strong>Guard</strong></td><td>Resource limits (time, memory, cost) with hard kill switch</td></tr>
</table>

---

## Quick Start

### Install

```bash
pip install enforcecore
```

### 1. Define a Policy

```yaml
# policy.yaml
name: "my-agent-policy"
version: "1.0"

rules:
  allowed_tools:
    - "search_web"
    - "calculator"
    - "get_weather"
  denied_tools:
    - "execute_shell"
  max_output_size_bytes: 524288   # 512KB

on_violation: "block"
```

### 2. Protect Your Tools

```python
from enforcecore import enforce

# Decorator — sync or async, just works
@enforce(policy="policy.yaml")
async def search_web(query: str) -> str:
    return await api.search(query)

@enforce(policy="policy.yaml")
def calculator(expr: str) -> float:
    return eval(expr)  # policy controls whether this tool can be called
```

### 3. See It Work

```python
# ✅ Allowed — tool is in the allowed list
result = await search_web("latest AI papers")

# ❌ Blocked — tool not allowed, raises ToolDeniedError
@enforce(policy="policy.yaml")
async def execute_shell(cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True).stdout
```

### 4. Programmatic Control

```python
from enforcecore import Enforcer, Policy

policy = Policy.from_file("policy.yaml")
enforcer = Enforcer(policy)

# Direct invocation (sync)
result = enforcer.enforce_sync(my_tool, arg1, arg2, tool_name="my_tool")

# Direct invocation (async)
result = await enforcer.enforce_async(my_tool, arg1, tool_name="my_tool")
```

> 📖 See [examples/quickstart.py](examples/quickstart.py) for a complete runnable demo.

---

## Framework Integrations

EnforceCore works with **any** Python-based agent system — no lock-in:

| Framework | Status | Example |
|---|---|---|
| **Plain Python** | ✅ Available | `@enforce()` decorator |
| **LangGraph** | ✅ Available | `@enforced_tool(policy="...")` |
| **CrewAI** | ✅ Available | `@enforced_tool(policy="...")` |
| **AutoGen** | ✅ Available | `@enforced_tool(policy="...")` |

```python
# LangGraph — one-line enforcement
from enforcecore.integrations.langgraph import enforced_tool

@enforced_tool(policy="policy.yaml")
def search(query: str) -> str:
    """Search the web."""
    return web_search(query)

# CrewAI
from enforcecore.integrations.crewai import enforced_tool

@enforced_tool(policy="policy.yaml")
def calculator(expr: str) -> str:
    """Calculate."""
    return str(eval(expr))

# AutoGen
from enforcecore.integrations.autogen import enforced_tool

@enforced_tool(policy="policy.yaml", description="Search the web")
async def search(query: str) -> str:
    return await web_search(query)
```

> No hard dependencies on any framework — adapters use optional imports.

---

## Key Design Principles

- **🔒 Fail-closed** — if enforcement fails, the call is blocked. Never fails open.
- **⚡ Async-native** — first-class support for both sync and async from day one.
- **🌍 Cross-platform** — core works on Linux, macOS, and Windows. Advanced Linux hardening optional.
- **📦 Zero lock-in** — no hard dependency on any agent framework.
- **📊 Honest benchmarks** — real overhead numbers, not marketing claims.

## Performance

> Measured with 1 000 iterations + 100 warmup on Apple Silicon (arm64), Python 3.13.
> Run `python -m benchmarks.run` for your hardware. See [docs/benchmarks.md](docs/benchmarks.md) for methodology.

| Component | P50 (ms) | P99 (ms) |
|---|---|---|
| Policy evaluation | 0.012 | 0.228 |
| PII redaction (short) | 0.028 | 0.275 |
| PII redaction (~2KB) | 0.129 | 0.220 |
| Audit entry (write) | 0.068 | 0.232 |
| Audit chain verify (100 entries) | 1.114 | 1.457 |
| Resource guard | < 0.001 | < 0.001 |
| Rate limiter | < 0.001 | 0.002 |
| Secret detection | 0.012 | 0.017 |
| **Full enforcement (E2E)** | **0.056** | **0.892** |
| **E2E + PII redaction** | **0.093** | **0.807** |

Negligible compared to tool call latency (100ms–10s for API calls).

---

## Roadmap

| Release | Focus | Status |
|---|---|---|
| **v1.0.0a1** | Core Enforcer + Policy Engine | ✅ Shipped |
| **v1.0.1a1** | PII Redactor | ✅ Shipped |
| **v1.0.2a1** | Merkle Audit Trail | ✅ Shipped |
| **v1.0.3a1** | Resource Guard + KillSwitch | ✅ Shipped |
| **v1.0.4a1** | Framework Integrations | ✅ Shipped |
| **v1.0.5a1** | Evaluation Suite | ✅ Shipped |
| **v1.0.6a1** | Hardening + Polish | ✅ Shipped |
| **v1.0.7a1** | Plugin & Extensibility | ✅ Shipped |
| **v1.0.8a1** | Deep Inspection & Network Control | ✅ Shipped |
| **v1.0.9a1** | CLI & Policy Tooling | ✅ Shipped |
| **v1.0.10a1** | Observability & Telemetry | ✅ Shipped |
| **v1.0.11a1** | Documentation & Academic Foundation | ✅ Shipped |
| **v1.0.12a1** | Threat Model & Compliance Mapping | ✅ Shipped |
| **v1.0.13a1** | Formal Verification & Property Testing | ✅ Shipped |
| **v1.0.14a1** | Reproducible Benchmarks & Evaluation | ✅ Shipped |
| **v1.0.15a1** | End-to-End Examples & Integration | ✅ Shipped |
| **v1.0.16a1** | API Freeze & Stability Audit | ✅ Shipped |
| **v1.0.17a1** | Adversarial Scenario Expansion | ✅ Shipped |
| **v1.0.18a1** | Security Landscape & Positioning | ✅ Shipped |
| **v1.0.19a1** | Pre-Release Polish & Community | ✅ Shipped |
| **v1.0.20a1** | Packaging & Publication | ✅ Shipped |
| **v1.0.21a1** | Security Fixes | ✅ Shipped |
| **v1.0.22a1** | Infrastructure Hardening | ✅ Shipped |
| **v1.0.23a1** | Release Infrastructure & CI Fix | ✅ Shipped |
| **v1.0.24a1** | Security Audit | ✅ Shipped |
| **v1.0.25a1** | API Pruning (110 → 30 symbols) | ✅ Shipped |
| **v1.0.0b1** | First Beta (deprecation warnings) | ✅ Shipped |
| **v1.0.0b2** | Security Fix (from_dict hoisting) | ✅ Shipped |
| **v1.0.0b3** | Documentation Accuracy Fixes | ✅ Shipped |
| **v1.0.0b4** | Tamper-Evidence (append-only + witness) | ✅ Shipped |
| **v1.0.0b5** | Settings Integration + Docs + Edge-Case Tests | ✅ Shipped |
| **v1.0.0** | **Stable Release** | 🎯 Target |

See [docs/roadmap.md](docs/roadmap.md) for detailed scope of each release.

---

## Documentation

| | |
|---|---|
| 📐 [Architecture](docs/architecture.md) | Technical design and component overview |
| 🗺️ [Roadmap](docs/roadmap.md) | v1.0.x incremental release plan |
| 🔧 [API Design](docs/api-design.md) | Public API surface and patterns |
| 📚 [API Reference](https://akios.ai/enforcecore) | API documentation |
| 🛠️ [Developer Guide](docs/dev-guide.md) | Setup, standards, and workflow |
| 🧪 [Tech Stack](docs/tech-stack.md) | Technology choices and rationale |
| 📊 [Evaluation](docs/evaluation.md) | Adversarial scenarios, benchmarks, and reports |
| 📄 [Related Work](docs/related-work.md) | Survey and academic positioning |
| 🛡️ [Defense-in-Depth](docs/defense-in-depth.md) | Security layer architecture and deployment stacks |
| 🧭 [Tool Selection](docs/security/tool-selection.md) | When to use EnforceCore vs. OS-level security |
| ❓ [FAQ](docs/faq.md) | Frequently asked questions |
| 🔍 [Troubleshooting](docs/troubleshooting.md) | Common errors and debugging tips |
| 🌍 [Vision](docs/vision.md) | Why EnforceCore exists |
| 🤝 [Contributing](CONTRIBUTING.md) | How to contribute |
| 📋 [Code of Conduct](CODE_OF_CONDUCT.md) | Community standards |
| 🔒 [Security](SECURITY.md) | Vulnerability reporting policy |

---

## For Researchers

EnforceCore applies established computer science principles — runtime
verification, reference monitors, information-flow control — to the novel
problem of AI agent safety. We welcome academic collaboration.

- 📄 [**Related Work**](docs/related-work.md) — survey of runtime verification
  for AI agents, positioning vs. NeMo Guardrails, LlamaGuard, and others
- 📑 [**CITATION.cff**](CITATION.cff) — machine-readable citation metadata
  ([how to cite](#citation))
- 🔬 [**Open Research Questions**](docs/related-work.md#5-open-research-questions) —
  policy composition, temporal properties, adversarial robustness
- 🧪 [**Evaluation Suite**](docs/evaluation.md) — reproducible adversarial
  benchmarks with 20 scenarios across 10 threat categories
- 📐 [**Architecture**](docs/architecture.md) — formal design with Mermaid
  diagrams

### Citation

```bibtex
@software{enforcecore2026,
  title  = {EnforceCore: Runtime Enforcement Layer for Agentic AI Systems},
  author = {{AKIOUD AI}},
  year   = {2026},
  url    = {https://github.com/akios-ai/EnforceCore},
  license = {Apache-2.0}
}
```

---

## For Enterprises

EnforceCore is designed for production deployment in regulated environments.

| Concern | EnforceCore Feature |
|---|---|
| **Audit compliance** | Merkle-chained, tamper-evident audit trails with OS-enforced append-only and hash-only remote witnesses |
| **Data protection** | Real-time PII redaction (11 categories) |
| **Cost control** | Per-call and cumulative cost budgets |
| **Access governance** | Declarative tool allow/deny policies |
| **Network control** | Domain allowlisting with wildcard support |
| **Rate limiting** | Per-tool, per-window, global rate caps |
| **Incident response** | Structured violation events + webhook alerts |
| **EU AI Act** | Designed for Article 9, 13, 14, 15 alignment |

- 🔒 **Fail-closed by default** — if enforcement fails, the call is blocked
- 📦 **No vendor lock-in** — Apache 2.0, works with any agent framework
- 🌍 **Cross-platform** — Linux, macOS, Windows (advanced Linux hardening optional)
- 📊 **Observability** — OpenTelemetry traces, Prometheus-compatible metrics

---

## Development

```bash
# Clone
git clone https://github.com/akios-ai/EnforceCore.git
cd EnforceCore

# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Test
pytest --cov=enforcecore

# Lint
ruff check . && ruff format --check .
```

**Current stats:** 1510 tests · 95% coverage · 0 lint errors

---

## Acknowledgements

EnforceCore builds on a foundation of prior work in computer science and AI safety:

- **Runtime Verification** — Leucker & Schallhart (2009), Havelund & Goldberg (2005)
- **Reference Monitors** — Anderson (1972) for the tamperproof, always-invoked enforcement model
- **Information Flow Control** — Sabelfeld & Myers (2003) for the PII boundary model
- **Audit Integrity** — Merkle (1987), Crosby & Wallach (2009) for hash-chained tamper evidence
- **Agent Containment** — Armstrong et al. (2012), Babcock et al. (2016) for the containment framing
- **Evaluation Methodology** — Prof. Valérie Viet Triem Tong (CentraleSupélec, IRISA/PIRAT) for feedback on adversarial evaluation strategies and containment testing
- **Microsoft Presidio** — for design inspiration on PII detection patterns
- **EU AI Act (2024)** — Articles 9, 13, 14, 15 directly shaped the design

See [CONTRIBUTORS.md](CONTRIBUTORS.md) and [docs/related-work.md](docs/related-work.md) for full citations.

---

## Legal

EnforceCore is provided **"as is"**, without warranty of any kind. See [DISCLAIMER.md](DISCLAIMER.md) for full legal terms.

EnforceCore is a **technical tool**, not a compliance certification. Using EnforceCore does not guarantee regulatory compliance. Always consult qualified legal counsel for compliance requirements.

## License

[Apache 2.0](LICENSE) — free for open-source and commercial use.

Copyright 2025–2026 AKIOUD AI, SAS. See [LICENSE](LICENSE) for details.


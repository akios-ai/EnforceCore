# EnforceCore — Roadmap

## Release Philosophy

We ship incrementally. Each release adds one well-tested, well-documented
component. No release ships without full test coverage, updated documentation,
and passing CI.

---

## Shipped Releases

### v1.0.0 — Core Enforcer + Policy Engine ✅

The minimum viable enforcement framework: Pydantic v2 policy models with YAML
loading, `@enforce(policy=...)` decorator (sync + async), context manager,
`EnforcementViolation` exception hierarchy, configuration via `pydantic-settings`,
structured logging, and a comprehensive test suite.

### v1.0.1 — PII Redactor ✅

Real-time PII detection and redaction on inputs and outputs. Lightweight
regex-based detection (no heavy dependencies), 5 PII categories (email, phone,
SSN, credit card, IP address), 4 configurable strategies (placeholder, mask,
hash, remove), and full pipeline integration.

### v1.0.2 — Merkle Auditor ✅

Tamper-proof audit trail with Merkle tree verification. Every enforced call
produces a cryptographic audit entry chained to the previous one, enabling
third-party verification that no records were altered or deleted.

### v1.0.3 — Resource Guard ✅

Resource limits and emergency stop: cost tracking, rate limiting, token budgets,
and a kill switch for immediate agent termination when limits are breached.

### v1.0.4 — Framework Integrations ✅

Official adapters for LangChain, CrewAI, and AutoGen. Developers can protect
agents in any major framework with minimal code changes.

### v1.0.5 — Evaluation Suite ✅

Adversarial evaluation framework with 20 attack scenarios across 9 threat
categories. Measures how well enforcement policies hold up against realistic
attack patterns.

### v1.0.6 — Hardening + Polish ✅

Cross-cutting quality improvements: edge case handling, error message clarity,
performance optimisation, and additional test coverage.

### v1.0.7 — Plugin & Extensibility System ✅

Plugin architecture for custom guards, redactors, and audit backends. Third
parties can extend EnforceCore without forking.

### v1.0.8 — Deep Inspection & Network Enforcement ✅

Content-level inspection of tool call arguments and return values. Network-level
enforcement (domain allowlisting, egress control) for agents that access
external services.

### v1.0.9 — CLI & Policy Tooling ✅

Command-line interface for policy validation, linting, and testing. Developers
can verify policies before deployment without writing code.

### v1.0.10 — Observability & Telemetry ✅

OpenTelemetry integration for production monitoring: enforcement decision spans,
metrics (call counts, block rates, latency), and structured log export.

---

## Current Release

### v1.0.2 — Latest Stable ✅

Available on [PyPI](https://pypi.org/project/enforcecore/):

```bash
pip install enforcecore
```

**Quality metrics:** 1520+ tests passing, 30 public API symbols, mypy strict
mode, ruff-formatted, CI-verified on Linux and macOS.

---

## Upcoming

### v1.1.0 — Evaluation Expansion

Expanded adversarial evaluation: 26 scenarios across 11 threat categories, with
HTML report generation and structured JSON output for CI integration.

---

## Future Directions

These are **not committed** — they represent potential future work based on
adoption and community input:

- **Multi-tenant enforcement** — per-agent/per-tenant policy isolation with
  namespace-scoped audit trails
- **Policy Hub** — community repository of reusable, audited policies (think
  "Docker Hub for agent policies")
- **Distributed enforcement** — multi-agent systems across processes/machines
  with consistent policy evaluation
- **Multi-language SDKs** — TypeScript, Go, Rust bindings via FFI
- **Formal verification backend** — integration with TLA+/Alloy/Z3 for
  machine-checked policy correctness proofs

### Research Track

Open problems we are interested in collaborating on:

- Optimal policy composition in multi-agent hierarchies
- Information-flow control at agent boundaries
- Runtime verification of temporal safety properties (LTL/CTL over agent traces)
- Quantitative enforcement (probabilistic policy decisions with risk budgets)

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to get involved. We welcome
contributions to any area of the roadmap.

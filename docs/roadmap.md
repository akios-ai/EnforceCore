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

### v1.1.0 — Evaluation Expansion ✅

Expanded adversarial evaluation: 26 scenarios across 11 threat categories, with
HTML report generation and structured JSON output for CI integration.

### v1.1.1 — Eval Polish ✅

Polish pass on evaluation suite and community feedback preparation.

### v1.1.2 — Beta Feedback Fixes ✅

Fixes from external beta testing:
- Added `--version` CLI flag (standard Unix convention)
- Fixed 13 broken doc links in `docs/compliance/eu-ai-act.md`
- `enforcecore info` now shows telemetry + redactor extras
- Empty-rules policy warning for safer defaults
- Improved error messages for misplaced `on_violation`

### v1.2.0 — Audit Storage System + Compliance ✅

Pluggable audit persistence (JSONL, SQLite, PostgreSQL) with EU AI Act compliance
queries (Articles 9, 13, 14, 52), HTML/JSON report generation, and
`AuditStoreBackendAdapter` for Auditor integration.

### v1.3.0 — Subprocess Sandbox ✅

Post-execution isolation layer: tool calls run in restricted subprocesses with
configurable resource limits, file-descriptor restrictions, and env-var
filtering. WASM sandboxing design included for high-isolation use cases.

### v1.4.0 — NER PII + Sensitivity Labels ✅

Optional NER-based PII detection tier via Presidio/spaCy alongside the existing
regex engine. Lightweight sensitivity labels (`public` / `restricted` /
`confidential` / `secret`) on tool schemas and data fields — the first step
toward label-based IFC. `pip install enforcecore[ner]`.

### v1.5.0 — OpenTelemetry + Observability ✅

Available on [PyPI](https://pypi.org/project/enforcecore/):

```bash
pip install enforcecore
pip install enforcecore[otel]         # OpenTelemetry traces + logs
pip install enforcecore[prometheus]   # Prometheus metrics
```

First-class observability for every enforcement decision:
- `EnforceCoreInstrumentor` — OTLP trace export; every `@enforce()` call
  becomes a span with policy decision, redaction events, and guard outcomes
- `EnforceCorePrometheusExporter` — 5 Prometheus metrics
  (`enforcecore_calls_total`, `enforcecore_violations_total`,
  `enforcecore_redactions_total`, `enforcecore_overhead_seconds`,
  `enforcecore_latency_seconds`), HTTP scrape endpoint
- `AuditLogExporter` — structured JSON audit logs to stdout / file /
  Splunk HEC / Elastic Bulk API / OTLP
- Pre-built Grafana dashboard (`docs/grafana-dashboard.json`)

**Quality metrics:** 1717 tests passing, mypy strict, ruff-formatted,
CI-verified on Linux and macOS.

### v1.6.0 — Multi-Tenant + Policy Inheritance ✅

Available on [PyPI](https://pypi.org/project/enforcecore/1.6.0/):

```bash
pip install enforcecore  # includes MultiTenantEnforcer
```

Hierarchical policy support and multi-tenant enforcement:
- `extends:` keyword in policy YAML for composable policies at org / team / agent
  granularity
- `MultiTenantEnforcer` — registry with lazy enforcer init, thread-safe, per-tenant
  audit trail
- `tenant_id` on `Enforcer` propagated to every `AuditEntry`
- Circular-extends detection raises `PolicyLoadError` before boot

```yaml
# agent_deployer.yaml
extends: team_dev.yaml
tools:
  allowed: [search, calculate, deploy_service]
  context:
    environment: [staging]
```

**Quality metrics:** 1756 tests passing, mypy strict, ruff-formatted,
CI-verified on Linux and macOS.

### v1.7.0 — Remote Policy Server ✅

Available on [PyPI](https://pypi.org/project/enforcecore/1.7.0/):

```bash
pip install enforcecore
```

Centralized policy management: policies stored and versioned server-side, agents
pull at startup or on cache miss.

```python
Enforcer.from_server(
    "https://policy.acme.com/agents/chatbot-v2",
    token=os.environ["POLICY_SERVER_TOKEN"],
    cache_ttl=300,
)
```

Key properties:
- `PolicyServerClient` with HMAC signature verification before applying
- Pull-only (server never pushes; trust model is explicit)
- TTL cache with stale-on-error fallback (graceful degradation)
- `PolicyServerError` raised on unrecoverable fetch failures
- Policy version recorded in audit trail for every enforcement decision

**Quality metrics:** 1817 tests passing, mypy strict, ruff-formatted,
CI-verified on Linux and macOS.

### v1.8.0 — Compliance Reporting ✅ Shipped

Available on [PyPI](https://pypi.org/project/enforcecore/1.8.0/):

```bash
pip install enforcecore
```

Turn the audit trail into structured compliance exports for EU AI Act, SOC2,
and GDPR — with a single CLI command or Python API:

```bash
# CLI
enforcecore audit export --format eu-ai-act --period 2026-Q4 --output report.json

# Python
reporter = ComplianceReporter()
report = reporter.export(ComplianceFormat.EU_AI_ACT, CompliancePeriod.from_label("2026-Q4"))
```

Key additions:
- `ComplianceReporter` — export/export_json/export_html/send_webhook
- Pre-built templates: EU AI Act Article 13, SOC2 CC6/7/8/9, GDPR Article 30
- `CompliancePeriod` — parses quarterly, half-year, or annual labels
- `ComplianceReport` — scored report with narratives and audit statistics
- `enforcecore audit export` CLI sub-command
- Vanta / Drata webhook integration via `send_webhook()`

**Quality metrics:** 1898 tests passing, mypy strict, ruff-formatted,
CI-verified on Linux and macOS.

### v1.9.0 — Plugin Ecosystem ✅ **Latest**

Available on [PyPI](https://pypi.org/project/enforcecore/1.9.0/):

```bash
pip install enforcecore
```

First-class plugin SDK — publish and consume custom guards, redactors, and audit
backends from PyPI without forking the core:

```python
# pip install enforcecore-guard-pii-enterprise
from enforcecore import PluginManager

manager = PluginManager()
manager.load_all()
print(manager.guards)  # [<EnterpriseGuard allow-guard v1.0.0>]
```

Key additions:
- `GuardPlugin`, `RedactorPlugin`, `AuditBackendPlugin` — stable ABCs for plugin authors
- `GuardResult`, `RedactResult`, `PluginInfo` — frozen dataclasses
- `PluginManager` — thread-safe entry-point discovery (`enforcecore.guards`, `enforcecore.redactors`, `enforcecore.audit_backends`)
- `PluginLoadError` — typed exception for import/instantiation failures
- `enforcecore plugin list` — discover all installed plugins
- `enforcecore plugin info <name>` — inspect a specific plugin

**Quality metrics:** 1972 tests passing, mypy strict, ruff-formatted,
CI-verified on Linux and macOS.

---

## Upcoming

### v2.0.0 — Distributed Enforcement

Major API evolution for multi-node, multi-agent deployments. Cross-agent audit
trail merging, distributed rate limits, and consensus-based policy updates.

---

## Future Directions

These are **not committed** — they represent potential future work based on
adoption and community input:

- **Distributed enforcement (v2.0.0)** — multi-node, multi-agent with global Merkle root
- **Policy Hub** — community repository of reusable, audited policies
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

See [CONTRIBUTING.md](https://github.com/akios-ai/EnforceCore/blob/main/CONTRIBUTING.md) for how to get involved. We welcome
contributions to any area of the roadmap.

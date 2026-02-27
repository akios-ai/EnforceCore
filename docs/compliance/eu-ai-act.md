# EU AI Act — Compliance Mapping

**Regulation:** Regulation (EU) 2024/1689 (Artificial Intelligence Act)
**Mapped against:** EnforceCore v1.1.2
**Last updated:** 2026-02-24

---

## Disclaimer

This document maps EnforceCore capabilities to specific articles of the EU AI
Act. It is a **technical analysis**, not legal advice. Using EnforceCore does
not guarantee regulatory compliance. Organizations must consult qualified
legal counsel for compliance assessments specific to their use case and
risk classification.

---

## Scope

The EU AI Act applies primarily to **high-risk AI systems** (Annex III).
Agentic AI systems that make autonomous decisions — especially in healthcare,
finance, employment, or critical infrastructure — are likely to fall under
high-risk classification. This mapping focuses on the articles most relevant
to runtime enforcement of AI agent behavior.

---

## Article-by-Article Mapping

### Article 9 — Risk Management System

> *"A risk management system shall be established, implemented, documented
> and maintained in relation to high-risk AI systems."*

| Requirement | EnforceCore Capability | Evidence |
|---|---|---|
| Identify and analyse known and foreseeable risks | Policy engine defines allowed/denied tools, content rules, network boundaries | `enforcecore/core/policy.py` — `Policy` model with `allowed_tools`, `denied_tools`, `content_rules` |
| Estimate and evaluate risks that may emerge | Evaluation suite with 20 adversarial scenarios across 10 threat categories covering tool abuse, data exfiltration, injection attacks, ransomware, supply-chain, and collusion | `enforcecore/eval/` — `ScenarioRunner`, `BenchmarkRunner` |
| Adopt risk management measures | Fail-closed enforcement, PII redaction, cost limits, rate limiting, domain enforcement | `enforcecore/core/enforcer.py` — `enforce_sync()`, `enforce_async()` |
| Test to identify the most appropriate measures | Dry-run mode replays tool calls against a policy without execution | `enforcecore/cli/` — `enforcecore dry-run` command |
| Residual risk documentation | Threat model documents known limitations and unmitigated risks | [docs/threat-model.md](../threat-model.md) §7 |

**Verification:**
```bash
# Run adversarial evaluation suite
enforcecore eval --scenarios all --output risk-assessment/

# Dry-run a policy against recorded calls
enforcecore dry-run policy.yaml --calls recorded_calls.jsonl
```

---

### Article 13 — Transparency and Provision of Information

> *"High-risk AI systems shall be designed and developed in such a way as
> to ensure that their operation is sufficiently transparent to enable
> deployers to interpret the system's output and use it appropriately."*

| Requirement | EnforceCore Capability | Evidence |
|---|---|---|
| Information about capabilities and limitations | Threat model with formal security properties and known limitations | [docs/threat-model.md](../threat-model.md) |
| Intended purpose and foreseeable misuse | Architecture docs with trust boundaries and adversary model | [docs/architecture.md](../architecture.md), [docs/threat-model.md](../threat-model.md) §3 |
| Level of accuracy, robustness, cybersecurity | Published benchmarks with statistical methodology (p50/p95/p99) | [docs/benchmarks.md](../benchmarks.md) |
| Logging capabilities | Merkle-chained audit trail records every enforcement decision with timestamps, tool names, args hashes, decisions, and timing | `enforcecore/auditor/engine.py` — `Auditor.record()` |
| Human-interpretable records | CLI inspection of audit trails with filtering and formatting | `enforcecore/cli/` — `enforcecore inspect audit.jsonl --tail 20` |

**Verification:**
```bash
# Inspect audit trail
enforcecore inspect audit.jsonl --tail 50 --filter decision=blocked

# Verify audit integrity
enforcecore verify audit.jsonl
```

---

### Article 14 — Human Oversight

> *"High-risk AI systems shall be designed and developed in such a way [...]
> as to enable natural persons to whom human oversight is assigned to
> effectively oversee the AI system."*

| Requirement | EnforceCore Capability | Evidence |
|---|---|---|
| Enable understanding of capacities and limitations | Declarative YAML policies readable by non-developers | Policy schema with `allowed_tools`, `denied_tools`, `on_violation` |
| Enable awareness of automation bias | `on_violation: "block"` prevents reliance on unverified agent actions | `enforcecore/core/policy.py` — `OnViolation` enum |
| Enable interpretation of output | Audit entries include full decision rationale (violation type, reason, matched rule) | `enforcecore/auditor/engine.py` — `AuditEntry` fields |
| Enable decision to override | Policy YAML is human-editable; dry-run mode previews effect of policy changes | `enforcecore dry-run` command |
| Enable intervention / stop | `on_violation: "block"` halts execution; webhook alerts enable human-in-the-loop | `enforcecore/plugins/webhooks.py` — `WebhookDispatcher` |

**Verification:**
```yaml
# Human-readable policy — no code required
name: "reviewed-policy"
version: "1.0"
rules:
  allowed_tools: ["search_web", "calculator"]
  denied_tools: ["execute_shell"]
on_violation: "block"  # Human decision: block, not log
```

---

### Article 15 — Accuracy, Robustness, and Cybersecurity

> *"High-risk AI systems shall be designed and developed in such a way that
> they achieve [...] an appropriate level of accuracy, robustness and
> cybersecurity."*

| Requirement | EnforceCore Capability | Evidence |
|---|---|---|
| Accuracy of decisions | Deterministic policy evaluation — same input always produces same decision | `enforcecore/core/policy.py` — no randomness in `evaluate_pre()` / `evaluate_post()` |
| Robustness against errors | Fail-closed by default — internal errors block the call rather than allowing it through | `enforcecore/core/enforcer.py` — `except EnforceCoreError: raise` |
| Resilience against manipulation | Content rules block injection patterns; Unicode normalization resists evasion | `enforcecore/core/rules.py`, `enforcecore/redactor/unicode.py` |
| Cybersecurity measures | PII redaction (5 categories), secret detection (11 categories), domain enforcement, rate limiting | Full enforcement pipeline |
| Redundancy and fail-safe | `fail_open=False` is the default; enabling it requires explicit env var + warning | `enforcecore/core/config.py` — `Settings.fail_open` |

**Verification:**
```bash
# Verify deterministic behavior
pytest tests/core/test_policy.py -v  # Same inputs → same outputs

# Verify fail-closed
pytest tests/core/test_hardening.py -v  # fail_open=False by default

# Verify injection resistance
pytest tests/core/test_rules.py -v  # Shell, SQL, path traversal blocked
pytest tests/redactor/test_unicode.py -v  # Evasion resistance
```

---

### Article 17 — Quality Management System

> *"Providers of high-risk AI systems shall put a quality management system
> in place."*

| Requirement | EnforceCore Capability | Evidence |
|---|---|---|
| Design and development procedures | Documented architecture, roadmap, dev guide | [docs/architecture.md](../architecture.md), [docs/roadmap.md](../roadmap.md), [docs/dev-guide.md](../dev-guide.md) |
| Testing and validation | 2307 tests, automated CI on macOS, type checking (mypy), linting (ruff) | `.github/workflows/ci.yml`, `pytest --cov` |
| Data management | PII redaction categories and secret patterns documented and tested | `enforcecore/redactor/patterns.py`, `enforcecore/redactor/secrets.py` |
| Record-keeping | Merkle-chained audit trails, CHANGELOG, git history | `enforcecore/auditor/`, `CHANGELOG.md` |
| Corrective actions | Webhook alerts on violations, structured logging for incident response | `enforcecore/plugins/webhooks.py`, structlog events |
| Post-market monitoring | OpenTelemetry metrics (calls, blocks, redactions, cost, latency) | `enforcecore/telemetry/` |
| Versioning | Semantic versioning with documented compatibility promises | `pyproject.toml`, `CHANGELOG.md` |

**Verification:**
```bash
# Full quality check (CI-equivalent)
ruff check . && ruff format --check .  # Lint
mypy enforcecore/                       # Type check
pytest --cov=enforcecore                # Test suite + coverage
```

---

## Traceability Matrix

| AI Act Article | EnforceCore Module | Test File | Docs |
|---|---|---|---|
| Art. 9 (Risk Mgmt) | `core/policy`, `core/rules`, `eval/` | `test_policy.py`, `test_rules.py`, `test_eval_*.py` | [threat-model.md](../threat-model.md) |
| Art. 13 (Transparency) | `auditor/`, `cli/` | `test_engine.py`, `test_cli.py` | [architecture.md](../architecture.md) |
| Art. 14 (Human Oversight) | `core/policy`, `cli/`, `plugins/webhooks` | `test_policy.py`, `test_cli.py`, `test_webhooks.py` | [api-design.md](../api-design.md) |
| Art. 15 (Robustness) | `core/enforcer`, `core/rules`, `redactor/` | `test_enforcer.py`, `test_rules.py`, `test_unicode.py` | [threat-model.md](../threat-model.md) |
| Art. 17 (Quality Mgmt) | CI, telemetry, auditor | `.github/workflows/ci.yml` | [dev-guide.md](../dev-guide.md) |

---

## Gaps and Planned Work

| Gap | Status | Planned Release |
|---|---|---|
| Published performance benchmarks (Art. 15) | ✅ Complete | v1.0.14a1 |
| Formal property verification (Art. 15) | ✅ Complete | v1.0.13a1 |
| SBOM for supply chain transparency (Art. 13) | Planned | Post-v1.0 |
| External audit trail root anchoring (Art. 13) | Future | Post-v1.0 |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0.23a1 | 2026-02-23 | Updated version header, test counts (1503), CI platform (macOS) |
| 1.0.19a1 | 2026-02-21 | Updated scenario counts, version header, gaps table |
| 1.0.12a1 | 2026-02-21 | Initial EU AI Act compliance mapping |

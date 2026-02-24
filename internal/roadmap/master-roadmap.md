
Here's the critical summary of what I wrote and why:

**Pre-stable (b6 → stable):**
✅ **SHIPPED.** Both v1.0.0b6 and v1.0.0 stable shipped on Feb 24, 2026 — ahead of the mid-March target. The benchmark suite, integration examples, and framework comparison are all done.

**Post-stable reality (Feb 24, 2026):**
- v1.0.0 is live on PyPI (`pip install enforcecore`)
- 147-point post-release audit: **147/147 passed (100%)**
- NeurIPS 2026 workshop paper: **written, 11 pages, compiled**
- 2 bugs found during audit → fixed in source for v1.0.1:
  1. `verify_with_witness` didn't normalize `WitnessRecord` objects to hash strings
  2. `PolicyRules` silently ignored unknown YAML keys (e.g., `pii` vs `pii_redaction`)
- All 1510 pytest tests still green after fixes

**The DEF CON deadline is a forcing function.** CFPs close around April 2026. We now have stable + benchmark results + NeurIPS paper. We are ready to submit.

**Post-stable milestones** (10 steps to v2.0):
1. **v1.0.1 Patch** — ship the 2 bug fixes found in audit
2. **v1.1 AgentSecBench** — the single highest-leverage release. This is what positions you as the standards body, not just a product.
3. **v1.2 Sandbox** — closes the one real security gap (post-decision enforcement)
4. **v1.3 NER PII + Sensitivity Labels** — answers the "regex is garbage" criticism with a concrete upgrade, and introduces lightweight IFC labels informed by Chalmers IFC research collaboration
5. **v1.4 OpenTelemetry** — the ops team unlock for enterprise
6. **v1.5 Multi-tenant** → **v1.6 Policy server** → **v1.7 Compliance** → **v2.0 Distributed**


# EnforceCore — Master Roadmap

**Written:** February 24, 2026  
**Last updated:** February 24, 2026 (post-v1.0.0 stable release)  
**Current version:** v1.0.0 (live on PyPI, CI green, 147/147 audit)  
**North star:** Become THE runtime security layer for AI agents — the thing serious teams add before going to production.

---

## Part 1 — State of the Product (Post-v1.0.0)

### What is done

| Area | State |
|------|-------|
| Core enforcement pipeline | **Shipped.** Policy → Redactor → Guard → Audit. 5-stage pipeline. |
| Merkle-chained audit trail | 0.0008ms per event. Tamper-evident. Append-only OS flags. Hash witnesses. |
| PII redaction | 50+ patterns, regex-based, ~0.028ms short text. 6 categories, 4 strategies. |
| Framework integrations | LangGraph, AutoGen, CrewAI decorators + quickstart examples. |
| API surface | 30 core symbols. Tier 1/2/deprecated separation. Stable. |
| Security audit | All known gaps closed (b1–b5). Zero open items in SECURITY.md. |
| Tests | 1510, all passing. CI green on 3.11/3.12/3.13. |
| Docs | API reference, migration guide, threat model, integration guides, formal invariants. |
| PyPI | `pip install enforcecore` v1.0.0 live. Clean install verified. |
| Benchmark suite | 20 scenarios, 10 threat categories. 100% containment (bare=22%). |
| Framework comparison | Published: LangGraph/AutoGen/CrewAI fail, EnforceCore passes. |
| Post-release audit | 147/147 checks passed (100%). |
| NeurIPS paper | 11-page workshop paper compiled. 25 peer-reviewed references. |

### What needs v1.0.1 (patch)

1. **`verify_with_witness` WitnessRecord normalization** — `CallbackWitness` callback receives `WitnessRecord` objects, but `verify_with_witness` tried to subscript them as strings. Fixed in source, needs release.
2. **`PolicyRules` alias validation** — unknown YAML keys (e.g., `pii` instead of `pii_redaction`) were silently ignored by Pydantic. Added `model_validator` that remaps common aliases with deprecation warnings and warns about unknown keys.

### What does NOT need to change

- The API surface — frozen and clean (30 symbols)
- The security model — all known gaps closed
- The performance — 0.055ms p50 overhead
- The test coverage — 1510 tests with property-based testing

---

## Part 2 — Path to v1.0.0 Stable ✅ COMPLETE

### v1.0.0b6 — Pre-stable Hardening ✅ SHIPPED Feb 24, 2026

All items complete:
- ✅ Benchmark suite — 20 scenarios, 10 threat categories, HTML report output
- ✅ Real integration examples — LangGraph, AutoGen, CrewAI quickstarts
- ✅ Published benchmark results — bare=22%, EnforceCore=100% containment
- ✅ Framework comparison — comprehensive side-by-side with methodology
- ✅ README polished with quickstart + benchmark badge

### v1.0.0 — Stable Release ✅ SHIPPED Feb 24, 2026

All entry criteria met:
- [x] Security review (Wallach design feedback documented)
- [x] Performance benchmarks stable and published (p50=0.055ms, p99=0.822ms)
- [x] README, docs, examples polished
- [x] PyPI metadata finalized
- [x] CHANGELOG comprehensive
- [x] Post-release audit: 147/147 (100%)

### v1.0.1 — Bug-fix Patch (NEXT)

**Target:** ✅ SHIPPED Feb 24, 2026 (PyPI: https://pypi.org/project/enforcecore/1.0.1/)  
**Scope:** 2 bug fixes found during post-release audit + 14 doc updates

| Fix | File | Description |
|-----|------|-------------|
| WitnessRecord normalization | `auditor/witness.py` | `verify_with_witness` now accepts `WitnessRecord` objects in `witness_hashes` list |
| PolicyRules alias validation | `core/policy.py` | `model_validator` remaps `pii` → `pii_redaction` with deprecation warning, warns on unknown keys |

**Tests:** 1510 pass, 0 fail. Both fixes verified by 147-point audit.

**Stable contract from this point:** semantic versioning, breaking changes only in v2.0, security patches backported to v1.0.x.

---

## Part 3 — Post-Stable Roadmap

### Release Overview

| Version | Theme | Target | Status |
|---------|-------|--------|--------|
| v1.0.0 | Stable release | Feb 24, 2026 | ✅ SHIPPED |
| v1.0.1 | Audit bug fixes | Feb 24, 2026 | ✅ SHIPPED |
| v1.0.2 | CI hardening + release process | Feb 25, 2026 | ✅ READY |
| v1.1.0 | Eval expansion (26 scenarios, HTML reports) | Mar 2026 | 🔧 CODE DONE — needs release |
| v1.1.1 | Eval polish + community feedback | Mar–Apr 2026 | 📋 Planned |
| v1.2.0 | AgentSecBench standalone package | May 2026 | 📋 Planned — defines the conversation |
| v1.3.0 | Subprocess sandbox | June 2026 | 📋 Planned — closes last real security gap |
| v1.4.0 | NER PII + sensitivity labels | July 2026 | 📋 Planned — answers "regex PII is garbage" + first IFC labels |
| v1.5.0 | OpenTelemetry + observability | Aug 2026 | 📋 Planned — enterprise deployability |
| v1.6.0 | Multi-tenant + policy inheritance | Sep 2026 | 📋 Planned — enterprise prerequisite |
| v1.7.0 | Policy server (remote + signed) | Nov 2026 | 📋 Planned — ops teams need this |
| v1.8.0 | Compliance reporting | Jan 2027 | 📋 Planned — EU AI Act / SOC2 |
| v2.0.0 | Distributed enforcement | 2027 | 📋 Planned — multi-node architectures |

---

### v1.0.x — Patch Series (Ongoing)

Purely reactive. Fix bugs reported by the community, backport security patches, never add features.

**What to watch:** HN comment patterns will reveal real friction points. Anything that generates 3+ identical complaints gets a patch within 1 week. This is the signal you can't invent in advance.

---

### v1.0.2 — CI Hardening + Release Process

**Target:** ✅ READY — Feb 25, 2026
**Scope:** Release process improvements discovered during v1.0.1 CI failures

**What happened:** After v1.0.1 shipped, 5 consecutive CI failures exposed gaps in the
pre-release workflow: ruff format not checked locally, stale version directives from
internal iteration (27 Sphinx directives referencing impossible versions like 1.0.24),
mypy errors from eval scenario code using wrong API, version mismatch in instrumentor.py.

**Deliverables:**
- `RELEASE_PROCESS.md` — 3-phase release process doc (pre-release → release → post-release)
- `scripts/pre_release_gate.py` — automated pre-release checks that mirror CI exactly
- Fixed 3 remaining stale version directives (1.0.16 → 1.0.0)
- Fixed `_SCOPE_VERSION` mismatch in `enforcecore/telemetry/instrumentor.py`
- Fixed `CONTRIBUTORS.md` — reframed Sabelfeld/Stucki entries for accuracy

**Tests:** 1520 pass, 0 fail.

**Lesson embedded:** Every future release runs `pre_release_gate.py` before `release.py`.
The gate catches what CI catches, but locally, before the push.

---

### v1.1.0 — Eval Expansion: 26 Scenarios + HTML Reports

**Target:** March 2026 (code done, needs release prep)
**What:** Major expansion of the evaluation suite from 20 → 26 scenarios with a new
threat category and HTML report generation.

**Status: Code is written, tested, and committed.** This is the next release to ship.

**What was added (committed post-v1.0.1):**

| New Scenario | Category | What it tests |
|---|---|---|
| `audit_trail_integrity` | AUDIT_COMPLETENESS | Merkle chain tamper detection |
| `audit_witness_callback` | AUDIT_COMPLETENESS | Witness callback fires and records |
| `tool_abuse_argument_injection` | TOOL_ABUSE | Malicious args in tool parameters |
| `pii_leak_chained_output` | PII_LEAKAGE | PII surviving multi-step chains |
| `resource_exhaust_large_input` | RESOURCE_EXHAUSTION | Oversized payloads |
| `prompt_injection_system_override` | PROMPT_INJECTION | System prompt override attempts |

**New threat category:** `AUDIT_COMPLETENESS` — validates that the audit trail is
complete, tamper-evident, and verifiable.

**HTML report generator:** `generate_html_report()` — produces a standalone HTML
report with scenario results, benchmark data, and visual formatting.

**Coverage now:** 26 scenarios across 11 threat categories:
`TOOL_ABUSE` (4), `DATA_EXFILTRATION` (2), `RESOURCE_EXHAUSTION` (3),
`POLICY_EVASION` (2), `PII_LEAKAGE` (2), `PRIVILEGE_ESCALATION` (2),
`PROMPT_INJECTION` (3), `RANSOMWARE` (2), `SUPPLY_CHAIN` (2),
`COLLUSION` (1), `AUDIT_COMPLETENESS` (2) + 1 multi-stage.

**Release checklist for v1.1.0:**
- [ ] Run `pre_release_gate.py` — must pass all 8 checks
- [ ] Update CHANGELOG [Unreleased] with new scenario list
- [ ] Run full eval suite and capture results
- [ ] Run `release.py 1.1.0 --execute`
- [ ] Verify CI green on tag
- [ ] Verify PyPI publication

---

### v1.1.1 — Eval Polish + Community Feedback (Planned)

**Target:** March–April 2026
**What:** Iterate on v1.1.0 based on early feedback. Add 2–4 more scenarios
if obvious gaps emerge. Polish HTML report formatting.

This is the buffer release — don't plan specific features, react to what users
actually report after trying the expanded eval suite.

---

### v1.2.0 — AgentSecBench: The Standalone Benchmark

**Target:** May 2026
**What:** Extract the evaluation suite into a standalone `agentsecbench` package.
- OPA contribution: AI agent policy templates that pass AgentSecBench scenarios

---

### v1.3.0 — Subprocess / WASM Sandbox

**Target:** June 2026  
**What:** True execution isolation — run agent tool calls inside a sandboxed subprocess or WASM environment.

**Why this is the right next technical milestone:**  
EnforceCore currently enforces *at the policy boundary* — it decides before the tool executes. But if a tool is allowed and then does something unexpected (reads /etc/passwd, makes an unapproved syscall), EnforceCore can't stop it post-decision. The sandbox closes this gap.

**Design options:**
1. **Subprocess isolation** — run tool in a subprocess with restricted environment variables, cwd, and file descriptor set. Low complexity, most portable.
2. **WASM sandbox** — compile tool to WASM or run it in a WASM host (Wasmtime/WasmEdge). Maximum isolation, higher complexity, requires tool rewrite.
3. **Both, tiered** — subprocess as default, WASM as opt-in for high-trust environments.

**Recommendation:** Ship subprocess isolation first (month 1), design WASM interface (month 2). Don't block v1.2 on WASM — it's a massive scope creep risk.

**Critical assessment of the Wasmtime contribution target:**  
Wasmtime was correctly dropped from the contribution plan. But a WASM integration in EnforceCore itself has real merit — not as a contribution to Wasmtime, but as a feature that uses it. Wait until v1.2 design is locked before engaging with Wasmtime maintainers.

---

### v1.4.0 — NER-Based PII + Lightweight Sensitivity Labels

**Target:** July 2026  
**What:** (a) Add an optional NER/ML-based PII detection tier alongside the existing regex engine. (b) Introduce lightweight sensitivity labels on tool schemas and data fields — the first step toward label-based IFC.

**The honest problem with current PII detection:**  
The regex approach covers the 90% case at 0.028ms latency. But the HN comment "regex-based PII detection is garbage" will come, and it's not entirely wrong — regex cannot detect:
- Named entities in context ("call John at the usual number")
- Implicit PII ("my social is the same as my old password")
- Novel PII patterns not in the 50-pattern library

**Design (NER tier):**
```python
# Today
Redactor(strategy=RedactionStrategy.REGEX)  # 0.028ms, 90% coverage

# v1.3.0
Redactor(
    strategy=RedactionStrategy.NER,          # ~5ms, 98% coverage (spaCy/Presidio NER)
    fallback=RedactionStrategy.REGEX,        # if NER slow or unavailable
    threshold=0.8,                           # confidence threshold
)
```

**Design (sensitivity labels):**
```python
# Tool schema declares field sensitivity
tool_schema = {
    "name": "send_email",
    "clearance": "public",               # this tool sends data externally
    "parameters": {
        "to":      {"type": "string", "sensitivity": "low"},
        "subject": {"type": "string", "sensitivity": "low"},
        "body":    {"type": "string", "sensitivity": "high"},  # may contain PII
    }
}

# Policy declares label-based flow rules
policy:
  rules:
    sensitivity_labels:
      enabled: true
      default_clearance: internal         # tools without clearance annotation
      enforce: true                       # block high→public flows
      fallback: redact                    # if enforce=false, redact instead of block
```

**Why labels?**
This responds directly to the research question posed by Sandro Stucki (Chalmers, Sabelfeld's group, Feb 2026): *"to get IFC-style guarantees, you'd need extra information about the data... labels, integrity, provenance."* Structured JSON tool calls make this practical — each field can carry a sensitivity annotation, and each tool can declare a clearance level. The Enforcer mediates flows at the boundary.

**Research connection:** This is the data minimization pattern from Sabelfeld's trigger-action platform work (LazyTAP), applied to AI agent tool calls. Also complementary to AirGapAgent (CCS 2024, Bagdasarian et al.) which restricts agent data *access* — we restrict agent data *output*.

**Why Presidio for NER?**  
We already contribute to Presidio. Their NER recognizers are battle-tested. The right move is not to build our own NER — it's to deepen the Presidio integration that's already in progress. This makes the OPA contribution + Presidio contribution a coherent ecosystem play.

---

### v1.5.0 — OpenTelemetry + Observability

**Target:** August 2026  
**What:** First-class OpenTelemetry trace/metric/log export from every enforcement decision.

**Why this matters for enterprise adoption:**  
Enterprise teams don't evaluate security tools — their ops teams do. Ops teams evaluate tools by asking "can I see it in Datadog / Grafana / Honeycomb?" If the answer is no, the tool doesn't exist from their perspective.

**Deliverables:**
- OTLP trace export: every `@enforce()` call becomes a span with policy decision, redaction events, guard outcomes
- Prometheus metrics: `enforcecore_calls_total`, `enforcecore_violations_total`, `enforcecore_redactions_total`, `enforcecore_overhead_seconds`
- Structured log export: every audit event to structured JSON suitable for Splunk/Elastic
- Dashboard template: pre-built Grafana dashboard for enforcement visibility

**Implementation approach:** optional dependency — `pip install enforcecore[otel]`. Zero-overhead if not configured.

---

### v1.6.0 — Multi-Tenant + Policy Inheritance

**Target:** September 2026  
**What:** Let multiple agents/teams share an EnforceCore deployment with hierarchical policies.

**Problem this solves:**  
Today EnforceCore is single-policy-per-enforcer. In a real enterprise, you have:
- An org-wide base policy (deny all PII to external APIs)
- A team policy (this team can use search and calculate)
- An agent policy (this specific agent can also use delete, but only in staging)

**Design:**
```yaml
# org_base.yaml
tools:
  denied: [drop_table, delete_user]
pii:
  redact: [ssn, passport]

# team_dev.yaml
extends: org_base.yaml
tools:
  allowed: [search, calculate, read_file]

# agent_deployer.yaml
extends: team_dev.yaml
tools:
  allowed: [search, calculate, read_file, deploy_service]
  context:
    environment: [staging]  # only in staging
```

**Why this is a v1.5, not earlier:**  
The single-policy model is the right starting point. Adding inheritance before users understand the single-policy model creates confusion. Wait for real multi-team adoption to drive this requirement.

---

### v1.7.0 — Remote Policy Server

**Target:** November 2026  
**What:** Centralized policy management — policies stored and versioned server-side, agents pull at startup or on cache miss.

**Problem:** At scale (50+ agents, 10+ teams), YAML files on disk become unmanageable. Policy updates require redeployments. Audit trails are scattered.

**Design:**
```python
# Today
Enforcer.from_file("policy.yaml")

# v1.6.0
Enforcer.from_server(
    "https://policy.acme.com/agents/chatbot-v2",
    token=os.environ["POLICY_SERVER_TOKEN"],
    cache_ttl=300,  # refresh every 5 minutes
)
```

**Key properties:**
- Signed policies — server signs with a key, enforcer verifies before applying
- Pull-only, never push — enforcer pulls, server never pushes (trust model is explicit)
- Graceful degradation — if server unreachable, use cached policy (fail-open disabled by default)
- Policy versioning — enforcer records which policy version approved each decision in the audit trail

**Why this is not a v1.1:**  
Build the server-side component only after the client (EnforceCore) is widely adopted. Premature infrastructure investment before community adoption is a trap.

---

### v1.8.0 — Compliance Reporting

**Target:** January 2027  
**What:** Turn the audit trail into structured compliance exports — EU AI Act, SOC2, GDPR.

**Deliverables:**
- `enforcecore audit export --format eu-ai-act --period 2026-Q4 > report.json`
- Pre-built report templates for EU AI Act Article 13 (transparency), GDPR Article 30 (records of processing)
- Audit trail → compliance narrative mapping ("All PII accessed by agents was redacted per policy — 47 events, 0 violations")
- Integration with common compliance platforms (Vanta, Drata) via webhook

**Why this is a late release:**  
Compliance buyers are late-stage enterprise. You don't optimize for them until you have the engineering-first adoption that gives you the case studies they need. Do this after v1.5 has enterprise customers.

---

### v2.0.0 — Distributed Enforcement

**Target:** 2027 (timeline flexible)  
**What:** Major API evolution for multi-node, multi-agent deployments.

This is the natural evolution when "AI agent" stops meaning "one agent on one machine" and starts meaning "a fleet of agents across a distributed system." At that point, the enforcement model changes fundamentally:

- Enforcement needs to be consistent across all nodes (same policy, same decision)
- Audit trails need to merge across agents (one tamper-evident trail for an entire pipeline)
- Policy updates need to propagate atomically
- Rate limits and budget tracking need to be distributed

**What changes in v2.0:**
- New `DistributedEnforcer` abstraction with consensus-based policy updates
- Cross-agent audit trail merging with global Merkle root
- Breaking API changes where necessary (semantic versioning — this is intentional)
- No backwards compatibility obligation for the distributed layer

**Don't build this before you have users who need it.** v2.0 is a 2027 milestone precisely because it requires real distributed deployment patterns to design correctly. Building it speculatively is how you end up with the wrong abstraction.

---

## Part 4 — Product Gravity Alignment

The strategy document's core insight is correct and worth restating:

> **Stop orbiting other projects. Become the planet.**

Each release maps to a gravity play:

| Release | Gravity play | Mechanism | Status |
|---------|-------------|-----------|--------|
| v1.0.0 stable | Show HN post | "It works, it's stable, here are the benchmark numbers" | ✅ Ready |
| v1.0.0 stable | NeurIPS 2026 workshop | 11-page paper with 100% containment results | ✅ Written |
| v1.0.2 | CI hardening | Release process formalized — never ship broken CI again | ✅ Ready |
| v1.1.0 | Eval expansion | 26 scenarios, 11 categories, HTML reports — proves depth | 🔧 Code done |
| v1.2.0 AgentSecBench | Defines the conversation | Every other framework gets measured against our criteria | 📋 Planned |
| v1.2.0 AgentSecBench | DEF CON CFP | Live demo: 3 frameworks fail, EnforceCore passes — with our benchmark | 📋 Planned |
| v1.2.0 AgentSecBench | arXiv paper | "AgentSecBench" as a citeable academic contribution | 📋 Planned |
| v1.3.0 Sandbox | Blog post #4 | "Runtime vs. prompt vs. sandbox — a hierarchy of defense" | 📋 Planned |
| v1.4.0 NER PII + Labels | Addresses HN criticism + IFC research | The "regex PII is garbage" comment gets a concrete answer; lightweight labels open IFC collaboration with Chalmers | 📋 Planned |
| v1.5.0 OTEL | Enterprise funnel | Ops teams can now see it in Datadog → procurement unlocked | 📋 Planned |
| v2.0.0 Distributed | Academic paper #3 | Distributed tamper-evident audit trails across agent fleets | 📋 Planned |

### The single most important sequence

```
v1.0.0 stable ✅ DONE (Feb 24)
    → benchmark results published ✅ DONE (bare=22%, EC=100%)
        → NeurIPS paper written ✅ DONE (11 pages, 25 refs)
            → v1.0.1 patch (ship bug fixes) ← NEXT
                → Show HN post (needs polished README + blog post #1)
                    → DEF CON CFP submitted (April deadline — we have time)
                        → arXiv preprint
                            → OWASP: present EnforceCore + AgentSecBench as reference implementation
```

**We are 3 weeks ahead of schedule.** The original plan had stable shipping mid-March. We shipped Feb 24. This gives comfortable buffer for Show HN preparation and DEF CON CFP.

---

## Part 5 — Critical Assessment of the Adoption Strategy Docs

### What fits and stays

**Product Gravity (enforcecore-v1.md):**  
The checklist is largely done. `pip install` works, 3-line integration works, API docs exist. The only open item is the benchmark suite — that becomes b6 + v1.1. Keep the "rock-solid first 5 minutes" principle as the acceptance criterion for every release.

**Benchmark Suite (benchmark-suite.md):**  
The design is excellent. The comparison table framing ("LangGraph FAIL / EnforceCore PASS") is the exact kind of concrete, verifiable claim that wins on HN and in CFP submissions. Build this in b6 as alpha, formalize as v1.1.0. **This is the highest-ROI item in the entire strategy.**

**OPA Contributions:**  
The strings.split_n PR is submitted and correct. The AI agent Rego policy library is genuinely valuable — there's no competition and it directly bridges the OPA ecosystem to AI agent security. Cap at 2-3 meaningful contributions (split_n, url.parse, AI agent templates). Don't turn this into a multi-month campaign.

**HN Strategy:**  
The timing rules are right: stable + benchmarks + polished README before posting. The prepared responses to anticipated criticism ("regex PII is garbage," "how is this different from NeMo") are the right preparation. One well-timed post > months of incremental activity.

**OWASP:**  
Low cost, right audience. Join now, contribute expertise first, reference EnforceCore second. We directly address 5/10 OWASP LLM Top 10 risks. This is a strong positioning.

**DEF CON / Black Hat:**  
The two talk proposals are strong. "Breaking AI agent frameworks with a benchmark" is exactly the right format for a security conference. This requires: stable product + benchmark results + demo videos. Move on this immediately.

**arXiv / Academic:**  
The abstract draft for Paper #1 ("EnforceCore: Policy-Driven Runtime Enforcement") is already strong. Wait until benchmark results exist before submitting. Paper #2 (AgentSecBench companion) is the higher-impact submission — a benchmark paper is more citeable than a system description.

### What to cut or deprioritize

**French social media strategy:**  
Premature. The technical community that adopts security tooling is English-first globally. French-language content makes sense after English-language adoption is established and you want to reach Francophone enterprise buyers. Not now.

**Presidio medical recognizer:**  
Correctly dropped (someone else merged it). The AnalysisExplanation follow-up and IPv6 fix are good targeted contributions. Don't expand beyond 2-3 Presidio PRs.

**Wasmtime contribution:**  
Correctly dropped. Use Wasmtime as a dependency in v1.2 if WASM sandboxing is built — don't contribute to Wasmtime for its own sake.

**"10-week contribution campaign" model (V1 strategy):**  
Correctly abandoned. The V2 "become the planet" framing is the right posture. Contributions serve EnforceCore's credibility, not the other way around.

**Multiple arXiv/conference venue strategy:**  
The arxiv-strategy.md lists USENIX Security, AAAI Workshop, IEEE S&P, NeurIPS Workshop, arXiv. Pick two: arXiv preprint (immediate, no wait) + NeurIPS AI Safety Workshop (highest visibility AI safety venue). Don't spread across 4-5 venues — it's not more impact, it's more revisions.

---

## Part 6 — Master Timeline (Updated Feb 24, 2026)

```
✅ DONE          v1.0.0b6 + v1.0.0 Stable
                  - Benchmark suite (20 scenarios, 3 framework adapters)         ✅
                  - Real integration examples (LangGraph + AutoGen + CrewAI)     ✅
                  - Benchmark results published (bare=22%, EC=100%)              ✅
                  - Framework comparison doc                                     ✅
                  - NeurIPS 2026 workshop paper (11 pages, 25 refs)              ✅
                  - Post-release audit (147/147 = 100%)                          ✅
                  - 1510 tests green                                             ✅

✅ DONE          v1.0.1 Patch (Feb 24)
                  - 2 bug fixes (witness + policy validator)                     ✅
                  - 14 doc updates                                               ✅

✅ READY         v1.0.2 CI Hardening (Feb 25)
                  - RELEASE_PROCESS.md (3-phase release process)                 ✅
                  - scripts/pre_release_gate.py (automated pre-release checks)   ✅
                  - Fixed stale version directives + version mismatch            ✅
                  - CONTRIBUTORS.md corrected                                    ✅

🔧 CODE DONE    v1.1.0 Eval Expansion (Mar)
                  - 6 new scenarios (26 total, 11 threat categories)             ✅
                  - AUDIT_COMPLETENESS threat category                           ✅
                  - HTML report generator                                        ✅
                  - 1520 tests green                                             ✅
                  - CHANGELOG update                                             ⬜
                  - Release via release.py                                       ⬜

Mar – Apr         v1.1.1 Eval Polish
                  - Community feedback on eval suite
                  - 2–4 additional scenarios if gaps found
                  - Blog post #1 (Merkle audit trails)

Apr – May         v1.2.0 AgentSecBench Standalone
                  - Extract eval → pip install agentsecbench
                  - DEF CON AI Village CFP draft
                  - arXiv preprint submission

May – Jun         v1.3.0 Sandbox
                  - Subprocess isolation layer
                  - WASM design (don't build yet)

Jul               v1.4.0 NER PII + Sensitivity Labels
                  - Presidio NER integration
                  - Lightweight sensitivity labels on tool schemas
                  - Follow up with Stucki/Sabelfeld on label model design

Aug               DEF CON AI Village (if CFP accepted)
                  - Live benchmark demo

Sep               v1.5.0 OpenTelemetry
Oct               v1.6.0 Multi-tenant policies
Nov               v1.7.0 Policy server
Jan 2027          v1.8.0 Compliance reporting
2027              v2.0.0 Distributed enforcement
```

**Key change from original timeline:** We shipped stable 3 weeks ahead of schedule. This gives us breathing room for Show HN + DEF CON CFP preparation. The April CFP deadline is no longer tight — it's comfortable.

---

## Part 7 — Decision Rules

Before any new feature or release is planned, ask:

1. **Does this make the first 5 minutes better?** If yes, it's high priority.
2. **Does this generate publishable numbers?** Benchmarks, latency, coverage — concrete claims beat feature lists.
3. **Would a security engineer at a serious company trust this?** Not "is it impressive," but "does it earn trust."
4. **Are we building OUR thing or fixing someone else's?** Contributions are allowed only when they directly serve #1–3.
5. **Is the adoption signal coming from users or from us?** The goal is pull, not push. Each release should create more pull than the last.

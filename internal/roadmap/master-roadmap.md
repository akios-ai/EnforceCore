
Here's the critical summary of what I wrote and why:

**Pre-stable (b6 → stable):**
You need exactly **one more beta** (b6), not several. The product is functionally complete. b6 is purely about generating benchmark numbers — because the benchmark is the foundation of every other adoption play. Stable follows ~2 weeks later.

**The DEF CON deadline is a forcing function.** CFPs close around April 2026. That means you need stable + benchmark results by **mid-March at the latest**, or you wait until Black Hat 2027. This makes b6 the most time-sensitive thing on the board right now.

**Post-stable milestones** (10 steps to v2.0):
1. **v1.1 AgentSecBench** — the single highest-leverage release. This is what positions you as the standards body, not just a product.
2. **v1.2 Sandbox** — closes the one real security gap (post-decision enforcement)
3. **v1.3 NER PII** — answers the "regex is garbage" criticism with a concrete upgrade
4. **v1.4 OpenTelemetry** — the ops team unlock for enterprise
5. **v1.5 Multi-tenant** → **v1.6 Policy server** → **v1.7 Compliance** → **v2.0 Distributed**

**What I cut from the strategy docs:** French social media (too early), Wasmtime contributions (correctly dropped — use it as a dependency later, don't contribute to it), the 4-5 conference venue shotgun approach (pick arXiv + NeurIPS workshop only), and the V1 "10-week contribution campaign" model (already abandoned).


# EnforceCore — Master Roadmap

**Written:** February 24, 2026  
**Current version:** v1.0.0b5 (live on PyPI, CI green)  
**North star:** Become THE runtime security layer for AI agents — the thing serious teams add before going to production.

---

## Part 1 — Honest State of the Product

### What is done and genuinely good

| Area | State |
|------|-------|
| Core enforcement pipeline | Solid. Policy → Redactor → Guard → Audit. |
| Merkle-chained audit trail | 0.0008ms per event. Tamper-evident. Append-only OS flags. Hash witnesses. |
| PII redaction | 50+ patterns, regex-based, ~0.028ms short text. Known limit: false positives. |
| Framework integrations | LangGraph, AutoGen, CrewAI decorators exist. |
| API surface | Pruned to 30 core symbols (from 110). Stable since b1. |
| Security audit | All known gaps closed (b1–b5). Zero open items in SECURITY.md. |
| Tests | 1510, all passing. CI green on 3.11/3.12/3.13. |
| Docs | API reference, migration guide, threat model, integration guides, formal invariants. |
| PyPI | `pip install enforcecore` works. 30 public symbols. No internal leakage. |

### What is missing before stable

1. **No external user has run the beta.** This is the only honest blocker. The product is functionally complete, but "battle-tested" requires at least one non-author trying it in the real world and hitting real edges. Havelund is the most likely first tester. HN is the second path.

2. **Benchmark suite exists only as a design doc.** The framework in `product-gravity/benchmark-suite.md` is well-designed but not built. This is the highest-leverage missing piece — not because stable requires it, but because it drives every other adoption vector.

3. **Integration examples are decorators wrapping mock functions.** The LangGraph/AutoGen/CrewAI adapters work, but there are no copy-paste-runnable examples that use the *actual* framework against a *real* LLM call. This is what developers evaluate when they land on the repo.

### What does NOT need to change for stable

- The API surface — it's already frozen and clean
- The security model — all known gaps are closed
- The performance — 0.056ms E2E overhead is well under any practical threshold
- The test coverage — 1510 tests with property-based testing is strong

---

## Part 2 — Path to v1.0.0 Stable

### v1.0.0b6 — Pre-stable Hardening

**Theme:** Make the product undeniable before the public launch.  
**Target:** ~2 weeks from now (mid-March 2026)

| Item | What | Why it matters |
|------|------|----------------|
| Benchmark suite alpha | Build `enforcecore/benchmarks/` — the test runner, 10 core scenarios, adapters for LangGraph/AutoGen/CrewAI, HTML report output | This generates the numbers that make every other adoption play work |
| Real integration examples | Working examples in `examples/` that use actual LangGraph/AutoGen/CrewAI pipelines with a real (or mocked-at-framework-level) tool call | Developers copy-paste-run to evaluate. This is the first 5 minutes of every adoption decision. |
| Publish benchmark results | Run the suite, write up the comparison table (LangGraph FAIL / AutoGen FAIL / CrewAI FAIL / EnforceCore PASS) | Required for HN post, DEF CON CFP, arXiv abstract |
| Final README pass | Fix the diagram rendering, add benchmark badge, sharpen the quickstart | One chance to make a first impression on HN |
| Havelund outreach + testing | Send Havelund the beta with specific questions — does the Merkle chain satisfy his requirements? | Satisfies the "external tester" stable criterion and produces a credible academic citation |

**Definition of done:** benchmark suite produces publishable results, Havelund has been contacted, integration examples run end-to-end, all 1510+ tests pass.

---

### v1.0.0 — Stable Release

**Target:** Late March 2026, immediately after b6 validation  
**Trigger:** b6 complete + at least one external tester response (Havelund OR first HN comments)

**Entry criteria (from path-to-stable.md — all must be green):**

- [ ] At least one external user has tested the beta
- [ ] All beta bug reports resolved
- [ ] Security review by at least one external reviewer (Wallach qualifies — b4 design feedback is documented)
- [ ] Performance benchmarks stable and published
- [ ] README, docs, examples polished
- [ ] PyPI metadata finalized
- [ ] CHANGELOG comprehensive

**What the stable release unlocks:**
- HN "Show HN" post (never post alpha/beta — HN penalizes for it)
- DEF CON AI Village CFP submission (deadline ~April 2026 — tight)
- arXiv preprint
- OWASP community engagement with a stable reference
- Blog post #3 (Show HN companion post)

**Stable contract from this point:** semantic versioning, breaking changes only in v2.0, security patches backported to v1.0.x.

---

## Part 3 — Post-Stable Roadmap

### Release Overview

| Version | Theme | Target | Adoption lever |
|---------|-------|--------|----------------|
| v1.0.x | Patch series | Ongoing | Community trust |
| v1.1.0 | AgentSecBench public | May 2026 | Defines the conversation |
| v1.2.0 | Subprocess / WASM sandbox | June 2026 | Closes the last real security gap |
| v1.3.0 | NER-based PII | July 2026 | Answers "regex PII is garbage" |
| v1.4.0 | OpenTelemetry + observability | Aug 2026 | Enterprise deployability |
| v1.5.0 | Multi-tenant + policy inheritance | Sep 2026 | Enterprise sales prerequisite |
| v1.6.0 | Policy server (remote + signed) | Nov 2026 | Ops teams need this for scale |
| v1.7.0 | Compliance reporting | Jan 2027 | EU AI Act / SOC2 audit buyers |
| v2.0.0 | Distributed enforcement | 2027 | Major: multi-node, multi-agent architectures |

---

### v1.0.x — Patch Series (Ongoing)

Purely reactive. Fix bugs reported by the community, backport security patches, never add features.

**What to watch:** HN comment patterns will reveal real friction points. Anything that generates 3+ identical complaints gets a patch within 1 week. This is the signal you can't invent in advance.

---

### v1.1.0 — AgentSecBench: The Benchmark

**Target:** May 2026  
**What:** Formalize the benchmark suite (built in b6) as a first-class public tool.

This is the single highest-leverage release in the entire roadmap. Here's why:

```
Nobody has defined "secure AI agent execution" in measurable terms.
If we create the benchmark, we define the conversation.
Every framework gets measured against OUR criteria.
```

**Deliverables:**
- `pip install agentsecbench` (separate package, co-maintained under akios-ai)
- 25+ security scenarios across 5 categories: tool safety, PII handling, prompt injection resistance, resource governance, audit completeness
- Framework adapters: LangGraph, AutoGen, CrewAI, + EnforceCore
- HTML comparison report generator
- Published results: "No framework provides built-in protection against any evaluated scenario"

**Why a separate package matters:** It lets EnforceCore *be the reference implementation* that passes the benchmark, while AgentSecBench can be adopted by other projects. It also positions akios-ai as the standards body, not just a product company.

**Adoption plays this unlocks:**
- arXiv paper #2 ("AgentSecBench: A Benchmark Suite for Evaluating Security in AI Agent Frameworks")
- DEF CON AI Village talk using the live benchmark demo
- Blog post #5: "We benchmarked 3 agent frameworks. They all failed."
- OPA contribution: AI agent policy templates that pass AgentSecBench scenarios

---

### v1.2.0 — Subprocess / WASM Sandbox

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

### v1.3.0 — NER-Based PII Detection

**Target:** July 2026  
**What:** Add an optional NER/ML-based PII detection tier alongside the existing regex engine.

**The honest problem with current PII detection:**  
The regex approach covers the 90% case at 0.028ms latency. But the HN comment "regex-based PII detection is garbage" will come, and it's not entirely wrong — regex cannot detect:
- Named entities in context ("call John at the usual number")
- Implicit PII ("my social is the same as my old password")
- Novel PII patterns not in the 50-pattern library

**Design:**
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

**Why Presidio?**  
We already contribute to Presidio. Their NER recognizers are battle-tested. The right move is not to build our own NER — it's to deepen the Presidio integration that's already in progress. This makes the OPA contribution + Presidio contribution a coherent ecosystem play.

---

### v1.4.0 — OpenTelemetry + Observability

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

### v1.5.0 — Multi-Tenant + Policy Inheritance

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

### v1.6.0 — Remote Policy Server

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

### v1.7.0 — Compliance Reporting

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

| Release | Gravity play | Mechanism |
|---------|-------------|-----------|
| v1.0.0 stable | Show HN post | "It works, it's stable, here are the benchmark numbers" |
| v1.1.0 AgentSecBench | Defines the conversation | Every other framework gets measured against our criteria |
| v1.1.0 AgentSecBench | DEF CON CFP | Live demo: 3 frameworks fail, EnforceCore passes — with our benchmark |
| v1.1.0 AgentSecBench | arXiv paper | "AgentSecBench" as a citeable academic contribution |
| v1.2.0 Sandbox | Blog post #4 | "Runtime vs. prompt vs. sandbox — a hierarchy of defense" |
| v1.3.0 NER PII | Addresses HN criticism | The "regex PII is garbage" comment gets a concrete answer |
| v1.4.0 OTEL | Enterprise funnel | Ops teams can now see it in Datadog → procurement unlocked |
| v2.0.0 Distributed | Academic paper #3 | Distributed tamper-evident audit trails across agent fleets |

### The single most important sequence

```
v1.0.0 stable
    → benchmark results published (b6 deliverable, formalized in v1.1)
        → Show HN post (stable required, benchmark numbers required)
            → DEF CON CFP submitted (April deadline — needs benchmark results NOW)
                → arXiv preprint
                    → OWASP: present EnforceCore + AgentSecBench as reference implementation
```

**The DEF CON deadline changes the timeline.** CFPs typically close April 2026 for the August event. That means:
- b6 benchmark alpha needs to produce publishable numbers by **early March 2026**
- stable needs to ship **before mid-March 2026**
- DEF CON submission needs **benchmark results + stable product** = mid-March at the latest

This is tight but achievable. Miss this window and the next opportunity is Black Hat 2027.

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

## Part 6 — Master Timeline

```
Feb 24 – Mar 7    v1.0.0b6
                  - Benchmark suite alpha (10 core scenarios, 3 framework adapters)
                  - Real integration examples (LangGraph + AutoGen with actual framework)
                  - Run benchmarks, generate results
                  - Havelund email (attach benchmark results, ask for feedback on Merkle chain)
                  - OPA strings.split_n PR merged (already submitted)

Mar 8 – Mar 21    v1.0.0 Stable
                  - Final pre-stable checklist
                  - Blog post #1 live (Merkle audit trails)
                  - Release stable
                  - Show HN post (Tuesday 9am EST)

Mar 22 – Apr 4    Post-launch response + DEF CON
                  - Respond to HN comments within 1 hour
                  - Fix any quick bugs from community (patch releases)
                  - DEF CON AI Village CFP submission (deadline ~April 1-15)
                  - Blog post #2 (prompt-level safety broken)
                  - OWASP Slack: join, read, don't post about EnforceCore yet

Apr 5 – May 2     v1.1.0 AgentSecBench
                  - Full benchmark suite: 25 scenarios, HTML reports, pip installable
                  - arXiv preprint submitted
                  - Blog post #3: "We benchmarked 3 agent frameworks. They all failed."
                  - OWASP: share benchmark results in relevant discussions

May – Jun         v1.2.0 Sandbox
                  - Subprocess isolation layer
                  - WASM design (don't build yet)
                  - OPA AI agent Rego library contribution

Jul               v1.3.0 NER PII
                  - Presidio NER integration
                  - Deepen Presidio contribution alignment

Aug               DEF CON AI Village (if CFP accepted)
                  - Live benchmark demo
                  - Release conference materials open-source

Sep               v1.4.0 OpenTelemetry
Oct               v1.5.0 Multi-tenant policies
Nov               v1.6.0 Policy server
Jan 2027          v1.7.0 Compliance reporting
2027              v2.0.0 Distributed enforcement
```

---

## Part 7 — Decision Rules

Before any new feature or release is planned, ask:

1. **Does this make the first 5 minutes better?** If yes, it's high priority.
2. **Does this generate publishable numbers?** Benchmarks, latency, coverage — concrete claims beat feature lists.
3. **Would a security engineer at a serious company trust this?** Not "is it impressive," but "does it earn trust."
4. **Are we building OUR thing or fixing someone else's?** Contributions are allowed only when they directly serve #1–3.
5. **Is the adoption signal coming from users or from us?** The goal is pull, not push. Each release should create more pull than the last.

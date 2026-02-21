# EnforceCore — Roadmap (v1.0.x)

## Release Philosophy

We ship incrementally. Each v1.0.x release adds one well-tested, well-documented component. No release ships without:
- Full test coverage for the new component
- Updated documentation
- At least one working example
- Passing CI on Linux and macOS

This is not a "dump everything and tag v1.0" approach. Each release is usable on its own, and each one makes the framework meaningfully more capable.

---

## v1.0.0 — Core Enforcer + Policy Engine ✅ Shipped
**Focus:** The absolute minimum viable enforcement framework.

### What ships:
- **Policy Engine**
  - Pydantic v2 policy models with YAML loading
  - Pre-call rule evaluation (allowed/denied tools, basic conditions)
  - Policy validation and schema enforcement
- **Enforcer**
  - `@enforce(policy=...)` decorator (sync + async)
  - `enforce()` async context manager
  - `EnforcementViolation` exception hierarchy
  - Call interception and allow/block decisions
- **Core types and exceptions**
- **Configuration** via `pydantic-settings` (env vars + YAML)
- **Basic structured logging** via `structlog`
- **Test suite** for all core components
- **Documentation:** README, quickstart, policy reference
- **CI:** GitHub Actions (pytest on Linux + macOS, ruff, mypy)

### What a user can do after v1.0.0:
```python
from enforcecore import enforce

@enforce(policy="my_policy.yaml")
async def search_web(query: str) -> str:
    return await external_api.search(query)

# If "search_web" is not in the policy's allowed_tools → blocked
# If it is allowed → executes normally
```

### Definition of Done:
- [x] `PolicyEngine` loads and validates YAML policies
- [x] `@enforce()` intercepts sync and async calls
- [x] Allowed calls pass through, denied calls raise `EnforcementViolation`
- [x] 97% test coverage on core module (94 tests)
- [x] README with quickstart guide
- [ ] Published to PyPI as `enforcecore==1.0.0`

---

## v1.0.1 — PII Redactor ✅ Shipped
**Focus:** Real-time PII detection and redaction on inputs and outputs.

### What ships:
- **Redactor module** (`enforcecore.redactor`)
  - Lightweight regex-based PII detection — zero heavy deps (no spaCy, no Presidio)
  - 5 PII categories: email, phone, SSN, credit card, IP address
  - 4 configurable redaction strategies: placeholder (`<EMAIL>`), mask (`****@****.***`), hash (`[SHA256:...]`), remove
  - Pre-call input redaction (string args + kwargs)
  - Post-call output redaction
  - Overlap resolution (keeps longer match)
  - `DetectedEntity`, `RedactionResult` data classes with event metadata
  - ~0.1–0.5ms per call (compiled regex, no NLP pipeline)
- **Enforcer pipeline integration:**
  - Automatic redaction wired into `enforce_sync` and `enforce_async`
  - `_build_redactor()` creates Redactor from policy config
  - Redaction counts logged in structured log events
- **Policy extension:** `pii_redaction` section in policy YAML (enabled, categories, strategy)
- **Tests:** 67 new tests (redactor unit + enforcer integration), 161 total, 97% coverage
- **Example:** `examples/pii_redaction.py` — 5 demo patterns (standalone, detection, selective, pipeline, decorator)

### What a user can do after v1.0.1:
```python
@enforce(policy="policy_with_pii.yaml")
async def call_llm(prompt: str) -> str:
    # If prompt contains "john.doe@email.com" → auto-redacted before call
    # If response contains SSN → auto-redacted before returning
    return await llm.generate(prompt)
```

### Definition of Done:
- [x] Regex engine detects 5 PII categories (email, phone, SSN, credit card, IP)
- [x] 4 redaction strategies implemented and tested
- [x] Redaction works on both inputs and outputs
- [x] Policy YAML supports `pii_redaction` configuration
- [x] 161 tests passing, 97% coverage

---

## v1.0.2 — Merkle Auditor ✅ Shipped
**Focus:** Tamper-proof, cryptographically verifiable audit trails.

### What ships:
- **Auditor module** (`enforcecore.auditor`)
  - SHA-256 Merkle chain linking each audit entry to its predecessor
  - `AuditEntry` dataclass with 14 fields (tool, policy, decision, timing, redaction counts, hashes)
  - `Auditor` class — thread-safe JSONL writer with append-only semantics
  - Chain resumption from existing trail files (cross-session continuity)
  - `verify_trail()` — full chain integrity verification with error reporting
  - `load_trail()` — load entries from JSONL for analysis
  - `VerificationResult` dataclass with is_valid, chain_intact, root/head hashes, error list
  - Tamper detection: modified, deleted, inserted, or reordered entries
- **Enforcer pipeline integration:**
  - Automatic audit recording for all `enforce_sync` and `enforce_async` calls
  - Both allowed and blocked calls generate audit entries
  - Blocked entries include `violation_type` and `violation_reason`
  - Respects `settings.audit_enabled` global toggle
- **Tests:** 52 new tests (32 engine unit + 20 enforcer integration), 213 total, 96% coverage
- **Example:** `examples/audit_trail.py` — 7 demo patterns (standalone, anatomy, verification, tamper detection, pipeline, cross-session, decorator)

### What a user can do after v1.0.2:
```python
# Every enforced call automatically generates an audit entry
# The audit trail is Merkle-chained and tamper-proof

# Later, verify the trail:
from enforcecore.auditor import verify_trail
result = verify_trail("audit.jsonl")
assert result.is_valid
```

### Definition of Done:
- [x] Merkle tree correctly chains audit entries
- [x] Tamper detection works (modified/deleted/inserted/reordered entries caught)
- [x] JSONL audit file format with cross-session chain resumption
- [ ] `enforcecore verify` CLI command works
- [x] Verification tested with intentionally corrupted trails
- [x] 213 tests passing, 96% coverage

---

## v1.0.3 — Resource Guard ✅ Shipped
**Focus:** Cross-platform resource limits and hard termination.

### What ships:
- **Guard module**
  - Platform detection and abstraction layer
  - Time limits (call duration timeout — all platforms)
  - Memory limits (POSIX `setrlimit` on Linux/macOS, monitoring on Windows)
  - Cost tracking (cumulative cost across calls with configurable budget)
  - KillSwitch: hard termination on limit breach
- **Policy extension:** `resource_limits` section in policy YAML
- **Optional Linux extra:** `enforcecore[linux]` with seccomp-bpf and cgroups v2 support
- **Tests** for all resource limit types on available platforms
- **Example:** Protecting against runaway tool calls that consume too many resources

### What a user can do after v1.0.3:
```python
# policy.yaml:
# resource_limits:
#   max_call_duration_seconds: 30
#   max_memory_mb: 256
#   max_cost_usd: 5.00

@enforce(policy="policy.yaml")
async def expensive_tool(args):
    # Automatically killed if it runs > 30s
    # Automatically killed if it uses > 256MB
    # Blocked if cumulative cost > $5.00
    return await run_expensive_operation(args)
```

### Definition of Done:
- [x] Time limits work on Linux and macOS
- [x] Memory limits work on Linux and macOS (best-effort on Windows)
- [x] Cost tracking is cumulative and thread-safe
- [x] KillSwitch terminates calls cleanly on breach
- [x] Platform abstraction documented (what works where)
- [x] 284 tests passing, 96% coverage

---

## v1.0.4 — Framework Integrations ✅ Shipped
**Focus:** First-class adapters for popular agent frameworks.

### What ships:
- **Integration adapters:**
  - **LangGraph** — Custom tool wrapper that enforces policies on tool nodes
  - **CrewAI** — Decorator adapter for CrewAI tools
  - **AutoGen** — Function registration wrapper with enforcement
  - **Plain Python** — Already supported via `@enforce()` (documented patterns)
- **Each adapter includes:**
  - Working example with the target framework
  - Integration test
  - Documentation page
- **Integration guide:** "Add EnforceCore to your existing agent in 5 minutes"

### What a user can do after v1.0.4:
```python
# LangGraph example
from enforcecore.integrations.langgraph import enforced_tool

@enforced_tool(policy="policy.yaml")
def search(query: str) -> str:
    return web_search(query)

# Use in LangGraph as normal — enforcement is automatic
```

### Definition of Done:
- [x] 3 framework adapters working with examples
- [x] Each adapter tested with mock frameworks (50 tests)
- [x] Integration guide written (examples/framework_integrations.py)
- [x] No hard dependencies on any framework (adapters are optional imports)

---

## v1.0.5 — Evaluation Suite ✅ Shipped
**Focus:** Reproducible adversarial testing framework for agent containment.

### What ships:
- **Malicious agent scenario suite:**
  - Ransomware-like behavior (file encryption/deletion attempts)
  - Data exfiltration attempts (sending data to unauthorized endpoints)
  - Unauthorized tool/API abuse (calling tools not in the allowed list)
  - Policy evasion attempts (trying to circumvent resource limits)
  - Prompt injection attacks that attempt to disable enforcement
- **Test harness:**
  - Automated scenario runner
  - Comparison engine (EnforceCore vs baseline — no protection)
  - Metrics: containment rate, false positive rate, overhead
  - Reproducible results with fixed seeds and configurations
- **Benchmark suite:**
  - Overhead measurements per component
  - End-to-end latency benchmarks
  - Memory footprint analysis
- **Report generator:** Markdown report with results and charts

### What a user can do after v1.0.5:
```bash
# Run the full evaluation suite
enforcecore eval --scenarios all --output results/

# Run specific scenario
enforcecore eval --scenario data-exfiltration --policy my_policy.yaml

# Compare with baseline
enforcecore eval --compare baseline,enforcecore --output comparison.md
```

### Definition of Done:
- [x] 5+ adversarial scenarios implemented and documented
- [x] Test harness runs all scenarios automatically
- [x] Benchmark results published in docs
- [x] Comparison with "no protection" baseline
- [x] Results are reproducible (fixed seeds, documented environment)

---

## v1.0.6 — Hardening + Polish ✅ Shipped
**Focus:** Production readiness, security audit, and documentation polish.

### What ships:
- **Security review** of all enforcement paths (ensure fail-closed behavior)
- **Edge case hardening:**
  - Recursive/nested enforcement calls (contextvars-based scope tracking)
  - Concurrent enforcement with shared state (threading.Lock on policy cache)
  - Large payload handling (input size validation, 10 MB default limit)
  - Unicode/encoding edge cases in redaction (NFC, homoglyphs, URL/HTML encoding)
- **Tool name validation** (reject empty, overlength, or invalid-char names)
- **Dev-mode gating** (fail_open emits RuntimeWarning without ENFORCECORE_DEV_MODE)
- **Deep recursive PII redaction** (nested dict/list/tuple/set traversal)
- **Auditor improvements** (max_entries for load_trail, optimized resume for large files)
- **Documentation polish:**
  - FAQ guide (docs/faq.md)
  - Troubleshooting guide (docs/troubleshooting.md)
  - Updated API reference with Hardening section
- **Stable API declaration:** After v1.0.6, the public API is considered stable

### Definition of Done:
- [x] All known edge cases documented and tested
- [x] No fail-open paths in enforcement logic (dev-mode gated)
- [x] API reference is complete (68 public exports documented)
- [x] Performance meets documented targets
- [x] README, docs, and examples are polished and consistent
- [x] 544 tests passing, 96% coverage

---

## v1.0.7 — Plugin & Extensibility System ✅ Shipped
**Focus:** Make EnforceCore extensible. Hooks, custom patterns, secret detection, pluggable audit backends.

### What ships:
- **Hook system** (`enforcecore.plugins.hooks`)
  - Pre-call, post-call, on-violation, on-redaction lifecycle hooks
  - `@on_pre_call`, `@on_post_call`, `@on_violation`, `@on_redaction` decorators
  - `HookRegistry` class for programmatic hook registration
  - Both sync and async hooks supported (async hooks auto-awaited)
  - Hooks receive typed context objects with full call metadata
  - Hooks can modify context, add metadata, or abort calls
  - Global and per-policy hook scoping
- **Custom PII patterns** (`enforcecore.redactor.patterns`)
  - `PatternRegistry` — register domain-specific regex patterns at runtime
  - Each pattern: category name, compiled regex, optional validator callable
  - Auto-integrated into the existing `Redactor.detect()` pipeline
  - Built-in patterns preserved; custom patterns additive
- **Secret detection** (`enforcecore.redactor.secrets`)
  - 7 built-in secret categories: AWS access keys, AWS secret keys, GitHub tokens, generic API keys,
    Bearer/JWT tokens, private keys (PEM), passwords in URLs
  - Integrated as redaction categories alongside PII
  - Configurable via policy YAML (`secret_detection.enabled`, `secret_detection.categories`)
- **Pluggable audit backends** (`enforcecore.auditor.backends`)
  - `AuditBackend` abstract base class with `write()` and `close()`
  - `JsonlBackend` — refactored from existing `Auditor` (default)
  - `NullBackend` — discard writes (for testing)
  - `CallbackBackend` — send entries to user-provided callable (for custom pipelines)
  - `Auditor` accepts `backend=` parameter for custom destinations
- **Examples:** Plugin patterns, custom redaction, secret scanning, audit to callback

### What a user can do after v1.0.7:
```python
from enforcecore.plugins.hooks import on_violation, HookRegistry

@on_violation
def alert_on_block(ctx):
    slack.post(f"BLOCKED: {ctx.tool_name} by {ctx.policy_name}")

# Custom PII pattern
from enforcecore.redactor.patterns import PatternRegistry
PatternRegistry.register("employee_id", r"EMP-\d{6}", category="internal_id")

# Secret detection is automatic
# AWS keys, GitHub tokens, etc. redacted alongside PII

# Custom audit backend
from enforcecore.auditor.backends import CallbackBackend
backend = CallbackBackend(lambda entry: send_to_siem(entry))
auditor = Auditor(backend=backend)
```

### Definition of Done:
- [x] Hook lifecycle works for all 4 events (pre, post, violation, redaction)
- [x] Custom patterns detected and redacted in enforcer pipeline
- [x] 7 secret categories detected with low false-positive rate
- [x] Audit backend interface works with custom implementations
- [x] Backward compatible — existing code works without changes
- [x] Tests passing, 96%+ coverage

---

## v1.0.8 — Deep Inspection & Network Enforcement ✅ Shipped
**Focus:** Move beyond tool-name gating. Inspect arguments, filter content, enforce network boundaries, rate-limit calls.

### What ships:
- **Argument-level rules** (`enforcecore.core.rules`)
  - Content rules: block calls where arguments match dangerous patterns
  - Built-in rules: shell injection (`rm -rf`, `; sudo`), path traversal (`../`),
    SQL injection fragments, code execution patterns (`exec()`, `eval()`)
  - Custom rules via regex or callable predicates
  - Policy YAML `content_rules` section with named rule sets
- **Network enforcement**
  - `DomainPolicy` (already modeled) finally enforced at runtime
  - Domain allow/deny lists checked against URL arguments
  - Optional outbound request interception (requires `httpx` or `requests` hook)
- **Rate limiting** (`enforcecore.guard.ratelimit`)
  - Per-tool call rate limits (e.g., max 10 calls/minute to `search_web`)
  - Global call rate limits across all tools
  - Sliding window algorithm (thread-safe)
  - Policy YAML `rate_limits` section
- **Output content filtering**
  - Block responses containing secrets or sensitive patterns (beyond PII)
  - Configurable content blocklist for output inspection
- **Example:** Defense-in-depth policy with content rules + network + rate limits

### What a user can do after v1.0.8:
```python
# policy.yaml:
# content_rules:
#   block_patterns:
#     - name: shell_injection
#       pattern: "rm\\s+-rf|;\\s*sudo|&&\\s*curl"
#       action: block
# network:
#   allowed_domains: ["api.openai.com", "*.internal.corp"]
#   denied_domains: ["*.malware.xyz"]
# rate_limits:
#   search_web: { max_calls: 10, window_seconds: 60 }
#   global: { max_calls: 100, window_seconds: 60 }

@enforce(policy="defense_in_depth.yaml")
async def agent_tool(command: str) -> str:
    # Blocked if command contains "rm -rf" (content rule)
    # Blocked if URL targets denied domain (network enforcement)
    # Blocked if called more than 10x/minute (rate limit)
    return await execute(command)
```

### Definition of Done:
- [x] Content rules block shell injection, path traversal, SQL injection
- [x] Domain allow/deny lists enforced on URL arguments
- [x] Rate limiting works per-tool and globally with sliding window
- [x] Output content filtering blocks secrets in responses
- [x] All rules configurable via policy YAML
- [x] Tests passing, 96%+ coverage (940 tests, 82 new)

---

## v1.0.9 — CLI & Policy Tooling  ✅ Shipped
**Focus:** Operator-facing tools. Full CLI, policy composition, dry-run mode, schema validation.

### What ships:
- **Full CLI** (`enforcecore.cli`)
  - `enforcecore validate <policy.yaml>` — validate policy schema
  - `enforcecore verify <audit.jsonl>` — verify Merkle chain integrity
  - `enforcecore eval [--scenarios ...] [--policy ...]` — run evaluation suite
  - `enforcecore info` — show version, platform, Python, installed extras
  - `enforcecore dry-run <policy.yaml> --calls <calls.jsonl>` — preview decisions
  - `enforcecore inspect <audit.jsonl> [--tail N] [--filter ...]` — explore audit trails
  - Rich terminal output with colors and tables (via `rich` + `typer`)
- **Policy composition**
  - `Policy.merge(base, override)` — layer policies (org base + project override)
  - `extends:` directive in policy YAML for inheritance
  - Merge semantics: override wins for scalars, union for lists, deep merge for dicts
- **Dry-run mode**
  - Replay a corpus of tool calls against a policy without executing
  - Shows allow/block/redact decisions for each call
  - Outputs summary statistics (block rate, redaction count, etc.)
  - Useful for policy tuning before deployment
- **Policy schema export**
  - `enforcecore schema` — export JSON Schema for policy YAML
  - Enables IDE autocompletion in policy files
- **Example:** Policy composition and dry-run workflow

### What a user can do after v1.0.9:
```bash
# Compose policies
# project_policy.yaml:
#   extends: org_base.yaml
#   allowed_tools: [search_web, write_file]

# Dry-run to preview enforcement
enforcecore dry-run project_policy.yaml --calls recorded_calls.jsonl
# Output: 142 allowed, 23 blocked, 7 redacted

# Inspect recent audit entries
enforcecore inspect audit.jsonl --tail 20 --filter decision=blocked

# Export JSON schema for IDE support
enforcecore schema > enforcecore-policy.schema.json
```

### Definition of Done:
- [ ] All 6 CLI commands working with rich output
- [ ] Policy composition with `extends:` and `merge()` works correctly
- [ ] Dry-run replays calls and shows accurate decisions
- [ ] Schema export enables IDE autocompletion
- [ ] Tests passing, 96%+ coverage

---

## v1.0.10 — Observability & Production Release
**Focus:** Enterprise observability, operational maturity, and the stable v1.0.0 release to PyPI.

### What ships:
- **OpenTelemetry integration** (`enforcecore.telemetry`)
  - Traces: span per enforcement call with tool name, decision, duration
  - Metrics: counters (calls, blocks, redactions), histograms (latency), gauges (cost)
  - Auto-instrumentation: opt-in via `enforcecore[telemetry]` extra
  - Works with any OTel-compatible backend (Jaeger, Datadog, Grafana, etc.)
- **Audit trail operations**
  - Rotation: size-based and time-based log rotation
  - Retention: configurable max age / max size with automatic cleanup
  - Compression: gzip completed trail files
  - Async writes: non-blocking audit for high-throughput systems
- **Event webhooks**
  - Configurable HTTP callbacks on violation, cost threshold, audit errors
  - Built-in retry with exponential backoff
  - Policy YAML `webhooks` section
- **Enhanced secret detection**
  - Cloud provider credentials (GCP, Azure service principal)
  - Database connection strings
  - SSH keys and certificates
- **Stable API declaration**
  - Remove all alpha (`a1`) suffixes
  - Semantic versioning commitment: no breaking changes until v2.0
  - Full API compatibility tests
- **PyPI publication**
  - `pip install enforcecore` — the official v1.0.0 stable release
  - Package signing and provenance attestation
  - Complete documentation on ReadTheDocs or GitHub Pages
- **Example:** Full production deployment with telemetry + webhooks + audit rotation

### What a user can do after v1.0.10:
```bash
pip install enforcecore
# OR with all extras:
pip install enforcecore[all]
```

```python
# Full production setup
from enforcecore import enforce, Settings

# Telemetry auto-instruments when installed
# pip install enforcecore[telemetry]

# Audit rotation is automatic
# ENFORCECORE_AUDIT_ROTATE_MB=100
# ENFORCECORE_AUDIT_RETAIN_DAYS=90

@enforce(policy="production.yaml")
async def agent_tool(query: str) -> str:
    return await execute(query)

# Violations trigger webhooks automatically
# production.yaml:
#   webhooks:
#     on_violation: https://hooks.slack.com/...
#     on_cost_threshold: https://pagerduty.com/...
```

### Definition of Done:
- [x] OpenTelemetry traces and metrics working with Jaeger/Datadog
- [x] Audit rotation, retention, and compression working
- [x] Webhook delivery with retry logic
- [ ] All alpha suffixes removed — v1.0.0 stable
- [ ] Published to PyPI with package signing
- [ ] Full documentation published
- [x] Tests passing, 96%+ coverage
- [x] Zero known security issues

---

## v1.0.11 — Documentation & Academic Foundation
**Focus:** Make the project credible at first glance to a researcher or academic reviewer.

### Why this matters:
A researcher evaluating a framework looks at three things in the first 30 seconds:
how to cite it, whether the API is documented, and where it sits in the literature.
Currently EnforceCore has none of these. The code is excellent — the packaging is not.

### What ships:
- **API reference site** (MkDocs + mkdocstrings)
  - Auto-generated from docstrings for all 110+ public exports
  - Browsable, searchable, versioned
  - Deployed to GitHub Pages (enforcecore.dev or equivalent)
  - Cross-linked from README
- **Docstring audit**
  - Every public class, function, and method has a complete docstring
  - Consistent format: one-line summary, Args, Returns, Raises, Example
  - Verified via `ruff` docstring rules (D100–D418)
- **CITATION.cff**
  - Machine-readable citation metadata (GitHub natively renders this)
  - BibTeX export for academic papers
  - Proper author attribution
- **Related work document** (`docs/related-work.md`)
  - Survey of runtime verification for AI agents
  - Positioning vs. existing tools: NeMo Guardrails, Guardrails AI, LlamaGuard, Rebuff
  - Academic references: agent containment, sandboxing, runtime monitoring
  - Clear articulation of what EnforceCore does differently (call-boundary enforcement vs. prompt-level)
- **Architecture diagrams**
  - Mermaid diagrams replacing ASCII art in `docs/architecture.md`
  - Component interaction diagrams
  - Data flow diagrams (enforcement pipeline, audit chain, redaction pipeline)
  - Threat boundary diagram (what is inside/outside the trust perimeter)
- **README completion**
  - Roadmap table shows all shipped releases (currently stale at v1.0.7)
  - "For Researchers" section with link to related work, citation, and contribution guide
  - "For Enterprises" section with link to compliance mapping and threat model

### What a user can do after v1.0.11:
```bash
# Browse the API docs
open https://akios-ai.github.io/EnforceCore/

# Cite the project in a paper
# CITATION.cff provides BibTeX automatically
```

### Definition of Done:
- [ ] Every public export has a complete docstring (110+)
- [ ] MkDocs site builds and deploys to GitHub Pages
- [ ] CITATION.cff renders correctly on GitHub
- [ ] `docs/related-work.md` has 10+ academic/industry references
- [ ] Architecture diagrams use Mermaid (not ASCII)
- [ ] README roadmap table is complete and accurate
- [ ] Tests passing, 96%+ coverage

---

## v1.0.12 — Threat Model & Compliance Mapping
**Focus:** Answer the questions regulators and security reviewers will ask. Make compliance claims verifiable.

### Why this matters:
The vision claims "EU AI Act ready" and "structurally impossible violations." These are powerful
claims but currently backed by zero documentation. A researcher will immediately ask:
"Against what adversary model? Which articles of the AI Act? Where's the proof?"
This release provides those answers.

### What ships:
- **Formal threat model** (`docs/threat-model.md`)
  - Adversary model: capabilities, goals, and attack vectors
    - Malicious agent (compromised LLM, prompt injection)
    - Malicious tool (dependency that attempts data exfiltration)
    - Insider threat (developer disabling enforcement)
    - Supply chain (compromised EnforceCore dependency)
  - Trust boundaries: what must be trusted, what is untrusted
  - Security properties with formal statements:
    - **Fail-closed completeness**: Every code path through the enforcer terminates in either allow or block
    - **Audit completeness**: Every enforced call produces exactly one audit entry
    - **Chain integrity**: Any modification to the audit trail is detectable
    - **Redaction totality**: Every PII/secret match in scope is redacted before the call
  - Assumptions: what must hold for guarantees to apply
  - Known limitations: what we explicitly do NOT protect against
- **EU AI Act compliance mapping** (`docs/compliance/eu-ai-act.md`)
  - Article 9 (Risk Management) → policy engine + content rules + rate limits
  - Article 13 (Transparency) → audit trails + CLI inspect
  - Article 14 (Human Oversight) → policy YAML review + dry-run mode
  - Article 15 (Accuracy, Robustness, Cybersecurity) → enforcement + resource guard
  - Article 17 (Quality Management) → test suite + CI + coverage + versioning
  - Each mapping: article text excerpt → EnforceCore capability → evidence (code + tests)
- **GDPR considerations** (`docs/compliance/gdpr.md`)
  - PII redaction as Article 25 (Data Protection by Design)
  - Audit trail as Article 30 (Records of Processing)
  - Retention enforcement as Article 5(1)(e) (Storage Limitation)
  - Right to erasure considerations (audit trail immutability vs. GDPR Article 17)
- **Attack surface analysis** (`docs/security/attack-surface.md`)
  - Enumerated attack vectors with mitigations
  - Dev-mode / fail-open analysis and documentation
  - Dependency audit (what each dependency does, why it's needed)
- **Enhanced SECURITY.md**
  - Expand with threat model summary
  - Link to full threat model document

### Definition of Done:
- [ ] Threat model reviewed and internally consistent
- [ ] EU AI Act mapping covers Articles 9, 13, 14, 15, 17
- [ ] GDPR document addresses Articles 5, 25, 30 and the right-to-erasure tension
- [ ] Attack surface analysis lists all entry points
- [ ] All claims in the vision document are backed by specific documentation
- [ ] Tests passing, 96%+ coverage

---

## v1.0.13 — Formal Verification & Property Testing
**Focus:** Prove enforcement properties with mathematical rigor. This is what makes researchers excited.

### Why this matters:
EnforceCore claims "structurally impossible violations." Property-based testing and formal
invariant verification transform this from a marketing claim into a verifiable statement.
Researchers can reproduce the proofs. This is the single most compelling differentiator
for academic adoption — no other agent safety framework does this.

### What ships:
- **Property-based testing** (Hypothesis)
  - Policy engine properties:
    - ∀ valid policy, ∀ tool call → decision is deterministic
    - ∀ policy where tool ∈ denied_tools → decision = blocked
    - ∀ policy where tool ∉ allowed_tools (when allowlist exists) → decision = blocked
    - merge(A, merge(B, C)) ≡ merge(merge(A, B), C) (associativity)
  - Merkle chain properties:
    - ∀ sequence of entries → chain is valid
    - ∀ chain, ∀ single-entry modification → verify_trail detects it
    - ∀ chain, ∀ deletion → verify_trail detects it
    - ∀ chain, ∀ insertion → verify_trail detects it
    - ∀ chain, ∀ reordering → verify_trail detects it
  - Redactor properties:
    - ∀ text containing a known PII pattern → redactor detects it
    - ∀ text, redact(text).count(PII) = 0 (completeness)
    - ∀ text without PII → redact(text) = text (no false positives on clean input)
  - Enforcer properties:
    - ∀ error during enforcement → call is blocked (fail-closed)
    - ∀ enforced call → exactly one audit entry is produced
    - ∀ allowed call → result passes through unmodified (modulo redaction)
- **Mutation testing** (mutmut)
  - Run mutation testing on core enforcement paths
  - Target: >85% mutation kill rate on enforcer, policy engine, auditor
  - Survivors analyzed and either killed or documented as benign
- **Formal invariant specifications** (`docs/formal/invariants.md`)
  - Written specifications of each property in precise language
  - Mapping from specification to test that verifies it
  - Discussion of completeness (what is proved, what is not)
- **Policy algebra** (`docs/formal/policy-algebra.md`)
  - Formal definition of policy composition (merge)
  - Properties: associativity, idempotency analysis, conflict resolution semantics
  - Edge cases documented and tested

### What a user/researcher can do after v1.0.13:
```bash
# Run property-based tests
pytest tests/formal/ -v --hypothesis-show-statistics

# Run mutation testing
mutmut run --paths-to-mutate=enforcecore/core/enforcer.py

# Read the formal invariant specifications
open docs/formal/invariants.md
```

### Definition of Done:
- [ ] 20+ Hypothesis property tests covering all core components
- [ ] Mutation testing >85% kill rate on enforcer + policy engine + auditor
- [ ] Formal invariant specifications written and linked to tests
- [ ] Policy algebra document with composition properties
- [ ] All properties reproducible from a clean checkout
- [ ] Tests passing, 96%+ coverage

---

## v1.0.14 — Reproducible Benchmarks & Evaluation
**Focus:** Replace marketing claims with rigorous, reproducible performance data.

### Why this matters:
The README says "< 1ms" for policy evaluation and "8–20ms" for full stack. The vision
says "< 0.5ms overhead." A researcher will immediately ask: "On what hardware? How many
iterations? What's the p99? Is it reproducible?" This release provides real answers.

### What ships:
- **Benchmark harness** (`benchmarks/`)
  - Automated benchmark suite with proper statistical methodology
  - Warmup phase + 10,000 iterations minimum per measurement
  - Reports: mean, median, p50, p95, p99, p99.9, std deviation
  - Hardware/software environment captured automatically
  - Comparison baselines: no enforcement, manual checks, other tools
  - Results output as JSON + human-readable Markdown
- **Component-level benchmarks**
  - Policy evaluation: simple policy, complex policy, large allowlist (1000 tools)
  - PII redaction: short text, long text, many entities, no entities
  - Audit entry: write latency, chain verification latency
  - Secret detection: 11 categories, various text lengths
  - Full stack: decorator overhead end-to-end
  - Rate limiter: sliding window under contention
- **Scalability analysis**
  - Policy size: 10, 100, 1,000, 10,000 allowed tools
  - Concurrent enforcement: 1, 10, 50, 100 threads
  - Audit trail size: resume performance with 1K, 10K, 100K entries
  - Memory footprint: base, per-policy, per-auditor
- **Memory profiling**
  - Base import footprint
  - Per-component allocation
  - Long-running session memory stability (no leaks)
- **Published benchmark report** (`docs/benchmarks.md`)
  - Tables with real numbers from CI hardware
  - Methodology section explaining how to reproduce
  - Comparison with "no enforcement" baseline
  - Discussion of overhead vs. typical tool call latency
- **Benchmark CI**
  - Performance regression detection in CI
  - Alert if any component exceeds documented thresholds

### What a user/researcher can do after v1.0.14:
```bash
# Run the full benchmark suite
python -m benchmarks.run --output results/

# Run a specific benchmark
python -m benchmarks.run --component policy --iterations 50000

# Compare with baseline
python -m benchmarks.run --compare no-enforcement,enforcecore

# View the published report
open docs/benchmarks.md
```

### Definition of Done:
- [ ] Benchmark harness runs all component benchmarks
- [ ] Results include p50/p95/p99 latencies (not just mean)
- [ ] Scalability tests cover policy size, concurrency, audit trail size
- [ ] Memory profiling shows no leaks over 100K calls
- [ ] Published report with methodology and reproduction instructions
- [ ] Benchmark CI detects regressions
- [ ] README performance table updated with real numbers
- [ ] Tests passing, 96%+ coverage

---

## v1.0.15 — End-to-End Examples & Integration Testing
**Focus:** Show, don't tell. Real-world scenarios that demonstrate the value proposition.

### Why this matters:
A researcher considering adoption needs to see EnforceCore solving real problems,
not just toy examples. A 5-line quickstart is necessary but not sufficient.
This release provides complete, runnable scenarios that map to real agent safety concerns.

### What ships:
- **End-to-end example suite** (`examples/scenarios/`)
  - **Healthcare agent** — HIPAA-style PII protection for a medical Q&A agent
    - Policy: only approved medical APIs, all patient data redacted
    - Audit trail for regulatory review
    - Shows: PII redaction + tool gating + audit
  - **Financial agent** — Cost-controlled trading research assistant
    - Policy: budget limits, rate limiting, authorized data sources only
    - Webhook alerts on cost threshold breach
    - Shows: cost tracking + rate limits + webhooks
  - **Code agent** — Sandboxed code execution assistant
    - Policy: no shell access, no file system writes, no network calls
    - Content rules blocking injection patterns
    - Shows: content rules + network enforcement + resource guard
  - **Multi-framework** — Same policy applied across LangGraph, CrewAI, AutoGen
    - Demonstrates framework-agnostic enforcement
    - Same audit trail format regardless of framework
    - Shows: integration adapters + audit consistency
  - **Compliance demo** — EU AI Act scenario
    - Full enforcement pipeline + audit + telemetry
    - Policy review via dry-run mode
    - Audit verification via CLI
    - Shows: compliance workflow end-to-end
- **Integration test suite** (`tests/integration/`)
  - End-to-end tests that exercise the full pipeline (not mocked)
  - Policy → Enforcer → Redactor → Guard → Auditor → Verify
  - Multi-policy composition scenarios
  - Concurrent enforcement stress tests
  - Cross-session audit chain continuity
- **Docker-based reproducibility**
  - `docker-compose.yml` for benchmark + evaluation environment
  - Pinned Python version + dependencies
  - Reproducible from any machine

### Definition of Done:
- [ ] 5 end-to-end example scenarios, each runnable standalone
- [ ] Integration test suite covers full pipeline (no mocks)
- [ ] Docker environment reproduces benchmarks and evaluation
- [ ] Each example has a README explaining the scenario
- [ ] Tests passing, 96%+ coverage

---

## v1.0.16 — API Freeze & Stability Audit
**Focus:** Lock down the public API surface. No more changes until v2.0.

### Why this matters:
Before declaring stable, we must be confident that every public symbol is intentional,
well-named, and something we're willing to maintain for years. Researchers and enterprises
need to trust that their code won't break on upgrade. This is a one-way door.

### What ships:
- **API surface audit**
  - Every one of the 110+ exports reviewed:
    - Is it necessary? (Remove if not)
    - Is it well-named? (Rename now or never)
    - Is it fully typed? (Fix any `Any` returns)
    - Is it tested? (Add test if not)
  - Deprecated symbols removed:
    - `guard_sync` / `guard_async` (deprecated since v1.0.6)
    - Any other deprecated aliases
  - Internal symbols verified as private (underscore-prefixed)
- **`py.typed` marker**
  - PEP 561 marker file for typed package
  - Full mypy strict compliance verified
  - Type stubs complete for all public API
- **API compatibility test suite** (`tests/api/`)
  - Tests that import and use every public symbol
  - Prevents accidental removal or signature changes
  - Version-pinned expectations
- **Semantic versioning contract** (`docs/versioning.md`)
  - What constitutes a breaking change
  - Deprecation policy: warn for 2 minor versions before removal
  - Backport policy for security fixes
  - Compatibility promises for v1.x
- **Migration guide** (`docs/migration.md`)
  - Alpha → stable migration steps
  - Deprecated API alternatives
  - Breaking changes summary (if any)

### Definition of Done:
- [ ] API surface audit complete — every export justified
- [ ] All deprecated symbols removed
- [ ] `py.typed` marker present and mypy strict passes
- [ ] API compatibility test suite covers all public symbols
- [ ] `docs/versioning.md` written and linked from README
- [ ] `docs/migration.md` covers alpha → stable path
- [ ] Tests passing, 96%+ coverage

---

## v1.0.17 — Adversarial Scenario Expansion
**Focus:** Broaden the evaluation suite with sophisticated, multi-stage attack scenarios.

### Why this matters:
The current eval suite covers 13 scenarios across 7 threat categories. Real-world attacks
don't consist of a single blocked tool call — they unfold as multi-step campaigns where each
step is innocuous in isolation but lethal in sequence. The framework's credibility depends on
demonstrating containment of realistic attack chains, not just individual violations.

### What ships:
- **Ransomware-like multi-stage scenario** (`scenarios/ransomware_campaign`)
  - Stage 1: Agent enumerates local files via `list_files` (allowed)
  - Stage 2: Agent attempts bulk file encryption via `write_file` with encoded content
  - Stage 3: Agent attempts to delete originals via `delete_file`
  - Stage 4: Agent attempts to send ransom note via `send_email` to unauthorized recipient
  - Each stage independently enforced — demonstrates defense-in-depth
  - Expected: stages 2–4 blocked, stage 1 logged with anomaly flag
- **Supply-chain attack scenario** (`scenarios/supply_chain`)
  - Compromised dependency attempts credential harvesting
  - Reads environment variables containing API keys
  - Attempts exfiltration via DNS resolution or HTTP callback
  - Tests: secret detection catches credentials, network enforcement blocks callback
- **Privilege escalation chain** (`scenarios/privilege_escalation`)
  - Agent starts with minimal permissions (read-only)
  - Attempts to modify its own policy file
  - Attempts to call admin-only tools by name manipulation (case, unicode)
  - Attempts to disable enforcement via environment variable injection
  - Tests: policy immutability, tool-name normalization, env-var gating
- **Multi-agent collusion scenario** (`scenarios/multi_agent_collusion`)
  - Two agents with separate policies attempt to relay blocked actions
  - Agent A (has network access) passes data to Agent B (has file access)
  - Tests: per-agent policy isolation, cross-agent audit correlation
- **Slow-burn exfiltration scenario** (`scenarios/slow_burn_exfil`)
  - Agent exfiltrates data in small chunks over many calls to stay under rate limits
  - Tests cumulative output monitoring + anomaly detection integration point
- **New `ThreatCategory` members** (if not already covered):
  - `RANSOMWARE` — destructive multi-stage campaigns
  - `SUPPLY_CHAIN` — compromised dependency attacks
  - `COLLUSION` — multi-agent coordinated policy evasion
- **Eval report generator** updated with new scenario results

### What a user can do after v1.0.17:
```bash
# Run the ransomware campaign scenario
enforcecore eval --scenario ransomware-campaign --policy strict.yaml

# Run all multi-stage scenarios
enforcecore eval --scenarios multi-stage --output results/

# Compare containment rates across scenario categories
enforcecore eval --compare baseline,enforcecore --scenarios all --output comparison.md
```

### Definition of Done:
- [x] 5 new multi-stage scenarios implemented and documented
- [x] Ransomware campaign demonstrates 4-stage containment
- [x] Supply-chain scenario catches credential exfiltration
- [x] Multi-agent collusion tested with isolated policies
- [x] All scenarios reproducible with fixed seeds
- [x] Eval report updated with new scenario results
- [x] Tests passing, 96%+ coverage

---

## v1.0.18 — Security Landscape & Positioning
**Focus:** Position EnforceCore in the broader security ecosystem. Show where it fits, what it complements, and what it doesn't replace.

### Why this matters:
Adopters — whether researchers, security engineers, or compliance teams — need to understand
how EnforceCore relates to existing security tools they already use. Does it replace SELinux?
Does it compete with AppArmor? Where does it sit relative to seccomp, capabilities, or
container sandboxing? Without clear positioning, users either overestimate the scope
("this replaces my OS security") or underestimate it ("why not just use SELinux?").

### What ships:
- **OS-level enforcement comparison** (expanded `docs/related-work.md`)
  - SELinux (Type Enforcement): kernel-level MAC, file/network/process labels, policy complexity
  - AppArmor (Path-based MAC): profile-based, path restrictions, simpler model
  - seccomp-bpf: syscall filtering, BPF programs, container-level sandboxing
  - Linux capabilities: fine-grained privilege decomposition
  - Comparison table: enforcement layer, granularity, target, policy model, overhead
  - Key insight: EnforceCore operates at the **application semantic layer** —
    it understands "tool calls", "PII", and "agent intent", not syscalls or file paths
  - These are **complementary**, not competing — use both for defense-in-depth
- **Defense-in-depth architecture document** (`docs/defense-in-depth.md`)
  - Layer diagram: hardware → kernel (seccomp/SELinux) → container → runtime (EnforceCore) → prompt
  - What each layer catches that others miss
  - Recommended deployment stack for maximum containment
  - Gap analysis: what falls between layers
- **Updated architecture docs**
  - `docs/architecture.md` updated with security-layer context
  - Mermaid diagram showing EnforceCore's position in the full stack
  - Clear scope boundaries: "EnforceCore enforces at the Python runtime boundary.
    It does not replace kernel-level MAC or container sandboxing."
- **"When to use what" guide** (`docs/security/tool-selection.md`)
  - Decision tree: containerized? → seccomp/AppArmor. Python agent? → EnforceCore. Both? → Yes.
  - Common deployment patterns: EnforceCore + Docker + AppArmor
  - Anti-patterns: using EnforceCore as sole sandboxing layer
- **Updated README positioning**
  - Add brief "EnforceCore vs. OS-Level Security" note in the "Why EnforceCore" section
  - Link to defense-in-depth document

### Definition of Done:
- [x] Related work document includes SELinux, AppArmor, seccomp comparison
- [x] Defense-in-depth document with layer diagram published
- [x] Architecture docs updated with security-layer context
- [x] Tool selection guide with decision tree
- [x] README updated with positioning note
- [x] No false claims — clearly state what EnforceCore does and does not replace
- [x] Tests passing, 96%+ coverage

---

## v1.0.19 — Pre-Release Polish & Community
**Focus:** Final quality pass before packaging. README completion, acknowledgements, contributor recognition, documentation consistency.

### Why this matters:
First impressions are permanent. When someone lands on the GitHub page — whether a potential
user, a researcher, a journalist, or an enterprise evaluator — every detail matters.
Broken links, stale tables, missing credits, inconsistent tone — any of these signals
"not production-ready." This release is the final polish pass before the world sees v1.0.0.

### What ships:
- **README final review**
  - All tables updated (roadmap, performance, comparison)
  - All links verified (no broken internal/external links)
  - Badge values accurate (test count, coverage, Python versions)
  - Consistent voice and tone throughout
  - "Quick Start" verified to work from a clean install
- **Acknowledgements section** (`README.md`)
  - Credit researchers, reviewers, and early feedback providers
  - Link to relevant academic work that influenced the design
  - "Standing on the shoulders of" — honest attribution of prior art
  - Follows standard open-source acknowledgement conventions
- **CONTRIBUTORS.md**
  - All contributors listed with roles
  - Contribution guidelines refreshed
  - Code of Conduct verified and linked
- **Documentation consistency pass**
  - Every `docs/` file reviewed for:
    - Consistent formatting (headers, code blocks, tables)
    - Accurate cross-references (no stale links)
    - Current version numbers and test counts
    - No TODO/FIXME markers left in published docs
  - Orphan page detection (pages not linked from anywhere)
- **CHANGELOG consolidation**
  - Review all 20 alpha entries for consistency
  - Ensure every shipped feature is documented
  - Prepare draft v1.0.0 consolidated changelog
- **License and legal review**
  - Apache 2.0 headers in all source files
  - NOTICE file if required by dependencies
  - Third-party license compatibility check
- **Example suite verification**
  - Every example in `examples/` runs successfully from clean checkout
  - README quick start tested on Python 3.11, 3.12, 3.13
  - Example READMEs updated

### Definition of Done:
- [ ] README reviewed — all tables, links, badges accurate
- [ ] Acknowledgements section present and appropriate
- [ ] CONTRIBUTORS.md complete
- [ ] All docs files pass consistency review (no broken links, no stale content)
- [ ] CHANGELOG covers all 20 alpha releases consistently
- [ ] License headers verified in all source files
- [ ] All examples run from clean checkout
- [ ] Tests passing, 96%+ coverage

---

## v1.0.20 — Packaging & Publication Infrastructure
**Focus:** Make EnforceCore installable by anyone in the world with one command.

### What ships:
- **PyPI publication pipeline**
  - GitHub Actions workflow: tag push → build → TestPyPI → PyPI
  - Wheel + sdist built with hatchling
  - TestPyPI dry-run verified
  - Automated version consistency checks (pyproject.toml ↔ __init__.py)
- **Package signing**
  - Sigstore attestations (PEP 740)
  - Provenance metadata for supply chain security
  - SLSA Level 2 compliance (build provenance)
- **Documentation site deployment**
  - MkDocs Material deployed to GitHub Pages
  - Automated on push to main
  - Versioned documentation (latest + per-release)
  - Search functionality
  - Custom domain if available
- **Docker images**
  - `ghcr.io/akios-ai/enforcecore:latest` — for reproducible evaluation
  - `ghcr.io/akios-ai/enforcecore:benchmark` — for benchmark reproduction
  - Automated builds in CI
- **Release automation**
  - Changelog verification (CHANGELOG.md entry required)
  - Version tag creation
  - GitHub Release with auto-generated notes
  - Announcement template for social/academic channels

### Definition of Done:
- [ ] `pip install enforcecore` works from TestPyPI
- [ ] Package signed with Sigstore attestations
- [ ] Documentation site accessible and searchable
- [ ] Docker images build and run correctly
- [ ] Release workflow tested end-to-end (tag → TestPyPI)
- [ ] Tests passing, 96%+ coverage

---

## v1.0.0 — Stable Release 🎯
**Focus:** The official stable release. Production-ready for the world.

### Why this is a separate release:
The stable release is not about new features — it's about **confidence**.
Every alpha suffix removed. Every claim backed by documentation. Every API
symbol committed to long-term stability. This is the version we stand behind.

### What ships:
- **Version `1.0.0`** — no alpha, no pre-release suffix
- **Published to PyPI** — `pip install enforcecore`
- **Documentation site live** — full API reference, guides, formal specs
- **All claims verified:**
  - "< X ms overhead" → backed by published benchmarks with methodology
  - "EU AI Act ready" → backed by specific article-by-article mapping
  - "Tamper-proof audit" → backed by formal Merkle chain invariants
  - "Structurally impossible violations" → backed by property tests + threat model
  - "Framework-agnostic" → backed by 3+ framework integration examples
- **GitHub Release** with complete changelog
- **CITATION.cff** verified and rendering correctly
- **Announcement ready** (social posts, academic channels, HN/Reddit)

### What a user/researcher can do:
```bash
pip install enforcecore

# OR with all extras:
pip install enforcecore[all]

# Cite in a paper:
# See CITATION.cff on GitHub

# Browse API docs:
# https://akios-ai.github.io/EnforceCore/

# Run the evaluation suite:
enforcecore eval --scenarios all

# Verify an audit trail:
enforcecore verify audit.jsonl

# Read the formal invariants:
# docs/formal/invariants.md
```

### Definition of Done:
- [ ] Version is `1.0.0` (no suffix)
- [ ] Published to PyPI and installable
- [ ] Documentation site live and accessible
- [ ] All README claims have backing documentation
- [ ] CITATION.cff correct and rendering
- [ ] Benchmark report published with real numbers
- [ ] Threat model, compliance mapping, and formal invariants published
- [ ] 5+ end-to-end example scenarios runnable
- [ ] Zero known security issues
- [ ] Test suite passing, 96%+ coverage

---

## Release Arc

```
Phase 1: Foundation                Phase 2: Extensibility       Phase 3: Deep Security
v1.0.0a  v1.0.1a  v1.0.2a         v1.0.7a                      v1.0.8a
 Core     PII     Audit            Plugins                       Content Rules
         Redact   Trail            Hooks                         Network
                                   Secrets                       Rate Limit
v1.0.3a  v1.0.4a  v1.0.5a         Backends                      Arg Inspection
 Guard    Frame    Eval
 Cost     Integ    Suite           Phase 4: Operations           Phase 5: Academic Rigor
 Kill                              v1.0.9a   v1.0.10a            v1.0.11a  v1.0.12a  v1.0.13a
v1.0.6a                            CLI       Telemetry            API Docs  Threat    Formal
 Harden                            Policy    Audit Ops            Citation  Model     Verification
 Unicode                           Compose   Webhooks             Related   EU AI     Property
 Polish                            Dry-Run                        Work      Act       Testing

                                   Phase 6: Production Readiness
                                   v1.0.14a  v1.0.15a  v1.0.16a
                                   Bench-     E2E       API
                                   marks      Examples  Freeze
                                   Repro      Docker    py.typed
                                   Profiling  Integ     Versioning

                                   Phase 7: Hardening & Release
                                   v1.0.17a  v1.0.18a  v1.0.19a  v1.0.20a  → v1.0.0 STABLE
                                   Adversar-  Security  Pre-Rel   Packaging   Release
                                   ial Eval   Landscape Polish    PyPI
                                   Multi-     Defense   Ack &     Signing
                                   Stage      in-Depth  Community Docs Site
```

Each release makes the framework meaningfully more capable and more credible.
By v1.0.0 stable, EnforceCore is the **complete, rigorously verified, production-ready
runtime enforcement layer** for any Python-based agentic AI system.

---

## Timeline

| Release | Focus | Tests (cumulative) | Status |
|---|---|---|---|
| v1.0.0a1 | Core Enforcer + Policy Engine | 94 | ✅ Shipped |
| v1.0.1a1 | PII Redactor | 161 | ✅ Shipped |
| v1.0.2a1 | Merkle Audit Trail | 213 | ✅ Shipped |
| v1.0.3a1 | Resource Guard + KillSwitch | 284 | ✅ Shipped |
| v1.0.4a1 | Framework Integrations | 334 | ✅ Shipped |
| v1.0.5a1 | Evaluation Suite | 431 | ✅ Shipped |
| v1.0.6a1 | Hardening + Polish | 544 | ✅ Shipped |
| v1.0.7a1 | Plugin & Extensibility | 709 | ✅ Shipped |
| v1.0.8a1 | Deep Inspection & Network | 858 | ✅ Shipped |
| v1.0.9a1 | CLI & Policy Tooling | 940 | ✅ Shipped |
| v1.0.10a1 | Observability & Telemetry | 1038 | ✅ Shipped |
| v1.0.11a1 | Documentation & Academic Foundation | — | ✅ Shipped |
| v1.0.12a1 | Threat Model & Compliance Mapping | — | ✅ Shipped |
| v1.0.13a1 | Formal Verification & Property Testing | 1068 | ✅ Shipped |
| v1.0.14a1 | Reproducible Benchmarks & Evaluation | 1090 | ✅ Shipped |
| v1.0.15a1 | End-to-End Examples & Integration | 1138 | ✅ Shipped |
| v1.0.16a1 | API Freeze & Stability Audit | 1416 | ✅ Shipped |
| v1.0.17a1 | Adversarial Scenario Expansion | — | ✅ Shipped |
| v1.0.18a1 | Security Landscape & Positioning | — | ✅ Shipped |
| v1.0.19a1 | Pre-Release Polish & Community | — | 📋 Planned |
| v1.0.20a1 | Packaging & Publication | — | 📋 Planned |
| **v1.0.0** | **Stable Release** | — | **🎯 Target** |

---

## Beyond v1.0 Stable (Future Directions)

These are **not committed** — they represent potential future work based on adoption
and community input. Each is a genuine research/engineering challenge:

- **v1.1** — Multi-tenant enforcement (per-agent/per-tenant policy isolation with namespace-scoped audit trails)
- **v1.2** — Policy Hub (community repository of reusable, audited policies and rule packs — think "Docker Hub for agent policies")
- **v1.3** — Distributed enforcement (multi-agent systems across processes/machines with consistent policy evaluation)
- **v1.4** — Multi-language SDKs (TypeScript, Go, Rust bindings via FFI — same enforcement semantics in every runtime)
- **v2.0** — Formal verification backend (integration with TLA+/Alloy/Z3 for machine-checked policy correctness proofs)
- **Research track** — Academic collaboration on open problems:
  - Optimal policy composition in multi-agent hierarchies
  - Information-flow control at agent boundaries
  - Runtime verification of temporal safety properties (LTL/CTL over agent traces)
  - Quantitative enforcement (probabilistic policy decisions with risk budgets)

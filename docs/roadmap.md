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
- [ ] OpenTelemetry traces and metrics working with Jaeger/Datadog
- [ ] Audit rotation, retention, and compression working
- [ ] Webhook delivery with retry logic
- [ ] All alpha suffixes removed — v1.0.0 stable
- [ ] Published to PyPI with package signing
- [ ] Full documentation published
- [ ] Tests passing, 96%+ coverage
- [ ] Zero known security issues

---

## Release Arc

```
Foundation                          Extensibility    Deep Security    Operations       Production
v1.0.0  v1.0.1  v1.0.2  v1.0.3    v1.0.7           v1.0.8           v1.0.9           v1.0.10
 Core    PII    Audit   Guard       Plugins          Content Rules    CLI              Telemetry
        Redact  Trail   Cost        Hooks            Network          Policy Compose   Audit Ops
                        Kill        Secrets          Rate Limit       Dry-Run          Webhooks
                                    Backends         Arg Inspection   Schema           PyPI v1.0.0

v1.0.4  v1.0.5  v1.0.6
 Frame   Eval    Harden
 Integ   Suite   Unicode
                 Polish
```

Each release makes the framework meaningfully more capable. By v1.0.10, EnforceCore is the
**complete, production-grade runtime enforcement layer** for any Python-based agentic AI system.

---

## Timeline

| Release | Focus | Tests (cumulative) | Status |
|---|---|---|---|
| v1.0.0 | Core Enforcer + Policy Engine | 94 | ✅ Shipped |
| v1.0.1 | PII Redactor | 161 | ✅ Shipped |
| v1.0.2 | Merkle Audit Trail | 213 | ✅ Shipped |
| v1.0.3 | Resource Guard + KillSwitch | 284 | ✅ Shipped |
| v1.0.4 | Framework Integrations | 334 | ✅ Shipped |
| v1.0.5 | Evaluation Suite | 431 | ✅ Shipped |
| v1.0.6 | Hardening + Polish | 544 | ✅ Shipped |
| v1.0.7 | Plugin & Extensibility | 709 | ✅ Shipped |
| v1.0.8 | Deep Inspection & Network | 858 | ✅ Shipped |
| v1.0.9 | CLI & Policy Tooling | 940 | ✅ Shipped |
| v1.0.10 | Observability + PyPI v1.0.0 | — | 📋 Planned |

---

## Beyond v1.0 (Future Directions)

These are **not committed** — they represent potential future work based on adoption:

- **v1.1** — Multi-tenant enforcement (per-agent/per-tenant policy isolation)
- **v1.2** — Policy Hub (community repository of reusable policies + rule packs)
- **v1.3** — Formal verification integration (model checking of policy correctness)
- **v1.4** — Multi-language SDKs (TypeScript, Go, Rust bindings via FFI)
- **v2.0** — Distributed enforcement for multi-agent systems across processes/machines

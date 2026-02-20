# EnforceCore — Roadmap (v1.0.x)

## Release Philosophy

We ship incrementally. Each v1.0.x release adds one well-tested, well-documented component. No release ships without:
- Full test coverage for the new component
- Updated documentation
- At least one working example
- Passing CI on Linux and macOS

This is not a "dump everything and tag v1.0" approach. Each release is usable on its own, and each one makes the framework meaningfully more capable.

---

## v1.0.0 — Core Enforcer + Policy Engine
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

## v1.0.1 — PII Redactor
**Focus:** Real-time PII detection and redaction on inputs and outputs.

### What ships:
- **Redactor module**
  - Presidio-based PII detection (email, phone, SSN, credit card, IP address, person name)
  - Configurable redaction strategies: mask (`****`), hash, remove, placeholder (`<REDACTED>`)
  - Pre-call input redaction
  - Post-call output redaction
  - Redaction event metadata (what was redacted, where, which strategy)
- **Policy extension:** `pii_redaction` section in policy YAML
- **Tests** for all PII categories and redaction strategies
- **Example:** Protecting a customer support agent from leaking PII

### What a user can do after v1.0.1:
```python
@enforce(policy="policy_with_pii.yaml")
async def call_llm(prompt: str) -> str:
    # If prompt contains "john.doe@email.com" → auto-redacted before call
    # If response contains SSN → auto-redacted before returning
    return await llm.generate(prompt)
```

### Definition of Done:
- [ ] Presidio integration detects 6 PII categories
- [ ] 4 redaction strategies implemented and tested
- [ ] Redaction works on both inputs and outputs
- [ ] Policy YAML supports `pii_redaction` configuration
- [ ] Performance benchmarked and documented

---

## v1.0.2 — Merkle Auditor
**Focus:** Tamper-proof, cryptographically verifiable audit trails.

### What ships:
- **Auditor module**
  - SHA-256 based Merkle tree for audit entries
  - Structured audit entries (call metadata, policy decision, timing, redaction summary)
  - JSONL file writer with append-only semantics
  - Audit trail verifier (prove no entries were modified or deleted)
  - Chain integrity validation
- **Policy extension:** `audit` section in policy YAML (enable/disable, storage path)
- **CLI tool:** `enforcecore verify <audit_file>` — verify trail integrity
- **Tests** for Merkle tree correctness, chain integrity, and tamper detection
- **Example:** Generating and verifying an audit trail for a multi-step agent workflow

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
- [ ] Merkle tree correctly chains audit entries
- [ ] Tamper detection works (modified/deleted entries caught)
- [ ] JSONL audit file format documented
- [ ] `enforcecore verify` CLI command works
- [ ] Verification tested with intentionally corrupted trails

---

## v1.0.3 — Resource Guard
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
- [ ] Time limits work on Linux and macOS
- [ ] Memory limits work on Linux and macOS (best-effort on Windows)
- [ ] Cost tracking is cumulative and thread-safe
- [ ] KillSwitch terminates calls cleanly on breach
- [ ] Platform abstraction documented (what works where)

---

## v1.0.4 — Framework Integrations
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
- [ ] 3 framework adapters working with examples
- [ ] Each adapter tested with the actual framework
- [ ] Integration guide written
- [ ] No hard dependencies on any framework (adapters are optional imports)

---

## v1.0.5 — Evaluation Suite
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
- [ ] 5+ adversarial scenarios implemented and documented
- [ ] Test harness runs all scenarios automatically
- [ ] Benchmark results published in docs
- [ ] Comparison with "no protection" baseline
- [ ] Results are reproducible (fixed seeds, documented environment)

---

## v1.0.6 — Hardening + Polish
**Focus:** Production readiness, security audit, and documentation polish.

### What ships:
- **Security review** of all enforcement paths (ensure fail-closed behavior)
- **Edge case hardening:**
  - Recursive/nested enforcement calls
  - Concurrent enforcement with shared state
  - Large payload handling
  - Unicode/encoding edge cases in redaction
- **Performance optimization** based on benchmark results from v1.0.5
- **Documentation polish:**
  - Complete API reference (auto-generated from docstrings)
  - Architecture decision records (ADRs) for key decisions
  - FAQ and troubleshooting guide
- **Stable API declaration:** After v1.0.6, the public API is considered stable

### Definition of Done:
- [ ] All known edge cases documented and tested
- [ ] No fail-open paths in enforcement logic
- [ ] API reference is complete
- [ ] Performance meets documented targets
- [ ] README, docs, and examples are polished and consistent

---

## Timeline (Realistic)

| Release | Estimated Duration | Cumulative |
|---|---|---|
| v1.0.0 | 1-2 weeks | Week 2 |
| v1.0.1 | 1 week | Week 3 |
| v1.0.2 | 1 week | Week 4 |
| v1.0.3 | 1-2 weeks | Week 6 |
| v1.0.4 | 1 week | Week 7 |
| v1.0.5 | 2 weeks | Week 9 |
| v1.0.6 | 1-2 weeks | Week 11 |

**Total: ~10-12 weeks to a complete, polished v1.0.6**

This is a realistic timeline for one developer working part-time alongside AKIOS. Adjust if there are contributors.

---

## Beyond v1.0 (Future Directions)

These are **not committed** — they represent potential future work based on community interest and adoption:

- **v1.1** — Network-level enforcement (domain filtering, request inspection)
- **v1.2** — Policy Hub (community repository of reusable policies)
- **v1.3** — Formal verification integration (model checking of policies)
- **v1.4** — Multi-language support (TypeScript/Go bindings)
- **v2.0** — Distributed enforcement for multi-agent systems across processes/machines

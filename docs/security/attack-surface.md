# Attack Surface Analysis

**Version:** 1.0.12a1
**Last updated:** 2026-02-21

---

## 1. Overview

This document enumerates every entry point into EnforceCore, the attack
vectors against each, and the mitigations in place. It is intended for
security reviewers and operators assessing deployment risk.

---

## 2. Entry Points

### 2.1 Enforcement API

These are the user-facing functions that initiate the enforcement pipeline.

| Entry Point | Module | Type | Notes |
|---|---|---|---|
| `@enforce(policy=...)` decorator | `enforcecore.core.enforcer` | Sync + Async | Primary API |
| `Enforcer.enforce_sync()` | `enforcecore.core.enforcer` | Sync | Direct invocation |
| `Enforcer.enforce_async()` | `enforcecore.core.enforcer` | Async | Direct invocation |

**Attack vectors:**
- A1: Call tool without decoration → **No mitigation** (library-level limitation)
- A2: Pass adversarial arguments → **Mitigated** by content rules + PII redaction
- A3: ~~Use deprecated `guard_*` to skip redaction/audit~~ → **Eliminated** (`guard_sync`/`guard_async` removed in v1.0.16)

### 2.2 Policy Loading

| Entry Point | Module | Input | Notes |
|---|---|---|---|
| `Policy.from_file(path)` | `enforcecore.core.policy` | File path | YAML loading |
| `Policy.from_dict(data)` | `enforcecore.core.policy` | Python dict | Direct construction |
| `Policy.merge(base, override)` | `enforcecore.core.policy` | Two policies | Composition |
| `extends:` directive | `enforcecore.core.policy` | YAML field | Recursive file loading |

**Attack vectors:**

| Vector | Risk | Mitigation | Status |
|---|---|---|---|
| YAML deserialization attack | Code execution | `yaml.safe_load()` only | ✅ Mitigated |
| Malformed policy schema | Unexpected behavior | Pydantic validation rejects invalid fields | ✅ Mitigated |
| Path traversal via `from_file()` | Read arbitrary file | No path jailing | ⚠️ Unmitigated |
| `extends:` recursion bomb | DoS via infinite recursion | No depth limit | ⚠️ Unmitigated |
| `on_violation: "log"` policy | Enforcement bypass | By design — policy controls behavior | ℹ️ Documented |

### 2.3 Configuration

| Entry Point | Module | Input | Notes |
|---|---|---|---|
| `Settings()` constructor | `enforcecore.core.config` | Env vars + kwargs | Pydantic Settings |
| `settings` singleton | `enforcecore.core.config` | Module-level global | Mutable at runtime |
| `ENFORCECORE_*` env vars | OS environment | String values | 15+ settings |

**Attack vectors:**

| Vector | Risk | Mitigation | Status |
|---|---|---|---|
| `ENFORCECORE_FAIL_OPEN=true` | Bypass on internal errors | Warning unless DEV_MODE | ⚠️ Partial |
| `ENFORCECORE_AUDIT_ENABLED=false` | No audit trail | No warning | ⚠️ Unmitigated |
| `ENFORCECORE_REDACTION_ENABLED=false` | PII passes through | No warning | ⚠️ Unmitigated |
| Runtime mutation of `settings` singleton | Any setting change | No protection | ⚠️ Unmitigated |

### 2.4 Audit Trail

| Entry Point | Module | Input | Notes |
|---|---|---|---|
| `Auditor.record()` | `enforcecore.auditor.engine` | `AuditEntry` | Write to file |
| `verify_trail(path)` | `enforcecore.auditor.engine` | File path | Read + verify |
| `load_trail(path)` | `enforcecore.auditor.engine` | File path | Read entries |
| Custom backends | `enforcecore.auditor.backends` | User callback | Extensible |

**Attack vectors:**

| Vector | Risk | Mitigation | Status |
|---|---|---|---|
| Audit file modification | Tamper with history | Merkle chain detection via `verify_trail()` | ✅ Mitigated |
| Chain rebuild (attacker has write access) | Undetectable tampering | No asymmetric signature | ⚠️ Unmitigated |
| Audit file deletion | Loss of history | Log rotation preserves + compresses | ⚠️ Partial |
| Malicious callback backend | Data exfiltration | User-provided — no sandboxing | ℹ️ By design |

### 2.5 Redactor

| Entry Point | Module | Input | Notes |
|---|---|---|---|
| `Redactor.redact()` | `enforcecore.redactor.engine` | Text string | Pattern matching |
| `Redactor.detect()` | `enforcecore.redactor.engine` | Text string | Detection only |
| `PatternRegistry.register()` | `enforcecore.redactor.patterns` | Regex pattern | Custom patterns |
| `SecretScanner.scan()` | `enforcecore.redactor.secrets` | Text string | Secret detection |

**Attack vectors:**

| Vector | Risk | Mitigation | Status |
|---|---|---|---|
| Regex evasion (Unicode tricks) | PII leakage | NFC normalization + homoglyph detection | ✅ Mitigated |
| Regex evasion (novel encoding) | PII leakage | URL + HTML entity decoding | ✅ Partial |
| ReDoS (regex denial of service) | DoS | Patterns are simple; no backtracking-heavy regex | ✅ Mitigated |
| PII in binary/images | PII leakage | Not scanned | ⚠️ Unmitigated |
| Malicious custom pattern | Unexpected behavior | User-provided — no validation of regex safety | ℹ️ By design |

### 2.6 Hook System

| Entry Point | Module | Input | Notes |
|---|---|---|---|
| `HookRegistry.register()` | `enforcecore.plugins.hooks` | Callable | Lifecycle hooks |
| `@on_pre_call`, `@on_post_call` etc. | `enforcecore.plugins.hooks` | Decorator | Convenience API |

**Attack vectors:**

| Vector | Risk | Mitigation | Status |
|---|---|---|---|
| Malicious hook modifies context | Bypass enforcement | Same-process trust | ℹ️ By design |
| Hook raises exception | Pipeline disruption | Caught and logged | ✅ Mitigated |
| Hook leaks data via side channel | Data exfiltration | Same-process trust | ℹ️ By design |

### 2.7 CLI

| Entry Point | Module | Input | Notes |
|---|---|---|---|
| `enforcecore validate` | `enforcecore.cli` | File path | Schema check |
| `enforcecore verify` | `enforcecore.cli` | File path | Chain verify |
| `enforcecore inspect` | `enforcecore.cli` | File path + filters | Audit browsing |
| `enforcecore dry-run` | `enforcecore.cli` | File path + calls | Policy preview |
| `enforcecore eval` | `enforcecore.cli` | Scenarios | Evaluation suite |

**Attack vectors:**

| Vector | Risk | Mitigation | Status |
|---|---|---|---|
| Path traversal in file arguments | Read arbitrary file | No sandboxing (CLI is operator-run) | ℹ️ By design |
| Malformed JSONL input to `inspect` | Crash | JSON parse errors caught | ✅ Mitigated |

---

## 3. Dependency Audit

### 3.1 Core Dependencies (always installed)

| Package | Version | Purpose | Risk Assessment |
|---|---|---|---|
| `pydantic` | ≥2.5 | Policy schema validation | **Low** — widely used, well-audited. Compiled Rust core (pydantic-core) is a potential supply chain target but is actively maintained. |
| `pydantic-settings` | ≥2.0 | Environment variable binding | **Low** — thin layer over pydantic. Reads env vars only. |
| `pyyaml` | ≥6.0 | YAML policy parsing | **Low** — only `safe_load()` is used. No `load()` or `unsafe_load()`. |
| `structlog` | ≥24.1 | Structured logging | **Low** — logging only, no network I/O, no file writes (beyond log handlers). |

### 3.2 Optional Dependencies

| Group | Package | Purpose | Risk Assessment |
|---|---|---|---|
| `cli` | `typer>=0.12` | CLI framework | **Low** — argument parsing only |
| `cli` | `rich>=13.0` | Terminal formatting | **Low** — display only |
| `telemetry` | `opentelemetry-api>=1.20` | OTel API | **Low** — API stubs only |
| `telemetry` | `opentelemetry-sdk>=1.20` | OTel SDK | **Medium** — network I/O for exporting spans/metrics |
| `nlp` | `presidio-analyzer>=2.2` | NLP-based PII detection | **Medium** — downloads NLP models, depends on spaCy |
| `nlp` | `presidio-anonymizer>=2.2` | NLP-based PII anonymization | **Medium** — same as above |
| `linux` | `python-seccomp>=0.1` | Syscall filtering | **Low** — Linux-only, well-established |
| `docs` | `mkdocs-material>=9.5` | Documentation site | **N/A** — dev-only, not shipped |
| `docs` | `mkdocstrings[python]>=0.24` | API doc generation | **N/A** — dev-only, not shipped |

### 3.3 Dependency Isolation

Optional dependencies are imported behind `try/except` guards. If an optional
dependency is compromised or unavailable:

- Core enforcement continues to function without it
- A missing optional dependency results in a feature being unavailable (not
  a security bypass)
- Example: if `opentelemetry` is compromised, disabling `enforcecore[telemetry]`
  removes all OTel code paths without affecting enforcement

---

## 4. Dev-Mode and Fail-Open Analysis

### 4.1 Fail-Open Behavior

The `fail_open` setting controls what happens when an **internal error**
(not a policy violation) occurs during enforcement:

| `fail_open` | `ENFORCECORE_DEV_MODE` | Behavior |
|---|---|---|
| `False` (default) | Any | ✅ **Fail-closed** — internal error blocks the call |
| `True` | Not set | ⚠️ **Fail-open** + `RuntimeWarning` emitted |
| `True` | `1` / `true` / `yes` | ⚠️ **Fail-open** + warning suppressed |

**Critical detail:** `EnforcementViolation` exceptions (policy denials) are
**never** subject to fail-open. Even with `fail_open=True`, a denied tool
call is always blocked. The fail-open path only applies to internal
`EnforceCoreError` exceptions (I/O failures, configuration errors, etc.).

### 4.2 Detection

- Setting `ENFORCECORE_FAIL_OPEN=true` without `ENFORCECORE_DEV_MODE=1`
  emits a `RuntimeWarning` with the message: *"SECURITY WARNING: fail_open
  is enabled without ENFORCECORE_DEV_MODE=1."*
- This warning is captured by Python's warning system and can be escalated
  to an error via `warnings.filterwarnings("error")`.

### 4.3 Recommendations for Production

```bash
# Production — never set these
# ENFORCECORE_FAIL_OPEN=true     ← NEVER in production
# ENFORCECORE_DEV_MODE=1         ← NEVER in production

# Production — verify fail-closed
python -c "from enforcecore.core.config import settings; assert not settings.fail_open"
```

---

## 5. Summary of Unmitigated Risks

| Risk | Severity | Why Unmitigated | Planned Fix |
|---|---|---|---|
| Decorator removal bypasses enforcement | High | Library limitation — can't enforce from inside | External lint rule (v1.0.16) |
| `settings` singleton mutable at runtime | Medium | Python design — no const globals | Freeze after init (v1.0.16) |
| Audit chain rebuild by attacker with write access | Medium | No asymmetric signature | External root anchoring (post-v1.0) |
| No path jailing for `Policy.from_file()` | Low | Operator-controlled input | Path restriction option (future) |
| `audit_enabled=false` has no warning | Low | Operator-intentional setting | Warning on production detection (future) |
| No SBOM published | Low | Not yet implemented | SBOM generation (v1.0.17) |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0.12a1 | 2026-02-21 | Initial attack surface analysis |

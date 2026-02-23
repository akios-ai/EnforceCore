# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 1.0.x | ✅ Active development |
| < 1.0 | ❌ Not supported |

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in EnforceCore, please report it privately:

1. **Email:** security@akios.ai
2. **Subject:** `[EnforceCore Security] <brief description>`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

We will acknowledge receipt within **48 hours** and provide a timeline for a fix.

## Security Design Principles

EnforceCore is a security-critical component. Our design principles:

- **Fail-closed:** If enforcement fails for any reason, the call is blocked. Never fails open (unless explicitly configured via `ENFORCECORE_FAIL_OPEN=true`).
- **No silent bypass:** Enabling fail-open without `ENFORCECORE_DEV_MODE=1` emits a `RuntimeWarning`.
- **Minimal dependencies:** 4 core runtime deps (pydantic, pydantic-settings, pyyaml, structlog). Fewer deps = smaller attack surface.
- **Tamper-evident audit:** Merkle-chained audit trails detect any modification, deletion, insertion, or reordering.
- **Deterministic decisions:** Policy evaluation is purely deterministic — same input always produces the same decision (no randomness, no ML).

## Security Properties

EnforceCore claims four formal security properties (see [Threat Model](docs/threat-model.md) §4 for full details):

| Property | Statement | Caveat |
|---|---|---|
| **S1 — Fail-Closed Completeness** | Every enforcement path terminates in ALLOW or BLOCK | `fail_open=True` allows internal (non-violation) errors to pass |
| **S2 — Audit Completeness** | Every enforced call produces exactly one audit entry | Requires `audit_enabled=True` (default) |
| **S3 — Chain Integrity** | Any audit trail modification is detectable | Symmetric only — no asymmetric signature (rebuild attack possible) |
| **S4 — Redaction Totality** | Every PII/secret match is redacted before tool execution | Regex-based — inherent false negatives on novel formats |

## Security Documentation

| Document | Description |
|---|---|
| [Threat Model](docs/threat-model.md) | Adversary model (4 types), trust boundaries, formal properties, assumptions, known limitations |
| [Attack Surface](docs/security/attack-surface.md) | All entry points, attack vectors, mitigations, dependency audit, dev-mode analysis |
| [EU AI Act Mapping](docs/compliance/eu-ai-act.md) | Articles 9, 13, 14, 15, 17 mapped to EnforceCore capabilities |
| [GDPR Considerations](docs/compliance/gdpr.md) | Data minimisation, storage limitation, data protection by design, right-to-erasure tension |

## Known Security Gaps (Under Active Fix)

The following issues were identified during internal security audits and are
being addressed in upcoming releases. None are critical — all have mitigations.

| ID | Severity | Description | Mitigation | Fix Target |
|---|---|---|---|---|
| A-4 | Medium | Pre-call hooks receive un-redacted args via `HookContext` | No hooks registered by default; user hooks are trusted code | v1.0.24a1 |
| M-4 | Medium | `generic_api_key` secret pattern has false positives on low-entropy strings | Only affects detection quality, not safety; actual secrets are still caught | v1.0.24a1 |
| A-5 | Medium | `@enforce()` creates Enforcer at import time; `clear_policy_cache()` doesn't affect already-decorated functions | Document limitation; use `lazy_policy=True` (planned) | v1.0.24a1 |
| M-5 | Medium | Unicode normalization that changes string length disables the normalization pipeline | Rare in practice; only affects URL-encoded PII like `%40` | v1.0.24a1 |

For the full audit roadmap, see the internal security audit documentation.

## Scope

The following are in scope for security reports:

- Bypass of policy enforcement (a denied tool call executes)
- Fail-open behavior (enforcement error allows a call through unexpectedly)
- Audit trail tampering that goes undetected by `verify_trail()`
- PII/secret leakage through the redaction engine
- Dependency vulnerabilities in core dependencies (pydantic, pyyaml, structlog)
- Unicode evasion of PII detection

## Out of Scope

- Vulnerabilities in optional/dev dependencies (presidio, opentelemetry, mkdocs)
- Denial of service via policy misconfiguration (user error)
- Issues that require physical access to the machine
- Decorator removal (library-level limitation — see Threat Model §7)
- In-process bypass by application code (same-process trust boundary)

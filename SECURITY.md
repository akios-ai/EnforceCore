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

- **Fail-closed:** If enforcement fails for any reason, the call is blocked. Never fails open.
- **No bypass paths:** There is no configuration that disables enforcement silently.
- **Minimal dependencies:** Core enforcement uses only stdlib + Pydantic. Fewer deps = smaller attack surface.
- **Tamper-proof audit:** Merkle-chained audit trails detect any modification, deletion, or reordering.

## Scope

The following are in scope for security reports:

- Bypass of policy enforcement (a denied tool call executes)
- Fail-open behavior (enforcement error allows a call through)
- Audit trail tampering that goes undetected
- PII leakage through the redaction engine
- Dependency vulnerabilities in core dependencies

## Out of Scope

- Vulnerabilities in optional/dev dependencies
- Denial of service via policy misconfiguration (user error)
- Issues that require physical access to the machine

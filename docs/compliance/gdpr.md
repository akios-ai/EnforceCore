# GDPR — Data Protection Considerations

**Regulation:** Regulation (EU) 2016/679 (General Data Protection Regulation)
**Mapped against:** EnforceCore v1.0.23a1
**Last updated:** 2026-02-23

---

## Disclaimer

This document analyses how EnforceCore's capabilities relate to specific GDPR
articles. It is a **technical analysis**, not legal advice. GDPR compliance
depends on the full processing context, legal basis, and data controller's
obligations. Organizations must consult qualified Data Protection Officers
(DPOs) and legal counsel.

---

## Scope

EnforceCore processes text data that may contain personal data (PII) when:

1. **Input redaction** — scanning tool call arguments for PII before execution
2. **Output redaction** — scanning tool responses for PII before returning
3. **Audit trail recording** — logging tool call metadata (hashed, not raw)

This document addresses the GDPR articles most relevant to these processing
activities.

---

## Article-by-Article Analysis

### Article 5(1)(c) — Data Minimisation

> *"Personal data shall be adequate, relevant and limited to what is necessary
> in relation to the purposes for which they are processed."*

**EnforceCore support:**
- **PII redaction** removes personal data from tool call arguments and
  responses **before** the data reaches external tools or is returned to
  the agent.
- Redaction strategies:
  - `placeholder` — replaces with `<EMAIL>`, `<PHONE>`, etc.
  - `mask` — replaces with asterisks (`****@****.***`)
  - `hash` — replaces with one-way SHA-256 hash (`[SHA256:abc...]`)
  - `remove` — deletes the match entirely
- **5 PII categories**: email, phone, SSN, credit card, IP address
- **11 secret categories**: AWS keys, GitHub tokens, API keys, etc.
- **Unicode evasion resistance**: NFC normalization, homoglyph detection,
  URL/HTML entity decoding

**Implementation:**
- `enforcecore/redactor/engine.py` — `Redactor.redact()`
- `enforcecore/redactor/patterns.py` — PII patterns
- `enforcecore/redactor/secrets.py` — secret patterns
- `enforcecore/redactor/unicode.py` — evasion resistance

**Verification:**
```bash
pytest tests/redactor/ -v          # PII detection tests
pytest tests/redactor/test_unicode.py -v  # Evasion resistance
```

**Limitations:**
- Regex-based detection has inherent false negatives
- Person names are not detected (too noisy without NLP)
- Binary/image data is not scanned
- PII in structured sub-formats (JSON-in-strings) may evade detection

---

### Article 5(1)(e) — Storage Limitation

> *"Personal data shall be kept in a form which permits identification of
> data subjects for no longer than is necessary."*

**EnforceCore support:**
- **Audit trail retention** — configurable automatic deletion of old audit
  files after a specified number of days.
- **Audit trail rotation** — size-based rotation prevents unbounded growth.
- **Settings:**
  - `audit_retain_days` (default: 90) — files older than this are deleted
  - `audit_rotate_mb` (default: 100) — rotate file when it exceeds this size
  - `audit_compress` (default: True) — gzip rotated files

**Implementation:**
- `enforcecore/auditor/rotation.py` — `AuditRotator`
- `enforcecore/core/config.py` — retention settings

**Verification:**
```bash
pytest tests/auditor/test_rotation.py -v  # Rotation and retention tests
```

**Important:** Audit entries contain **hashed** arguments and results
(`args_hash`, `result_hash`), not raw personal data. However, tool names,
timestamps, and decision reasons may contain identifying information
depending on the application context.

---

### Article 25 — Data Protection by Design and by Default

> *"The controller shall [...] implement appropriate technical and
> organisational measures [...] which are designed to implement data-protection
> principles."*

**EnforceCore support:**

| Principle | Implementation |
|---|---|
| **By design** | PII redaction is built into the enforcement pipeline — not an add-on |
| **By default** | When `pii_redaction.enabled: true` is in the policy, redaction is automatic |
| **Minimisation** | Redaction removes PII before it reaches external tools |
| **Pseudonymisation** | `hash` strategy replaces PII with irreversible SHA-256 hashes |
| **Confidentiality** | Secret detection strips credentials from data flows |

**Policy example:**
```yaml
rules:
  pii_redaction:
    enabled: true
    categories: [email, phone, ssn, credit_card, ip_address]
    strategy: "placeholder"
  secret_detection:
    enabled: true
    categories: [aws_access_key, github_token, generic_api_key]
```

**By default**, if `pii_redaction` is not configured in the policy, no
redaction occurs. This is intentional — redaction is opt-in per policy to
avoid false positives in applications where PII processing is legitimate
and lawful.

---

### Article 30 — Records of Processing Activities

> *"Each controller [...] shall maintain a record of processing activities
> under its responsibility."*

**EnforceCore support:**
- **Merkle-chained audit trail** records every enforcement decision with:
  - Timestamp (ISO 8601)
  - Tool name
  - Policy name and version
  - Decision (allowed / blocked)
  - Violation type and reason (if blocked)
  - Input/output argument hashes (SHA-256)
  - Redaction counts (number of PII matches redacted)
  - Timing (enforcement overhead, call duration)
  - Merkle chain hash (links to previous entry)
- **Tamper-evident** — any modification to a past entry breaks the hash chain
- **Verifiable** — `enforcecore verify audit.jsonl` checks integrity
- **Inspectable** — `enforcecore inspect audit.jsonl` with filtering

**Implementation:**
- `enforcecore/auditor/engine.py` — `Auditor`, `AuditEntry`
- `enforcecore/auditor/backends.py` — storage backends (JSONL, Callback)

**Verification:**
```bash
pytest tests/auditor/ -v        # Audit trail tests
enforcecore verify audit.jsonl  # Chain integrity check
```

---

## The Right-to-Erasure Tension (Article 17)

### The Problem

> *"The data subject shall have the right to obtain from the controller the
> erasure of personal data concerning him or her without undue delay."*

EnforceCore's audit trail is designed to be **tamper-evident** — any deletion
breaks the Merkle hash chain. This creates a tension with GDPR Article 17
(right to erasure): if a data subject requests deletion of their personal
data from audit records, complying would break the chain integrity.

### Analysis

This tension is well-known in the intersection of immutable logging and data
protection law. Key considerations:

1. **Audit entries contain hashes, not raw PII.** The `args_hash` and
   `result_hash` fields are SHA-256 hashes of the original data. SHA-256
   is a one-way function — the original data cannot be recovered from the
   hash. Under GDPR Recital 26, data that cannot be attributed to a natural
   person is not personal data.

2. **Tool names and metadata may be identifying.** If a tool name includes
   user-specific information (e.g., `search_for_user_12345`), the audit
   entry could be considered personal data even without raw PII.

3. **Legal basis matters.** Audit trails for security and compliance purposes
   may be justified under Article 6(1)(f) (legitimate interest) or
   Article 6(1)(c) (legal obligation). In regulated industries, audit
   retention may be legally required, which overrides the right to erasure
   per Article 17(3)(b).

### Recommended Approach

| Strategy | Description |
|---|---|
| **Hash-only storage** (default) | Store only `args_hash` and `result_hash` in audit entries — no raw PII |
| **Redact before audit** | Ensure PII redaction runs before audit recording — audit entries contain only redacted data |
| **Retention limits** | Configure `audit_retain_days` to automatically delete old entries |
| **Tombstone records** | Replace specific entries with a tombstone marker (preserving chain integrity) — requires re-sealing subsequent entries |
| **Legal basis documentation** | Document the legitimate interest / legal obligation basis for audit retention |

### Current Implementation

EnforceCore's enforcement pipeline processes in this order:

1. Input redaction (PII removed)
2. Tool execution (with redacted args)
3. Output redaction (PII removed from response)
4. **Audit recording** (with hashed, redacted data)

This means the audit trail already contains **redacted and hashed** data by
default. The risk of personal data in audit entries is limited to metadata
fields (tool name, timestamps, policy decisions) that may be indirectly
identifying in context.

**Tombstone support** is not implemented in v1.0.12 but could be added as
a future feature. The chain would need to be re-sealed from the tombstone
point forward.

---

## Summary

| GDPR Article | EnforceCore Support | Status |
|---|---|---|
| Art. 5(1)(c) — Data Minimisation | PII redaction on inputs/outputs | ✅ Implemented |
| Art. 5(1)(e) — Storage Limitation | Audit retention + rotation | ✅ Implemented |
| Art. 25 — Data Protection by Design | Redaction built into pipeline | ✅ Implemented |
| Art. 30 — Records of Processing | Merkle-chained audit trail | ✅ Implemented |
| Art. 17 — Right to Erasure | Hash-only storage + retention limits; tombstone not yet supported | ⚠️ Partial |

---

## Revision History

| Version | Date | Changes |
|---|---|---|
| 1.0.23a1 | 2026-02-23 | Updated version header to current release |
| 1.0.12a1 | 2026-02-21 | Initial GDPR considerations document |

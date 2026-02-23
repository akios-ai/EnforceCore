# EnforceCore — FAQ

## General

### What is EnforceCore?

EnforceCore is a runtime enforcement layer for agentic AI systems. It
intercepts tool/API calls at the code boundary and applies policy-driven
rules — blocking denied calls, redacting PII, enforcing resource limits,
and recording tamper-proof audit trails.

### How is this different from prompt guardrails?

Prompt guardrails operate inside the LLM context — they *ask* the model
to behave. EnforceCore operates at the **runtime call boundary** — the
moment before a tool is actually executed. Prompts can be jailbroken;
code-level enforcement cannot.

### Does EnforceCore work with my agent framework?

Yes. EnforceCore works with **any** Python-based agent system:

- **Plain Python** — `@enforce()` decorator
- **LangGraph / LangChain** — `@enforced_tool()` adapter
- **CrewAI** — `@enforced_tool()` adapter
- **AutoGen** — `@enforced_tool()` adapter

No hard dependency on any framework. Adapters use optional imports.

### Is EnforceCore production-ready?

v1.0.6 includes security hardening, unicode evasion protection, and
fail-closed enforcement on all paths. The public API is considered stable
after v1.0.6. We are still in alpha (`pip install enforcecore==1.0.23a1`)
and recommend thorough testing with your own workloads.

---

## Security

### What does "fail-closed" mean?

If anything goes wrong during enforcement (parsing error, internal
exception, etc.), the tool call is **blocked** — it never executes.
This is the safe default. The `fail_open` setting exists for development
only and emits a loud warning in production.

### Can I enable `fail_open` in production?

You can, but you **should not**. When `fail_open=True`, any internal
enforcement error causes the call to proceed unprotected. In production
this means a bug in EnforceCore could silently bypass all protection.

If you set `fail_open=True` without `ENFORCECORE_DEV_MODE=1`, you will
see a `RuntimeWarning`:

```
SECURITY WARNING: fail_open is enabled without ENFORCECORE_DEV_MODE=1.
```

### What is `ENFORCECORE_DEV_MODE`?

An environment variable that acknowledges you are running in a development
environment. Set `ENFORCECORE_DEV_MODE=1` to suppress the `fail_open`
security warning. **Never set this in production.**

### Does EnforceCore protect against unicode PII evasion?

Yes. Since v1.0.6, the PII redactor normalizes text before regex matching:

1. **NFC normalization** and zero-width character stripping
2. **Homoglyph normalization** (Cyrillic/Greek/fullwidth to ASCII)
3. **Encoded PII decoding** (URL percent-encoding, HTML entities)

This defeats attacks like embedding PII with zero-width characters, using
Cyrillic look-alikes, or URL-encoding the `@` sign in email addresses.

### What is the enforcement depth limit?

EnforceCore tracks nested enforcement calls via `contextvars`. If a tool
calls another enforced tool, the nesting depth increases. The default
maximum depth is 10. If exceeded, `EnforcementDepthError` is raised.
This prevents infinite recursion in enforcement chains.

---

## PII Redaction

### What PII categories are supported?

| Category | Example | Placeholder |
|---|---|---|
| `email` | `john@example.com` | `<EMAIL>` |
| `phone` | `(555) 123-4567` | `<PHONE>` |
| `ssn` | `123-45-6789` | `<SSN>` |
| `credit_card` | `4111-1111-1111-1111` | `<CREDIT_CARD>` |
| `ip_address` | `192.168.1.100` | `<IP_ADDRESS>` |

### Why not use spaCy or Presidio?

Presidio requires spaCy + Pydantic v1, which is incompatible with
Python 3.14. EnforceCore uses pure regex for zero heavy dependencies,
portability, and speed (~0.1--0.5ms per call). Presidio can be added as
an optional enhanced backend in a future release.

### Does redaction work on nested data structures?

Yes. Since v1.0.6, the `deep_redact()` function recursively traverses
`dict`, `list`, `tuple`, and `set` containers, applying redaction to all
string leaves. This is automatically used by `enforce_sync()` and
`enforce_async()`.

### What redaction strategies are available?

| Strategy | Result for `john@example.com` |
|---|---|
| `placeholder` | `<EMAIL>` |
| `mask` | `****@****.***` |
| `hash` | `[SHA256:6b0b4806b1e57501]` |
| `remove` | *(empty string)* |

---

## Performance

### What is the enforcement overhead?

| Component | Overhead |
|---|---|
| Policy evaluation | < 1ms |
| PII redaction | 5--15ms |
| Audit entry | < 1ms |
| Resource guard | < 1ms |
| **Typical total** | **8--20ms** (full stack) |

This is negligible compared to typical tool call latency (100ms--10s for
API calls).

### Is the policy cache thread-safe?

Yes. Since v1.0.6, the policy cache uses a `threading.Lock` for
thread-safe access. Multiple threads can safely use `@enforce()` with
the same policy path.

### What is the maximum input size?

By default, 10 MB (sum of all string and bytes arguments). This is
configurable via the `max_bytes` parameter of `check_input_size()`.
Inputs exceeding this limit raise `InputTooLargeError` before any
processing occurs.

---

## Audit Trail

### How does the Merkle chain work?

Each audit entry contains a `previous_hash` field pointing to the
SHA-256 hash of the preceding entry. This creates a linked chain where
any modification, deletion, insertion, or reordering is detectable by
`verify_trail()`.

### Can I resume the chain across sessions?

Yes. When you create an `Auditor` pointing to an existing trail file,
it reads the last entry's hash and continues the chain seamlessly.
Multiple sessions can append to the same trail file.

### Can I load only recent entries?

Yes. Since v1.0.6, `load_trail()` accepts a `max_entries` parameter.
When set, it returns only the most recent N entries from the trail:

```python
recent = load_trail("audit.jsonl", max_entries=100)
```

---

## Configuration

### What environment variables does EnforceCore use?

| Variable | Default | Description |
|---|---|---|
| `ENFORCECORE_DEFAULT_POLICY` | `None` | Default policy file path |
| `ENFORCECORE_AUDIT_PATH` | `./audit_logs/` | Audit trail directory |
| `ENFORCECORE_AUDIT_ENABLED` | `true` | Enable/disable auditing |
| `ENFORCECORE_REDACTION_ENABLED` | `true` | Enable/disable PII redaction |
| `ENFORCECORE_LOG_LEVEL` | `INFO` | Structured log level |
| `ENFORCECORE_COST_BUDGET_USD` | `100.0` | Global cost budget |
| `ENFORCECORE_FAIL_OPEN` | `false` | Allow bypass on errors |
| `ENFORCECORE_DEV_MODE` | `false` | Development mode flag |

### How do I disable auditing for tests?

Set `ENFORCECORE_AUDIT_ENABLED=false` in your test environment, or use
the `_disable_audit_globally` autouse fixture pattern from EnforceCore's
own test suite.

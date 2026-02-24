# EnforceCore — Tech Stack

## Core Dependencies

| Dependency | Version | Purpose | Why this one |
|---|---|---|---|
| **Python** | 3.11+ | Runtime | Walrus operator, `tomllib`, `TaskGroup`, modern typing. 3.11+ is standard in AI/ML. |
| **Pydantic** | >= 2.5 | Policy models, validation, serialization | Industry standard for data models in Python. Researchers already know it. V2 is fast. |
| **pydantic-settings** | >= 2.0 | Configuration (env vars + files) | Clean config management without custom code. |
| **PyYAML** | >= 6.0 | Policy file parsing | The standard YAML parser for Python. Policies are YAML. |
| **structlog** | >= 24.1 | Structured logging | Clean, structured, machine-readable logs. Much better than stdlib logging for enforcement audit. |
| **cryptography** | >= 42.0 | Merkle tree hashing, signing | Well-maintained, audited crypto library. Don't roll your own crypto. |

### PII Redaction (v1.0.1+)

| Dependency | Version | Purpose | Why this one |
|---|---|---|---|
| **presidio-analyzer** | >= 2.2 | PII entity detection | Microsoft's battle-tested PII detection. Supports 10+ entity types, multiple languages. |
| **presidio-anonymizer** | >= 2.2 | PII redaction/anonymization | Pairs with analyzer for clean redaction strategies. |

### Optional Linux Hardening (v1.0.3+)

| Dependency | Version | Purpose | Why this one |
|---|---|---|---|
| **python-seccomp** | >= 0.1 | Syscall filtering | Linux-only. seccomp-bpf bindings for kernel-level sandboxing. |

## Development Dependencies

| Dependency | Purpose |
|---|---|
| **pytest** | Test framework |
| **pytest-asyncio** | Async test support |
| **pytest-cov** | Coverage reporting |
| **ruff** | Linting + formatting (replaces flake8, black, isort) |
| **mypy** | Static type checking (strict mode) |
| **hatch** | Build system + environment management |
| **rich** | Beautiful CLI output for examples and eval suite |
| **typer** | CLI framework for `enforcecore` commands |

## What We Explicitly Do NOT Use

| Technology | Why not |
|---|---|
| **FastAPI / Flask** | EnforceCore is a library, not a web service. No HTTP server needed. |
| **SQLAlchemy / databases** | v1.0 uses JSONL files for audit. DB backends come later as plugins. |
| **Docker SDK** | Container support is out of scope for v1.0. |
| **LangChain / LlamaIndex** | Zero hard dependencies on agent frameworks. Integrations are optional. |
| **TensorFlow / PyTorch** | No ML in v1.0. Policy evaluation is rule-based. |
| **Click** | Typer is built on Click but provides a better DX. |

## Build System

**Hatch** (via `pyproject.toml`)

Why Hatch over alternatives:
- **vs setuptools:** Modern, cleaner, better environment management
- **vs Poetry:** Less opinionated, doesn't lock you into its resolver
- **vs Flit:** More features (environments, scripts, versioning)
- **vs PDM:** Hatch is more widely adopted in the Python ecosystem now

## Python Version Support

| Version | Support |
|---|---|
| 3.11 | ✅ Fully supported |
| 3.12 | ✅ Fully supported |
| 3.13 | ✅ Fully supported |
| 3.10 | ❌ Not supported (missing `TaskGroup`, modern typing features) |
| < 3.10 | ❌ Not supported |

**Rationale:** 3.11+ gives us `TaskGroup` for structured concurrency, `tomllib` for config parsing, and modern typing syntax (`X | None` instead of `Optional[X]`). The AI/ML ecosystem has largely moved to 3.11+.

## Platform Support

| Platform | Core (Policy + Enforcer + Redactor + Auditor) | Guard (Resource Limits) | Guard (Syscall Sandbox) |
|---|---|---|---|
| Linux (x86_64) | ✅ Full | ✅ Full (cgroups v2 + setrlimit) | ✅ Full (seccomp-bpf) |
| Linux (aarch64) | ✅ Full | ✅ Full | ✅ Full |
| macOS (Apple Silicon) | ✅ Full | ⚠️ Partial (setrlimit, no cgroups) | ❌ N/A |
| macOS (Intel) | ✅ Full | ⚠️ Partial | ❌ N/A |
| Windows | ✅ Full | ⚠️ Basic (thread timeout only) | ❌ N/A |

**The security-critical components (Policy, Enforcer, Redactor, Auditor) work on ALL platforms.** Only the OS-level sandboxing requires Linux.

## Critical Technical Decisions

### 1. Why regex-based PII detection (not Presidio/spaCy)

EnforceCore uses compiled regex patterns for PII detection by default. This was a deliberate choice:
- **Zero heavy dependencies:** No spaCy, no model downloads, no Presidio
- **Deterministic:** Same input always produces the same result
- **Fast:** ~0.028ms per short text — critical for a security enforcement layer
- **Portable:** Works on all Python 3.11+ without platform-specific issues

The tradeoff is lower coverage on novel PII formats. NER-based detection (via optional Presidio integration) is planned for v1.3.0 as an opt-in tier.

### 2. Why Pydantic v2 for policies (not raw YAML dicts)

- **Validation:** Invalid policies are caught at load time, not at runtime
- **IDE support:** Autocomplete and type checking for policy authors
- **Serialization:** Easy to convert between YAML, JSON, and Python objects
- **Extensibility:** Custom validators for complex policy rules

### 3. Why JSONL for audit logs (not SQLite/Postgres)

- **Simplicity:** No database setup, no migrations, no connection management
- **Append-only:** Perfect for Merkle chain (just append new entries)
- **Portable:** A single file that can be copied, verified, archived
- **Extensible:** Database backends can be added as plugins later without breaking the core

### 4. Why structlog over stdlib logging

- **Structured:** Every log entry is a dict, not a formatted string
- **Machine-readable:** Easy to parse, filter, aggregate
- **Context binding:** Attach enforcement metadata to all log entries in a call
- **Researcher-friendly:** Clean, readable output by default

### 5. Why NOT hashlib-only for crypto (using `cryptography` library)

`hashlib` is fine for SHA-256 hashing. But we also need:
- HMAC for signed audit entries
- Potential future: asymmetric signing of audit trails
- The `cryptography` library is maintained by security professionals and regularly audited

Using `hashlib` for hashing + `cryptography` for signing gives us the best of both worlds.

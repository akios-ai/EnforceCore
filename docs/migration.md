# Migration Guide

This document covers breaking changes and how to update your code when
upgrading between EnforceCore versions.

---

## v1.0.0b1 — First Beta (API Frozen)

### What "beta" means

Starting with v1.0.0b1, the public API (`__all__`) is **frozen**.
No symbols will be added or removed from `__all__` until v2.0.0.
Only bug fixes and documentation improvements will be made during beta.

### API Surface: Tier 1 vs Tier 2

In v1.0.25a1 the `__all__` was pruned from 110 symbols to 30.
In v1.0.0b1, the ~80 symbols that were removed from `__all__` now
emit a **`DeprecationWarning`** when imported from the top-level package.

**Tier 1 (30 symbols) — stable, no warning:**

```python
from enforcecore import (
    # Enforcement
    enforce, Enforcer,
    # Policy
    Policy, load_policy,
    # Redaction
    Redactor, RedactionResult, RedactionStrategy, SecretScanner,
    # Audit
    Auditor, AuditEntry, VerificationResult, verify_trail, load_trail,
    # Guards
    ResourceGuard, CostTracker, KillSwitch, RateLimiter,
    # Core types
    Decision, EnforcementResult,
    # Errors
    EnforceCoreError, EnforcementViolation, ToolDeniedError,
    ContentViolationError, PolicyError, PolicyLoadError,
    CostLimitError, ResourceLimitError,
    # Config
    Settings, settings,
)
```

**Tier 2 (~80 symbols) — use submodule imports:**

```python
# ❌ Deprecated — emits DeprecationWarning
from enforcecore import JsonlBackend, RuleEngine, on_pre_call

# ✅ Correct — stable submodule imports
from enforcecore.auditor.backends import JsonlBackend
from enforcecore.core.rules import RuleEngine
from enforcecore.plugins.hooks import on_pre_call
```

### How to migrate

1. **Search your codebase** for `from enforcecore import` statements
2. **Check each symbol** against the Tier 1 list above
3. **Move Tier 2 imports** to their canonical submodule path

The deprecation warning message includes the exact submodule path:

```
DeprecationWarning: Importing 'JsonlBackend' from 'enforcecore' is deprecated
and will be removed in v2.0.0. Use 'from enforcecore.auditor.backends import
JsonlBackend' instead.
```

### Submodule import reference

| Symbol | Submodule import |
|--------|-----------------|
| `RuleEngine`, `ContentRule` | `from enforcecore.core.rules import ...` |
| `JsonlBackend`, `MultiBackend` | `from enforcecore.auditor.backends import ...` |
| `on_pre_call`, `on_violation` | `from enforcecore.plugins.hooks import ...` |
| `ScenarioRunner`, `get_all_scenarios` | `from enforcecore.eval import ...` |
| `DomainChecker` | `from enforcecore.guard.network import ...` |
| `EnforceCoreInstrumentor` | `from enforcecore.telemetry import ...` |
| `validate_tool_name`, `check_input_size` | `from enforcecore.core.hardening import ...` |
| `CallContext`, `RedactionEvent` | `from enforcecore.core.types import ...` |

---

## Alpha → Stable (v1.0.xaN → v1.0.0)

If you have been using any alpha release, this section covers everything
you need to update before the stable v1.0.0 release.

### Summary of Breaking Changes

| Change | Alpha Introduced | Alpha Removed | Replacement |
|---|---|---|---|
| `guard_sync()` removed | v1.0.0a1 | v1.0.16a1 | `enforce_sync()` |
| `guard_async()` removed | v1.0.0a1 | v1.0.16a1 | `enforce_async()` |
| `warn_fail_open()` renamed | v1.0.6a1 | v1.0.16a1 | `_warn_fail_open()` (internal) |

---

## v1.0.16a1 — API Freeze & Stability Audit

### 1. `guard_sync()` and `guard_async()` Removed

**What changed:** The `Enforcer.guard_sync()` and `Enforcer.guard_async()`
context managers have been removed. They were deprecated since v1.0.6a1
because they only performed pre-call policy checks — they did **not**
redact PII, enforce resource limits, check content rules, or record
audit entries.

**Before (broken):**

```python
from enforcecore import Enforcer, Policy

policy = Policy.from_file("policy.yaml")
enforcer = Enforcer(policy)

# ❌ This no longer works
with enforcer.guard_sync("search_web") as ctx:
    result = do_search(query)

# ❌ This no longer works either
async with enforcer.guard_async("search_web") as ctx:
    result = await do_search(query)
```

**After (correct):**

```python
from enforcecore import Enforcer, Policy

policy = Policy.from_file("policy.yaml")
enforcer = Enforcer(policy)

# ✅ Full enforcement pipeline (redaction, audit, resource guards)
result = enforcer.enforce_sync(do_search, query, tool_name="search_web")

# ✅ Async version
result = await enforcer.enforce_async(do_search, query, tool_name="search_web")
```

**Why:** `enforce_sync()` and `enforce_async()` provide the complete
enforcement pipeline. Using `guard_sync()` silently skipped PII redaction,
audit trail recording, content rule checking, rate limiting, and resource
guarding. Removing the partial-enforcement path eliminates an entire
class of security gaps (see [attack-surface.md](security/attack-surface.md),
vector A3).

### 2. `warn_fail_open()` Renamed to `_warn_fail_open()`

**What changed:** The `warn_fail_open` function in
`enforcecore.core.hardening` has been renamed to `_warn_fail_open` to
mark it as internal API.

**Impact:** This function was **never** part of `enforcecore.__all__`
and was not intended for external use. If you were importing it directly
from the hardening module, update your import:

```python
# Before
from enforcecore.core.hardening import warn_fail_open

# After
from enforcecore.core.hardening import _warn_fail_open
```

However, you should not need to call this function — it is invoked
automatically by the Enforcer when `fail_open` is enabled.

### 3. `py.typed` Marker Added

**What changed:** The package now includes a PEP 561 `py.typed` marker
file, making it a fully typed package.

**Impact:** If you use `mypy` or another type checker, EnforceCore's
type information will now be automatically discovered. No action needed.

### 4. API Compatibility Test Suite

**What changed:** A new `tests/api/` test suite verifies that every
symbol in `enforcecore.__all__` exists, has the expected type, and
maintains stable signatures.

**Impact:** None — this is a development safeguard. It prevents
accidental API breakage in future releases.

---

## Internal Symbols (Not Part of Public API)

The following symbols are importable but are **not** part of the public
API. They may be renamed, moved, or removed without notice:

| Symbol | Module | Purpose |
|---|---|---|
| `_warn_fail_open` | `enforcecore.core.hardening` | Emits fail-open security warning |
| `_policy_cache` | `enforcecore.core.enforcer` | Internal policy cache dict |
| `_policy_cache_lock` | `enforcecore.core.enforcer` | Threading lock for cache |
| `get_secret_placeholder` | `enforcecore.redactor.secrets` | Secret placeholder lookup |
| `get_secret_mask` | `enforcecore.redactor.secrets` | Secret mask lookup |
| `get_all_secret_categories` | `enforcecore.redactor.secrets` | List secret categories |
| `extract_strings` | `enforcecore.core.hardening` | Extract strings from args |

If you depend on any of these, please open an issue to discuss adding
them to the public API.

---

## Compatibility Reference

For the full versioning policy, deprecation rules, and compatibility
promises, see [docs/versioning.md](versioning.md).

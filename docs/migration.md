# Migration Guide

This document covers breaking changes and how to update your code when
upgrading between EnforceCore versions.

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

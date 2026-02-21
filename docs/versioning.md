# Versioning & Compatibility Policy

> **Applies to:** EnforceCore v1.0.0 and all subsequent v1.x releases.

EnforceCore follows [Semantic Versioning 2.0.0](https://semver.org/).

---

## Version Format

```
MAJOR.MINOR.PATCH[-PRERELEASE]
```

| Segment | Meaning | Example |
|---|---|---|
| **MAJOR** | Incompatible API changes | `2.0.0` |
| **MINOR** | Backward-compatible new features | `1.1.0` |
| **PATCH** | Backward-compatible bug fixes | `1.0.1` |
| **PRERELEASE** | Alpha / beta / release candidate | `1.0.0a1`, `1.0.0b1`, `1.0.0rc1` |

### Alpha Releases (Current)

All `1.0.xaN` releases are **pre-release** versions. The API may change
between alpha releases. Once `1.0.0` (stable) is released, the
compatibility guarantees below take full effect.

---

## What Constitutes a Breaking Change

A **breaking change** is any modification that would cause existing code
using the **public API** to fail, produce different results, or require
code changes. Specifically:

### Breaking (requires MAJOR bump after v1.0.0)

| Change | Example |
|---|---|
| Removing a public symbol from `__all__` | Removing `Enforcer` |
| Renaming a public class, function, or method | `Enforcer` → `RuntimeEnforcer` |
| Changing a function signature incompatibly | Removing a parameter, changing its type |
| Changing exception hierarchy | `ToolDeniedError` no longer inherits from `EnforcementViolation` |
| Changing enum member values | `Decision.allowed` → `Decision.permit` |
| Changing return types | `verify_trail()` returns `bool` instead of `VerificationResult` |
| Removing a configuration setting | Removing `Settings.audit_enabled` |
| Changing default behavior | `fail_open` defaulting to `True` |

### Non-Breaking (allowed in MINOR or PATCH)

| Change | Example |
|---|---|
| Adding new symbols to `__all__` | New exception class |
| Adding optional parameters with defaults | `verify_trail(path, *, verbose=False)` |
| Adding new enum members | `Decision.deferred` |
| Adding new methods to existing classes | `Enforcer.enforce_batch()` |
| Adding new exception subclasses | `NetworkTimeoutError(DomainDeniedError)` |
| Performance improvements | Faster policy evaluation |
| Bug fixes that correct documented behavior | Fixing false negatives in PII detection |
| Internal implementation changes | Refactoring private modules |

---

## Public API Definition

The **public API** consists of:

1. **All symbols in `enforcecore.__all__`** — currently 110 symbols.
2. **All public methods** on exported classes (methods without a leading underscore).
3. **All public attributes** on exported dataclasses and Pydantic models.
4. **Policy YAML schema** — the structure and semantics of policy files.
5. **CLI commands and their flags** — `enforcecore validate`, `verify`, etc.
6. **Configuration environment variables** — `ENFORCECORE_*` settings.

### What Is NOT Public API

- Symbols not in `__all__` (even if importable).
- Functions or classes with a leading underscore (`_warn_fail_open`, `_EnforcementState`).
- Internal module structure (e.g., `enforcecore.core.enforcer._policy_cache`).
- Undocumented behavior or side effects.
- Test utilities and fixtures.

---

## Deprecation Policy

Before removing any public API symbol:

1. **Deprecation warning** — The symbol emits a `DeprecationWarning` with
   a message explaining the replacement.

2. **Deprecation period** — The symbol remains functional for at least
   **2 minor versions** after the deprecation warning is added.

3. **Migration guide** — A `docs/migration.md` entry explains how to
   update code.

4. **Removal** — The symbol is removed in the next major version (or,
   during alpha, in the next alpha release after the deprecation period).

### Example Timeline

```
v1.2.0  — guard_sync() deprecated with DeprecationWarning
v1.3.0  — guard_sync() still works, warning persists
v1.4.0  — guard_sync() still works, warning persists
v2.0.0  — guard_sync() removed
```

### Alpha Exception

During the alpha phase (v1.0.xaN), the deprecation period may be
shortened to **1 release** since the API is not yet stable. This is
what happened with `guard_sync`/`guard_async`:

```
v1.0.6a1  — Deprecated with DeprecationWarning
v1.0.16a1 — Removed (API freeze release)
```

---

## Backport Policy

| Release Stream | Backported | Duration |
|---|---|---|
| Latest stable (v1.x) | Security fixes, critical bugs | Until next MAJOR |
| Previous MAJOR (v0.x) | Not applicable (no v0.x exists) | — |
| Alpha releases | Not backported — upgrade to latest alpha | — |

---

## Compatibility Promises (v1.x)

Once v1.0.0 is released:

1. **`pip install enforcecore` will not break your code** on any v1.x upgrade.
2. **Policy YAML files** written for v1.0 will load in all v1.x releases.
3. **Audit trail files** written by v1.0 will be verifiable by all v1.x releases.
4. **Exception types** in `except` clauses will not change hierarchy.
5. **`py.typed`** — the package will remain PEP 561 compliant.

---

## Version Consistency

The version string is maintained in three locations, which must always
agree:

| Location | Symbol |
|---|---|
| `pyproject.toml` | `project.version` |
| `enforcecore/__init__.py` | `__version__` |
| `enforcecore/telemetry/instrumentor.py` | `_SCOPE_VERSION` |

CI verifies consistency. The API compatibility test suite (`tests/api/`)
validates that `__version__` matches the expected format (PEP 440).

---

## Reporting Compatibility Issues

If you believe a release introduced an unintentional breaking change:

1. Check `docs/migration.md` — the change may be documented.
2. Check the CHANGELOG — the change may be an intentional fix.
3. Open a GitHub issue with the label `compatibility`.

We take backward compatibility seriously. Unintentional breaks are
treated as **critical bugs** and fixed in a patch release.

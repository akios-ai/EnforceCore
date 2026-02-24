# EnforceCore Release Process

**Last updated:** February 2026
**Applies to:** v1.0.x patches and v1.x.0 minor releases

---

## Overview

Every release goes through three phases. No phase may be skipped.

```
Phase 1: Pre-Release (local)     → catches what broke us before
Phase 2: Release (automated)     → scripts/release.py does the work
Phase 3: Post-Release (verify)   → confirms the world is correct
```

---

## Phase 1 — Pre-Release Gate

**Run before touching release.py.** This catches the exact issues that caused
5 consecutive CI failures on v1.0.1:

### 1.1 Code Quality (CI parity)

These four commands must pass locally. They are the exact same checks CI runs.

```bash
# Format check — CI runs this FIRST and it's the one people forget
ruff format --check .

# Lint
ruff check .

# Type checking
mypy enforcecore/

# Tests (with CI-matching timeout + hypothesis settings)
HYPOTHESIS_MAX_EXAMPLES=10 pytest --timeout=60 -q
```

**Shortcut:** Run the gate script instead:

```bash
python scripts/pre_release_gate.py
```

### 1.2 Version Consistency

Version must match across all four files:

| File | Field |
|------|-------|
| `pyproject.toml` | `version = "X.Y.Z"` |
| `enforcecore/__init__.py` | `__version__ = "X.Y.Z"` |
| `CITATION.cff` | `version: "X.Y.Z"` |
| `enforcecore/telemetry/instrumentor.py` | `_SCOPE_VERSION = "X.Y.Z"` |

The gate script checks this automatically.

### 1.3 Stale Version Directives

Sphinx docstrings must not contain version numbers higher than the current
release. This catches pre-release iteration artifacts (e.g., `versionadded:: 1.0.24`
when releasing `1.0.1`).

The gate script scans all `.py` files for `versionadded` and `versionchanged`
directives and flags any with impossible version numbers.

### 1.4 CHANGELOG

`CHANGELOG.md` must have an `[Unreleased]` section with content describing
what's new. Empty `[Unreleased]` sections block the release.

### 1.5 Documentation Strings

Scan `__init__.py` and `scripts/` for stale beta/pre-release version references
(e.g., "v1.0.0b5+").

---

## Phase 2 — Release Execution

**Only after Phase 1 passes.** Use the automation script:

```bash
# Dry run first — see what will change:
python scripts/release.py 1.1.0

# Execute — bump, build, commit, tag, push, wait for CI + PyPI:
python scripts/release.py 1.1.0 --execute

# If you want to review before pushing:
python scripts/release.py 1.1.0 --execute --local-only
# Then later:
python scripts/release.py 1.1.0 --push-only
```

### What release.py does (12 steps)

| Step | Action | Automated? |
|------|--------|-----------|
| 1 | Pre-flight: clean tree, main branch, remote reachable | ✅ |
| 2 | Validate version format | ✅ |
| 3 | Quality gate: pytest + ruff check + ruff format + mypy | ✅ |
| 4 | Bump version in 4 files | ✅ |
| 5 | Update CHANGELOG `[Unreleased]` → new version header | ✅ |
| 6 | Build sdist + wheel | ✅ |
| 7 | Verify artifacts (no `internal/` leakage, clean import) | ✅ |
| 8 | Git commit + tag | ✅ |
| 9 | Push to origin | ✅ |
| 10 | Wait for GitHub Actions CI to pass | ✅ |
| 11 | Wait for PyPI publication (OIDC trusted publishing) | ✅ |
| 12 | Post-release verification from PyPI | ✅ |

---

## Phase 3 — Post-Release Verification

After CI is green and PyPI is live:

```bash
# Verify the published package:
python scripts/post_release_verify.py 1.1.0

# Or verify latest:
python scripts/post_release_verify.py
```

### Manual checklist (5 minutes)

- [ ] `pip install enforcecore==X.Y.Z` in a fresh venv works
- [ ] `python -c "import enforcecore; print(enforcecore.__version__)"` shows correct version
- [ ] GitHub Release page exists with correct changelog
- [ ] CI shows green on the tagged commit
- [ ] No `internal/` content visible in the PyPI file listing

---

## Release Types

### Patch (v1.0.x)

Bug fixes only. No new features, no API changes.

```bash
python scripts/pre_release_gate.py
python scripts/release.py 1.0.2 --execute
```

### Minor (v1.x.0)

New features, new scenarios, new modules. API additions only (no breaking changes).

```bash
# Extra step: review CHANGELOG for completeness
python scripts/pre_release_gate.py
python scripts/release.py 1.1.0 --execute
```

### Pre-release (alpha/beta/rc)

For testing before a minor release:

```bash
python scripts/pre_release_gate.py
python scripts/release.py 1.1.0a1 --execute
```

---

## What Went Wrong Before (Lessons Learned)

### v1.0.1 → 5 consecutive CI failures

| Root Cause | Gate That Catches It |
|------------|---------------------|
| `ruff format` not run locally before push | Phase 1.1: `ruff format --check .` |
| Import order wrong in `policy.py` | Phase 1.1: `ruff check .` |
| Wrong attribute names on `VerificationResult` | Phase 1.1: `mypy enforcecore/` |
| Non-existent kwargs passed to `Enforcer()` | Phase 1.1: `mypy enforcecore/` |
| 27 stale `versionadded:: 1.0.X` directives | Phase 1.3: version directive scan |
| `__init__.py` docstring said "v1.0.0b5+" | Phase 1.5: stale reference scan |

**Every single failure would have been caught by running `pre_release_gate.py`
before pushing.**

---

## File Inventory

| File | Purpose |
|------|---------|
| `RELEASE_PROCESS.md` | This document — human-readable process |
| `scripts/pre_release_gate.py` | Automated Phase 1 checks |
| `scripts/release.py` | Phase 2 automation (bump → build → push → verify) |
| `scripts/post_release_verify.py` | Phase 3 PyPI verification |
| `.github/workflows/release.yml` | CI: quality → build → publish → GitHub Release |
| `.github/workflows/ci.yml` | CI: lint + typecheck + test + benchmark (every push) |

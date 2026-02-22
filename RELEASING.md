# Releasing EnforceCore

Complete runbook for shipping EnforceCore releases to PyPI.

> **One command does everything:**
> ```bash
> python scripts/release.py 1.0.21a1 --execute
> ```

---

## Quick Reference

| Command | What it does |
|---|---|
| `python scripts/release.py 1.0.21a1` | Dry-run — shows what would change |
| `python scripts/release.py 1.0.21a1 --execute` | **Full release** — test, bump, build, push, wait, verify |
| `python scripts/release.py 1.0.21a1 --execute --local-only` | Local only — no push, no CI wait |
| `python scripts/release.py 1.0.21a1 --push-only` | Push existing tag + wait for CI + verify |
| `python scripts/post_release_verify.py 1.0.21a1` | Verify a published release (12 checks) |

---

## Prerequisites

| Requirement | How to check | Purpose |
|---|---|---|
| Python 3.11+ | `python --version` | Build environment |
| venv activated | `which python` → `.venv/bin/python` | Correct deps |
| `build` package | `pip show build` | Package building |
| Git push access | `git push --dry-run` | Tagging and pushing |
| GitHub "pypi" environment | Repo → Settings → Environments | OIDC publishing |
| PyPI trusted publisher | pypi.org → Manage → Publishing | No tokens needed |

### One-time setup (already done)

1. **PyPI trusted publisher** configured at
   [pypi.org/manage/project/enforcecore/settings/publishing/](https://pypi.org/manage/project/enforcecore/settings/publishing/):
   - Owner: `akios-ai`
   - Repository: `EnforceCore`
   - Workflow: `release.yml`
   - Environment: `pypi`

2. **GitHub environment** `pypi` created at
   Settings → Environments → `pypi`.

---

## Full Release Process

### The Automated Way (recommended)

```bash
# From repo root, venv activated:
python scripts/release.py 1.0.21a1 --execute
```

This single command performs ALL 12 steps:

1. ✅ Validates version format
2. ✅ Checks branch is `main`, tree is clean, remote reachable
3. ✅ Runs `pytest` (1472+ tests)
4. ✅ Runs `ruff check .`
5. ✅ Runs `ruff format --check .` ← **this caught the v1.0.20a1 CI failure**
6. ✅ Runs `mypy enforcecore/`
7. ✅ Bumps version in 4 files + CHANGELOG date
8. ✅ Builds sdist + wheel, verifies no `internal/` leakage
9. ✅ Tests clean install in fresh venv (all 110+ symbols)
10. ✅ Git commits + tags
11. ✅ Pushes to origin, waits for GitHub Actions CI to pass
12. ✅ Waits for PyPI, runs 12-point post-release verification

### If something fails mid-way

| Failure point | Recovery |
|---|---|
| Quality checks fail | Fix the issue, re-run |
| Build fails | `pip install --upgrade build hatchling`, re-run |
| Push fails | Check git remote auth, re-run with `--push-only` |
| CI fails | Fix, delete tag, re-run full release |
| PyPI timeout | Check pypi.org manually; run `python scripts/post_release_verify.py` |

### If you need to re-tag

```bash
# Delete broken tag locally and on remote:
git tag -d v1.0.21a1
git push origin :refs/tags/v1.0.21a1

# Fix the issue, then either:
python scripts/release.py 1.0.21a1 --execute --skip-tests
# or manually:
git tag -a v1.0.21a1 -m "Release v1.0.21a1"
python scripts/release.py 1.0.21a1 --push-only
```

---

## Post-Release Verification

After any release, run:

```bash
python scripts/post_release_verify.py 1.0.21a1
```

This performs **12 independent checks** from a clean venv:

| # | Check | What it verifies |
|---|---|---|
| 1 | PyPI metadata | Version, name, Python requires, summary |
| 2 | Homepage URL | Points to akios.ai/enforcecore |
| 3 | License | Apache-2.0 declared |
| 4 | Artifacts | Both wheel and sdist exist |
| 5 | README on PyPI | Description present, logo reference |
| 6 | Clean install | `pip install` succeeds from PyPI |
| 7 | Import + version | `import enforcecore` works, version matches |
| 8 | Public API symbols | All 110+ `__all__` symbols importable |
| 9 | Core classes | Enforcer, Policy, Redactor, Auditor, etc. instantiate |
| 10 | @enforce() decorator | PII redaction works end-to-end |
| 11 | Tool denial | ToolDeniedError raised correctly |
| 12 | Audit + Merkle chain | Audit entries written, chain verifiable |

Plus: async enforcement, content rules, secret scanning, no leakage,
dependencies correct, disclaimer present.

---

## Version Files

The release script automatically updates these files:

| File | Field |
|---|---|
| `pyproject.toml` | `version = "..."` |
| `enforcecore/__init__.py` | `__version__ = "..."` |
| `CITATION.cff` | `version: "..."` and `date-released: "..."` |
| `enforcecore/telemetry/instrumentor.py` | `_SCOPE_VERSION = "..."` |
| `CHANGELOG.md` | `## [Unreleased]` → `## [x.y.z] — YYYY-MM-DD` |

---

## CI Pipeline (release.yml)

Triggered by pushing a `v*` tag:

```
quality (macOS × 3.11/3.12/3.13)
  → ruff check → ruff format → mypy → pytest (60s timeout/test)
    → build (Ubuntu)
      → verify wheel/sdist, clean install test
        → pypi (OIDC trusted publishing)
        → github-release (changelog + artifacts)
```

### Known CI Gotchas

| Issue | Cause | Solution |
|---|---|---|
| Ubuntu pytest hangs | RLIMIT_AS memory tests + hypothesis on slow runners | macOS-only for release gate; `pytest-timeout=60` added |
| `ruff format --check` fails | Formatting not checked locally before push | Release script now checks this automatically |
| OIDC publish fails | Missing `pypi` environment or trusted publisher | Check repo Settings → Environments |

---

## Safety Guarantees

Every release verifies:

1. **No `internal/` leakage** — Private `internal/` directory excluded from
   both wheel and sdist
2. **Clean install** — Fresh venv can install and import all public symbols
3. **All tests pass** — Full 1472+ test suite green
4. **Type safety** — mypy strict mode on all source files
5. **Code quality** — ruff lint + format checks
6. **Functional** — PII redaction, tool denial, audit trail, content rules
   all work from the published package

---

## Version Scheme

```
1.0.20a1    ← alpha (pre-release, expect breaking changes)
1.0.20b1    ← beta (feature-complete, bug fixes only)
1.0.20rc1   ← release candidate (final testing)
1.0.20      ← stable release
```

Pre-release versions are automatically marked as such on both PyPI and
GitHub Releases.

---

## Manual Fallback

If automation fails completely:

```bash
# 1. Build locally
python -m build --sdist --wheel

# 2. Upload to PyPI (requires API token — avoid if possible)
python -m twine upload dist/*

# 3. Verify
python scripts/post_release_verify.py <VERSION>
```

⚠️ **Never paste API tokens in chat, logs, or terminal history.**
Use OIDC trusted publishing (automated) whenever possible.

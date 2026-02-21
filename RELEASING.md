# Releasing EnforceCore

This document describes the structured, reproducible release process for
EnforceCore.

## Prerequisites

| Requirement | Purpose |
|---|---|
| Python 3.11+ | Build environment |
| `pip install build twine` | Package building & upload |
| Git (with push access) | Tagging and pushing |
| PyPI account | Package publication |
| GitHub repo access | Release creation |

## Release Process (Step by Step)

### Step 1 — Pre-flight Checks

Run the full quality gate locally:

```bash
# From the repo root, with your venv activated:
pytest --tb=short -q           # All tests must pass
ruff check .                   # Zero lint issues
ruff format --check .          # Formatting correct
mypy enforcecore/              # Zero type errors
```

### Step 2 — Dry Run

```bash
python scripts/release.py <NEW_VERSION>
# e.g. python scripts/release.py 1.0.20a1
```

This will:
- Validate the version format
- Show which files would be updated
- **Not** modify any files

Review the output. If it looks correct, proceed.

### Step 3 — Execute Release

```bash
python scripts/release.py <NEW_VERSION> --execute
# Or, if you already ran tests in Step 1:
python scripts/release.py <NEW_VERSION> --execute --skip-tests
```

This will:
1. Bump version in `pyproject.toml`, `enforcecore/__init__.py`,
   `CITATION.cff`, and `enforcecore/telemetry/instrumentor.py`
2. Update `CITATION.cff` release date
3. Insert a new version header in `CHANGELOG.md`
4. Build sdist + wheel in `dist/`
5. Verify no `internal/` folder leakage in artifacts
6. Test clean install from the wheel (fresh venv)
7. Verify all 110+ public API symbols import correctly
8. Git commit with message `release: v<NEW_VERSION>`
9. Git tag `v<NEW_VERSION>`

### Step 4 — Push

```bash
git push origin main --tags
```

This triggers the GitHub Actions release workflow (`.github/workflows/release.yml`),
which will:
- Run the full CI matrix (3.11–3.13 × Ubuntu + macOS)
- Rebuild and verify artifacts
- Publish to PyPI (via trusted publishing / OIDC)
- Create a GitHub Release with changelog

### Step 5 — Verify Publication

1. Check [PyPI](https://pypi.org/project/enforcecore/) for the new version
2. Check [GitHub Releases](https://github.com/akios-ai/EnforceCore/releases)
3. Test installation from PyPI:
   ```bash
   pip install enforcecore==<NEW_VERSION>
   python -c "import enforcecore; print(enforcecore.__version__)"
   ```

### Step 6 — Post-Release

Update `README.md` and `docs/roadmap.md` to mark the milestone as shipped.

## Manual PyPI Upload (if not using GitHub Actions)

```bash
# Upload to TestPyPI first:
python -m twine upload --repository testpypi dist/*

# Verify from TestPyPI:
pip install --index-url https://test.pypi.org/simple/ enforcecore==<VERSION>

# Upload to production PyPI:
python -m twine upload dist/*
```

## Version Files

The release script automatically updates these files:

| File | Field |
|---|---|
| `pyproject.toml` | `version = "..."` |
| `enforcecore/__init__.py` | `__version__ = "..."` |
| `CITATION.cff` | `version: "..."` and `date-released: "..."` |
| `enforcecore/telemetry/instrumentor.py` | `_SCOPE_VERSION = "..."` |
| `CHANGELOG.md` | `## [Unreleased]` → `## [x.y.z] — YYYY-MM-DD` |

## Safety Guarantees

The release process verifies that:

1. **No `internal/` leakage** — The private `internal/` directory is excluded
   from both wheel and sdist via `.gitignore` + explicit `pyproject.toml`
   hatch build excludes
2. **Clean install works** — A fresh venv can install the wheel and import
   all public symbols
3. **All tests pass** — The full 1400+ test suite runs green
4. **Type safety** — mypy strict mode passes on all source files
5. **Code quality** — ruff lint + format checks pass
6. **20/20 scenarios contained** — All adversarial evaluation scenarios pass

## Troubleshooting

### "internal/ leaked into wheel/sdist!"

Check that `.gitignore` contains `internal/` and that `pyproject.toml` has:

```toml
[tool.hatch.build.targets.sdist]
exclude = ["internal/", ".github/"]
```

### Build fails

```bash
pip install --upgrade build hatchling
python -m build --sdist --wheel
```

### PyPI upload fails

- Ensure you have a PyPI API token or trusted publishing configured
- For trusted publishing, configure at:
  https://pypi.org/manage/project/enforcecore/settings/publishing/

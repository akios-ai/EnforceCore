# EnforceCore v1.1.1 — Issue Tracker (Fixed)

Issues identified during deep end-to-end testing of v1.1.0 (clean PyPI install, Python 3.12).

## 🔴 Critical / High Priority

### 1. CLI entrypoint crashes on bare install

**Category:** Packaging  
**Severity:** 🔴 High  
**Reproduction:**
```bash
pip install enforcecore
enforcecore --help
# ModuleNotFoundError: No module named 'typer'
```

**Root cause:** `pyproject.toml` registers `enforcecore = "enforcecore.cli.main:app"` as a console script, but `typer` is only in the `[cli]` optional extra. Every user who does `pip install enforcecore` gets a broken `enforcecore` binary in their PATH.

**Fix options:**
1. Move `typer` to core dependencies (increases install size)
2. Move CLI to a lazy import with a helpful error message
3. Guard the entrypoint: try to import typer, if missing print "pip install enforcecore[cli]"
4. Remove console_scripts and only register CLI via `python -m enforcecore.cli`

**Recommended:** Option 3 — guard the entrypoint with a helpful message.

---

### 2. `enforce()` decorator uses function name as tool_name — not documented

**Category:** API / Documentation  
**Severity:** 🔴 High (UX issue)  
**Reproduction:**
```python
@enforce(policy="policy.yaml")
async def my_search_function(query: str) -> str:  # <- "my_search_function" ≠ "search_web"
    return await api.search(query)

await my_search_function("test")  # ToolDeniedError!
```

**Root cause:** When `tool_name=` is not specified, the decorator uses `func.__name__` as the tool name. If the function name doesn't exactly match an entry in `allowed_tools`, it gets blocked.

**Current README examples work by coincidence** — the function names (`search_web`, `calculator`, `execute_shell`) match the policy entries exactly. But the README never explains this behavior.

**Fix:**
1. Add a note in Quick Start explaining the function-name-as-tool-name behavior
2. Show an example using `tool_name=` parameter for custom function names
3. Consider adding a warning log when the auto-detected tool name is not in the policy

---

### 3. `python -m enforcecore` doesn't work

**Category:** Packaging  
**Severity:** 🟡 Medium  
**Reproduction:**
```bash
python -m enforcecore --help
# 'enforcecore' is a package and cannot be directly executed
```

**Fix:** Add `enforcecore/__main__.py`:
```python
from enforcecore.cli.main import app
app()
```

---

## 🟡 Medium Priority

### 4. `RedactionStrategy` not importable from `enforcecore.redactor`

**Category:** API discoverability  
**Severity:** 🟡 Medium  
**Reproduction:**
```python
from enforcecore.redactor import RedactionStrategy  # ImportError!
from enforcecore import RedactionStrategy  # Works
```

**Fix:** Re-export `RedactionStrategy` from `enforcecore/redactor/__init__.py`.

---

### 5. `Auditor.record()` signature is not intuitive

**Category:** API ergonomics  
**Severity:** 🟡 Medium  
**Details:** The `record()` method requires many keyword-only arguments:
```python
auditor.record(
    tool_name="search",
    policy_name="my-policy",
    policy_version="1.0",
    decision="allowed",
    ...
)
```

A simpler wrapper for common use cases would improve DX:
```python
auditor.log("search", decision="allowed")  # minimal API
```

**Fix:** Consider adding a simplified `log()` convenience method that derives `policy_name` / `policy_version` from context.

---

### 6. `ScenarioRunner` requires `policy` argument — not obvious

**Category:** API discoverability  
**Severity:** 🟡 Medium  
**Reproduction:**
```python
from enforcecore.eval.runner import ScenarioRunner
runner = ScenarioRunner()  # TypeError: missing 'policy'
```

**Fix:** 
1. Allow `ScenarioRunner()` with no args to use a default strict policy
2. Or document clearly in docstring and README evaluation section

---

### 7. README: Roadmap table says "v1.0.1 — PII Redactor + Bug Fixes"

**Category:** Documentation accuracy  
**Severity:** 🟡 Low  
**Details:** The roadmap description for v1.0.1 is a bit vague. The table is clean enough but could link to CHANGELOG for details.

---

## 🟢 Low Priority / Polish

### 8. `RedactionResult.text` naming

**Category:** API naming  
**Severity:** 🟢 Low  
**Details:** The attribute is `.text` (redacted output) and `.original_text`. A name like `.redacted_text` would be more self-documenting. Non-breaking change is hard since it would be a rename.

**Fix:** Add a `.redacted_text` property alias (deprecation-free).

---

### 9. No `Auditor.verify()` convenience method

**Category:** API completeness  
**Severity:** 🟢 Low  
**Details:** The Merkle chain verification is a core feature but there's no simple `auditor.verify()` method. Verification requires loading the trail separately via `verify_trail()`.

**Fix:** Add `Auditor.verify() -> bool` that calls `verify_trail` on the current output path.

---

### 10. Debug logging is noisy by default

**Category:** UX  
**Severity:** 🟢 Low  
**Details:** When running with `@enforce()`, structlog outputs debug-level messages like `audit_chain_resumed`, `enforcement_scope_entered`, etc. to stderr. In a production app, this is noisy.

**Fix:** Set default log level to WARNING, let users opt-in to DEBUG via `ENFORCECORE_LOG_LEVEL=DEBUG` or similar.

---

### 11. Static badge fallback

**Category:** Documentation  
**Severity:** 🟢 Low (fixed in this session)  
**Details:** README had static badges for tests (1520_passed) and coverage (95%) that go stale between releases.

**Status:** ✅ Fixed — replaced with live PyPI badges + Ruff badge.

---

### 12. Contributing nav link pointed to `docs/contributing.md` instead of `CONTRIBUTING.md`

**Category:** Documentation  
**Severity:** 🟢 Low (fixed in this session)  
**Details:** The top nav bar linked to `docs/contributing.md` while the standard GitHub convention is `CONTRIBUTING.md` at root.

**Status:** ✅ Fixed.

---

### 13. Researchers section had stale scenario counts

**Category:** Documentation  
**Severity:** 🟢 Low (fixed in this session)  
**Details:** Said "20 scenarios across 10 threat categories" but v1.1.0 shipped with 26 scenarios across 11 categories.

**Status:** ✅ Fixed.

---

### 14. Development section had stale test count

**Category:** Documentation  
**Severity:** 🟢 Low (fixed in this session)  
**Details:** Said "1510 tests" but current count is 1520.

**Status:** ✅ Fixed.

---

## Summary

| Severity | Count | Fixed this session |
|---|---|---|
| 🔴 Critical | 3 | 0 |
| 🟡 Medium | 4 | 0 |
| 🟢 Low | 7 | 4 |
| **Total** | **14** | **4** |

### Recommended for v1.2.0

1. **CLI entrypoint guard** — add graceful error when typer is missing
2. **Document `tool_name=` parameter** — README Quick Start needs a note
3. **Re-export `RedactionStrategy` from `enforcecore.redactor`**
4. **Add `__main__.py`** for `python -m enforcecore` support
5. **Default log level to WARNING** — reduce noise for production users

### Nice-to-have for v1.2.0

6. Simplified `Auditor.log()` wrapper
7. `ScenarioRunner()` default policy
8. `RedactionResult.redacted_text` alias
9. `Auditor.verify()` convenience method

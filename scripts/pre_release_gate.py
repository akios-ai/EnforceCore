#!/usr/bin/env python3
# Copyright 2025 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Pre-release gate — catches issues BEFORE they reach CI.

Run this before every release. It performs the exact same checks as CI
plus additional hygiene checks that CI doesn't cover (stale version
directives, version consistency, CHANGELOG completeness).

Usage:
    python scripts/pre_release_gate.py          # full gate
    python scripts/pre_release_gate.py --quick   # skip tests (lint + hygiene only)

Exit code 0 = ready to release, non-zero = fix issues first.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parent.parent

# ── Output helpers ────────────────────────────────────────────────────────

_PASS = 0
_FAIL = 0
_WARN = 0


class CheckResult(NamedTuple):
    name: str
    passed: bool
    detail: str = ""


def _log(msg: str, *, level: str = "info") -> None:
    symbols = {"info": "·", "ok": "✓", "warn": "⚠", "err": "✗", "step": "▸", "head": "━"}
    print(f"  {symbols.get(level, '-')} {msg}")


def _section(title: str) -> None:
    print()
    print(f"  ━━ {title} ━━")


def _check(name: str, passed: bool, detail: str = "") -> bool:
    global _PASS, _FAIL
    if passed:
        _PASS += 1
        _log(f"{name}" + (f": {detail}" if detail else ""), level="ok")
    else:
        _FAIL += 1
        _log(f"{name}" + (f": {detail}" if detail else ""), level="err")
    return passed


def _warn(name: str, detail: str = "") -> None:
    global _WARN
    _WARN += 1
    _log(f"{name}" + (f": {detail}" if detail else ""), level="warn")


def _run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kwargs)


# ── Gate 1: Code Quality (CI Parity) ─────────────────────────────────────


def gate_ruff_format() -> bool:
    """Check ruff format (the one people forget)."""
    r = _run([sys.executable, "-m", "ruff", "format", "--check", "."])
    if r.returncode != 0:
        lines = [line for line in r.stdout.splitlines() if line.strip() and "would" in line.lower()]
        count = len(lines)
        detail = f"{count} file(s) need reformatting — run: ruff format ."
        return _check("ruff format", False, detail)
    return _check("ruff format", True, "all files formatted")


def gate_ruff_check() -> bool:
    """Check ruff lint."""
    r = _run([sys.executable, "-m", "ruff", "check", "."])
    if r.returncode != 0:
        errors = [line for line in r.stdout.splitlines() if line.strip()]
        return _check("ruff check", False, f"{len(errors)} issue(s)")
    return _check("ruff check", True, "no lint issues")


def gate_mypy() -> bool:
    """Check mypy type checking."""
    r = _run([sys.executable, "-m", "mypy", "enforcecore/"])
    if r.returncode != 0:
        error_lines = [line for line in r.stdout.splitlines() if ": error:" in line]
        return _check("mypy", False, f"{len(error_lines)} type error(s)")
    return _check("mypy", True, "no type errors")


def gate_pytest() -> bool:
    """Run tests with CI-matching settings."""
    env = {**os.environ, "HYPOTHESIS_MAX_EXAMPLES": "10"}
    r = _run(
        [sys.executable, "-m", "pytest", "-q", "--tb=short", "--timeout=60"],
        env=env,
    )
    if r.returncode != 0:
        return _check("pytest", False, "tests failed")
    # Extract summary
    for line in reversed(r.stdout.splitlines()):
        if "passed" in line:
            return _check("pytest", True, line.strip())
    return _check("pytest", True)


# ── Gate 2: Version Consistency ───────────────────────────────────────────

_VERSION_FILES: list[tuple[Path, str]] = [
    (ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
    (ROOT / "enforcecore" / "__init__.py", r'^__version__\s*=\s*"([^"]+)"'),
    (ROOT / "CITATION.cff", r'^version:\s*"([^"]+)"'),
    (
        ROOT / "enforcecore" / "telemetry" / "instrumentor.py",
        r'^_SCOPE_VERSION\s*=\s*"([^"]+)"',
    ),
]


def gate_version_consistency() -> bool:
    """All version files must agree."""
    versions: dict[str, str] = {}
    for path, pattern in _VERSION_FILES:
        if not path.exists():
            _warn(f"Version file missing: {path.relative_to(ROOT)}")
            continue
        match = re.search(pattern, path.read_text(), re.MULTILINE)
        if match:
            versions[str(path.relative_to(ROOT))] = match.group(1)
        else:
            _warn(f"Version pattern not found in {path.relative_to(ROOT)}")

    unique = set(versions.values())
    if len(unique) == 1:
        ver = unique.pop()
        return _check("version consistency", True, f"all {len(versions)} files = {ver}")
    else:
        detail = ", ".join(f"{f}={v}" for f, v in versions.items())
        return _check("version consistency", False, f"MISMATCH: {detail}")


# ── Gate 3: Stale Version Directives ─────────────────────────────────────


def gate_stale_version_directives() -> bool:
    """Sphinx versionadded/versionchanged directives must not reference
    versions higher than the current release."""
    # Get current version
    init = ROOT / "enforcecore" / "__init__.py"
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init.read_text())
    if not m:
        return _check("version directives", False, "cannot read __version__")

    current = m.group(1)
    # Parse version tuple (handle pre-release suffixes like 1.0.1a1)
    current_base = re.match(r"(\d+)\.(\d+)\.(\d+)", current)
    if not current_base:
        return _check("version directives", False, f"cannot parse version: {current}")

    cur_tuple = tuple(int(x) for x in current_base.groups())

    stale: list[str] = []
    directive_re = re.compile(r"\.\.\s+version(?:added|changed)::\s*(\d+\.\d+\.\d+)")

    for py_file in (ROOT / "enforcecore").rglob("*.py"):
        text = py_file.read_text()
        for match in directive_re.finditer(text):
            ver = match.group(1)
            parts = tuple(int(x) for x in ver.split("."))
            if parts > cur_tuple:
                rel = py_file.relative_to(ROOT)
                stale.append(f"{rel}: {ver}")

    # Also check tests/
    for py_file in (ROOT / "tests").rglob("*.py"):
        if not py_file.exists():
            continue
        text = py_file.read_text()
        for match in directive_re.finditer(text):
            ver = match.group(1)
            parts = tuple(int(x) for x in ver.split("."))
            if parts > cur_tuple:
                rel = py_file.relative_to(ROOT)
                stale.append(f"{rel}: {ver}")

    if stale:
        detail = f"{len(stale)} directive(s) reference future versions: {', '.join(stale[:5])}"
        return _check("version directives", False, detail)
    return _check("version directives", True, f"all directives ≤ {current}")


# ── Gate 4: CHANGELOG ─────────────────────────────────────────────────────


def gate_changelog() -> bool:
    """CHANGELOG.md must have [Unreleased] with content."""
    changelog = ROOT / "CHANGELOG.md"
    if not changelog.exists():
        return _check("CHANGELOG", False, "CHANGELOG.md not found")

    text = changelog.read_text()

    # Check [Unreleased] exists
    if "## [Unreleased]" not in text:
        return _check("CHANGELOG", False, "missing [Unreleased] section")

    # Check if there's content between [Unreleased] and the next version header
    unreleased_match = re.search(
        r"## \[Unreleased\]\s*\n(.*?)(?=## \[|\Z)",
        text,
        re.DOTALL,
    )
    if unreleased_match:
        content = unreleased_match.group(1).strip()
        if not content:
            _warn("CHANGELOG", "[Unreleased] section is empty — add release notes before releasing")
        else:
            return _check("CHANGELOG", True, f"[Unreleased] has content ({len(content)} chars)")

    return _check("CHANGELOG", True, "[Unreleased] section present")


# ── Gate 5: Stale References ─────────────────────────────────────────────


def gate_stale_references() -> bool:
    """Check for pre-release version strings in key files.

    Skips files where alpha/beta references are legitimate
    (examples, historical changelog, usage docs).
    """
    stale_patterns = [
        (r"v\d+\.\d+\.\d+b\d+", "beta version reference"),
        (r"v\d+\.\d+\.\d+a\d+", "alpha version reference"),
    ]

    # Only check files where stale pre-release refs are a real problem
    key_files = [
        ROOT / "enforcecore" / "__init__.py",
    ]

    issues: list[str] = []
    for path in key_files:
        if not path.exists():
            continue
        text = path.read_text()
        for pattern, desc in stale_patterns:
            matches = re.findall(pattern, text)
            if matches:
                rel = path.relative_to(ROOT)
                issues.append(f"{rel}: {desc} ({matches[0]})")

    if issues:
        return _check("stale references", False, f"{len(issues)} issue(s): {', '.join(issues[:3])}")
    return _check("stale references", True, "no pre-release references in key files")


# ── Gate 6: Git State ─────────────────────────────────────────────────────


def gate_git_state() -> bool:
    """Working tree should be clean and on main."""
    ok = True

    r = _run(["git", "status", "--porcelain"])
    dirty = r.stdout.strip()
    if dirty:
        count = len(dirty.splitlines())
        _warn("git status", f"{count} uncommitted change(s) — commit or stash before releasing")
    else:
        _check("git status", True, "clean working tree")

    r = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    branch = r.stdout.strip()
    if branch != "main":
        _warn("git branch", f"on '{branch}' — releases should be from main")
    else:
        _check("git branch", True, "on main")

    return ok


# ── Main ──────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(description="Pre-release gate checks")
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip pytest (lint + hygiene checks only)",
    )
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  EnforceCore Pre-Release Gate")
    print("=" * 60)

    # ── Hygiene gates (fast, always run) ──────────────────────────────
    _section("Git State")
    gate_git_state()

    _section("Version Consistency")
    gate_version_consistency()

    _section("Stale Version Directives")
    gate_stale_version_directives()

    _section("Stale References")
    gate_stale_references()

    _section("CHANGELOG")
    gate_changelog()

    # ── Code quality gates (CI parity) ────────────────────────────────
    _section("Code Quality (CI Parity)")
    gate_ruff_format()
    gate_ruff_check()
    gate_mypy()

    if not args.quick:
        gate_pytest()
    else:
        _log("pytest: SKIPPED (--quick mode)", level="warn")

    # ── Summary ───────────────────────────────────────────────────────
    print()
    print("=" * 60)
    total = _PASS + _FAIL
    if _FAIL == 0:
        print(f"  GATE PASSED — {_PASS}/{total} checks passed")
        if _WARN > 0:
            print(f"  ({_WARN} warning(s) — review before releasing)")
        print()
        print("  Ready to release:")
        print("    python scripts/release.py <version> --execute")
    else:
        print(f"  GATE FAILED — {_FAIL}/{total} checks failed")
        print()
        print("  Fix the issues above before releasing.")
    print("=" * 60)
    print()

    sys.exit(1 if _FAIL > 0 else 0)


if __name__ == "__main__":
    main()

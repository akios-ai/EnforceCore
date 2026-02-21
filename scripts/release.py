#!/usr/bin/env python3
# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore release automation script.

Usage:
    # Dry-run (default) — shows what would change, builds, runs checks:
    python scripts/release.py 1.0.20a1

    # Execute — actually writes files, commits, tags:
    python scripts/release.py 1.0.20a1 --execute

    # Skip tests (if you already ran them):
    python scripts/release.py 1.0.20a1 --execute --skip-tests

Steps performed:
    1. Validate new version string
    2. Run full test suite, ruff, mypy  (unless --skip-tests)
    3. Bump version in all files
    4. Update CHANGELOG [Unreleased] → new version
    5. Build sdist + wheel
    6. Verify artifacts (no internal/ leakage, clean import)
    7. (execute mode) Git commit + tag
    8. Print next steps (push, publish)
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ── Files that contain the version string ─────────────────────────────────
VERSION_FILES: list[tuple[Path, str]] = [
    # (file, regex pattern where group(1) is the old version)
    (ROOT / "pyproject.toml", r'^version\s*=\s*"([^"]+)"'),
    (ROOT / "enforcecore" / "__init__.py", r'^__version__\s*=\s*"([^"]+)"'),
    (ROOT / "CITATION.cff", r'^version:\s*"([^"]+)"'),
    (
        ROOT / "enforcecore" / "telemetry" / "instrumentor.py",
        r'^_SCOPE_VERSION\s*=\s*"([^"]+)"',
    ),
]

DATE_FILES: list[tuple[Path, str]] = [
    (ROOT / "CITATION.cff", r'^date-released:\s*"([^"]+)"'),
]


def log(msg: str, *, level: str = "info") -> None:
    symbols = {"info": "i", "ok": "+", "warn": "!", "err": "x", "step": ">"}
    print(f"  {symbols.get(level, '-')} {msg}")


def run(cmd: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, **kwargs)


def current_version() -> str:
    init = ROOT / "enforcecore" / "__init__.py"
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init.read_text())
    if not match:
        sys.exit("Cannot find __version__ in __init__.py")
    return match.group(1)


def validate_version(new: str, old: str) -> None:
    pattern = r"^\d+\.\d+\.\d+(a\d+|b\d+|rc\d+)?$"
    if not re.match(pattern, new):
        sys.exit(f"Invalid version format: {new!r}  (expected e.g. 1.0.20a1)")
    if new == old:
        sys.exit(f"New version {new!r} is the same as current {old!r}")


# ── Step: Quality checks ──────────────────────────────────────────────────
def run_checks() -> bool:
    ok = True

    log("Running pytest …", level="step")
    r = run([sys.executable, "-m", "pytest", "-q", "--tb=short"])
    if r.returncode != 0:
        log(f"pytest failed:\n{r.stdout}\n{r.stderr}", level="err")
        ok = False
    else:
        # Extract summary line
        for line in r.stdout.splitlines()[::-1]:
            if "passed" in line:
                log(f"pytest: {line.strip()}", level="ok")
                break

    log("Running ruff check …", level="step")
    r = run([sys.executable, "-m", "ruff", "check", "."])
    if r.returncode != 0:
        log(f"ruff failed:\n{r.stdout}", level="err")
        ok = False
    else:
        log("ruff: clean", level="ok")

    log("Running ruff format --check …", level="step")
    r = run([sys.executable, "-m", "ruff", "format", "--check", "."])
    if r.returncode != 0:
        log("ruff format: files would be reformatted", level="err")
        ok = False
    else:
        log("ruff format: clean", level="ok")

    log("Running mypy …", level="step")
    r = run([sys.executable, "-m", "mypy", "enforcecore/"])
    if r.returncode != 0:
        log(f"mypy failed:\n{r.stdout}", level="err")
        ok = False
    else:
        for line in r.stdout.splitlines()[::-1]:
            if "Success" in line:
                log(f"mypy: {line.strip()}", level="ok")
                break

    return ok


# ── Step: Bump version ────────────────────────────────────────────────────
def bump_version(old: str, new: str, today: str, *, dry_run: bool) -> None:
    log(f"Bumping {old} → {new}", level="step")

    for path, pattern in VERSION_FILES:
        text = path.read_text()
        new_text, n = re.subn(
            pattern,
            lambda m: m.group(0).replace(m.group(1), new),
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if n == 0:
            log(f"WARNING: pattern not found in {path.name}", level="warn")
            continue
        if dry_run:
            log(f"Would update {path.relative_to(ROOT)}", level="info")
        else:
            path.write_text(new_text)
            log(f"Updated {path.relative_to(ROOT)}", level="ok")

    for path, pattern in DATE_FILES:
        text = path.read_text()
        new_text, n = re.subn(
            pattern,
            lambda m: m.group(0).replace(m.group(1), today),
            text,
            count=1,
            flags=re.MULTILINE,
        )
        if n == 0:
            log(f"WARNING: date pattern not found in {path.name}", level="warn")
            continue
        if dry_run:
            log(f"Would update date in {path.relative_to(ROOT)}", level="info")
        else:
            path.write_text(new_text)
            log(f"Updated date in {path.relative_to(ROOT)}", level="ok")


# ── Step: Update CHANGELOG ────────────────────────────────────────────────
def update_changelog(new: str, today: str, *, dry_run: bool) -> None:
    changelog = ROOT / "CHANGELOG.md"
    text = changelog.read_text()

    # Insert new version header after [Unreleased]
    unreleased_pattern = r"(## \[Unreleased\])\n"
    replacement = f"\\1\n\n## [{new}] — {today}\n"

    new_text, n = re.subn(unreleased_pattern, replacement, text, count=1)
    if n == 0:
        log("WARNING: [Unreleased] header not found in CHANGELOG.md", level="warn")
        return

    if dry_run:
        log("Would update CHANGELOG.md with new version header", level="info")
    else:
        changelog.write_text(new_text)
        log(f"Updated CHANGELOG.md: [{new}] — {today}", level="ok")


# ── Step: Build ───────────────────────────────────────────────────────────
def build_package() -> tuple[Path, Path]:
    log("Building sdist + wheel …", level="step")

    dist = ROOT / "dist"
    # Clean old builds
    if dist.exists():
        for f in dist.iterdir():
            f.unlink()

    r = run([sys.executable, "-m", "build", "--sdist", "--wheel"])
    if r.returncode != 0:
        sys.exit(f"Build failed:\n{r.stderr}")

    wheels = list(dist.glob("*.whl"))
    sdists = list(dist.glob("*.tar.gz"))
    if not wheels or not sdists:
        sys.exit("Build produced no artifacts")

    log(f"Built: {wheels[0].name}", level="ok")
    log(f"Built: {sdists[0].name}", level="ok")
    return wheels[0], sdists[0]


# ── Step: Verify artifacts ────────────────────────────────────────────────
def verify_artifacts(wheel: Path, sdist: Path) -> bool:
    ok = True

    # Check wheel for internal/ leakage
    log("Checking wheel for internal/ leakage …", level="step")
    r = run(["python", "-m", "zipfile", "-l", str(wheel)])
    if "internal/" in r.stdout:
        log("LEAKED: internal/ found in wheel!", level="err")
        ok = False
    else:
        log("Wheel: no internal/ leakage", level="ok")

    # Check sdist for internal/ leakage
    log("Checking sdist for internal/ leakage …", level="step")
    r = run(["tar", "tzf", str(sdist)])
    if any("internal/" in line for line in r.stdout.splitlines()):
        log("LEAKED: internal/ found in sdist!", level="err")
        ok = False
    else:
        log("Sdist: no internal/ leakage", level="ok")

    # Clean install test
    log("Testing clean install from wheel …", level="step")
    with tempfile.TemporaryDirectory() as tmp:
        venv_dir = Path(tmp) / "venv"
        r = run([sys.executable, "-m", "venv", str(venv_dir)])
        if r.returncode != 0:
            log("Failed to create test venv", level="err")
            return False

        pip = str(venv_dir / "bin" / "pip")
        python = str(venv_dir / "bin" / "python")

        r = run([pip, "install", "--quiet", str(wheel)])
        if r.returncode != 0:
            log(f"pip install failed:\n{r.stderr}", level="err")
            return False

        r = run([python, "-c", "import enforcecore; print(enforcecore.__version__)"])
        if r.returncode != 0:
            log(f"Import failed:\n{r.stderr}", level="err")
            return False

        log(f"Clean install: enforcecore {r.stdout.strip()}", level="ok")

        # Verify all __all__ symbols
        r = run(
            [
                python,
                "-c",
                (
                    "import enforcecore; "
                    "missing = [s for s in enforcecore.__all__ if not hasattr(enforcecore, s)]; "
                    "print(f'{len(enforcecore.__all__)} symbols, {len(missing)} missing'); "
                    "assert not missing, f'Missing: {missing}'"
                ),
            ]
        )
        if r.returncode != 0:
            log(f"Symbol check failed:\n{r.stderr}", level="err")
            ok = False
        else:
            log(f"Public API: {r.stdout.strip()}", level="ok")

    return ok


# ── Step: Git commit + tag ────────────────────────────────────────────────
def git_commit_and_tag(new: str, *, dry_run: bool) -> None:
    if dry_run:
        log(f"Would: git add -A && git commit && git tag v{new}", level="info")
        return

    log("Staging changes …", level="step")
    run(["git", "add", "-A"])

    log("Committing …", level="step")
    r = run(["git", "commit", "-m", f"release: v{new}"])
    if r.returncode != 0:
        log(f"Commit failed:\n{r.stderr}", level="err")
        sys.exit(1)
    log(f"Committed: release: v{new}", level="ok")

    log("Tagging …", level="step")
    r = run(["git", "tag", "-a", f"v{new}", "-m", f"Release v{new}"])
    if r.returncode != 0:
        log(f"Tag failed:\n{r.stderr}", level="err")
        sys.exit(1)
    log(f"Tagged: v{new}", level="ok")


# ── Main ──────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="EnforceCore release automation")
    parser.add_argument("version", help="New version (e.g. 1.0.20a1)")
    parser.add_argument(
        "--execute", action="store_true", help="Actually write files + commit + tag"
    )
    parser.add_argument("--skip-tests", action="store_true", help="Skip test/lint/type checks")
    args = parser.parse_args()

    dry_run = not args.execute
    new_ver = args.version
    old_ver = current_version()
    today = datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%d")

    print()
    print("=" * 60)
    print(f"  EnforceCore Release {'(DRY RUN)' if dry_run else '(EXECUTE)'}")
    print(f"  {old_ver} → {new_ver}")
    print("=" * 60)
    print()

    # 1. Validate
    validate_version(new_ver, old_ver)
    log(f"Version format valid: {new_ver}", level="ok")

    # 2. Quality checks
    if not args.skip_tests:
        if not run_checks():
            sys.exit("\nQuality checks failed. Fix issues before releasing.")
        print()

    # 3. Bump version
    bump_version(old_ver, new_ver, today, dry_run=dry_run)
    print()

    # 4. Update CHANGELOG
    update_changelog(new_ver, today, dry_run=dry_run)
    print()

    # 5. Build
    if not dry_run:
        wheel, sdist = build_package()
        print()

        # 6. Verify
        if not verify_artifacts(wheel, sdist):
            sys.exit("\nArtifact verification failed!")
        print()

        # 7. Commit + tag
        git_commit_and_tag(new_ver, dry_run=dry_run)
    else:
        log("Would build sdist + wheel", level="info")
        log("Would verify artifacts", level="info")
        log("Would git commit + tag", level="info")

    # 8. Next steps
    print()
    print("=" * 60)
    if dry_run:
        print("  DRY RUN complete. Re-run with --execute to apply.")
    else:
        print(f"  Release v{new_ver} prepared locally!")
        print()
        print("  Next steps:")
        print("    1. git push origin main --tags")
        print("    2. python -m twine upload dist/*")
        print("       (or use GitHub Actions release workflow)")
        print(f"    3. Create GitHub Release for tag v{new_ver}")
    print("=" * 60)
    print()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# Copyright 2025 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EnforceCore release automation script.

Usage:
    # Full release (recommended) — checks, bumps, builds, pushes, verifies:
    python scripts/release.py 1.0.23a1 --execute

    # Dry-run (default) — shows what would change, no modifications:
    python scripts/release.py 1.0.23a1

    # Skip tests (if you already ran them):
    python scripts/release.py 1.0.23a1 --execute --skip-tests

    # Local only -- don't push or verify PyPI:
    python scripts/release.py 1.0.23a1 --execute --local-only

    # Push only (after a previous --local-only run):
    python scripts/release.py 1.0.23a1 --push-only

Steps performed:
    1. Pre-flight checks (clean tree, branch, remote)
    2. Validate new version string
    3. Run full quality gate: pytest, ruff check, ruff format, mypy
    4. Bump version in all files
    5. Update CHANGELOG [Unreleased] → new version
    6. Build sdist + wheel
    7. Verify artifacts (no internal/ leakage, clean import)
    8. Git commit + tag
    9. Push to origin (unless --local-only)
   10. Wait for GitHub Actions CI to pass
   11. Wait for PyPI publication
   12. Run post-release verification from PyPI
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
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


# ── Step: Pre-flight ──────────────────────────────────────────────────────
def preflight_checks() -> bool:
    """Verify the repo is in a releasable state."""
    ok = True

    # Clean working tree
    r = run(["git", "status", "--porcelain"])
    if r.stdout.strip():
        log("Working tree is dirty — commit or stash changes first", level="err")
        log(f"  Dirty files:\n{r.stdout}", level="info")
        ok = False
    else:
        log("Working tree: clean", level="ok")

    # On main branch
    r = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    branch = r.stdout.strip()
    if branch != "main":
        log(f"Not on main branch (on '{branch}')", level="warn")
    else:
        log("Branch: main", level="ok")

    # Remote is reachable
    r = run(["git", "ls-remote", "--exit-code", "origin", "HEAD"])
    if r.returncode != 0:
        log("Cannot reach origin remote", level="err")
        ok = False
    else:
        log("Remote: origin reachable", level="ok")

    # Up to date with remote
    run(["git", "fetch", "origin", "main", "--quiet"])
    r = run(["git", "rev-list", "HEAD..origin/main", "--count"])
    behind = int(r.stdout.strip() or "0")
    if behind > 0:
        log(f"Local is {behind} commits behind origin/main — pull first", level="err")
        ok = False
    else:
        log("Branch: up to date with origin/main", level="ok")

    return ok


# ── CI parity constants ───────────────────────────────────────────────────
# These MUST match .github/workflows/release.yml and ci.yml exactly.
# If CI changes, update here too — and vice versa.
_CI_PYTEST_TIMEOUT = "60"  # seconds per test (--timeout=60)
_CI_HYPOTHESIS_MAX = "10"  # HYPOTHESIS_MAX_EXAMPLES env var
_CI_REQUIRED_PACKAGES = ["pytest-timeout"]  # CI installs these separately


def _ensure_ci_deps() -> None:
    """Ensure packages that CI installs separately are available locally.

    CI runs: pip install -e ".[dev]" pytest-timeout
    Local dev venvs only have [dev] — missing pytest-timeout causes
    silent test-timeout mismatches (root cause of v1.0.21a1 CI failure).
    """
    missing = []
    for pkg in _CI_REQUIRED_PACKAGES:
        r = run([sys.executable, "-m", "pip", "show", pkg])
        if r.returncode != 0:
            missing.append(pkg)

    if missing:
        log(f"Installing CI-required packages: {', '.join(missing)} …", level="step")
        r = run([sys.executable, "-m", "pip", "install", "--quiet", *missing])
        if r.returncode != 0:
            log(f"Failed to install {missing}: {r.stderr}", level="err")
            sys.exit(1)
        log(f"Installed: {', '.join(missing)}", level="ok")


# ── Step: Quality checks ──────────────────────────────────────────────────
def run_checks() -> bool:
    ok = True

    # Ensure CI parity — install any missing CI-only packages
    _ensure_ci_deps()

    log("Running pytest (CI parity: --timeout=60, HYPOTHESIS_MAX_EXAMPLES=10) …", level="step")
    ci_env = {**os.environ, "HYPOTHESIS_MAX_EXAMPLES": _CI_HYPOTHESIS_MAX}
    r = run(
        [sys.executable, "-m", "pytest", "-q", "--tb=short", "--timeout", _CI_PYTEST_TIMEOUT],
        env=ci_env,
    )
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


# ── Step: Push ────────────────────────────────────────────────────────────
def git_push(new: str) -> None:
    log("Pushing to origin …", level="step")
    r = run(["git", "push", "origin", "main", "--tags"])
    if r.returncode != 0:
        log(f"Push failed:\n{r.stderr}", level="err")
        sys.exit(1)
    log(f"Pushed: main + tag v{new}", level="ok")


# ── Step: Wait for GitHub Actions ─────────────────────────────────────────
def wait_for_ci(new: str, *, timeout_minutes: int = 20) -> bool:
    """Poll GitHub Actions API until the Release workflow completes."""
    log(f"Waiting for Release workflow (timeout: {timeout_minutes}min) …", level="step")

    api_url = "https://api.github.com/repos/akios-ai/EnforceCore/actions/runs"
    deadline = time.time() + timeout_minutes * 60
    run_id = None

    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                f"{api_url}?per_page=5&event=push",
                headers={"Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            for wf_run in data.get("workflow_runs", []):
                if wf_run["name"] == "Release" and f"v{new}" in wf_run.get("head_branch", ""):
                    run_id = wf_run["id"]
                    status = wf_run["status"]
                    conclusion = wf_run["conclusion"]

                    if status == "completed":
                        if conclusion == "success":
                            log(f"Release workflow passed (run {run_id})", level="ok")
                            return True
                        else:
                            log(
                                f"Release workflow failed: {conclusion} (run {run_id})",
                                level="err",
                            )
                            log(
                                f"  See: https://github.com/akios-ai/EnforceCore/actions/runs/{run_id}",
                                level="info",
                            )
                            return False
                    else:
                        elapsed = int(time.time() - (deadline - timeout_minutes * 60))
                        log(
                            f"  … {status} ({elapsed}s elapsed) — run {run_id}",
                            level="info",
                        )
                        break

        except Exception as e:
            log(f"  … API poll error: {e}", level="warn")

        time.sleep(30)

    log(f"Timeout after {timeout_minutes} minutes", level="err")
    if run_id:
        log(
            f"  Check: https://github.com/akios-ai/EnforceCore/actions/runs/{run_id}",
            level="info",
        )
    return False


# ── Step: Wait for PyPI ───────────────────────────────────────────────────
def wait_for_pypi(new: str, *, timeout_minutes: int = 5) -> bool:
    """Poll PyPI until the version is available."""
    log(f"Waiting for v{new} on PyPI …", level="step")
    deadline = time.time() + timeout_minutes * 60

    while time.time() < deadline:
        try:
            url = f"https://pypi.org/pypi/enforcecore/{new}/json"
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.loads(resp.read())
                if data.get("info", {}).get("version") == new:
                    log(f"v{new} is live on PyPI!", level="ok")
                    return True
        except Exception:
            pass
        time.sleep(15)

    log(f"v{new} not found on PyPI after {timeout_minutes} minutes", level="err")
    return False


# ── Step: Post-release verification ──────────────────────────────────────
def run_post_verify(new: str) -> bool:
    """Run the post-release verification script."""
    log("Running post-release verification …", level="step")
    script = ROOT / "scripts" / "post_release_verify.py"
    if not script.exists():
        log("post_release_verify.py not found — skipping", level="warn")
        return True

    r = subprocess.run(
        [sys.executable, str(script), new],
        cwd=ROOT,
        text=True,
    )
    return r.returncode == 0


# ── Main ──────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        description="EnforceCore release automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/release.py 1.0.23a1                    # dry-run
  python scripts/release.py 1.0.23a1 --execute          # full release
  python scripts/release.py 1.0.23a1 --execute --local-only  # no push
  python scripts/release.py 1.0.23a1 --push-only        # push existing tag
        """,
    )
    parser.add_argument("version", help="New version (e.g. 1.0.21a1)")
    parser.add_argument(
        "--execute", action="store_true", help="Actually write files + commit + tag + push"
    )
    parser.add_argument("--skip-tests", action="store_true", help="Skip test/lint/type checks")
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="Don't push, don't wait for CI, don't verify PyPI",
    )
    parser.add_argument(
        "--push-only",
        action="store_true",
        help="Just push an existing tag and wait for CI + PyPI",
    )
    parser.add_argument(
        "--ci-timeout",
        type=int,
        default=20,
        help="Minutes to wait for CI (default: 20)",
    )
    args = parser.parse_args()

    dry_run = not args.execute and not args.push_only
    new_ver = args.version
    old_ver = current_version()
    today = datetime.datetime.now(tz=datetime.UTC).strftime("%Y-%m-%d")

    print()
    print("=" * 64)
    mode = "(DRY RUN)" if dry_run else "(PUSH ONLY)" if args.push_only else "(EXECUTE)"
    print(f"  EnforceCore Release {mode}")
    print(f"  {old_ver} → {new_ver}")
    print("=" * 64)
    print()

    if args.push_only:
        # ── Push-only mode ────────────────────────────────────────────
        # Verify the tag exists
        r = run(["git", "tag", "-l", f"v{new_ver}"])
        if f"v{new_ver}" not in r.stdout:
            sys.exit(f"Tag v{new_ver} does not exist locally. Run --execute first.")
        log(f"Tag v{new_ver} exists locally", level="ok")

        git_push(new_ver)
        print()

        if wait_for_ci(new_ver, timeout_minutes=args.ci_timeout):
            print()
            if wait_for_pypi(new_ver):
                print()
                run_post_verify(new_ver)
        else:
            log("CI failed — check GitHub Actions for details", level="err")
            sys.exit(1)

        _print_summary(new_ver, pushed=True)
        return

    # ── Normal flow ───────────────────────────────────────────────────

    # 1. Validate
    validate_version(new_ver, old_ver)
    log(f"Version format valid: {new_ver}", level="ok")

    # 2. Pre-flight
    if not dry_run:
        print()
        log("Pre-flight checks …", level="step")
        # In execute mode, tree will be clean before we modify anything
        # but we check remote/branch first
        r = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        branch = r.stdout.strip()
        if branch != "main":
            log(f"WARNING: Not on main branch (on '{branch}')", level="warn")
        else:
            log("Branch: main", level="ok")

    # 3. Quality checks
    if not args.skip_tests:
        print()
        if not run_checks():
            sys.exit("\nQuality checks failed. Fix issues before releasing.")
        print()

    # 4. Bump version
    bump_version(old_ver, new_ver, today, dry_run=dry_run)
    print()

    # 5. Update CHANGELOG
    update_changelog(new_ver, today, dry_run=dry_run)
    print()

    # 6-7. Build + verify
    if not dry_run:
        wheel, sdist = build_package()
        print()

        if not verify_artifacts(wheel, sdist):
            sys.exit("\nArtifact verification failed!")
        print()

        # 8. Commit + tag
        git_commit_and_tag(new_ver, dry_run=dry_run)
        print()

        # 9-12. Push + CI + PyPI + verify
        if not args.local_only:
            git_push(new_ver)
            print()

            if wait_for_ci(new_ver, timeout_minutes=args.ci_timeout):
                print()
                if wait_for_pypi(new_ver):
                    print()
                    run_post_verify(new_ver)
            else:
                log("CI failed — check GitHub Actions for details", level="err")
                log("You can fix and re-run with: --push-only", level="info")
    else:
        log("Would build sdist + wheel", level="info")
        log("Would verify artifacts", level="info")
        log("Would git commit + tag", level="info")
        if not args.local_only:
            log("Would push to origin", level="info")
            log("Would wait for CI + PyPI", level="info")
            log("Would run post-release verification", level="info")

    _print_summary(new_ver, pushed=not dry_run and not args.local_only)


def _print_summary(new_ver: str, *, pushed: bool) -> None:
    print()
    print("=" * 64)
    if pushed:
        print(f"  Release v{new_ver} — complete!")
        print()
        print(f"  PyPI:    https://pypi.org/project/enforcecore/{new_ver}/")
        print(f"  GitHub:  https://github.com/akios-ai/EnforceCore/releases/tag/v{new_ver}")
        print(f"  Install: pip install enforcecore=={new_ver}")
    else:
        print(f"  Release v{new_ver} — prepared locally.")
        print()
        print("  Next steps:")
        print(f"    python scripts/release.py {new_ver} --push-only")
        print("    # or: git push origin main --tags")
    print("=" * 64)
    print()


if __name__ == "__main__":
    main()

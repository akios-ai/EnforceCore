#!/usr/bin/env python3
# Copyright 2025 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Post-release verification for EnforceCore.

Installs the package from PyPI into a clean venv and runs comprehensive
checks to confirm the release is correct and fully functional.

Usage:
    # Verify the latest version on PyPI:
    python scripts/post_release_verify.py

    # Verify a specific version:
    python scripts/post_release_verify.py 1.0.20a1

    # Verify from TestPyPI:
    python scripts/post_release_verify.py 1.0.20a1 --test-pypi

    # Keep the venv after verification (for manual inspection):
    python scripts/post_release_verify.py --keep-venv

This script is designed to be run after every release to catch issues
that only manifest in the published package (missing files, broken
imports, incorrect metadata, etc.).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import textwrap
import urllib.request
from pathlib import Path

# ── Logging ───────────────────────────────────────────────────────────────

PASS = 0
FAIL = 0


def log(msg: str, *, level: str = "info") -> None:
    symbols = {"info": "·", "ok": "✓", "warn": "!", "err": "✗", "step": "▸"}
    print(f"  {symbols.get(level, '-')} {msg}")


def check(name: str, passed: bool, detail: str = "") -> bool:
    global PASS, FAIL
    if passed:
        PASS += 1
        log(f"{name}: {detail}" if detail else name, level="ok")
    else:
        FAIL += 1
        log(f"{name}: {detail}" if detail else f"{name}: FAILED", level="err")
    return passed


# ── PyPI metadata ─────────────────────────────────────────────────────────


def fetch_pypi_metadata(version: str | None, *, test_pypi: bool = False) -> dict | None:
    """Fetch package metadata from PyPI JSON API."""
    base = "https://test.pypi.org" if test_pypi else "https://pypi.org"
    url = f"{base}/pypi/enforcecore/{version}/json" if version else f"{base}/pypi/enforcecore/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log(f"Failed to fetch PyPI metadata: {e}", level="err")
        return None


# ── Verification steps ────────────────────────────────────────────────────


def verify_pypi_metadata(data: dict, expected_version: str) -> bool:
    """Check PyPI metadata is correct."""
    info = data["info"]
    ok = True

    ok &= check(
        "Version on PyPI",
        info["version"] == expected_version,
        info["version"],
    )
    ok &= check(
        "Package name",
        info["name"] == "enforcecore",
        info["name"],
    )
    ok &= check(
        "Python requires",
        info.get("requires_python", "").startswith(">=3.11"),
        info.get("requires_python", "NOT SET"),
    )
    ok &= check(
        "Summary present",
        bool(info.get("summary")),
        info.get("summary", "MISSING")[:80],
    )
    ok &= check(
        "Homepage URL",
        "akios.ai" in (info.get("home_page") or info.get("project_urls", {}).get("Homepage", "")),
        info.get("home_page") or info.get("project_urls", {}).get("Homepage", "MISSING"),
    )

    # License can be in classifiers or license field
    license_text = info.get("license") or ""
    classifiers = info.get("classifiers") or []
    has_apache = "Apache" in license_text or any("Apache" in c for c in classifiers)
    ok &= check("License declared", has_apache, "Apache-2.0")

    # Check artifacts
    urls = data.get("urls", [])
    has_wheel = any(u["packagetype"] == "bdist_wheel" for u in urls)
    has_sdist = any(u["packagetype"] == "sdist" for u in urls)
    ok &= check("Wheel artifact exists", has_wheel)
    ok &= check("Sdist artifact exists", has_sdist)

    # Check description has content
    desc = info.get("description", "")
    ok &= check(
        "README/description present",
        len(desc) > 500,
        f"{len(desc)} chars",
    )
    ok &= check(
        "Logo reference in description",
        "logo" in desc.lower() or "svg" in desc.lower() or "img" in desc.lower(),
        "found" if ("logo" in desc.lower() or "svg" in desc.lower()) else "NOT FOUND",
    )

    return ok


def verify_clean_install(
    version: str,
    venv_dir: Path,
    *,
    test_pypi: bool = False,
) -> bool:
    """Install from PyPI into a clean venv and verify."""
    ok = True

    log("Creating clean venv …", level="step")
    r = subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        log(f"venv creation failed: {r.stderr}", level="err")
        return False

    pip = str(venv_dir / "bin" / "pip")
    python = str(venv_dir / "bin" / "python")

    # Install from PyPI
    log(
        f"Installing enforcecore=={version} from {'TestPyPI' if test_pypi else 'PyPI'} …",
        level="step",
    )
    install_cmd = [pip, "install", "--quiet", f"enforcecore=={version}"]
    if test_pypi:
        install_cmd.extend(
            [
                "--index-url",
                "https://test.pypi.org/simple/",
                "--extra-index-url",
                "https://pypi.org/simple/",
            ]
        )

    r = subprocess.run(install_cmd, capture_output=True, text=True)
    ok &= check(
        "pip install",
        r.returncode == 0,
        "success" if r.returncode == 0 else r.stderr[:200],
    )
    if r.returncode != 0:
        return False

    # ── Check 1: Basic import + version ───────────────────────────────
    r = subprocess.run(
        [python, "-c", "import enforcecore; print(enforcecore.__version__)"],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Import + version",
        r.returncode == 0 and r.stdout.strip() == version,
        r.stdout.strip() if r.returncode == 0 else r.stderr[:200],
    )

    # ── Check 2: All __all__ symbols importable ───────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import enforcecore
                missing = [s for s in enforcecore.__all__ if not hasattr(enforcecore, s)]
                print(f"{len(enforcecore.__all__)} symbols, {len(missing)} missing")
                if missing:
                    print(f"MISSING: {missing}")
                    exit(1)
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check("Public API symbols", r.returncode == 0, r.stdout.strip())

    # ── Check 3: Core classes instantiable ────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                from enforcecore import Enforcer, Policy, Redactor, Auditor
                from enforcecore import ResourceGuard, CostTracker, KillSwitch

                # Policy — Pydantic model with name required
                p = Policy(name="test")
                print(f"Policy: {p.name}")

                # Redactor
                r = Redactor()
                result = r.redact("My email is test@example.com")
                assert "test@example.com" not in result.text, f"PII not redacted: {result.text}"
                print(f"Redactor: redacted {result.count} entities")

                # ResourceGuard
                g = ResourceGuard()
                print(f"ResourceGuard: ok")

                # CostTracker
                ct = CostTracker(budget_usd=10.0)
                print(f"CostTracker: budget=${ct.budget}")

                # KillSwitch
                ks = KillSwitch()
                print(f"KillSwitch: is_tripped={ks.is_tripped}")

                # Auditor (temp file)
                import tempfile, pathlib
                with tempfile.TemporaryDirectory() as tmp:
                    a = Auditor(output_path=pathlib.Path(tmp) / "audit.jsonl")
                    print(f"Auditor: ok")

                print("ALL_CORE_CLASSES_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Core classes instantiable",
        r.returncode == 0 and "ALL_CORE_CLASSES_OK" in r.stdout,
        "all 7 classes" if r.returncode == 0 else r.stderr[:200],
    )

    # ── Check 4: Enforcer decorator works ─────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import tempfile, pathlib, yaml
                from enforcecore import enforce

                # Create a policy YAML — the proper way to configure enforce()
                with tempfile.TemporaryDirectory() as tmp:
                    policy_path = pathlib.Path(tmp) / "policy.yaml"
                    policy_path.write_text(yaml.dump({
                        "name": "verify",
                        "version": "1.0",
                        "rules": {
                            "allowed_tools": ["greet"],
                            "pii_redaction": {"enabled": True, "action": "redact"},
                        },
                    }))

                    @enforce(policy=str(policy_path))
                    def greet(name: str) -> str:
                        return f"Hello, {name}!"

                    result = greet("test@example.com")
                    assert "test@example.com" not in result, f"PII leaked: {result}"
                    print(f"enforce() decorator: {result}")
                    print("ENFORCE_DECORATOR_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "@enforce() decorator",
        r.returncode == 0 and "ENFORCE_DECORATOR_OK" in r.stdout,
        "redaction works"
        if r.returncode == 0 and "ENFORCE_DECORATOR_OK" in r.stdout
        else r.stderr[:200],
    )

    # ── Check 5: Async enforcement works ──────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import asyncio, tempfile, pathlib, yaml
                from enforcecore import enforce

                with tempfile.TemporaryDirectory() as tmp:
                    policy_path = pathlib.Path(tmp) / "policy.yaml"
                    policy_path.write_text(yaml.dump({
                        "name": "async-verify",
                        "version": "1.0",
                        "rules": {"allowed_tools": ["async_greet"]},
                    }))

                    @enforce(policy=str(policy_path))
                    async def async_greet(name: str) -> str:
                        return f"Hello, {name}!"

                    result = asyncio.run(async_greet("world"))
                    print(f"Async enforce: {result}")
                    print("ASYNC_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Async enforcement",
        r.returncode == 0 and "ASYNC_OK" in r.stdout,
        "works" if r.returncode == 0 else r.stderr[:200],
    )

    # ── Check 6: Tool denial works ────────────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import tempfile, pathlib, yaml
                from enforcecore import enforce, ToolDeniedError

                with tempfile.TemporaryDirectory() as tmp:
                    policy_path = pathlib.Path(tmp) / "policy.yaml"
                    policy_path.write_text(yaml.dump({
                        "name": "deny-test",
                        "version": "1.0",
                        "rules": {
                            "allowed_tools": [],
                            "denied_tools": ["dangerous"],
                        },
                    }))

                    @enforce(policy=str(policy_path), tool_name="dangerous")
                    def dangerous() -> str:
                        return "should not run"

                    try:
                        dangerous()
                        print("DENY_FAILED")
                    except ToolDeniedError:
                        print("DENY_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Tool denial enforcement",
        r.returncode == 0 and "DENY_OK" in r.stdout,
        "blocked correctly" if "DENY_OK" in (r.stdout or "") else r.stderr[:200],
    )

    # ── Check 7: Audit trail + Merkle chain ───────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import json, tempfile, pathlib
                from enforcecore import Auditor, verify_trail

                with tempfile.TemporaryDirectory() as tmp:
                    audit_path = pathlib.Path(tmp) / "audit.jsonl"
                    auditor = Auditor(output_path=audit_path)

                    # Record audit entries directly (Auditor is standalone)
                    auditor.record(
                        tool_name="test_tool",
                        policy_name="test",
                        policy_version="1.0",
                        decision="allowed",
                    )
                    auditor.record(
                        tool_name="test_tool_2",
                        policy_name="test",
                        policy_version="1.0",
                        decision="denied",
                        violation_type="tool_denied",
                        violation_reason="Not in allowed list",
                    )

                    # Read audit trail
                    lines = audit_path.read_text().strip().split("\\n")
                    entries = [json.loads(l) for l in lines if l.strip()]
                    print(f"Audit entries: {len(entries)}")
                    assert len(entries) >= 2, f"Expected 2+ entries, got {len(entries)}"

                    # Verify Merkle chain
                    result = verify_trail(audit_path)
                    print(f"Chain valid: {result.is_valid}, entries: {result.total_entries}")
                    assert result.is_valid, f"Chain invalid: {result.errors}"
                    print("AUDIT_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Audit trail + Merkle verify",
        r.returncode == 0 and "AUDIT_OK" in r.stdout,
        "chain valid" if "AUDIT_OK" in (r.stdout or "") else r.stderr[:300],
    )

    # ── Check 8: Content rules work ───────────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import tempfile, pathlib, yaml
                from enforcecore import enforce, ContentViolationError

                with tempfile.TemporaryDirectory() as tmp:
                    policy_path = pathlib.Path(tmp) / "policy.yaml"
                    policy_path.write_text(yaml.dump({
                        "name": "content-test",
                        "version": "1.0",
                        "rules": {
                            "allowed_tools": ["say"],
                            "content_rules": {
                                "enabled": True,
                                "block_patterns": [
                                    {"name": "custom", "pattern": "BLOCKED_WORD", "action": "block"},
                                ],
                            },
                        },
                    }))

                    @enforce(policy=str(policy_path))
                    def say(text: str) -> str:
                        return text

                    try:
                        say("this has BLOCKED_WORD in it")
                        print("CONTENT_FAILED")
                    except ContentViolationError:
                        print("CONTENT_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Content rules enforcement",
        r.returncode == 0 and "CONTENT_OK" in r.stdout,
        "blocked correctly" if "CONTENT_OK" in (r.stdout or "") else r.stderr[:200],
    )

    # ── Check 9: Secret scanning ──────────────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                from enforcecore import Redactor
                r = Redactor(secret_detection=True)
                text = "key is aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                result = r.redact(text)
                assert "wJalrXUtnFEMI" not in result.text, f"Secret not redacted: {result.text}"
                print(f"Secret scanning: redacted {result.count} secrets")
                print("SECRETS_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Secret scanning",
        r.returncode == 0 and "SECRETS_OK" in r.stdout,
        "works" if "SECRETS_OK" in (r.stdout or "") else r.stderr[:200],
    )

    # ── Check 10: No internal/ in installed package ───────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import enforcecore, pathlib
                pkg_dir = pathlib.Path(enforcecore.__file__).parent
                # Check nothing leaked into the package directory itself
                internal = pkg_dir / "internal"
                if internal.exists():
                    print(f"LEAKED: {internal}")
                    exit(1)
                # Check site-packages for test/benchmark artifacts
                site_packages = pkg_dir.parent
                for bad in ["tests", "benchmarks"]:
                    bad_path = site_packages / bad
                    # Only flag if it looks like it belongs to enforcecore
                    if bad_path.exists():
                        contents = list(bad_path.iterdir()) if bad_path.is_dir() else []
                        enforcecore_files = [f for f in contents if "enforce" in f.name.lower()]
                        if enforcecore_files:
                            print(f"LEAKED: {bad_path} (enforcecore files: {enforcecore_files})")
                            exit(1)
                print("NO_LEAKAGE")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "No internal/ leakage",
        r.returncode == 0 and "NO_LEAKAGE" in r.stdout,
        "clean" if r.returncode == 0 else r.stderr[:200],
    )

    # ── Check 11: Dependencies are correct ────────────────────────────
    r = subprocess.run(
        [pip, "show", "enforcecore"],
        capture_output=True,
        text=True,
    )
    if r.returncode == 0:
        for line in r.stdout.splitlines():
            if line.startswith("Requires:"):
                deps = line.split(":", 1)[1].strip()
                ok &= check("Dependencies", bool(deps), deps)
                break

    # ── Check 12: Disclaimer in package ───────────────────────────────
    r = subprocess.run(
        [
            python,
            "-c",
            textwrap.dedent("""\
                import enforcecore
                doc = enforcecore.__doc__ or ""
                assert "AS IS" in doc or "WARRANTY" in doc.upper() or "DISCLAIMER" in doc.upper(), \
                    "No disclaimer found in package docstring"
                print("DISCLAIMER_OK")
            """),
        ],
        capture_output=True,
        text=True,
    )
    ok &= check(
        "Disclaimer in package",
        r.returncode == 0 and "DISCLAIMER_OK" in r.stdout,
        "present" if r.returncode == 0 else "MISSING",
    )

    return ok


# ── Main ──────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Post-release verification for EnforceCore",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python scripts/post_release_verify.py              # latest version
              python scripts/post_release_verify.py 1.0.20a1     # specific version
              python scripts/post_release_verify.py --test-pypi   # from TestPyPI
              python scripts/post_release_verify.py --keep-venv   # keep venv
        """),
    )
    parser.add_argument(
        "version",
        nargs="?",
        default=None,
        help="Version to verify (default: latest on PyPI)",
    )
    parser.add_argument(
        "--test-pypi",
        action="store_true",
        help="Install from TestPyPI instead of production PyPI",
    )
    parser.add_argument(
        "--keep-venv",
        action="store_true",
        help="Keep the temporary venv after verification",
    )
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  EnforceCore — Post-Release Verification")
    print("=" * 60)
    print()

    # ── Step 1: Fetch PyPI metadata ───────────────────────────────────
    log("Fetching PyPI metadata …", level="step")
    data = fetch_pypi_metadata(args.version, test_pypi=args.test_pypi)
    if not data:
        sys.exit("Cannot fetch package metadata from PyPI. Is it published?")

    version = data["info"]["version"]
    log(f"Target version: {version}", level="ok")
    print()

    # ── Step 2: Verify metadata ───────────────────────────────────────
    log("Checking PyPI metadata …", level="step")
    verify_pypi_metadata(data, version)
    print()

    # ── Step 3: Clean install + functional tests ──────────────────────
    if args.keep_venv:
        venv_dir = Path(f".verify-venv-{version}")
        log(f"Venv will be kept at: {venv_dir}", level="info")
    else:
        _tmp = tempfile.mkdtemp(prefix=f"enforcecore-verify-{version}-")
        venv_dir = Path(_tmp) / "venv"

    try:
        verify_clean_install(version, venv_dir, test_pypi=args.test_pypi)
    finally:
        if not args.keep_venv and venv_dir.parent.exists():
            import shutil

            shutil.rmtree(venv_dir.parent, ignore_errors=True)

    # ── Summary ───────────────────────────────────────────────────────
    print()
    print("=" * 60)
    total = PASS + FAIL
    if FAIL == 0:
        print(f"  ✅ ALL {total} CHECKS PASSED — v{version} is good!")
    else:
        print(f"  ❌ {FAIL}/{total} CHECKS FAILED — v{version} has issues!")
    print("=" * 60)
    print()

    sys.exit(1 if FAIL > 0 else 0)


if __name__ == "__main__":
    main()

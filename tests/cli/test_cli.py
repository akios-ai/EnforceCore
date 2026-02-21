"""Tests for CLI commands (enforcecore.cli.main)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest
from typer.testing import CliRunner

from enforcecore.cli.main import app

if TYPE_CHECKING:
    from pathlib import Path

runner = CliRunner()

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VALID_POLICY_YAML = """\
name: test-policy
version: "1.0"
rules:
  allowed_tools: ["search_web", "calculator"]
  denied_tools: ["execute_shell"]
  pii_redaction:
    enabled: true
    categories: ["email", "phone"]
  content_rules:
    enabled: true
  rate_limits:
    enabled: true
    per_tool:
      search_web:
        max_calls: 10
        window_seconds: 60
  network:
    enabled: true
    allowed_domains: ["api.example.com"]
    denied_domains: ["evil.com"]
on_violation: block
"""


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "policy.yaml"
    f.write_text(VALID_POLICY_YAML)
    return f


@pytest.fixture()
def invalid_policy_file(tmp_path: Path) -> Path:
    f = tmp_path / "bad.yaml"
    f.write_text("not_a_valid: [")
    return f


@pytest.fixture()
def audit_file(tmp_path: Path) -> Path:
    f = tmp_path / "audit.jsonl"
    entries = [
        {
            "tool_name": "search_web",
            "decision": "allowed",
            "policy_name": "test-policy",
            "duration_ms": 12.5,
            "input_redactions": 2,
            "output_redactions": 0,
            "prev_hash": "",
            "hash": "abc123",
        },
        {
            "tool_name": "calculator",
            "decision": "allowed",
            "policy_name": "test-policy",
            "duration_ms": 1.2,
            "input_redactions": 0,
            "output_redactions": 0,
            "prev_hash": "abc123",
            "hash": "def456",
        },
        {
            "tool_name": "execute_shell",
            "decision": "blocked",
            "policy_name": "test-policy",
            "duration_ms": 0.1,
            "input_redactions": 0,
            "output_redactions": 0,
            "prev_hash": "def456",
            "hash": "ghi789",
        },
    ]
    with open(f, "w") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    return f


# ---------------------------------------------------------------------------
# enforcecore info
# ---------------------------------------------------------------------------


class TestInfoCommand:
    def test_info_shows_version(self) -> None:
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "EnforceCore Info" in result.output
        assert "Version" in result.output

    def test_info_shows_python(self) -> None:
        result = runner.invoke(app, ["info"])
        assert "Python" in result.output

    def test_info_shows_exports(self) -> None:
        result = runner.invoke(app, ["info"])
        assert "Exports" in result.output


# ---------------------------------------------------------------------------
# enforcecore validate
# ---------------------------------------------------------------------------


class TestValidateCommand:
    def test_valid_policy(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["validate", str(policy_file)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower() or "✓" in result.output

    def test_valid_policy_shows_summary(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["validate", str(policy_file)])
        assert "test-policy" in result.output

    def test_invalid_yaml(self, invalid_policy_file: Path) -> None:
        result = runner.invoke(app, ["validate", str(invalid_policy_file)])
        assert result.exit_code == 1

    def test_missing_file(self) -> None:
        result = runner.invoke(app, ["validate", "/nonexistent/policy.yaml"])
        assert result.exit_code == 1

    def test_policy_missing_name(self, tmp_path: Path) -> None:
        f = tmp_path / "noname.yaml"
        f.write_text("version: '1.0'\nrules: {}")
        result = runner.invoke(app, ["validate", str(f)])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# enforcecore verify
# ---------------------------------------------------------------------------


class TestVerifyCommand:
    def test_missing_file(self) -> None:
        result = runner.invoke(app, ["verify", "/nonexistent/audit.jsonl"])
        assert result.exit_code == 1

    def test_valid_audit_trail(self, tmp_path: Path) -> None:
        """Create a proper Merkle-chained audit trail and verify it."""
        from enforcecore.auditor.engine import Auditor

        out = tmp_path / "valid_audit.jsonl"
        auditor = Auditor(output_path=str(out))
        auditor.record(
            tool_name="test",
            decision="allowed",
            policy_name="p",
            call_duration_ms=1.0,
        )
        auditor.record(
            tool_name="test2",
            decision="allowed",
            policy_name="p",
            call_duration_ms=2.0,
        )
        result = runner.invoke(app, ["verify", str(out)])
        assert result.exit_code == 0
        assert "valid" in result.output.lower() or "✓" in result.output


# ---------------------------------------------------------------------------
# enforcecore eval
# ---------------------------------------------------------------------------


class TestEvalCommand:
    def test_eval_requires_policy(self) -> None:
        result = runner.invoke(app, ["eval"])
        assert result.exit_code != 0

    def test_eval_with_policy(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["eval", "--policy", str(policy_file)])
        # Should run and show containment rate
        assert "Containment" in result.output or "containment" in result.output.lower()

    def test_eval_verbose(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["eval", "-p", str(policy_file), "--verbose"])
        assert "Scenario" in result.output or "containment" in result.output.lower()


# ---------------------------------------------------------------------------
# enforcecore dry-run
# ---------------------------------------------------------------------------


class TestDryRunCommand:
    def test_allowed_tool(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["dry-run", str(policy_file), "--tool", "search_web"])
        assert result.exit_code == 0
        assert "allowed" in result.output.lower()

    def test_denied_tool(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["dry-run", str(policy_file), "--tool", "execute_shell"])
        assert "blocked" in result.output.lower()

    def test_unknown_tool(self, policy_file: Path) -> None:
        result = runner.invoke(app, ["dry-run", str(policy_file), "--tool", "unknown_tool"])
        # Should be blocked because allowed_tools is set
        assert "blocked" in result.output.lower()

    def test_with_args(self, policy_file: Path) -> None:
        result = runner.invoke(
            app,
            ["dry-run", str(policy_file), "-t", "search_web", "-a", "query=test"],
        )
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# enforcecore inspect
# ---------------------------------------------------------------------------


class TestInspectCommand:
    def test_inspect_shows_entries(self, audit_file: Path) -> None:
        result = runner.invoke(app, ["inspect", str(audit_file)])
        assert result.exit_code == 0
        assert "search_web" in result.output

    def test_inspect_with_tail(self, audit_file: Path) -> None:
        result = runner.invoke(app, ["inspect", str(audit_file), "--tail", "1"])
        assert result.exit_code == 0

    def test_inspect_filter_by_tool(self, audit_file: Path) -> None:
        result = runner.invoke(app, ["inspect", str(audit_file), "--tool", "calculator"])
        assert result.exit_code == 0
        assert "calculator" in result.output

    def test_inspect_filter_by_decision(self, audit_file: Path) -> None:
        result = runner.invoke(app, ["inspect", str(audit_file), "--decision", "blocked"])
        assert result.exit_code == 0
        assert "blocked" in result.output

    def test_inspect_missing_file(self) -> None:
        result = runner.invoke(app, ["inspect", "/nonexistent/audit.jsonl"])
        assert result.exit_code == 1

    def test_inspect_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.jsonl"
        f.write_text("")
        result = runner.invoke(app, ["inspect", str(f)])
        assert result.exit_code == 0
        assert "No matching" in result.output

    def test_inspect_no_matching_filter(self, audit_file: Path) -> None:
        result = runner.invoke(app, ["inspect", str(audit_file), "--tool", "nonexistent"])
        assert "No matching" in result.output


# ---------------------------------------------------------------------------
# No-args shows help
# ---------------------------------------------------------------------------


class TestNoArgs:
    def test_no_args_shows_help(self) -> None:
        result = runner.invoke(app, [])
        # typer may exit 0 or 2 for no-args help
        assert "Usage" in result.output or "enforcecore" in result.output.lower()

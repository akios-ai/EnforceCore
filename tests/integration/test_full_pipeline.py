"""Full pipeline integration tests — Policy → Enforcer → Redactor → Guard → Auditor.

No mocks. Real policies, real redaction, real audit files on disk.
Every test exercises the entire enforcement pipeline end-to-end.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore import (
    ContentViolationError,
    Enforcer,
    ToolDeniedError,
)
from enforcecore.auditor.engine import load_trail, verify_trail

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def echo(text: str) -> str:
    """Passthrough tool for testing."""
    return f"echo: {text}"


def noop() -> str:
    return "ok"


# ---------------------------------------------------------------------------
# Healthcare scenario — full pipeline
# ---------------------------------------------------------------------------


class TestHealthcarePipeline:
    """End-to-end: HIPAA-style PII redaction + tool gating + audit."""

    def test_allowed_tool_produces_result(self, healthcare_policy: Policy) -> None:
        enforcer = Enforcer(healthcare_policy)
        result = enforcer.enforce_sync(
            echo,
            "patient info",
            tool_name="lookup_drug_interactions",
        )
        assert result == "echo: patient info"

    def test_pii_redacted_in_args(self, healthcare_policy: Policy) -> None:
        """PII is redacted in the args passed to the tool."""
        enforcer = Enforcer(healthcare_policy)

        def capture_arg(text: str) -> str:
            return text  # returns the (redacted) input

        result = enforcer.enforce_sync(
            capture_arg,
            "Contact john@hospital.org, SSN 123-45-6789",
            tool_name="lookup_drug_interactions",
        )
        # Email and SSN should be replaced
        assert "john@hospital.org" not in result
        assert "123-45-6789" not in result

    def test_denied_tool_raises(self, healthcare_policy: Policy) -> None:
        enforcer = Enforcer(healthcare_policy)
        with pytest.raises(ToolDeniedError, match="execute_shell"):
            enforcer.enforce_sync(echo, "whoami", tool_name="execute_shell")

    def test_unlisted_tool_denied(self, healthcare_policy: Policy) -> None:
        enforcer = Enforcer(healthcare_policy)
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(noop, tool_name="send_external_data")

    def test_audit_trail_written_and_valid(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)

        # One allowed, one blocked
        enforcer.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(echo, "test", tool_name="execute_shell")

        assert audit_trail_path.exists()
        result = verify_trail(audit_trail_path)
        assert result.is_valid
        assert result.total_entries == 2

        entries = load_trail(audit_trail_path)
        assert entries[0].decision == "allowed"
        assert entries[0].tool_name == "lookup_drug_interactions"
        assert entries[1].decision == "blocked"
        assert entries[1].tool_name == "execute_shell"

    def test_redaction_count_in_audit(
        self, healthcare_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(healthcare_policy)
        enforcer.enforce_sync(
            echo,
            "patient@hospital.org SSN 123-45-6789",
            tool_name="query_symptoms_db",
        )

        entries = load_trail(audit_trail_path)
        assert len(entries) == 1
        assert entries[0].input_redactions >= 2


# ---------------------------------------------------------------------------
# Financial scenario — cost + rate limiting
# ---------------------------------------------------------------------------


class TestFinancialPipeline:
    """End-to-end: cost budget + rate limiting + tool gating."""

    def test_allowed_tool(self, financial_policy: Policy) -> None:
        enforcer = Enforcer(financial_policy)
        result = enforcer.enforce_sync(echo, "AAPL", tool_name="get_stock_quote")
        assert "AAPL" in result

    def test_denied_tool(self, financial_policy: Policy) -> None:
        enforcer = Enforcer(financial_policy)
        with pytest.raises(ToolDeniedError, match="execute_trade"):
            enforcer.enforce_sync(echo, "BUY 100", tool_name="execute_trade")

    def test_rate_limiting_kicks_in(self, financial_policy: Policy) -> None:
        """After enough rapid calls, rate limiter should block."""
        enforcer = Enforcer(financial_policy)
        blocked = 0
        for _i in range(20):
            try:
                enforcer.enforce_sync(echo, "TSLA", tool_name="get_stock_quote")
            except Exception:
                blocked += 1
        assert blocked > 0, "Rate limiter should have blocked at least one call"


# ---------------------------------------------------------------------------
# Code agent scenario — content rules
# ---------------------------------------------------------------------------


class TestCodeAgentPipeline:
    """End-to-end: content rules + tool gating."""

    def test_safe_code_allowed(self, code_agent_policy: Policy) -> None:
        enforcer = Enforcer(code_agent_policy)
        result = enforcer.enforce_sync(
            echo,
            "def fib(n): return n if n < 2 else fib(n-1) + fib(n-2)",
            tool_name="run_python_sandbox",
        )
        assert "fib" in result

    def test_os_system_blocked(self, code_agent_policy: Policy) -> None:
        enforcer = Enforcer(code_agent_policy)
        with pytest.raises(ContentViolationError):
            enforcer.enforce_sync(
                echo,
                "import os\nos.system('rm -rf /')",
                tool_name="run_python_sandbox",
            )

    def test_subprocess_blocked(self, code_agent_policy: Policy) -> None:
        enforcer = Enforcer(code_agent_policy)
        with pytest.raises(ContentViolationError):
            enforcer.enforce_sync(
                echo,
                "import subprocess\nsubprocess.run(['ls'])",
                tool_name="run_python_sandbox",
            )

    def test_shell_tool_denied(self, code_agent_policy: Policy) -> None:
        enforcer = Enforcer(code_agent_policy)
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(echo, "whoami", tool_name="execute_shell")

    def test_pii_in_code_redacted(self, code_agent_policy: Policy) -> None:
        enforcer = Enforcer(code_agent_policy)

        def capture(text: str) -> str:
            return text

        result = enforcer.enforce_sync(
            capture,
            "email = 'user@example.com'",
            tool_name="explain_code",
        )
        assert "user@example.com" not in result


# ---------------------------------------------------------------------------
# Compliance scenario — dry-run + audit chain
# ---------------------------------------------------------------------------


class TestCompliancePipeline:
    """End-to-end: policy preview + full pipeline + audit verification."""

    def test_dry_run_preview(self, compliance_policy: Policy) -> None:
        """PolicyEngine can preview allow/deny decisions without executing."""
        from enforcecore.core.policy import PolicyEngine
        from enforcecore.core.types import CallContext

        engine = PolicyEngine(compliance_policy)

        allowed = engine.evaluate_pre_call(CallContext(tool_name="classify_document"))
        assert allowed.is_allowed

        denied = engine.evaluate_pre_call(CallContext(tool_name="delete_file"))
        assert not denied.is_allowed

    def test_full_pipeline_with_audit(
        self, compliance_policy: Policy, audit_trail_path: Path
    ) -> None:
        enforcer = Enforcer(compliance_policy)

        # 3 allowed calls
        for tool in ["classify_document", "summarize_text", "extract_entities"]:
            enforcer.enforce_sync(echo, "test input", tool_name=tool)

        # 1 blocked call
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(echo, "test", tool_name="delete_file")

        result = verify_trail(audit_trail_path)
        assert result.is_valid
        assert result.total_entries == 4
        assert result.chain_intact

        entries = load_trail(audit_trail_path)
        decisions = [e.decision for e in entries]
        assert decisions == ["allowed", "allowed", "allowed", "blocked"]

    def test_merkle_chain_detects_tampering(
        self, compliance_policy: Policy, audit_trail_path: Path
    ) -> None:
        """Modifying a trail entry breaks the Merkle chain."""
        enforcer = Enforcer(compliance_policy)
        enforcer.enforce_sync(echo, "a", tool_name="classify_document")
        enforcer.enforce_sync(echo, "b", tool_name="summarize_text")

        # Tamper with the trail
        assert audit_trail_path.exists()
        lines = audit_trail_path.read_text().strip().split("\n")
        assert len(lines) >= 2
        # Corrupt the first entry
        lines[0] = lines[0].replace("classify_document", "TAMPERED")
        audit_trail_path.write_text("\n".join(lines) + "\n")

        result = verify_trail(audit_trail_path)
        assert not result.is_valid or not result.chain_intact


# ---------------------------------------------------------------------------
# Cross-policy enforcement
# ---------------------------------------------------------------------------


class TestCrossPolicyEnforcement:
    """Different enforcers with different policies in the same process."""

    def test_two_enforcers_different_policies(
        self, healthcare_policy: Policy, code_agent_policy: Policy
    ) -> None:
        health = Enforcer(healthcare_policy)
        code = Enforcer(code_agent_policy)

        # Healthcare allows medical tools
        result = health.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")
        assert "test" in result

        # Code agent allows sandbox tools
        result = code.enforce_sync(echo, "test", tool_name="run_python_sandbox")
        assert "test" in result

        # Healthcare blocks code tools
        with pytest.raises(ToolDeniedError):
            health.enforce_sync(echo, "test", tool_name="run_python_sandbox")

        # Code agent blocks medical tools
        with pytest.raises(ToolDeniedError):
            code.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")

    def test_shared_audit_trail(
        self,
        healthcare_policy: Policy,
        compliance_policy: Policy,
        audit_trail_path: Path,
    ) -> None:
        """Both enforcers write to the same audit file."""
        h = Enforcer(healthcare_policy)
        c = Enforcer(compliance_policy)

        h.enforce_sync(echo, "a", tool_name="lookup_drug_interactions")
        c.enforce_sync(echo, "b", tool_name="classify_document")

        entries = load_trail(audit_trail_path)
        assert len(entries) == 2
        policies = {e.policy_name for e in entries}
        assert len(policies) == 2  # two different policies

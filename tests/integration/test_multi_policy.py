# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Multi-policy composition integration tests.

Tests using multiple policies in the same process, policy merging,
and cross-policy enforcement scenarios.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from enforcecore import Enforcer, Policy, ToolDeniedError
from enforcecore.auditor.engine import load_trail

SCENARIOS_DIR = Path(__file__).parent.parent.parent / "examples" / "scenarios"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def echo(text: str) -> str:
    return f"echo: {text}"


def noop() -> str:
    return "ok"


# ---------------------------------------------------------------------------
# Same tool, different policies
# ---------------------------------------------------------------------------


class TestMultiPolicyIsolation:
    """Each Enforcer honours its own policy independently."""

    def test_healthcare_vs_code_agent(
        self,
        healthcare_policy: Policy,
        code_agent_policy: Policy,
    ) -> None:
        health = Enforcer(healthcare_policy)
        code = Enforcer(code_agent_policy)

        # Healthcare allows lookup_drug_interactions, code doesn't
        health.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")
        with pytest.raises(ToolDeniedError):
            code.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")

        # Code allows run_python_sandbox, healthcare doesn't
        code.enforce_sync(echo, "test", tool_name="run_python_sandbox")
        with pytest.raises(ToolDeniedError):
            health.enforce_sync(echo, "test", tool_name="run_python_sandbox")

    def test_financial_vs_compliance(
        self,
        financial_policy: Policy,
        compliance_policy: Policy,
    ) -> None:
        fin = Enforcer(financial_policy)
        comp = Enforcer(compliance_policy)

        # Financial allows get_stock_quote
        fin.enforce_sync(echo, "AAPL", tool_name="get_stock_quote")

        # Compliance doesn't allow get_stock_quote
        with pytest.raises(ToolDeniedError):
            comp.enforce_sync(echo, "AAPL", tool_name="get_stock_quote")

        # Compliance allows classify_document
        comp.enforce_sync(echo, "doc", tool_name="classify_document")

        # Financial doesn't allow classify_document
        with pytest.raises(ToolDeniedError):
            fin.enforce_sync(echo, "doc", tool_name="classify_document")


# ---------------------------------------------------------------------------
# All policies deny execute_shell
# ---------------------------------------------------------------------------


class TestUniversalDenials:
    """All scenario policies should deny dangerous tools."""

    @pytest.mark.parametrize(
        "policy_fixture",
        [
            "healthcare_policy",
            "financial_policy",
            "code_agent_policy",
            "compliance_policy",
        ],
    )
    def test_execute_shell_denied_everywhere(
        self, policy_fixture: str, request: pytest.FixtureRequest
    ) -> None:
        policy = request.getfixturevalue(policy_fixture)
        enforcer = Enforcer(policy)
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(echo, "whoami", tool_name="execute_shell")


# ---------------------------------------------------------------------------
# Policy property access
# ---------------------------------------------------------------------------


class TestPolicyProperties:
    """Enforcer exposes policy metadata correctly."""

    def test_policy_name(self, healthcare_policy: Policy) -> None:
        enforcer = Enforcer(healthcare_policy)
        assert enforcer.policy_name == "hipaa-medical"

    def test_policy_object(self, financial_policy: Policy) -> None:
        enforcer = Enforcer(financial_policy)
        assert enforcer.policy.name == "financial-research"
        assert enforcer.policy.version != ""


# ---------------------------------------------------------------------------
# Sequential multi-policy audit trail
# ---------------------------------------------------------------------------


class TestMultiPolicyAuditTrail:
    """Multiple policies writing to the same audit trail."""

    def test_three_policies_one_trail(
        self,
        healthcare_policy: Policy,
        financial_policy: Policy,
        compliance_policy: Policy,
        audit_trail_path: Path,
    ) -> None:
        h = Enforcer(healthcare_policy)
        f = Enforcer(financial_policy)
        c = Enforcer(compliance_policy)

        h.enforce_sync(echo, "a", tool_name="lookup_drug_interactions")
        f.enforce_sync(echo, "b", tool_name="get_stock_quote")
        c.enforce_sync(echo, "c", tool_name="classify_document")

        # All entries are written to the same file
        entries = load_trail(audit_trail_path)
        assert len(entries) == 3
        names = [e.policy_name for e in entries]
        assert len(set(names)) == 3  # 3 distinct policies


# ---------------------------------------------------------------------------
# From-file construction
# ---------------------------------------------------------------------------


class TestEnforcerFromFile:
    """Test Enforcer.from_file() with scenario policies."""

    def test_from_file_healthcare(self) -> None:
        enforcer = Enforcer.from_file(SCENARIOS_DIR / "healthcare" / "policy.yaml")
        result = enforcer.enforce_sync(echo, "test", tool_name="lookup_drug_interactions")
        assert "test" in result

    def test_from_file_compliance(self) -> None:
        enforcer = Enforcer.from_file(SCENARIOS_DIR / "compliance" / "policy.yaml")
        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(echo, "test", tool_name="delete_file")

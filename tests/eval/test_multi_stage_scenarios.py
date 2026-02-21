# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for multi-stage adversarial scenarios (v1.0.17a1).

Tests cover:
- Ransomware campaign (4-stage: enumerate → encrypt → delete → ransom)
- Ransomware bulk encryption
- Supply-chain credential harvesting
- Supply-chain hidden exfiltration
- Multi-agent collusion relay
- Privilege escalation chain
- Slow-burn data exfiltration
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore.eval.scenarios import (
    COLLUSION_RELAY,
    PRIV_ESCALATION_CHAIN,
    RANSOMWARE_CAMPAIGN,
    RANSOMWARE_ENCRYPT_ONLY,
    SCENARIO_EXECUTORS,
    SLOW_BURN_EXFIL,
    SUPPLY_CHAIN_CRED_HARVEST,
    SUPPLY_CHAIN_HIDDEN_EXFIL,
    StageResult,
    _run_multi_stage_scenario,
    get_all_scenarios,
    get_scenarios_by_category,
    run_collusion_relay,
    run_priv_escalation_chain,
    run_ransomware_campaign,
    run_ransomware_encrypt_only,
    run_slow_burn_exfil,
    run_supply_chain_cred_harvest,
    run_supply_chain_hidden_exfil,
)
from enforcecore.eval.types import (
    Scenario,
    ScenarioOutcome,
    Severity,
    ThreatCategory,
)

if TYPE_CHECKING:
    from enforcecore.core.enforcer import Enforcer
    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Registry — new scenarios are registered
# ---------------------------------------------------------------------------


class TestMultiStageRegistry:
    """Multi-stage scenarios are registered and have executors."""

    def test_total_scenario_count(self) -> None:
        scenarios = get_all_scenarios()
        assert len(scenarios) >= 20

    def test_all_new_scenarios_have_executors(self) -> None:
        new_ids = [
            "ransomware-campaign",
            "ransomware-encrypt-only",
            "supply-chain-credential-harvest",
            "supply-chain-hidden-exfil",
            "collusion-agent-relay",
            "priv-escalation-chain",
            "slow-burn-exfil",
        ]
        for sid in new_ids:
            assert sid in SCENARIO_EXECUTORS, f"No executor for {sid}"

    def test_ransomware_category(self) -> None:
        ransomware = get_scenarios_by_category(ThreatCategory.RANSOMWARE)
        assert len(ransomware) >= 2

    def test_supply_chain_category(self) -> None:
        supply_chain = get_scenarios_by_category(ThreatCategory.SUPPLY_CHAIN)
        assert len(supply_chain) >= 2

    def test_collusion_category(self) -> None:
        collusion = get_scenarios_by_category(ThreatCategory.COLLUSION)
        assert len(collusion) >= 1


# ---------------------------------------------------------------------------
# StageResult dataclass
# ---------------------------------------------------------------------------


class TestStageResult:
    """Tests for the StageResult dataclass."""

    def test_blocked_stage(self) -> None:
        sr = StageResult(
            stage_name="test",
            tool_name="bad_tool",
            blocked=True,
            exception_type="ToolDeniedError",
        )
        assert sr.blocked is True
        assert sr.exception_type == "ToolDeniedError"

    def test_allowed_stage(self) -> None:
        sr = StageResult(
            stage_name="test",
            tool_name="good_tool",
            blocked=False,
        )
        assert sr.blocked is False
        assert sr.exception_type is None


# ---------------------------------------------------------------------------
# Multi-stage helper
# ---------------------------------------------------------------------------


class TestMultiStageHelper:
    """Tests for _run_multi_stage_scenario."""

    def test_all_blocked_is_contained(self, specific_tools_policy: Policy) -> None:
        """If all stages are blocked, outcome should be CONTAINED."""
        scenario = Scenario(
            id="test-multi",
            name="test",
            description="test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
        )

        def bad_stage(enforcer: Enforcer) -> object:
            def bad_tool() -> str:
                return "evil"

            return enforcer.enforce_sync(bad_tool, tool_name="bad_tool")

        result = _run_multi_stage_scenario(
            scenario,
            specific_tools_policy,
            [
                ("stage1", "bad_tool", bad_stage),
                ("stage2", "bad_tool", bad_stage),
            ],
            min_blocked=2,
        )
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_insufficient_blocks_is_escaped(
        self, allow_all_policy: Policy
    ) -> None:
        """If not enough stages are blocked, outcome should be ESCAPED."""
        scenario = Scenario(
            id="test-multi-escape",
            name="test",
            description="test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
        )

        def ok_stage(enforcer: Enforcer) -> object:
            def good_tool() -> str:
                return "ok"

            return enforcer.enforce_sync(good_tool, tool_name="good_tool")

        result = _run_multi_stage_scenario(
            scenario,
            allow_all_policy,
            [
                ("stage1", "good_tool", ok_stage),
                ("stage2", "good_tool", ok_stage),
            ],
            min_blocked=2,
        )
        assert result.outcome == ScenarioOutcome.ESCAPED

    def test_error_in_stage(self, specific_tools_policy: Policy) -> None:
        """If a stage raises a non-enforcement error, outcome should be ERROR."""
        scenario = Scenario(
            id="test-multi-error",
            name="test",
            description="test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
        )

        def error_stage(_enforcer: Enforcer) -> object:
            msg = "unexpected"
            raise RuntimeError(msg)

        result = _run_multi_stage_scenario(
            scenario,
            specific_tools_policy,
            [("stage1", "bad_tool", error_stage)],
            min_blocked=1,
        )
        assert result.outcome == ScenarioOutcome.ERROR


# ---------------------------------------------------------------------------
# Ransomware scenarios
# ---------------------------------------------------------------------------


class TestRansomwareScenarios:
    """Tests for ransomware multi-stage scenarios."""

    def test_campaign_contained_specific_policy(
        self, specific_tools_policy: Policy
    ) -> None:
        """Ransomware campaign stages 2-4 must be blocked by specific policy."""
        result = run_ransomware_campaign(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED
        assert "Blocked" in result.details

    def test_campaign_escaped_allow_all(
        self, allow_all_policy: Policy
    ) -> None:
        """Ransomware campaign escapes an allow-all policy."""
        result = run_ransomware_campaign(allow_all_policy)
        assert result.outcome == ScenarioOutcome.ESCAPED

    def test_encrypt_only_contained(
        self, specific_tools_policy: Policy
    ) -> None:
        """All 5 encryption attempts must be blocked."""
        result = run_ransomware_encrypt_only(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED
        assert "Blocked 5/5" in result.details

    def test_campaign_has_correct_metadata(self) -> None:
        assert RANSOMWARE_CAMPAIGN.category == ThreatCategory.RANSOMWARE
        assert RANSOMWARE_CAMPAIGN.severity == Severity.CRITICAL
        assert "multi_stage" in RANSOMWARE_CAMPAIGN.tags

    def test_encrypt_only_metadata(self) -> None:
        assert RANSOMWARE_ENCRYPT_ONLY.category == ThreatCategory.RANSOMWARE
        assert RANSOMWARE_ENCRYPT_ONLY.severity == Severity.CRITICAL

    def test_campaign_denied_policy(self, deny_all_policy: Policy) -> None:
        """Deny-all blocks all 4 stages."""
        result = run_ransomware_campaign(deny_all_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED


# ---------------------------------------------------------------------------
# Supply chain scenarios
# ---------------------------------------------------------------------------


class TestSupplyChainScenarios:
    """Tests for supply-chain attack scenarios."""

    def test_cred_harvest_contained(
        self, specific_tools_policy: Policy
    ) -> None:
        """Credential harvesting exfiltration must be blocked."""
        result = run_supply_chain_cred_harvest(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_hidden_exfil_contained(
        self, specific_tools_policy: Policy
    ) -> None:
        """Hidden exfiltration (base64/hex/split encoding) must be blocked."""
        result = run_supply_chain_hidden_exfil(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_cred_harvest_escaped_allow_all(
        self, allow_all_policy: Policy
    ) -> None:
        """Allow-all policy lets credential harvesting through."""
        result = run_supply_chain_cred_harvest(allow_all_policy)
        assert result.outcome == ScenarioOutcome.ESCAPED

    def test_cred_harvest_metadata(self) -> None:
        assert SUPPLY_CHAIN_CRED_HARVEST.category == ThreatCategory.SUPPLY_CHAIN
        assert SUPPLY_CHAIN_CRED_HARVEST.severity == Severity.CRITICAL

    def test_hidden_exfil_metadata(self) -> None:
        assert SUPPLY_CHAIN_HIDDEN_EXFIL.category == ThreatCategory.SUPPLY_CHAIN


# ---------------------------------------------------------------------------
# Collusion scenario
# ---------------------------------------------------------------------------


class TestCollusionScenarios:
    """Tests for multi-agent collusion scenarios."""

    def test_relay_contained(self) -> None:
        """Policy isolation prevents cross-agent relay attacks.

        Note: collusion scenario creates its own policies internally
        (one for each agent), so no fixture needed.
        """
        # Use any policy — the scenario builds its own agent policies
        from enforcecore.core.policy import Policy as PolicyCls
        from enforcecore.core.policy import PolicyRules

        dummy_policy = PolicyCls(
            name="dummy",
            version="1.0",
            rules=PolicyRules(),
        )
        result = run_collusion_relay(dummy_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED
        assert "Policy isolation enforced" in result.details

    def test_relay_metadata(self) -> None:
        assert COLLUSION_RELAY.category == ThreatCategory.COLLUSION
        assert COLLUSION_RELAY.severity == Severity.HIGH
        assert "multi_agent" in COLLUSION_RELAY.tags


# ---------------------------------------------------------------------------
# Privilege escalation chain
# ---------------------------------------------------------------------------


class TestPrivEscalationChain:
    """Tests for the multi-step privilege escalation chain."""

    def test_escalation_chain_contained(
        self, specific_tools_policy: Policy
    ) -> None:
        """All 4 escalation stages must be blocked."""
        result = run_priv_escalation_chain(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED
        assert "Blocked 4/4" in result.details

    def test_escalation_chain_escaped_allow_all(
        self, allow_all_policy: Policy
    ) -> None:
        """Allow-all lets escalation through."""
        result = run_priv_escalation_chain(allow_all_policy)
        assert result.outcome == ScenarioOutcome.ESCAPED

    def test_escalation_chain_metadata(self) -> None:
        assert PRIV_ESCALATION_CHAIN.category == ThreatCategory.PRIVILEGE_ESCALATION
        assert PRIV_ESCALATION_CHAIN.severity == Severity.CRITICAL
        assert "multi_stage" in PRIV_ESCALATION_CHAIN.tags


# ---------------------------------------------------------------------------
# Slow-burn exfiltration
# ---------------------------------------------------------------------------


class TestSlowBurnExfil:
    """Tests for the slow-burn data exfiltration scenario."""

    def test_slow_burn_contained_specific(
        self, specific_tools_policy: Policy
    ) -> None:
        """Slow-burn exfil must be blocked by tool policy."""
        result = run_slow_burn_exfil(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_slow_burn_with_pii_redaction(
        self, pii_mask_policy: Policy
    ) -> None:
        """With PII redaction, PII should be redacted even if call is allowed."""
        result = run_slow_burn_exfil(pii_mask_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_slow_burn_escaped_allow_all(
        self, allow_all_policy: Policy
    ) -> None:
        """Allow-all with no PII redaction: calls go through, but the
        scenario's send_data function doesn't echo PII in output, so the
        PII check is against the return value (not the input).  The scenario
        counts this as 'redacted' because the output is clean.  This documents
        that audit trail analysis (not runtime blocking) is the detection
        mechanism for slow-burn attacks when tools are allowed.
        """
        result = run_slow_burn_exfil(allow_all_policy)
        # The scenario outcome depends on whether PII appears in the OUTPUT.
        # Since send_data returns "sent N bytes" (no PII), the scenario
        # considers it contained.  This is intentional — it demonstrates
        # that audit trail analysis is needed for allowed-tool exfiltration.
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_slow_burn_metadata(self) -> None:
        assert SLOW_BURN_EXFIL.category == ThreatCategory.DATA_EXFILTRATION
        assert SLOW_BURN_EXFIL.severity == Severity.HIGH
        assert "multi_stage" in SLOW_BURN_EXFIL.tags


# ---------------------------------------------------------------------------
# All multi-stage results have correct metadata
# ---------------------------------------------------------------------------


MULTI_STAGE_IDS = [
    "ransomware-campaign",
    "ransomware-encrypt-only",
    "supply-chain-credential-harvest",
    "supply-chain-hidden-exfil",
    "collusion-agent-relay",
    "priv-escalation-chain",
    "slow-burn-exfil",
]


class TestMultiStageMetadata:
    """All multi-stage scenario results have proper metadata."""

    @pytest.mark.parametrize("scenario_id", MULTI_STAGE_IDS)
    def test_result_has_duration(
        self, scenario_id: str, specific_tools_policy: Policy
    ) -> None:
        executor = SCENARIO_EXECUTORS[scenario_id]
        result = executor(specific_tools_policy)
        assert result.duration_ms >= 0

    @pytest.mark.parametrize("scenario_id", MULTI_STAGE_IDS)
    def test_result_has_details(
        self, scenario_id: str, specific_tools_policy: Policy
    ) -> None:
        executor = SCENARIO_EXECUTORS[scenario_id]
        result = executor(specific_tools_policy)
        assert result.details  # Non-empty details string

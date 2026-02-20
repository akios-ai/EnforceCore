"""Tests for enforcecore.eval.scenarios — adversarial scenario execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from enforcecore.eval.scenarios import (
    SCENARIO_EXECUTORS,
    get_all_scenarios,
    get_scenarios_by_category,
    run_data_exfil_output_size,
    run_data_exfil_pii_output,
    run_pii_leak_input,
    run_policy_evasion_case_variant,
    run_policy_evasion_name_trick,
    run_priv_escalation_multiple,
    run_prompt_injection_input,
    run_prompt_injection_tool_name,
    run_resource_exhaust_cost,
    run_tool_abuse_denied,
    run_tool_abuse_not_allowed,
    run_tool_abuse_rapid_fire,
)
from enforcecore.eval.types import (
    ScenarioOutcome,
    ThreatCategory,
)

if TYPE_CHECKING:
    from enforcecore.core.policy import Policy

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestScenarioRegistry:
    """Tests for the scenario registry."""

    def test_all_scenarios_registered(self) -> None:
        scenarios = get_all_scenarios()
        assert len(scenarios) >= 13

    def test_all_have_executors(self) -> None:
        for s in get_all_scenarios():
            assert s.id in SCENARIO_EXECUTORS, f"No executor for {s.id}"

    def test_get_by_category(self) -> None:
        tool_abuse = get_scenarios_by_category(ThreatCategory.TOOL_ABUSE)
        assert len(tool_abuse) >= 3

    def test_get_by_category_empty(self) -> None:
        # All categories should have at least one scenario
        for cat in ThreatCategory:
            scenarios = get_scenarios_by_category(cat)
            assert len(scenarios) >= 1, f"No scenarios for {cat}"

    def test_all_scenarios_returns_copy(self) -> None:
        a = get_all_scenarios()
        b = get_all_scenarios()
        assert a is not b
        assert a == b


# ---------------------------------------------------------------------------
# Tool abuse scenarios
# ---------------------------------------------------------------------------


class TestToolAbuseScenarios:
    """Tests for tool abuse adversarial scenarios."""

    def test_denied_tool_is_contained(self, specific_tools_policy: Policy) -> None:
        """Calling an explicitly denied tool should be blocked."""
        result = run_tool_abuse_denied(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED
        assert result.exception_type == "ToolDeniedError"

    def test_not_allowed_tool_is_contained(self, deny_all_policy: Policy) -> None:
        """Calling a tool not in the allowed list should be blocked."""
        result = run_tool_abuse_not_allowed(deny_all_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_rapid_fire_contained(self, specific_tools_policy: Policy) -> None:
        """All 100 rapid-fire calls to a denied tool should be blocked."""
        result = run_tool_abuse_rapid_fire(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_denied_tool_allowed_on_allow_all(self, allow_all_policy: Policy) -> None:
        """On an allow-all policy, even 'execute_shell' is allowed."""
        result = run_tool_abuse_denied(allow_all_policy)
        # allow_all has no denied_tools so should escape
        assert result.outcome == ScenarioOutcome.ESCAPED


# ---------------------------------------------------------------------------
# Data exfiltration scenarios
# ---------------------------------------------------------------------------


class TestDataExfiltrationScenarios:
    """Tests for data exfiltration scenarios."""

    def test_oversized_output_contained(self, output_limit_policy: Policy) -> None:
        """Output exceeding max_output_size_bytes should be blocked."""
        result = run_data_exfil_output_size(output_limit_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_pii_output_redacted(self, pii_mask_policy: Policy) -> None:
        """PII in output should be redacted when PII redaction is enabled."""
        result = run_data_exfil_pii_output(pii_mask_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED
        assert "redacted" in result.details.lower() or "blocked" in result.details.lower()


# ---------------------------------------------------------------------------
# Resource exhaustion scenarios
# ---------------------------------------------------------------------------


class TestResourceExhaustionScenarios:
    """Tests for resource exhaustion scenarios."""

    def test_cost_exceeded_contained(self, cost_limit_policy: Policy) -> None:
        """Exceeding cost budget should be blocked."""
        result = run_resource_exhaust_cost(cost_limit_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED


# ---------------------------------------------------------------------------
# Policy evasion scenarios
# ---------------------------------------------------------------------------


class TestPolicyEvasionScenarios:
    """Tests for policy evasion scenarios."""

    def test_name_trick_contained(self, specific_tools_policy: Policy) -> None:
        """Calling a denied tool name, even if function is different, should block."""
        result = run_policy_evasion_name_trick(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_case_variant_contained(self, specific_tools_policy: Policy) -> None:
        """Case variant of a tool name not in allowed list should be blocked."""
        result = run_policy_evasion_case_variant(specific_tools_policy)
        # specific_tools has an allowed list, so variant won't be in it
        assert result.outcome == ScenarioOutcome.CONTAINED


# ---------------------------------------------------------------------------
# PII leakage scenarios
# ---------------------------------------------------------------------------


class TestPIILeakageScenarios:
    """Tests for PII leakage scenarios."""

    def test_pii_in_input_redacted(self, pii_mask_policy: Policy) -> None:
        """PII in tool arguments should be redacted before reaching the tool."""
        result = run_pii_leak_input(pii_mask_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_pii_not_redacted_when_disabled(self, allow_all_policy: Policy) -> None:
        """Without PII redaction, PII passes through (escaped)."""
        result = run_pii_leak_input(allow_all_policy)
        assert result.outcome == ScenarioOutcome.ESCAPED


# ---------------------------------------------------------------------------
# Privilege escalation scenarios
# ---------------------------------------------------------------------------


class TestPrivilegeEscalationScenarios:
    """Tests for privilege escalation scenarios."""

    def test_all_denied_blocked(self, specific_tools_policy: Policy) -> None:
        """All denied tools must be blocked, not just the first."""
        result = run_priv_escalation_multiple(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_no_denied_tools_skipped(self, allow_all_policy: Policy) -> None:
        """When no denied tools exist, the scenario should be skipped."""
        result = run_priv_escalation_multiple(allow_all_policy)
        assert result.outcome == ScenarioOutcome.SKIPPED


# ---------------------------------------------------------------------------
# Prompt injection scenarios
# ---------------------------------------------------------------------------


class TestPromptInjectionScenarios:
    """Tests for prompt injection scenarios."""

    def test_injection_in_input_no_effect(self, allow_all_policy: Policy) -> None:
        """Injection payloads in arguments should have no effect on enforcement."""
        result = run_prompt_injection_input(allow_all_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED

    def test_injection_in_tool_name_contained(self, specific_tools_policy: Policy) -> None:
        """Injection-like tool names should be blocked by allowed list."""
        result = run_prompt_injection_tool_name(specific_tools_policy)
        assert result.outcome == ScenarioOutcome.CONTAINED


# ---------------------------------------------------------------------------
# Scenario results have correct metadata
# ---------------------------------------------------------------------------


class TestScenarioResultMetadata:
    """All scenario results should have proper metadata."""

    def test_all_results_have_duration(self, specific_tools_policy: Policy) -> None:
        """All results should have non-negative duration."""
        for scenario_id, executor in SCENARIO_EXECUTORS.items():
            if callable(executor):
                result = executor(specific_tools_policy)
                assert result.duration_ms >= 0, f"{scenario_id} has negative duration"

    def test_all_results_have_category(self, specific_tools_policy: Policy) -> None:
        """All results should have valid category."""
        for scenario_id, executor in SCENARIO_EXECUTORS.items():
            if callable(executor):
                result = executor(specific_tools_policy)
                assert result.category in ThreatCategory, f"{scenario_id} bad category"

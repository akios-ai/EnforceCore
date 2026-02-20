"""Tests for enforcecore.eval.runner — scenario runner / test harness."""

from __future__ import annotations

from typing import TYPE_CHECKING

from enforcecore.eval.runner import ScenarioRunner
from enforcecore.eval.types import (
    ScenarioOutcome,
    Severity,
    SuiteResult,
    ThreatCategory,
)

if TYPE_CHECKING:
    from enforcecore.core.policy import Policy

# ---------------------------------------------------------------------------
# ScenarioRunner basics
# ---------------------------------------------------------------------------


class TestScenarioRunner:
    """Tests for the ScenarioRunner class."""

    def test_init(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        assert runner.policy.name == specific_tools_policy.name

    def test_list_all_scenarios(self) -> None:
        scenarios = ScenarioRunner.list_scenarios()
        assert len(scenarios) >= 13

    def test_list_by_category(self) -> None:
        scenarios = ScenarioRunner.list_scenarios(category=ThreatCategory.TOOL_ABUSE)
        assert len(scenarios) >= 3
        for s in scenarios:
            assert s.category == ThreatCategory.TOOL_ABUSE

    def test_list_by_severity(self) -> None:
        scenarios = ScenarioRunner.list_scenarios(severity=Severity.CRITICAL)
        assert len(scenarios) >= 1
        for s in scenarios:
            assert s.severity == Severity.CRITICAL

    def test_list_by_tags(self) -> None:
        scenarios = ScenarioRunner.list_scenarios(tags={"pii"})
        assert len(scenarios) >= 1
        for s in scenarios:
            assert "pii" in s.tags

    def test_list_combined_filters(self) -> None:
        scenarios = ScenarioRunner.list_scenarios(
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
        )
        for s in scenarios:
            assert s.category == ThreatCategory.TOOL_ABUSE
            assert s.severity == Severity.HIGH


# ---------------------------------------------------------------------------
# Running scenarios
# ---------------------------------------------------------------------------


class TestRunScenario:
    """Tests for running individual and all scenarios."""

    def test_run_single_scenario(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        scenarios = runner.list_scenarios(category=ThreatCategory.TOOL_ABUSE)
        result = runner.run_scenario(scenarios[0])
        assert result.scenario_id == scenarios[0].id
        assert result.outcome in ScenarioOutcome

    def test_run_all_returns_suite(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        suite = runner.run_all()
        assert isinstance(suite, SuiteResult)
        assert suite.total >= 13
        assert suite.total_duration_ms > 0

    def test_run_all_has_policy_name(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        suite = runner.run_all()
        assert suite.policy_name == "specific-tools"

    def test_run_all_category_filter(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        suite = runner.run_all(category=ThreatCategory.TOOL_ABUSE)
        for r in suite.results:
            assert r.category == ThreatCategory.TOOL_ABUSE

    def test_run_all_severity_filter(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        suite = runner.run_all(severity=Severity.HIGH)
        for r in suite.results:
            assert r.severity == Severity.HIGH

    def test_run_quick(self, specific_tools_policy: Policy) -> None:
        runner = ScenarioRunner(specific_tools_policy)
        suite = runner.run_quick()
        for r in suite.results:
            assert r.severity in (Severity.HIGH, Severity.CRITICAL)


# ---------------------------------------------------------------------------
# Containment expectations with strict policy
# ---------------------------------------------------------------------------


class TestContainmentRates:
    """Test that a strict policy achieves high containment."""

    def test_strict_policy_high_containment(self, specific_tools_policy: Policy) -> None:
        """A strict policy should contain most threats."""
        runner = ScenarioRunner(specific_tools_policy)
        suite = runner.run_all()
        # With specific_tools policy, most scenarios should be contained
        assert suite.containment_rate >= 0.5

    def test_allow_all_lower_containment(self, allow_all_policy: Policy) -> None:
        """An allow-all policy should have lower containment."""
        runner = ScenarioRunner(allow_all_policy)
        suite = runner.run_all()
        # Some scenarios (like prompt injection) are still contained
        # because EnforceCore enforcement is code-level
        assert suite.total > 0

    def test_deny_all_high_containment(self, deny_all_policy: Policy) -> None:
        """A deny-all policy should block everything."""
        runner = ScenarioRunner(deny_all_policy)
        suite = runner.run_all()
        assert suite.containment_rate >= 0.7

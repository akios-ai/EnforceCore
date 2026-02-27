# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Extra coverage for eval/runner.py — SKIPPED and ERROR outcome paths."""

from __future__ import annotations

import pytest

from enforcecore.eval.runner import ScenarioRunner
from enforcecore.eval.types import (
    Scenario,
    ScenarioOutcome,
    Severity,
    ThreatCategory,
)


@pytest.fixture
def allow_all_policy():
    from enforcecore.core.policy import Policy

    return Policy.from_dict({"name": "allow-all", "version": "1.0", "default": "allow"})


@pytest.fixture
def fake_scenario() -> Scenario:
    return Scenario(
        id="test-no-executor-xyz",
        name="Unregistered Scenario",
        description="A synthetic scenario with no registered executor.",
        category=ThreatCategory.TOOL_ABUSE,
        severity=Severity.LOW,
        tags=("test",),
    )


@pytest.fixture
def error_scenario() -> Scenario:
    return Scenario(
        id="test-raises-error-xyz",
        name="Error Scenario",
        description="A synthetic scenario whose executor raises.",
        category=ThreatCategory.TOOL_ABUSE,
        severity=Severity.MEDIUM,
        tags=("test",),
    )


# ---------------------------------------------------------------------------
# SKIPPED outcome — no executor registered (lines 113-114)
# ---------------------------------------------------------------------------


class TestRunScenarioSkipped:
    def test_skipped_when_no_executor(self, allow_all_policy, fake_scenario):
        """run_scenario returns SKIPPED when no executor is registered."""
        runner = ScenarioRunner(allow_all_policy)
        result = runner.run_scenario(fake_scenario)
        assert result.outcome == ScenarioOutcome.SKIPPED
        assert "No executor registered" in result.details

    def test_skipped_scenario_id_matches(self, allow_all_policy, fake_scenario):
        """SKIPPED result carries the correct scenario_id."""
        runner = ScenarioRunner(allow_all_policy)
        result = runner.run_scenario(fake_scenario)
        assert result.scenario_id == fake_scenario.id


# ---------------------------------------------------------------------------
# ERROR outcome — executor raises (lines 136-139)
# ---------------------------------------------------------------------------


class TestRunScenarioError:
    def test_error_when_executor_raises(self, allow_all_policy, error_scenario):
        """run_scenario returns ERROR when the executor function raises."""
        from enforcecore.eval.scenarios import SCENARIO_EXECUTORS

        def _raise_executor(policy):
            raise RuntimeError("simulated executor failure")

        original = SCENARIO_EXECUTORS.pop(error_scenario.id, None)
        SCENARIO_EXECUTORS[error_scenario.id] = _raise_executor
        try:
            runner = ScenarioRunner(allow_all_policy)
            result = runner.run_scenario(error_scenario)
            assert result.outcome == ScenarioOutcome.ERROR
            assert result.exception_type == "RuntimeError"
            assert "simulated executor failure" in result.exception_message
        finally:
            del SCENARIO_EXECUTORS[error_scenario.id]
            if original is not None:
                SCENARIO_EXECUTORS[error_scenario.id] = original

    def test_error_result_has_duration(self, allow_all_policy, error_scenario):
        """ERROR result has a non-negative duration_ms."""
        from enforcecore.eval.scenarios import SCENARIO_EXECUTORS

        def _raise_executor(policy):
            raise ValueError("err")

        SCENARIO_EXECUTORS[error_scenario.id] = _raise_executor
        try:
            runner = ScenarioRunner(allow_all_policy)
            result = runner.run_scenario(error_scenario)
            assert result.duration_ms is not None
            assert result.duration_ms >= 0
        finally:
            del SCENARIO_EXECUTORS[error_scenario.id]

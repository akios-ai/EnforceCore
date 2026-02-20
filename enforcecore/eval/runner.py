"""Test harness — scenario runner that orchestrates evaluation.

The ``ScenarioRunner`` class executes adversarial scenarios against a
given policy and collects results into a ``SuiteResult``.  It supports
filtering by category, severity, or tags, and can generate reports.

Usage::

    from enforcecore.eval.runner import ScenarioRunner
    from enforcecore.core.policy import Policy

    policy = Policy.from_file("policies/strict.yaml")
    runner = ScenarioRunner(policy)
    suite = runner.run_all()
    print(f"Containment: {suite.containment_rate:.0%}")
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import structlog

from enforcecore.eval.scenarios import (
    SCENARIO_EXECUTORS,
    get_all_scenarios,
    get_scenarios_by_category,
)
from enforcecore.eval.types import (
    ScenarioOutcome,
    ScenarioResult,
    Severity,
    SuiteResult,
    ThreatCategory,
)

if TYPE_CHECKING:
    from enforcecore.core.policy import Policy
    from enforcecore.eval.types import Scenario

logger = structlog.get_logger("enforcecore.eval.runner")


class ScenarioRunner:
    """Execute adversarial scenarios against a policy.

    The runner looks up the scenario executor function from the
    :data:`SCENARIO_EXECUTORS` registry and invokes it with the policy.

    Example::

        runner = ScenarioRunner(policy)
        suite = runner.run_all()
        for r in suite.results:
            print(f"{r.scenario_name}: {r.outcome}")
    """

    __slots__ = ("_policy",)

    def __init__(self, policy: Policy) -> None:
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    # -- Filtering helpers ---------------------------------------------------

    @staticmethod
    def list_scenarios(
        *,
        category: ThreatCategory | None = None,
        severity: Severity | None = None,
        tags: set[str] | None = None,
    ) -> list[Scenario]:
        """Return scenarios matching the given filters.

        All filters are combined with AND logic.  ``None`` means "no filter".
        """
        scenarios = (
            get_scenarios_by_category(category) if category is not None else get_all_scenarios()
        )
        if severity is not None:
            scenarios = [s for s in scenarios if s.severity == severity]
        if tags is not None:
            scenarios = [s for s in scenarios if tags.issubset(set(s.tags))]
        return scenarios

    # -- Execution -----------------------------------------------------------

    def run_scenario(self, scenario: Scenario) -> ScenarioResult:
        """Execute a single scenario against the configured policy.

        If no executor is registered for the scenario, a ``SKIPPED`` result
        is returned.

        Args:
            scenario: The scenario to execute.

        Returns:
            The result of executing the scenario.
        """
        executor_fn = SCENARIO_EXECUTORS.get(scenario.id)
        if executor_fn is None or not callable(executor_fn):
            logger.warning("scenario_no_executor", scenario_id=scenario.id)
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                outcome=ScenarioOutcome.SKIPPED,
                details=f"No executor registered for scenario '{scenario.id}'",
            )

        logger.info("scenario_start", scenario=scenario.id, category=scenario.category)
        t0 = time.perf_counter()

        try:
            result = executor_fn(self._policy)
            elapsed = (time.perf_counter() - t0) * 1000
            logger.info(
                "scenario_complete",
                scenario=scenario.id,
                outcome=result.outcome,
                duration_ms=round(elapsed, 2),
            )
            return result
        except Exception as exc:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.error("scenario_error", scenario=scenario.id, exc_info=True)
            return ScenarioResult(
                scenario_id=scenario.id,
                scenario_name=scenario.name,
                category=scenario.category,
                severity=scenario.severity,
                outcome=ScenarioOutcome.ERROR,
                duration_ms=round(elapsed, 2),
                exception_type=type(exc).__name__,
                exception_message=str(exc),
                details=f"Runner-level error: {exc}",
            )

    def run_all(
        self,
        *,
        category: ThreatCategory | None = None,
        severity: Severity | None = None,
        tags: set[str] | None = None,
    ) -> SuiteResult:
        """Execute all matching scenarios and return aggregated results.

        Args:
            category: Filter by threat category (``None`` = all).
            severity: Filter by severity level (``None`` = all).
            tags: Filter by tags — scenarios must have ALL given tags.

        Returns:
            A :class:`SuiteResult` with all scenario results aggregated.
        """
        scenarios = self.list_scenarios(
            category=category,
            severity=severity,
            tags=tags,
        )
        suite = SuiteResult(policy_name=self._policy.name)

        logger.info(
            "suite_start",
            policy=self._policy.name,
            scenario_count=len(scenarios),
            category_filter=str(category),
            severity_filter=str(severity),
        )

        t0 = time.perf_counter()

        for scenario in scenarios:
            result = self.run_scenario(scenario)
            suite.results.append(result)

        suite.total_duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        logger.info(
            "suite_complete",
            policy=self._policy.name,
            total=suite.total,
            contained=suite.contained,
            escaped=suite.escaped,
            errors=suite.errors,
            skipped=suite.skipped,
            containment_rate=f"{suite.containment_rate:.1%}",
            duration_ms=suite.total_duration_ms,
        )

        return suite

    def run_quick(self) -> SuiteResult:
        """Run only HIGH and CRITICAL severity scenarios.

        Convenience method for fast validation.
        """
        high = self.run_all(severity=Severity.HIGH)
        critical = self.run_all(severity=Severity.CRITICAL)

        suite = SuiteResult(policy_name=self._policy.name)
        suite.results = high.results + critical.results
        suite.total_duration_ms = high.total_duration_ms + critical.total_duration_ms
        return suite

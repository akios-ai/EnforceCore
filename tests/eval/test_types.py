"""Tests for enforcecore.eval.types — type definitions."""

from __future__ import annotations

import pytest

from enforcecore.eval.types import (
    BenchmarkResult,
    BenchmarkSuite,
    Scenario,
    ScenarioOutcome,
    ScenarioResult,
    Severity,
    SuiteResult,
    ThreatCategory,
)

# ---------------------------------------------------------------------------
# ThreatCategory enum
# ---------------------------------------------------------------------------


class TestThreatCategory:
    """Tests for the ThreatCategory enum."""

    def test_all_categories_exist(self) -> None:
        assert len(ThreatCategory) == 10

    def test_category_values(self) -> None:
        expected = {
            "tool_abuse",
            "data_exfiltration",
            "resource_exhaustion",
            "policy_evasion",
            "pii_leakage",
            "privilege_escalation",
            "prompt_injection",
            "ransomware",
            "supply_chain",
            "collusion",
        }
        assert {c.value for c in ThreatCategory} == expected

    def test_string_comparison(self) -> None:
        assert ThreatCategory.TOOL_ABUSE == "tool_abuse"


# ---------------------------------------------------------------------------
# Severity enum
# ---------------------------------------------------------------------------


class TestSeverity:
    """Tests for the Severity enum."""

    def test_all_levels_exist(self) -> None:
        assert len(Severity) == 4

    def test_severity_values(self) -> None:
        assert Severity.LOW == "low"
        assert Severity.MEDIUM == "medium"
        assert Severity.HIGH == "high"
        assert Severity.CRITICAL == "critical"


# ---------------------------------------------------------------------------
# ScenarioOutcome enum
# ---------------------------------------------------------------------------


class TestScenarioOutcome:
    """Tests for the ScenarioOutcome enum."""

    def test_all_outcomes_exist(self) -> None:
        assert len(ScenarioOutcome) == 4

    def test_outcome_values(self) -> None:
        assert ScenarioOutcome.CONTAINED == "contained"
        assert ScenarioOutcome.ESCAPED == "escaped"
        assert ScenarioOutcome.ERROR == "error"
        assert ScenarioOutcome.SKIPPED == "skipped"


# ---------------------------------------------------------------------------
# Scenario dataclass
# ---------------------------------------------------------------------------


class TestScenario:
    """Tests for the Scenario frozen dataclass."""

    def test_create_scenario(self) -> None:
        s = Scenario(
            id="test-1",
            name="Test Scenario",
            description="A test scenario.",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
        )
        assert s.id == "test-1"
        assert s.name == "Test Scenario"
        assert s.category == ThreatCategory.TOOL_ABUSE
        assert s.severity == Severity.HIGH
        assert s.tags == ()

    def test_scenario_with_tags(self) -> None:
        s = Scenario(
            id="test-2",
            name="Tagged",
            description="With tags.",
            category=ThreatCategory.PII_LEAKAGE,
            severity=Severity.CRITICAL,
            tags=("pii", "redaction"),
        )
        assert s.tags == ("pii", "redaction")

    def test_scenario_is_frozen(self) -> None:
        s = Scenario(
            id="test-3",
            name="Frozen",
            description="Cannot mutate.",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.LOW,
        )
        with pytest.raises(AttributeError):
            s.id = "changed"  # type: ignore[misc]

    def test_scenario_empty_id_raises(self) -> None:
        with pytest.raises(ValueError, match="Scenario ID must not be empty"):
            Scenario(
                id="   ",
                name="Bad",
                description="Bad ID.",
                category=ThreatCategory.TOOL_ABUSE,
                severity=Severity.LOW,
            )


# ---------------------------------------------------------------------------
# ScenarioResult dataclass
# ---------------------------------------------------------------------------


class TestScenarioResult:
    """Tests for the ScenarioResult dataclass."""

    def test_contained_result(self) -> None:
        r = ScenarioResult(
            scenario_id="s-1",
            scenario_name="Test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
            outcome=ScenarioOutcome.CONTAINED,
            duration_ms=1.5,
        )
        assert r.is_contained is True
        assert r.is_escaped is False

    def test_escaped_result(self) -> None:
        r = ScenarioResult(
            scenario_id="s-2",
            scenario_name="Test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
            outcome=ScenarioOutcome.ESCAPED,
        )
        assert r.is_contained is False
        assert r.is_escaped is True

    def test_result_has_run_id(self) -> None:
        r = ScenarioResult(
            scenario_id="s-3",
            scenario_name="Test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
            outcome=ScenarioOutcome.CONTAINED,
        )
        assert r.run_id  # Non-empty UUID

    def test_exception_info(self) -> None:
        r = ScenarioResult(
            scenario_id="s-4",
            scenario_name="Test",
            category=ThreatCategory.TOOL_ABUSE,
            severity=Severity.HIGH,
            outcome=ScenarioOutcome.CONTAINED,
            exception_type="ToolDeniedError",
            exception_message="tool 'bad_tool' is denied",
        )
        assert r.exception_type == "ToolDeniedError"
        assert "bad_tool" in (r.exception_message or "")


# ---------------------------------------------------------------------------
# SuiteResult dataclass
# ---------------------------------------------------------------------------


class TestSuiteResult:
    """Tests for the SuiteResult dataclass."""

    @pytest.fixture()
    def suite(self) -> SuiteResult:
        return SuiteResult(
            policy_name="test-policy",
            results=[
                ScenarioResult(
                    scenario_id="s-1",
                    scenario_name="A",
                    category=ThreatCategory.TOOL_ABUSE,
                    severity=Severity.HIGH,
                    outcome=ScenarioOutcome.CONTAINED,
                ),
                ScenarioResult(
                    scenario_id="s-2",
                    scenario_name="B",
                    category=ThreatCategory.TOOL_ABUSE,
                    severity=Severity.MEDIUM,
                    outcome=ScenarioOutcome.ESCAPED,
                ),
                ScenarioResult(
                    scenario_id="s-3",
                    scenario_name="C",
                    category=ThreatCategory.PII_LEAKAGE,
                    severity=Severity.CRITICAL,
                    outcome=ScenarioOutcome.CONTAINED,
                ),
                ScenarioResult(
                    scenario_id="s-4",
                    scenario_name="D",
                    category=ThreatCategory.PII_LEAKAGE,
                    severity=Severity.HIGH,
                    outcome=ScenarioOutcome.SKIPPED,
                ),
                ScenarioResult(
                    scenario_id="s-5",
                    scenario_name="E",
                    category=ThreatCategory.RESOURCE_EXHAUSTION,
                    severity=Severity.HIGH,
                    outcome=ScenarioOutcome.ERROR,
                ),
            ],
        )

    def test_total(self, suite: SuiteResult) -> None:
        assert suite.total == 5

    def test_contained(self, suite: SuiteResult) -> None:
        assert suite.contained == 2

    def test_escaped(self, suite: SuiteResult) -> None:
        assert suite.escaped == 1

    def test_errors(self, suite: SuiteResult) -> None:
        assert suite.errors == 1

    def test_skipped(self, suite: SuiteResult) -> None:
        assert suite.skipped == 1

    def test_containment_rate(self, suite: SuiteResult) -> None:
        # 2 contained / (2 contained + 1 escaped) = 66.7%
        assert abs(suite.containment_rate - 2.0 / 3.0) < 0.01

    def test_containment_rate_all_contained(self) -> None:
        s = SuiteResult(
            results=[
                ScenarioResult(
                    scenario_id="s-1",
                    scenario_name="A",
                    category=ThreatCategory.TOOL_ABUSE,
                    severity=Severity.HIGH,
                    outcome=ScenarioOutcome.CONTAINED,
                ),
            ]
        )
        assert s.containment_rate == 1.0

    def test_containment_rate_empty(self) -> None:
        s = SuiteResult()
        assert s.containment_rate == 0.0

    def test_by_category(self, suite: SuiteResult) -> None:
        by_cat = suite.by_category()
        assert len(by_cat[ThreatCategory.TOOL_ABUSE]) == 2
        assert len(by_cat[ThreatCategory.PII_LEAKAGE]) == 2
        assert len(by_cat[ThreatCategory.RESOURCE_EXHAUSTION]) == 1

    def test_by_severity(self, suite: SuiteResult) -> None:
        by_sev = suite.by_severity()
        assert len(by_sev[Severity.HIGH]) == 3
        assert len(by_sev[Severity.MEDIUM]) == 1
        assert len(by_sev[Severity.CRITICAL]) == 1


# ---------------------------------------------------------------------------
# BenchmarkResult dataclass
# ---------------------------------------------------------------------------


class TestBenchmarkResult:
    """Tests for the BenchmarkResult dataclass."""

    def test_ops_per_second(self) -> None:
        r = BenchmarkResult(
            name="test",
            iterations=1000,
            mean_ms=0.5,
            median_ms=0.4,
            p50_ms=0.4,
            p95_ms=0.8,
            p99_ms=1.0,
            p999_ms=1.5,
            min_ms=0.1,
            max_ms=2.0,
            std_dev_ms=0.2,
            total_ms=500.0,
        )
        assert r.ops_per_second == 2000.0

    def test_ops_per_second_zero_mean(self) -> None:
        r = BenchmarkResult(
            name="test",
            iterations=0,
            mean_ms=0.0,
            median_ms=0.0,
            p50_ms=0.0,
            p95_ms=0.0,
            p99_ms=0.0,
            p999_ms=0.0,
            min_ms=0.0,
            max_ms=0.0,
            std_dev_ms=0.0,
            total_ms=0.0,
        )
        assert r.ops_per_second == 0.0


# ---------------------------------------------------------------------------
# BenchmarkSuite dataclass
# ---------------------------------------------------------------------------


class TestBenchmarkSuite:
    """Tests for the BenchmarkSuite dataclass."""

    def test_empty_suite(self) -> None:
        s = BenchmarkSuite()
        assert s.results == []
        assert s.total_duration_ms == 0.0
        assert s.timestamp  # Non-empty

    def test_suite_with_results(self) -> None:
        r = BenchmarkResult(
            name="test",
            iterations=100,
            mean_ms=1.0,
            median_ms=0.9,
            p50_ms=0.9,
            p95_ms=2.0,
            p99_ms=3.0,
            p999_ms=4.0,
            min_ms=0.5,
            max_ms=5.0,
            std_dev_ms=0.5,
            total_ms=100.0,
        )
        s = BenchmarkSuite(results=[r], python_version="3.14.2", platform="macOS arm64")
        assert len(s.results) == 1
        assert s.python_version == "3.14.2"

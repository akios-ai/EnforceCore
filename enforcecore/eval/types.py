"""Evaluation types — scenario definitions, results, and threat categories.

All types are plain dataclasses with no external dependencies beyond stdlib.
They define the vocabulary for the entire evaluation subsystem.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Threat categories
# ---------------------------------------------------------------------------


class ThreatCategory(enum.StrEnum):
    """Classification of adversarial threat scenarios."""

    TOOL_ABUSE = "tool_abuse"
    DATA_EXFILTRATION = "data_exfiltration"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    POLICY_EVASION = "policy_evasion"
    PII_LEAKAGE = "pii_leakage"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PROMPT_INJECTION = "prompt_injection"


class Severity(enum.StrEnum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScenarioOutcome(enum.StrEnum):
    """Result of a single scenario execution."""

    CONTAINED = "contained"  # Threat was blocked (good)
    ESCAPED = "escaped"  # Threat was NOT blocked (bad)
    ERROR = "error"  # Scenario execution failed
    SKIPPED = "skipped"  # Scenario was not applicable


# ---------------------------------------------------------------------------
# Scenario definition
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    """A single adversarial test scenario.

    Scenarios are atomic — each tests one specific threat vector.
    They are framework-agnostic and rely only on EnforceCore's core API.
    """

    id: str
    name: str
    description: str
    category: ThreatCategory
    severity: Severity
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.id.strip():
            msg = "Scenario ID must not be empty"
            raise ValueError(msg)


# ---------------------------------------------------------------------------
# Scenario result
# ---------------------------------------------------------------------------


@dataclass
class ScenarioResult:
    """Outcome of executing a single scenario.

    Captures the outcome, timing, and any exception that occurred.
    """

    scenario_id: str
    scenario_name: str
    category: ThreatCategory
    severity: Severity
    outcome: ScenarioOutcome
    duration_ms: float = 0.0
    exception_type: str | None = None
    exception_message: str | None = None
    details: str = ""
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def is_contained(self) -> bool:
        """True if the threat was successfully contained."""
        return self.outcome == ScenarioOutcome.CONTAINED

    @property
    def is_escaped(self) -> bool:
        """True if the threat escaped enforcement."""
        return self.outcome == ScenarioOutcome.ESCAPED


# ---------------------------------------------------------------------------
# Suite-level results
# ---------------------------------------------------------------------------


@dataclass
class SuiteResult:
    """Aggregated results from running an entire evaluation suite.

    Provides containment metrics and per-scenario breakdowns.
    """

    results: list[ScenarioResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_name: str = ""
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def contained(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.CONTAINED)

    @property
    def escaped(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.ESCAPED)

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.ERROR)

    @property
    def skipped(self) -> int:
        return sum(1 for r in self.results if r.outcome == ScenarioOutcome.SKIPPED)

    @property
    def containment_rate(self) -> float:
        """Fraction of applicable scenarios that were contained (0.0-1.0).

        Skipped and errored scenarios are excluded from the denominator.
        """
        applicable = self.contained + self.escaped
        if applicable == 0:
            return 0.0
        return self.contained / applicable

    def by_category(self) -> dict[ThreatCategory, list[ScenarioResult]]:
        """Group results by threat category."""
        groups: dict[ThreatCategory, list[ScenarioResult]] = {}
        for r in self.results:
            groups.setdefault(r.category, []).append(r)
        return groups

    def by_severity(self) -> dict[Severity, list[ScenarioResult]]:
        """Group results by severity."""
        groups: dict[Severity, list[ScenarioResult]] = {}
        for r in self.results:
            groups.setdefault(r.severity, []).append(r)
        return groups


# ---------------------------------------------------------------------------
# Benchmark types
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkResult:
    """Result of a single benchmark measurement."""

    name: str
    iterations: int
    mean_ms: float
    median_ms: float
    p95_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float
    total_ms: float
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ops_per_second(self) -> float:
        """Operations per second based on mean latency."""
        if self.mean_ms == 0:
            return 0.0
        return 1000.0 / self.mean_ms


@dataclass
class BenchmarkSuite:
    """Aggregated benchmark results."""

    results: list[BenchmarkResult] = field(default_factory=list)
    total_duration_ms: float = 0.0
    python_version: str = ""
    platform: str = ""
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )

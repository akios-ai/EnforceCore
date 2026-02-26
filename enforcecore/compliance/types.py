# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Types for v1.8.0 Compliance Reporting.

This module has ZERO external dependencies — only stdlib.

Exports:
    ComplianceFormat — StrEnum of supported report formats.
    CompliancePeriod — Reporting period with start/end dates.
    ComplianceReport — Structured compliance export (dataclass).
    ComplianceError  — Raised on compliance export failures.
"""

from __future__ import annotations

import enum
import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ComplianceFormat(enum.StrEnum):
    """Supported compliance report formats.

    .. versionadded:: 1.8.0
    """

    EU_AI_ACT = "eu-ai-act"  #: EU AI Act Article 13 (transparency obligations)
    SOC2 = "soc2"  #: SOC2 Type II security controls
    GDPR = "gdpr"  #: GDPR Article 30 (records of processing activities)


# ---------------------------------------------------------------------------
# CompliancePeriod
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompliancePeriod:
    """A reporting period with an explicit start and end.

    Construct via :meth:`from_label` (e.g. ``"2026-Q4"``) or
    :meth:`from_dates` (arbitrary start/end).

    .. versionadded:: 1.8.0
    """

    start: datetime
    end: datetime
    label: str  # e.g. "2026-Q4", "2026-H1", "2026"

    # ------------------------------------------------------------------
    # Factory constructors
    # ------------------------------------------------------------------

    @classmethod
    def from_label(cls, label: str) -> CompliancePeriod:
        """Parse a human-friendly period label into a :class:`CompliancePeriod`.

        Supported formats:

        - ``"YYYY-Q{1-4}"`` — quarterly  (e.g. ``"2026-Q4"``)
        - ``"YYYY-H{1-2}"`` — half-year  (e.g. ``"2026-H1"``)
        - ``"YYYY"``        — full year   (e.g. ``"2026"``)

        Args:
            label: The period label string.

        Raises:
            ValueError: If the label format is unrecognized.
        """
        label = label.strip()
        parts = label.split("-", 1)

        try:
            year = int(parts[0])
        except ValueError as exc:
            raise ValueError(f"Invalid period label: {label!r}") from exc

        if len(parts) == 1:
            # Full year: "2026"
            start = datetime(year, 1, 1, tzinfo=UTC)
            end = datetime(year, 12, 31, 23, 59, 59, tzinfo=UTC)
            return cls(start=start, end=end, label=label)

        suffix = parts[1].upper()

        if suffix.startswith("Q") and len(suffix) == 2:
            q = int(suffix[1])
            if q not in (1, 2, 3, 4):
                raise ValueError(f"Invalid quarter in period label: {label!r}")
            _quarter_months: dict[int, tuple[int, int, int]] = {
                1: (1, 3, 31),
                2: (4, 6, 30),
                3: (7, 9, 30),
                4: (10, 12, 31),
            }
            start_month, end_month, end_day = _quarter_months[q]
            start = datetime(year, start_month, 1, tzinfo=UTC)
            end = datetime(year, end_month, end_day, 23, 59, 59, tzinfo=UTC)
            return cls(start=start, end=end, label=label)

        if suffix.startswith("H") and len(suffix) == 2:
            h = int(suffix[1])
            if h not in (1, 2):
                raise ValueError(f"Invalid half in period label: {label!r}")
            if h == 1:
                start = datetime(year, 1, 1, tzinfo=UTC)
                end = datetime(year, 6, 30, 23, 59, 59, tzinfo=UTC)
            else:
                start = datetime(year, 7, 1, tzinfo=UTC)
                end = datetime(year, 12, 31, 23, 59, 59, tzinfo=UTC)
            return cls(start=start, end=end, label=label)

        raise ValueError(f"Unrecognized period label format: {label!r}")

    @classmethod
    def from_dates(
        cls,
        start: datetime,
        end: datetime,
        *,
        label: str = "",
    ) -> CompliancePeriod:
        """Create a :class:`CompliancePeriod` from explicit datetimes.

        Args:
            start: Period start (inclusive).
            end:   Period end   (inclusive).
            label: Optional human-readable label (auto-generated if omitted).
        """
        if end < start:
            raise ValueError("end must be >= start")
        if not label:
            label = f"{start.date().isoformat()}..{end.date().isoformat()}"
        return cls(start=start, end=end, label=label)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def contains(self, ts: datetime) -> bool:
        """Return True if *ts* falls within this period (inclusive)."""
        return self.start <= ts <= self.end

    def __str__(self) -> str:
        return self.label


# ---------------------------------------------------------------------------
# ComplianceReport
# ---------------------------------------------------------------------------


@dataclass
class ComplianceReport:
    """Structured compliance export generated by :class:`~enforcecore.compliance.reporter.ComplianceReporter`.

    Contains aggregated statistics from the audit trail plus human-readable
    compliance narratives appropriate for the chosen :class:`ComplianceFormat`.

    .. versionadded:: 1.8.0
    """

    format: ComplianceFormat
    period: CompliancePeriod
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Aggregated audit stats
    total_calls: int = 0
    violations: int = 0
    pii_redactions: int = 0
    compliance_score: float = 1.0  # (total_calls - violations) / total_calls

    # Contextual metadata
    policy_versions: list[str] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    tenant_ids: list[str] = field(default_factory=list)

    # Human-readable narratives (one per article / control area)
    narratives: list[str] = field(default_factory=list)

    # Raw count used to generate this report (may differ from total_calls if
    # some entries were excluded due to filter criteria)
    raw_entry_count: int = 0

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dictionary."""
        d = asdict(self)
        # Convert non-serializable types
        d["format"] = str(self.format)
        d["period"] = {
            "label": self.period.label,
            "start": self.period.start.isoformat(),
            "end": self.period.end.isoformat(),
        }
        d["generated_at"] = self.generated_at.isoformat()
        return d

    def to_json(self, *, indent: int | None = 2) -> str:
        """Serialize to a JSON string.

        Args:
            indent: JSON indentation level. Defaults to 2.
        """
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def __str__(self) -> str:
        return (
            f"ComplianceReport(format={self.format!s}, period={self.period!s}, "
            f"calls={self.total_calls}, violations={self.violations}, "
            f"score={self.compliance_score:.1%})"
        )


# ---------------------------------------------------------------------------
# ComplianceError
# ---------------------------------------------------------------------------


class ComplianceError(Exception):
    """Raised when a compliance report cannot be generated.

    Common causes:

    - Audit trail file is missing or unreadable.
    - The requested period contains no audit entries.
    - Serialization / output-path errors.

    .. versionadded:: 1.8.0
    """

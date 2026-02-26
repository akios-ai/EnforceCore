# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""v1.8.0 Compliance Reporting package.

Turn the audit trail into structured compliance exports — EU AI Act, SOC2, GDPR.

Usage::

    from enforcecore.compliance import (
        ComplianceReporter,
        ComplianceFormat,
        CompliancePeriod,
        ComplianceReport,
        ComplianceError,
    )

    reporter = ComplianceReporter(trail_path="audit_logs/trail.jsonl")
    period   = CompliancePeriod.from_label("2026-Q4")
    report   = reporter.export(ComplianceFormat.EU_AI_ACT, period)

.. versionadded:: 1.8.0
"""

from enforcecore.compliance.reporter import ComplianceReporter
from enforcecore.compliance.types import (
    ComplianceError,
    ComplianceFormat,
    CompliancePeriod,
    ComplianceReport,
)

__all__ = [
    "ComplianceError",
    "ComplianceFormat",
    "CompliancePeriod",
    "ComplianceReport",
    "ComplianceReporter",
]

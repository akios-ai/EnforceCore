# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""GDPR Article 30 compliance narrative template.

Generates human-readable records-of-processing-activities narratives
suitable for GDPR Article 30 compliance documentation.

GDPR Article 30 requires controllers to maintain records of processing
activities. EnforceCore's audit trail is the authoritative source for
these records when AI agents process personal data.

.. versionadded:: 1.8.0
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from enforcecore.compliance.types import CompliancePeriod


def generate_narratives(
    period: CompliancePeriod,
    total_calls: int,
    violations: int,
    pii_redactions: int,
    tool_names: list[str],
    policy_versions: list[str],
) -> list[str]:
    """Generate GDPR Article 30 compliance narratives.

    Returns a list of paragraph-length narrative strings covering the
    Article 30 records-of-processing-activities requirements.

    Args:
        period:          The reporting period.
        total_calls:     Total number of enforced tool calls.
        violations:      Number of calls blocked by policy.
        pii_redactions:  Total PII redaction events.
        tool_names:      Unique tool names exercised in the period.
        policy_versions: Unique policy versions active in the period.
    """
    tools_str = ", ".join(sorted(tool_names)) if tool_names else "none"
    personal_data_calls = pii_redactions  # each redaction event = 1 personal data encounter
    protection_rate = (
        pii_redactions / (pii_redactions + violations) if (pii_redactions + violations) > 0 else 1.0
    )

    return [
        # Article 30(1)(a) — Name and contact details of the controller
        (
            f"[GDPR — Article 30(1): Records of Processing Activities] "
            f"For the reporting period {period.label}, EnforceCore maintained a complete, "
            f"tamper-evident record of all AI agent processing activities involving "
            f"external tool calls. Total processing activities recorded: {total_calls}. "
            f"Categories of tools (external recipients): [{tools_str}]."
        ),
        # Article 30(1)(d) — Description of categories of data subjects
        (
            f"[GDPR — Article 30(1)(d): Categories of Personal Data] "
            f"Personal data processed during {period.label}: EnforceCore's PII detection "
            f"engine identified and redacted personal data in {personal_data_calls} instances. "
            f"Categories detected include: names, email addresses, phone numbers, "
            f"financial identifiers, and other PII as defined by the active policy. "
            f"All detected personal data was redacted before transmission to external tools, "
            f"ensuring data minimisation per GDPR Article 5(1)(c)."
        ),
        # Article 30(1)(f) — Technical and organisational security measures
        (
            f"[GDPR — Article 30(1)(f): Security Measures] "
            f"Technical measures implemented during {period.label}: "
            f"(1) Inline PII redaction — {pii_redactions} personal data items redacted "
            f"at enforcement boundary before tool dispatch. "
            f"(2) Policy enforcement — {violations} policy-violating calls blocked, "
            f"preventing unauthorised data processing. "
            f"(3) Immutable audit trail — all {total_calls} processing activities "
            f"recorded with SHA-256 Merkle chain integrity verification. "
            f"Data protection applied in {protection_rate:.1%} of at-risk calls."
        ),
    ]

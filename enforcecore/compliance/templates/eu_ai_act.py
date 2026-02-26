# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""EU AI Act Article 13 compliance narrative template.

Generates human-readable transparency narratives suitable for inclusion in
EU AI Act Article 13 (transparency obligations for high-risk AI systems)
compliance reports.

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
    """Generate EU AI Act Article 13 compliance narratives.

    Returns a list of paragraph-length narrative strings covering:

    - Article 13(1): Transparency and information provision.
    - Article 13(3)(b): Human oversight capability.
    - Article 13(3)(f): Accuracy, robustness, and cybersecurity.

    Args:
        period:          The reporting period.
        total_calls:     Total number of enforced tool calls.
        violations:      Number of calls blocked by policy.
        pii_redactions:  Total PII redaction events.
        tool_names:      Unique tool names exercised in the period.
        policy_versions: Unique policy versions active in the period.
    """
    allowed = total_calls - violations
    violation_rate = violations / total_calls if total_calls > 0 else 0.0
    tools_str = ", ".join(sorted(tool_names)) if tool_names else "none"
    versions_str = ", ".join(sorted(policy_versions)) if policy_versions else "none"

    return [
        # Article 13(1) — Transparency obligations
        (
            f"[EU AI Act — Article 13(1): Transparency] "
            f"During the reporting period {period.label}, EnforceCore provided real-time, "
            f"policy-driven enforcement for all external tool calls made by AI agents. "
            f"A total of {total_calls} tool calls were evaluated against the active policy. "
            f"Tool names exercised: [{tools_str}]. "
            f"Active policy versions: [{versions_str}]."
        ),
        # Article 13(3)(b) — Human oversight
        (
            f"[EU AI Act — Article 13(3)(b): Human Oversight] "
            f"Of the {total_calls} evaluated calls, {allowed} were permitted and "
            f"{violations} were blocked by policy ({violation_rate:.1%} violation rate). "
            f"All blocked calls were logged to the tamper-proof audit trail for "
            f"human review. EnforceCore's kill-switch capability allows operators to "
            f"halt all agent activity within one enforcement cycle."
        ),
        # Article 13(3)(f) — Data accuracy / PII
        (
            f"[EU AI Act — Article 13(3)(f): Accuracy & Data Protection] "
            f"Personal data protection was enforced via automatic PII redaction. "
            f"A total of {pii_redactions} PII redaction events were applied during the period. "
            f"All personal data detected in agent inputs and outputs was redacted "
            f"prior to transmission, in accordance with the active redaction policy."
        ),
    ]

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""SOC2 Type II compliance narrative template.

Generates human-readable security-control narratives suitable for SOC2
Type II audit evidence packages.

Covers the five Trust Services Criteria (TSC):
- CC6 — Logical and physical access controls
- CC7 — System operations
- CC8 — Change management
- CC9 — Risk mitigation

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
    """Generate SOC2 compliance narratives.

    Returns a list of paragraph-length narrative strings covering the
    relevant Trust Services Criteria for AI agent enforcement controls.

    Args:
        period:          The reporting period.
        total_calls:     Total number of enforced tool calls.
        violations:      Number of calls blocked by policy.
        pii_redactions:  Total PII redaction events.
        tool_names:      Unique tool names exercised in the period.
        policy_versions: Unique policy versions active in the period.
    """
    allowed = total_calls - violations
    containment_rate = allowed / total_calls if total_calls > 0 else 1.0
    versions_str = ", ".join(sorted(policy_versions)) if policy_versions else "none"
    tool_count = len(tool_names)

    return [
        # CC6 — Logical access controls
        (
            f"[SOC2 — CC6: Logical and Physical Access Controls] "
            f"During {period.label}, EnforceCore enforced access controls on {tool_count} "
            f"distinct tool types across {total_calls} total calls. "
            f"Policy allow-lists restricted agent access to only pre-approved tools. "
            f"All policy versions active during the period: [{versions_str}]. "
            f"Policy changes are tracked in the immutable audit trail."
        ),
        # CC7 — System operations / monitoring
        (
            f"[SOC2 — CC7: System Operations] "
            f"EnforceCore maintained continuous enforcement coverage for all "
            f"agent-to-tool interactions during {period.label}. "
            f"Of {total_calls} calls, {allowed} were authorized ({containment_rate:.1%} "
            f"authorization rate) and {violations} were blocked as policy violations. "
            f"All events — allowed and blocked — are recorded in the cryptographically "
            f"verified (Merkle-chained) audit trail for post-incident investigation."
        ),
        # CC8 — Change management
        (
            f"[SOC2 — CC8: Change Management] "
            f"Policy enforcement configuration is version-controlled. "
            f"Any policy change requires an explicit version bump, ensuring "
            f"that all audit entries reference the exact policy version in effect "
            f"at the time of the call. Distinct policy versions in effect during "
            f"{period.label}: {len(policy_versions)}."
        ),
        # CC9 — Risk mitigation / data protection
        (
            f"[SOC2 — CC9: Risk Mitigation] "
            f"Sensitive data exposure risk was mitigated through automatic PII "
            f"redaction. A total of {pii_redactions} PII redaction events were applied "
            f"during {period.label}, preventing personal data from reaching external "
            f"tool endpoints. The redaction engine operates inline, with zero "
            f"network calls, and adds < 1 ms overhead per enforcement cycle."
        ),
    ]

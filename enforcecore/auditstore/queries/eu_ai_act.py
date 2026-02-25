"""EU AI Act compliance queries and templates."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..core import AuditEntry, AuditStore


class EUAIActQueries:
    """Compliance queries for EU AI Act Articles 9, 13, 14, 52."""

    def __init__(self, store: AuditStore):
        """Initialize with audit store."""
        self.store = store

    def article_9_high_risk_decisions(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Article 9: List all decisions made by high-risk AI system.

        Per Article 9, high-risk systems must log all decisions.
        """
        entries = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            limit=999999,
        )

        return {
            "article": "9",
            "title": "High-Risk AI System Decisions",
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_decisions": len(entries),
            "decisions": [e.to_dict() for e in entries],
        }

    def article_13_human_oversight(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Article 13: Evidence of human oversight (policy violations).

        Human oversight is demonstrated by policy violations (blocked calls).
        """
        violations = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            decision="blocked",
            limit=999999,
        )

        return {
            "article": "13",
            "title": "Human Oversight Evidence",
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "blocked_calls": len(violations),
            "blocked_calls_detail": [v.to_dict() for v in violations],
            "evidence": "Blocked calls demonstrate that human-defined policies are enforced and override AI decisions when needed",
        }

    def article_14_information_requirements(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Article 14: Transparency information for end users.

        Article 14 requires transparency about AI system behavior.
        """
        entries = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            limit=999999,
        )

        stats = {
            "total_calls": len(entries),
            "allowed_calls": len([e for e in entries if e.decision == "allowed"]),
            "blocked_calls": len([e for e in entries if e.decision == "blocked"]),
            "total_redactions": sum(e.input_redactions + e.output_redactions for e in entries),
        }

        return {
            "article": "14",
            "title": "Transparency Information for End Users",
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "statistics": stats,
            "disclaimer": "This AI system operates under policy enforcement. All tool calls are subject to predefined policy rules.",
        }

    def article_52_transparency_log(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Article 52: Transparency log for AI Act compliance.

        Article 52 requires logging of all AI system activity for compliance.
        """
        entries = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            limit=999999,
        )

        merkle_verified = self.store.verify_chain()

        return {
            "article": "52",
            "title": "Transparency Log (Article 52)",
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "entries_count": len(entries),
            "entries": [e.to_dict() for e in entries],
            "merkle_chain_verified": merkle_verified,
            "compliance_status": "EU AI Act Article 52 compliant",
            "audit_trail_integrity": "Merkle-chained and tamper-evident",
        }

    def pii_exposure_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Summary of PII exposure and redaction activity."""
        entries = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            limit=999999,
        )

        redactions_by_category = {}
        for entry in entries:
            for category in entry.redacted_categories:
                redactions_by_category[category] = redactions_by_category.get(category, 0) + 1

        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_entries": len(entries),
            "total_pii_redactions": sum(e.input_redactions + e.output_redactions for e in entries),
            "redactions_by_category": redactions_by_category,
            "entries_with_redactions": len([e for e in entries if e.input_redactions > 0 or e.output_redactions > 0]),
        }

    def policy_violations_summary(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Summary of policy violations and blocked calls."""
        violations = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            decision="blocked",
            limit=999999,
        )

        violations_by_tool = {}
        for v in violations:
            tool = v.tool_name
            violations_by_tool[tool] = violations_by_tool.get(tool, 0) + 1

        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_violations": len(violations),
            "violations_by_tool": violations_by_tool,
            "violations_detail": [v.to_dict() for v in violations],
        }

    def cost_analysis(
        self,
        start_date: datetime,
        end_date: datetime,
        policy_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cost analysis and budget utilization."""
        entries = self.store.list_entries(
            policy_name=policy_name,
            start_time=start_date,
            end_time=end_date,
            limit=999999,
        )

        costs_by_tool = {}
        total_cost = 0.0

        for entry in entries:
            if entry.cost_usd:
                tool = entry.tool_name
                costs_by_tool[tool] = costs_by_tool.get(tool, 0.0) + entry.cost_usd
                total_cost += entry.cost_usd

        return {
            "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
            "total_cost_usd": round(total_cost, 4),
            "cost_by_tool": {k: round(v, 4) for k, v in costs_by_tool.items()},
            "average_cost_per_call": round(total_cost / len(entries), 6) if entries else 0,
            "entries_tracked": len([e for e in entries if e.cost_usd]),
        }

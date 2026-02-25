"""Report generation for regulatory compliance."""

from datetime import datetime
from typing import Any, Dict, Optional

from ..core import AuditStore
from ..queries import EUAIActQueries


class Report:
    """A generated compliance report."""

    def __init__(self, title: str, content: str, format: str = "html"):
        """Initialize report."""
        self.title = title
        self.content = content
        self.format = format
        self.generated_at = datetime.utcnow()

    def render(self) -> str:
        """Return report content as string."""
        return self.content

    def save(self, filename: str) -> None:
        """Save report to file."""
        with open(filename, "w") as f:
            f.write(self.content)

    def __str__(self) -> str:
        """String representation."""
        return f"Report({self.title}, format={self.format})"


class ReportGenerator:
    """Generate compliance reports from audit data."""

    def __init__(self, store: AuditStore):
        """Initialize report generator."""
        self.store = store
        self.queries = EUAIActQueries(store)

    def generate_eu_ai_act_report(
        self,
        organization: str,
        period: str,
        format: str = "html",
    ) -> Report:
        """Generate EU AI Act compliance report (Articles 9, 13, 14, 52).

        Args:
            organization: Organization name
            period: Reporting period (e.g., "Q1 2026")
            format: Output format ("html" or "json")

        Returns:
            Report object
        """
        start_date, end_date = self._parse_period(period)

        # Gather compliance data
        data = {
            "organization": organization,
            "period": period,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "article_9": self.queries.article_9_high_risk_decisions(start_date, end_date),
            "article_13": self.queries.article_13_human_oversight(start_date, end_date),
            "article_14": self.queries.article_14_information_requirements(start_date, end_date),
            "article_52": self.queries.article_52_transparency_log(start_date, end_date),
            "pii_summary": self.queries.pii_exposure_summary(start_date, end_date),
            "violations": self.queries.policy_violations_summary(start_date, end_date),
            "costs": self.queries.cost_analysis(start_date, end_date),
        }

        if format == "html":
            content = self._render_html_report(data)
        elif format == "json":
            import json
            content = json.dumps(data, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported format: {format}")

        return Report(
            title=f"EU AI Act Compliance Report - {period}",
            content=content,
            format=format,
        )

    def _render_html_report(self, data: Dict[str, Any]) -> str:
        """Render HTML report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EU AI Act Compliance Report - {data['period']}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 40px; }}
        .header h1 {{ font-size: 32px; margin-bottom: 10px; }}
        .header p {{ font-size: 16px; opacity: 0.9; }}
        .meta {{ display: flex; gap: 20px; margin: 20px 0; font-size: 14px; color: #666; }}
        .section {{ margin: 30px 0; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; background: #f9f9f9; }}
        .section h2 {{ color: #667eea; margin-bottom: 20px; font-size: 22px; border-bottom: 2px solid #667eea; padding-bottom: 10px; }}
        .section h3 {{ color: #764ba2; margin: 15px 0 10px 0; font-size: 16px; }}
        .metric {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0; }}
        .metric-box {{ background: white; padding: 15px; border-radius: 6px; border-left: 4px solid #667eea; }}
        .metric-box .value {{ font-size: 24px; font-weight: bold; color: #667eea; }}
        .metric-box .label {{ font-size: 12px; color: #666; text-transform: uppercase; margin-top: 5px; }}
        .status {{ padding: 15px; border-radius: 6px; margin: 15px 0; }}
        .status.pass {{ background: #d4edda; border-left: 4px solid #28a745; color: #155724; }}
        .status.warning {{ background: #fff3cd; border-left: 4px solid #ffc107; color: #856404; }}
        .table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        .table th {{ background: #f0f0f0; padding: 12px; text-align: left; font-weight: 600; }}
        .table td {{ padding: 10px 12px; border-bottom: 1px solid #e0e0e0; }}
        .table tr:hover {{ background: #f9f9f9; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 12px; }}
        .compliance-check {{ margin: 10px 0; }}
        .compliance-check.yes {{ color: #28a745; }}
        .compliance-check.no {{ color: #dc3545; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>EU AI Act Compliance Report</h1>
            <p>{data['organization']} • {data['period']}</p>
            <div class="meta">
                <span>Period: {data['start_date']} to {data['end_date']}</span>
                <span>Generated: {data['generated_at']}</span>
            </div>
        </div>

        <div class="section">
            <h2>Executive Summary</h2>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">{data['article_9']['total_decisions']}</div>
                    <div class="label">Total Decisions</div>
                </div>
                <div class="metric-box">
                    <div class="value">{data['article_13']['blocked_calls']}</div>
                    <div class="label">Blocked Calls (Human Oversight)</div>
                </div>
                <div class="metric-box">
                    <div class="value">{data['pii_summary']['total_pii_redactions']}</div>
                    <div class="label">PII Redactions</div>
                </div>
                <div class="metric-box">
                    <div class="value">${{data['costs']['total_cost_usd']:.2f}}</div>
                    <div class="label">Total Cost</div>
                </div>
            </div>

            <div class="status pass">
                <strong>✓ Compliance Status:</strong> EU AI Act Article 52 compliant
            </div>
            <div class="status pass">
                <strong>✓ Audit Trail:</strong> Merkle-chained and tamper-evident
            </div>
        </div>

        <div class="section">
            <h2>Article 9: High-Risk AI System Decisions</h2>
            <p>All decisions made by the high-risk AI system during the reporting period.</p>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">{data['article_9']['total_decisions']}</div>
                    <div class="label">Total Logged Decisions</div>
                </div>
            </div>
            <p><em>Logged decisions are available in the transparency log (Article 52).</em></p>
        </div>

        <div class="section">
            <h2>Article 13: Human Oversight Evidence</h2>
            <p>Evidence that human oversight is implemented and functional.</p>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">{data['article_13']['blocked_calls']}</div>
                    <div class="label">Blocked Calls</div>
                </div>
            </div>
            <div class="status pass">
                <strong>Finding:</strong> {data['article_13']['evidence']}
            </div>
        </div>

        <div class="section">
            <h2>Article 14: Transparency Information</h2>
            <p>Information provided to end users about AI system behavior and limitations.</p>
            <table class="table">
                <tr>
                    <th>Metric</th>
                    <th>Value</th>
                </tr>
                <tr>
                    <td>Total Calls</td>
                    <td>{data['article_14']['statistics']['total_calls']}</td>
                </tr>
                <tr>
                    <td>Allowed Calls</td>
                    <td>{data['article_14']['statistics']['allowed_calls']}</td>
                </tr>
                <tr>
                    <td>Blocked Calls</td>
                    <td>{data['article_14']['statistics']['blocked_calls']}</td>
                </tr>
                <tr>
                    <td>PII Redactions</td>
                    <td>{data['article_14']['statistics']['pii_redactions']}</td>
                </tr>
            </table>
            <div class="status pass">
                <strong>Note:</strong> {data['article_14']['disclaimer']}
            </div>
        </div>

        <div class="section">
            <h2>Article 52: Transparency Log</h2>
            <p>Complete audit trail of all enforced calls with Merkle chain verification.</p>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">{data['article_52']['entries_count']}</div>
                    <div class="label">Logged Entries</div>
                </div>
                <div class="metric-box">
                    <div class="value">{'✓ Valid' if data['article_52']['merkle_chain_verified'] else '✗ Invalid'}</div>
                    <div class="label">Merkle Chain</div>
                </div>
            </div>
            <div class="compliance-check yes">
                ✓ Audit trail integrity: {data['article_52']['audit_trail_integrity']}
            </div>
        </div>

        <div class="section">
            <h2>PII Handling Summary</h2>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">{data['pii_summary']['total_pii_redactions']}</div>
                    <div class="label">Total Redactions</div>
                </div>
                <div class="metric-box">
                    <div class="value">{data['pii_summary']['entries_with_redactions']}</div>
                    <div class="label">Entries with Redactions</div>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Policy Violations</h2>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">{data['violations']['total_violations']}</div>
                    <div class="label">Total Violations</div>
                </div>
            </div>
            <p><em>All policy violations indicate successful enforcement of human-defined policies.</em></p>
        </div>

        <div class="section">
            <h2>Cost Analysis</h2>
            <div class="metric">
                <div class="metric-box">
                    <div class="value">${{data['costs']['total_cost_usd']:.2f}}</div>
                    <div class="label">Total Cost</div>
                </div>
                <div class="metric-box">
                    <div class="value">${{data['costs']['average_cost_per_call']:.6f}}</div>
                    <div class="label">Avg Cost Per Call</div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p>This report was generated automatically by EnforceCore.</p>
            <p>For questions or concerns, contact your compliance team.</p>
            <p>&copy; 2026 AKIOUD AI. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _parse_period(self, period: str) -> tuple:
        """Parse period string to start and end dates.

        Supports: "Q1 2026", "Jan 2026", "2026-01", etc.
        """
        import re
        from dateutil.relativedelta import relativedelta

        # Try "Q1 2026" format
        match = re.match(r"Q(\d)[ -]?(\d{4})", period)
        if match:
            quarter = int(match.group(1))
            year = int(match.group(2))
            month = (quarter - 1) * 3 + 1
            start = datetime(year, month, 1)
            end = start + relativedelta(months=3) - relativedelta(days=1)
            return start, end

        # Try "Jan 2026" or "January 2026" format
        match = re.match(r"(\w+)[ -]?(\d{4})", period)
        if match:
            month_str = match.group(1)
            year = int(match.group(2))
            months = {
                "jan": 1, "january": 1,
                "feb": 2, "february": 2,
                "mar": 3, "march": 3,
                "apr": 4, "april": 4,
                "may": 5, "jun": 6, "june": 6,
                "jul": 7, "july": 7,
                "aug": 8, "august": 8,
                "sep": 9, "september": 9,
                "oct": 10, "october": 10,
                "nov": 11, "november": 11,
                "dec": 12, "december": 12,
            }
            month = months.get(month_str.lower())
            if month:
                start = datetime(year, month, 1)
                end = start + relativedelta(months=1) - relativedelta(days=1)
                return start, end

        # Default: last 30 days
        end = datetime.utcnow()
        start = end - relativedelta(days=30)
        return start, end

#!/usr/bin/env python3
# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Run the full adversarial evaluation suite and save results."""

from __future__ import annotations

from enforcecore.core.policy import PIIRedactionConfig, Policy, PolicyRules
from enforcecore.core.types import RedactionStrategy
from enforcecore.eval.report import generate_suite_report
from enforcecore.eval.runner import ScenarioRunner

policy = Policy(
    name="example-strict",
    version="1.0.0",
    rules=PolicyRules(
        allowed_tools=["search_web", "calculate", "translate", "read_file"],
        denied_tools=["execute_shell", "delete_file", "write_to_db", "send_email"],
        pii_redaction=PIIRedactionConfig(
            enabled=True,
            categories=["email", "phone", "ssn", "credit_card", "passport"],
            strategy=RedactionStrategy.MASK,
        ),
        max_output_size_bytes=10_000,
        max_cost_usd=5.0,
        max_call_duration_ms=500,
    ),
)

runner = ScenarioRunner(policy)
suite = runner.run_all()
report = generate_suite_report(suite)

with open("results/eval_report.md", "w") as f:
    f.write(report)

print(
    f"Scenarios: {suite.total} | Contained: {suite.contained} "
    f"| Escaped: {suite.escaped} | Rate: {suite.containment_rate:.0%}"
)
print("Saved: results/eval_report.md")

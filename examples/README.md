# EnforceCore Examples

This directory contains working examples demonstrating how to use EnforceCore with different agent frameworks.

## Examples

| File | Description | Requires |
|---|---|---|
| `quickstart.py` | Minimal example — enforce a single tool call | enforcecore |
| `pii_redaction.py` | PII detection, redaction strategies, pipeline integration | enforcecore |
| `audit_trail.py` | Merkle-chained audit trail — verification & tamper detection | enforcecore |
| `resource_guard.py` | Time limits, cost budgets, kill switch | enforcecore |
| `framework_integrations.py` | Enforce tools in LangGraph, CrewAI, and AutoGen agents | enforcecore |
| `evaluation_suite.py` | Adversarial scenarios, benchmarks, and report generation | enforcecore |

## End-to-End Scenarios

The `scenarios/` directory contains self-contained scenario examples:

| Directory | Description |
|---|---|
| `scenarios/code_agent/` | Code-executing agent with tool enforcement |
| `scenarios/financial/` | Financial agent with cost budgets and PII redaction |
| `scenarios/healthcare/` | Healthcare agent with strict PII and audit requirements |
| `scenarios/compliance/` | Compliance demo with EU AI Act policy alignment |
| `scenarios/multi_framework/` | Same policy enforced across LangGraph, CrewAI, AutoGen |

## Example Policies

The `policies/` directory contains reusable policy files:

| File | Description |
|---|---|
| `default.yaml` | Balanced policy — moderate restrictions |
| `strict.yaml` | Strict policy — minimal allowed tools, full PII redaction |
| `permissive.yaml` | Permissive policy — most tools allowed, logging only |

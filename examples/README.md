# EnforceCore Examples

This directory contains working examples demonstrating how to use EnforceCore with different agent frameworks.

## Examples

| File | Description | Requires |
|---|---|---|
| `quickstart.py` | Minimal example — enforce a single tool call | enforcecore |
| `pii_redaction.py` | PII detection, redaction strategies, pipeline integration | enforcecore |
| `audit_trail.py` | Merkle-chained audit trail — verification & tamper detection | enforcecore |
| `langgraph_example.py` | Enforce tools in a LangGraph agent | enforcecore, langgraph |
| `crewai_example.py` | Enforce tools in a CrewAI agent | enforcecore, crewai |
| `autogen_example.py` | Enforce tools in an AutoGen agent | enforcecore, autogen |
| `evaluation_suite.py` | Adversarial scenarios, benchmarks, and report generation | enforcecore |

## Example Policies

The `policies/` directory contains reusable policy files:

| File | Description |
|---|---|
| `default.yaml` | Balanced policy — moderate restrictions |
| `strict.yaml` | Strict policy — minimal allowed tools, full PII redaction |
| `permissive.yaml` | Permissive policy — most tools allowed, logging only |

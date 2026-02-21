# Compliance Demo Scenario

## Overview

This example demonstrates a **EU AI Act compliance workflow** with:

- Full enforcement pipeline (policy + redaction + audit + telemetry)
- Policy review via dry-run mode
- Audit trail verification via the Python API
- End-to-end compliance evidence generation

## What it shows

| EnforceCore Feature | Purpose |
|---|---|
| Full Pipeline | Policy → Enforcer → Redactor → Guard → Auditor |
| Dry-Run Mode | Preview policy decisions without executing tools |
| Audit Verification | Merkle chain integrity check for compliance evidence |
| Policy Composition | Policy extends base with additional rules |
| Telemetry | Structured logging for observability |

## Running

```bash
cd examples/scenarios/compliance
python compliance_demo.py
```

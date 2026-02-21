# Healthcare Agent Scenario

## Overview

This example demonstrates a **HIPAA-style medical Q&A agent** where:

- Only approved medical APIs are allowed (no shell, no file writes)
- All patient PII (names, emails, phones, SSNs) is redacted from inputs and outputs
- Every tool call is recorded in a Merkle-chained audit trail for regulatory review
- Secret detection catches any leaked API keys

## What it shows

| EnforceCore Feature | Purpose |
|---|---|
| PII Redaction | Protect patient data (email, phone, SSN, person name) |
| Tool Gating | Only `lookup_drug_interactions`, `query_symptoms_db`, `schedule_appointment` allowed |
| Audit Trail | Tamper-evident log for HIPAA compliance audits |
| Secret Detection | Prevent API key leaks in medical system integrations |
| Content Rules | Block prompt injection patterns |

## Running

```bash
cd examples/scenarios/healthcare
python healthcare_agent.py
```

## Files

| File | Description |
|---|---|
| `healthcare_agent.py` | Runnable scenario with simulated medical tools |
| `policy.yaml` | HIPAA-style enforcement policy |
| `README.md` | This file |

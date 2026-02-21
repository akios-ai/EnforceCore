# Code Agent Scenario

## Overview

This example demonstrates a **sandboxed code execution assistant** where:

- No shell access, no file system writes, no network calls
- Content rules block injection patterns and dangerous code
- Resource guards enforce time and memory limits
- Network enforcement denies all external domains

## What it shows

| EnforceCore Feature | Purpose |
|---|---|
| Tool Gating | Only `run_python_sandbox`, `explain_code`, `format_code` allowed |
| Content Rules | Block `os.system`, `subprocess`, `eval`, injection patterns |
| Network Enforcement | Deny all external network access |
| Resource Guard | 5s time limit, 64MB memory limit |
| PII Redaction | Prevent leaking personal data through code snippets |

## Running

```bash
cd examples/scenarios/code_agent
python code_agent.py
```

# Multi-Framework Agent Scenario

## Overview

This example demonstrates the **same policy applied across multiple agent
frameworks** — LangGraph, CrewAI, and AutoGen — showing that EnforceCore's
enforcement is framework-agnostic.

## What it shows

| EnforceCore Feature | Purpose |
|---|---|
| Integration Adapters | Same policy enforced through LangGraph, CrewAI, AutoGen |
| Framework-Agnostic Policy | One YAML policy, three frameworks |
| Consistent Audit Trail | Same audit format regardless of framework |
| @enforce Decorator | Plain Python function enforcement |

## Running

```bash
cd examples/scenarios/multi_framework
python multi_framework.py
```

> **Note:** Framework adapters are import-guarded. The example runs with
> plain `@enforce` if LangGraph/CrewAI/AutoGen are not installed.

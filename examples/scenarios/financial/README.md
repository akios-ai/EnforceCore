# Financial Agent Scenario

## Overview

This example demonstrates a **cost-controlled trading research assistant** where:

- Budget limits prevent runaway API costs (max $5.00 cumulative)
- Rate limiting caps tool calls (10/minute per tool, 50/minute global)
- Only authorized data sources are permitted
- Webhook alerts fire on cost threshold breach

## What it shows

| EnforceCore Feature | Purpose |
|---|---|
| Cost Tracking | Cumulative spend budget ($5.00 cap) |
| Rate Limiting | Per-tool and global sliding window limits |
| Tool Gating | Only `get_stock_quote`, `search_news`, `get_financials` allowed |
| Network Enforcement | Only approved financial data domains |
| Webhooks | Alerts when cost exceeds 80% of budget |

## Running

```bash
cd examples/scenarios/financial
python financial_agent.py
```

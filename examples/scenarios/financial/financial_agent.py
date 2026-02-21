"""Financial Agent — Cost-controlled trading research assistant.

Demonstrates:
- Cumulative cost budget ($5.00 cap)
- Per-tool and global rate limiting
- Tool gating to authorized financial data sources only
- PII masking for credit card numbers
- Network domain enforcement

Run::

    python examples/scenarios/financial/financial_agent.py
"""

from __future__ import annotations

from pathlib import Path

from enforcecore import (
    Enforcer,
    Policy,
    ToolDeniedError,
)

POLICY_PATH = Path(__file__).parent / "policy.yaml"


# ---------------------------------------------------------------------------
# Simulated financial tools
# ---------------------------------------------------------------------------


def get_stock_quote(symbol: str) -> str:
    """Simulate stock quote API call."""
    prices = {"AAPL": 185.42, "GOOGL": 141.80, "MSFT": 415.60, "TSLA": 248.50}
    price = prices.get(symbol.upper(), 100.00)
    return f"{symbol.upper()}: ${price:.2f} (+1.2%)"


def search_news(query: str) -> str:
    """Simulate financial news search."""
    return (
        f"News for '{query}': "
        "[1] 'Q4 earnings beat estimates' (Reuters) "
        "[2] 'Analyst upgrades target price' (Bloomberg)"
    )


def get_financials(symbol: str) -> str:
    """Simulate financial data retrieval."""
    return (
        f"Financials for {symbol.upper()}: Revenue $94.8B, Net Income $23.6B, EPS $1.46, P/E 28.3"
    )


def execute_trade(symbol: str, qty: int) -> str:
    """Dangerous tool — should be blocked by policy."""
    return f"EXECUTED: BUY {qty} shares of {symbol}"


# ---------------------------------------------------------------------------
# Scenario
# ---------------------------------------------------------------------------


def main() -> None:
    """Run the financial agent scenario."""
    print("=" * 60)
    print("Financial Agent — Cost-Controlled Research")
    print("=" * 60)

    policy = Policy.from_file(POLICY_PATH)
    enforcer = Enforcer(policy)

    # --- Allowed: stock quote ---
    print("\n1. Getting stock quote (allowed)...")
    try:
        result = enforcer.enforce_sync(
            get_stock_quote,
            "AAPL",
            tool_name="get_stock_quote",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # --- Allowed: news search ---
    print("\n2. Searching financial news (allowed)...")
    try:
        result = enforcer.enforce_sync(
            search_news,
            "AAPL earnings",
            tool_name="search_news",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # --- Allowed: financials with PII in input ---
    print("\n3. Getting financials (PII in request)...")
    try:
        result = enforcer.enforce_sync(
            lambda _pii_text: get_financials("MSFT"),
            "Account 4532-1234-5678-9012 requesting MSFT data",
            tool_name="get_financials",
        )
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # --- Denied: trade execution ---
    print("\n4. Attempting trade execution (DENIED)...")
    try:
        enforcer.enforce_sync(
            lambda: execute_trade("AAPL", 1000),
            tool_name="execute_trade",
        )
        print("   ✗ Should have been blocked!")
    except ToolDeniedError as e:
        print(f"   ✓ Blocked: {e}")

    # --- Rate limit demonstration ---
    print("\n5. Rate limiting demo (rapid calls)...")
    blocked = 0
    for _i in range(15):
        try:
            enforcer.enforce_sync(
                get_stock_quote,
                "TSLA",
                tool_name="get_stock_quote",
            )
        except Exception:
            blocked += 1
    print(f"   Sent 15 rapid calls, {blocked} blocked by rate limiter")

    print("\n" + "=" * 60)
    print("Financial scenario complete.")
    print("=" * 60)


if __name__ == "__main__":
    main()

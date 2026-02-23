# Framework Integrations

EnforceCore provides zero-dependency adapter modules for popular AI agent
frameworks.  Each adapter wraps the framework's native tool decorator with
full enforcement — policy checks, PII redaction, audit trails, resource
guards, and rate limiting — in a single line.

!!! note "No hard dependencies"
    EnforceCore **does not** depend on any framework.  Adapter modules use
    optional imports and raise a clear `ImportError` with install instructions
    if the framework is not installed.

## Quick Start

```python
# LangGraph / LangChain
from enforcecore.integrations.langgraph import enforced_tool

@enforced_tool(policy="policy.yaml")
def search_web(query: str) -> str:
    """Search the web."""
    return api.search(query)
```

```python
# CrewAI
from enforcecore.integrations.crewai import enforced_tool

@enforced_tool(policy="policy.yaml")
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))
```

```python
# AutoGen
from enforcecore.integrations.autogen import enforced_tool

@enforced_tool(policy="policy.yaml", description="Get weather")
def get_weather(city: str) -> str:
    return f"Weather in {city}: 22°C, sunny"
```

## Shared Utilities

These helpers are useful when building custom adapters for other frameworks.

::: enforcecore.integrations._base.wrap_with_policy

::: enforcecore.integrations._base.require_package

## LangGraph / LangChain Adapter

The LangGraph adapter creates a `StructuredTool` (from `langchain-core`)
that wraps the decorated function with the full EnforceCore enforcement
pipeline.

```python
from enforcecore.integrations.langgraph import enforced_tool

@enforced_tool(policy="policy.yaml")
def search_web(query: str) -> str:
    """Search the web for information."""
    return api.search(query)

# Use in a LangGraph node — tool calls are automatically enforced
result = search_web.invoke({"query": "AI safety"})
```

**Requirements:** `pip install langchain-core`

## CrewAI Adapter

The CrewAI adapter creates a `Tool` (from `crewai`) with enforcement
applied to every invocation.

```python
from enforcecore.integrations.crewai import enforced_tool

@enforced_tool(policy="policy.yaml")
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))

# Assign to a CrewAI agent
agent = Agent(tools=[calculator], ...)
```

**Requirements:** `pip install crewai`

## AutoGen Adapter

The AutoGen adapter creates an `FunctionTool` (from `autogen-core` v0.4+)
with enforcement wrapping.

```python
from enforcecore.integrations.autogen import enforced_tool

@enforced_tool(policy="policy.yaml", description="Get current weather")
def get_weather(city: str) -> str:
    return f"Weather in {city}: 22°C, sunny"

# Register with an AutoGen agent
agent.register_tool(get_weather)
```

**Requirements:** `pip install autogen-core`

## Building Custom Adapters

Use `wrap_with_policy` to add enforcement to any callable:

```python
from enforcecore.core.policy import Policy
from enforcecore.integrations import wrap_with_policy

policy = Policy.from_file("policy.yaml")

def my_tool(x: int) -> int:
    return x * 2

enforced_fn = wrap_with_policy(my_tool, policy=policy)
result = enforced_fn(21)  # Fully enforced
```

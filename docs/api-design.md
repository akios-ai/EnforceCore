# EnforceCore — API Design (v1.0)

## Design Principles

1. **Simple by default** — Protecting a tool call should take 1-3 lines of code
2. **Explicit over magic** — No hidden behavior; the user should understand what enforcement does
3. **Async-native** — Async-first internally, with sync wrappers for convenience
4. **Composable** — Components can be used independently or together
5. **Type-safe** — Full type annotations, Pydantic models, mypy-strict compatible

---

## Public API Surface

### Top-level imports (`enforcecore`)

```python
from enforcecore import (
    # Primary API
    enforce,                    # Decorator (sync + async)
    Enforcer,                  # Main class for programmatic control

    # Policy
    Policy,                    # Policy model
    PolicyEngine,              # Rule evaluation engine
    load_policy,               # Load policy from YAML file

    # Config
    Settings,                  # Global configuration
    settings,                  # Module-level singleton

    # Redactor (v1.0.1)
    Redactor,                  # PII detection and redaction engine
    RedactionResult,           # Result of a redaction operation
    DetectedEntity,            # A PII entity found in text

    # Auditor (v1.0.2)
    Auditor,                   # Merkle-chained audit trail writer
    AuditEntry,                # Single audit entry with SHA-256 hash
    VerificationResult,        # Result of trail verification
    verify_trail,              # Verify integrity of a JSONL trail file
    load_trail,                # Load trail entries from a JSONL file

    # Guard (v1.0.3)
    ResourceGuard,             # Time/memory limit enforcer
    CostTracker,               # Thread-safe cumulative cost tracker
    KillSwitch,                # Hard termination on limit breach

    # Integrations (v1.0.4)
    require_package,           # Verify optional deps with install messages
    wrap_with_policy,          # Wrap any callable with enforcement

    # Exceptions
    EnforceCoreError,          # Base exception
    EnforcementViolation,      # Policy violation (call blocked)
    ToolDeniedError,           # Specific: tool not allowed
    CostLimitError,            # Specific: cost budget exceeded
    ResourceLimitError,        # Specific: resource limit breached
    RedactionError,            # PII redaction error (fails closed)

    # Types
    CallContext,               # Immutable per-call context
    Decision,                  # Enum: allowed/blocked/redacted
    EnforcementResult,         # Result metadata from an enforced call
    RedactionEvent,            # Record of a single redacted entity
    RedactionStrategy,         # Enum: mask/hash/remove/placeholder
    ViolationType,             # Enum: why a call was blocked
    ViolationAction,           # Enum: block/log/redact
)
```

---

## Core API

### 1. `@enforce()` Decorator

The primary API. Wraps any callable with policy enforcement.

```python
from enforcecore import enforce

# Minimal usage — policy from file
@enforce(policy="policies/agent.yaml")
async def search_web(query: str) -> str:
    return await api.search(query)

# Sync functions also work
@enforce(policy="policies/agent.yaml")
def read_file(path: str) -> str:
    return open(path).read()

# Inline policy (for quick prototyping)
@enforce(
    allowed_tools=["search_web", "calculator"],
    pii_redaction=True,
    max_cost_usd=5.0,
)
async def my_tool(args: dict) -> str:
    ...

# With explicit tool name (when function name differs)
@enforce(policy="policy.yaml", tool_name="web_search")
async def _internal_search(query: str) -> str:
    ...
```

**Behavior:**
- Before call: evaluate pre-call policy rules, redact inputs
- During call: enforce resource limits
- After call: evaluate post-call rules, redact outputs, record audit entry
- On violation: raise `EnforcementViolation` (call never executes)

**Return type:** The original function's return type is preserved. Enforcement metadata is available via `EnforcementResult.last()` or the context manager.

### 2. `enforce()` Context Manager

For cases where the decorator pattern doesn't fit (e.g., wrapping third-party code, dynamic tool selection).

```python
from enforcecore import enforce

async def run_agent_tool(tool_name: str, args: dict) -> dict:
    async with enforce(policy="policy.yaml", tool_name=tool_name) as ctx:
        # ctx.check_pre(args) is called automatically on entry
        result = await execute_tool(tool_name, args)
        ctx.record_result(result)
        # ctx.check_post(result) is called automatically on exit
    return result
```

### 3. `Enforcer` Class

For programmatic control when you need more than the decorator.

```python
from enforcecore import Enforcer, Policy

# Create from a policy
enforcer = Enforcer(Policy.from_file("policy.yaml"))

# Or from a file directly
enforcer = Enforcer.from_file("policy.yaml")

# Sync enforcement
result = enforcer.enforce_sync(search_fn, "query", tool_name="search_web")

# Async enforcement
result = await enforcer.enforce_async(search_fn, "query", tool_name="search_web")

# Context managers (pre-call check only)
with enforcer.guard_sync("search_web") as ctx:
    result = do_search(query)

async with enforcer.guard_async("search_web") as ctx:
    result = await do_search(query)

# Properties
print(enforcer.policy_name)  # "my-policy"
print(enforcer.policy)       # Policy instance
```

---

## Policy API

### Loading Policies

```python
from enforcecore import Policy, load_policy

# From YAML file
policy = load_policy("policies/strict.yaml")

# From dict (programmatic)
policy = Policy(
    name="my-policy",
    rules={
        "allowed_tools": ["search", "calculator"],
        "pii_redaction": {"enabled": True, "categories": ["email", "phone"]},
        "resource_limits": {"max_call_duration_seconds": 30},
    },
    on_violation="block",
)

# Validate without loading
errors = Policy.validate_file("policies/strict.yaml")
if errors:
    print(f"Policy has errors: {errors}")
```

### Policy Model (Pydantic)

```python
from pydantic import BaseModel
from typing import Literal

class PIIRedactionConfig(BaseModel):
    enabled: bool = False
    categories: list[str] = ["email", "phone", "ssn", "credit_card"]
    strategy: Literal["mask", "hash", "remove", "placeholder"] = "placeholder"

class ResourceLimits(BaseModel):
    max_call_duration_seconds: float | None = None
    max_memory_mb: int | None = None
    max_cost_usd: float | None = None

class NetworkPolicy(BaseModel):
    allowed_domains: list[str] = []
    deny_all_other: bool = True

class PolicyRules(BaseModel):
    allowed_tools: list[str] | None = None    # None = all allowed
    denied_tools: list[str] = []
    pii_redaction: PIIRedactionConfig = PIIRedactionConfig()
    resource_limits: ResourceLimits = ResourceLimits()
    network: NetworkPolicy = NetworkPolicy()
    max_output_size_bytes: int | None = None
    redact_output: bool = True

class Policy(BaseModel):
    name: str
    version: str = "1.0"
    rules: PolicyRules
    on_violation: Literal["block", "log", "redact"] = "block"
```

---

## Redactor API (v1.0.1)

The PII redactor uses compiled regex patterns — no heavy NLP dependencies (spaCy, Presidio, etc.). Fast (~0.1–0.5ms per call), portable across all Python versions.

### Supported PII Categories

| Category       | Example                     | Placeholder     |
|----------------|-----------------------------|-----------------|
| `email`        | `john@example.com`          | `<EMAIL>`       |
| `phone`        | `(555) 123-4567`            | `<PHONE>`       |
| `ssn`          | `123-45-6789`               | `<SSN>`         |
| `credit_card`  | `4111-1111-1111-1111`       | `<CREDIT_CARD>` |
| `ip_address`   | `192.168.1.100`             | `<IP_ADDRESS>`  |

### Redaction Strategies

| Strategy       | Result for `john@example.com`   |
|----------------|---------------------------------|
| `placeholder`  | `<EMAIL>`                       |
| `mask`         | `****@****.***`                  |
| `hash`         | `[SHA256:6b0b4806b1e57501]`     |
| `remove`       | *(empty string)*                |

### Standalone Usage

```python
from enforcecore.redactor import Redactor, RedactionResult, DetectedEntity
from enforcecore.core.types import RedactionStrategy

# Default: all categories, placeholder strategy
redactor = Redactor()

# Selective categories
redactor = Redactor(categories=["email", "phone"])

# Custom strategy
redactor = Redactor(strategy=RedactionStrategy.HASH)

# Detection only (no modification)
entities: list[DetectedEntity] = redactor.detect("Email john@example.com")
for e in entities:
    print(f"  {e.category}: {e.text!r} at [{e.start}:{e.end}]")

# Full redaction
result: RedactionResult = redactor.redact("Call 555-123-4567 or john@example.com")
print(result.text)           # "Call <PHONE> or <EMAIL>"
print(result.count)          # 2
print(result.was_redacted)   # True
print(result.original_text)  # "Call 555-123-4567 or john@example.com"
print(result.entities)       # [DetectedEntity(category="phone", ...), ...]
print(result.events)         # [RedactionEvent(entity_type="phone", ...), ...]
```

### Pipeline Integration

When a policy has `pii_redaction.enabled: true`, the Enforcer automatically:

1. **Redacts string args/kwargs** before the tool call
2. **Executes the tool** with clean arguments
3. **Redacts string output** after the tool returns
4. **Logs redaction counts** in the structured log event

```yaml
# policy.yaml
rules:
  pii_redaction:
    enabled: true
    categories: [email, phone, ssn]
    strategy: placeholder
```

```python
from enforcecore import enforce

@enforce(policy="policy.yaml")
def customer_lookup(query: str) -> str:
    # 'query' is already redacted — PII never reaches your tool
    return db.search(query)
```

---

## Auditor API (v1.0.2)

The Merkle-chained auditor records every enforcement decision in a tamper-proof, cryptographically verifiable JSONL trail. Each entry is linked to the previous via SHA-256 hashes — any modification, deletion, or reordering is detectable.

### AuditEntry Fields

| Field | Type | Description |
|---|---|---|
| `entry_id` | `str` | UUID v4, auto-generated |
| `call_id` | `str` | UUID of the enforcement call |
| `timestamp` | `str` | ISO 8601 UTC timestamp |
| `tool_name` | `str` | Name of the tool that was called |
| `policy_name` | `str` | Policy applied |
| `policy_version` | `str` | Policy version |
| `decision` | `str` | `"allowed"` or `"blocked"` |
| `violation_type` | `str \| None` | Error class name (if blocked) |
| `violation_reason` | `str \| None` | Human-readable reason (if blocked) |
| `overhead_ms` | `float` | Enforcement overhead in ms |
| `call_duration_ms` | `float` | Tool execution time in ms |
| `input_redactions` | `int` | PII entities redacted from inputs |
| `output_redactions` | `int` | PII entities redacted from outputs |
| `previous_hash` | `str` | SHA-256 hash of the preceding entry |
| `entry_hash` | `str` | SHA-256 hash of this entry (Merkle link) |

### Standalone Usage

```python
from enforcecore import Auditor, AuditEntry, verify_trail, load_trail

# Create an auditor — writes to a JSONL file
auditor = Auditor(output_path="audit.jsonl")

# Record entries (Merkle-chained automatically)
e1 = auditor.record(
    tool_name="search_web",
    policy_name="default",
    decision="allowed",
    overhead_ms=1.2,
)
e2 = auditor.record(
    tool_name="delete_file",
    policy_name="default",
    decision="blocked",
    violation_type="ToolDeniedError",
    violation_reason="Tool not in allowed list",
)
print(e2.previous_hash == e1.entry_hash)  # True — chain is linked

# Verify trail integrity
result = verify_trail("audit.jsonl")
print(result.is_valid)        # True
print(result.total_entries)   # 2
print(result.chain_intact)    # True
print(result.root_hash)       # SHA-256 of the first entry
print(result.head_hash)       # SHA-256 of the last entry
print(result.error_count)     # 0

# Load entries for analysis
trail: list[AuditEntry] = load_trail("audit.jsonl")
for entry in trail:
    print(f"{entry.tool_name} → {entry.decision}")
```

### Pipeline Integration

When `settings.audit_enabled` is `True` (the default), the Enforcer automatically records an audit entry for every enforced call — both allowed and blocked:

```python
from enforcecore import Enforcer, Policy

enforcer = Enforcer(Policy.from_file("policy.yaml"))
result = enforcer.enforce_sync(my_tool, "arg", tool_name="my_tool")
# → Audit entry written automatically to settings.audit_path / "trail.jsonl"
```

Configure via environment variables:
```bash
ENFORCECORE_AUDIT_ENABLED=true
ENFORCECORE_AUDIT_PATH=./audit_logs/
```

### Cross-Session Continuity

The Auditor resumes the Merkle chain from an existing trail file. Multiple processes or sessions can append to the same trail without breaking the chain:

```python
# Session 1
a1 = Auditor(output_path="trail.jsonl")
a1.record(tool_name="tool_a", policy_name="p")
a1.record(tool_name="tool_b", policy_name="p")

# Session 2 — chain resumes automatically
a2 = Auditor(output_path="trail.jsonl")
a2.record(tool_name="tool_c", policy_name="p")

result = verify_trail("trail.jsonl")
assert result.is_valid  # True — chain intact across sessions
```

### Tamper Detection

Any modification to the JSONL file is detected by `verify_trail()`:

- **Modified entry** → hash mismatch (computed ≠ stored)
- **Deleted entry** → chain break (previous_hash doesn't match)
- **Inserted entry** → chain break (next entry's previous_hash wrong)
- **Reordered entries** → chain break (previous_hash sequence invalid)

---

## Guard API (v1.0.3)

```python
from enforcecore.guard import ResourceGuard, CostTracker, KillSwitch

# ── CostTracker — thread-safe cumulative cost tracking ──────────────

tracker = CostTracker(budget_usd=10.0)
tracker.record(0.05)            # Record a cost, returns new total
tracker.record(0.10)
print(tracker.total_cost)       # 0.15
print(tracker.budget)           # 10.0
tracker.check_budget()          # Passes — under budget
tracker.reset()                 # Reset to zero

# Per-policy budget check
tracker.check_budget(
    "my_tool", "my_policy",
    per_call_budget=5.0,        # From policy's resource_limits.max_cost_usd
)

# ── KillSwitch — coordinated hard termination ──────────────────────

ks = KillSwitch()
ks.trip("memory exceeded 256MB")
print(ks.is_tripped)            # True
print(ks.reason)                # "memory exceeded 256MB"
ks.check("tool", "policy")     # Raises ResourceLimitError
ks.reset()                      # Re-enable calls

# ── ResourceGuard — time/memory limit enforcement ──────────────────

guard = ResourceGuard(
    cost_tracker=tracker,
    kill_switch=ks,
)

# Sync execution with time limit
result = guard.execute_sync(
    my_func, (arg1,), {"key": "val"},
    max_duration_seconds=30.0,
    max_memory_mb=256,
    tool_name="my_tool",
)

# Async execution with time limit
result = await guard.execute_async(
    my_async_func, (arg1,), {},
    max_duration_seconds=30.0,
)

# Platform support info
info = ResourceGuard.platform_info()
# {"platform": "Darwin", "time_limits": True, "memory_limits": True, ...}

# ── Enforcer integration (automatic) ───────────────────────────────

from enforcecore import Enforcer, Policy

policy = Policy.from_file("policy.yaml")
enforcer = Enforcer(policy)

# Access the guard
guard = enforcer.guard
guard.cost_tracker.total_cost   # Cumulative cost

# Record cost after each call
enforcer.record_cost(2.50)

# Resource limits come from policy YAML:
# rules:
#   resource_limits:
#     max_call_duration_seconds: 30
#     max_memory_mb: 256
#     max_cost_usd: 5.00
```

### Platform Support

| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Time limits | ✓ | ✓ | ✓ |
| Memory limits | ✓ (`RLIMIT_AS`) | ~ (`RLIMIT_RSS`, advisory) | ✗ |
| Cost tracking | ✓ | ✓ | ✓ |
| KillSwitch | ✓ | ✓ | ✓ |

---

## Result Types

### EnforcementResult

```python
from dataclasses import dataclass
from enforcecore.core.types import EnforcementResult

@dataclass
class EnforcementResult:
    decision: str               # "allowed" | "blocked" | "redacted"
    tool_name: str
    policy_name: str
    overhead_ms: float
    redactions_input: int       # Number of PII entities redacted from input
    redactions_output: int      # Number of PII entities redacted from output
    audit_entry_id: str | None  # UUID of the audit entry
    resource_usage: dict        # {"duration_ms": ..., "memory_mb": ...}
```

---

## Exception Hierarchy

```python
class EnforceCoreError(Exception):
    """Base exception for all EnforceCore errors."""

class PolicyError(EnforceCoreError):
    """Errors related to policy loading/validation/evaluation."""

class PolicyLoadError(PolicyError):
    """Policy file not found or unparseable."""

class PolicyValidationError(PolicyError):
    """Policy does not conform to schema."""

class EnforcementViolation(EnforceCoreError):
    """A call was blocked due to policy violation."""
    tool_name: str
    policy_name: str
    reason: str

class ToolDeniedError(EnforcementViolation):
    """Tool is not in the allowed list or is explicitly denied."""

class DomainDeniedError(EnforcementViolation):
    """Network domain is not allowed by policy."""

class CostLimitError(EnforcementViolation):
    """Cumulative cost exceeds budget."""

class ResourceLimitError(EnforcementViolation):
    """Resource limit (time, memory) exceeded."""

class RedactionError(EnforceCoreError):
    """Error during PII redaction (fails closed — call is blocked)."""

class AuditError(EnforceCoreError):
    """Error writing audit entry (fails closed — call is blocked)."""
```

---

## CLI Interface (v1.0.2+)

```bash
# Validate a policy file
enforcecore validate policies/strict.yaml

# Verify an audit trail
enforcecore verify audit.jsonl

# Run evaluation suite (v1.0.5+)
enforcecore eval --scenarios all --output results/

# Show version and platform info
enforcecore info
```

---

## Configuration (Environment Variables)

All settings can be overridden via environment variables prefixed with `ENFORCECORE_`:

```bash
ENFORCECORE_DEFAULT_POLICY=policies/default.yaml
ENFORCECORE_AUDIT_PATH=./audit_logs/
ENFORCECORE_AUDIT_ENABLED=true
ENFORCECORE_REDACTION_ENABLED=true
ENFORCECORE_LOG_LEVEL=INFO
ENFORCECORE_COST_BUDGET_USD=100.0
ENFORCECORE_FAIL_OPEN=false  # NEVER set to true in production
```

---

## Integration Adapters API (v1.0.4)

### Overview

Framework integration adapters provide drop-in replacements for each framework's
tool decorator, adding EnforceCore policy enforcement transparently.

All adapters share these properties:
- **No hard dependencies** — framework packages are only imported at call time
- **Import always succeeds** — importing the adapter module never fails
- **Consistent API** — `@enforced_tool(policy=...)` pattern across all frameworks
- **Full enforcement** — policy, PII redaction, resource guards, cost tracking, audit

### Shared Utilities

```python
from enforcecore.integrations import require_package, wrap_with_policy
```

| Function | Description |
|---|---|
| `require_package(pkg, pip_name=...)` | Verify optional dep is installed, raise clear `ImportError` if not |
| `wrap_with_policy(func, policy=..., tool_name=...)` | Wrap any callable with enforcement (used by all adapters) |

### LangGraph / LangChain Adapter

```python
from enforcecore.integrations.langgraph import enforced_tool

# Drop-in replacement for @tool
@enforced_tool(policy="policy.yaml")
def search(query: str) -> str:
    """Search the web for information."""
    return web_search(query)

# With all options
@enforced_tool(
    policy="policy.yaml",
    tool_name="web_search",
    description="Custom description for LLM",
    args_schema=SearchInput,   # Pydantic model
    return_direct=True,
)
def search(query: str) -> str: ...

# Async support
@enforced_tool(policy="policy.yaml")
async def fetch(url: str) -> str: ...
```

**Returns:** `langchain_core.tools.StructuredTool`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `func` | `Callable` | — | Function to wrap (when used without parens) |
| `policy` | `str \| Path \| Policy \| None` | `None` | Policy to enforce |
| `tool_name` | `str \| None` | `func.__name__` | Override tool name for policy evaluation |
| `description` | `str \| None` | docstring | Override tool description shown to LLM |
| `args_schema` | `type \| None` | `None` | Pydantic model for input validation |
| `return_direct` | `bool` | `False` | Return output directly to user |

### CrewAI Adapter

```python
from enforcecore.integrations.crewai import enforced_tool

@enforced_tool(policy="policy.yaml")
def calculator(expression: str) -> str:
    """Evaluate a math expression."""
    return str(eval(expression))

# Custom name
@enforced_tool(policy="policy.yaml", tool_name="math_calculator")
def calc(expr: str) -> str: ...
```

**Returns:** CrewAI tool object

| Parameter | Type | Default | Description |
|---|---|---|---|
| `func` | `Callable` | — | Function to wrap (when used without parens) |
| `policy` | `str \| Path \| Policy \| None` | `None` | Policy to enforce |
| `tool_name` | `str \| None` | `func.__name__` | Override tool name |

### AutoGen Adapter

```python
from enforcecore.integrations.autogen import enforced_tool

@enforced_tool(policy="policy.yaml", description="Get the weather")
async def get_weather(city: str) -> str:
    return await weather_api.get(city)

# Description from docstring
@enforced_tool(policy="policy.yaml")
def search(query: str) -> str:
    """Search the web for information."""
    return web_search(query)
```

**Returns:** `autogen_core.tools.FunctionTool`

| Parameter | Type | Default | Description |
|---|---|---|---|
| `func` | `Callable` | — | Function to wrap (when used without parens) |
| `policy` | `str \| Path \| Policy \| None` | `None` | Policy to enforce |
| `tool_name` | `str \| None` | `func.__name__` | Override tool name |
| `description` | `str \| None` | docstring or name | Tool description shown to LLM |

### Building Custom Adapters

Use `wrap_with_policy` to build adapters for any framework:

```python
from enforcecore.integrations import wrap_with_policy

def my_framework_tool(func, policy):
    """Example custom adapter."""
    enforced = wrap_with_policy(func, policy=policy)
    return MyFramework.register_tool(enforced)
```

---

## Evaluation API (v1.0.5)

The evaluation module provides adversarial testing, benchmarking, and report generation.

### Imports

```python
from enforcecore.eval import (
    # Types
    ThreatCategory, Severity, ScenarioOutcome,
    Scenario, ScenarioResult, SuiteResult,
    BenchmarkResult, BenchmarkSuite,
    # Runners
    ScenarioRunner, BenchmarkRunner,
    # Helpers
    get_all_scenarios, get_scenarios_by_category,
    # Reports
    generate_suite_report, generate_benchmark_report, generate_report,
)
```

### Enums

#### `ThreatCategory(StrEnum)`

Categories of adversarial threats:

| Value | Description |
|---|---|
| `tool_abuse` | Calling denied or unauthorized tools |
| `data_exfiltration` | Exfiltrating data via oversized or PII-containing outputs |
| `resource_exhaustion` | Timeout abuse and cost overrun attacks |
| `policy_evasion` | Bypassing policy via naming tricks or case variants |
| `pii_leakage` | PII appearing in inputs |
| `privilege_escalation` | Attempting access to multiple denied tools |
| `prompt_injection` | Injecting malicious payloads via inputs or tool names |

#### `Severity(StrEnum)`

| Value | Description |
|---|---|
| `low` | Minor policy issues |
| `medium` | Moderate security concern |
| `high` | Significant threat |
| `critical` | Must be blocked |

#### `ScenarioOutcome(StrEnum)`

| Value | Description |
|---|---|
| `contained` | Attack was blocked by EnforceCore |
| `escaped` | Attack was not caught |
| `error` | Scenario raised an unexpected exception |
| `skipped` | Scenario was not run |

### Data Classes

#### `Scenario`

Frozen dataclass describing an adversarial scenario.

| Field | Type | Description |
|---|---|---|
| `id` | `str` | Unique scenario identifier |
| `name` | `str` | Human-readable name |
| `description` | `str` | What the scenario tests |
| `category` | `ThreatCategory` | Threat category |
| `severity` | `Severity` | Severity level |
| `tags` | `frozenset[str]` | Tags for filtering |

#### `ScenarioResult`

Result from running a single scenario.

| Field | Type | Description |
|---|---|---|
| `scenario_id` | `str` | Scenario identifier |
| `scenario_name` | `str` | Scenario name |
| `category` | `ThreatCategory` | Threat category |
| `severity` | `Severity` | Severity level |
| `outcome` | `ScenarioOutcome` | Result outcome |
| `duration_ms` | `float` | Execution time in milliseconds |
| `details` | `str` | Human-readable detail |
| `exception_type` | `str \| None` | Exception class name if error |
| `exception_message` | `str \| None` | Exception message if error |

**Properties:**
- `is_contained: bool` — True if the attack was blocked
- `is_escaped: bool` — True if the attack was not caught

#### `SuiteResult`

Aggregated results from running multiple scenarios.

| Field | Type | Description |
|---|---|---|
| `results` | `list[ScenarioResult]` | All individual results |
| `total_duration_ms` | `float` | Total execution time |

**Properties:**
- `containment_rate: float` — Fraction of scenarios that were contained

**Methods:**
- `by_category() -> dict[ThreatCategory, list[ScenarioResult]]` — Group results by category
- `by_severity() -> dict[Severity, list[ScenarioResult]]` — Group results by severity

#### `BenchmarkResult`

Timing result for a single benchmark.

| Field | Type | Description |
|---|---|---|
| `name` | `str` | Benchmark name |
| `iterations` | `int` | Number of iterations |
| `mean_ms` | `float` | Mean execution time |
| `median_ms` | `float` | Median execution time |
| `p95_ms` | `float` | 95th percentile |
| `p99_ms` | `float` | 99th percentile |
| `min_ms` | `float` | Minimum time |
| `max_ms` | `float` | Maximum time |

**Properties:**
- `ops_per_second: float` — Operations per second (1000 / mean_ms)

#### `BenchmarkSuite`

Collection of benchmark results with platform info.

| Field | Type | Description |
|---|---|---|
| `results` | `list[BenchmarkResult]` | All benchmark results |
| `python_version` | `str` | Python version |
| `platform` | `str` | OS platform |
| `cpu_count` | `int` | Number of CPUs |
| `timestamp` | `str` | ISO 8601 timestamp |

### ScenarioRunner

Orchestrates adversarial scenario execution.

```python
runner = ScenarioRunner(policy)
```

| Parameter | Type | Description |
|---|---|---|
| `policy` | `Policy` | Policy to test against |

#### `run_all`

```python
result: SuiteResult = runner.run_all(
    category=ThreatCategory.tool_abuse,  # optional filter
    severity=Severity.high,               # optional filter
    tags={"pii"},                         # optional filter
)
```

Runs all scenarios matching the given filters. Filters are AND-combined.

#### `run_quick`

```python
result: SuiteResult = runner.run_quick()
```

Runs only HIGH and CRITICAL severity scenarios for a quick smoke test.

#### `run_scenario`

```python
result: ScenarioResult = runner.run_scenario(scenario)
```

Runs a single `Scenario` object.

#### `list_scenarios` (static)

```python
scenarios: list[Scenario] = ScenarioRunner.list_scenarios(
    category=ThreatCategory.prompt_injection,
    severity=Severity.critical,
    tags={"sql"},
)
```

Returns scenarios matching filters without executing them.

### BenchmarkRunner

Measures per-component performance.

```python
bench = BenchmarkRunner()
suite: BenchmarkSuite = bench.run_all(iterations=1000)
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `iterations` | `int` | `1000` | Number of iterations per benchmark |

**Built-in benchmarks:**

| Name | What it measures |
|---|---|
| `policy_pre_call` | Pre-call policy enforcement |
| `policy_post_call` | Post-call policy enforcement |
| `pii_redaction` | PII redaction pipeline |
| `audit_record` | Audit record creation |
| `guard_overhead` | Resource guard overhead |
| `enforcer_e2e` | Full enforcer end-to-end |
| `enforcer_e2e_with_pii` | Full enforcer with PII redaction |

### Report Generation

#### `generate_suite_report`

```python
markdown: str = generate_suite_report(suite_result)
```

Generates a Markdown report for adversarial scenario results including summary, per-category breakdown, and detailed results table.

#### `generate_benchmark_report`

```python
markdown: str = generate_benchmark_report(benchmark_suite)
```

Generates a Markdown report for benchmark results including platform info and performance stats.

#### `generate_report`

```python
markdown: str = generate_report(suite_result, benchmark_suite)
```

Generates a combined Markdown report with both scenario and benchmark sections.

### Helper Functions

#### `get_all_scenarios`

```python
scenarios: list[Scenario] = get_all_scenarios()
```

Returns all 13 registered adversarial scenarios.

#### `get_scenarios_by_category`

```python
scenarios: list[Scenario] = get_scenarios_by_category(ThreatCategory.tool_abuse)
```

Returns scenarios for a specific threat category.

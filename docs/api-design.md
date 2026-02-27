# EnforceCore — API Design (v1.0 – v1.11)

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

    # Hardening (v1.0.6)
    validate_tool_name,        # Validate tool name charset/length
    check_input_size,          # Reject oversized payloads
    deep_redact,               # Recursive nested PII redaction
    enter_enforcement,         # Enter enforcement scope (ContextVar)
    exit_enforcement,          # Exit enforcement scope
    get_enforcement_depth,     # Current nesting depth
    get_enforcement_chain,     # List of tool names in scope
    is_dev_mode,               # Check ENFORCECORE_DEV_MODE
    warn_fail_open,            # Emit RuntimeWarning for fail_open

    # Unicode hardening (v1.0.6)
    normalize_unicode,         # NFC normalization + strip zero-width
    normalize_homoglyphs,      # Confusable char replacement
    decode_encoded_pii,        # URL/HTML entity decoding
    prepare_for_detection,     # Full unicode pipeline

    # Exceptions
    EnforceCoreError,          # Base exception
    EnforcementViolation,      # Policy violation (call blocked)
    ToolDeniedError,           # Specific: tool not allowed
    CostLimitError,            # Specific: cost budget exceeded
    ResourceLimitError,        # Specific: resource limit breached
    RedactionError,            # PII redaction error (fails closed)
    HardeningError,            # Base hardening error (v1.0.6)
    InvalidToolNameError,      # Invalid tool name (v1.0.6)
    InputTooLargeError,        # Payload exceeds limit (v1.0.6)
    EnforcementDepthError,     # Recursive depth exceeded (v1.0.6)

    # Plugin hooks (v1.0.7)
    HookContext,               # Pre/post call hook context
    HookRegistry,              # Hook registration and firing
    ViolationHookContext,      # Violation hook context
    RedactionHookContext,      # Redaction hook context
    on_pre_call,               # Decorator: register pre-call hook
    on_post_call,              # Decorator: register post-call hook
    on_violation,              # Decorator: register violation hook
    on_redaction,              # Decorator: register redaction hook

    # Custom patterns (v1.0.7)
    CustomPattern,             # User-defined PII pattern
    PatternRegistry,           # Pattern registration and lookup

    # Secret detection (v1.0.7)
    DetectedSecret,            # A secret found in text
    SecretScanner,             # Scans text for API keys, tokens, etc.

    # Audit backends (v1.0.7)
    AuditBackend,              # ABC for custom audit backends
    JsonlBackend,              # Default JSONL file backend
    NullBackend,               # Discard backend (testing)
    CallbackBackend,           # Send entries to a callable
    MultiBackend,              # Fan-out to multiple backends

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

class HardeningError(EnforceCoreError):
    """Base exception for hardening validation failures (v1.0.6)."""

class InvalidToolNameError(HardeningError):
    """Tool name is empty, too long, or contains invalid characters."""

class InputTooLargeError(HardeningError):
    """Combined input payload exceeds MAX_INPUT_SIZE_BYTES."""

class EnforcementDepthError(HardeningError):
    """Recursive enforcement nesting exceeds MAX_ENFORCEMENT_DEPTH."""
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
ENFORCECORE_DEV_MODE=false   # Set to true/1/yes to suppress fail_open warnings
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
| `tags` | `tuple[str, ...]` | Tags for filtering |

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
| `run_id` | `str` | Auto-generated UUID for this run |

**Properties:**
- `is_contained: bool` — True if the attack was blocked
- `is_escaped: bool` — True if the attack was not caught

#### `SuiteResult`

Aggregated results from running multiple scenarios.

| Field | Type | Description |
|---|---|---|
| `results` | `list[ScenarioResult]` | All individual results |
| `total_duration_ms` | `float` | Total execution time |
| `run_id` | `str` | Auto-generated UUID for this suite run |
| `policy_name` | `str` | Name of the policy under test |
| `timestamp` | `str` | Auto-generated ISO 8601 timestamp |

**Properties:**
- `total: int` — Total number of results
- `contained: int` — Count of contained results
- `escaped: int` — Count of escaped results
- `errors: int` — Count of error results
- `skipped: int` — Count of skipped results
- `containment_rate: float` — Fraction of applicable scenarios contained (skipped and errored excluded from denominator)

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
| `total_ms` | `float` | Total time across all iterations |
| `details` | `dict[str, Any]` | Optional extra metadata |

**Properties:**
- `ops_per_second: float` — Operations per second (1000 / mean_ms)

#### `BenchmarkSuite`

Collection of benchmark results with platform info.

| Field | Type | Description |
|---|---|---|
| `results` | `list[BenchmarkResult]` | All benchmark results |
| `total_duration_ms` | `float` | Total benchmark suite duration |
| `python_version` | `str` | Python version |
| `platform` | `str` | OS platform |
| `timestamp` | `str` | Auto-generated ISO 8601 timestamp |

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

---

## Hardening API (v1.0.6)

The hardening module provides input validation, scope tracking, recursive redaction,
and unicode evasion protection for production-grade enforcement.

### Imports

```python
from enforcecore import (
    # Validation
    validate_tool_name,
    check_input_size,
    deep_redact,
    # Scope tracking
    enter_enforcement,
    exit_enforcement,
    get_enforcement_depth,
    get_enforcement_chain,
    # Dev mode
    is_dev_mode,
    warn_fail_open,
    # Unicode hardening
    normalize_unicode,
    normalize_homoglyphs,
    decode_encoded_pii,
    prepare_for_detection,
    # Exceptions
    HardeningError,
    InvalidToolNameError,
    InputTooLargeError,
    EnforcementDepthError,
)
```

### Constants

| Constant | Value | Description |
|---|---|---|
| `MAX_TOOL_NAME_LENGTH` | `256` | Maximum allowed tool name length |
| `MAX_INPUT_SIZE_BYTES` | `10_485_760` (10 MB) | Default maximum input payload size |
| `MAX_ENFORCEMENT_DEPTH` | `10` | Maximum recursive enforcement nesting |

### Input Validation

#### `validate_tool_name`

```python
validate_tool_name(name: str) -> str
```

Validates and sanitizes a tool name. Strips leading/trailing whitespace, then checks:
- Non-empty after stripping
- Length ≤ `MAX_TOOL_NAME_LENGTH`
- Characters match `[\w.\-:<>]+` (alphanumeric, underscore, dot, hyphen, colon, angle brackets)

Returns the stripped name. Raises `InvalidToolNameError` on failure.

#### `check_input_size`

```python
check_input_size(
    args: tuple,
    kwargs: dict,
    max_bytes: int = MAX_INPUT_SIZE_BYTES,
) -> None
```

Measures the total size of all `str` and `bytes` arguments. Raises `InputTooLargeError`
if the combined size exceeds `max_bytes`.

### Recursive Redaction

#### `deep_redact`

```python
deep_redact(
    value: Any,
    redact_fn: Callable[[str], str],
    max_depth: int = 10,
) -> Any
```

Recursively traverses nested data structures (dict, list, tuple, set) and applies
`redact_fn` to every string value found. Preserves container types (tuples stay tuples,
sets stay frozensets of redacted values). Stops at `max_depth` to prevent stack overflow.

**Example:**

```python
from enforcecore import deep_redact

data = {
    "user": {"name": "John Doe", "email": "john@example.com"},
    "notes": ["Contact Jane at jane@test.com"],
}

redacted = deep_redact(data, redactor.redact_string)
# {"user": {"name": "[REDACTED]", "email": "[REDACTED]"}, ...}
```

### Enforcement Scope Tracking

Uses `contextvars.ContextVar` to track enforcement nesting depth and call chains.
Thread-safe and async-safe.

#### `enter_enforcement`

```python
enter_enforcement(tool_name: str) -> None
```

Enters an enforcement scope for the given tool. Increments depth and appends
the tool name to the chain. Raises `EnforcementDepthError` if depth exceeds
`MAX_ENFORCEMENT_DEPTH`.

#### `exit_enforcement`

```python
exit_enforcement() -> None
```

Exits the current enforcement scope. Decrements depth and pops the last tool
from the chain. Safe to call even at depth 0 (no-op).

#### `get_enforcement_depth`

```python
get_enforcement_depth() -> int
```

Returns the current enforcement nesting depth (0 when not inside any enforcement).

#### `get_enforcement_chain`

```python
get_enforcement_chain() -> list[str]
```

Returns a copy of the current enforcement call chain (list of tool names,
outermost first).

### Dev Mode & Fail-Open Gating

#### `is_dev_mode`

```python
is_dev_mode() -> bool
```

Returns `True` if the `ENFORCECORE_DEV_MODE` environment variable is set to
a truthy value (`1`, `true`, `yes`, case-insensitive).

#### `warn_fail_open`

```python
warn_fail_open() -> None
```

Emits a `RuntimeWarning` if `fail_open=True` is configured but `ENFORCECORE_DEV_MODE`
is not set. This ensures accidental fail-open in production is immediately visible.

### Unicode Hardening

Protects PII detection against Unicode evasion techniques including zero-width
character insertion, homoglyph substitution, and URL/HTML encoding.

#### `normalize_unicode`

```python
normalize_unicode(text: str) -> str
```

Applies NFC normalization and strips zero-width characters (zero-width space,
zero-width non-joiner, zero-width joiner, soft hyphen, word joiner, BOM, and
11 other invisible characters).

#### `normalize_homoglyphs`

```python
normalize_homoglyphs(text: str) -> str
```

Replaces ~40 known confusable characters with their ASCII equivalents:
- Cyrillic lookalikes (А→A, В→B, С→C, etc.)
- Greek lookalikes (Α→A, Β→B, etc.)
- Fullwidth ASCII (Ａ→A, ０→0, etc.)

Includes a fast-path optimization: skips replacement if the text contains no
characters from the confusable set.

#### `decode_encoded_pii`

```python
decode_encoded_pii(text: str) -> str
```

Decodes URL-encoded (`%40` → `@`) and HTML-entity-encoded (`&#64;` → `@`)
text that may be used to evade PII pattern matching.

#### `prepare_for_detection`

```python
prepare_for_detection(text: str) -> str
```

Full unicode hardening pipeline. Chains all three normalizations in order:
1. `normalize_unicode()` — NFC + strip zero-width
2. `normalize_homoglyphs()` — replace confusables
3. `decode_encoded_pii()` — URL/HTML decoding

This is called automatically by `Redactor.detect()` before pattern matching.

### Enforcer Hardening (Automatic)

The `enforce` decorator and `Enforcer` class automatically apply hardening
in both sync and async paths:

1. **Tool name validation** — `validate_tool_name()` on every call
2. **Scope entry** — `enter_enforcement()` tracks depth/chain
3. **Input size check** — `check_input_size()` rejects oversized payloads
4. **Recursive redaction** — `deep_redact()` handles nested PII in args
5. **Scope exit** — `exit_enforcement()` in `finally` block
6. **Fail-open warning** — `warn_fail_open()` if error handling uses fail_open

### Auditor Improvements (v1.0.6)

#### `load_trail` — new `max_entries` parameter

```python
entries = load_trail(path, max_entries=100)  # Returns last 100 entries
```

When `max_entries` is specified, only the most recent N entries are returned.
Useful for dashboards and quick inspections of large trail files.

#### Optimized resume for large files

For files larger than 8 KB, the auditor seeks near the end of the file to
find the last entry for chain resumption, instead of reading the entire file.

---

## Plugin & Extensibility API (v1.0.7)

### Hook System (`enforcecore.plugins.hooks`)

#### Lifecycle Events

| Event | When | Context | Can abort? |
|---|---|---|---|
| `pre_call` | Before policy evaluation | `HookContext` | ✅ Yes |
| `post_call` | After successful execution | `HookContext` (with result) | No |
| `violation` | When a call is blocked | `ViolationHookContext` | No |
| `redaction` | When PII is redacted | `RedactionHookContext` | No |

#### Decorator API

```python
from enforcecore import on_pre_call, on_post_call, on_violation, on_redaction

@on_pre_call
def log_calls(ctx: HookContext):
    print(f"Calling {ctx.tool_name}")

@on_post_call
def measure_latency(ctx: HookContext):
    metrics.record(ctx.tool_name, ctx.duration_ms)

@on_violation
def alert_on_block(ctx: ViolationHookContext):
    slack.post(f"BLOCKED: {ctx.tool_name} — {ctx.violation_reason}")

@on_redaction
def track_redactions(ctx: RedactionHookContext):
    counter.increment(f"pii.{ctx.direction}.{ctx.category}", ctx.redaction_count)
```

#### Programmatic API

```python
from enforcecore import HookRegistry

registry = HookRegistry.global_registry()
registry.add_pre_call(my_hook_fn)
registry.add_violation(my_alert_fn)

# Instance isolation (for testing)
isolated = HookRegistry()
isolated.add_pre_call(test_hook)

# Count & clear
print(registry.total_count)
registry.clear()
```

#### Pre-call Abort

```python
@on_pre_call
def rate_limiter(ctx: HookContext):
    if is_rate_limited(ctx.tool_name):
        ctx.abort = True
        ctx.abort_reason = "Rate limit exceeded"
```

#### Async Hooks

```python
@on_pre_call
async def async_audit(ctx: HookContext):
    await audit_service.log(ctx.tool_name)
```

Async hooks are awaited in `enforce_async()` and run via `asyncio.run()` in `enforce_sync()`.

---

### Custom PII Patterns (`enforcecore.redactor.patterns`)

```python
from enforcecore import PatternRegistry

# Register a domain-specific pattern
PatternRegistry.register(
    "employee_id",
    r"EMP-\d{6}",
    placeholder="<EMPLOYEE_ID>",
    mask="EMP-******",
)

# With validation to reduce false positives
PatternRegistry.register(
    "medical_record",
    r"MRN-\d{8}",
    validator=lambda match: match.startswith("MRN-"),
)

# Query
PatternRegistry.categories()   # ["employee_id", "medical_record"]
PatternRegistry.count()        # 2

# Unregister
PatternRegistry.unregister("employee_id")

# Instance isolation (for testing)
isolated = PatternRegistry()
isolated.add("test_pattern", r"TEST-\d+")
```

Custom patterns are automatically scanned alongside built-in PII categories during redaction.

---

### Secret Detection (`enforcecore.redactor.secrets`)

```python
from enforcecore import SecretScanner, DetectedSecret

scanner = SecretScanner()
secrets = scanner.detect("My key is AKIAIOSFODNN7EXAMPLE")
# [DetectedSecret(category="aws_access_key", start=10, end=30, text="AKIA...")]

# Limit to specific categories
scanner = SecretScanner(categories=["github_token", "private_key"])

# Quick audit
counts = scanner.scan_and_report(text)
# {"aws_access_key": 1, "github_token": 2}
```

Built-in categories: `aws_access_key`, `aws_secret_key`, `github_token`, `generic_api_key`, `bearer_token`, `private_key`, `password_in_url`.

---

### Pluggable Audit Backends (`enforcecore.auditor.backends`)

```python
from enforcecore import (
    AuditBackend, JsonlBackend, NullBackend,
    CallbackBackend, MultiBackend, Auditor,
)

# Default JSONL backend
backend = JsonlBackend("audit/trail.jsonl")

# Null backend (testing)
backend = NullBackend()

# Callback backend (send to custom pipeline)
entries = []
backend = CallbackBackend(entries.append)

# Error handling
backend = CallbackBackend(
    send_to_siem,
    on_error=lambda exc, entry: logger.error(f"SIEM error: {exc}"),
)

# Fan-out to multiple backends
backend = MultiBackend([
    JsonlBackend("audit.jsonl"),
    CallbackBackend(send_to_siem),
])

# Use with Auditor
auditor = Auditor(backend=backend)

# Custom backend
class S3Backend(AuditBackend):
    def write(self, entry_dict: dict) -> None:
        s3.put_object(Body=json.dumps(entry_dict), ...)

    def close(self) -> None:
        pass  # flush buffers if any
```


---

## API Added in v1.2.0 — Audit Storage System

### `AuditEntry` (dataclass)

```python
from enforcecore import AuditEntry
```

Full-fidelity audit record stored by `AuditStore` backends. All fields are
typed; `merkle_hash`, `parent_hash`, and `chain_index` are set by the backend
on write.

| Field | Type | Notes |
|---|---|---|
| `entry_id` | `str` | UUID4 string, set by `create()` |
| `timestamp` | `datetime` | UTC, set by `create()` |
| `policy_name` | `str` | — |
| `policy_version` | `str` | — |
| `tool_name` | `str` | — |
| `decision` | `str` | `"allowed"` \| `"blocked"` \| `"redacted"` |
| `call_duration_ms` | `float` | End-to-end call time |
| `enforcement_overhead_ms` | `float` | EnforceCore overhead only |
| `input_redactions` | `int` | Default `0` |
| `output_redactions` | `int` | Default `0` |
| `redacted_categories` | `list[str]` | Default `[]` |
| `cost_usd` | `float \| None` | Optional cost tracking |
| `tokens_used` | `int \| None` | Optional token count |
| `violation_type` | `str \| None` | — |
| `violation_reason` | `str \| None` | — |
| `merkle_hash` | `str \| None` | Set by backend on write |
| `parent_hash` | `str \| None` | Set by backend on write |
| `chain_index` | `int \| None` | Set by backend on write |
| `context` | `dict[str, Any]` | Default `{}` |

```python
@classmethod
def create(
    cls,
    policy_name: str,
    policy_version: str,
    tool_name: str,
    decision: str,
    call_duration_ms: float,
    enforcement_overhead_ms: float,
    input_redactions: int = 0,
    output_redactions: int = 0,
    **kwargs: Any,
) -> AuditEntry

def to_dict(self) -> dict[str, Any]
```

---

### `AuditStore`

```python
from enforcecore.auditstore import AuditStore
```

High-level query interface over an `AuditBackend`. All reads go through here.

```python
def __init__(self, backend: AuditBackend, verify_on_read: bool = True) -> None

def record(self, **kwargs: Any) -> AuditEntry

def get_entry(self, entry_id: str) -> AuditEntry | None

def list_entries(
    self,
    policy_name: str | None = None,
    tool_name: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    decision: str | None = None,
    limit: int = 1000,
    offset: int = 0,
) -> list[AuditEntry]

def verify_chain(self, start_index: int = 0, end_index: int | None = None) -> bool

def verify_entry(self, entry: AuditEntry) -> bool

def export(self, format: str = "jsonl") -> str
```

---

### `AuditBackend` (abstract base class)

```python
from enforcecore.auditstore.backends import AuditBackend
```

Implement all abstract methods to create a custom storage backend.

```python
@abstractmethod
def record(self, entry: AuditEntry) -> AuditEntry
# Must compute and set merkle_hash, parent_hash, chain_index.

@abstractmethod
def get_entry(self, entry_id: str) -> AuditEntry | None

@abstractmethod
def list_entries(self, ...) -> list[AuditEntry]

@abstractmethod
def get_chain_tail(self) -> AuditEntry | None

@abstractmethod
def verify_chain(self, start_index: int = 0, end_index: int | None = None) -> bool

@abstractmethod
def verify_entry(self, entry: AuditEntry) -> bool

@abstractmethod
def export(self, format: str = "jsonl") -> str

# Concrete helper — provided for all subclasses:
def _compute_merkle_hash(self, entry: AuditEntry, parent_hash: str | None = None) -> str
# SHA-256 over {entry_id, timestamp, policy_name, tool_name, decision,
#               violation_type, parent_hash}. Genesis parent_hash = "0" * 64.
```

---

### `JSONLBackend`

```python
from enforcecore.auditstore.backends import JSONLBackend

backend = JSONLBackend("audit_logs/trail.jsonl")
```

Append-only JSONL file. Thread-safe via per-call file open. Suitable for
development and low-volume production.

```python
def __init__(self, path: str = "audit_logs/trail.jsonl")
# Parent directories created automatically (mkdir -p).
```

---

### `SQLiteBackend`

```python
from enforcecore.auditstore.backends import SQLiteBackend

backend = SQLiteBackend("audit.db")
```

Local SQLite database with a `merkle_chain` verification table and indices
on `timestamp`, `policy_name`, `tool_name`, `decision`. Best for single-node
production.

```python
def __init__(self, db_path: str = "audit.db", verify_merkle: bool = True)
```

---

### `PostgreSQLBackend`

```python
from enforcecore.auditstore.backends import PostgreSQLBackend
# Requires: pip install enforcecore[postgres]

backend = PostgreSQLBackend(
    host="localhost",
    database="enforcecore",
    user="postgres",
    password="secret",
    port=5432,
    verify_merkle=True,
    pool_size=5,
    ssl_mode="prefer",  # "disable" | "allow" | "prefer" | "require"
)
```

Production-grade backend. Connection pooling, JSONB context column, TIMESTAMPTZ
timestamps, concurrent-write safe. Raises `ImportError` if `psycopg2` is not
installed.

---

### `AuditStoreBackendAdapter`

```python
from enforcecore import AuditStoreBackendAdapter

adapter = AuditStoreBackendAdapter(backend)
auditor = Auditor(backend=adapter)
```

Bridges any `AuditBackend` to the existing `Auditor` write API. Translates
the `Auditor`'s dict format to `AuditEntry` automatically.

```python
def __init__(self, auditstore_backend: AuditBackend) -> None

def write(self, entry_dict: dict[str, Any]) -> None
# Raises AuditError on failure.

def close(self) -> None
```

**Field mapping**: `overhead_ms` → `enforcement_overhead_ms`, `entry_hash` →
`merkle_hash`, `previous_hash` → `parent_hash`.

---

### `EUAIActQueries`

```python
from enforcecore.auditstore.queries.eu_ai_act import EUAIActQueries

queries = EUAIActQueries(store)
```

All methods accept `start_date`, `end_date` (`datetime`) and optional
`policy_name` filter. All return `dict[str, Any]`.

| Method | Article | Returns |
|---|---|---|
| `article_9_high_risk_decisions()` | 9 | Total decisions + detail list |
| `article_13_human_oversight()` | 13 | Blocked calls count + evidence |
| `article_14_information_requirements()` | 14 | Statistics: total/allowed/blocked/redacted |
| `article_52_transparency_log()` | 52 | All entries + Merkle chain verification |
| `pii_exposure_summary()` | — | Total redactions, by-category breakdown |
| `policy_violations_summary()` | — | Violations by tool, detail list |
| `cost_analysis()` | — | Cost by tool, average cost per call |

---

### `ReportGenerator` and `Report`

```python
from enforcecore.auditstore.reports import ReportGenerator

generator = ReportGenerator(store)
report = generator.generate_eu_ai_act_report(
    organization="Acme Corp",
    period="Q1 2026",    # or "Jan 2026", "January 2026"
    format="html",       # or "json"
)
report.save("compliance_report.html")
```

`Report` attributes: `title`, `content`, `format`, `generated_at` (UTC datetime).

```python
def render(self) -> str
def save(self, filename: str) -> None
```

**Supported `period` formats:** `"Q1 2026"`, `"Jan 2026"`, `"January 2026"`.
Defaults to last 30 days if format is unrecognised.

---

## API Added in v1.3.0 — Subprocess Sandbox

### `SandboxStrategy` (enum)

```python
from enforcecore import SandboxStrategy

SandboxStrategy.NONE        # In-process execution (no isolation)
SandboxStrategy.SUBPROCESS  # Isolated subprocess with resource limits
```

### `SandboxConfig` (dataclass)

```python
from enforcecore import SandboxConfig

config = SandboxConfig(
    strategy=SandboxStrategy.SUBPROCESS,
    timeout_seconds=30.0,
    max_memory_mb=256,
    allowed_env_vars=["PATH", "HOME"],
    capture_output=True,
)
```

| Field | Type | Default |
|---|---|---|
| `strategy` | `SandboxStrategy` | `SandboxStrategy.NONE` |
| `timeout_seconds` | `float` | `30.0` |
| `max_memory_mb` | `int \| None` | `None` (unlimited) |
| `allowed_env_vars` | `list[str]` | `[]` (inherit all) |
| `capture_output` | `bool` | `True` |

### `SubprocessSandbox`

```python
from enforcecore import SubprocessSandbox

sandbox = SubprocessSandbox(config)

# Synchronous execution
result = sandbox.run(my_tool, *args, tool_name="my_tool", **kwargs)

# Asynchronous execution
result = await sandbox.run_async(my_tool, *args, tool_name="my_tool", **kwargs)
```

```python
def __init__(self, config: SandboxConfig) -> None

def run(
    self,
    func: Callable[..., Any],
    *args: Any,
    tool_name: str = "",
    policy_name: str = "",
    **kwargs: Any,
) -> Any

async def run_async(
    self,
    func: Callable[..., Any],
    *args: Any,
    tool_name: str = "",
    policy_name: str = "",
    **kwargs: Any,
) -> Any
```

**Notes:** Function and all args/kwargs must be picklable for `SUBPROCESS`
strategy. POSIX resource limits (`RLIMIT_AS` for memory, `RLIMIT_CPU` for CPU)
are applied on Linux/macOS. Windows: process isolation only.

### Sandbox Exceptions

```python
from enforcecore import SandboxTimeoutError, SandboxMemoryError, SandboxViolationError

# SandboxTimeoutError   — subprocess exceeded timeout_seconds
# SandboxMemoryError    — subprocess exceeded max_memory_mb
# SandboxViolationError — other sandbox failures (non-picklable result, etc.)
```

### `platform_info()`

```python
from enforcecore.sandbox.runner import platform_info

info = platform_info()
# Returns dict: {platform, subprocess_isolation, resource_limits,
#                memory_limits, cpu_time_limits, env_restriction,
#                wasm_sandbox, python_version}
```

---

## API Added in v1.4.0 — NER PII Detection + Sensitivity Labels

### `NERBackend`

```python
from enforcecore import NERBackend
# Requires: pip install enforcecore[ner]
# Requires: python -m spacy download en_core_web_lg

ner = NERBackend(threshold=0.8, language="en")
spans = ner.analyze("Call John at john@acme.com")
# -> [(9, 13, "person_name", 0.95), (17, 29, "email", 0.99)]
```

```python
def __init__(self, threshold: float = 0.8, language: str = "en") -> None
# Raises ImportError if presidio-analyzer not installed or spaCy model unavailable.

def analyze(
    self,
    text: str,
    categories: set[str] | None = None,
    *,
    threshold: float | None = None,
) -> list[tuple[int, int, str, float]]
# Returns [(start, end, category, score), ...] sorted by start position.
# categories=None -> all 17 supported entity types.

@property
def threshold(self) -> float

@property
def language(self) -> str
```

**Supported entity categories:** `email`, `phone`, `ssn`, `credit_card`,
`ip_address`, `person_name`, `passport`, `location`, `date_time`,
`national_id`, `medical_id`, `driver_license`, `iban`, `crypto_address`,
`bank_account`, `itin`, `us_tin`.

### `is_ner_available()`

```python
from enforcecore import is_ner_available

if is_ner_available():
    ner = NERBackend()
```

Returns `True` if `presidio-analyzer` is importable. Does not check the spaCy
model.

---

### `SensitivityLabel` (enum)

```python
from enforcecore import SensitivityLabel

SensitivityLabel.PUBLIC        # 0 — openly shareable
SensitivityLabel.INTERNAL      # 1 — company-internal only
SensitivityLabel.CONFIDENTIAL  # 2 — restricted to authorised roles
SensitivityLabel.RESTRICTED    # 3 — highest sensitivity, minimum distribution
```

Flow rule: data with a higher sensitivity level cannot flow to a tool with a
lower clearance level.

### `SensitivityEnforcer`

```python
from enforcecore import SensitivityEnforcer, SensitivityLabel

enforcer = SensitivityEnforcer(
    tool_clearance=SensitivityLabel.INTERNAL,
    field_labels={
        "body": SensitivityLabel.CONFIDENTIAL,
        "subject": SensitivityLabel.INTERNAL,
        "to": SensitivityLabel.PUBLIC,
    },
    default_field_sensitivity=SensitivityLabel.PUBLIC,
)

violations = enforcer.check_kwargs({"body": "...", "to": "..."})
enforcer.raise_if_violated(violations, tool_name="send_email")
```

```python
def __init__(
    self,
    tool_clearance: SensitivityLabel | str,
    field_labels: dict[str, SensitivityLabel | str] | None = None,
    *,
    default_field_sensitivity: SensitivityLabel | str = SensitivityLabel.PUBLIC,
) -> None

def check(self) -> list[SensitivityViolation]

def check_kwargs(
    self,
    kwargs: dict[str, Any],
    *,
    override_labels: dict[str, SensitivityLabel | str] | None = None,
) -> list[SensitivityViolation]

def raise_if_violated(
    self,
    violations: list[SensitivityViolation],
    *,
    tool_name: str = "",
    policy_name: str = "",
) -> None

@property
def tool_clearance(self) -> SensitivityLabel

@property
def field_labels(self) -> dict[str, SensitivityLabel]
```

String label aliases: `"low"` → `PUBLIC`, `"medium"` → `INTERNAL`,
`"high"` → `CONFIDENTIAL`, `"critical"` → `RESTRICTED`.

### `check_tool_schema_sensitivity()`

```python
from enforcecore import check_tool_schema_sensitivity, SensitivityLabel

tool_schema = {
    "name": "send_email",
    "clearance": "internal",
    "parameters": {
        "to":   {"type": "string", "sensitivity": "low"},
        "body": {"type": "string", "sensitivity": "high"},
    },
}
violations = check_tool_schema_sensitivity(tool_schema, SensitivityLabel.INTERNAL)
```

```python
def check_tool_schema_sensitivity(
    tool_schema: dict[str, Any],
    policy_clearance: SensitivityLabel | str,
) -> list[SensitivityViolation]
# Effective clearance = min(schema["clearance"], policy_clearance).
```

### `SensitivityViolation` (frozen dataclass)

```python
@dataclass(frozen=True)
class SensitivityViolation:
    field_name: str
    field_sensitivity: SensitivityLabel
    tool_clearance: SensitivityLabel
```

### `sensitivity_level()`

```python
from enforcecore import sensitivity_level, SensitivityLabel

level = sensitivity_level("confidential")
# -> SensitivityLabel.CONFIDENTIAL
```

Coerces a string (including aliases) to `SensitivityLabel`. Raises `ValueError`
on invalid input.

### `SensitivityLabelConfig`

YAML-based sensitivity configuration object. Loaded from policy YAML:

```yaml
sensitivity_labels:
  enabled: true
  default_clearance: internal
  enforce: true
  fallback: redact
```

---

## API Added in v1.5.0 — OpenTelemetry + Observability

### `EnforceCoreInstrumentor`

```python
from enforcecore import EnforceCoreInstrumentor
# Requires: pip install enforcecore[otel]

instrumentor = EnforceCoreInstrumentor()
instrumentor.instrument(
    tracer_provider=my_provider,  # optional; falls back to global OTel provider
    meter_provider=my_meter,      # optional
)
```

```python
def instrument(
    self,
    *,
    tracer_provider: Any = None,
    meter_provider: Any = None,
) -> None

def uninstrument(self) -> None

@property
def metrics(self) -> EnforceCoreMetrics

@property
def is_instrumented(self) -> bool
```

Every `@enforce()` call becomes an OTel span named `"enforcecore.<tool_name>"`
with attributes: `enforcecore.tool`, `enforcecore.policy`, `enforcecore.call_id`,
`enforcecore.decision`, `enforcecore.duration_ms`, `enforcecore.overhead_ms`,
`enforcecore.input_redactions`, `enforcecore.output_redactions`,
`enforcecore.violation_type`, `enforcecore.violation_reason`.

### `EnforceCorePrometheusExporter`

```python
from enforcecore import EnforceCorePrometheusExporter
# Requires: pip install enforcecore[prometheus]

exporter = EnforceCorePrometheusExporter()
exporter.instrument()
exporter.start_http_server(port=9090)
```

```python
def __init__(self, *, registry: Any = None) -> None
# registry: prometheus_client.CollectorRegistry or None (uses global registry).
# Operates in no-op mode if prometheus_client not installed — never raises on init.

def instrument(self) -> None
def uninstrument(self) -> None
def start_http_server(self, port: int = 9090, addr: str = "0.0.0.0") -> None

@property
def is_instrumented(self) -> bool

@property
def is_available(self) -> bool
```

**Metrics exposed:**

| Metric | Type | Labels |
|---|---|---|
| `enforcecore_calls_total` | Counter | `tool`, `decision` |
| `enforcecore_violations_total` | Counter | `tool`, `violation_type` |
| `enforcecore_redactions_total` | Counter | `tool`, `direction` |
| `enforcecore_overhead_seconds` | Histogram | `tool` |
| `enforcecore_latency_seconds` | Histogram | `tool` |

### `AuditLogExporter`

```python
from enforcecore.telemetry import AuditLogExporter

exporter = AuditLogExporter(
    sink=make_splunk_hec_sink("https://splunk.acme.com:8088", token="xxx"),
)
```

Exports every audit entry as structured JSON to configurable sinks: stdout,
file, Splunk HEC, Elastic Bulk API, or OTLP HTTP.

### Sink factory functions

```python
from enforcecore.telemetry import make_splunk_hec_sink, make_elastic_sink

splunk_sink = make_splunk_hec_sink(url, token, *, index=None, source=None)
elastic_sink = make_elastic_sink(url, index, *, api_key=None, username=None, password=None)
```

---

## API Added in v1.6.0 — Multi-Tenant + Policy Inheritance

### `MultiTenantEnforcer`

```python
from enforcecore import MultiTenantEnforcer

mt = MultiTenantEnforcer(default_policy="base_policy.yaml")
mt.register("team_a", "team_a_policy.yaml")
mt.register("team_b", "team_b_policy.yaml")
```

```python
def __init__(self, default_policy: Policy | str | Path | None = None) -> None

def register(self, tenant_id: str, policy: Policy | str | Path) -> None
# Raises ValueError if tenant_id is empty.

def unregister(self, tenant_id: str) -> None
# Raises KeyError if tenant not registered.

@property
def tenants(self) -> list[str]   # sorted

def get_enforcer(self, tenant_id: str) -> Enforcer
# Raises KeyError if not registered and no default policy.

def enforce_sync(
    self,
    tenant_id: str,
    func: Callable[..., T],
    /,
    *args: Any,
    tool_name: str | None = None,
    **kwargs: Any,
) -> T

async def enforce_async(
    self,
    tenant_id: str,
    func: Callable[..., Any],
    /,
    *args: Any,
    tool_name: str | None = None,
    **kwargs: Any,
) -> Any

def __len__(self) -> int
def __contains__(self, tenant_id: object) -> bool
```

**Policy inheritance** — use `extends:` in YAML:

```yaml
# agent_deployer.yaml
extends: team_dev.yaml
tools:
  allowed: [search, calculate, deploy_service]
  context:
    environment: [staging]
```

Child policies override parent fields. Circular `extends:` raises
`PolicyLoadError` at load time.

---

## API Added in v1.7.0 — Remote Policy Server

### `PolicyServerClient`

```python
from enforcecore import PolicyServerClient

client = PolicyServerClient(
    url="https://policy.acme.com/agents/chatbot-v2",
    token=os.environ["POLICY_SERVER_TOKEN"],
    cache_ttl=300,          # seconds; 0 disables caching
    verify_signature=True,  # HMAC-SHA256 verification
)
enforcer = Enforcer.from_server(client)

# Or directly:
enforcer = Enforcer.from_server(
    "https://policy.acme.com/agents/chatbot-v2",
    token=os.environ["POLICY_SERVER_TOKEN"],
    cache_ttl=300,
)
```

```python
def __init__(
    self,
    url: str,
    token: str,
    *,
    cache_ttl: int = 300,
    verify_signature: bool = True,
) -> None
# Raises ValueError if url/token empty or cache_ttl < 0.

def get_policy(self) -> Policy
# Returns cached policy if fresh (cache_ttl > 0 and not expired).
# On cache miss: fetches from server, verifies HMAC signature (if header present).
# Stale-on-error: returns cached policy if server unreachable and cache exists.
# Raises PolicyServerError if server unreachable and no cache.

def invalidate(self) -> None
# Forces re-fetch on next get_policy().

@property
def url(self) -> str

@property
def cache_ttl(self) -> int

@property
def policy_version(self) -> str | None  # from X-Policy-Version response header
```

**Security model:** pull-only (server never pushes); HMAC-SHA256 signature
verification via `X-Policy-Signature` header; policy version recorded in audit
trail for every enforcement decision.

### `PolicyServerError`

Raised when the policy server is unreachable and no cached policy is available.

---

## API Added in v1.8.0 — Compliance Reporting

### `ComplianceReporter`

```python
from enforcecore import ComplianceReporter, ComplianceFormat, CompliancePeriod

reporter = ComplianceReporter()
report = reporter.export(
    ComplianceFormat.EU_AI_ACT,
    CompliancePeriod.from_label("2026-Q4"),
)
```

```python
def export(
    self,
    format: ComplianceFormat,
    period: CompliancePeriod,
    *,
    organization: str = "",
) -> ComplianceReport

def export_json(self, ...) -> str
def export_html(self, ...) -> str
def send_webhook(self, url: str, ...) -> None
# Vanta / Drata webhook integration.
```

### `ComplianceFormat` (enum)

```python
ComplianceFormat.EU_AI_ACT  # EU AI Act Articles 9, 13, 14, 52
ComplianceFormat.SOC2       # SOC2 CC6, CC7, CC8, CC9
ComplianceFormat.GDPR       # GDPR Article 30 (records of processing)
```

### `CompliancePeriod`

```python
period = CompliancePeriod.from_label("2026-Q4")  # quarterly
period = CompliancePeriod.from_label("2026-H1")  # half-year
period = CompliancePeriod.from_label("2026")     # annual
```

### `ComplianceReport` (dataclass)

```python
@dataclass
class ComplianceReport:
    title: str
    format: ComplianceFormat
    period: CompliancePeriod
    content: str           # rendered report body
    score: float           # 0.0 – 1.0 compliance score
    narratives: list[str]  # human-readable compliance statements
    statistics: dict[str, Any]
    generated_at: datetime
```

### `ComplianceError`

Raised when compliance report generation fails (insufficient audit data,
invalid period, or unsupported format).

### CLI

```bash
enforcecore audit export --format eu-ai-act --period 2026-Q4 --output report.json
enforcecore audit export --format soc2 --period 2026-H1 --output soc2.html
```

---

## API Added in v1.9.0 — Plugin Ecosystem

### `GuardPlugin` (abstract base class)

```python
from enforcecore import GuardPlugin, GuardResult

class MyGuard(GuardPlugin):

    @property
    def name(self) -> str:
        return "my-guard"

    @property
    def version(self) -> str:
        return "1.0.0"

    def check(
        self,
        tool_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> GuardResult:
        if tool_name == "dangerous_tool":
            return GuardResult(allowed=False, reason="blocked by policy")
        return GuardResult(allowed=True)
```

Register in `pyproject.toml`:

```toml
[project.entry-points."enforcecore.guards"]
my-guard = "my_package.guards:MyGuard"
```

### `RedactorPlugin` (abstract base class)

```python
from enforcecore import RedactorPlugin, RedactResult

class MyRedactor(RedactorPlugin):

    @property
    def name(self) -> str:
        return "my-redactor"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def categories(self) -> list[str]:
        return ["internal_id"]

    def redact(self, text: str) -> RedactResult:
        cleaned, count = _scrub_internal_ids(text)
        return RedactResult(text=cleaned, count=count)
```

Register under entry-point group `"enforcecore.redactors"`.

### `AuditBackendPlugin` (abstract base class)

```python
from enforcecore import AuditBackendPlugin

class MyBackend(AuditBackendPlugin):

    @property
    def name(self) -> str:
        return "my-backend"

    @property
    def version(self) -> str:
        return "1.0.0"

    def record(self, entry: dict[str, Any]) -> None:
        # entry matches AuditEntry.to_dict() schema
        my_db.insert(entry)

    def flush(self) -> None:
        my_db.flush()
```

Register under entry-point group `"enforcecore.audit_backends"`.

### Result types

```python
@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    reason: str = ""

@dataclass(frozen=True)
class RedactResult:
    text: str
    count: int = 0

@dataclass(frozen=True)
class PluginInfo:
    name: str
    version: str
    kind: str         # "guard" | "redactor" | "audit_backend"
    package: str = ""
    description: str = ""
```

### `PluginManager`

```python
from enforcecore import PluginManager

manager = PluginManager()

# Discover without loading (metadata only):
infos = manager.discover()

# Load all installed plugins:
count = manager.load_all(ignore_errors=False)
# Raises PluginLoadError if any plugin fails and ignore_errors=False.

# Load a single plugin by name:
manager.load("my-guard")

# Access loaded plugins:
manager.guards          # list[GuardPlugin]
manager.redactors       # list[RedactorPlugin]
manager.audit_backends  # list[AuditBackendPlugin]
```

```python
def discover(self) -> list[PluginInfo]
def load_all(self, *, ignore_errors: bool = False) -> int
def load(self, name: str) -> None
# Raises PluginLoadError if name not found or instantiation fails.

@property
def guards(self) -> list[GuardPlugin]

@property
def redactors(self) -> list[RedactorPlugin]

@property
def audit_backends(self) -> list[AuditBackendPlugin]
```

### `PluginLoadError`

```python
from enforcecore import PluginLoadError
```

Raised when a plugin fails to import, fails the subclass check, or raises
during instantiation.

### CLI

```bash
enforcecore plugin list           # Discover all installed plugins
enforcecore plugin info <name>    # Load and inspect a specific plugin
```


---

## API Added in v1.11.0 — AsyncIO Streaming Enforcement

### `stream_enforce()` — async context manager

```python
from enforcecore import stream_enforce, Policy
from collections.abc import AsyncGenerator

policy = Policy.from_file("policies/production.yaml")

async def run(llm_stream: AsyncGenerator[str, None]) -> None:
    result_holder: list[StreamEnforcementResult] = []
    async with stream_enforce(
        llm_stream,
        policy=policy,
        tool_name="chatbot_reply",
        redact=True,
        redaction_strategy="placeholder",   # placeholder | mask | hash | remove
        lookahead=64,                        # chars buffered for boundary detection
        result_out=result_holder,
    ) as safe:
        async for token in safe:
            print(token, end="", flush=True)

    result = result_holder[0]
    print(f"\nRedacted {result.total_redactions} PII entities in {result.stream_duration_ms:.1f}ms")
```

**Parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `source` | `AsyncGenerator[str, None]` | required | Upstream LLM token stream |
| `policy` | `Policy` | required | Policy to enforce |
| `tool_name` | `str` | `"stream"` | Identifier written to audit records |
| `redact` | `bool` | `True` | Enable PII redaction |
| `redaction_strategy` | `str` | `"placeholder"` | `placeholder`, `mask`, `hash`, or `remove` |
| `lookahead` | `int` | `64` | Lookahead window in chars for boundary-spanning PII |
| `on_violation` | `str \| None` | `None` | Override policy `on_violation`; `None` uses policy setting |
| `result_out` | `list[StreamEnforcementResult] \| None` | `None` | List to append the result to after the stream completes |

**Raises** `StreamingViolation` when `on_violation="block"` and a hard policy violation is detected.

---

### `StreamingRedactor` — stateful lookahead-window redactor

```python
from enforcecore import StreamingRedactor

sr = StreamingRedactor(strategy="placeholder", lookahead=64)

async for raw_token in llm_stream:
    safe_token, events = sr.push(raw_token)
    yield safe_token

remainder, events = sr.flush()  # flush buffered lookahead at stream end
yield remainder
```

**Constructor parameters**

| Name | Type | Default | Description |
|---|---|---|---|
| `strategy` | `str` | `"placeholder"` | Redaction strategy |
| `lookahead` | `int` | `64` | Lookahead window in chars (must be > 0) |
| `categories` | `set[str] \| None` | `None` | PII categories to scan; `None` = all |

**Methods**

| Method | Returns | Description |
|---|---|---|
| `push(token: str)` | `(str, list[StreamRedactionEvent])` | Emit the safe prefix; buffer the lookahead tail |
| `flush()` | `(str, list[StreamRedactionEvent])` | Emit all buffered chars; finalize stream |
| `reset()` | `None` | Clear buffer, counts, and events |

**Properties**: `.redaction_count: int`, `.events: list[StreamRedactionEvent]`, `._buffer: str`

---

### `StreamEnforcementResult` — stream session summary

```python
@dataclass
class StreamEnforcementResult:
    stream_id: str           # UUID
    policy_name: str
    tool_name: str
    decision: str            # "allowed" | "blocked"
    violation_reason: str | None
    tokens_total: int
    tokens_redacted: int
    total_redactions: int
    overhead_ms: float
    stream_duration_ms: float
    audit_entry_id: str | None
```

---

### `StreamAuditEntry` — per-stream audit record

Produced automatically by `stream_enforce()`.  Written to the same
Merkle-chained audit trail as standard `@enforce()` records.

```python
@dataclass
class StreamAuditEntry:
    entry_id: str            # UUID
    stream_id: str
    timestamp: str           # ISO-8601
    policy_name: str
    tool_name: str
    decision: str
    violation_reason: str | None
    tokens_emitted: int
    tokens_redacted: int
    total_redactions: int
    redaction_events: list[StreamRedactionEvent]
    overhead_ms: float
    stream_duration_ms: float
```

---

### `StreamingViolation` — block-mode streaming exception

```python
class StreamingViolation(Exception):
    reason: str
    stream_id: str
    result: StreamEnforcementResult
```

---

### Framework adapters (`enforcecore.streaming.adapters`)

#### LangChain

```python
from enforcecore.streaming.adapters import EnforceCoreStreamingCallback

callback = EnforceCoreStreamingCallback(policy=policy, redact=True)

# Wrap the LLM's token stream:
async for token in callback.on_llm_new_token_stream(llm_token_generator):
    print(token, end="")

result = callback.last_result  # StreamEnforcementResult
```

#### AutoGen

```python
from enforcecore.streaming.adapters import autogen_stream_enforce

async for token in autogen_stream_enforce(agent_stream, policy=policy):
    print(token, end="")
```

#### LangGraph

```python
from enforcecore.streaming.adapters import langgraph_stream_enforce

async with langgraph_stream_enforce(
    graph.astream(inputs),
    policy=policy,
    token_extractor=lambda e: e.get("content") if isinstance(e, dict) else None,
) as safe_events:
    async for event in safe_events:
        process(event)
```

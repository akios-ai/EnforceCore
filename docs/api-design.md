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

## Guard API

```python
from enforcecore.guard import Guard, ResourceLimits

# Standalone usage
guard = Guard(
    limits=ResourceLimits(
        max_call_duration_seconds=30,
        max_memory_mb=256,
    )
)

async with guard.protect() as ctx:
    result = await long_running_tool()
    # Automatically killed if exceeds 30s or 256MB

# Cost tracking
from enforcecore.guard import CostTracker

tracker = CostTracker(budget_usd=10.0)
tracker.record_cost(0.05)   # Record tool call cost
tracker.record_cost(0.10)
print(tracker.remaining)    # 9.85
print(tracker.can_afford(1.0))  # True
```

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

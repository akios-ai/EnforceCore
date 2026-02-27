# EnforceCore — Technical Architecture

## Design Philosophy

EnforceCore is designed around one core idea: **enforcement at the call boundary**.

Every time an agent system makes an external call — invoking a tool, hitting an API, reading a file, opening a network connection, spawning a process — that call passes through an enforcement point. At that point, policies are evaluated, data is redacted, resources are constrained, and an audit entry is recorded.

This is fundamentally different from:
- **Prompt-level guardrails** — which operate inside the LLM and can be bypassed
- **Output filters** — which operate after the damage is already done
- **Network firewalls** — which operate at the wrong granularity for agent tool calls

## High-Level Architecture

```mermaid
flowchart TB
    subgraph APP["Agent Application Layer"]
        direction LR
        A1["LangGraph"] ~~~ A2["CrewAI"] ~~~ A3["AutoGen"] ~~~ A4["Custom Agent"]
    end

    APP -->|"tool_call(args)"| API

    subgraph API["EnforceCore Public API"]
        DEC["@enforce(policy='my_policy.yaml')<br/>async def call_tool(args): ..."]
    end

    API --> ENF

    subgraph ENF["Enforcer (Coordinator)"]
        direction TB
        S1["1. Load & resolve policy"]
        S2["2. Run pre-call checks"]
        S3["3. Apply redaction to inputs"]
        S4["4. Set up resource constraints"]
        S5["5. Execute call inside sandbox"]
        S6["6. Apply redaction to outputs"]
        S7["7. Run post-call checks"]
        S8["8. Record audit entry"]
        S9["9. Return result or raise violation"]
        S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
    end

    ENF --> PE["Policy Engine"]
    ENF --> RD["Redactor"]
    ENF --> AU["Auditor (Merkle)"]
    ENF --> GU["Guard (Resource + Kill)"]

    style APP fill:#e3f2fd,stroke:#1565c0
    style API fill:#e8f5e9,stroke:#2e7d32
    style ENF fill:#fff3e0,stroke:#e65100
    style PE fill:#f3e5f5,stroke:#7b1fa2
    style RD fill:#f3e5f5,stroke:#7b1fa2
    style AU fill:#f3e5f5,stroke:#7b1fa2
    style GU fill:#f3e5f5,stroke:#7b1fa2
```

## Core Components

### Enforcement Data Flow

The following diagram shows the complete flow of an enforced tool call,
including threat boundaries:

```mermaid
sequenceDiagram
    participant Agent as Agent / Framework
    participant Enforcer as Enforcer
    participant Policy as Policy Engine
    participant Redactor as Redactor
    participant Guard as Guard
    participant Auditor as Auditor
    participant Tool as External Tool

    Agent->>Enforcer: tool_call(name, args)

    rect rgb(255, 235, 238)
        Note over Enforcer,Policy: Pre-call enforcement
        Enforcer->>Policy: evaluate_pre(name, args)
        Policy-->>Enforcer: PreCallResult(allow/deny)
        alt Denied
            Enforcer-->>Agent: raise ToolDeniedError
        end
    end

    rect rgb(232, 245, 233)
        Note over Enforcer,Redactor: Input redaction
        Enforcer->>Redactor: redact(args)
        Redactor-->>Enforcer: sanitized_args
    end

    rect rgb(227, 242, 253)
        Note over Enforcer,Guard: Resource setup
        Enforcer->>Guard: check_limits(cost, rate)
        Guard-->>Enforcer: ok / raise
    end

    Enforcer->>Tool: execute(sanitized_args)
    Tool-->>Enforcer: raw_result

    rect rgb(232, 245, 233)
        Note over Enforcer,Redactor: Output redaction
        Enforcer->>Redactor: redact(result)
        Redactor-->>Enforcer: sanitized_result
    end

    rect rgb(255, 243, 224)
        Note over Enforcer,Auditor: Audit recording
        Enforcer->>Auditor: record(entry)
        Auditor-->>Enforcer: merkle_hash
    end

    Enforcer-->>Agent: sanitized_result
```

### 1. Enforcer (Coordinator)

The central orchestrator. It intercepts external calls, coordinates all protection components, and makes the allow/block/redact decision.

**Responsibilities:**
- Provide the `@enforce()` decorator and `enforce()` async context manager
- Coordinate the execution pipeline (pre-call → execute → post-call)
- Handle both sync and async call patterns
- Aggregate decisions from all components
- Raise `EnforcementViolation` on policy breach

**Critical design decision — Async-first:**
Modern agent frameworks (LangGraph, AutoGen, etc.) are async-first. EnforceCore MUST support both sync and async from day one. The `Enforcer` internally runs async and provides sync wrappers.

```python
# Both patterns work
@enforce(policy="policy.yaml")
def sync_tool(args):
    ...

@enforce(policy="policy.yaml")
async def async_tool(args):
    ...
```

### 2. Policy Engine

Loads, validates, and evaluates declarative policies. Policies define what is allowed, denied, and how violations should be handled.

**Responsibilities:**
- Load policies from YAML files or Python objects
- Validate policies against a Pydantic schema
- Evaluate pre-call conditions (before execution)
- Evaluate post-call conditions (after execution)
- Support policy composition (inherit, override, merge)

**Policy structure (YAML):**
```yaml
name: "default-agent-policy"
version: "1.0"

rules:
  allowed_tools:
    - "web_search"
    - "read_file"
    - "calculator"

  denied_tools:
    - "execute_shell"
    - "send_email"

  pii_redaction:
    enabled: true
    categories:
      - email
      - phone
      - ssn
      - credit_card
      - ip_address
      - person_name

  resource_limits:
    max_call_duration_seconds: 30
    max_memory_mb: 256
    max_cost_usd: 1.00

  network:
    allowed_domains:
      - "api.openai.com"
      - "*.wikipedia.org"
    deny_all_other: true

  post_call:
    max_output_size_bytes: 1048576  # 1MB
    redact_output: true

on_violation: "block"  # block | log | redact
```

**Design note:** Policies are Pydantic models internally, giving us validation, serialization, and IDE autocompletion for free.

### 3. Redactor

Real-time PII and sensitive data redaction on both inputs and outputs of enforced calls.

**Responsibilities:**
- Detect PII in text (emails, phone numbers, SSNs, credit cards, IP addresses, names)
- Redact detected PII before the call (input protection)
- Redact detected PII in the response (output protection)
- Support configurable redaction strategies (mask, hash, remove, placeholder)
- Log redaction events for audit

**Implementation:**
Uses a pure regex-based detection engine with 5 compiled PII category patterns. Designed for zero external dependencies and sub-millisecond overhead.

**Performance (benchmarked):**
Regex-based redaction is extremely fast:
- Policy evaluation: ~0.01ms
- PII redaction (short input): ~0.028ms
- PII redaction (~2KB input): ~0.129ms
- Audit entry creation: ~0.01ms
- Full E2E overhead: ~0.056ms

**Total realistic overhead: < 1ms** — negligible compared to typical tool call latency (100ms-10s).

### 4. Auditor (Merkle)

Produces tamper-proof, cryptographically verifiable audit trails for every enforced call.

**Responsibilities:**
- Generate a signed audit entry for every enforced call (inputs, outputs, policy, decision, timing)
- Chain entries using a Merkle tree (each entry includes the hash of the previous)
- Support verification (prove no entries were modified or deleted)
- Write to JSONL files (v1.0) with pluggable storage backends later

**Audit entry structure:**
```json
{
  "id": "uuid-v4",
  "timestamp": "2026-02-20T10:30:00Z",
  "call": {
    "tool": "web_search",
    "args_hash": "sha256:abc...",
    "result_hash": "sha256:def..."
  },
  "policy": {
    "name": "default-agent-policy",
    "version": "1.0",
    "decision": "allowed"
  },
  "redaction": {
    "input_redactions": 2,
    "output_redactions": 0
  },
  "timing": {
    "enforcement_overhead_ms": 12.3,
    "call_duration_ms": 450.1
  },
  "merkle": {
    "entry_hash": "sha256:ghi...",
    "previous_hash": "sha256:jkl...",
    "tree_root": "sha256:mno..."
  }
}
```

### 5. Guard (Resource + KillSwitch)

Constrains the resources available to a tool call and provides hard termination on violations.

**Responsibilities:**
- Enforce time limits (call duration)
- Enforce memory limits
- Enforce cost limits (cumulative across calls)
- Hard kill on limit breach (signal-based termination)

**⚠️ Critical architecture decision — Cross-platform strategy:**

The original conversation proposed seccomp-bpf and cgroups v2 as core components. **This is problematic because these are Linux-only.**

Most researchers and developers work on macOS (and some on Windows). If the Guard component only works on Linux, adoption will be severely limited.

**Our approach for v1.0:**

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| Time limits | `signal.alarm` + thread timeout | `signal.alarm` + thread timeout | Thread timeout |
| Memory limits | cgroups v2 (if available) | `resource.setrlimit` | Process monitoring |
| CPU limits | cgroups v2 (if available) | `resource.setrlimit` | Process monitoring |
| Syscall filtering | seccomp-bpf (optional extra) | N/A (logged warning) | N/A (logged warning) |
| Process isolation | Optional (via subprocess) | Optional (via subprocess) | Optional (via subprocess) |

**Design:** The Guard uses a `Platform` abstraction that auto-detects the OS and applies the strongest available constraints. On Linux with root/cgroup access, you get the full hardened sandbox. On macOS, you get time/memory limits via POSIX signals. On any platform, you always get the Enforcer + Policy + Redactor + Auditor — the security-critical parts.

Advanced Linux hardening (seccomp, cgroups) is available as an optional `enforcecore[linux]` extra.

### 6. Integration Layer

Provides clean adapters for popular agent frameworks.

**Design:** The integration layer is NOT a hard dependency. It provides thin adapter patterns that translate framework-specific tool call mechanisms into EnforceCore's enforcement API.

**Supported in v1.0.x:**
- **Plain Python** — `@enforce()` decorator on any function
- **LangGraph** — Custom tool wrapper
- **CrewAI** — Tool decorator adapter
- **AutoGen** — Function registration wrapper

Each adapter is ~20-50 lines of code. The examples directory provides copy-paste-ready integration patterns.

## Module Dependency Graph

```mermaid
graph LR
    subgraph core["enforcecore/core/"]
        TYPES["types.py<br/><em>Shared types, exceptions</em>"]
        POLICY["policy.py<br/><em>Policy models + engine</em>"]
        CONFIG["config.py<br/><em>Global configuration</em>"]
        RULES["rules.py<br/><em>Rule evaluation</em>"]
        ENFORCER["enforcer.py<br/><em>Main coordinator</em>"]
    end

    subgraph redactor["enforcecore/redactor/"]
        REDACT_ENG["engine.py<br/><em>PII detection + redaction</em>"]
        PATTERNS["patterns.py<br/><em>Regex patterns</em>"]
        SECRETS["secrets.py<br/><em>Secret scanning</em>"]
        UNICODE["unicode.py<br/><em>Unicode normalization</em>"]
    end

    subgraph auditor["enforcecore/auditor/"]
        MERKLE["merkle.py<br/><em>Merkle tree</em>"]
        LOGGER["logger.py<br/><em>Audit log writer</em>"]
        BACKENDS["backends.py<br/><em>Storage backends</em>"]
        ROTATION["rotation.py<br/><em>Log rotation</em>"]
    end

    subgraph guard["enforcecore/guard/"]
        GUARD_ENG["engine.py<br/><em>Resource limits</em>"]
        NETWORK["network.py<br/><em>Domain enforcement</em>"]
        RATELIMIT["ratelimit.py<br/><em>Rate limiting</em>"]
    end

    subgraph plugins["enforcecore/plugins/"]
        HOOKS["hooks.py<br/><em>Lifecycle hooks</em>"]
        WEBHOOKS["webhooks.py<br/><em>Webhook dispatch</em>"]
    end

    subgraph telemetry["enforcecore/telemetry/"]
        INSTRUMENTOR["instrumentor.py<br/><em>OpenTelemetry</em>"]
        METRICS["metrics.py<br/><em>Metrics recording</em>"]
    end

    ENFORCER --> POLICY
    ENFORCER --> REDACT_ENG
    ENFORCER --> MERKLE
    ENFORCER --> GUARD_ENG
    ENFORCER --> RULES
    ENFORCER --> HOOKS
    POLICY --> TYPES
    RULES --> TYPES
    CONFIG -.-> TYPES
    REDACT_ENG --> PATTERNS
    REDACT_ENG --> SECRETS
    REDACT_ENG --> UNICODE
    LOGGER --> MERKLE
    LOGGER --> BACKENDS
    LOGGER --> ROTATION
    INSTRUMENTOR --> METRICS

    style core fill:#e3f2fd,stroke:#1565c0
    style redactor fill:#e8f5e9,stroke:#2e7d32
    style auditor fill:#fff3e0,stroke:#e65100
    style guard fill:#fce4ec,stroke:#c62828
    style plugins fill:#f3e5f5,stroke:#7b1fa2
    style telemetry fill:#e0f2f1,stroke:#00695c
```

## Error Handling Strategy

EnforceCore uses a clear exception hierarchy:

```mermaid
classDiagram
    class EnforceCoreError {
        <<base>>
    }
    class PolicyError
    class PolicyLoadError
    class PolicyValidationError
    class PolicyEvaluationError
    class EnforcementViolation
    class ToolDeniedError
    class DomainDeniedError
    class CostLimitError
    class ResourceLimitError
    class ContentViolationError
    class RedactionError
    class AuditError
    class GuardError

    EnforceCoreError <|-- PolicyError
    EnforceCoreError <|-- EnforcementViolation
    EnforceCoreError <|-- RedactionError
    EnforceCoreError <|-- AuditError
    EnforceCoreError <|-- GuardError
    PolicyError <|-- PolicyLoadError
    PolicyError <|-- PolicyValidationError
    PolicyError <|-- PolicyEvaluationError
    EnforcementViolation <|-- ToolDeniedError
    EnforcementViolation <|-- DomainDeniedError
    EnforcementViolation <|-- CostLimitError
    EnforcementViolation <|-- ResourceLimitError
    EnforcementViolation <|-- ContentViolationError
```

**Key principle:** Enforcement failures should **always fail closed** (block the call), never fail open (let it through). If the Policy Engine crashes, the call is blocked. If the Redactor fails, the call is blocked. Safety by default.

## Thread Safety & Concurrency

- The `PolicyEngine` is thread-safe (policies are immutable after loading)
- The `Enforcer` supports concurrent async calls (no shared mutable state per call)
- The `Auditor` uses a thread-safe append-only log with file locking
- The `Guard` resource tracking is per-call, not global (except cumulative cost, which uses an atomic counter)

## Performance Targets (Benchmarked)

| Component | Measured | Notes |
|---|---|---|
| Policy evaluation | < 0.1ms | Pydantic model validation + rule matching |
| PII redaction (short input) | ~0.028ms | Compiled regex patterns |
| PII redaction (~2KB input) | ~0.129ms | Scales linearly with input length |
| Audit entry creation | < 0.1ms | SHA-256 hash + JSONL append |
| **Full E2E overhead** | **~0.056ms** | **Negligible vs tool call latency (100ms-10s)** |

Benchmarks are published with every release. See the README for current numbers.

## Threat Boundary Model

```mermaid
graph TB
    subgraph UNTRUSTED["🔴 Untrusted Zone"]
        LLM["LLM Output<br/>(stochastic, injectable)"]
        USER["User Input<br/>(prompt injection)"]
        TOOL_OUT["Tool Responses<br/>(external, uncontrolled)"]
    end

    subgraph BOUNDARY["🟡 Enforcement Boundary — EnforceCore"]
        direction TB
        POLICY_CHECK["Policy Engine<br/>Allow / Deny"]
        REDACT_IN["Input Redaction<br/>PII removal"]
        REDACT_OUT["Output Redaction<br/>PII removal"]
        GUARD_CHECK["Guard<br/>Cost / Rate / Resource"]
        AUDIT["Audit Trail<br/>Merkle chain"]
    end

    subgraph TRUSTED["🟢 Trusted Zone"]
        TOOLS["Authorized Tools"]
        DB["Databases"]
        APIS["External APIs<br/>(allow-listed domains)"]
    end

    LLM -->|"tool_call"| POLICY_CHECK
    USER -->|"args"| REDACT_IN
    POLICY_CHECK --> GUARD_CHECK
    REDACT_IN --> GUARD_CHECK
    GUARD_CHECK --> TOOLS
    TOOLS --> REDACT_OUT
    TOOL_OUT --> REDACT_OUT
    REDACT_OUT --> AUDIT
    AUDIT -->|"sanitized result"| LLM
    TOOLS --> DB
    TOOLS --> APIS

    style UNTRUSTED fill:#ffebee,stroke:#c62828
    style BOUNDARY fill:#fff8e1,stroke:#f57f17
    style TRUSTED fill:#e8f5e9,stroke:#2e7d32
```

---

## Security-Layer Context

EnforceCore operates at the **application semantic layer** — it understands
tool calls, PII, cost budgets, and content rules. It does not replace
kernel-level MAC (SELinux, AppArmor), syscall filtering (seccomp), or
container isolation (Docker, gVisor). These are complementary layers in a
defense-in-depth stack.

```mermaid
graph TB
    subgraph "Defense-in-Depth Stack"
        HW["🔒 Hardware — TPM · SGX"]
        OS["🐧 OS/Kernel — SELinux · AppArmor · seccomp"]
        CT["📦 Container — Docker · gVisor · Firecracker"]
        RT["⚙️ Runtime — EnforceCore"]
        PR["💬 Prompt — NeMo Guardrails · LlamaGuard"]
    end

    HW --> OS --> CT --> RT --> PR

    style RT fill:#2d7d46,stroke:#1a5c30,color:#fff
```

**Scope boundary:** EnforceCore enforces at the Python runtime boundary.
It does not replace kernel-level MAC or container sandboxing. For production
deployments, use EnforceCore inside a hardened container with OS-level
enforcement enabled.

| Layer | Catches | Cannot Catch |
|---|---|---|
| OS/Kernel | Unauthorized syscalls, file access | Agent-level tool abuse, PII |
| Container | Process escape, resource exhaustion | Tool-call semantics |
| **EnforceCore** | **Tool abuse, PII, cost, rate limits** | **Kernel exploits, container escape** |
| Prompt | Injection, toxic output | Agent actions after LLM output |

See [Defense-in-Depth Architecture](defense-in-depth.md) for full deployment
guidance and [Tool Selection Guide](security/tool-selection.md) for when to
use each layer.


---

## Architecture Evolution: v1.2 – v1.9

EnforceCore has grown substantially since v1.0. The four core components
(Policy Engine, Redactor, Auditor, Guard) are unchanged and remain the
critical enforcement path. Eight new subsystems were added across v1.2–v1.9,
all optional and composable.

### Complete Component Map (v1.9)

```mermaid
flowchart TB
    subgraph APP["Agent Application Layer"]
        A1["LangGraph"] ~~~ A2["CrewAI"] ~~~ A3["AutoGen"] ~~~ A4["Custom"]
    end

    APP -->|tool_call| MT

    subgraph MT["Multi-Tenant Router (v1.6)"]
        MT1["tenant_id → Enforcer"]
    end

    MT --> API

    subgraph API["EnforceCore Public API"]
        DEC["@enforce / enforce()"]
    end

    API --> RPS
    RPS["Remote Policy Client (v1.7)
HTTPS pull + HMAC verify + cache"] --> ENF

    subgraph ENF["Enforcer — Enforcement Pipeline"]
        direction TB
        S1["1. Load policy"] --> S2["2. Pre-call checks"]
        S2 --> S3["3. Redact inputs"]
        S3 --> S4["4. Resource limits"]
        S4 --> S5["5. Execute / Sandbox"]
        S5 --> S6["6. Redact outputs"]
        S6 --> S7["7. Post-call checks"]
        S7 --> S8["8. Record audit"]
        S8 --> S9["9. Return result"]
    end

    ENF --> PE["Policy Engine
YAML + Pydantic + rules"]
    ENF --> RD["Redactor
Regex + NER (v1.4)"]
    ENF --> AU["Auditor
Merkle chain"]
    ENF --> GU["Guard
Rate + Cost + Kill"]
    ENF --> SB["Subprocess Sandbox (v1.3)
timeout + memory + isolation"]
    ENF --> SL["Sensitivity Labels (v1.4)
data flow classification"]

    AU --> AS["AuditStore (v1.2)
JSONL · SQLite · PostgreSQL"]
    AS --> CR["Compliance Reporter (v1.8)
EU AI Act · SOC2 · GDPR"]

    ENF --> TL["Telemetry (v1.5)
OTel spans · Prometheus metrics"]
    ENF --> PM["Plugin Manager (v1.9)
guards · redactors · backends"]

    style APP fill:#e3f2fd,stroke:#1565c0
    style MT fill:#e0f7fa,stroke:#006064
    style RPS fill:#e0f7fa,stroke:#006064
    style ENF fill:#fff3e0,stroke:#e65100
    style PE fill:#f3e5f5,stroke:#7b1fa2
    style RD fill:#f3e5f5,stroke:#7b1fa2
    style AU fill:#f3e5f5,stroke:#7b1fa2
    style GU fill:#f3e5f5,stroke:#7b1fa2
    style SB fill:#fce4ec,stroke:#c62828
    style SL fill:#fce4ec,stroke:#c62828
    style AS fill:#e8f5e9,stroke:#2e7d32
    style CR fill:#e8f5e9,stroke:#2e7d32
    style TL fill:#e0f2f1,stroke:#00695c
    style PM fill:#fff8e1,stroke:#f57f17
```

### Updated Module Dependency Graph

```mermaid
graph LR
    subgraph core["enforcecore/core/"]
        TYPES["types.py"]
        POLICY["policy.py"]
        CONFIG["config.py"]
        RULES["rules.py"]
        ENFORCER["enforcer.py"]
        HARDENING["hardening.py"]
    end

    subgraph redactor["enforcecore/redactor/"]
        REDACT_ENG["engine.py"]
        PATTERNS["patterns.py"]
        SECRETS["secrets.py"]
        UNICODE["unicode.py"]
    end

    subgraph auditor["enforcecore/auditor/"]
        MERKLE["merkle.py"]
        LOGGER["logger.py"]
        BACKENDS_OLD["backends.py"]
        ROTATION["rotation.py"]
    end

    subgraph auditstore["enforcecore/auditstore/ (v1.2)"]
        AS_STORE["store.py"]
        AS_ENTRY["entry.py"]
        AS_SQLITE["backends/sqlite.py"]
        AS_JSONL["backends/jsonl.py"]
        AS_PG["backends/postgresql.py"]
        AS_QUERIES["queries/eu_ai_act.py"]
        AS_REPORTS["reports/generator.py"]
    end

    subgraph sandbox["enforcecore/sandbox/ (v1.3)"]
        SB_RUNNER["runner.py"]
        SB_CONFIG["config.py"]
    end

    subgraph guard["enforcecore/guard/"]
        GUARD_ENG["engine.py"]
        NETWORK["network.py"]
        RATELIMIT["ratelimit.py"]
        NER["ner.py (v1.4)"]
        SENSITIVITY["sensitivity.py (v1.4)"]
    end

    subgraph plugins["enforcecore/plugins/"]
        HOOKS["hooks.py"]
        WEBHOOKS["webhooks.py"]
        PLUGIN_MGR["manager.py (v1.9)"]
        PLUGIN_BASE["base.py (v1.9)"]
    end

    subgraph telemetry["enforcecore/telemetry/"]
        INSTRUMENTOR["instrumentor.py"]
        METRICS["metrics.py"]
        PROMETHEUS["prometheus.py (v1.5)"]
        SINKS["sinks.py (v1.5)"]
    end

    subgraph integrations["enforcecore/integrations/"]
        INT_BASE["_base.py"]
        INT_LG["langgraph.py"]
        INT_CA["crewai.py"]
        INT_AG["autogen.py"]
        POLICY_CLIENT["policy_server.py (v1.7)"]
    end

    ENFORCER --> POLICY
    ENFORCER --> REDACT_ENG
    ENFORCER --> MERKLE
    ENFORCER --> GUARD_ENG
    ENFORCER --> RULES
    ENFORCER --> HOOKS
    ENFORCER --> SB_RUNNER
    ENFORCER --> SENSITIVITY
    ENFORCER --> PLUGIN_MGR
    LOGGER --> MERKLE
    LOGGER --> BACKENDS_OLD
    LOGGER --> ROTATION
    REDACT_ENG --> PATTERNS
    REDACT_ENG --> SECRETS
    REDACT_ENG --> UNICODE
    REDACT_ENG --> NER
    AS_STORE --> AS_ENTRY
    AS_STORE --> AS_SQLITE
    AS_STORE --> AS_JSONL
    AS_STORE --> AS_PG
    AS_REPORTS --> AS_QUERIES
    AS_QUERIES --> AS_STORE
    SB_RUNNER --> SB_CONFIG
    INSTRUMENTOR --> METRICS
    INSTRUMENTOR --> PROMETHEUS
    INSTRUMENTOR --> SINKS
    POLICY_CLIENT --> POLICY
    PLUGIN_MGR --> PLUGIN_BASE

    style core fill:#e3f2fd,stroke:#1565c0
    style redactor fill:#e8f5e9,stroke:#2e7d32
    style auditor fill:#fff3e0,stroke:#e65100
    style auditstore fill:#e8f5e9,stroke:#1b5e20
    style sandbox fill:#fce4ec,stroke:#c62828
    style guard fill:#fce4ec,stroke:#880e4f
    style plugins fill:#f3e5f5,stroke:#7b1fa2
    style telemetry fill:#e0f2f1,stroke:#00695c
    style integrations fill:#e0f7fa,stroke:#006064
```

---

### New Subsystem Descriptions

#### v1.2 — AuditStore

A structured, queryable audit storage layer sitting above the existing Merkle
Auditor. While the Auditor writes append-only JSONL, the AuditStore provides
SQL-level queries, chain integrity verification on read, and multiple backend
options.

```
Auditor (Merkle chain write) → AuditStoreBackendAdapter → AuditBackend
                                                               ↓
                                                    JSONLBackend / SQLiteBackend
                                                          / PostgreSQLBackend
```

**Key invariant:** Every write goes through the Merkle chain regardless of
storage backend. `verify_chain()` can always be called after any sequence of
reads to prove no entries were tampered with.

---

#### v1.3 — Subprocess Sandbox

Provides POSIX-level resource isolation for tool execution: memory caps
(`RLIMIT_AS`), CPU time limits (`RLIMIT_CPU`), and environment variable
stripping. All enforcement still happens at the Python call boundary — the
subprocess sandbox is a defence-in-depth layer on top.

```
Enforcer.execute()
  → SubprocessSandbox.run(func, *args)
      → multiprocessing.Process (isolated child)
          → resource limits applied
          → func(*args) executes
          → result pickled back to parent
```

**Platform matrix:** Full limits on Linux and macOS. Process isolation only
on Windows.

---

#### v1.4 — NER PII Detection + Sensitivity Labels

Two independent v1.4 features:

**NER PII Detection** (`enforcecore[ner]`): Presidio + spaCy neural entity
recognition as an alternative to regex-only detection. Higher recall for
names, locations, and languages without Latin character dominance. Configured
via `pii_redaction.backend: "ner"` in policy YAML.

**Sensitivity Labels**: A compile-time data-flow classification system.
Tools declare their clearance level; input kwargs declare their sensitivity.
Violations are caught before execution, before any redaction is attempted.
This is inspired by Bell-LaPadula mandatory access control but operates at
the Python argument level.

```
SensitivityEnforcer.check_kwargs({"body": "...", "to": "..."})
  → field "body" has CONFIDENTIAL sensitivity
  → tool has INTERNAL clearance
  → CONFIDENTIAL > INTERNAL → SensitivityViolation raised
```

---

#### v1.5 — OpenTelemetry + Observability

Every `@enforce()` call is automatically instrumented as an OTel span.
Prometheus metrics are exported on a configurable HTTP endpoint.

```
@enforce()
async def my_tool(...):      # ← span begins: "enforcecore.my_tool"
    ...                      # ← span attributes set: decision, overhead_ms, redactions
                             # ← span ends; counters incremented
```

No code changes required: install `enforcecore[otel]` and call
`EnforceCoreInstrumentor().instrument()` at startup.

---

#### v1.6 — Multi-Tenant + Policy Inheritance

`MultiTenantEnforcer` maps tenant IDs to independent `Enforcer` instances,
each with its own policy. Policy inheritance (`extends:` in YAML) allows
child policies to override only the fields they need.

```
MultiTenantEnforcer
  ├── "default" → Enforcer(base_policy.yaml)
  ├── "team_a"  → Enforcer(team_a.yaml extends base_policy.yaml)
  └── "team_b"  → Enforcer(team_b.yaml extends base_policy.yaml)
```

Inheritance is resolved at load time (depth-first, cycle-detected). The
resolved policy is a flat `Policy` object — no runtime inheritance overhead.

---

#### v1.7 — Remote Policy Server

`PolicyServerClient` implements a pull-only remote policy distribution
model. Policies are fetched over HTTPS, verified by HMAC-SHA256 signature,
and cached locally with a configurable TTL.

```
PolicyServerClient.get_policy()
  → cache hit?  → return cached Policy
  → cache miss  → GET /policy endpoint
                  → verify X-Policy-Signature header (if present)
                  → parse + validate Policy
                  → cache for cache_ttl seconds
                  → return Policy

  → server down + cache stale → raise PolicyServerError
  → server down + cache valid → return stale-but-valid Policy (fail-safe)
```

**Security design:** Server can only serve policies; it cannot push or
execute. The policy version is embedded in every audit entry.

---

#### v1.8 — Compliance Reporting

`ComplianceReporter` queries the AuditStore and generates structured
compliance reports. EU AI Act mapping:

| EU AI Act Article | AuditStore Query |
|---|---|
| Article 9 — Risk management | High-risk decisions (blocked tool calls) |
| Article 13 — Transparency | Human oversight evidence (blocked calls with reasons) |
| Article 14 — Human oversight | PII redaction statistics |
| Article 52 — Transparency for GPAI | Full audit trail + Merkle chain proof |

Reports render to HTML or JSON and include a `score` (0.0–1.0) and a list
of human-readable `narratives` for regulatory submission.

---

#### v1.9 — Plugin Ecosystem

Three plugin types, each loaded from Python package entry points
(`enforcecore.guards`, `enforcecore.redactors`, `enforcecore.audit_backends`):

| Type | ABC | Loaded by |
|---|---|---|
| `GuardPlugin` | `check(tool, args, kwargs) → GuardResult` | Enforcer pre-call |
| `RedactorPlugin` | `redact(text) → RedactResult` | Redactor pipeline |
| `AuditBackendPlugin` | `record(entry_dict)` | AuditStore write path |

Plugins are discovered at import time (`PluginManager.discover()`) and
loaded explicitly (`PluginManager.load_all()`). Failed plugin loads raise
`PluginLoadError` unless `ignore_errors=True`.

---

### Error Hierarchy (Updated v1.9)

```mermaid
classDiagram
    class EnforceCoreError {
        <<base>>
    }
    class PolicyError
    class PolicyLoadError
    class PolicyValidationError
    class PolicyEvaluationError
    class PolicyServerError
    class EnforcementViolation
    class ToolDeniedError
    class DomainDeniedError
    class CostLimitError
    class ResourceLimitError
    class ContentViolationError
    class SensitivityViolation
    class RedactionError
    class AuditError
    class GuardError
    class SandboxTimeoutError
    class SandboxMemoryError
    class SandboxViolationError
    class PluginLoadError
    class ComplianceError

    EnforceCoreError <|-- PolicyError
    EnforceCoreError <|-- EnforcementViolation
    EnforceCoreError <|-- RedactionError
    EnforceCoreError <|-- AuditError
    EnforceCoreError <|-- GuardError
    EnforceCoreError <|-- PluginLoadError
    EnforceCoreError <|-- ComplianceError
    PolicyError <|-- PolicyLoadError
    PolicyError <|-- PolicyValidationError
    PolicyError <|-- PolicyEvaluationError
    PolicyError <|-- PolicyServerError
    EnforcementViolation <|-- ToolDeniedError
    EnforcementViolation <|-- DomainDeniedError
    EnforcementViolation <|-- CostLimitError
    EnforcementViolation <|-- ResourceLimitError
    EnforcementViolation <|-- ContentViolationError
    EnforcementViolation <|-- SensitivityViolation
    GuardError <|-- SandboxTimeoutError
    GuardError <|-- SandboxMemoryError
    GuardError <|-- SandboxViolationError
```

---

## v1.11.0 — Streaming Subsystem

### Design Invariants

1. **Zero full-response buffering** — Memory usage is O(lookahead), not O(stream).
   Tokens are forwarded to the consumer as soon as they clear the lookahead window.
2. **Additive API** — `stream_enforce()` is a new Tier 1 symbol.  No existing API is changed.
3. **Policy-driven** — The same `Policy` objects used by `@enforce()` drive streaming enforcement.
4. **Audit parity** — One `StreamAuditEntry` per stream is written to the Merkle-chained audit
   trail, keeping the tamper-evident chain intact.

### Component Diagram

```mermaid
flowchart TB
    SRC["AsyncGenerator[str, None]\n(LLM token stream)"]

    subgraph SE["stream_enforce() context manager"]
        SR["StreamingRedactor\n(lookahead window)"]
        AC["audit / result accumulation"]
        EG["_enforced_gen()\nasync generator"]
    end

    CONSUMER["Consumer\nasync for token in safe: ..."]
    AUDIT["AuditStore\n(Merkle chain)"]
    RESULT["StreamEnforcementResult\n(result_out list)"]

    SRC -->|"raw tokens"| EG
    EG -->|"push(token)"| SR
    SR -->|"(safe_chunk, events)"| AC
    AC -->|"safe tokens"| CONSUMER
    EG -->|"flush() on exit"| SR
    AC -->|"StreamAuditEntry"| AUDIT
    AC -->|"result.append()"| RESULT
```

### Lookahead Algorithm (`StreamingRedactor._scan`)

```
buffer  = already-received chars
hold_back = lookahead  (during push)  OR  0  (during flush)

safe_prefix = buffer[:len(buffer) - hold_back]
              ↑ scan this for PII patterns

for each match in safe_prefix:
    replace match with redacted form
    record StreamRedactionEvent

emit safe_prefix (redacted)
buffer = buffer[len(safe_prefix):]  ← keep only the held-back tail
```

**Why hold back?**  An email `alice@example.com` may arrive as two tokens:
`"alice"` + `"@example.com"`.  Neither half alone matches the email regex.
By holding back the last `lookahead` chars (default 64), the next `push()`
will see `"alice@example.com"` as a contiguous string in `safe_prefix` and
redact it correctly.

### Adapter Layer

```
enforcecore.streaming.adapters
├── EnforceCoreStreamingCallback   LangChain BaseCallbackHandler thin wrapper
├── autogen_stream_enforce()       AutoGen: async generator → async generator
└── langgraph_stream_enforce()     LangGraph: @asynccontextmanager for graph.astream()
```

All adapters import framework code lazily — `import enforcecore` never fails
when LangChain/AutoGen/LangGraph is absent.


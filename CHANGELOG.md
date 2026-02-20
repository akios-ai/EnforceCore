# EnforceCore Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.5a1] — 2025-02-20

### Added

#### Evaluation Suite (`enforcecore.eval`)
- **13 adversarial scenarios** across 7 threat categories:
  - **Tool abuse** (3) — denied tool, not-in-allowed-list, rapid-fire 100× calls
  - **Data exfiltration** (2) — oversized output, PII leakage in output
  - **Resource exhaustion** (2) — timeout violation, cost budget exceeded
  - **Policy evasion** (2) — tool name spoofing, case-variant bypass
  - **PII leakage** (1) — PII in tool input arguments
  - **Privilege escalation** (1) — exhaustive denied-tools enumeration
  - **Prompt injection** (2) — injection payloads in args + tool names

- **Scenario runner** (`ScenarioRunner`)
  - `run_all()` — execute all or filtered scenarios against a policy
  - `run_quick()` — run HIGH + CRITICAL severity only
  - `run_scenario()` — execute a single scenario
  - `list_scenarios()` — filter by category, severity, or tags
  - `SuiteResult` with containment rate, per-category/severity breakdowns

- **Benchmark suite** (`BenchmarkRunner`)
  - 7 component benchmarks: policy pre-call, post-call, PII redaction,
    audit record, guard overhead, enforcer E2E, enforcer E2E with PII
  - Statistics: mean, median, P95, P99, min, max, ops/sec
  - `BenchmarkSuite` with platform info and timestamp

- **Report generator** (`generate_report`)
  - `generate_suite_report()` — Markdown with containment rates, emojis, tables
  - `generate_benchmark_report()` — Markdown with performance tables
  - `generate_report()` — combined evaluation + benchmark report

- **Type system** (`enforcecore.eval.types`)
  - `ThreatCategory` enum (7 categories)
  - `Severity` enum (4 levels)
  - `ScenarioOutcome` enum (CONTAINED, ESCAPED, ERROR, SKIPPED)
  - `Scenario`, `ScenarioResult`, `SuiteResult` dataclasses
  - `BenchmarkResult`, `BenchmarkSuite` dataclasses

#### New Public Exports
- 11 new exports: `BenchmarkResult`, `BenchmarkRunner`, `BenchmarkSuite`,
  `Scenario`, `ScenarioOutcome`, `ScenarioResult`, `ScenarioRunner`,
  `Severity`, `SuiteResult`, `ThreatCategory`, `generate_report`

#### Testing
- 97 new tests across 4 test files:
  - `test_types.py` — 30 tests (enums, dataclasses, aggregation, properties)
  - `test_scenarios.py` — 21 tests (registry, all 7 categories, metadata)
  - `test_runner.py` — 16 tests (runner, filters, containment rates)
  - `test_benchmarks.py` — 13 tests (measure helper, per-benchmark, full suite)
  - `test_report.py` — 17 tests (suite report, benchmark report, combined)
- Total: **431 tests, 96% coverage**

#### Examples & Documentation
- `examples/evaluation_suite.py` — complete demo of scenarios, benchmarks, reports
- `docs/evaluation.md` — comprehensive evaluation suite guide

### Changed
- Version bumped from `1.0.4a1` to `1.0.5a1`
- `enforcecore.__init__.py` updated with eval exports (51 total public exports)

## [1.0.4a1] — 2025-02-20

### Added

#### Framework Integration Adapters (`enforcecore.integrations`)
- **LangGraph / LangChain** adapter (`enforcecore.integrations.langgraph`)
  - `enforced_tool` — drop-in replacement for `@langchain.tools.tool` with policy enforcement
  - Creates `StructuredTool` instances with enforcement baked in
  - Supports sync and async functions, custom names, descriptions, `args_schema`, `return_direct`
  - Example: `@enforced_tool(policy="policy.yaml") def search(query: str) -> str: ...`

- **CrewAI** adapter (`enforcecore.integrations.crewai`)
  - `enforced_tool` — drop-in replacement for `@crewai.tools.tool` with policy enforcement
  - Wraps functions with enforcement before passing to CrewAI's tool system
  - Example: `@enforced_tool(policy="policy.yaml") def calculator(expr: str) -> str: ...`

- **AutoGen** adapter (`enforcecore.integrations.autogen`)
  - `enforced_tool` — creates AutoGen `FunctionTool` instances with policy enforcement
  - Targets AutoGen v0.4+ (`autogen-core`)
  - Supports custom descriptions (from argument, docstring, or function name)
  - Example: `@enforced_tool(policy="p.yaml", description="Search") async def search(q: str) -> str: ...`

#### Shared Adapter Utilities (`enforcecore.integrations._base`)
- `require_package(package, pip_name=...)` — verify optional deps with clear install messages
- `wrap_with_policy(func, policy=..., tool_name=...)` — wrap any callable with enforcement

#### All Adapters Share These Properties
- **No hard dependencies** — framework packages only imported at function call time
- **Import always succeeds** — importing the adapter module never fails
- **Consistent API** — `@enforced_tool(policy=...)` decorator pattern across all frameworks
- **Full enforcement** — policy checks, PII redaction, resource guards, cost tracking, audit trails
- **Sync + async** — both sync and async functions supported in all adapters

#### New Public Exports
- `wrap_with_policy`, `require_package` added to `enforcecore` top-level imports
- `enforcecore.integrations` package exports shared utilities

#### Testing
- 50 new tests across 4 test files:
  - `test_base.py` — 17 tests (require_package, wrap_with_policy sync/async, edge cases)
  - `test_langgraph.py` — 12 tests (tool creation, enforcement, async, metadata)
  - `test_crewai.py` — 9 tests (tool creation, enforcement, callable tools, policy filtering)
  - `test_autogen.py` — 12 tests (tool creation, enforcement, descriptions, async)
- Mock framework modules in conftest for CI testing without framework deps
- Total: 334 tests, 96% coverage

#### Examples & Documentation
- `examples/framework_integrations.py` — complete demo of all adapters + plain Python + utilities
- Integration guide with 5-minute onboarding for each framework

### Changed
- Version bumped from `1.0.3a1` to `1.0.4a1`
- `enforcecore.integrations.__init__.py` updated with adapter documentation and shared exports

### Fixed
- Removed unused `cryptography` dependency from core deps
- Commented out unbuilt CLI entry point in `pyproject.toml`

## [1.0.3a1] — 2025-02-20

### Added

#### Resource Guard (`enforcecore.guard`)
- `ResourceGuard` class — wraps function execution with time and memory limits
  - `execute_sync()` — sync execution with `concurrent.futures.ThreadPoolExecutor` timeout
  - `execute_async()` — async execution with `asyncio.wait_for` timeout
  - POSIX memory limits via `setrlimit` (Linux: `RLIMIT_AS`, macOS: `RLIMIT_RSS`)
  - `platform_info()` — returns dict of supported features per platform
- `CostTracker` class — thread-safe cumulative cost tracking
  - `record(cost)` — record a cost, returns new cumulative total
  - `check_budget()` — raises `CostLimitError` if budget exceeded
  - Supports both global budget (from `Settings`) and per-policy budget (from `ResourceLimits`)
  - Thread-safe via `threading.Lock`
  - `budget` property setter, `reset()` method
- `KillSwitch` class — coordinated hard termination on limit breach
  - `trip(reason)` — trip the switch, blocking all subsequent calls
  - `check()` — raises `ResourceLimitError` if tripped
  - `reset()` — re-enable calls after investigation
  - Thread-safe via `threading.Lock`
- `_MemoryLimiter` (internal) — best-effort POSIX memory limiting with apply/restore

#### Enforcer Pipeline Integration
- Guard wired into `enforce_sync()` and `enforce_async()` pipeline
- Pre-call cost budget check (global + per-policy)
- Time and memory limits applied during function execution
- `Enforcer.guard` property — access the `ResourceGuard` instance
- `Enforcer.record_cost(cost_usd)` — convenience method for cost tracking
- Guard violations (`ResourceLimitError`, `CostLimitError`) recorded in audit trail
- KillSwitch auto-trips on any resource limit breach

#### Platform Support
| Feature | Linux | macOS | Windows |
|---|---|---|---|
| Time limits | ✓ | ✓ | ✓ |
| Memory limits | ✓ | ~ (advisory) | ✗ |
| Cost tracking | ✓ | ✓ | ✓ |
| KillSwitch | ✓ | ✓ | ✓ |

#### New Public Exports
- `CostTracker`, `KillSwitch`, `ResourceGuard` added to `enforcecore` top-level imports

#### Testing
- 71 new tests (51 guard engine unit tests + 20 enforcer integration tests)
- Total: 284 tests, 96% coverage
- Thread-safety tests for CostTracker and KillSwitch
- Memory limiter tests with platform-aware assertions
- Timeout tests for both sync and async execution
- KillSwitch cascade tests (timeout → subsequent calls blocked)

#### Examples & Documentation
- `examples/resource_guard.py` — complete demo of all guard features
- New test fixtures: `time_limit.yaml`, `cost_limit.yaml`, `resource_limits.yaml`

## [1.0.2a1] — 2025-02-20

### Added

#### Merkle-Chained Audit Trail (`enforcecore.auditor`)
- `AuditEntry` dataclass — 14-field audit record with SHA-256 Merkle hash
  - Fields: entry_id, call_id, timestamp, tool_name, policy_name, policy_version, decision, violation_type, violation_reason, overhead_ms, call_duration_ms, input_redactions, output_redactions, previous_hash, entry_hash
  - `compute_hash()` — deterministic SHA-256 of canonical JSON (sorted keys, excludes entry_hash)
  - `seal()` — compute hash and set it on the entry, returns self for chaining
  - `to_dict()`, `from_dict()`, `to_json()` serialization methods
- `Auditor` class — thread-safe JSONL audit trail writer
  - Append-only JSONL file format
  - Automatic Merkle chain linking (each entry's `previous_hash` = prior entry's `entry_hash`)
  - Chain resumption from existing trail files (cross-session continuity)
  - `threading.Lock` for thread-safe concurrent writes
  - Parent directory auto-creation
- `verify_trail()` — full chain integrity verification
  - Recomputes every hash and checks chain linkage
  - Detects: modified entries, deleted entries, inserted entries, reordered entries
  - Returns `VerificationResult` with error details
- `VerificationResult` dataclass — verification outcome with `is_valid`, `chain_intact`, `root_hash`, `head_hash`, `errors` list, `entries_checked`, `error_count`
- `load_trail()` — load all entries from a JSONL file as `AuditEntry` objects

#### Enforcer Pipeline Integration
- Automatic audit recording in `enforce_sync()` and `enforce_async()`
- Both allowed and blocked calls generate audit entries
- Blocked entries include `violation_type` (exception class name) and `violation_reason`
- `_build_auditor()` creates Auditor from `settings.audit_path` when `settings.audit_enabled` is True
- Deferred import pattern to avoid circular dependency (`enforcer` ↔ `auditor` ↔ `types`)

#### New Public Exports
- `Auditor`, `AuditEntry`, `VerificationResult`, `verify_trail`, `load_trail` added to `enforcecore` top-level imports

#### Testing
- 52 new tests (32 auditor engine unit tests + 20 enforcer integration tests)
- Total: 213 tests, 96% coverage
- Autouse `_disable_audit_globally` fixture in conftest.py to prevent audit side effects in non-audit tests
- Tamper detection tests: modified, deleted, inserted, reordered entries
- Cross-session chain continuity tests

#### Examples & Documentation
- `examples/audit_trail.py` — 7 demo patterns (standalone auditor, entry anatomy, trail verification, tamper detection, enforcer pipeline, cross-session continuity, decorator)
- Updated `docs/api-design.md` — Auditor API section with field tables, usage examples, tamper detection docs
- Updated `docs/roadmap.md` — v1.0.2 marked as shipped with Definition of Done

### Changed
- Version bumped from `1.0.1a1` to `1.0.2a1`
- `Enforcer.__slots__` extended: `("_engine", "_redactor")` → `("_auditor", "_engine", "_redactor")`

### Design Decisions
- **JSONL over SQLite:** JSONL is append-only, human-readable, easily verifiable, and works with standard Unix tools. SQLite would add complexity and a binary format. JSONL can always be imported into a database later.
- **Deferred import pattern:** The auditor imports types from `enforcecore.core.types`, which re-exports from `enforcecore.core` (which imports `enforcer`). To break this cycle, the Auditor import in `enforcer.py` is deferred to runtime inside `_build_auditor()`, with a `TYPE_CHECKING`-only import for type annotations.

## [1.0.1a1] — 2025-02-20

### Added

#### PII Redactor (`enforcecore.redactor`)
- `Redactor` class — lightweight regex-based PII detection and redaction engine
- 5 PII categories: `email`, `phone`, `ssn`, `credit_card`, `ip_address`
- 4 redaction strategies: `placeholder` (`<EMAIL>`), `mask` (`****@****.***`), `hash` (`[SHA256:...]`), `remove`
- `DetectedEntity` frozen dataclass — represents a detected PII entity with position info
- `RedactionResult` dataclass — contains redacted text, entity list, event list, and convenience properties
- `detect()` method for PII detection without modification
- `redact()` method for full detection + replacement
- Overlap resolution — keeps the longer match when entities overlap
- Compiled regex patterns at import time for ~0.1–0.5ms performance

#### Enforcer Pipeline Integration
- Automatic pre-call input redaction (string args and kwargs)
- Automatic post-call output redaction (string return values)
- `_build_redactor()` creates Redactor from policy's `pii_redaction` config
- Redaction counts (`input_redactions`, `output_redactions`) included in structured log events
- Respects `settings.redaction_enabled` global toggle

#### New Public Exports
- `Redactor`, `RedactionResult`, `DetectedEntity` added to `enforcecore` top-level imports

#### Testing
- 67 new tests (46 redactor unit tests + 21 enforcer integration tests)
- Total: 161 tests, 97% coverage
- 2 new test fixture policies: `pii_redaction.yaml`, `pii_mask.yaml`

#### Examples & Documentation
- `examples/pii_redaction.py` — 5 demo patterns (standalone, detection-only, selective categories, enforcer pipeline, decorator)
- `examples/policies/pii_demo.yaml` — example PII policy
- Updated `docs/api-design.md` — Redactor API section with tables and code samples
- Updated `docs/roadmap.md` — v1.0.1 marked as shipped with Definition of Done

### Changed
- Version bumped from `1.0.0a1` to `1.0.1a1`
- `Enforcer.__slots__` extended: `("_engine",)` → `("_engine", "_redactor")`

### Design Decisions
- **Regex over Presidio:** Presidio requires spaCy + Pydantic v1, which is incompatible with Python 3.14. Chose pure regex for zero heavy deps, portability, and speed. Presidio can be added as an optional enhanced backend in a future release.

## [1.0.0a1] — 2025-02-20

### Added

#### Core Enforcement Engine
- `@enforce()` decorator — wraps any sync or async callable with policy enforcement
- `Enforcer` class with `enforce_sync()`, `enforce_async()`, `guard_sync()`, `guard_async()`
- `PolicyEngine` — stateless pre-call/post-call policy evaluation
- `Policy` model — Pydantic-validated, loaded from YAML via `Policy.from_file()`
- Policy caching in the decorator to avoid re-parsing YAML on every call
- Fail-closed by default (`fail_open=False`)

#### Policy System
- YAML-based policy files with `allowed_tools`, `denied_tools`, `on_violation`
- `on_violation: block` (raises) vs `on_violation: log` (warns and continues)
- Output size limit enforcement via `max_output_size_bytes`
- `Policy.from_dict()` for programmatic policy creation
- `Policy.validate_file()` for dry-run validation
- PII redaction config model (evaluation deferred to v1.0.1)
- Resource limits model (evaluation deferred to v1.0.1)
- Network policy model (evaluation deferred to v1.0.2)

#### Types & Exceptions
- Zero-dependency types module (stdlib only)
- Enums: `Decision`, `ViolationType`, `ViolationAction`, `RedactionStrategy`
- Frozen dataclasses: `CallContext` (UUID + timestamp), `EnforcementResult`, `RedactionEvent`
- Exception hierarchy: `EnforceCoreError` → `PolicyError`/`EnforcementViolation` with specific subtypes (`ToolDeniedError`, `DomainDeniedError`, `CostLimitError`, `ResourceLimitError`)

#### Configuration
- `pydantic-settings` based config with `ENFORCECORE_` env prefix
- Settings: `default_policy`, `audit_enabled`, `log_level`, `fail_open`, `cost_budget_usd`

#### Testing
- 94 tests, 97% code coverage
- Full test coverage for types, config, policy, and enforcer modules
- 7 test fixture policies (allow_all, deny_all, specific_tools, log_only, output_limit, invalid, broken)

#### Documentation & Examples
- Vision, architecture, roadmap, API design, tech stack, dev guide, contributing docs
- Quickstart example demonstrating all 3 usage patterns
- Example policies: strict, permissive, research

#### Project Infrastructure
- Python 3.11+ with `pyproject.toml` (Hatch build system)
- ruff linting + formatting, mypy strict mode
- GitHub Actions CI (Linux + macOS, Python 3.11–3.13)
- Apache 2.0 license

### Added (initial setup)
- Initial project structure and documentation
- Vision, architecture, roadmap, API design, tech stack docs
- Apache 2.0 license
- pyproject.toml with Hatch build system

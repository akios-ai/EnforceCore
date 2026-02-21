# EnforceCore Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.9a1] — 2025-02-20

### Added

#### CLI (`enforcecore.cli`)
- **Full CLI** via `enforcecore` entry point (requires `pip install enforcecore[cli]`)
- **`enforcecore info`** — show version, Python, platform, installed extras, export count
- **`enforcecore validate <policy.yaml>`** — schema validation with rich summary table
- **`enforcecore verify <audit.jsonl>`** — Merkle chain integrity verification
- **`enforcecore eval --policy <file>`** — adversarial evaluation suite with optional `--verbose`
- **`enforcecore dry-run <policy.yaml> --tool <name>`** — preview policy decision without execution
- **`enforcecore inspect <audit.jsonl>`** — explore/filter audit trail entries with `--tail`, `--tool`, `--decision`

#### Policy Composition (`enforcecore.core.policy`)
- **`Policy.merge(base, override)`** classmethod — deep merge with special semantics:
  - Scalar fields: override wins
  - `denied_tools`: union of both lists
  - `network.denied_domains`: union of both lists
  - `content_rules.block_patterns`: union (override wins on same name)
  - `rate_limits.per_tool`: merged (override wins per tool)
- **`extends` directive** — YAML `extends: base.yaml` loads base policy and merges child on top; supports chained inheritance
- **`Policy.dry_run(tool_name, **kwargs)`** — preview decisions (allowed/blocked), content violations, PII info, rate limits, network policy without executing

#### Shared Utilities (`enforcecore.utils`)
- **`extract_strings(values)`** — recursively extracts strings from nested structures (dicts, lists, tuples, sets) with max depth 20 protection
- Replaces duplicated `_extract_strings` in `rules.py` and `network.py`

#### New Exports
- `clear_policy_cache` — clear the FIFO-bounded policy cache
- `ContentRulesPolicyConfig`, `NetworkPolicy`, `PIIRedactionConfig`, `PolicyRules`, `RateLimitPolicyConfig`, `ResourceLimits` — policy model classes
- `generate_benchmark_report`, `generate_suite_report`, `get_all_scenarios`, `get_scenarios_by_category` — eval utilities
- Total public API: **105 exports** (was 100)

### Fixed

#### Audit Fixes (from deep audit of v1.0.8a1)
- **H-1**: `RateLimitError` now uses `ViolationType.RATE_LIMIT` (was incorrectly `RESOURCE_LIMIT`)
- **H-2**: Async hook `create_task` references now stored in `_background_tasks` set to prevent GC
- **M-1**: `RuleEngine.remove_rule(name)` method added (was documented but missing)
- **M-4**: Policy cache comment corrected from "LRU-style" to "FIFO-bounded"
- **M-5/L-6**: `person_name` PII category warns once at init, silently skips per-call (no spam)
- **L-1**: Deduplicated `_extract_strings` into shared `enforcecore/utils.py`
- **L-2**: Unreachable fallback in redactor replaced with `AssertionError`
- **L-3**: Roadmap secret categories count corrected from 6 → 7

### Changed
- Version bumped from `1.0.8a1` to `1.0.9a1`
- CLI entry point uncommented in `pyproject.toml`
- **940 tests** (82 new), 1 skipped, 4 warnings — all passing
- Quality gates: ruff ✓, ruff format ✓, mypy strict ✓

## [1.0.8a1] — 2025-02-20

### Added

#### Content Rules Engine (`enforcecore.core.rules`)
- **ContentRule** frozen dataclass — named rule with regex pattern and/or predicate function
- **RuleViolation** frozen dataclass — matched rule name, matched text, position
- **RuleEngine** — evaluates text against a collection of content rules
  - `check(text)` scans text for violations, returns list of `RuleViolation`
  - `check_args(args, kwargs)` recursively extracts and checks all string arguments
  - `add_rule()` / `remove_rule()` for runtime modification
  - `from_config(ContentRuleConfig)` factory for policy-driven construction
  - `with_builtins()` factory pre-loaded with all 4 built-in rule sets
- **4 built-in rule categories** via `get_builtin_rules()`:
  - `shell_injection` — rm -rf, sudo, curl|bash chains, backtick execution, pipe to shell
  - `path_traversal` — ../, %2e%2e, /etc/passwd, /etc/shadow patterns
  - `sql_injection` — ' OR 1=1, UNION SELECT, DROP TABLE, comment injection
  - `code_execution` — exec/eval/compile calls, `__import__`, os.system, subprocess
- **ContentRuleConfig** policy model — `enabled` flag + `block_patterns` list

#### Rate Limiter (`enforcecore.guard.ratelimit`)
- **RateLimiter** with sliding-window algorithm
  - Per-tool limits via `RateLimit(max_calls, window_seconds)`
  - Global limit across all tools
  - Case-insensitive tool name matching
  - Thread-safe via per-window locks
  - `acquire(tool_name)` — raises `RateLimitError` when limit exceeded
  - `reset(tool_name?)` — clear one or all windows
  - `get_tool_usage()` / `get_global_usage()` — current window counts
  - `get_limits()` — introspect configured limits
  - `from_config(RateLimitConfig)` factory for policy-driven construction
- **RateLimitError** exception with `tool_name`, `limit`, `window_seconds` attributes
- **RateLimitConfig** / **RateLimit** policy models
- **RateLimitPolicyConfig** — `enabled`, `per_tool` dict, `global_limit` config

#### Network Domain Enforcement (`enforcecore.guard.network`)
- **DomainChecker** — URL domain allow/deny enforcement
  - `is_domain_allowed(domain)` — checks against allow/deny lists
  - `extract_domains(text)` — extracts domains from URLs in text
  - `check_text(text)` — raises `DomainDeniedError` for denied domains
  - `check_args(args, kwargs)` — recursively checks all string arguments
  - `from_policy(NetworkPolicy)` factory for policy-driven construction
  - Wildcard patterns via fnmatch (e.g., `*.example.com`)
  - Denied domains always take priority over allowed
  - Port stripping and case-insensitive matching
- Expanded **NetworkPolicy** with `enabled`, `denied_domains` fields

#### Output Content Filtering
- Enforcer now runs content rule checks on tool outputs (both sync + async paths)
- Raises `ContentViolationError` when output contains dangerous content
- Completes the input→execute→output inspection pipeline

#### New Public Exports (10 new, 100 total)
- Rules: `ContentRule`, `ContentRuleConfig`, `RuleEngine`, `RuleViolation`, `get_builtin_rules`
- Rate Limiting: `RateLimit`, `RateLimitError`, `RateLimiter`
- Network: `DomainChecker`
- Types: `ContentViolationError`

#### Testing
- 149 new tests across 4 test files:
  - `test_rules.py` — 35 tests: content rules, built-in categories, engine operations, config
  - `test_ratelimit.py` — 28 tests: sliding window, per-tool/global limits, thread safety, config
  - `test_network.py` — 24 tests: domain matching, wildcards, URL extraction, policy factory
  - `test_v108_fixes.py` — 62 tests: all bug fixes + integration (content rules, network,
    rate limiting, defense-in-depth pipeline)
- Total: **858 tests**

### Fixed

#### Critical
- **C-1**: `_redact_output()` now checks `redact_output` policy flag before redacting
- **C-2**: Tool matching in `evaluate_pre_call()` is now case-insensitive (`.lower()` comparison)

#### High
- **H-1**: Policy evaluation uses LRU cache (max 64 entries, FIFO eviction) with `clear_policy_cache()`
- **H-3**: `input_redactions` initialized before try block so blocked audit entries preserve the count
- **H-4**: Unicode normalization falls back to original text when normalization changes string length
- **H-6**: SSN regex tightened to require consistent separators (all dashes, all spaces, or no separators)

#### Medium
- **M-1**: Enforcer class docstring updated from stale "v1.0.0" description
- **M-2**: `person_name` detection escalated from `logger.debug` to `logger.warning`
- **M-3**: PII default categories aligned to include `ip_address`
- **M-4**: `NullBackend._count` made thread-safe with `threading.Lock()`
- **M-6**: `MultiBackend.write()` raises `AuditError` when ALL backends fail
- **M-7**: `guard_sync`/`guard_async` changed from `UserWarning` to `DeprecationWarning`

#### Low
- **L-3**: Added `__repr__` to `Redactor` class
- **L-6**: Credit card regex `\d{0,4}` corrected to `\d{1,4}` (disallow zero-length groups)

### Changed
- Version bumped from `1.0.7a1` to `1.0.8a1`
- `enforcecore.__init__.py` updated with 10 new exports (100 total)
- `enforcecore.core.enforcer` — wires content rules, network enforcement, and rate limiting
  into both `enforce_sync()` and `enforce_async()` pipelines (input check → execute → output check)
- `enforcecore.core.policy` — new config models for content rules, rate limits; expanded network policy
- `enforcecore.core.types` — new `ViolationType.CONTENT_VIOLATION`, `ViolationType.RATE_LIMIT`,
  `ContentViolationError` exception

## [1.0.7a1] — 2025-02-20

### Added

#### Plugin & Hook System (`enforcecore.plugins.hooks`)
- **Lifecycle hook registry** (`HookRegistry`)
  - 4 hook categories: pre-call, post-call, violation, redaction
  - Thread-safe registration, removal, and execution
  - Sync and async hooks supported — async hooks auto-awaited in async paths
  - Hooks are best-effort: exceptions are logged but never break enforcement
  - Global singleton via `HookRegistry.global_registry()`, per-instance isolation available
  - `reset_global()` for clean test teardown
- **Typed context objects** for each hook category:
  - `HookContext` — pre/post call context with `abort` flag, `metadata` dict, `result`, `duration_ms`
  - `ViolationHookContext` — violation type, reason, tool/policy info
  - `RedactionHookContext` — direction (input/output), category, count
- **Decorator registration** — `@on_pre_call`, `@on_post_call`, `@on_violation`, `@on_redaction`
- **Enforcer wiring** — hooks fire at every lifecycle point in both `enforce_sync()` and `enforce_async()`
  - Pre-call hooks can abort execution by setting `ctx.abort = True`
  - Metadata set by pre-call hooks is available to post-call hooks

#### Custom PII Patterns (`enforcecore.redactor.patterns`)
- **PatternRegistry** with dual API:
  - Class-level (global): `register()`, `unregister()`, `get()`, `get_all()`, `categories()`, `clear()`, `count()`
  - Instance-level (isolated): `add()`, `remove()`, `get_patterns()`, `list_categories()`, `clear_all()`, `pattern_count`
- **CustomPattern** frozen dataclass — category, compiled regex, placeholder, mask, optional validator callable
- Thread-safe via locks; validates category (non-empty) and regex (compilable)
- Default placeholder auto-generated as `<CATEGORY_UPPER>`, default mask as `********`
- Wired into `Redactor.detect()` — custom patterns scanned alongside built-in PII categories

#### Secret Detection (`enforcecore.redactor.secrets`)
- **SecretScanner** class with 7 built-in categories:
  - `aws_access_key` — AKIA/ABIA/ACCA/ASIA prefixed 20-char keys
  - `aws_secret_key` — 40-char base64 secrets after key=/: separators
  - `github_token` — ghp_/gho_/ghs_/ghr_ prefixed tokens
  - `generic_api_key` — api_key/apikey/api-key followed by 16-128 chars
  - `bearer_token` — Bearer/JWT tokens in Authorization headers
  - `private_key` — PEM-encoded private keys (RSA, EC, DSA, OPENSSH)
  - `password_in_url` — passwords in connection strings (http, postgres, mongodb, etc.)
- **DetectedSecret** frozen dataclass — category, start, end, text
- Category-limiting: `SecretScanner(categories=["aws_access_key", "github_token"])`
- Overlap removal keeps the longer match
- Results sorted descending by position for safe right-to-left replacement
- `scan_and_report()` returns count-per-category dict for quick auditing
- Helper functions: `get_secret_placeholder()`, `get_secret_mask()`, `get_all_secret_categories()`
- Wired into `Redactor` via `secret_detection=True` parameter

#### Pluggable Audit Backends (`enforcecore.auditor.backends`)
- **AuditBackend** abstract base class — `write(entry_dict)`, `close()`, context manager support
- **JsonlBackend** — append-only JSONL files, thread-safe, creates parent dirs
- **NullBackend** — discards entries with counter (testing/benchmarking)
- **CallbackBackend** — sends to user callable, optional `on_error` handler, entry counter
- **MultiBackend** — fan-out to multiple backends, logs errors but continues
- `Auditor` now accepts optional `backend=` parameter (backward compatible)
- `output_path` now optional when backend is provided

#### New Public Exports (22 new, 90 total)
- Backends: `AuditBackend`, `CallbackBackend`, `JsonlBackend`, `MultiBackend`, `NullBackend`
- Hooks: `HookContext`, `HookRegistry`, `RedactionHookContext`, `ViolationHookContext`,
  `on_pre_call`, `on_post_call`, `on_violation`, `on_redaction`
- Patterns: `CustomPattern`, `PatternRegistry`
- Secrets: `DetectedSecret`, `SecretScanner`

#### Testing
- 165 new tests across 5 test files:
  - `test_hooks.py` — hook registry, sync/async firing, abort, decorators, error resilience
  - `test_patterns.py` — global/instance registry, validation, regex matching
  - `test_secrets.py` — all 7 categories, scan_and_report, helpers, overlap removal
  - `test_backends.py` — all 4 backends, ABC validation, Auditor integration, chain integrity
  - `test_plugin_integration.py` — hooks in enforcer pipeline, async hooks, redaction hooks,
    abort via hook, metadata passing, combined features
- Total: **709 tests**

### Changed
- Version bumped from `1.0.6a1` to `1.0.7a1`
- `enforcecore.__init__.py` updated with 22 new exports (90 total)
- `enforcecore.core.enforcer` — both sync/async paths now fire hooks at all lifecycle points
- `enforcecore.redactor.engine` — detects custom patterns and secrets alongside built-in PII
- `enforcecore.auditor.engine` — supports pluggable backends via `backend=` parameter

## [1.0.6a1] — 2025-02-20

### Added

#### Security Hardening (`enforcecore.core.hardening`)
- **Tool name validation** (`validate_tool_name()`)
  - Rejects empty, overly long, or invalid-character tool names
  - Allowed characters: word chars, dots, hyphens, colons, angle brackets
  - `InvalidToolNameError` exception for validation failures
- **Input size checking** (`check_input_size()`)
  - Measures combined size of string/bytes arguments
  - Default limit: 10 MB, configurable via `max_bytes` parameter
  - `InputTooLargeError` exception when exceeded
- **Deep recursive redaction** (`deep_redact()`)
  - Traverses `dict`, `list`, `tuple`, `set` containers recursively
  - Applies PII redaction to all string leaves
  - Configurable max depth (default: 10) as safety limit
- **Enforcement scope tracking** (via `contextvars`)
  - `enter_enforcement()` / `exit_enforcement()` — track nesting depth
  - `get_enforcement_depth()` / `get_enforcement_chain()` — inspect state
  - `EnforcementDepthError` raised when nesting exceeds max (default: 10)
- **Dev-mode gating**
  - `is_dev_mode()` — checks `ENFORCECORE_DEV_MODE` env var
  - `warn_fail_open()` — emits `RuntimeWarning` if `fail_open` is used without dev mode
- **Exception hierarchy**: `HardeningError` base, `InvalidToolNameError`, `InputTooLargeError`, `EnforcementDepthError`

#### Unicode Hardening (`enforcecore.redactor.unicode`)
- **NFC normalization** (`normalize_unicode()`) — canonical form + zero-width character stripping
  - Strips 17 zero-width/invisible characters (ZWS, ZWNJ, ZWJ, BOM, directional marks, etc.)
- **Homoglyph normalization** (`normalize_homoglyphs()`) — defeats confusable character evasion
  - ~40 Cyrillic-to-Latin, Greek-to-Latin, and Fullwidth-to-ASCII mappings
  - Fast path when no confusables found
- **Encoded PII decoding** (`decode_encoded_pii()`) — URL percent-encoding and HTML entity decoding
- **Combined pipeline** (`prepare_for_detection()`) — chains all three normalizations in order
- Wired into `Redactor.detect()` — all PII detection now uses normalized text

#### Enforcer Hardening
- `enforce_sync()` and `enforce_async()` now call:
  - `validate_tool_name()` — rejects invalid tool names before processing
  - `enter_enforcement()` / `exit_enforcement()` — tracks nesting depth
  - `check_input_size()` — rejects oversized inputs before processing
- `_redact_args()` now uses `deep_redact()` for recursive nested structure redaction
- `_policy_cache_lock` (`threading.Lock`) — thread-safe policy cache access
- `guard_sync()` / `guard_async()` emit deprecation `UserWarning` recommending `enforce_sync()` / `enforce_async()`
- `fail_open` error paths now call `warn_fail_open()` for production safety

#### Auditor Improvements
- `load_trail()` gains `max_entries` parameter — returns only the most recent N entries
- `_resume_chain()` optimized with reverse seeking for large files (>8KB)

#### New Public Exports (16 new, 68 total)
- Hardening: `HardeningError`, `InvalidToolNameError`, `InputTooLargeError`, `EnforcementDepthError`, `validate_tool_name`, `check_input_size`, `deep_redact`, `enter_enforcement`, `exit_enforcement`, `get_enforcement_chain`, `get_enforcement_depth`, `is_dev_mode`
- Unicode: `normalize_unicode`, `normalize_homoglyphs`, `decode_encoded_pii`, `prepare_for_detection`

#### New Documentation
- `docs/faq.md` — Frequently Asked Questions (security, PII, performance, config)
- `docs/troubleshooting.md` — Common errors and debugging tips
- Updated `docs/api-design.md` — Hardening API section

#### Testing
- 113 new tests across 3 test files:
  - `test_hardening.py` — 47 tests (tool name validation, input size, deep redact, enforcement scope, dev mode)
  - `test_unicode.py` — 35 tests (normalization, homoglyphs, encoded PII, combined pipeline)
  - `test_hardening_integration.py` — 31 tests (enforcer wiring, unicode-hardened detection, auditor edge cases)
- Total: **544 tests, 96% coverage**

### Changed
- Version bumped from `1.0.5a1` to `1.0.6a1`
- `enforcecore.__init__.py` updated with 16 new exports (68 total)
- `enforcecore.redactor.engine` uses `prepare_for_detection()` before regex matching
- `enforcecore.core.enforcer` uses `threading.Lock` for policy cache
- `person_name` category now emits `logger.debug()` instead of silent skip

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

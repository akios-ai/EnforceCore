# EnforceCore Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0b3] — 2026-02-23

### Fixed
- **Documentation accuracy** — Corrected false Presidio dependency claim in architecture.md (engine is pure-regex), removed references to deprecated `async with enforce()` context manager API, updated performance benchmarks from estimated 8-20ms to measured ~0.056ms E2E.
- **README academic credibility** — Replaced "Provable" claim with "Property-tested" (22 Hypothesis properties), fixed misleading `eval()` code comment, repaired corrupted emoji characters.
- **Formal invariants precision** — Added explicit note distinguishing property-based testing (Hypothesis) from mechanical formal proof in `docs/formal/invariants.md`.
- **CHANGELOG date** — Corrected v1.0.24a1 date from future 2026-02-24 to 2026-02-23.

### Changed
- **SECURITY.md** — Updated supported versions table for current beta.
- **Threat model** — Updated version header to reflect current release.
- **Audit script** — Applied ruff auto-fixes (import sorting, assert patterns) to `scripts/full_audit.py`.

## [1.0.0b2] — 2026-02-23

### Fixed
- **Policy.from_dict() silent rule drop** — Rule-level keys (`denied_tools`, `allowed_tools`, etc.) placed at the top level of a `from_dict()` call were silently ignored by Pydantic, resulting in **no enforcement**. These keys are now automatically hoisted into `rules` with a `DeprecationWarning`.  Top-level rule keys will be rejected in v2.0.0.

### Added
- **Regression tests** — New tests verifying flat-dict rule hoisting and enforcement.

## [1.0.0b1] — 2026-02-23

### Added

- **[Deprecation Warnings]** Tier 2 symbols (~80 advanced types) now emit a
  `DeprecationWarning` when imported from the top-level `enforcecore` package.
  The warning message includes the canonical submodule import path.  These
  symbols will be removed from the top-level package in v2.0.0.

- **[Migration Guide]** Added `docs/migration.md` section covering the
  Tier 1/Tier 2 split, deprecation warnings, and how to migrate imports.

- **[Integration Guides]** Expanded `docs/api/integrations.md` with full
  documentation for LangGraph, CrewAI, and AutoGen adapters including
  usage examples and custom adapter guidance.

### Changed

- **[Beta Status]** Development status upgraded from Alpha to Beta.
  The 30-symbol public API (`__all__`) is now **frozen** — no additions
  or removals until v2.0.0.  Only bug fixes during the beta period.

- **[API Docs]** Updated `docs/api/index.md` to reflect the Tier 1/Tier 2
  split and import conventions.

- **[Docs Navigation]** Added Migration Guide and Benchmarks to
  mkdocs.yml navigation.

## [1.0.25a1] — 2026-02-23

### Changed

- **[API Pruning]** `__all__` reduced from 110 symbols to 30 core symbols
  (Tier 1 public API). All 110 symbols remain importable via
  `from enforcecore import X` for backwards compatibility, but only the 30
  Tier 1 symbols are part of the stable API contract going forward.

  **Tier 1 (in `__all__`):** `enforce`, `Enforcer`, `Policy`, `load_policy`,
  `Redactor`, `RedactionResult`, `RedactionStrategy`, `SecretScanner`,
  `Auditor`, `AuditEntry`, `VerificationResult`, `verify_trail`, `load_trail`,
  `ResourceGuard`, `CostTracker`, `KillSwitch`, `RateLimiter`, `Decision`,
  `EnforcementResult`, `EnforceCoreError`, `EnforcementViolation`,
  `ToolDeniedError`, `ContentViolationError`, `PolicyError`, `PolicyLoadError`,
  `CostLimitError`, `ResourceLimitError`, `Settings`, `settings`, `__version__`.

  **Tier 2 (importable, not in `__all__`):** All other symbols — eval types,
  hook decorators, audit backends, hardening utilities, policy sub-configs,
  telemetry, unicode helpers, etc. Import from submodules for the stable path:
  `from enforcecore.eval import ScenarioRunner`
  `from enforcecore.plugins.hooks import on_pre_call`
  `from enforcecore.auditor.backends import JsonlBackend`

### Tests

- Updated `tests/api/test_public_api.py` with Tier 1/Tier 2 classification.
  Added `test_tier2_symbols_importable` to verify backwards compatibility.

## [1.0.24a1] — 2026-02-23

### Security

- **[A-4]** `AuditEntry.to_dict()` now validates JSON-safety via `json.dumps()`
  before returning. Non-serialisable extras raise `AuditError` immediately
  instead of silently producing corrupt audit data.
- **[M-4]** `SecretScanner.detect()` applies a Shannon entropy filter
  (`_GENERIC_KEY_MIN_ENTROPY = 3.0`) to `generic_api_key` matches. Low-entropy
  false positives (e.g. `key=aaaaaabbbbbb`) are now suppressed.
- **[A-5]** `check_input_size()` enforces `MIN_INPUT_SIZE_BYTES = 64` floor.
  Passing `max_bytes < 64` now raises `HardeningError`, preventing
  misconfiguration that could silently block all inputs.
- **[M-5]** Unicode normalization pipeline rewritten with offset mapping.
  New `NormalizationResult` dataclass tracks position changes through all 5
  normalization steps (NFC, zero-width strip, homoglyph, URL-decode,
  HTML-decode). `Redactor.detect()` now runs regex on normalised text and
  maps entity positions back to the original string via `map_span()`.
  Previously, length-changing normalisations (e.g. `%40` → `@`) disabled
  the entire pipeline, allowing Unicode evasion of PII detection.

### Changed

- **[A-8]** `Redactor.detect()` and `SecretScanner.detect()` now return
  entities in ascending order by start position (was descending).
  `Redactor.redact()` internally uses `reversed()` for right-to-left
  replacement. No double-reverse in `RedactionResult.entities`.
- **[M-2]** `Enforcer` refactored: extracted 7 shared helper methods
  (`_prepare_call`, `_validate_pre_call`, `_redact_and_check_budget`,
  `_process_result`, `_log_and_audit_allowed`, `_handle_enforcement_violation`,
  `_fail_open_redact_fallback`) from `enforce_sync`/`enforce_async`.
  Eliminates ~130 lines of duplication. Both paths now call identical
  validation logic, differing only at async boundaries.

### Tests

- Added 15 new tests: 4 for A-5 minimum floor, 8 for M-5 offset mapping
  (`TestNormalizationResult`), 4 for M-5 end-to-end Redactor integration
  (`TestM5RedactorIntegration`). Updated A-8 sort-order test to ascending.

## [1.0.23a1] — 2026-02-23

### Fixed

- **Release infrastructure:** `scripts/release.py` now runs pytest with `--timeout=60`
  and `HYPOTHESIS_MAX_EXAMPLES=10`, matching CI exactly (CI parity constants).
  Root cause of v1.0.21a1 CI failure.
- **Release script:** `verify_artifacts()` now uses `sys.executable` instead of
  bare `python` command, fixing venv detection in artifact validation.
- **CI pipeline:** Test matrix changed from `[ubuntu-latest, macos-latest]` to
  `[macos-latest]` only. RLIMIT_AS memory-limit tests hang on Ubuntu CI runners,
  causing 15-minute timeouts and cancelled jobs since run #19.

### Security

- Added "Known Security Gaps" section to `SECURITY.md` documenting A-4, M-4,
  A-5, M-5 audit findings with mitigations and fix targets.
- Added CI Parity section and v1.0.21a1 post-mortem to `RELEASING.md`.

## [1.0.22a1] — 2026-02-22

### Security

- **[H-3]** `_resolve_policy()`: policy cache now stores `(Policy, mtime)` tuples
  and checks `path.stat().st_mtime` on every lookup. Stale entries are
  automatically evicted and reloaded, preventing enforcement of outdated
  rules when policy files change on disk.
- **[H-2]** `ResourceGuard`: replaced per-call `ThreadPoolExecutor` creation
  with a shared instance (`max_workers=4`, daemon threads, prefix
  `enforcecore-guard`). Eliminates thread leak on every guarded call.
  New `leaked_thread_count` property tracks threads abandoned due to
  timeout. Critical warning logged when leaked count ≥ pool capacity.

### Fixed

- **[L-4]** `Auditor._resume_chain()`: switched from text-mode `seek()` to
  binary-mode with a 64 KB read-back window and `decode("utf-8",
  errors="replace")`. Retry with doubled window on parse failure.
  Fixes undefined behaviour of `seek()` on text streams and handles
  multi-byte characters correctly.
- **[A-3]** `_run_async_hook()`: `_background_tasks` set is now capped at
  1 000 entries. When at capacity, a `background_tasks_limit_reached`
  warning is logged and the new task reference is not tracked (the task
  still runs but may be garbage-collected early).

### Tests

- Added 16 regression tests in `tests/core/test_v1022_fixes.py` covering
  all four fixes: H-3 mtime cache invalidation (4 tests), H-2 shared
  thread pool (6 tests), L-4 binary-mode audit resume (3 tests),
  A-3 background tasks cap (3 tests).

## [1.0.21a1] — 2026-02-22

### Security

- **[H-1]** `enforce_sync` / `enforce_async`: when `fail_open=True` and an
  `EnforceCoreError` occurs *before* the normal `_redact_args()` step (e.g.,
  during `check_input_size`), the fail-open fallback now explicitly calls
  `_redact_args()` before executing `func()`. Previously, raw un-redacted
  PII could leak to the tool. If even redaction itself fails, a nuclear
  fallback replaces all string arguments with `[REDACTED]`.

### Fixed

- **[M-3]** `_on_background_task_done()`: fire-and-forget async hook tasks
  now log exceptions via `logger.warning("async_hook_error", ...)` instead
  of silently discarding them.
- **[L-3]** `AuditEntry.from_dict()`: replaced private `cls.__dataclass_fields__`
  access with the public `dataclasses.fields(cls)` API.
- **[A-1]** `_warn_fail_open()`: now accepts `tool_name` and `error` keyword
  arguments. Both the `RuntimeWarning` message and the structured log entry
  include the failing tool name and error type for diagnostics.
- **[A-2]** `_record_audit()`: when audit recording fails and `fail_open=True`,
  a `logger.critical("audit_trail_incomplete", ...)` message is now emitted
  warning that the tamper-proof audit trail has a gap for this call.

### Tests

- Added 15 regression tests in `tests/core/test_v1021_fixes.py` covering
  all five fixes: H-1 PII redaction in fail-open (sync, async, nuclear
  fallback), M-3 async hook error logging, L-3 public API usage,
  A-1 warning context, A-2 audit failure logging.

## [1.0.20a1] — 2026-02-22

### Added

#### Packaging & Publication
- `scripts/release.py` — automated release script with dry-run mode,
  version bumping across all files, CHANGELOG management, artifact
  building, leakage verification, clean-install testing, and git
  commit/tag automation
- `.github/workflows/release.yml` — GitHub Actions release workflow:
  cross-platform CI gate (3.11–3.13 × Ubuntu/macOS), artifact leakage
  checks, PyPI trusted publishing (OIDC), and automatic GitHub Release
  creation with changelog extraction
- `[tool.hatch.build.targets.sdist] exclude` — explicit exclusion of
  `internal/` and `.github/` from sdist builds (belt-and-suspenders
  alongside `.gitignore`)
- Release process documented in RELEASING.md

### Verified

- Clean wheel install: all 110 public symbols import correctly
- 10-point enforcement correctness test from clean install (tool deny,
  PII redaction, domain checking, rate limiting, content rules, audit,
  input hardening, eval scenarios, unicode normalization, secret scanning)
- All 6 examples execute successfully (`quickstart.py`, `pii_redaction.py`,
  `resource_guard.py`, `audit_trail.py`, `evaluation_suite.py`,
  `framework_integrations.py`)
- 20/20 adversarial scenarios contained, 0 escaped
- No `internal/` folder leakage in wheel or sdist

## [1.0.19a1] — 2026-02-21

### Added

#### Pre-Release Polish & Community
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1 with enforcement guidelines
- `CONTRIBUTORS.md` — contributor list, roles, and acknowledgements of academic
  and industry prior art
- `CITATION.cff` updated to current version (v1.0.19a1)
- Apache 2.0 SPDX license headers added to all 106 Python source files
  (`enforcecore/` and `tests/`)
- README: Acknowledgements section (prior art, academic references)
- README: Code of Conduct link in documentation table
- README: defense-in-depth and tool-selection guide links
- `examples/README.md` corrected — removed 3 phantom files
  (`langgraph_example.py`, `crewai_example.py`, `autogen_example.py`),
  added `resource_guard.py`, `framework_integrations.py`, and
  `scenarios/` directory

### Fixed

#### Documentation Consistency Pass
- `docs/index.md`: scenario count 13 → 20 across 10 threat categories
- `docs/compliance/eu-ai-act.md`: mapped version 1.0.12a1 → 1.0.19a1,
  scenario count 26 → 20, benchmarks status `Planned` → `Complete`,
  formal verification status `Planned` → `Complete`, SBOM planned release
  updated to `Post-v1.0`
- `docs/compliance/gdpr.md`: mapped version 1.0.12a1 → 1.0.19a1
- `docs/api-design.md`: removed `guard_sync`/`guard_async` context manager
  examples (removed from API in v1.0.16a1)
- `docs/roadmap.md`: test counts filled for v1.0.17a1 and v1.0.18a1 (1461),
  v1.0.17 rationale updated to past tense
- `README.md`: benchmark Python version `3.14` → `3.13`

## [1.0.18a1] — 2026-02-21

### Added

#### Security Landscape & Positioning
- `docs/related-work.md` Section 6: OS-Level Enforcement comparison —
  SELinux, AppArmor, seccomp-bpf, Linux capabilities with detailed
  comparison table, references, and complementary model diagram
- `docs/defense-in-depth.md` — five-layer security architecture document
  with Mermaid diagrams, threat coverage matrix, recommended deployment
  stacks (minimal, standard, high-security, multi-agent), Docker example,
  and gap analysis (side-channel, semantic evasion, transitive deps, model
  manipulation)
- `docs/security/tool-selection.md` — "When to Use What" decision tree,
  4 deployment patterns (simple, customer-facing, untrusted, multi-agent),
  4 anti-patterns with explanations
- `docs/architecture.md` — Security-Layer Context section with Mermaid
  defense-in-depth diagram, scope boundary statement, and layer comparison
  table
- README positioning note: "EnforceCore vs. OS-level security" callout in
  the Why section, links to defense-in-depth and tool-selection docs
- README documentation table: added Defense-in-Depth and Tool Selection
  guide links

## [1.0.17a1] — 2026-02-21

### Added

#### Adversarial Scenario Expansion
- 7 new multi-stage adversarial scenarios (20 total, up from 13)
- 3 new `ThreatCategory` enum members: `RANSOMWARE`, `SUPPLY_CHAIN`,
  `COLLUSION`
- `StageResult` dataclass — structured per-stage outcome for multi-stage
  scenario pipelines (stage name, tool, blocked flag, exception type, details)
- `_run_multi_stage_scenario()` helper — orchestrates multi-stage attacks
  with configurable `min_blocked` threshold, returns `CONTAINED` or `ESCAPED`

#### New Scenarios
- **Ransomware campaign** (`ransomware_campaign`) — 4-stage attack:
  enumerate files → encrypt → delete originals → send ransom note.
  Demonstrates defense-in-depth across file and network enforcement
- **Ransomware encrypt-only** (`ransomware_encrypt_only`) — 5 parallel
  file encryption attempts, all must be blocked
- **Supply-chain credential harvest** (`supply_chain_cred_harvest`) —
  reads environment variables → HTTP exfiltration → DNS exfiltration.
  Tests secret detection and network enforcement
- **Supply-chain hidden exfiltration** (`supply_chain_hidden_exfil`) —
  base64, hex, and split-encoding evasion of output inspection
- **Multi-agent collusion relay** (`collusion_relay`) — two agents with
  isolated policies attempt cross-agent data relay. Tests per-agent
  policy isolation
- **Privilege escalation chain** (`priv_escalation_chain`) — modify own
  policy → call admin tool → unicode trick → env injection. Tests
  policy immutability and tool-name normalization
- **Slow-burn exfiltration** (`slow_burn_exfil`) — 20 small data chunks
  with embedded PII, tests cumulative output monitoring

#### Tests
- `tests/eval/test_multi_stage_scenarios.py` — 44 new tests across 9
  test classes covering all multi-stage scenarios, StageResult, helper
  function, registry, and metadata validation
- Updated `test_threat_category_members` to include all 10 categories

## [1.0.16a1] — 2026-02-21

### Added

#### PEP 561 Typed Package
- `enforcecore/py.typed` marker file — type checkers (mypy, pyright) now
  automatically discover EnforceCore's type information

#### API Compatibility Test Suite (`tests/api/`)
- 80+ parametrized tests verifying every symbol in `__all__` is importable
  and has the expected type (class, function, enum, exception, instance)
- Exception hierarchy stability tests (parent-child relationships)
- Enforcer public interface tests (expected methods, removed methods)
- Policy interface tests (construction methods, fields)
- Enum member stability tests (Decision, RedactionStrategy, ViolationType)
- Submodule re-export consistency tests (root ↔ submodule identity)
- Function signature tests for key public functions
- Version string PEP 440 format validation
- Integration adapter importability tests

#### Documentation
- `docs/versioning.md` — semantic versioning contract, breaking change
  definition, deprecation policy (2 minor versions), backport policy,
  compatibility promises for v1.x
- `docs/migration.md` — alpha → stable migration guide, breaking changes
  summary, deprecated API alternatives, internal symbols reference

### Removed

#### Deprecated Methods
- **`Enforcer.guard_sync()`** — removed (deprecated since v1.0.6a1).
  Use `Enforcer.enforce_sync()` for full enforcement pipeline.
- **`Enforcer.guard_async()`** — removed (deprecated since v1.0.6a1).
  Use `Enforcer.enforce_async()` for full enforcement pipeline.
- These methods only performed pre-call policy checks, silently skipping
  PII redaction, audit trail recording, content rule checking, rate
  limiting, and resource guarding. Their removal eliminates attack
  surface vector A3.

### Changed

#### Internal API Privatized
- `warn_fail_open()` → `_warn_fail_open()` — renamed to signal internal-only
  usage (was never in `__all__`, called only by the Enforcer on fail-open)
- Unused imports cleaned from `enforcecore/core/enforcer.py` (`warnings`,
  `contextmanager`, `asynccontextmanager`, `Iterator`, `AsyncIterator`)

#### Documentation Updates
- README: replaced `guard_sync`/`guard_async` examples with `enforce_sync`/
  `enforce_async`
- Troubleshooting: updated deprecated method warning to removal notice
- Attack surface: marked A3 vector as eliminated, removed deprecated entries
- Quickstart example: simplified to 4 demos (removed context manager demo)

### Meta
- **Tests:** 1416 passed, 1 skipped (up from 1138)
- **Quality:** ruff clean, mypy strict clean, 0 issues in 41 source files

## [1.0.15a1] — 2026-02-21

### Added

#### End-to-End Scenario Examples (`examples/scenarios/`)
- **Healthcare** (`healthcare/`) — HIPAA-style PII redaction (email, phone, SSN),
  tool gating for approved medical APIs, Merkle-chained audit trail with
  verification, content rule enforcement
- **Financial** (`financial/`) — cumulative cost budget ($5 cap), per-tool and
  global rate limiting (10/min per-tool, 50/min global), tool gating to
  authorized financial data sources, PII masking for credit card numbers,
  network domain enforcement
- **Code Agent** (`code_agent/`) — content rules blocking dangerous patterns
  (os.system, subprocess, eval, file_write, prompt_injection), deny-all
  network policy, resource guards (5s time limit, 64MB memory), PII protection
  in code snippets
- **Multi-Framework** (`multi_framework/`) — same YAML policy enforced
  identically across plain `@enforce` decorator, `Enforcer` class,
  LangGraph adapter, CrewAI adapter, AutoGen adapter (import-guarded)
- **Compliance** (`compliance/`) — EU AI Act compliant workflow with policy
  dry-run preview (PolicyEngine.evaluate_pre_call), full enforcement pipeline,
  Merkle-chained audit trail generation and cryptographic verification,
  compliance evidence summary
- Each scenario includes README.md, policy.yaml, and runnable Python demo

#### Integration Test Suite (`tests/integration/`)
- **48 new integration tests** — no mocks, real policies, real audit files
- `test_full_pipeline.py` — full E2E: Policy → Enforcer → Redactor → Guard →
  Auditor → Verify for all 5 scenarios (healthcare, financial, code agent,
  compliance, cross-policy)
- `test_multi_policy.py` — multi-policy isolation, universal denial checks,
  policy properties, multi-policy audit trail, `Enforcer.from_file()`
- `test_concurrent.py` — thread-safety (20-thread concurrent calls, mixed
  allow/deny, concurrent audit integrity), async concurrency, stress tests
  (100 sequential calls, rapid rate-limited calls)
- `test_audit_continuity.py` — Merkle chain structure validation (first
  entry, chain links, deterministic hashes), tamper detection (modified
  tool name, deleted entry, swapped entries), edge cases (empty trail,
  single entry, order preservation)
- Integration `conftest.py` re-enables audit (overrides the global autouse
  `_disable_audit_globally` fixture)

#### Docker Reproducibility
- `Dockerfile` — Python 3.12-slim base, full dev install, runs test suite
- `docker-compose.yml` — services: `test`, `integration`, `benchmark`, `lint`

### Changed
- Test count: 1090 → 1138 (+48 integration tests)

## [1.0.14a1] — 2026-02-21

### Added

#### Reproducible Benchmark Suite (`enforcecore/eval/benchmarks.py`)
- Enhanced `_measure()` with configurable warmup phase (default 100 iterations)
- New percentile fields: P50, P99.9, standard deviation on every benchmark
- `_percentile()` helper for linear interpolation percentile calculation
- 8 new component-level benchmarks:
  - `bench_policy_large_allowlist` — scalability with 100/1000/10000 tools
  - `bench_pii_long_text` — PII redaction on ~2KB text
  - `bench_pii_clean_text` — PII scan fast-path (no entities)
  - `bench_audit_verify` — Merkle chain verification
  - `bench_rate_limiter` — sliding window acquire
  - `bench_secret_detection` — AWS/GitHub/bearer token scanning
- Suite now runs 15 benchmarks total (was 7)

#### Benchmark Types (`enforcecore/eval/types.py`)
- `BenchmarkResult`: added `p50_ms`, `p999_ms`, `std_dev_ms`, `warmup_iterations`
- `BenchmarkResult.to_dict()` — JSON-serializable dictionary export
- `BenchmarkResult.to_row()` — Markdown table row formatting
- `BenchmarkSuite`: added `cpu`, `machine`, `enforcecore_version` fields
- `BenchmarkSuite.to_dict()` — structured dict with metadata + results
- `BenchmarkSuite.to_json()` — indented JSON export
- `BenchmarkSuite.to_markdown()` — full Markdown report with environment info

#### Benchmark CLI (`benchmarks/`)
- `python -m benchmarks.run` CLI entry point
- `--iterations`, `--warmup`, `--format`, `--output` options
- JSON, Markdown, or both output formats
- Output to stdout or directory

#### Documentation (`docs/benchmarks.md`)
- Methodology: warmup, iteration count, percentile calculation, clock source
- Full reference results table from 1000-iteration run
- Key observations and performance characteristics
- Reproduction instructions (CLI and Python API)

#### CI Benchmark Job (`.github/workflows/ci.yml`)
- New `benchmark` job runs after tests pass
- Generates JSON + Markdown results as build artifacts
- 90-day artifact retention for regression tracking

### Changed
- `BenchmarkRunner.run_all()` now captures CPU, machine, and version metadata
- `run_all()` now executes 15 benchmarks (up from 7)
- Updated all existing test fixtures for new `BenchmarkResult` required fields

## [1.0.13a1] — 2025-02-21

### Added

#### Property-Based Tests (`tests/formal/`)
- 30 Hypothesis property-based tests verifying 22 formal invariants
- `test_prop_policy.py` — 10 tests covering 8 policy engine properties:
  - P1: Evaluation determinism
  - P2: Deny enforcement (with case-insensitivity)
  - P3: Allowlist enforcement (with converse)
  - P4: Deny priority over allow
  - P5: Open-by-default (null allowlist)
  - P6: Closed-on-empty (empty allowlist)
  - P7: Merge denied-tools union
  - P8: Decision completeness
- `test_prop_merkle.py` — 8 tests covering 5 Merkle chain properties:
  - M1: Hash determinism
  - M2: Hash sensitivity
  - M3: Chain validity (arbitrary length)
  - M4: Tamper detection (modification, deletion, reorder)
  - M5: Append stability
- `test_prop_redactor.py` — 8 tests covering 5 redactor properties:
  - R1: Idempotency
  - R2: Completeness (email, phone)
  - R3: Safety (clean text unchanged)
  - R4: Detect–redact consistency
  - R5: Strategy independence
- `test_prop_enforcer.py` — 4 tests covering 4 enforcer properties:
  - E1: Fail-closed (denied tools raise)
  - E2: Allowed pass-through
  - E3: Enforcement idempotency
  - E4: Internal error propagation

#### Formal Documentation (`docs/formal/`)
- `invariants.md` — Complete formal specification of all 22 invariants
  with mathematical notation, linking each to its Hypothesis test
- `policy-algebra.md` — Algebraic properties of the merge operation:
  - Formal definition using tuple notation
  - Monotonic denial proof
  - Evaluation truth table
  - Conflict resolution summary with security implications
  - Edge cases (empty merge, self-merge, cascade example)

### Changed
- Added `hypothesis>=6.100` to dev dependencies in `pyproject.toml`
- Test count increased from 1038 to 1068 (+30 property tests)

## [1.0.12a1] — 2025-02-21

### Added

#### Threat Model (`docs/threat-model.md`)
- Formal threat model with 4 adversary types:
  - A1: Compromised LLM output (prompt injection, jailbreak)
  - A2: Malicious tool response (compromised API, MITM)
  - A3: Insider threat (developer disabling enforcement)
  - A4: Supply chain (compromised dependency)
- 4 formal security properties with precise statements:
  - S1: Fail-closed completeness
  - S2: Audit completeness
  - S3: Chain integrity
  - S4: Redaction totality
- Each property linked to implementation code and verification tests
- 5 trust boundaries documented (policy files, env vars, audit storage, hooks, settings singleton)
- 6 assumptions and 11 known limitations explicitly stated
- Mermaid diagram of trust zones

#### EU AI Act Compliance Mapping (`docs/compliance/eu-ai-act.md`)
- Article-by-article mapping for Articles 9, 13, 14, 15, 17
- Each mapping: requirement → EnforceCore capability → evidence (code paths + tests)
- Traceability matrix: Article → Module → Test file → Documentation
- Verification commands for each article
- Gaps and planned work table with target releases

#### GDPR Considerations (`docs/compliance/gdpr.md`)
- Article 5(1)(c) — Data minimisation via PII redaction
- Article 5(1)(e) — Storage limitation via audit retention/rotation
- Article 25 — Data protection by design (redaction in pipeline)
- Article 30 — Records of processing via Merkle audit trail
- Article 17 — Right-to-erasure tension analysis:
  - Hash-only storage mitigates most concerns
  - Redact-before-audit pipeline documented
  - Tombstone strategy discussed (not yet implemented)

#### Attack Surface Analysis (`docs/security/attack-surface.md`)
- 7 entry point categories enumerated (enforcement API, policy loading, config, audit, redactor, hooks, CLI)
- Attack vectors with risk level, mitigation, and status for each entry point
- Full dependency audit (4 core + 10 optional) with risk assessments
- Dev-mode and fail-open analysis with truth table
- Summary of 6 unmitigated risks with planned fixes

### Changed

#### SECURITY.md
- Added security properties table (S1–S4) with caveats
- Added links to threat model, attack surface, EU AI Act, and GDPR docs
- Updated design principles to be more precise (fail-open caveat documented)
- Expanded scope and out-of-scope sections

#### MkDocs Navigation
- Added Security section (Threat Model, Attack Surface)
- Added Compliance section (EU AI Act, GDPR)

## [1.0.11a1] — 2025-02-21

### Added

#### Documentation & Academic Foundation
- **MkDocs site** — full API reference site powered by MkDocs Material + mkdocstrings
  - Auto-generated docs for all 110+ public exports from Google-style docstrings
  - 22 API reference pages organized by module (core, redactor, auditor, guard, plugins, telemetry)
  - Quick start guide, architecture overview, and navigation structure
  - Mermaid diagram support via `pymdownx.superfences` custom fences
  - Dark/light theme toggle, search, code copy, and navigation tabs
- **CITATION.cff** — machine-readable citation metadata (CFF v1.2.0) for academic use
- **`docs/related-work.md`** — survey of runtime verification for AI agents
  - Positions EnforceCore vs. NeMo Guardrails, Guardrails AI, LlamaGuard, Rebuff, LangChain
  - 10+ academic references (runtime verification, reference monitors, agent containment, IFC)
  - Comparison table across 12 dimensions (enforcement point, determinism, audit, cost, etc.)
  - Five open research questions for collaboration

#### Architecture Diagrams
- **Mermaid diagrams** replace all ASCII art in `docs/architecture.md`:
  - High-level architecture flowchart (agent → API → enforcer → components)
  - Enforcement data-flow sequence diagram (pre-call → redact → guard → execute → audit)
  - Module dependency graph (6 subgraph clusters with 20+ nodes)
  - Exception hierarchy class diagram (13 exception types)
  - Threat boundary model (untrusted → enforcement boundary → trusted zones)

#### README Enhancements
- **For Researchers** section — links to related work, citation, open questions, evaluation suite
- **For Enterprises** section — feature table (audit, PII, cost, governance, EU AI Act)
- **Documentation table** — added Related Work and API Reference links

### Changed

#### Docstring Completeness
- Audited all 110+ public exports; fixed 18 missing + 36 incomplete docstrings
- All exception `__init__` methods now have full Args documentation
- All class constructors document parameters with types and defaults
- All `BenchmarkRunner.bench_*` methods have Args/Returns sections
- Enhanced `RuleEngine`, `RateLimiter`, `MetricsRecorder` method docstrings
- Added `docs` optional dependency group: `mkdocs-material>=9.5`, `mkdocstrings[python]>=0.24`
- Updated Documentation URL in `pyproject.toml` to MkDocs site

## [1.0.10a1] — 2025-02-21

### Added

#### Telemetry (`enforcecore.telemetry`)
- **`EnforceCoreMetrics`** — thread-safe counters (calls, blocks, redactions, violations, cost) with optional OpenTelemetry binding via `bind_otel(meter)`
- **`EnforceCoreInstrumentor`** — auto-instruments all enforcement calls via HookRegistry; creates OTel spans per call with tool name, decision, duration, and violation details
- OTel is optional: `pip install enforcecore[telemetry]` for OpenTelemetry support; in-process metrics work without it
- Metric constants: `CALLS_TOTAL`, `BLOCKS_TOTAL`, `REDACTIONS_TOTAL`, `VIOLATIONS_TOTAL`, `LATENCY_HISTOGRAM`, `OVERHEAD_HISTOGRAM`, `COST_GAUGE`

#### Audit Rotation (`enforcecore.auditor.rotation`)
- **`AuditRotator`** — manages audit trail file lifecycle
  - Size-based rotation: auto-rotate JSONL files when they exceed configurable MB threshold
  - Time-based retention: auto-delete audit files older than configurable days
  - Gzip compression: compress rotated files to save disk space
  - `get_stats()`: file count, total size, compressed count
- New settings: `audit_rotate_mb` (100), `audit_retain_days` (90), `audit_compress` (True)

#### Event Webhooks (`enforcecore.plugins.webhooks`)
- **`WebhookDispatcher`** — HTTP POST callbacks for enforcement events
  - Event types: `violation`, `cost_threshold`, `audit_error`
  - Retry with exponential backoff (configurable attempts, timeout, backoff)
  - Auto-registers via HookRegistry `install()`/`uninstall()`
- **`WebhookEvent`** — frozen dataclass for typed event dispatch
- New settings: `webhook_on_violation`, `webhook_on_cost_threshold`, `webhook_retry_attempts` (3), `webhook_timeout_seconds` (10)

#### Enhanced Secret Detection
- 4 new secret categories (11 total, was 7):
  - `gcp_service_account` — Google Cloud service account key JSON
  - `azure_connection_string` — Azure storage/service bus connection strings
  - `database_connection_string` — Database URIs with credentials (postgres, mysql, mongodb, redis)
  - `ssh_private_key` — OpenSSH private key blocks

### Fixed
- **H-1**: CLI `inspect` now reads `call_duration_ms` with fallback to `duration_ms` for backward compatibility
- **H-2**: `Policy.merge()` uses `model_dump(exclude_none=True)` so default `None` values don't overwrite base
- **M-1**: Core `__init__` now exports `ContentRulesPolicyConfig`, `RateLimitPolicyConfig`, `clear_policy_cache`
- **M-2**: Fail-open code path now uses redacted args (`r_args`/`r_kwargs`) instead of original arguments
- **M-4**: CLI test fixture updated to use real `AuditEntry` field names
- **L-1**: Removed dead `_extract_strings` backward-compat aliases
- **Bound method identity bug**: Instrumentor and WebhookDispatcher now store bound method references for reliable hook add/remove

### Changed
- Top-level exports: 110 (was 105)
- `pyproject.toml`: added `telemetry` optional extra (`opentelemetry-api>=1.20`, `opentelemetry-sdk>=1.20`); `all` extra now includes `telemetry`
- `mypy` overrides: added `opentelemetry.*` to ignore-missing-imports
- Version bumped from `1.0.9a1` to `1.0.10a1`
- Tests: 1038 passing (was 940)

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

# EnforceCore Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

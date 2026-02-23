# API Reference

Auto-generated documentation for all public EnforceCore APIs.

EnforceCore exports **30 core symbols** (Tier 1) in `__all__`.
An additional ~80 advanced symbols (Tier 2) remain importable from the
top-level package for backwards compatibility, but emit a
`DeprecationWarning` — use submodule imports instead.

!!! tip "Import convention"
    ```python
    # ✅ Tier 1 — stable, no warning
    from enforcecore import enforce, Enforcer, Policy, Redactor, Auditor

    # ✅ Tier 2 — stable via submodule
    from enforcecore.plugins.hooks import on_pre_call, on_violation
    from enforcecore.auditor.backends import JsonlBackend

    # ⚠️ Deprecated — emits DeprecationWarning
    from enforcecore import JsonlBackend  # will be removed in v2.0.0
    ```

## Core

The enforcement engine and policy system.

| Module | Description |
|--------|-------------|
| [Enforcer](enforcer.md) | Central coordinator — `@enforce()` decorator and `Enforcer` class |
| [Policy](policy.md) | Policy models, engine, and YAML loading |
| [Types](types.md) | Shared types, exceptions, enums, and dataclasses |
| [Rules](rules.md) | Content rule engine for argument-level inspection |
| [Hardening](hardening.md) | Input validation, size checks, enforcement depth tracking |
| [Config](config.md) | Global settings via environment variables |

## Redactor

PII detection and redaction pipeline.

| Module | Description |
|--------|-------------|
| [Engine](redactor.md) | PII detection engine with configurable strategies |
| [Patterns](patterns.md) | Custom pattern registry for domain-specific PII |
| [Secrets](secrets.md) | API key, token, and credential detection (11 categories) |
| [Unicode](unicode.md) | Homoglyph normalization and encoded PII decoding |

## Auditor

Tamper-proof audit trail system.

| Module | Description |
|--------|-------------|
| [Engine](auditor.md) | Merkle-chained audit writer and verifier |
| [Backends](backends.md) | Pluggable storage backends (JSONL, callback, multi) |
| [Rotation](rotation.md) | Size-based rotation, retention, and compression |
| [Witness](witness.md) | Hash-only remote witnesses for tamper detection |
| [Immutable](immutable.md) | OS-enforced append-only file protection |

## Guard

Resource enforcement and rate limiting.

| Module | Description |
|--------|-------------|
| [Engine](guard.md) | Resource guard, cost tracker, and kill switch |
| [Network](network.md) | Domain allow/deny enforcement |
| [Rate Limiter](ratelimit.md) | Sliding-window rate limiting |

## Plugins

Extensibility hooks and integrations.

| Module | Description |
|--------|-------------|
| [Hooks](hooks.md) | Lifecycle hook registry (pre-call, post-call, violation, redaction) |
| [Webhooks](webhooks.md) | HTTP webhook dispatcher for enforcement events |

## Telemetry

Observability and metrics.

| Module | Description |
|--------|-------------|
| [Instrumentor](instrumentor.md) | OpenTelemetry auto-instrumentor |
| [Metrics](metrics.md) | In-process metrics collector |

## Other

| Module | Description |
|--------|-------------|
| [Integrations](integrations.md) | Framework adapters (LangGraph, CrewAI, AutoGen) |
| [Evaluation](evaluation.md) | Adversarial scenarios and benchmark runner |

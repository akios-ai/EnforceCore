# API Reference

Auto-generated documentation for all public EnforceCore APIs.

EnforceCore exports **110+ public symbols** organized into these modules:

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

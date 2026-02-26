# EnforceCore — Versioning & Release Roadmap

> **Audience:** Anyone (including non-engineers) who wants to understand what
> our version numbers mean, how stable the software is right now, and when
> it will be ready for production use.

---

## How Version Numbers Work

Every EnforceCore release has a version number like **`1.0.23a1`**.
Here's what each part means:

```
  1  .  0  .  23  a1
  │     │     │   │
  │     │     │   └── Pre-release tag: "a" = alpha, "b" = beta, "rc" = release candidate
  │     │     └────── Patch number: increments with each release
  │     └──────────── Minor version: stays at 0 for all v1.0.x releases
  └────────────────── Major version: stays at 1
```

### The Four Stages of a Release

Think of it like building a house:

| Stage | Version Example | What It Means | Who Should Use It |
|-------|-----------------|---------------|-------------------|
| **Alpha** (`a`) | `1.0.23a1` | 🏗️ **Under construction.** Core features work, but things may change. Expect rough edges. | Developers who want early access and don't mind occasional breakage |
| **Beta** (`b`) | `1.0.25b1` | 🏠 **Walls are up.** All planned features are done. We're fixing bugs, not adding features. | Early adopters who want to test before everyone else |
| **Release Candidate** (`rc`) | `1.0.28rc1` | 🏡 **Final inspection.** We believe it's ready. If no bugs are found, this becomes the stable release. | Teams preparing for production deployment |
| **Stable** | `1.0.0` | ✅ **Move-in ready.** Fully tested, documented, and supported. Safe for production. | Everyone |

### What Changes Between Stages

| | Alpha → Beta | Beta → RC | RC → Stable |
|---|---|---|---|
| **New features?** | Yes | No | No |
| **API changes?** | Yes (with notice) | Only bug fixes | Nothing |
| **Bug fixes?** | Yes | Yes | Only critical |
| **Safe for production?** | ❌ No | ⚠️ With caution | ✅ Yes |

---

## Where EnforceCore Is Today

**Current version: `1.0.0` (Stable)**
**Published:** February 24, 2026 on [PyPI](https://pypi.org/project/enforcecore/)

### What Stable Means for You

✅ **What works right now:**
- Full enforcement pipeline (`@enforce()` decorator)
- PII redaction (emails, phones, SSNs, credit cards, IPs, passports)
- Secret scanning (AWS keys, GitHub tokens, API keys, etc.)
- Tool allow/deny lists
- Content rules (block dangerous patterns)
- Audit trail with Merkle-chain verification + hash witnesses
- Policy-as-YAML configuration
- Async support
- Framework adapters (LangGraph, AutoGen, CrewAI)
- 1,510 tests passing, 95%+ code coverage
- 30-symbol public API, frozen since beta
- 147-point post-release audit: 100% pass rate

✅ **API guarantees:**
- The public API (`enforcecore.__all__`) is frozen—no breaking changes until v2.0
- Policy YAML files written for v1.0 will load in all v1.x releases
- Audit trail files written by v1.0 will be verifiable by all v1.x releases

✅ **Safe for production:**
- Use `pip install enforcecore` with confidence
- Pin to `enforcecore>=1.0.0,<2` for stability

---

## The Road to Stable (v1.0.0) — Complete ✅

All phases completed ahead of schedule (shipped Feb 24, 2026 vs. original June 2026 target).

### Phase 1: Alpha Hardening ✅ Complete

| Release | Focus | Key Changes |
|---------|-------|-------------|
| **v1.0.21a1** | ⚠️ Security quick wins | Fix PII leak on fail_open path, log async hook errors, use public dataclass API *(code shipped; not on PyPI — superseded by v1.0.22a1)* |
| **v1.0.22a1** | ✅ Infrastructure | Policy cache with mtime invalidation, shared thread pool (no more per-call pools), larger audit seek window |
| **v1.0.23a1** | ✅ Release infra & CI | CI parity in release script, macOS-only test matrix, release.py hardening, security docs |
| **v1.0.24a1** | ⚡ Architecture | Refactor sync/async enforcement into shared pipeline, fix unicode normalization offset mapping |

### Phase 2: Beta ✅ Complete (shipped as v1.0.0b1–b6)

| Release | Focus | Key Changes |
|---------|-------|-------------|
| **v1.0.25b1** | 📦 API stabilization | Reduce `__all__` from 110 to ~25 core symbols, move specialized types to submodules, add deprecation warnings |
| **v1.0.26b1** | 📖 Documentation | Complete API reference, migration guide for deprecated imports, integration guides for LangChain/CrewAI/AutoGen |
| **v1.0.27b1** | 🧪 Extended testing | Fuzz testing, property-based testing expansion, performance regression benchmarks |

### Phase 3: Release Candidate ✅ (Skipped — went directly to stable)

| Release | Focus | Key Changes |
|---------|-------|-------------|
| **v1.0.28rc1** | 🔍 Final audit | Independent security review, penetration testing of enforcement bypass scenarios |
| **v1.0.29rc2** | 🐛 Bug fixes only | Address anything found in rc1, final documentation review |

### Phase 4: Stable Release ✅ Shipped Feb 24, 2026

| Release | What It Means |
|---------|---------------|
| **v1.0.0** | ✅ Production-ready. Public API is frozen. Breaking changes only in v2.0.0. Semantic versioning applies. |

---

## After v1.0.0 — What Comes Next

Once stable, version numbers follow [Semantic Versioning](https://semver.org/):

| Change Type | Version Bump | Example | What Changed |
|-------------|-------------|---------|--------------|
| **Bug fix** | Patch (`x.y.Z`) | 1.0.0 → 1.0.1 | Fixed a bug, no API changes |
| **New feature** | Minor (`x.Y.0`) | 1.0.1 → 1.1.0 | Added new capability, old code still works |
| **Breaking change** | Major (`X.0.0`) | 1.1.0 → 2.0.0 | Changed existing API, migration may be needed |

### Post-Stable Releases

| Version | Focus | Status |
|---------|-------|--------|
| **v1.0.1** | Bug fixes from post-release audit (witness verification, policy validation) | ✅ Shipped |
| **v1.1.0** | Eval expansion (26 scenarios, 11 threat categories, HTML reports) | ✅ Shipped |
| **v1.1.2** | Beta feedback fixes (CLI `--version`, doc links, extras) | ✅ Shipped |
| **v1.2.0** | Audit Storage System + Compliance (JSONL/SQLite/PostgreSQL backends, EU AI Act) | ✅ Shipped |
| **v1.3.0** | Subprocess sandbox (post-execution isolation, resource limits) | ✅ Shipped |
| **v1.4.0** | NER PII + sensitivity labels (`enforcecore[ner]`) | ✅ Shipped |
| **v1.5.0** | OpenTelemetry + Observability (Prometheus, OTLP, Grafana) | ✅ Shipped |
| **v1.6.0** | Multi-tenant + policy inheritance (`extends:` keyword) | 🔄 In Progress |
| **v1.7.0** | Remote policy server (signed policies, pull-only) | 📋 Planned |
| **v1.8.0** | Compliance reporting (EU AI Act / SOC2 / GDPR exports) | 📋 Planned |
| **v2.0.0** | Distributed enforcement for multi-agent architectures | 📋 Planned |

---

## How We Decide When to Move Between Stages

### Alpha → Beta Checklist

- [x] All known security findings from audit are fixed
- [x] No known data leaks (PII, secrets) under any code path
- [x] Thread safety verified under concurrent load
- [x] Policy cache properly invalidates on file changes
- [x] Sync and async paths share a single enforcement pipeline
- [x] Unicode evasion fully mitigated
- [x] All 1,510+ tests pass on Python 3.11, 3.12, 3.13

### Beta → Release Candidate Checklist

- [x] Public API surface finalized (30 core symbols)
- [x] All deprecated imports emit warnings for 1 release cycle
- [x] Complete API documentation published
- [x] Integration guides for top 3 agent frameworks
- [x] Performance benchmarks stable (<1ms enforcement overhead)
- [x] No new bugs reported in beta for 2+ weeks

### Release Candidate → Stable Checklist

- [x] Independent security review completed
- [x] No P0/P1 bugs open
- [x] Documentation reviewed by a non-contributor
- [x] Migration guide tested by an external user
- [x] Changelog complete and accurate
- [x] Legal review of all licenses and attributions

---

## FAQ

**Q: Can I use EnforceCore in my project?**
A: Yes! v1.0.0 is stable and production-ready. Install with `pip install enforcecore`
and pin to `enforcecore>=1.0.0,<2` for stability.

**Q: Will my code break when you release v1.1?**
A: No. We follow semantic versioning. Breaking changes only happen in v2.0.0.
The core `@enforce()` decorator and `Policy` class will not change.

**Q: How often do you release?**
A: Patch releases as needed for bug fixes. Minor releases every 1–2 months
for new features. See the [Roadmap](roadmap.md) for planned releases.

**Q: What if I find a bug?**
A: Open an issue at [github.com/akios-ai/EnforceCore/issues](https://github.com/akios-ai/EnforceCore/issues).
Bug reports are always welcome.

**Q: Is EnforceCore free?**
A: Yes. EnforceCore is open-source under the Apache 2.0 license. You can
use it commercially, modify it, and distribute it. See [LICENSE](../LICENSE)
for details.

---

*This document is updated with each release. Last updated: February 24, 2026 (v1.0.0 stable).*

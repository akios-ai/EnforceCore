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

**Current version: `1.0.23a1` (Alpha)**
**Published:** February 23, 2026 on [PyPI](https://pypi.org/project/enforcecore/)

### What "Alpha" Means for You

✅ **What works right now:**
- Full enforcement pipeline (`@enforce()` decorator)
- PII redaction (emails, phones, SSNs, credit cards, IPs)
- Secret scanning (AWS keys, GitHub tokens, API keys, etc.)
- Tool allow/deny lists
- Content rules (block dangerous patterns)
- Audit trail with Merkle-chain verification
- Policy-as-YAML configuration
- Async support
- 1,503 tests passing, 95%+ code coverage

⚠️ **What may change before stable:**
- Some internal APIs may be renamed or reorganized
- The number of symbols exported from `import enforcecore` will be reduced
- Performance optimizations are ongoing
- Some edge cases in error handling are being hardened

❌ **What you should NOT do yet:**
- Deploy to production without your own testing
- Depend on internal/undocumented APIs
- Assume the public API surface is frozen

---

## The Road to Stable (v1.0.0)

Here's the plan, release by release:

### Phase 1: Alpha Hardening (Now → ~March 2026)

| Release | Focus | Key Changes |
|---------|-------|-------------|
| **v1.0.21a1** | ⚠️ Security quick wins | Fix PII leak on fail_open path, log async hook errors, use public dataclass API *(code shipped; not on PyPI — superseded by v1.0.22a1)* |
| **v1.0.22a1** | ✅ Infrastructure | Policy cache with mtime invalidation, shared thread pool (no more per-call pools), larger audit seek window |
| **v1.0.23a1** | ✅ Release infra & CI | CI parity in release script, macOS-only test matrix, release.py hardening, security docs |
| **v1.0.24a1** | ⚡ Architecture | Refactor sync/async enforcement into shared pipeline, fix unicode normalization offset mapping |

### Phase 2: Beta (Target: April 2026)

| Release | Focus | Key Changes |
|---------|-------|-------------|
| **v1.0.25b1** | 📦 API stabilization | Reduce `__all__` from 110 to ~25 core symbols, move specialized types to submodules, add deprecation warnings |
| **v1.0.26b1** | 📖 Documentation | Complete API reference, migration guide for deprecated imports, integration guides for LangChain/CrewAI/AutoGen |
| **v1.0.27b1** | 🧪 Extended testing | Fuzz testing, property-based testing expansion, performance regression benchmarks |

### Phase 3: Release Candidate (Target: May 2026)

| Release | Focus | Key Changes |
|---------|-------|-------------|
| **v1.0.28rc1** | 🔍 Final audit | Independent security review, penetration testing of enforcement bypass scenarios |
| **v1.0.29rc2** | 🐛 Bug fixes only | Address anything found in rc1, final documentation review |

### Phase 4: Stable Release (Target: June 2026)

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

### Planned Post-Stable Work

| Version | Focus |
|---------|-------|
| **v1.1.0** | Framework-specific integrations (LangChain, CrewAI, AutoGen) as first-class plugins |
| **v1.2.0** | OpenTelemetry traces and metrics built into enforcement pipeline |
| **v1.3.0** | Policy composition (multiple YAML files merged with inheritance) |
| **v2.0.0** | Major architectural changes (if needed based on real-world usage) |

---

## How We Decide When to Move Between Stages

### Alpha → Beta Checklist

- [ ] All known security findings from audit are fixed
- [x] No known data leaks (PII, secrets) under any code path
- [x] Thread safety verified under concurrent load
- [x] Policy cache properly invalidates on file changes
- [ ] Sync and async paths share a single enforcement pipeline
- [ ] Unicode evasion fully mitigated
- [x] All 1,503+ tests pass on Python 3.11, 3.12, 3.13

### Beta → Release Candidate Checklist

- [ ] Public API surface finalized (~25 core symbols)
- [ ] All deprecated imports emit warnings for 1 release cycle
- [ ] Complete API documentation published
- [ ] Integration guides for top 3 agent frameworks
- [ ] Performance benchmarks stable (<1ms enforcement overhead)
- [ ] No new bugs reported in beta for 2+ weeks

### Release Candidate → Stable Checklist

- [ ] Independent security review completed
- [ ] No P0/P1 bugs open
- [ ] Documentation reviewed by a non-contributor
- [ ] Migration guide tested by an external user
- [ ] Changelog complete and accurate
- [ ] Legal review of all licenses and attributions

---

## FAQ

**Q: Can I use the alpha in my project today?**
A: Yes, but pin the exact version (`enforcecore==1.0.23a1`) and be prepared
to update your code when the API stabilizes.

**Q: Will my code break when you release beta?**
A: Possibly. We'll provide a migration guide and deprecation warnings
before removing anything. The core `@enforce()` decorator and `Policy` class
will not change.

**Q: How often do you release?**
A: During alpha, roughly every 1-2 weeks. During beta, every 2-4 weeks.
Release candidates only when we believe it's ready.

**Q: What if I find a bug?**
A: Open an issue at [github.com/akios-ai/EnforceCore/issues](https://github.com/akios-ai/EnforceCore/issues).
Alpha is exactly when we want to find bugs.

**Q: Is EnforceCore free?**
A: Yes. EnforceCore is open-source under the Apache 2.0 license. You can
use it commercially, modify it, and distribute it. See [LICENSE](../LICENSE)
for details.

---

*This document is updated with each release. Last updated: February 23, 2026.*

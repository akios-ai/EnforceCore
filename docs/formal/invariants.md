# Formal Invariants

This document specifies the formal properties that EnforceCore guarantees,
along with the property-based tests that verify them.  Every invariant
stated here is checked by [Hypothesis](https://hypothesis.readthedocs.io/)
on every CI run.

> **Note on verification methodology:** These invariants are specified using
> formal notation and verified *empirically* via property-based testing
> (Hypothesis), not mechanically proved via theorem provers.  Property-based
> testing provides high confidence by checking invariants against thousands
> of randomly generated inputs per CI run, but does not constitute a
> mathematical proof.

## Notation

| Symbol | Meaning |
|--------|---------|
| ∀ | "for all" — universally quantified |
| ∈ | "is an element of" |
| ∉ | "is not an element of" |
| ⟹ | "implies" |
| ≡ | "is equivalent to" |
| ∪ | set union |
| ⊇ | superset-or-equal |

---

## Policy Engine Properties (P1–P8)

### P1: Determinism

> ∀ valid policy *π*, ∀ tool call *t*:
> `evaluate(π, t)₁ ≡ evaluate(π, t)₂`

The same policy and tool name always produce the same decision.
No hidden state, no randomness.

**Test:** `tests/formal/test_prop_policy.py::TestPolicyDeterminism`

---

### P2: Deny Enforcement

> ∀ policy *π*, ∀ tool *t* ∈ `π.denied_tools`:
> `evaluate(π, t).decision = BLOCKED`

Any tool in the denied list is always blocked, regardless of the
allowed list.

**Sub-property (P2a):** The check is case-insensitive.

**Test:** `tests/formal/test_prop_policy.py::TestDeniedAlwaysBlocked`

---

### P3: Allowlist Enforcement

> ∀ policy *π* where `π.allowed_tools ≠ None`,
> ∀ tool *t* ∉ `π.allowed_tools`:
> `evaluate(π, t).decision = BLOCKED`

When an explicit allowlist exists, only listed tools may proceed.

**Converse (P3b):** ∀ *t* ∈ `π.allowed_tools` ∧ *t* ∉ `π.denied_tools` →
`evaluate(π, t).decision = ALLOWED`

**Test:** `tests/formal/test_prop_policy.py::TestAllowlistEnforcement`

---

### P4: Deny Priority

> ∀ tool *t* ∈ `π.denied_tools` ∩ `π.allowed_tools`:
> `evaluate(π, t).decision = BLOCKED`

Deny always wins over allow.  This prevents privilege escalation via
allowlist manipulation.

**Test:** `tests/formal/test_prop_policy.py::TestDenyPriority`

---

### P5: Open-by-Default

> ∀ policy *π* where `π.allowed_tools = None`,
> ∀ tool *t* ∉ `π.denied_tools`:
> `evaluate(π, t).decision = ALLOWED`

With no explicit allowlist, any tool not denied is allowed.

**Test:** `tests/formal/test_prop_policy.py::TestNullAllowlist`

---

### P6: Closed-on-Empty

> ∀ policy *π* where `π.allowed_tools = []`,
> ∀ tool *t*:
> `evaluate(π, t).decision = BLOCKED`

An empty allowed list blocks everything — there is no tool that
could match an empty set.

**Test:** `tests/formal/test_prop_policy.py::TestEmptyAllowlist`

---

### P7: Merge Union

> `merge(A, B).denied_tools ⊇ A.denied_tools ∪ B.denied_tools`

Merging two policies never drops denied tools.  The merged deny list
is the union of both source lists.

**Test:** `tests/formal/test_prop_policy.py::TestMergeDeniedUnion`

---

### P8: Decision Completeness

> ∀ policy *π*, ∀ tool *t*:
> `evaluate(π, t).decision ∈ {ALLOWED, BLOCKED}`

Every evaluation produces a definite outcome.  There is no "unknown"
or "maybe" state.

**Test:** `tests/formal/test_prop_policy.py::TestDecisionCompleteness`

---

## Merkle Chain Properties (M1–M5)

### M1: Hash Determinism

> ∀ entry *e*: `compute_hash(e)₁ ≡ compute_hash(e)₂`

Hashing is a pure function of the entry fields.

**Test:** `tests/formal/test_prop_merkle.py::TestHashDeterminism`

---

### M2: Hash Sensitivity

> ∀ entries *e₁*, *e₂* where *e₁*.tool_name ≠ *e₂*.tool_name:
> `compute_hash(e₁) ≠ compute_hash(e₂)`

Changing any field changes the hash.

**Test:** `tests/formal/test_prop_merkle.py::TestHashSensitivity`

---

### M3: Chain Validity

> ∀ *n* ≥ 1, ∀ sequence of *n* entries sealed sequentially:
> `verify_trail().is_valid = True`

Any number of honestly-produced entries always forms a valid chain.

**Test:** `tests/formal/test_prop_merkle.py::TestChainConstruction`

---

### M4: Tamper Detection

> ∀ valid chain, ∀ modification (field change, deletion, reorder):
> `verify_trail().is_valid = False`

Any modification to any entry in the chain is detected.

*Note:* Tail truncation (deleting only the last entry) is not
detectable by chain linkage alone without an external entry count
commitment.  This is a known limitation documented in
[threat-model.md](../threat-model.md).

**Test:** `tests/formal/test_prop_merkle.py::TestTamperDetection`

---

### M5: Append Stability

> ∀ chain of *n* entries, after appending entry *n+1*:
> entries 1..*n* are byte-identical.

Appending never modifies prior entries.

**Test:** `tests/formal/test_prop_merkle.py::TestChainRootStability`

---

## Redactor Properties (R1–R5)

### R1: Idempotency

> ∀ text *s*: `redact(redact(s)) ≡ redact(s)`

Redacting already-redacted text produces no further changes.

**Test:** `tests/formal/test_prop_redactor.py::TestRedactorIdempotency`

---

### R2: Completeness

> ∀ text *s* containing a known PII pattern *p*:
> *p* ∉ `redact(s).text`

Known PII is always removed from the output.

**Test:** `tests/formal/test_prop_redactor.py::TestRedactorCompleteness`

---

### R3: Safety

> ∀ text *s* without PII patterns:
> `redact(s).text ≡ s` ∧ `redact(s).count = 0`

Clean text passes through unmodified.

**Test:** `tests/formal/test_prop_redactor.py::TestRedactorSafety`

---

### R4: Detect–Redact Consistency

> ∀ text *s*: `|detect(s)| = redact(s).count`

The number of detected entities equals the redaction count.

**Test:** `tests/formal/test_prop_redactor.py::TestDetectRedactConsistency`

---

### R5: Strategy Independence

> ∀ redaction strategy *σ*, ∀ text *s*:
> `redact(s, σ).count` is the same across all strategies.

The detection logic is independent of the replacement strategy.

**Test:** `tests/formal/test_prop_redactor.py::TestStrategyIndependence`

---

## Enforcer Properties (E1–E4)

### E1: Fail-Closed

> ∀ denied tool *t*:
> `enforce_sync(f, tool_name=t)` raises `EnforcementViolation`

Denied tools are blocked at the enforcement layer, not just at
policy evaluation.

**Test:** `tests/formal/test_prop_enforcer.py::TestFailClosed`

---

### E2: Allowed Pass-Through

> ∀ allowed tool *t* (not denied):
> `enforce_sync(f, tool_name=t) = f()`

Allowed tools execute and return the original function result.

**Test:** `tests/formal/test_prop_enforcer.py::TestAllowedToolsSucceed`

---

### E3: Enforcement Idempotency

> ∀ tool *t*: `enforce(f, t)₁ ≡ enforce(f, t)₂`

Repeated enforcement of the same call yields the same outcome.

**Test:** `tests/formal/test_prop_enforcer.py::TestEnforcerIdempotency`

---

### E4: Internal Error Propagation

> When `fail_open = False`:
> ∀ internal `EnforceCoreError` → error is re-raised, call is blocked.

The default fail-closed behaviour never silently swallows errors.

**Test:** `tests/formal/test_prop_enforcer.py::TestInternalErrorFailClosed`

---

## Summary

| Category | Properties | Tests | Status |
|----------|-----------|-------|--------|
| Policy Engine | P1–P8 | 10 | ✅ All pass |
| Merkle Chain | M1–M5 | 8 | ✅ All pass |
| Redactor | R1–R5 | 8 | ✅ All pass |
| Enforcer | E1–E4 | 4 | ✅ All pass |
| **Total** | **22** | **30** | ✅ |

All properties are verified on every CI run via `pytest tests/formal/`.

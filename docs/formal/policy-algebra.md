# Policy Algebra

This document defines the algebraic properties of EnforceCore's policy
merge operation.  Understanding these properties is essential for
composing policies safely in multi-layer deployments.

## Definitions

A **policy** is a tuple:

$$
\pi = (N, V, D, A, R, \omega)
$$

where:

| Field | Type | Description |
|-------|------|-------------|
| $N$ | string | Policy name |
| $V$ | string | Policy version |
| $D$ | set⟨string⟩ | Denied tools (case-insensitive) |
| $A$ | set⟨string⟩ ∪ {⊥} | Allowed tools (⊥ = no restriction) |
| $R$ | record | Policy rules (rate limits, content rules, etc.) |
| $\omega$ | string | On-violation action ("block" or "log") |

## Merge Operation

The merge operation $\text{merge}(\pi_{\text{base}}, \pi_{\text{override}})$
produces a new policy $\pi'$ according to these rules:

### Scalar Fields (Override Wins)

$$
\pi'.N = \pi_{\text{override}}.N \qquad
\pi'.V = \pi_{\text{override}}.V \qquad
\pi'.\omega = \pi_{\text{override}}.\omega
$$

### Denied Tools (Union)

$$
\pi'.D = \text{lower}(\pi_{\text{base}}.D) \cup \text{lower}(\pi_{\text{override}}.D)
$$

The denied tools set is the **union** of both source sets, normalized
to lowercase.  This is the key security property — merging never
*removes* a denial.

### Allowed Tools (Override Wins)

$$
\pi'.A = \begin{cases}
  \pi_{\text{override}}.A & \text{if } \pi_{\text{override}}.A \neq \bot \\
  \pi_{\text{base}}.A & \text{otherwise}
\end{cases}
$$

### Denied Domains (Union)

$$
\pi'.D_{\text{domains}} = \pi_{\text{base}}.D_{\text{domains}} \cup \pi_{\text{override}}.D_{\text{domains}}
$$

### Block Patterns (Union with Override-First Dedup)

$$
\pi'.B = \text{dedup}(\pi_{\text{override}}.B \mathbin\Vert \pi_{\text{base}}.B)
$$

Override patterns take precedence when names collide.

### Rate Limits (Per-Tool Override)

$$
\pi'.R_{\text{per\_tool}}[t] = \begin{cases}
  \pi_{\text{override}}.R_{\text{per\_tool}}[t] & \text{if } t \in \pi_{\text{override}}.R_{\text{per\_tool}} \\
  \pi_{\text{base}}.R_{\text{per\_tool}}[t] & \text{otherwise}
\end{cases}
$$

---

## Algebraic Properties

### 1. Monotonic Denial (Proven)

$$
\forall\, \pi_1, \pi_2:\quad
\text{merge}(\pi_1, \pi_2).D \supseteq \pi_1.D \cup \pi_2.D
$$

Merging policies never removes denied tools.  This property is
critical for security: an administrator's denials cannot be
overridden by a downstream policy.

**Verified by:** `tests/formal/test_prop_policy.py::TestMergeDeniedUnion`

### 2. Denial Monotonicity Through Composition

$$
\forall\, \pi_1, \pi_2, \pi_3:\quad
\text{merge}(\pi_1, \text{merge}(\pi_2, \pi_3)).D \supseteq
\pi_1.D \cup \pi_2.D \cup \pi_3.D
$$

This follows from applying Property 1 twice:

1. $\text{merge}(\pi_2, \pi_3).D \supseteq \pi_2.D \cup \pi_3.D$
2. $\text{merge}(\pi_1, \text{merge}(\pi_2, \pi_3)).D \supseteq \pi_1.D \cup (\pi_2.D \cup \pi_3.D)$

### 3. Override Determinism

$$
\forall\, \pi_1, \pi_2:\quad
\text{merge}(\pi_1, \pi_2).N = \pi_2.N
\quad\land\quad
\text{merge}(\pi_1, \pi_2).V = \pi_2.V
$$

Scalar fields always take the override value.  This is deterministic
and not affected by the base policy's values.

### 4. Deny Priority Over Allow

$$
\forall\, t \in \pi.D \cap \pi.A:\quad
\text{evaluate}(\pi, t) = \text{BLOCKED}
$$

The enforcement engine checks denied tools **before** allowed tools.
This means that even if a tool appears in both lists, it is always
blocked.

**Verified by:** `tests/formal/test_prop_policy.py::TestDenyPriority`

---

## Evaluation Semantics

The `evaluate_pre_call` function implements a two-stage check:

```
evaluate(π, t):
    if lower(t) ∈ lower(π.D):
        return BLOCKED          ← Stage 1: deny check
    if π.A ≠ ⊥ and lower(t) ∉ lower(π.A):
        return BLOCKED          ← Stage 2: allow check
    return ALLOWED
```

This produces the following truth table:

| `t ∈ D` | `A = ⊥` | `t ∈ A` | **Decision** |
|:-------:|:-------:|:-------:|:------------:|
| ✓ | — | — | BLOCKED |
| ✗ | ✓ | — | ALLOWED |
| ✗ | ✗ | ✓ | ALLOWED |
| ✗ | ✗ | ✗ | BLOCKED |

---

## Conflict Resolution

When composing multiple policies (e.g., org → team → project), the
merge operation applies left to right:

```
final = merge(merge(org, team), project)
```

**Conflict resolution summary:**

| Field | Resolution | Security Impact |
|-------|-----------|-----------------|
| `denied_tools` | Union | ✅ Denials are additive — cannot be removed |
| `denied_domains` | Union | ✅ Domain blocks are additive |
| `allowed_tools` | Override wins | ⚠️ Override can widen or narrow access |
| `block_patterns` | Union (override-first) | ✅ Patterns are additive |
| `rate_limits` | Per-tool override | ⚠️ Override can relax limits |
| `name`, `version` | Override wins | Informational |
| `on_violation` | Override wins | ⚠️ Override can change to "log" |

### Security Implications

1. **Safe composability of denials:** Since `denied_tools` uses union,
   an organization-level denial **cannot** be overridden by a team or
   project policy.  This is the foundational security guarantee.

2. **Allowlist caution:** The override-wins semantics for `allowed_tools`
   means a downstream policy can widen access.  Organizations should
   enforce allowlists at the highest level and use denied tools for
   hard restrictions.

3. **Rate limit relaxation:** A downstream policy can override rate
   limits per tool.  Enforce minimum rate limits at the organization
   level through denied tools or monitoring.

---

## Edge Cases

### Empty Merge

$$
\text{merge}(\pi, \text{default}) \approx \pi
$$

Merging with a default (empty-rules) policy preserves all fields from
the base, except name and version which take the override values.

### Self-Merge

$$
\text{merge}(\pi, \pi).D = \pi.D
$$

Merging a policy with itself is idempotent for denied tools (union of
a set with itself).

### Cascade Example

Given three policies:

```yaml
# org.yaml
denied_tools: [dangerous_tool]
allowed_tools: null  # unrestricted

# team.yaml
denied_tools: [risky_tool]
allowed_tools: [search, browse, code_exec]

# project.yaml
denied_tools: []
allowed_tools: [search, browse]
```

The final merged policy:

```
denied_tools: [dangerous_tool, risky_tool]  # union of all
allowed_tools: [search, browse]             # project override wins
```

This means:
- `dangerous_tool` → BLOCKED (org denial persists)
- `risky_tool` → BLOCKED (team denial persists)
- `code_exec` → BLOCKED (project narrowed the allowlist)
- `search` → ALLOWED
- `browse` → ALLOWED

# Tool Selection Guide: When to Use What

A practical guide for choosing the right security tools for AI agent
deployments. EnforceCore is one layer in a defense-in-depth stack — this
guide helps you decide which other layers you need.

---

## Decision Tree

```
Is your agent running in production?
├── No (development/testing)
│   └── ✅ EnforceCore only
│       Sufficient for policy validation and testing.
│       Add container isolation before deploying to production.
│
└── Yes (production)
    │
    ├── Does the agent have network access?
    │   ├── Yes → ✅ EnforceCore + Container + Network Policy
    │   │         seccomp to block raw sockets,
    │   │         Kubernetes NetworkPolicy / firewall rules,
    │   │         EnforceCore network enforcement for tool-level control
    │   │
    │   └── No → ✅ EnforceCore + Container
    │             Isolated process, no network stack needed
    │
    ├── Does the agent handle PII?
    │   ├── Yes → ✅ EnforceCore PII redaction + encryption at rest
    │   │         EnforceCore redacts PII in tool I/O,
    │   │         OS-level encryption for audit logs,
    │   │         consider AppArmor to restrict log file access
    │   │
    │   └── No → Standard EnforceCore policy
    │
    ├── Is the agent untrusted (third-party, fine-tuned, user-provided)?
    │   ├── Yes → ✅ Full stack: gVisor/Firecracker + SELinux + EnforceCore
    │   │         Maximum isolation. Treat as hostile code.
    │   │         Default-deny at every layer.
    │   │
    │   └── No → ✅ EnforceCore + Container + seccomp
    │             Standard production stack
    │
    └── Are you subject to regulatory compliance (EU AI Act, SOC 2, etc.)?
        ├── Yes → ✅ EnforceCore audit trail + all layers documented
        │         Merkle-chained audit logs for tamper evidence,
        │         EnforceCore compliance mapping (docs/compliance/),
        │         document your defense-in-depth stack for auditors
        │
        └── No → Choose based on risk tolerance above
```

---

## Common Deployment Patterns

### Pattern 1: Simple Agent (Low Risk)

**Scenario:** Internal tool with trusted model, no PII, no external network.

```
Python process
  └── EnforceCore
      ├── Policy: allowed_tools only
      ├── Audit trail: enabled
      └── Rate limiting: optional
```

**Why this works:** The agent is trusted, the environment is controlled, and
the blast radius of a failure is low. EnforceCore prevents accidental
misuse and provides an audit trail.

### Pattern 2: Customer-Facing Agent (Medium Risk)

**Scenario:** Agent serves external users, has API access, handles some PII.

```
Docker container (--cap-drop=ALL, --read-only)
  ├── seccomp profile (minimal syscalls)
  └── Python process
      └── EnforceCore
          ├── Policy: strict allowed_tools, denied_tools
          ├── PII redaction: enabled
          ├── Cost budget: $X per session
          ├── Rate limiting: Y calls/minute
          ├── Network rules: allow specific APIs only
          └── Audit trail: Merkle-chained
```

**Why this works:** Container isolation limits blast radius. EnforceCore
provides semantic enforcement. Audit trail enables incident investigation.

### Pattern 3: Untrusted Agent (High Risk)

**Scenario:** Running third-party agent code, fine-tuned model, or
user-provided agent. Maximum risk.

```
Firecracker microVM / gVisor sandbox
  ├── SELinux / AppArmor profile (strict)
  ├── seccomp-bpf (whitelist only)
  ├── Network: isolated VLAN, egress filtered
  ├── Capabilities: none
  └── Container
      └── Python process
          ├── NeMo Guardrails (prompt safety)
          └── EnforceCore
              ├── Policy: default-deny everything
              ├── PII redaction: aggressive
              ├── Content rules: strict
              ├── Cost budget: minimal
              ├── Rate limiting: aggressive
              └── Audit trail: Merkle-chained, exported to SIEM
```

**Why this works:** Every layer assumes the layer above it has been
compromised. The agent cannot escape the container, cannot make unauthorized
syscalls, cannot access unauthorized files, and cannot invoke unauthorized
tools.

### Pattern 4: Multi-Agent System (Complex Risk)

**Scenario:** Multiple agents with different trust levels communicating
via a coordinator.

```
Kubernetes cluster
  ├── NetworkPolicy: per-pod isolation
  ├── Pod Security Standards: restricted
  └── Per-agent pods:
      ├── Agent A (trusted, network access)
      │   └── EnforceCore (Policy A: allow network tools)
      ├── Agent B (trusted, file access)
      │   └── EnforceCore (Policy B: allow file tools)
      └── Agent C (untrusted, minimal access)
          ├── gVisor runtime
          └── EnforceCore (Policy C: default-deny, read-only)
```

**Why this works:** Per-agent policy isolation prevents collusion.
Kubernetes NetworkPolicy prevents unauthorized inter-pod communication.
Each agent has exactly the permissions it needs, no more.

---

## Anti-Patterns

### ❌ EnforceCore as Sole Sandbox

```
# DON'T DO THIS IN PRODUCTION
Python process (no container, no OS hardening)
  └── EnforceCore
```

**Why it fails:** EnforceCore enforces at the Python level. A vulnerability
in the Python interpreter, a native extension, or a dependency could bypass
EnforceCore entirely. Always use OS-level isolation in production.

### ❌ OS-Level Only (No Runtime Enforcement)

```
# DON'T DO THIS
Docker container (hardened)
  └── Python process (no EnforceCore)
```

**Why it fails:** The container prevents process escape, but the agent can
still call any tool, leak PII, exceed cost budgets, and abuse rate limits.
OS-level tools cannot distinguish between legitimate and malicious tool calls.

### ❌ Prompt Safety Only

```
# DON'T DO THIS
LlamaGuard → LLM → Agent → Tools (no enforcement)
```

**Why it fails:** Prompt filters check LLM output, not agent actions.
An agent can produce "safe-looking" output that results in dangerous tool
calls. Prompt safety is necessary but not sufficient.

### ❌ Identical Policies for All Agents

```
# DON'T DO THIS
Agent A → EnforceCore (Policy: allow everything)
Agent B → EnforceCore (Policy: allow everything)
```

**Why it fails:** Violates least privilege. Each agent should have the
minimum permissions required for its task. Use per-agent policies.

---

## Quick Reference

| Question | Answer |
|---|---|
| Do I need EnforceCore? | Yes, if your agent calls external tools. |
| Do I need a container? | Yes, in production. Always. |
| Do I need SELinux/AppArmor? | Yes, for high-risk or untrusted agents. |
| Do I need seccomp? | Yes, in production containers. Minimal overhead. |
| Do I need prompt safety? | Yes, if the agent processes user input via LLM. |
| Can I skip a layer? | Each skipped layer is an unmitigated risk. |

---

## See Also

- [Defense-in-Depth Architecture](../defense-in-depth.md) — full layer diagram and threat coverage
- [Related Work: OS-Level Enforcement](../related-work.md#6-os-level-enforcement-complementary-not-competing) — detailed comparison
- [Attack Surface](attack-surface.md) — EnforceCore-specific threat model
- [EU AI Act Compliance](../compliance/eu-ai-act.md) — regulatory requirements

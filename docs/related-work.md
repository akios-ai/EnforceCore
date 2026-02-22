# Related Work

This document surveys existing approaches to AI agent safety and runtime
enforcement, and positions EnforceCore within the landscape.

---

## 1. The Problem Space

As AI agents gain the ability to call external tools — web APIs, databases,
file systems, code interpreters — a new class of safety concern emerges:
**what happens when an agent takes an action it shouldn't?**

Traditional approaches fall into two categories:

1. **Prompt-level guardrails** — instruct the LLM to be safe, then hope it
   complies. This is fundamentally unreliable because LLMs are stochastic,
   prompt-injectable, and cannot enforce hard constraints.

2. **Application-level checks** — developers manually add `if` statements
   around tool calls. This is error-prone, inconsistent, and impossible to
   audit at scale.

EnforceCore occupies a third position: **structural enforcement at the call
boundary**. Instead of asking the agent to be safe, EnforceCore makes unsafe
actions physically impossible by intercepting every tool call before execution.

---

## 2. Industry Tools

### 2.1 NVIDIA NeMo Guardrails

- **Approach:** Colang-based programmable rails that intercept LLM I/O.
  Defines topical, safety, and security rails via a declarative language.
- **Strengths:** Mature, NVIDIA-backed, supports input/output/dialog rails.
- **Limitations:** Focused on LLM conversation flow, not tool call enforcement.
  No audit trail. No cost/resource limits. Rails are advisory — they filter
  LLM output but don't prevent the underlying action.
- **Key difference from EnforceCore:** NeMo Guardrails sits between the user
  and the LLM; EnforceCore sits between the agent and the tools. These are
  complementary layers.

**References:**

- Rebedea, T., Dinu, R., Sreedhar, M., Parisien, C., & Cohen, J. (2023).
  NeMo Guardrails: A Toolkit for Controllable and Safe LLM Applications with
  Programmable Rails. *arXiv preprint arXiv:2310.10501*.

### 2.2 Guardrails AI

- **Approach:** Python library for validating LLM outputs against a schema.
  Uses "validators" (regex, ML models, API calls) to check outputs.
- **Strengths:** Large validator hub, Pydantic integration, retry mechanisms.
- **Limitations:** Output validation only — does not enforce tool access,
  cost budgets, or rate limits. No audit trail. No enforcement at the call
  boundary.
- **Key difference from EnforceCore:** Guardrails AI validates *what the LLM says*;
  EnforceCore enforces *what the agent does*.

### 2.3 Meta LlamaGuard

- **Approach:** Fine-tuned Llama model that classifies inputs/outputs as safe
  or unsafe according to a safety taxonomy.
- **Strengths:** Multilingual, customizable taxonomy, strong on content safety.
- **Limitations:** Requires an inference call per check (~100ms+ latency).
  Classification-based (not deterministic). No tool-level enforcement.
- **Key difference from EnforceCore:** LlamaGuard is a content classifier;
  EnforceCore is a runtime enforcer. LlamaGuard tells you *if* something
  is unsafe; EnforceCore *prevents* the unsafe action.

**References:**

- Inan, H., Upasani, K., Chi, J., Rungta, R., Iyer, K., Mao, Y., et al. (2023).
  Llama Guard: LLM-based Input-Output Safeguard for Human-AI Conversations.
  *arXiv preprint arXiv:2312.06674*.

### 2.4 Rebuff

- **Approach:** Multi-layered prompt injection detection (heuristic, LLM-based,
  vector database).
- **Strengths:** Specifically targets prompt injection attacks.
- **Limitations:** Single-purpose (prompt injection only). No policy engine,
  no audit trail, no resource enforcement.
- **Key difference from EnforceCore:** Rebuff detects one specific attack vector;
  EnforceCore provides comprehensive enforcement across all tool interactions.

### 2.5 LangChain / LangGraph Safety

- **Approach:** Framework-level callbacks and conditional edges for safety checks.
- **Strengths:** Native integration with the LangChain ecosystem.
- **Limitations:** Framework-specific. Safety logic is interleaved with application
  logic. No formal audit trail. No policy-as-code separation.
- **Key difference from EnforceCore:** EnforceCore is framework-agnostic and
  provides adapters for LangGraph, CrewAI, and AutoGen without requiring
  changes to the framework code.

---

## 3. Academic Foundations

### 3.1 Runtime Verification

Runtime verification (RV) monitors program execution against formal
specifications. EnforceCore applies RV principles to AI agent tool calls.

- Leucker, M., & Schallhart, C. (2009). A brief account of runtime
  verification. *The Journal of Logic and Algebraic Programming*, 78(5),
  293–303.
- Havelund, K., & Goldberg, A. (2005). Verify your runs. *Verified Software:
  Theories, Tools, Experiments*, LNCS 4171, 374–383.

### 3.2 Reference Monitors

The reference monitor concept (Anderson, 1972) requires that security
enforcement be: (1) tamperproof, (2) always invoked, and (3) small enough
to verify. EnforceCore's decorator-based enforcement aims to satisfy these
properties at the Python level.

- Anderson, J. P. (1972). Computer Security Technology Planning Study.
  *Technical Report ESD-TR-73-51*, Air Force Electronic Systems Division.

### 3.3 Agent Containment

The AI containment problem asks: how do we ensure an AI system operates
within intended boundaries? EnforceCore provides a practical engineering
answer for tool-calling agents.

- Armstrong, S., Sandberg, A., & Bostrom, N. (2012). Thinking Inside the
  Box: Controlling and Using an Oracle AI. *Minds and Machines*, 22(4),
  299–324.
- Babcock, J., Kramár, J., & Yampolskiy, R. V. (2016). The AGI Containment
  Problem. *Artificial General Intelligence*, LNCS 9782, 53–63.

### 3.4 Information Flow Control

EnforceCore's PII redaction pipeline implements a form of information flow
control — preventing sensitive data from flowing through untrusted channels.

- Sabelfeld, A., & Myers, A. C. (2003). Language-based information-flow
  security. *IEEE Journal on Selected Areas in Communications*, 21(1), 5–19.
- Myers, A. C., & Liskov, B. (1997). A Decentralized Model for Information
  Flow Control. *ACM Symposium on Operating Systems Principles (SOSP)*.

### 3.5 Audit and Accountability

Merkle-chained audit trails provide tamper-evident logging — any modification
to a past entry breaks the hash chain and is detectable.

- Merkle, R. C. (1987). A Digital Signature Based on a Conventional
  Encryption Function. *Advances in Cryptology — CRYPTO '87*, LNCS 293.
- Crosby, S. A., & Wallach, D. S. (2009). Efficient Data Structures for
  Tamper-Evident Logging. *USENIX Security Symposium*.

### 3.6 AI Regulation

The EU AI Act (2024) establishes legal requirements for AI systems,
including risk management (Article 9), transparency (Article 13), human
oversight (Article 14), and technical robustness (Article 15). EnforceCore's
policy engine, audit trail, and enforcement pipeline directly address these
requirements.

- European Parliament and Council. (2024). Regulation (EU) 2024/1689
  laying down harmonised rules on artificial intelligence (AI Act).
  *Official Journal of the European Union*.
- Smuha, N. A. (2021). From a "Race to AI" to a "Race to AI Regulation":
  Regulatory Competition for Artificial Intelligence. *Law, Innovation and
  Technology*, 13(1), 57–84.

---

## 4. Positioning: Where EnforceCore Fits

| Dimension | NeMo Guardrails | Guardrails AI | LlamaGuard | Rebuff | **EnforceCore** |
|---|---|---|---|---|---|
| **Enforcement point** | LLM I/O | LLM output | LLM I/O | LLM input | **Tool call boundary** |
| **Deterministic** | Partial | Partial | No (ML) | Partial | **Yes** |
| **Tool access control** | No | No | No | No | **Yes** |
| **PII redaction** | No | Validators | No | No | **Yes (regex + secrets)** |
| **Audit trail** | No | No | No | No | **Yes (Merkle chain)** |
| **Cost/resource limits** | No | No | No | No | **Yes** |
| **Rate limiting** | No | No | No | No | **Yes** |
| **Network enforcement** | No | No | No | No | **Yes** |
| **Framework-agnostic** | No | Partial | Yes | Yes | **Yes** |
| **Policy-as-code** | Colang | RAIL XML | Taxonomy | Config | **YAML + Pydantic** |
| **Latency** | ~50ms | ~10ms | ~100ms+ | ~50ms | **< 1ms** (policy only) |
| **EU AI Act alignment** | No | No | No | No | **Designed for it** |

### Key insight

These tools are **complementary**, not competitive:

```
User → [NeMo Guardrails / LlamaGuard] → LLM → Agent → [EnforceCore] → Tools
       ↑                                                     ↑
       Content safety                              Structural enforcement
       (what the LLM says)                       (what the agent does)
```

EnforceCore is the **last line of defense** — the enforcement layer that
ensures the agent's actual behavior matches its intended behavior, regardless
of what the LLM produces.

---

## 5. Open Research Questions

EnforceCore's architecture raises several research questions that we welcome
collaboration on:

1. **Optimal policy composition in multi-agent hierarchies** — When agents
   delegate to sub-agents, how should policies compose? What are the
   algebraic properties of policy merge?

2. **Information-flow control at agent boundaries** — How to formally verify
   that PII cannot flow through an enforcement boundary even via indirect
   channels (timing, error messages, etc.)?

3. **Runtime verification of temporal properties** — Can we express and
   enforce temporal safety properties (e.g., "tool A must be called before
   tool B") using LTL/CTL over agent execution traces?

4. **Quantitative enforcement** — Instead of binary allow/block, can we
   support probabilistic policy decisions with risk budgets?

5. **Adversarial robustness of pattern-based detection** — What is the
   false-negative rate of regex-based PII detection under adversarial
   evasion (homoglyphs, encoding, etc.)?

---

## 6. OS-Level Enforcement: Complementary, Not Competing

EnforceCore operates at the **application semantic layer** — it understands
"tool calls", "PII", and "agent intent." OS-level enforcement mechanisms
operate at the **kernel/syscall layer** — they understand file descriptors,
network sockets, and process capabilities. These are fundamentally different
enforcement points, and both are necessary for defense-in-depth.

### 6.1 SELinux (Type Enforcement)

- **Layer:** Kernel (Linux Security Module)
- **Model:** Mandatory Access Control (MAC) via type labels. Every process,
  file, socket, and port is assigned a security context (type). Policy rules
  define which types can interact.
- **Strengths:** Extremely fine-grained. Can prevent a compromised process
  from accessing files it shouldn't touch, even if running as root.
- **Limitations:** Operates on syscalls and kernel objects — has no concept of
  "this is a tool call from an AI agent" or "this output contains PII."
  Policy complexity is notoriously high (hundreds of thousands of rules in
  reference policy).
- **Relationship to EnforceCore:** SELinux constrains the Python process
  running the agent. EnforceCore constrains what the agent does within that
  process. A compromised agent that EnforceCore blocks at the tool level
  would also be blocked by SELinux at the syscall level — defense-in-depth.

**References:**

- Smalley, S., Vance, C., & Salamon, W. (2001). Implementing SELinux as a
  Linux Security Module. *NSA Technical Report*.
- Spencer, R., Smalley, S., Loscocco, P., Hibler, M., Andersen, D., &
  Lepreau, J. (2000). The Flask Security Architecture: System Support for
  Diverse Security Policies. *USENIX Security Symposium*.

### 6.2 AppArmor (Path-Based MAC)

- **Layer:** Kernel (Linux Security Module)
- **Model:** Path-based MAC. Profiles restrict which file paths, network
  operations, and capabilities a program can use.
- **Strengths:** Simpler than SELinux. Profile per application, human-readable
  rules. Widely deployed (Ubuntu default).
- **Limitations:** Path-based enforcement can be bypassed via hard links or
  mount manipulation. No semantic understanding of application-level actions.
- **Relationship to EnforceCore:** AppArmor restricts the agent process's
  file and network access at the OS level. EnforceCore restricts which
  *logical tools* the agent can invoke. An agent denied network access by
  AppArmor cannot exfiltrate data regardless of EnforceCore's policy, and
  vice versa.

**References:**

- Bauer, M. (2006). Paranoid Penguin: AppArmor in Ubuntu. *Linux Journal*,
  2006(148).

### 6.3 seccomp-bpf (Syscall Filtering)

- **Layer:** Kernel (syscall boundary)
- **Model:** BPF programs that filter syscalls by number and argument values.
  Used heavily in container runtimes (Docker, gVisor).
- **Strengths:** Very low overhead. Deterministic. Reduces kernel attack surface.
- **Limitations:** Operates on raw syscall numbers — cannot distinguish between
  a file write that encrypts user data (ransomware) and a file write that
  saves a report (legitimate). No application-level semantics.
- **Relationship to EnforceCore:** seccomp blocks dangerous syscalls
  (e.g., `ptrace`, `mount`). EnforceCore blocks dangerous tool invocations
  (e.g., `execute_shell`, `delete_file`). Both are deterministic, both are
  low-overhead, but they enforce at different abstraction levels.

**References:**

- Edge, J. (2015). A seccomp overview. *LWN.net*.
- Drewry, W. (2012). SECure COMPuting with filters. *Linux Kernel
  Documentation*.

### 6.4 Linux Capabilities

- **Layer:** Kernel (process privilege decomposition)
- **Model:** Decomposes root privilege into ~40 individual capabilities
  (e.g., `CAP_NET_RAW`, `CAP_SYS_ADMIN`). Processes run with minimal
  capability sets.
- **Strengths:** Fine-grained privilege control without full root.
- **Limitations:** Binary per-capability — cannot express "allow network
  access to api.example.com but not to evil.com." No semantic awareness.
- **Relationship to EnforceCore:** Capabilities restrict what the process
  *can* do at the OS level. EnforceCore restricts what the agent *is allowed*
  to do at the application level. Dropping `CAP_NET_RAW` prevents all raw
  sockets; EnforceCore's network rules can allow `api.openai.com` while
  blocking `evil.com`.

### 6.5 Comparison Table

| Dimension | SELinux | AppArmor | seccomp-bpf | Capabilities | **EnforceCore** |
|---|---|---|---|---|---|
| **Layer** | Kernel (LSM) | Kernel (LSM) | Kernel (syscall) | Kernel (process) | **Application (Python)** |
| **Enforcement target** | Kernel objects | File paths | Syscall numbers | Privilege bits | **Tool calls** |
| **Granularity** | Type labels | Path patterns | Syscall + args | 40 capabilities | **Per-tool, per-agent** |
| **Semantic awareness** | None | None | None | None | **PII, cost, content** |
| **Policy model** | Type Enforcement | Path profiles | BPF programs | Capability sets | **YAML + Pydantic** |
| **Overhead** | ~2-5% | ~1-3% | < 1% | Negligible | **< 1ms per call** |
| **Agent-aware** | No | No | No | No | **Yes** |
| **Audit trail** | AVC denials | Audit log | Kill/ERRNO | No | **Merkle-chained** |
| **PII detection** | No | No | No | No | **Yes** |
| **Cost/rate limits** | No | No | No | No | **Yes** |

### 6.6 The Complementary Model

```
┌─────────────────────────────────────────────────────┐
│  Prompt Layer    │ NeMo Guardrails / LlamaGuard     │  Content safety
├──────────────────┼──────────────────────────────────-┤
│  Runtime Layer   │ EnforceCore                       │  Tool enforcement, PII, audit
├──────────────────┼──────────────────────────────────-┤
│  Container Layer │ Docker / Kubernetes / gVisor       │  Process isolation
├──────────────────┼──────────────────────────────────-┤
│  OS Layer        │ SELinux / AppArmor / seccomp       │  Kernel-level MAC
├──────────────────┼──────────────────────────────────-┤
│  Hardware Layer  │ TPM / SGX / TrustZone              │  Hardware root of trust
└─────────────────────────────────────────────────────┘
```

Each layer catches threats that others miss:

- **Hardware** catches physical tampering and firmware attacks
- **OS/Kernel** catches syscall-level exploitation and privilege escalation
- **Container** catches process escape and resource abuse
- **Runtime (EnforceCore)** catches agent-level policy violations, PII leakage,
  tool abuse, and cost overruns
- **Prompt** catches unsafe LLM outputs and prompt injection

**No single layer is sufficient.** EnforceCore is designed to be deployed
alongside OS-level enforcement, not instead of it. See
[Defense-in-Depth Architecture](defense-in-depth.md) for deployment guidance.

---

## Citation

If you use EnforceCore in your research, please cite:

```bibtex
@software{enforcecore2026,
  title = {EnforceCore: Runtime Enforcement Layer for Agentic AI Systems},
  author = {{AKIOUD AI}},
  year = {2026},
  url = {https://github.com/akios-ai/EnforceCore},
  license = {Apache-2.0}
}
```

See also [CITATION.cff](../CITATION.cff) for machine-readable citation metadata.

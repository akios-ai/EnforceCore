# EnforceCore — Vision

## The Problem

The future of AI is agentic. Autonomous systems that act, use tools, call APIs, access files, and make decisions at scale. Every major framework — LangGraph, CrewAI, AutoGen, Semantic Kernel — is racing to build more capable agents.

But almost nobody is building the **control layer**.

Today, if an agent calls a tool, there is no standard way to:
- Enforce what it's allowed to do **before** the call executes
- Verify what it **actually did** after the call returns
- Prove to a regulator or auditor that violations were **structurally impossible**

Most "safety" solutions in the agent space are prompt-level guardrails — suggestions to the LLM that can be bypassed, ignored, or jailbroken. They operate at the wrong layer.

**EnforceCore operates at the runtime boundary — the only layer that cannot be bypassed.**

## What EnforceCore Is

EnforceCore is a **lightweight, modular, open-source runtime enforcement framework** for any Python-based agentic system.

It provides **mandatory policy enforcement at every external call boundary** — tool calls, API calls, file access, network access, subprocess execution — so that violations become structurally impossible, not just discouraged.

### It is:
- A **foundational primitive** — like a secure runtime for agents
- **Framework-agnostic** — works with LangGraph, CrewAI, AutoGen, or plain Python
- **Policy-driven** — declarative YAML + Pydantic policies, not hardcoded rules
- **Verifiable** — tamper-proof Merkle audit trails for every enforced call
- **Lightweight** — designed for minimal overhead in production workloads

### It is NOT:
- A prompt-level guardrail (those can be bypassed)
- A monitoring/observability tool (we enforce, not just observe)
- An agent framework (we protect agents, not build them)
- A product or commercial offering (Apache 2.0, genuinely open)

## Why This Matters Now

### 1. The EU AI Act is real
High-risk AI systems must demonstrate technical safeguards at runtime. "We told the LLM to be safe" is not a compliance strategy. EnforceCore provides **measurable, provable, auditable enforcement** that regulators can verify.

### 2. Enterprise trust requires proof
Companies deploying agents internally (HR, finance, legal, customer support) need guarantees that agents cannot exfiltrate data, exceed cost budgets, or access unauthorized resources. EnforceCore provides that guarantee at the runtime level.

### 3. Multi-agent systems are ungovernable today
When Agent A calls Agent B which calls Agent C which calls a tool — who enforces the rules? Currently, nobody. EnforceCore sits at every boundary in that chain.

### 4. Researchers need a common foundation
There is no standard framework for studying runtime verification, sandboxing, or formal guarantees in agentic systems. EnforceCore aims to become that common base — reproducible, extensible, and well-documented.

## Core Principles

1. **Enforce, don't suggest** — Policies are mandatory, not advisory. If a call violates policy, it is blocked. Period.

2. **Boundary-first** — Enforcement happens at the call boundary (the moment before a tool/API/resource is accessed), not inside the LLM or after the fact.

3. **Verify, don't trust** — Every enforced call produces a cryptographic audit entry. The full trail is Merkle-tree verifiable.

4. **Minimal by default** — The framework should be easy to adopt (3-5 lines of code), lightweight in production, and simple to understand.

5. **Framework-agnostic** — No lock-in to any specific agent framework. Works everywhere Python runs.

6. **Open and honest** — Apache 2.0 license. No hidden commercial agenda in the core. Real contributions welcome.

## What Success Looks Like

**Near-term (v1.0.x):**
- Developers can protect any tool-calling agent with a decorator and a YAML policy file
- The framework is clean, tested, documented, and genuinely useful
- A small community of researchers and developers finds it valuable

**Medium-term:**
- Official adapters for all major agent frameworks
- Used as a research baseline for papers on agent safety, runtime verification, and compliance
- Companies adopt it for EU AI Act compliance without rewriting their stack

**Long-term:**
- EnforceCore becomes the standard enforcement layer for agentic systems
- A community-driven Policy Hub of reusable, audited policies
- "EnforceCore Certified" as a trust signal for safe agent deployments

## Relationship to AKIOS

EnforceCore was born from the enforcement engine inside [AKIOS](https://github.com/akios-ai/akios), a production runtime for secure multi-agent systems.

The core enforcement concepts were extracted into this independent, general-purpose framework so they can benefit the entire ecosystem — not just one product.

- **EnforceCore** = the open foundation (Apache 2.0, general-purpose, researcher-friendly)
- **AKIOS** = a production system built on top of EnforceCore (open core + pro features)

This separation is intentional: security mechanisms should be transparent, auditable, and community-hardened.

# Contributors

Thank you to everyone who has contributed to EnforceCore.

---

## Core Team

| Contributor | Role |
|---|---|
| **AKIOUD AI** | Project creator, architecture, core implementation |

---

## How to Contribute

We welcome contributions of all kinds:

- 🐛 **Bug reports** — open a GitHub Issue with reproduction steps
- 💡 **Feature requests** — open a GitHub Issue with motivation and use case
- 🔧 **Code contributions** — see [CONTRIBUTING.md](CONTRIBUTING.md) for setup and workflow
- 📄 **Documentation** — improvements to docs, examples, and docstrings
- 🔬 **Research** — academic collaboration on open research questions (see
  [docs/related-work.md](docs/related-work.md#5-open-research-questions))
- 🌍 **Translations** — localization of documentation

All contributors are expected to follow our
[Code of Conduct](CODE_OF_CONDUCT.md).

---

## Acknowledgements

EnforceCore builds on a foundation of prior work in computer science and AI safety.
We are grateful to the researchers and practitioners whose work made this possible:

### Academic Foundations

- **Runtime Verification** — Leucker & Schallhart (2009), Havelund & Goldberg (2005)
  for foundational RV theory that underpins the enforcement pipeline
- **Reference Monitors** — James P. Anderson (1972) for the reference monitor concept
  (tamperproof, always-invoked, verifiable enforcement)
- **Information Flow Control** — Sabelfeld & Myers (2003), Myers & Liskov (1997)
  for the IFC model that informs PII redaction boundaries
- **Audit Trail Integrity** — Merkle (1987), Crosby & Wallach (2009) for
  Merkle-tree tamper evidence applied to the audit chain
- **Agent Containment** — Armstrong, Sandberg & Bostrom (2012), Babcock et al. (2016)
  for framing the containment problem EnforceCore addresses

### Design Feedback

- **Prof. Dan S. Wallach** (Rice University) — direct design guidance on
  tamper-evidence mitigations for the audit trail, including OS-enforced
  append-only files (`chattr +a`) and hash-only remote witnesses. Co-author
  of Crosby & Wallach (2009), the paper that informs EnforceCore’s Merkle-chained
  audit engine.
### Research Collaboration

- **Prof. Andrei Sabelfeld** (Chalmers University of Technology) — information-flow
  control expertise. Co-author of the definitive IFC survey with Andrew Myers (2003).
  Connected EnforceCore's redaction pipeline to the broader IFC research landscape
  and directed further collaboration through his research group.
- **Dr. Sandro Stucki** (Chalmers University of Technology, Sabelfeld group) —
  identified EnforceCore's PII redaction as a **data minimization** mechanism
  (connected to trigger-action platform work / LazyTAP). Posed the key research
  question on sensitivity label inference for AI agent tool calls. Referenced
  AirGapAgent (CCS 2024) as a complementary approach. His feedback directly shaped
  the v1.3.0 sensitivity labels design.
### Evaluation Methodology

- **Prof. Valérie Viet Triem Tong** (CentraleSupélec, IRISA/PIRAT) — the adversarial
  evaluation approach (ransomware-like containment scenarios, SELinux/AppArmor
  comparison methodology) was directly inspired by her feedback on defining
  realistic threat models and convincing evaluation strategies

### Industry Tools

- **Pydantic** — for the policy model and validation layer
- **structlog** — for structured, machine-readable enforcement logs
- **Microsoft Presidio** — design inspiration for PII detection patterns
- **OpenTelemetry** — for the observability integration layer

### Regulatory Guidance

- **EU AI Act (2024)** — Articles 9, 13, 14, 15 directly shaped the policy engine,
  audit trail, and enforcement pipeline design
- **NIST AI RMF (2023)** — risk management framework that informed the
  threat model and evaluation suite

Full citations and academic references are in [docs/related-work.md](docs/related-work.md).

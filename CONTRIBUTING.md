# Contributing to EnforceCore

Thank you for your interest in contributing to EnforceCore. This document explains how to contribute effectively.

## Code of Conduct

All contributors are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).
Be respectful, constructive, and professional. We're building a security-critical tool — code quality and honest technical discussion matter more than speed.

## How to Contribute

### Reporting Issues

- **Security vulnerabilities:** Email security@akios.ai privately. Do NOT open a public issue.
- **Bugs:** Open a GitHub issue with a minimal reproduction case.
- **Feature requests:** Open a GitHub issue with a clear description of the use case.

### Submitting Code

1. **Fork the repository** and create a branch from `dev`:
   ```bash
   git checkout dev
   git checkout -b feat/your-feature
   ```

2. **Write your code** following the standards in [dev-guide.md](docs/dev-guide.md)

3. **Write tests** for all new functionality:
   - New policy rules → test in `tests/core/test_policy.py`
   - New redaction categories → test in `tests/redactor/test_engine.py`
   - New integrations → test in `tests/integrations/`

4. **Run the full check suite:**
   ```bash
   ruff check .
   ruff format --check .
   mypy enforcecore/
   pytest --cov=enforcecore
   ```

5. **Open a Pull Request** against the `dev` branch with:
   - Clear description of what changed and why
   - Link to the related issue (if any)
   - Confirmation that tests pass

### What We're Looking For

**High-value contributions:**
- New adversarial scenarios for the evaluation suite
- New PII entity recognizers (e.g., medical record numbers, passport IDs)
- Framework integration adapters (Semantic Kernel, LlamaIndex, etc.)
- Performance benchmarks and optimizations
- Documentation improvements and tutorials
- Bug fixes in enforcement paths (these are security-critical)

**Lower priority (but welcome):**
- Cosmetic improvements
- Additional logging/output formats
- Tooling improvements

### What We Won't Accept

- Changes that make enforcement fail open (let calls through when they should be blocked)
- Hard dependencies on specific agent frameworks in the core package
- Breaking changes to the public API without discussion
- Code without tests
- Code without type annotations

## Development Setup

See [dev-guide.md](docs/dev-guide.md) for full setup instructions.

Quick start:
```bash
git clone git@github.com:akios-ai/EnforceCore.git
cd EnforceCore
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Adding a New Adversarial Scenario (Evaluation Suite)

This is one of the most valuable contributions you can make.

1. Create a new file in `eval/scenarios/`:
   ```python
   # eval/scenarios/my_scenario.py
   from enforcecore.eval import Scenario, ScenarioResult

   class MyMaliciousScenario(Scenario):
       name = "data-exfiltration-via-dns"
       description = "Agent attempts to exfiltrate data via DNS queries"
       severity = "high"

       async def run(self, enforcer) -> ScenarioResult:
           # Implement the attack attempt
           # Return whether enforcement caught it
           ...
   ```

2. Add a test in `tests/eval/`
3. Add the scenario to the registry in `eval/scenarios/__init__.py`

## Adding a Framework Integration

1. Create `enforcecore/integrations/your_framework.py`
2. Implement the adapter (see `base.py` for the interface)
3. Add an example in `examples/your_framework_example.py`
4. Add a test in `tests/integrations/`
5. **Important:** The framework must be an optional dependency, not a hard requirement

## Licensing

By contributing to EnforceCore, you agree that your contributions will be licensed under the Apache 2.0 License.

## Questions?

Open a GitHub Discussion or reach out to the maintainers. We're happy to help you get started.

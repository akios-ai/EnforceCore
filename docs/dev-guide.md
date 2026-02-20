# EnforceCore — Developer Guide

## Project Structure

```
enforcecore/
├── enforcecore/                # Main package
│   ├── __init__.py             # Public API exports
│   ├── core/                   # Core enforcement engine
│   │   ├── __init__.py
│   │   ├── types.py            # Shared types, enums, dataclasses
│   │   ├── config.py           # Global configuration (pydantic-settings)
│   │   ├── policy.py           # Policy models + engine
│   │   └── enforcer.py         # Main enforcer (coordinator)
│   ├── redactor/               # PII redaction (v1.0.1+)
│   │   ├── __init__.py
│   │   ├── engine.py           # Presidio-based detection + redaction
│   │   └── strategies.py       # Redaction strategies (mask, hash, etc.)
│   ├── auditor/                # Merkle audit trail (v1.0.2+)
│   │   ├── __init__.py
│   │   ├── merkle.py           # Merkle tree implementation
│   │   ├── logger.py           # Audit log writer (JSONL)
│   │   └── verifier.py         # Trail integrity verification
│   ├── guard/                  # Resource limits + kill switch (v1.0.3+)
│   │   ├── __init__.py
│   │   ├── platform.py         # Platform detection + abstraction
│   │   ├── resource.py         # Resource limits (cross-platform)
│   │   ├── killswitch.py       # Hard termination
│   │   └── sandbox_linux.py    # Optional seccomp/cgroups (Linux only)
│   ├── integrations/           # Framework adapters (v1.0.4+)
│   │   ├── __init__.py
│   │   ├── base.py             # Base adapter interface
│   │   ├── langgraph.py
│   │   ├── crewai.py
│   │   └── autogen.py
│   └── cli/                    # CLI commands (v1.0.2+)
│       ├── __init__.py
│       └── main.py
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Shared fixtures
│   ├── core/
│   │   ├── test_policy.py
│   │   ├── test_enforcer.py
│   │   └── test_types.py
│   ├── redactor/
│   │   └── test_engine.py
│   ├── auditor/
│   │   ├── test_merkle.py
│   │   └── test_verifier.py
│   ├── guard/
│   │   └── test_resource.py
│   └── integrations/
│       └── test_langgraph.py
├── examples/                   # Working examples
│   ├── quickstart.py
│   ├── langgraph_example.py
│   ├── crewai_example.py
│   ├── autogen_example.py
│   └── policies/
│       ├── default.yaml
│       ├── strict.yaml
│       └── permissive.yaml
├── eval/                       # Evaluation suite (v1.0.5+)
│   ├── scenarios/
│   ├── harness.py
│   └── report.py
├── docs/                       # Documentation
│   ├── vision.md
│   ├── architecture.md
│   ├── roadmap.md
│   ├── api-design.md
│   ├── tech-stack.md
│   ├── dev-guide.md
│   └── contributing.md
├── .github/
│   └── workflows/
│       └── ci.yml              # GitHub Actions CI
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
└── CHANGELOG.md
```

## Setting Up the Development Environment

### Prerequisites
- Python 3.11+ (3.12+ recommended)
- Git
- macOS or Linux (Windows works for core, limited Guard support)

### Setup

```bash
# Clone the repository
git clone git@github-akiosai:akios-ai/EnforceCore.git
cd EnforceCore

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with all dev dependencies
pip install -e ".[dev]"

# Verify setup
python -c "import enforcecore; print(enforcecore.__version__)"
```

### Using Hatch (alternative)

```bash
# Install hatch if you don't have it
pip install hatch

# Create environment and install dependencies
hatch env create

# Run inside the hatch environment
hatch run python -c "import enforcecore; print(enforcecore.__version__)"
```

## Development Workflow

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=enforcecore --cov-report=term-missing

# Run specific module tests
pytest tests/core/test_policy.py

# Run only fast tests (skip slow integration tests)
pytest -m "not slow"

# Run async tests
pytest tests/core/test_enforcer.py -v
```

### Code Quality

```bash
# Lint and format
ruff check .
ruff format .

# Type checking
mypy enforcecore/

# Fix auto-fixable lint issues
ruff check --fix .
```

### Pre-commit Checklist

Before every commit, ensure:
1. `ruff check .` — no lint errors
2. `ruff format --check .` — code is formatted
3. `mypy enforcecore/` — no type errors
4. `pytest` — all tests pass
5. If you added a new public API, update `enforcecore/__init__.py` exports

## Coding Standards

### General
- **Type annotations everywhere** — all function signatures, all class attributes
- **Docstrings on all public APIs** — Google-style docstrings
- **No `Any` types** unless absolutely necessary (and documented why)
- **Fail closed** — if in doubt, block the call, don't let it through

### Naming Conventions
- Classes: `PascalCase` (e.g., `PolicyEngine`, `EnforcementResult`)
- Functions/methods: `snake_case` (e.g., `enforce_call`, `load_policy`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_POLICY_PATH`)
- Private/internal: prefix with `_` (e.g., `_evaluate_rules`)
- Modules: `snake_case` (e.g., `policy.py`, `merkle.py`)

### Error Handling
- Use the defined exception hierarchy (see `core/types.py`)
- Never catch bare `Exception` in enforcement paths
- Always fail closed: if enforcement logic fails, block the call
- Log errors with `structlog` before raising

### Async Patterns
```python
# Correct: support both sync and async
import asyncio
import functools
from typing import Callable, TypeVar

T = TypeVar("T")

def enforce(policy: str) -> Callable:
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs) -> T:
                # ... enforcement logic ...
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs) -> T:
                # ... enforcement logic ...
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator
```

### Testing Patterns
```python
import pytest
from enforcecore import enforce, EnforcementViolation

# Test that allowed calls pass through
@pytest.mark.asyncio
async def test_allowed_call_succeeds():
    @enforce(policy="tests/fixtures/allow_all.yaml")
    async def allowed_tool():
        return "result"

    assert await allowed_tool() == "result"

# Test that denied calls are blocked
@pytest.mark.asyncio
async def test_denied_call_raises():
    @enforce(policy="tests/fixtures/deny_all.yaml")
    async def denied_tool():
        return "should not reach here"

    with pytest.raises(EnforcementViolation):
        await denied_tool()
```

## Component Development Order

When implementing a new component, follow this order:

1. **Types first** — Define the data models and exceptions in `core/types.py`
2. **Interface second** — Define the public API (what the component exposes)
3. **Tests third** — Write tests for the expected behavior
4. **Implementation fourth** — Build the component to pass the tests
5. **Integration fifth** — Wire it into the `Enforcer` coordinator
6. **Documentation sixth** — Update API docs, README, and examples

## Git Conventions

### Branch Naming
- `main` — stable, released code
- `dev` — integration branch for upcoming release
- `feat/<name>` — feature branches (e.g., `feat/redactor`)
- `fix/<name>` — bug fixes
- `docs/<name>` — documentation changes

### Commit Messages
Follow [Conventional Commits](https://www.conventionalcommits.org/):
```
feat(policy): add YAML policy loading with Pydantic validation
fix(enforcer): handle async generator functions correctly
docs(readme): add quickstart guide
test(auditor): add Merkle chain integrity tests
chore(ci): add macOS to test matrix
```

### Release Process
1. All v1.0.x changes go to `dev` branch first
2. When ready to release, merge `dev` → `main`
3. Tag with version: `git tag v1.0.x`
4. CI automatically publishes to PyPI on tag push
5. Update CHANGELOG.md with release notes

## CI Pipeline (GitHub Actions)

The CI runs on every push and PR:

```yaml
# .github/workflows/ci.yml
jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        python: ["3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: pip install -e ".[dev]"
      - run: ruff check .
      - run: ruff format --check .
      - run: mypy enforcecore/
      - run: pytest --cov=enforcecore
```

## Debugging Tips

### Verbose enforcement logging
```python
import structlog
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(0),  # DEBUG level
)
```

### Inspecting policy evaluation
```python
from enforcecore.core.policy import PolicyEngine

engine = PolicyEngine.from_file("policy.yaml")
result = engine.evaluate_pre_call(tool_name="search", args={"query": "test"})
print(result)  # Shows which rules matched and the decision
```

### Platform detection
```python
from enforcecore.guard.platform import detect_platform

info = detect_platform()
print(info)
# PlatformInfo(os='darwin', arch='arm64', cgroups=False, seccomp=False, setrlimit=True)
```

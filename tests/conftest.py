"""Shared test fixtures for EnforceCore."""

from __future__ import annotations

from pathlib import Path

import pytest

from enforcecore.core.policy import Policy

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    """Path to the test fixtures directory."""
    return FIXTURES_DIR


@pytest.fixture
def allow_all_policy() -> Policy:
    """A policy that allows everything."""
    return Policy.from_file(FIXTURES_DIR / "allow_all.yaml")


@pytest.fixture
def deny_all_policy() -> Policy:
    """A policy with an empty allowed list (blocks all tools)."""
    return Policy.from_file(FIXTURES_DIR / "deny_all.yaml")


@pytest.fixture
def specific_tools_policy() -> Policy:
    """A policy that allows only search_web, calculator, get_weather."""
    return Policy.from_file(FIXTURES_DIR / "specific_tools.yaml")


@pytest.fixture
def log_only_policy() -> Policy:
    """A policy that logs violations instead of blocking."""
    return Policy.from_file(FIXTURES_DIR / "log_only.yaml")


@pytest.fixture
def output_limit_policy() -> Policy:
    """A policy with a 100-byte output size limit."""
    return Policy.from_file(FIXTURES_DIR / "output_limit.yaml")


@pytest.fixture
def pii_redaction_policy() -> Policy:
    """A policy with PII redaction enabled (placeholder strategy)."""
    return Policy.from_file(FIXTURES_DIR / "pii_redaction.yaml")


@pytest.fixture
def pii_mask_policy() -> Policy:
    """A policy with PII redaction using mask strategy."""
    return Policy.from_file(FIXTURES_DIR / "pii_mask.yaml")

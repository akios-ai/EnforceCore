# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Shared test fixtures for EnforceCore."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from enforcecore.core.config import settings
from enforcecore.core.policy import Policy

if TYPE_CHECKING:
    from collections.abc import Iterator

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _disable_audit_globally(tmp_path: Path) -> Iterator[None]:
    """Disable audit by default so tests don't write trail files.

    Audit integration tests explicitly re-enable it.
    """
    original_enabled = settings.audit_enabled
    original_path = settings.audit_path
    settings.audit_enabled = False
    settings.audit_path = tmp_path / "audit_logs"
    yield
    settings.audit_enabled = original_enabled
    settings.audit_path = original_path


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


@pytest.fixture
def time_limit_policy() -> Policy:
    """A policy with a 5-second call duration limit."""
    return Policy.from_file(FIXTURES_DIR / "time_limit.yaml")


@pytest.fixture
def cost_limit_policy() -> Policy:
    """A policy with a $5.00 cumulative cost budget."""
    return Policy.from_file(FIXTURES_DIR / "cost_limit.yaml")


@pytest.fixture
def resource_limits_policy() -> Policy:
    """A policy with time (10s), memory (256MB), and cost ($10) limits."""
    return Policy.from_file(FIXTURES_DIR / "resource_limits.yaml")

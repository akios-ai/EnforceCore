# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for integration tests.

Re-enables audit and provides scenario-specific policies and helpers.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from enforcecore.core.config import settings
from enforcecore.core.policy import Policy

if TYPE_CHECKING:
    from collections.abc import Iterator

SCENARIOS_DIR = Path(__file__).parent.parent.parent / "examples" / "scenarios"
FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


@pytest.fixture(autouse=True)
def _enable_audit(tmp_path: Path) -> Iterator[None]:
    """Override the global autouse fixture — enable audit for integration tests."""
    original_enabled = settings.audit_enabled
    original_path = settings.audit_path
    settings.audit_enabled = True
    settings.audit_path = tmp_path / "audit_logs"
    yield
    settings.audit_enabled = original_enabled
    settings.audit_path = original_path


@pytest.fixture
def audit_trail_path(tmp_path: Path) -> Path:
    """Return the audit trail JSONL path used by integration tests."""
    return tmp_path / "audit_logs" / "trail.jsonl"


@pytest.fixture
def healthcare_policy() -> Policy:
    return Policy.from_file(SCENARIOS_DIR / "healthcare" / "policy.yaml")


@pytest.fixture
def financial_policy() -> Policy:
    return Policy.from_file(SCENARIOS_DIR / "financial" / "policy.yaml")


@pytest.fixture
def code_agent_policy() -> Policy:
    return Policy.from_file(SCENARIOS_DIR / "code_agent" / "policy.yaml")


@pytest.fixture
def compliance_policy() -> Policy:
    return Policy.from_file(SCENARIOS_DIR / "compliance" / "policy.yaml")


@pytest.fixture
def multi_framework_policy() -> Policy:
    return Policy.from_file(SCENARIOS_DIR / "multi_framework" / "policy.yaml")


@pytest.fixture
def allow_all_policy() -> Policy:
    return Policy.from_file(FIXTURES_DIR / "allow_all.yaml")


@pytest.fixture
def pii_redaction_policy() -> Policy:
    return Policy.from_file(FIXTURES_DIR / "pii_redaction.yaml")

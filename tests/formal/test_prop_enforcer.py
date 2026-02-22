# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the Enforcer — Hypothesis.

These tests verify fail-closed behaviour and audit completeness.
"""

from __future__ import annotations

import string

from hypothesis import given, settings
from hypothesis import strategies as st

from enforcecore.core.enforcer import Enforcer
from enforcecore.core.policy import Policy
from enforcecore.core.types import (
    EnforceCoreError,
    EnforcementViolation,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_tool_names = st.text(
    alphabet=string.ascii_letters + string.digits + "_",
    min_size=1,
    max_size=30,
)


def _make_policy(
    *,
    denied: list[str] | None = None,
    allowed: list[str] | None = None,
) -> Policy:
    """Build a minimal policy."""
    rules: dict[str, object] = {}
    if denied is not None:
        rules["denied_tools"] = denied
    if allowed is not None:
        rules["allowed_tools"] = allowed
    return Policy.from_dict({"name": "enforcer-prop", "version": "1.0", "rules": rules})


# ---------------------------------------------------------------------------
# E1: Fail-closed — denied tools always raise
# ---------------------------------------------------------------------------


class TestFailClosed:
    """E1: ∀ denied tool → enforce_sync raises EnforcementViolation."""

    @given(
        denied=st.lists(_tool_names, min_size=1, max_size=5, unique=True),
        data=st.data(),
    )
    @settings(max_examples=100, deadline=5000)
    def test_denied_tool_raises(
        self,
        denied: list[str],
        data: st.DataObject,
    ) -> None:
        """Calling a denied tool must raise EnforcementViolation."""
        tool = data.draw(st.sampled_from(denied))
        policy = _make_policy(denied=denied)
        enforcer = Enforcer(policy)

        def dummy() -> str:
            return "result"

        try:
            enforcer.enforce_sync(dummy, tool_name=tool)
            raised = False
        except EnforcementViolation:
            raised = True

        assert raised, f"Expected EnforcementViolation for denied tool {tool!r}"


# ---------------------------------------------------------------------------
# E2: Allowed tools succeed
# ---------------------------------------------------------------------------


class TestAllowedToolsSucceed:
    """E2: ∀ tool in allowed_tools (and not denied) → call succeeds."""

    @given(
        tools=st.lists(_tool_names, min_size=1, max_size=5, unique=True),
        data=st.data(),
    )
    @settings(max_examples=100, deadline=5000)
    def test_allowed_tool_succeeds(
        self,
        tools: list[str],
        data: st.DataObject,
    ) -> None:
        """Calling an allowed tool must return the function result."""
        tool = data.draw(st.sampled_from(tools))
        policy = _make_policy(allowed=tools, denied=[])
        enforcer = Enforcer(policy)

        sentinel = object()

        def dummy() -> object:
            return sentinel

        result = enforcer.enforce_sync(dummy, tool_name=tool)
        assert result is sentinel


# ---------------------------------------------------------------------------
# E3: Idempotent enforcement — same call, same outcome
# ---------------------------------------------------------------------------


class TestEnforcerIdempotency:
    """E3: Enforcing the same call twice yields the same outcome."""

    @given(tool=_tool_names)
    @settings(max_examples=100, deadline=5000)
    def test_same_call_same_result(self, tool: str) -> None:
        """Repeated enforcement of the same tool must be consistent."""
        policy = _make_policy(denied=[])
        enforcer = Enforcer(policy)

        def dummy() -> str:
            return "ok"

        r1 = enforcer.enforce_sync(dummy, tool_name=tool)
        r2 = enforcer.enforce_sync(dummy, tool_name=tool)
        assert r1 == r2


# ---------------------------------------------------------------------------
# E4: Internal error → fail closed (default)
# ---------------------------------------------------------------------------


class TestInternalErrorFailClosed:
    """E4: Internal EnforceCoreError → re-raised when fail_open=False."""

    def test_internal_error_reraises(self) -> None:
        """An internal error during enforcement must not be swallowed."""
        policy = _make_policy(denied=[])
        enforcer = Enforcer(policy)

        def bomb() -> str:
            raise EnforceCoreError("boom")

        try:
            enforcer.enforce_sync(bomb, tool_name="bomb_tool")
            raised = False
        except EnforceCoreError:
            raised = True

        assert raised, "Internal error should propagate when fail_open=False"

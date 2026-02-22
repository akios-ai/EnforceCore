# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for PolicyEngine — Hypothesis.

These tests verify formal invariants of the policy engine using
randomly generated inputs.  Every property stated here corresponds
to a specification in docs/formal/invariants.md.
"""

from __future__ import annotations

import string

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from enforcecore.core.policy import Policy, PolicyEngine
from enforcecore.core.types import CallContext, Decision

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Tool names: 1-50 alphanumeric + underscore characters
tool_names = st.text(
    alphabet=string.ascii_letters + string.digits + "_",
    min_size=1,
    max_size=50,
)

# Lists of unique tool names
tool_name_lists = st.lists(tool_names, min_size=0, max_size=20, unique=True)


def make_policy(
    *,
    name: str = "test-policy",
    allowed: list[str] | None = None,
    denied: list[str] | None = None,
    on_violation: str = "block",
) -> Policy:
    """Helper to build a Policy object."""
    rules: dict[str, object] = {}
    if allowed is not None:
        rules["allowed_tools"] = allowed
    if denied is not None:
        rules["denied_tools"] = denied
    return Policy.from_dict(
        {
            "name": name,
            "version": "1.0",
            "rules": rules,
            "on_violation": on_violation,
        }
    )


# ---------------------------------------------------------------------------
# P1: Determinism — same input always yields same decision
# ---------------------------------------------------------------------------


class TestPolicyDeterminism:
    """P1: ∀ valid policy, ∀ tool call → decision is deterministic."""

    @given(
        allowed=tool_name_lists,
        denied=tool_name_lists,
        tool=tool_names,
    )
    @settings(max_examples=200)
    def test_same_input_same_decision(
        self,
        allowed: list[str],
        denied: list[str],
        tool: str,
    ) -> None:
        """Evaluating the same policy + tool twice must yield the same decision."""
        policy = make_policy(allowed=allowed, denied=denied)
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result1 = engine.evaluate_pre_call(ctx)
        result2 = engine.evaluate_pre_call(ctx)

        assert result1.decision == result2.decision
        assert result1.reason == result2.reason


# ---------------------------------------------------------------------------
# P2: Denied tools are always blocked
# ---------------------------------------------------------------------------


class TestDeniedAlwaysBlocked:
    """P2: ∀ policy, ∀ tool ∈ denied_tools → decision = BLOCKED."""

    @given(
        allowed=tool_name_lists,
        denied=st.lists(tool_names, min_size=1, max_size=10, unique=True),
        data=st.data(),
    )
    @settings(max_examples=200)
    def test_denied_tool_always_blocked(
        self,
        allowed: list[str],
        denied: list[str],
        data: st.DataObject,
    ) -> None:
        """Any tool in the denied list must be blocked."""
        tool = data.draw(st.sampled_from(denied))
        policy = make_policy(allowed=allowed, denied=denied)
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.BLOCKED

    @given(
        denied=st.lists(tool_names, min_size=1, max_size=10, unique=True),
        data=st.data(),
    )
    @settings(max_examples=200)
    def test_denied_tool_case_insensitive(
        self,
        denied: list[str],
        data: st.DataObject,
    ) -> None:
        """Denied check must be case-insensitive."""
        tool = data.draw(st.sampled_from(denied))
        # Randomly change case
        tool_variant = data.draw(st.sampled_from([tool.lower(), tool.upper(), tool.title()]))
        policy = make_policy(denied=denied)
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool_variant)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.BLOCKED


# ---------------------------------------------------------------------------
# P3: Tools not in allowed list are blocked (when allowlist exists)
# ---------------------------------------------------------------------------


class TestAllowlistEnforcement:
    """P3: ∀ policy with allowed_tools, ∀ tool ∉ allowed_tools → BLOCKED."""

    @given(
        allowed=st.lists(tool_names, min_size=1, max_size=10, unique=True),
        tool=tool_names,
    )
    @settings(max_examples=200)
    def test_unlisted_tool_blocked(
        self,
        allowed: list[str],
        tool: str,
    ) -> None:
        """A tool not in the allowed list must be blocked."""
        assume(tool.lower() not in {t.lower() for t in allowed})

        policy = make_policy(allowed=allowed)
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.BLOCKED

    @given(
        allowed=st.lists(tool_names, min_size=1, max_size=10, unique=True),
        data=st.data(),
    )
    @settings(max_examples=200)
    def test_listed_tool_allowed(
        self,
        allowed: list[str],
        data: st.DataObject,
    ) -> None:
        """A tool in the allowed list must be allowed (if not also denied)."""
        tool = data.draw(st.sampled_from(allowed))
        policy = make_policy(allowed=allowed, denied=[])
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.ALLOWED


# ---------------------------------------------------------------------------
# P4: Deny takes priority over allow
# ---------------------------------------------------------------------------


class TestDenyPriority:
    """P4: ∀ tool ∈ denied_tools ∩ allowed_tools → decision = BLOCKED."""

    @given(
        tools=st.lists(tool_names, min_size=1, max_size=10, unique=True),
        data=st.data(),
    )
    @settings(max_examples=200)
    def test_deny_overrides_allow(
        self,
        tools: list[str],
        data: st.DataObject,
    ) -> None:
        """A tool that is both allowed and denied must be blocked."""
        tool = data.draw(st.sampled_from(tools))
        policy = make_policy(allowed=tools, denied=tools)
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.BLOCKED


# ---------------------------------------------------------------------------
# P5: Null allowlist allows everything (except denied)
# ---------------------------------------------------------------------------


class TestNullAllowlist:
    """P5: ∀ policy with allowed_tools=None, ∀ tool ∉ denied → ALLOWED."""

    @given(tool=tool_names)
    @settings(max_examples=200)
    def test_null_allowlist_allows_all(self, tool: str) -> None:
        """With no allowlist, any tool not denied is allowed."""
        policy = make_policy(allowed=None, denied=[])
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.ALLOWED


# ---------------------------------------------------------------------------
# P6: Empty allowlist denies everything
# ---------------------------------------------------------------------------


class TestEmptyAllowlist:
    """P6: ∀ policy with allowed_tools=[], ∀ tool → BLOCKED."""

    @given(tool=tool_names)
    @settings(max_examples=200)
    def test_empty_allowlist_blocks_all(self, tool: str) -> None:
        """An empty allowed list must block every tool."""
        policy = make_policy(allowed=[])
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision == Decision.BLOCKED


# ---------------------------------------------------------------------------
# P7: Policy merge — denied_tools union
# ---------------------------------------------------------------------------


class TestMergeDeniedUnion:
    """P7: merge(A, B).denied_tools >= A.denied_tools | B.denied_tools."""

    @given(
        denied_a=tool_name_lists,
        denied_b=tool_name_lists,
    )
    @settings(max_examples=200)
    def test_merge_denied_is_union(
        self,
        denied_a: list[str],
        denied_b: list[str],
    ) -> None:
        """Merged denied list must contain all denied tools from both policies."""
        a = make_policy(name="a", denied=denied_a)
        b = make_policy(name="b", denied=denied_b)
        merged = Policy.merge(a, b)

        expected = {t.lower() for t in denied_a} | {t.lower() for t in denied_b}
        actual = {t.lower() for t in merged.rules.denied_tools}

        assert expected == actual


# ---------------------------------------------------------------------------
# P8: Decision is always ALLOWED or BLOCKED (never unknown)
# ---------------------------------------------------------------------------


class TestDecisionCompleteness:
    """P8: ∀ policy, ∀ tool → decision ∈ {ALLOWED, BLOCKED}."""

    @given(
        allowed=st.one_of(st.none(), tool_name_lists),
        denied=tool_name_lists,
        tool=tool_names,
    )
    @settings(max_examples=200)
    def test_decision_is_complete(
        self,
        allowed: list[str] | None,
        denied: list[str],
        tool: str,
    ) -> None:
        """Every evaluation must yield ALLOWED or BLOCKED, nothing else."""
        policy = make_policy(allowed=allowed, denied=denied)
        engine = PolicyEngine(policy)
        ctx = CallContext(tool_name=tool)

        result = engine.evaluate_pre_call(ctx)
        assert result.decision in {Decision.ALLOWED, Decision.BLOCKED}

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the Merkle audit chain — Hypothesis.

These tests verify that the tamper-evident log maintains integrity
under random operations and that any modification is detected.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from enforcecore.auditor.engine import AuditEntry, Auditor, verify_trail

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

_tool_names = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz_",
    min_size=1,
    max_size=30,
)

_decisions = st.sampled_from(["allowed", "blocked"])


def _make_entry(
    *,
    tool_name: str = "test_tool",
    decision: str = "allowed",
    policy_name: str = "default",
) -> AuditEntry:
    """Build a fresh AuditEntry."""
    return AuditEntry(
        call_id=str(uuid.uuid4()),
        tool_name=tool_name,
        policy_name=policy_name,
        policy_version="1.0",
        decision=decision,
        overhead_ms=0.1,
        call_duration_ms=1.0,
    )


def _fresh_trail() -> Path:
    """Create a fresh temp file path for a trail."""
    with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
        p = Path(f.name)
    p.unlink()  # Auditor will create it
    return p


# ---------------------------------------------------------------------------
# M1: Hash determinism — same fields ⟹ same hash
# ---------------------------------------------------------------------------


class TestHashDeterminism:
    """M1: compute_hash is a pure function of the entry fields."""

    @given(tool=_tool_names, decision=_decisions)
    @settings(max_examples=200)
    def test_same_fields_same_hash(self, tool: str, decision: str) -> None:
        """Two entries with identical fields must produce the same hash."""
        e1 = _make_entry(tool_name=tool, decision=decision)
        e2 = _make_entry(tool_name=tool, decision=decision)

        # Align all mutable fields that differ between instances
        e2.entry_id = e1.entry_id
        e2.call_id = e1.call_id
        e2.timestamp = e1.timestamp

        h1 = e1.compute_hash()
        h2 = e2.compute_hash()
        assert h1 == h2


# ---------------------------------------------------------------------------
# M2: Hash sensitivity — any field change ⟹ different hash
# ---------------------------------------------------------------------------


class TestHashSensitivity:
    """M2: Changing any field changes the hash."""

    @given(tool_a=_tool_names, tool_b=_tool_names)
    @settings(max_examples=200)
    def test_different_tool_different_hash(self, tool_a: str, tool_b: str) -> None:
        """Different tool names must yield different hashes."""
        assume(tool_a != tool_b)
        e1 = _make_entry(tool_name=tool_a)
        e2 = _make_entry(tool_name=tool_b)
        e2.entry_id = e1.entry_id
        e2.call_id = e1.call_id
        e2.timestamp = e1.timestamp

        assert e1.compute_hash() != e2.compute_hash()


# ---------------------------------------------------------------------------
# M3: Valid chain construction — any N entries form a valid chain
# ---------------------------------------------------------------------------


class TestChainConstruction:
    """M3: ∀ n entries, sealing sequentially produces a valid chain."""

    @given(n=st.integers(min_value=1, max_value=50))
    @settings(max_examples=50, deadline=5000)
    def test_chain_always_valid(self, n: int) -> None:
        """A chain of N entries must always verify."""
        trail_path = _fresh_trail()
        try:
            auditor = Auditor(output_path=trail_path)

            for i in range(n):
                auditor.record(
                    call_id=str(uuid.uuid4()),
                    tool_name=f"tool_{i}",
                    policy_name="prop-test",
                    policy_version="1.0",
                    decision="allowed",
                    overhead_ms=0.1,
                    call_duration_ms=1.0,
                )

            result = verify_trail(trail_path)
            assert result.is_valid, f"Chain invalid: {result.errors}"
            assert result.total_entries == n
            assert result.chain_intact is True
        finally:
            trail_path.unlink(missing_ok=True)

    @given(
        tools=st.lists(_tool_names, min_size=2, max_size=20),
        decisions=st.lists(_decisions, min_size=2, max_size=20),
    )
    @settings(max_examples=50, deadline=5000)
    def test_random_entries_form_valid_chain(self, tools: list[str], decisions: list[str]) -> None:
        """Random tool/decision combinations must form a valid chain."""
        n = min(len(tools), len(decisions))
        trail_path = _fresh_trail()
        try:
            auditor = Auditor(output_path=trail_path)

            for i in range(n):
                auditor.record(
                    call_id=str(uuid.uuid4()),
                    tool_name=tools[i],
                    policy_name="prop-test",
                    policy_version="1.0",
                    decision=decisions[i],
                    overhead_ms=0.1,
                    call_duration_ms=1.0,
                )

            result = verify_trail(trail_path)
            assert result.is_valid
        finally:
            trail_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# M4: Tamper detection — modification is always detected
# ---------------------------------------------------------------------------


class TestTamperDetection:
    """M4: ∀ chain, ∀ single-entry modification → verify_trail fails."""

    @given(
        n=st.integers(min_value=2, max_value=20),
        tamper_idx=st.integers(min_value=0),
    )
    @settings(max_examples=50, deadline=5000)
    def test_field_modification_detected(self, n: int, tamper_idx: int) -> None:
        """Modifying a field in any entry must break verification."""
        tamper_idx = tamper_idx % n

        trail_path = _fresh_trail()
        try:
            auditor = Auditor(output_path=trail_path)

            for i in range(n):
                auditor.record(
                    call_id=str(uuid.uuid4()),
                    tool_name=f"tool_{i}",
                    policy_name="prop-test",
                    policy_version="1.0",
                    decision="allowed",
                    overhead_ms=0.1,
                    call_duration_ms=1.0,
                )

            # Tamper with one entry
            lines = trail_path.read_text().strip().split("\n")
            entry = json.loads(lines[tamper_idx])
            entry["tool_name"] = "TAMPERED_TOOL"
            lines[tamper_idx] = json.dumps(entry)
            trail_path.write_text("\n".join(lines) + "\n")

            result = verify_trail(trail_path)
            assert not result.is_valid, "Tampered chain should fail verification"
        finally:
            trail_path.unlink(missing_ok=True)

    @given(
        n=st.integers(min_value=3, max_value=20),
        del_idx=st.integers(min_value=1),
    )
    @settings(max_examples=50, deadline=5000)
    def test_deletion_detected(self, n: int, del_idx: int) -> None:
        """Deleting any non-terminal entry must be detected."""
        del_idx = (del_idx % (n - 1)) + 1  # 1..n-1
        # Ensure we don't delete the last entry (tail truncation is
        # undetectable by chain linkage alone without an expected count)
        if del_idx >= n - 1:
            del_idx = n - 2
        if del_idx < 1:
            del_idx = 1

        trail_path = _fresh_trail()
        try:
            auditor = Auditor(output_path=trail_path)

            for i in range(n):
                auditor.record(
                    call_id=str(uuid.uuid4()),
                    tool_name=f"tool_{i}",
                    policy_name="prop-test",
                    policy_version="1.0",
                    decision="allowed",
                    overhead_ms=0.1,
                    call_duration_ms=1.0,
                )

            lines = trail_path.read_text().strip().split("\n")
            del lines[del_idx]
            trail_path.write_text("\n".join(lines) + "\n")

            result = verify_trail(trail_path)
            assert not result.is_valid, "Chain with deleted entry should fail"
        finally:
            trail_path.unlink(missing_ok=True)

    @given(n=st.integers(min_value=3, max_value=15))
    @settings(max_examples=30, deadline=5000)
    def test_reorder_detected(self, n: int) -> None:
        """Swapping two entries must be detected."""
        trail_path = _fresh_trail()
        try:
            auditor = Auditor(output_path=trail_path)

            for i in range(n):
                auditor.record(
                    call_id=str(uuid.uuid4()),
                    tool_name=f"tool_{i}",
                    policy_name="prop-test",
                    policy_version="1.0",
                    decision="allowed",
                    overhead_ms=0.1,
                    call_duration_ms=1.0,
                )

            lines = trail_path.read_text().strip().split("\n")
            # Swap first and last
            lines[0], lines[-1] = lines[-1], lines[0]
            trail_path.write_text("\n".join(lines) + "\n")

            result = verify_trail(trail_path)
            assert not result.is_valid, "Reordered chain should fail verification"
        finally:
            trail_path.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# M5: Chain root stability — adding entries never changes earlier hashes
# ---------------------------------------------------------------------------


class TestChainRootStability:
    """M5: Appending entries does not change prior entry hashes."""

    @given(n=st.integers(min_value=2, max_value=30))
    @settings(max_examples=30, deadline=5000)
    def test_append_preserves_prior_hashes(self, n: int) -> None:
        """After writing N entries, the first N-1 hashes are unchanged."""
        trail_path = _fresh_trail()
        try:
            auditor = Auditor(output_path=trail_path)

            # Write first N-1 entries
            for i in range(n - 1):
                auditor.record(
                    call_id=str(uuid.uuid4()),
                    tool_name=f"tool_{i}",
                    policy_name="prop-test",
                    policy_version="1.0",
                    decision="allowed",
                    overhead_ms=0.1,
                    call_duration_ms=1.0,
                )

            before = trail_path.read_text().strip().split("\n")

            # Append one more
            auditor.record(
                call_id=str(uuid.uuid4()),
                tool_name=f"tool_{n - 1}",
                policy_name="prop-test",
                policy_version="1.0",
                decision="allowed",
                overhead_ms=0.1,
                call_duration_ms=1.0,
            )

            after = trail_path.read_text().strip().split("\n")

            # First N-1 lines must be identical
            for i, (b, a) in enumerate(zip(before, after)):  # noqa: B905
                assert b == a, f"Entry {i} changed after append"
        finally:
            trail_path.unlink(missing_ok=True)

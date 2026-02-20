"""Integration tests: Audit trail in the enforcer pipeline."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import pytest

from enforcecore.auditor.engine import verify_trail
from enforcecore.core.config import settings
from enforcecore.core.enforcer import Enforcer
from enforcecore.core.types import EnforcementViolation

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.core.policy import Policy


# =========================================================================
# Helpers
# =========================================================================


def _echo(msg: str) -> str:
    return msg


async def _async_echo(msg: str) -> str:
    return msg


# =========================================================================
# Sync enforcer + audit
# =========================================================================


class TestEnforcerSyncAudit:
    """enforce_sync records audit entries."""

    def test_audit_entry_written(self, allow_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(allow_all_policy)
        enforcer.enforce_sync(_echo, "hello", tool_name="echo")

        trail_file = tmp_path / "trail.jsonl"
        assert trail_file.exists()

        lines = trail_file.read_text().strip().split("\n")
        assert len(lines) == 1

        data = json.loads(lines[0])
        assert data["tool_name"] == "echo"
        assert data["policy_name"] == "allow-all"
        assert data["decision"] == "allowed"
        assert data["entry_hash"] != ""

    def test_multiple_calls_chain(self, allow_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(allow_all_policy)
        enforcer.enforce_sync(_echo, "a", tool_name="echo")
        enforcer.enforce_sync(_echo, "b", tool_name="echo")
        enforcer.enforce_sync(_echo, "c", tool_name="echo")

        trail_file = tmp_path / "trail.jsonl"
        result = verify_trail(trail_file)
        assert result.is_valid is True
        assert result.total_entries == 3
        assert result.chain_intact is True

    def test_blocked_call_recorded(self, deny_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(deny_all_policy)
        with pytest.raises(EnforcementViolation):
            enforcer.enforce_sync(_echo, "hello", tool_name="blocked_tool")

        trail_file = tmp_path / "trail.jsonl"
        assert trail_file.exists()

        data = json.loads(trail_file.read_text().strip())
        assert data["decision"] == "blocked"
        assert data["tool_name"] == "blocked_tool"
        assert data["violation_type"] is not None


# =========================================================================
# Async enforcer + audit
# =========================================================================


class TestEnforcerAsyncAudit:
    """enforce_async records audit entries."""

    @pytest.mark.asyncio
    async def test_async_audit_entry(self, allow_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(allow_all_policy)
        await enforcer.enforce_async(_async_echo, "hello", tool_name="async_echo")

        trail_file = tmp_path / "trail.jsonl"
        data = json.loads(trail_file.read_text().strip())
        assert data["tool_name"] == "async_echo"
        assert data["decision"] == "allowed"

    @pytest.mark.asyncio
    async def test_async_blocked_recorded(self, deny_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(deny_all_policy)
        with pytest.raises(EnforcementViolation):
            await enforcer.enforce_async(_async_echo, "hello", tool_name="denied")

        trail_file = tmp_path / "trail.jsonl"
        data = json.loads(trail_file.read_text().strip())
        assert data["decision"] == "blocked"


# =========================================================================
# Audit disabled
# =========================================================================


class TestAuditDisabled:
    """When audit is disabled, no trail files are created."""

    def test_no_audit_file_when_disabled(self, allow_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = False
        settings.audit_path = tmp_path

        enforcer = Enforcer(allow_all_policy)
        enforcer.enforce_sync(_echo, "hello", tool_name="echo")

        trail_file = tmp_path / "trail.jsonl"
        assert not trail_file.exists()

    def test_auditor_is_none_when_disabled(self, allow_all_policy: Policy) -> None:
        settings.audit_enabled = False
        enforcer = Enforcer(allow_all_policy)
        assert enforcer._auditor is None


# =========================================================================
# Trail verification end-to-end
# =========================================================================


class TestEndToEndTrail:
    """Full end-to-end: calls → trail → verify."""

    def test_full_workflow(self, allow_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(allow_all_policy)
        for i in range(20):
            enforcer.enforce_sync(_echo, f"msg_{i}", tool_name=f"tool_{i}")

        trail_file = tmp_path / "trail.jsonl"
        result = verify_trail(trail_file)
        assert result.is_valid is True
        assert result.total_entries == 20
        assert result.chain_intact is True
        assert result.root_hash != ""
        assert result.head_hash != ""

    def test_mixed_allowed_and_blocked(self, specific_tools_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(specific_tools_policy)

        # Allowed call
        enforcer.enforce_sync(_echo, "hello", tool_name="search_web")

        # Blocked call
        with pytest.raises(EnforcementViolation):
            enforcer.enforce_sync(_echo, "hello", tool_name="execute_shell")

        # Another allowed call
        enforcer.enforce_sync(_echo, "hello", tool_name="calculator")

        trail_file = tmp_path / "trail.jsonl"
        result = verify_trail(trail_file)
        assert result.is_valid is True
        assert result.total_entries == 3

        # Check decisions
        lines = trail_file.read_text().strip().split("\n")
        decisions = [json.loads(line)["decision"] for line in lines]
        assert decisions == ["allowed", "blocked", "allowed"]


# =========================================================================
# Audit metadata
# =========================================================================


class TestAuditMetadata:
    """Verify correct metadata in audit entries."""

    def test_policy_info_recorded(self, specific_tools_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(specific_tools_policy)
        enforcer.enforce_sync(_echo, "test", tool_name="search_web")

        trail_file = tmp_path / "trail.jsonl"
        data = json.loads(trail_file.read_text().strip())
        assert data["policy_name"] == "specific-tools"
        assert data["policy_version"] == "1.0"

    def test_timing_recorded(self, allow_all_policy: Policy, tmp_path: Path) -> None:
        settings.audit_enabled = True
        settings.audit_path = tmp_path

        enforcer = Enforcer(allow_all_policy)
        enforcer.enforce_sync(_echo, "hello", tool_name="echo")

        trail_file = tmp_path / "trail.jsonl"
        data = json.loads(trail_file.read_text().strip())
        assert "overhead_ms" in data
        assert "call_duration_ms" in data
        assert data["overhead_ms"] >= 0
        assert data["call_duration_ms"] >= 0

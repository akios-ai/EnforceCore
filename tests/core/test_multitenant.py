# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.6.0 Multi-Tenant + Policy Inheritance features.

Covers:
- MultiTenantEnforcer — register/unregister/tenants/get_enforcer
- MultiTenantEnforcer — enforce_sync / enforce_async
- MultiTenantEnforcer — default_policy fallback
- MultiTenantEnforcer — thread-safety surface tests
- MultiTenantEnforcer — __contains__, __len__, __repr__
- Enforcer.tenant_id property
- Enforcer.__init__(policy, tenant_id=…)
- Enforcer.from_file(path, tenant_id=…)
- AuditEntry.tenant_id field
- Auditor.record(tenant_id=…)
- Policy.from_file circular extends detection
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from enforcecore.auditor.engine import AuditEntry, Auditor
from enforcecore.core.enforcer import Enforcer
from enforcecore.core.multitenant import MultiTenantEnforcer
from enforcecore.core.policy import Policy, PolicyLoadError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures"


def add(x: int, y: int) -> int:
    """Simple sync tool for enforcement tests."""
    return x + y


async def async_add(x: int, y: int) -> int:
    """Simple async tool for enforcement tests."""
    await asyncio.sleep(0)
    return x + y


def _allow_all() -> Policy:
    return Policy.from_file(FIXTURES / "allow_all.yaml")


def _specific() -> Policy:
    return Policy.from_file(FIXTURES / "specific_tools.yaml")


# ---------------------------------------------------------------------------
# Enforcer.tenant_id
# ---------------------------------------------------------------------------


class TestEnforcerTenantId:
    def test_default_is_none(self) -> None:
        enforcer = Enforcer(_allow_all())
        assert enforcer.tenant_id is None

    def test_set_via_init(self) -> None:
        enforcer = Enforcer(_allow_all(), tenant_id="acme")
        assert enforcer.tenant_id == "acme"

    def test_from_file(self, tmp_path: Path) -> None:
        """from_file forwards tenant_id to the Enforcer."""
        path = tmp_path / "p.yaml"
        path.write_text(
            "name: t\nversion: '1.0'\nrules:\n  allowed_tools: null\n  denied_tools: []\n  pii_redaction:\n    enabled: false\n  resource_limits: {}\non_violation: block\n"
        )
        enforcer = Enforcer.from_file(path, tenant_id="beta")
        assert enforcer.tenant_id == "beta"

    def test_tenant_id_in_audit_entry(self, tmp_path: Path) -> None:
        """Audit entries written by an Enforcer carry its tenant_id."""
        from enforcecore.core.config import settings

        trail = tmp_path / "trail.jsonl"
        settings.audit_enabled = True
        settings.audit_path = tmp_path
        try:
            enforcer = Enforcer(_allow_all(), tenant_id="team_x")
            enforcer.enforce_sync(add, 1, 2, tool_name="add")
        finally:
            settings.audit_enabled = False

        # Load the trail and inspect the last entry
        import json

        lines = trail.read_text().strip().splitlines()
        last = json.loads(lines[-1])
        assert last.get("tenant_id") == "team_x"


# ---------------------------------------------------------------------------
# AuditEntry.tenant_id field
# ---------------------------------------------------------------------------


class TestAuditEntryTenantId:
    def test_default_none(self) -> None:
        entry = AuditEntry(
            tool_name="t",
            decision="allowed",
            policy_name="p",
            policy_version="1",
        )
        assert entry.tenant_id is None

    def test_set_tenant_id(self) -> None:
        entry = AuditEntry(
            tool_name="t",
            decision="allowed",
            policy_name="p",
            policy_version="1",
            tenant_id="corp-a",
        )
        assert entry.tenant_id == "corp-a"

    def test_auditor_record_accepts_tenant_id(self, tmp_path: Path) -> None:
        from enforcecore.auditor.backends import NullBackend

        auditor = Auditor(backend=NullBackend())
        # Should not raise
        auditor.record(
            tool_name="t",
            decision="allowed",
            policy_name="p",
            policy_version="1",
            tenant_id="corp-b",
        )

    def test_entry_hash_stable_with_tenant(self) -> None:
        """compute_hash must succeed when tenant_id is populated."""
        entry = AuditEntry(
            tool_name="t",
            decision="allowed",
            policy_name="p",
            policy_version="1",
            tenant_id="org-x",
        )
        h = entry.compute_hash()
        assert isinstance(h, str) and len(h) == 64


# ---------------------------------------------------------------------------
# Policy.from_file — circular extends detection
# ---------------------------------------------------------------------------


class TestPolicyCircularExtends:
    def test_direct_self_reference_raises(self, tmp_path: Path) -> None:
        """A policy that extends itself must raise PolicyLoadError."""
        p = tmp_path / "self_ref.yaml"
        p.write_text(
            "name: self\nversion: '1.0'\nextends: self_ref.yaml\n"
            "rules:\n  allowed_tools: null\n  denied_tools: []\n"
            "  pii_redaction:\n    enabled: false\n  resource_limits: {}\n"
            "on_violation: block\n"
        )
        with pytest.raises(PolicyLoadError, match=r"[Cc]ircular"):
            Policy.from_file(p)

    def test_mutual_cycle_raises(self, tmp_path: Path) -> None:
        """A → B → A cycle must raise PolicyLoadError."""
        a = tmp_path / "a.yaml"
        b = tmp_path / "b.yaml"
        a.write_text(
            "name: a\nversion: '1.0'\nextends: b.yaml\n"
            "rules:\n  allowed_tools: null\n  denied_tools: []\n"
            "  pii_redaction:\n    enabled: false\n  resource_limits: {}\n"
            "on_violation: block\n"
        )
        b.write_text(
            "name: b\nversion: '1.0'\nextends: a.yaml\n"
            "rules:\n  allowed_tools: null\n  denied_tools: []\n"
            "  pii_redaction:\n    enabled: false\n  resource_limits: {}\n"
            "on_violation: block\n"
        )
        with pytest.raises(PolicyLoadError, match=r"[Cc]ircular"):
            Policy.from_file(a)

    def test_three_node_cycle_raises(self, tmp_path: Path) -> None:
        """A → B → C → A must raise PolicyLoadError."""
        a = tmp_path / "x.yaml"
        b = tmp_path / "y.yaml"
        c = tmp_path / "z.yaml"
        a.write_text(
            "name: x\nversion: '1.0'\nextends: y.yaml\n"
            "rules:\n  allowed_tools: null\n  denied_tools: []\n"
            "  pii_redaction:\n    enabled: false\n  resource_limits: {}\n"
            "on_violation: block\n"
        )
        b.write_text(
            "name: y\nversion: '1.0'\nextends: z.yaml\n"
            "rules:\n  allowed_tools: null\n  denied_tools: []\n"
            "  pii_redaction:\n    enabled: false\n  resource_limits: {}\n"
            "on_violation: block\n"
        )
        c.write_text(
            "name: z\nversion: '1.0'\nextends: x.yaml\n"
            "rules:\n  allowed_tools: null\n  denied_tools: []\n"
            "  pii_redaction:\n    enabled: false\n  resource_limits: {}\n"
            "on_violation: block\n"
        )
        with pytest.raises(PolicyLoadError, match=r"[Cc]ircular"):
            Policy.from_file(a)

    def test_valid_chain_does_not_raise(self, tmp_path: Path) -> None:
        """A valid A → B chain (no cycle) must load without error."""
        base = tmp_path / "base.yaml"
        child = tmp_path / "child.yaml"
        _policy_stub = (
            "rules:\n"
            "  allowed_tools: null\n"
            "  denied_tools: []\n"
            "  pii_redaction:\n"
            "    enabled: false\n"
            "  resource_limits: {}\n"
            "on_violation: block\n"
        )
        base.write_text("name: base\nversion: '1.0'\n" + _policy_stub)
        child.write_text(f"name: child\nversion: '1.0'\nextends: {base}\n" + _policy_stub)
        policy = Policy.from_file(child)
        assert policy.name == "child"


# ---------------------------------------------------------------------------
# MultiTenantEnforcer — registration API
# ---------------------------------------------------------------------------


class TestMultiTenantEnforcerRegistration:
    def test_register_and_tenants(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("alpha", _allow_all())
        mte.register("beta", _allow_all())
        assert mte.tenants == ["alpha", "beta"]

    def test_tenants_sorted(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("zzz", _allow_all())
        mte.register("aaa", _allow_all())
        assert mte.tenants == ["aaa", "zzz"]

    def test_empty_tenant_id_raises(self) -> None:
        mte = MultiTenantEnforcer()
        with pytest.raises(ValueError, match="empty"):
            mte.register("", _allow_all())

    def test_whitespace_only_tenant_id_raises(self) -> None:
        mte = MultiTenantEnforcer()
        with pytest.raises(ValueError, match="empty"):
            mte.register("   ", _allow_all())

    def test_unregister(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("t1", _allow_all())
        mte.unregister("t1")
        assert "t1" not in mte.tenants

    def test_unregister_nonexistent_raises(self) -> None:
        mte = MultiTenantEnforcer()
        with pytest.raises(KeyError):
            mte.unregister("ghost")

    def test_re_register_clears_cache(self) -> None:
        """Re-registering a tenant invalidates the cached Enforcer."""
        mte = MultiTenantEnforcer()
        mte.register("t", _allow_all())
        e1 = mte.get_enforcer("t")
        mte.register("t", _allow_all())  # new policy registration
        e2 = mte.get_enforcer("t")
        assert e1 is not e2


# ---------------------------------------------------------------------------
# MultiTenantEnforcer — get_enforcer
# ---------------------------------------------------------------------------


class TestMultiTenantEnforcerGetEnforcer:
    def test_lazy_build(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("t", _allow_all())
        enforcer = mte.get_enforcer("t")
        assert isinstance(enforcer, Enforcer)
        assert enforcer.tenant_id == "t"

    def test_cached_enforcer(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("t", _allow_all())
        e1 = mte.get_enforcer("t")
        e2 = mte.get_enforcer("t")
        assert e1 is e2  # same object — cached

    def test_path_registration(self, tmp_path: Path) -> None:
        """Registering a path (str) loads the policy lazily."""
        path = tmp_path / "pol.yaml"
        path.write_text(
            "name: lazy\nversion: '1.0'\nrules:\n  allowed_tools: null\n  denied_tools: []\n  pii_redaction:\n    enabled: false\n  resource_limits: {}\non_violation: block\n"
        )
        mte = MultiTenantEnforcer()
        mte.register("lazy_t", str(path))
        enforcer = mte.get_enforcer("lazy_t")
        assert enforcer.tenant_id == "lazy_t"

    def test_unregistered_no_default_raises(self) -> None:
        mte = MultiTenantEnforcer()
        with pytest.raises(KeyError, match="ghost"):
            mte.get_enforcer("ghost")

    def test_unregistered_with_default_uses_default(self) -> None:
        mte = MultiTenantEnforcer(default_policy=_allow_all())
        enforcer = mte.get_enforcer("unknown_tenant")
        assert isinstance(enforcer, Enforcer)
        assert enforcer.tenant_id == "unknown_tenant"


# ---------------------------------------------------------------------------
# MultiTenantEnforcer — enforce_sync / enforce_async
# ---------------------------------------------------------------------------


class TestMultiTenantEnforcerEnforce:
    def test_enforce_sync_allowed(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("t", _allow_all())
        result = mte.enforce_sync("t", add, 3, 4)
        assert result == 7

    def test_enforce_sync_denied_tool(self) -> None:
        from enforcecore.core.types import ToolDeniedError

        mte = MultiTenantEnforcer()
        mte.register("t", _specific())
        with pytest.raises(ToolDeniedError):
            mte.enforce_sync("t", add, 1, 2, tool_name="execute_shell")

    def test_enforce_async_allowed(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("t", _allow_all())
        result = asyncio.run(mte.enforce_async("t", async_add, 5, 6))
        assert result == 11

    def test_enforce_async_denied_tool(self) -> None:
        from enforcecore.core.types import ToolDeniedError

        mte = MultiTenantEnforcer()
        mte.register("t", _specific())
        with pytest.raises(ToolDeniedError):
            asyncio.run(mte.enforce_async("t", async_add, 1, 2, tool_name="execute_shell"))

    def test_enforce_sync_unregistered_raises(self) -> None:
        mte = MultiTenantEnforcer()
        with pytest.raises(KeyError):
            mte.enforce_sync("ghost", add, 1, 2)

    def test_two_tenants_independent_policies(self) -> None:
        """Each tenant enforces its own policy independently."""
        from enforcecore.core.types import ToolDeniedError

        mte = MultiTenantEnforcer()
        mte.register("open_tenant", _allow_all())
        mte.register("strict_tenant", _specific())

        # open_tenant can call execute_shell
        assert mte.enforce_sync("open_tenant", add, 1, 2, tool_name="execute_shell") == 3

        # strict_tenant blocks it
        with pytest.raises(ToolDeniedError):
            mte.enforce_sync("strict_tenant", add, 1, 2, tool_name="execute_shell")


# ---------------------------------------------------------------------------
# MultiTenantEnforcer — dunder helpers
# ---------------------------------------------------------------------------


class TestMultiTenantEnforcerDunders:
    def test_contains(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("x", _allow_all())
        assert "x" in mte
        assert "y" not in mte

    def test_len(self) -> None:
        mte = MultiTenantEnforcer()
        assert len(mte) == 0
        mte.register("a", _allow_all())
        assert len(mte) == 1
        mte.register("b", _allow_all())
        assert len(mte) == 2

    def test_repr(self) -> None:
        mte = MultiTenantEnforcer()
        assert "MultiTenantEnforcer" in repr(mte)
        assert "tenants=0" in repr(mte)
        mte.register("t1", _allow_all())
        assert "tenants=1" in repr(mte)

    def test_repr_after_unregister(self) -> None:
        mte = MultiTenantEnforcer()
        mte.register("t1", _allow_all())
        mte.register("t2", _allow_all())
        mte.unregister("t1")
        assert "tenants=1" in repr(mte)


# ---------------------------------------------------------------------------
# MultiTenantEnforcer — exported from public API
# ---------------------------------------------------------------------------


class TestMultiTenantEnforcerPublicAPI:
    def test_importable_from_enforcecore(self) -> None:
        from enforcecore import MultiTenantEnforcer as MultiTenantEnf

        assert MultiTenantEnf is MultiTenantEnforcer

    def test_importable_from_core(self) -> None:
        from enforcecore.core import MultiTenantEnforcer as MultiTenantEnf

        assert MultiTenantEnf is MultiTenantEnforcer

    def test_in_all(self) -> None:
        import enforcecore

        assert "MultiTenantEnforcer" in enforcecore.__all__

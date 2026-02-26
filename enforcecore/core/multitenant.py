# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Multi-tenant enforcement support for EnforceCore.

:class:`MultiTenantEnforcer` is a registry that maps tenant IDs to their
own :class:`Enforcer` instances, each backed by a separate policy.  Every
audit entry written through the registry carries the ``tenant_id`` field,
enabling per-tenant filtering of audit trails.

Typical usage::

    from enforcecore.core.multitenant import MultiTenantEnforcer

    mte = MultiTenantEnforcer()
    mte.register("team_alpha", "policies/team_alpha.yaml")
    mte.register("team_beta",  "policies/team_beta.yaml")

    result = await mte.enforce_async("team_alpha", my_tool, query="hello")

Policy inheritance works transparently — each per-tenant YAML may use
``extends:`` to build on an org-wide base::

    # team_alpha.yaml
    extends: ../org_base.yaml
    name: team_alpha
    rules:
      allowed_tools: [search, summarise]

.. versionadded:: 1.6.0
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

from enforcecore.core.enforcer import Enforcer
from enforcecore.core.policy import Policy

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = structlog.get_logger("enforcecore.multitenant")

T = TypeVar("T")


class MultiTenantEnforcer:
    """Registry mapping tenant IDs to independent :class:`Enforcer` instances.

    Thread-safe.  Enforcer instances are created lazily on first use of a
    given tenant and then cached for the lifetime of the registry.

    Args:
        default_policy: Optional fallback :class:`Policy` or YAML path used
            for tenants that have not been explicitly registered.  If *None*
            (the default), calls for unregistered tenants raise
            :class:`KeyError`.

    Example::

        mte = MultiTenantEnforcer(default_policy="policies/org_base.yaml")
        # team_a has a custom policy; team_b falls back to org_base
        mte.register("team_a", "policies/team_a.yaml")

        result = await mte.enforce_async("team_a", my_tool, arg="x")
        result = await mte.enforce_async("team_b", my_tool, arg="y")

    .. versionadded:: 1.6.0
    """

    def __init__(self, default_policy: Policy | str | Path | None = None) -> None:
        self._lock = threading.Lock()
        # {tenant_id: Enforcer}  (lazily populated)
        self._enforcers: dict[str, Enforcer] = {}
        # {tenant_id: policy source}  (path or Policy object)
        self._registrations: dict[str, Policy | str | Path] = {}
        self._default: Policy | str | Path | None = default_policy

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        tenant_id: str,
        policy: Policy | str | Path,
    ) -> None:
        """Register a policy for *tenant_id*.

        Args:
            tenant_id: Tenant identifier string (e.g. ``"team_alpha"``).
            policy: A :class:`Policy` instance **or** a path to a YAML
                policy file.  If a path, the policy is loaded lazily on
                the first call for this tenant.

        Raises:
            ValueError: If *tenant_id* is empty.
        """
        if not tenant_id or not tenant_id.strip():
            msg = "tenant_id must not be empty"
            raise ValueError(msg)
        with self._lock:
            self._registrations[tenant_id] = policy
            # Invalidate any cached enforcer so it is rebuilt next call.
            self._enforcers.pop(tenant_id, None)
        logger.debug("tenant_registered", tenant=tenant_id)

    def unregister(self, tenant_id: str) -> None:
        """Remove the registration for *tenant_id*.

        Args:
            tenant_id: The tenant to remove.

        Raises:
            KeyError: If *tenant_id* is not registered.
        """
        with self._lock:
            if tenant_id not in self._registrations:
                raise KeyError(tenant_id)
            del self._registrations[tenant_id]
            self._enforcers.pop(tenant_id, None)
        logger.debug("tenant_unregistered", tenant=tenant_id)

    @property
    def tenants(self) -> list[str]:
        """Sorted list of currently registered tenant IDs."""
        with self._lock:
            return sorted(self._registrations)

    # ------------------------------------------------------------------
    # Enforcer access
    # ------------------------------------------------------------------

    def get_enforcer(self, tenant_id: str) -> Enforcer:
        """Return (or lazily build) the :class:`Enforcer` for *tenant_id*.

        Args:
            tenant_id: The tenant identifier.

        Returns:
            The :class:`Enforcer` for this tenant.

        Raises:
            KeyError: If *tenant_id* is not registered and no default policy
                is configured.
        """
        with self._lock:
            if tenant_id in self._enforcers:
                return self._enforcers[tenant_id]
            source = self._registrations.get(tenant_id) or self._default
            if source is None:
                raise KeyError(
                    f"No policy registered for tenant {tenant_id!r} "
                    "and no default policy configured."
                )
            enforcer = self._build_enforcer(tenant_id, source)
            self._enforcers[tenant_id] = enforcer
            return enforcer

    @staticmethod
    def _build_enforcer(tenant_id: str, source: Policy | str | Path) -> Enforcer:
        """Create an :class:`Enforcer` tagged with *tenant_id*."""
        policy = source if isinstance(source, Policy) else Policy.from_file(source)
        return Enforcer(policy, tenant_id=tenant_id)

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------

    def enforce_sync(
        self,
        tenant_id: str,
        func: Callable[..., T],
        /,
        *args: Any,
        tool_name: str | None = None,
        **kwargs: Any,
    ) -> T:
        """Enforce *func* under the policy for *tenant_id* (sync).

        Args:
            tenant_id: The tenant to enforce under.
            func: The callable to enforce.
            *args: Positional arguments for *func*.
            tool_name: Override the tool name (defaults to ``func.__name__``).
            **kwargs: Keyword arguments for *func*.

        Returns:
            The return value of *func*.

        Raises:
            KeyError: If *tenant_id* is not registered.
            EnforcementViolation: If the call violates the tenant's policy.
        """
        enforcer = self.get_enforcer(tenant_id)
        return enforcer.enforce_sync(func, *args, tool_name=tool_name, **kwargs)

    async def enforce_async(
        self,
        tenant_id: str,
        func: Callable[..., Any],
        /,
        *args: Any,
        tool_name: str | None = None,
        **kwargs: Any,
    ) -> Any:
        """Enforce *func* under the policy for *tenant_id* (async).

        Args:
            tenant_id: The tenant to enforce under.
            func: The async callable to enforce.
            *args: Positional arguments for *func*.
            tool_name: Override the tool name (defaults to ``func.__name__``).
            **kwargs: Keyword arguments for *func*.

        Returns:
            The awaited return value of *func*.

        Raises:
            KeyError: If *tenant_id* is not registered.
            EnforcementViolation: If the call violates the tenant's policy.
        """
        enforcer = self.get_enforcer(tenant_id)
        return await enforcer.enforce_async(func, *args, tool_name=tool_name, **kwargs)

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        with self._lock:
            n = len(self._registrations)
        return f"<MultiTenantEnforcer tenants={n}>"

    def __len__(self) -> int:
        with self._lock:
            return len(self._registrations)

    def __contains__(self, tenant_id: object) -> bool:
        with self._lock:
            return tenant_id in self._registrations

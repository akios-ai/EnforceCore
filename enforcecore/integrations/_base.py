# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Shared utilities for framework integration adapters.

This module provides the building blocks used by all framework-specific
adapters.  It has no external dependencies beyond EnforceCore itself.

The adapters in this package use *optional imports* — framework packages
(``langchain-core``, ``crewai``, ``autogen-core``) are only loaded when
you call the adapter functions.  Importing an adapter module never fails.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from enforcecore.core.policy import Policy

__all__ = ["require_package", "wrap_with_policy"]


def require_package(package: str, *, pip_name: str | None = None) -> None:
    """Verify that *package* is importable; raise with install instructions if not.

    This is called by each framework adapter before attempting to import
    framework-specific modules, so users get a clear error message instead
    of a raw ``ModuleNotFoundError``.

    Args:
        package: Top-level Python package name to check
            (e.g. ``"langchain_core"``).
        pip_name: PyPI name shown in the error message when it differs
            from *package* (e.g. ``"langchain-core"``).

    Raises:
        ImportError: With a user-friendly ``pip install`` command.
    """
    try:
        __import__(package)
    except ImportError:
        install = pip_name or package
        msg = (
            f"Package '{package}' is required for this EnforceCore integration "
            f"but is not installed.  Install it with:  pip install {install}"
        )
        raise ImportError(msg) from None


def wrap_with_policy(
    func: Callable[..., Any],
    *,
    policy: str | Path | Policy | None = None,
    tool_name: str | None = None,
) -> Callable[..., Any]:
    """Wrap *func* with EnforceCore policy enforcement.

    This is the shared core used by all framework adapters.  It applies
    the ``@enforce()`` decorator, preserving the original function's
    signature and metadata via ``functools.wraps``.

    Args:
        func: The callable to wrap (sync or async).
        policy: A YAML policy path, ``Policy`` object, or ``None`` to use
            the default policy from ``ENFORCECORE_DEFAULT_POLICY``.
        tool_name: Override the tool name used for policy evaluation.

    Returns:
        A wrapped callable whose every invocation is subject to policy
        enforcement (pre-call checks, PII redaction, resource limits,
        cost tracking, audit trail, etc.).

    Raises:
        PolicyLoadError: If *policy* is ``None`` and no default policy
            is configured.
    """
    from enforcecore.core.enforcer import enforce

    # Two-step pattern so mypy matches the keyword-only overload:
    #   enforce(policy=..., tool_name=...) → decorator
    #   decorator(func) → wrapped callable
    decorator = enforce(policy=policy, tool_name=tool_name)
    return decorator(func)

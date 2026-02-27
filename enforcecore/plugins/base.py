# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Abstract base classes for EnforceCore plugins.

Third parties publish plugins by:

1. Subclassing :class:`GuardPlugin`, :class:`RedactorPlugin`, or
   :class:`AuditBackendPlugin`.
2. Registering the class via ``pyproject.toml`` entry points::

       [project.entry-points."enforcecore.guards"]
       my-guard = "my_package.guards:MyGuard"

       [project.entry-points."enforcecore.redactors"]
       my-redactor = "my_package.redactors:MyRedactor"

       [project.entry-points."enforcecore.audit_backends"]
       my-backend = "my_package.backends:MyAuditBackend"

3. :meth:`PluginManager.discover` / :meth:`PluginManager.load_all` will
   auto-load them.

**Plugin API stability:** This module follows **Tier 1** stability
guarantees.  The abstract method signatures of :class:`GuardPlugin`,
:class:`RedactorPlugin`, and :class:`AuditBackendPlugin` will not change
in any v1.x release.  :class:`GuardResult` and :class:`RedactResult` may
gain optional fields in minor releases (additive only).

.. versionadded:: 1.9.0
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GuardResult:
    """The result of a :class:`GuardPlugin` check.

    Attributes:
        allowed: ``True`` if the tool call should proceed, ``False`` to
            block it.
        reason: Human-readable explanation.  Required when *allowed* is
            ``False``; optional (but helpful) when *allowed* is ``True``.
    """

    allowed: bool
    reason: str = ""


@dataclass(frozen=True)
class RedactResult:
    """The result of a :class:`RedactorPlugin` pass.

    Attributes:
        text: The redacted text (same as input if nothing was found).
        count: Number of redactions applied.
    """

    text: str
    count: int = 0


# ---------------------------------------------------------------------------
# Plugin metadata
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PluginInfo:
    """Metadata about a discovered or loaded plugin.

    Attributes:
        name: Entry-point name as registered in ``pyproject.toml``.
        version: Distribution version of the package that provides the plugin.
        kind: One of ``"guard"``, ``"redactor"``, or ``"audit_backend"``.
        package: Dotted import path of the plugin class (``module:Class``).
        description: Optional human-readable description.
    """

    name: str
    version: str
    kind: str  # "guard" | "redactor" | "audit_backend"
    package: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# Abstract base classes
# ---------------------------------------------------------------------------


class GuardPlugin(abc.ABC):
    """Abstract base class for custom guard plugins.

    Subclass this to publish a guard that EnforceCore can discover and call
    during enforcement.  A guard runs **after** allow/deny list checks and
    **before** the tool executes.

    Returning :class:`GuardResult` with ``allowed=False`` blocks the tool
    call with an :class:`~enforcecore.core.types.EnforcementViolation`.

    Example::

        class ToxicityGuard(GuardPlugin):
            @property
            def name(self) -> str:
                return "toxicity-guard"

            @property
            def version(self) -> str:
                return "1.0.0"

            def check(self, tool_name, args, kwargs) -> GuardResult:
                text = str(args) + str(kwargs)
                if is_toxic(text):
                    return GuardResult(allowed=False, reason="toxic content")
                return GuardResult(allowed=True)

    Publish via ``pyproject.toml``::

        [project.entry-points."enforcecore.guards"]
        toxicity-guard = "my_pkg.guards:ToxicityGuard"

    .. versionadded:: 1.9.0
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique plugin name (lowercase, hyphens allowed).

        Example: ``"toxicity-guard"``.
        """
        ...  # pragma: no cover

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Semantic version string of this plugin.

        Example: ``"1.0.0"``.
        """
        ...  # pragma: no cover

    @abc.abstractmethod
    def check(
        self,
        tool_name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> GuardResult:
        """Check whether a tool call should be allowed.

        Args:
            tool_name: Name of the tool being called.
            args: Positional arguments to the tool.
            kwargs: Keyword arguments to the tool.

        Returns:
            :class:`GuardResult` — ``allowed=True`` to permit the call,
            ``allowed=False`` to block it (include a ``reason``).
        """
        ...  # pragma: no cover

    def info(self) -> PluginInfo:
        """Return metadata about this plugin."""
        return PluginInfo(name=self.name, version=self.version, kind="guard")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, version={self.version!r})"


class RedactorPlugin(abc.ABC):
    """Abstract base class for custom redactor plugins.

    Subclass this to publish a redactor that EnforceCore applies in the PII
    detection pipeline.  Called on both tool inputs and outputs.

    Example::

        class EmployeeIDRedactor(RedactorPlugin):
            @property
            def name(self) -> str:
                return "employee-id-redactor"

            @property
            def version(self) -> str:
                return "1.0.0"

            @property
            def categories(self) -> list[str]:
                return ["employee_id", "internal_project_code"]

            def redact(self, text: str) -> RedactResult:
                import re
                result, n = re.subn(r'EMP-\\d{6}', '[EMPLOYEE_ID]', text)
                return RedactResult(text=result, count=n)

    Publish via ``pyproject.toml``::

        [project.entry-points."enforcecore.redactors"]
        employee-id-redactor = "my_pkg.redactors:EmployeeIDRedactor"

    .. versionadded:: 1.9.0
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique plugin name (lowercase, hyphens allowed)."""
        ...  # pragma: no cover

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Semantic version string of this plugin."""
        ...  # pragma: no cover

    @property
    @abc.abstractmethod
    def categories(self) -> list[str]:
        """PII category names this plugin detects.

        Example: ``["employee_id", "internal_project_code"]``.
        """
        ...  # pragma: no cover

    @abc.abstractmethod
    def redact(self, text: str) -> RedactResult:
        """Redact PII from *text*.

        Args:
            text: Raw text to scan and redact.

        Returns:
            :class:`RedactResult` with the redacted text and count of
            redactions applied.  Return ``RedactResult(text=text, count=0)``
            if no PII was found.
        """
        ...  # pragma: no cover

    def info(self) -> PluginInfo:
        """Return metadata about this plugin."""
        return PluginInfo(name=self.name, version=self.version, kind="redactor")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, version={self.version!r})"


class AuditBackendPlugin(abc.ABC):
    """Abstract base class for custom audit backend plugins.

    Subclass this to publish an audit backend that persists audit entries to
    a custom destination (SaaS SIEM, custom database, stream, etc.).

    :meth:`record` is called synchronously for every enforcement decision.
    Keep it fast — heavy I/O should be buffered and flushed in :meth:`flush`.

    Example::

        class SplunkAuditBackend(AuditBackendPlugin):
            def __init__(self):
                self._buffer = []

            @property
            def name(self) -> str:
                return "splunk-audit-backend"

            @property
            def version(self) -> str:
                return "1.0.0"

            def record(self, entry: dict) -> None:
                self._buffer.append(entry)
                if len(self._buffer) >= 100:
                    self.flush()

            def flush(self) -> None:
                if self._buffer:
                    splunk_client.send_batch(self._buffer)
                    self._buffer.clear()

    Publish via ``pyproject.toml``::

        [project.entry-points."enforcecore.audit_backends"]
        splunk-audit-backend = "my_pkg.backends:SplunkAuditBackend"

    .. versionadded:: 1.9.0
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Unique plugin name (lowercase, hyphens allowed)."""
        ...  # pragma: no cover

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """Semantic version string of this plugin."""
        ...  # pragma: no cover

    @abc.abstractmethod
    def record(self, entry: dict[str, Any]) -> None:
        """Record a single audit entry.

        Called for every enforcement decision.  Must not raise — the plugin
        manager catches and logs exceptions so the enforcement pipeline is
        never broken by a misbehaving backend.

        Args:
            entry: Audit entry dict matching the ``AuditEntry.to_dict()``
                schema.
        """
        ...  # pragma: no cover

    @abc.abstractmethod
    def flush(self) -> None:
        """Flush any buffered audit entries.

        Called on enforcer shutdown or when the operator requests a flush.
        Must not raise.
        """
        ...  # pragma: no cover

    def info(self) -> PluginInfo:
        """Return metadata about this plugin."""
        return PluginInfo(name=self.name, version=self.version, kind="audit_backend")

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, version={self.version!r})"

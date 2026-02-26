# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Plugin manager — discovers and loads EnforceCore plugins from entry points.

Usage::

    manager = PluginManager()
    manager.load_all()

    for guard in manager.guards:
        result = guard.check("my_tool", args, kwargs)
        if not result.allowed:
            raise EnforcementViolation(result.reason)

    # Discover without loading (metadata only):
    for info in manager.discover():
        print(info.name, info.kind, info.version)

.. versionadded:: 1.9.0
"""

from __future__ import annotations

import importlib.metadata
import threading

import structlog

from enforcecore.plugins.base import (
    AuditBackendPlugin,
    GuardPlugin,
    PluginInfo,
    RedactorPlugin,
)

logger = structlog.get_logger("enforcecore.plugins.manager")

# ---------------------------------------------------------------------------
# Entry-point group names (stable in v1.x)
# ---------------------------------------------------------------------------

_ENTRY_POINT_GROUPS: dict[str, str] = {
    "guard": "enforcecore.guards",
    "redactor": "enforcecore.redactors",
    "audit_backend": "enforcecore.audit_backends",
}

_BASE_CLASSES: dict[str, type] = {
    "guard": GuardPlugin,
    "redactor": RedactorPlugin,
    "audit_backend": AuditBackendPlugin,
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PluginLoadError(Exception):
    """Raised when a plugin fails to load or instantiate.

    Common causes:

    * The entry-point module cannot be imported (missing dependency).
    * The class registered in the entry point is not a valid subclass of
      :class:`~enforcecore.plugins.base.GuardPlugin`,
      :class:`~enforcecore.plugins.base.RedactorPlugin`, or
      :class:`~enforcecore.plugins.base.AuditBackendPlugin`.
    * The plugin class ``__init__`` raised an exception.

    .. versionadded:: 1.9.0
    """


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_dist_version(ep: importlib.metadata.EntryPoint) -> str:
    """Return the distribution version for *ep*, or ``""`` if unavailable."""
    try:
        dist = ep.dist
        if dist is not None:
            return str(dist.version)
    except AttributeError:
        pass
    return ""


# ---------------------------------------------------------------------------
# PluginManager
# ---------------------------------------------------------------------------


class PluginManager:
    """Discovers and loads EnforceCore plugins from installed packages.

    Plugins are published by third-party packages via ``pyproject.toml``
    entry points.  :meth:`discover` scans installed packages without loading
    any code.  :meth:`load_all` (or :meth:`load`) imports and instantiates
    the plugin classes.

    Thread-safe: all mutations to the internal plugin lists are protected by a
    :class:`threading.Lock`.

    Entry-point groups
    ------------------
    ``enforcecore.guards``
        Each entry point must point to a :class:`~enforcecore.plugins.base.GuardPlugin`
        subclass.

    ``enforcecore.redactors``
        Each entry point must point to a
        :class:`~enforcecore.plugins.base.RedactorPlugin` subclass.

    ``enforcecore.audit_backends``
        Each entry point must point to an
        :class:`~enforcecore.plugins.base.AuditBackendPlugin` subclass.

    Example::

        manager = PluginManager()
        n = manager.load_all(ignore_errors=True)
        print(f"Loaded {n} plugins")
        for guard in manager.guards:
            print(guard.name, guard.version)

    .. versionadded:: 1.9.0
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._guards: list[GuardPlugin] = []
        self._redactors: list[RedactorPlugin] = []
        self._audit_backends: list[AuditBackendPlugin] = []

    # ------------------------------------------------------------------
    # Discovery (no imports — metadata only)
    # ------------------------------------------------------------------

    def discover(self) -> list[PluginInfo]:
        """Scan installed packages for EnforceCore plugin entry points.

        Does **not** import or instantiate any plugin code.  Returns only
        metadata gathered from the package index.

        Returns:
            List of :class:`~enforcecore.plugins.base.PluginInfo` describing
            each discovered entry point across all three groups.
        """
        infos: list[PluginInfo] = []
        for kind, group in _ENTRY_POINT_GROUPS.items():
            for ep in importlib.metadata.entry_points(group=group):
                version = _get_dist_version(ep)
                infos.append(
                    PluginInfo(
                        name=ep.name,
                        version=version,
                        kind=kind,
                        package=ep.value,
                    )
                )
        return infos

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_all(self, *, ignore_errors: bool = False) -> int:
        """Load all discovered plugins.

        Args:
            ignore_errors: If ``True``, :class:`PluginLoadError` exceptions
                are logged as warnings and skipped rather than re-raised.
                Default ``False`` (fail fast).

        Returns:
            Number of plugins successfully loaded.

        Raises:
            PluginLoadError: If a plugin fails to load and *ignore_errors*
                is ``False``.
        """
        loaded = 0
        for kind, group in _ENTRY_POINT_GROUPS.items():
            for ep in importlib.metadata.entry_points(group=group):
                try:
                    self._load_entry_point(ep, kind)
                    loaded += 1
                except PluginLoadError:
                    if not ignore_errors:
                        raise
                    logger.warning(
                        "plugin_load_failed",
                        name=ep.name,
                        kind=kind,
                        entrypoint=ep.value,
                    )
        return loaded

    def load(self, name: str) -> None:
        """Load a plugin by its entry-point name.

        Searches all entry-point groups for *name* and loads the first match.

        Args:
            name: Entry-point name as registered in ``pyproject.toml``.

        Raises:
            PluginLoadError: If the plugin is not found or fails to load.
        """
        for kind, group in _ENTRY_POINT_GROUPS.items():
            for ep in importlib.metadata.entry_points(group=group):
                if ep.name == name:
                    self._load_entry_point(ep, kind)
                    return
        msg = f"No plugin named {name!r} found in any EnforceCore entry-point group."
        raise PluginLoadError(msg)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_entry_point(
        self,
        ep: importlib.metadata.EntryPoint,
        kind: str,
    ) -> None:
        """Import, validate, and instantiate a single entry-point plugin."""
        try:
            cls = ep.load()
        except Exception as exc:
            msg = f"Failed to import plugin {ep.name!r} ({ep.value}): {exc}"
            raise PluginLoadError(msg) from exc

        expected_base = _BASE_CLASSES[kind]
        if not (isinstance(cls, type) and issubclass(cls, expected_base)):
            msg = (
                f"Plugin {ep.name!r} ({ep.value}) must be a subclass of "
                f"{expected_base.__name__}, got {cls!r}."
            )
            raise PluginLoadError(msg)

        try:
            instance = cls()
        except Exception as exc:
            msg = f"Failed to instantiate plugin {ep.name!r} ({ep.value}): {exc}"
            raise PluginLoadError(msg) from exc

        version = _get_dist_version(ep)
        with self._lock:
            if kind == "guard":
                self._guards.append(instance)  # type: ignore[arg-type]
            elif kind == "redactor":
                self._redactors.append(instance)  # type: ignore[arg-type]
            else:
                self._audit_backends.append(instance)  # type: ignore[arg-type]

        logger.debug(
            "plugin_loaded",
            name=ep.name,
            kind=kind,
            version=version,
            cls=f"{cls.__module__}.{cls.__qualname__}",
        )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def guards(self) -> list[GuardPlugin]:
        """Loaded guard plugins (returns a defensive copy)."""
        with self._lock:
            return list(self._guards)

    @property
    def redactors(self) -> list[RedactorPlugin]:
        """Loaded redactor plugins (returns a defensive copy)."""
        with self._lock:
            return list(self._redactors)

    @property
    def audit_backends(self) -> list[AuditBackendPlugin]:
        """Loaded audit backend plugins (returns a defensive copy)."""
        with self._lock:
            return list(self._audit_backends)

    def __repr__(self) -> str:
        g = len(self._guards)
        r = len(self._redactors)
        a = len(self._audit_backends)
        return f"PluginManager(guards={g}, redactors={r}, audit_backends={a})"

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.9.0 Plugin Ecosystem.

Covers:
- enforcecore.plugins.base: GuardPlugin, RedactorPlugin, AuditBackendPlugin ABCs
- enforcecore.plugins.base: GuardResult, RedactResult, PluginInfo dataclasses
- enforcecore.plugins.manager: PluginManager, PluginLoadError
- enforcecore plugin CLI: plugin list, plugin info
- Public API symbols (Tier 1)
"""

from __future__ import annotations

import importlib.metadata
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

import enforcecore
from enforcecore.plugins.base import (
    AuditBackendPlugin,
    GuardPlugin,
    GuardResult,
    PluginInfo,
    RedactorPlugin,
    RedactResult,
)
from enforcecore.plugins.manager import PluginLoadError, PluginManager

# ---------------------------------------------------------------------------
# Concrete plugin implementations for testing
# ---------------------------------------------------------------------------


class AllowGuard(GuardPlugin):
    """A guard that always allows."""

    @property
    def name(self) -> str:
        return "allow-guard"

    @property
    def version(self) -> str:
        return "1.0.0"

    def check(self, tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> GuardResult:
        return GuardResult(allowed=True)


class BlockGuard(GuardPlugin):
    """A guard that always blocks."""

    @property
    def name(self) -> str:
        return "block-guard"

    @property
    def version(self) -> str:
        return "2.0.0"

    def check(self, tool_name: str, args: tuple[Any, ...], kwargs: dict[str, Any]) -> GuardResult:
        return GuardResult(allowed=False, reason="blocked by test guard")


class SimpleRedactor(RedactorPlugin):
    """A redactor that replaces 'SECRET' with '[REDACTED]'."""

    @property
    def name(self) -> str:
        return "simple-redactor"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def categories(self) -> list[str]:
        return ["test_secret"]

    def redact(self, text: str) -> RedactResult:
        count = text.count("SECRET")
        return RedactResult(text=text.replace("SECRET", "[REDACTED]"), count=count)


class BufferingAuditBackend(AuditBackendPlugin):
    """An audit backend that buffers entries in memory."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._flushed = False

    @property
    def name(self) -> str:
        return "buffering-audit-backend"

    @property
    def version(self) -> str:
        return "1.0.0"

    def record(self, entry: dict[str, Any]) -> None:
        self._entries.append(entry)

    def flush(self) -> None:
        self._flushed = True


# ---------------------------------------------------------------------------
# GuardResult tests
# ---------------------------------------------------------------------------


class TestGuardResult:
    def test_allowed_defaults_reason_empty(self) -> None:
        r = GuardResult(allowed=True)
        assert r.allowed is True
        assert r.reason == ""

    def test_blocked_with_reason(self) -> None:
        r = GuardResult(allowed=False, reason="too dangerous")
        assert r.allowed is False
        assert r.reason == "too dangerous"

    def test_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        r = GuardResult(allowed=True)
        with pytest.raises(FrozenInstanceError):
            r.allowed = False  # type: ignore[misc]

    def test_equality(self) -> None:
        assert GuardResult(allowed=True) == GuardResult(allowed=True)
        assert GuardResult(allowed=False, reason="x") != GuardResult(allowed=True)


# ---------------------------------------------------------------------------
# RedactResult tests
# ---------------------------------------------------------------------------


class TestRedactResult:
    def test_defaults(self) -> None:
        r = RedactResult(text="hello")
        assert r.text == "hello"
        assert r.count == 0

    def test_with_count(self) -> None:
        r = RedactResult(text="[REDACTED]", count=1)
        assert r.count == 1

    def test_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        r = RedactResult(text="x")
        with pytest.raises(FrozenInstanceError):
            r.text = "y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PluginInfo tests
# ---------------------------------------------------------------------------


class TestPluginInfo:
    def test_required_fields(self) -> None:
        info = PluginInfo(name="my-guard", version="1.0.0", kind="guard")
        assert info.name == "my-guard"
        assert info.version == "1.0.0"
        assert info.kind == "guard"
        assert info.package == ""
        assert info.description == ""

    def test_all_fields(self) -> None:
        info = PluginInfo(
            name="my-guard",
            version="1.0.0",
            kind="guard",
            package="my_pkg.guards:MyGuard",
            description="Does stuff",
        )
        assert info.package == "my_pkg.guards:MyGuard"
        assert info.description == "Does stuff"

    def test_frozen(self) -> None:
        from dataclasses import FrozenInstanceError

        info = PluginInfo(name="x", version="1.0", kind="guard")
        with pytest.raises(FrozenInstanceError):
            info.name = "y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# GuardPlugin tests
# ---------------------------------------------------------------------------


class TestGuardPlugin:
    def test_allow_guard_passes(self) -> None:
        g = AllowGuard()
        result = g.check("my_tool", (), {})
        assert result.allowed is True

    def test_block_guard_blocks(self) -> None:
        g = BlockGuard()
        result = g.check("dangerous_tool", (1, 2), {"key": "val"})
        assert result.allowed is False
        assert "blocked" in result.reason

    def test_info_returns_plugin_info(self) -> None:
        g = AllowGuard()
        info = g.info()
        assert isinstance(info, PluginInfo)
        assert info.kind == "guard"
        assert info.name == "allow-guard"
        assert info.version == "1.0.0"

    def test_repr(self) -> None:
        g = AllowGuard()
        r = repr(g)
        assert "allow-guard" in r
        assert "1.0.0" in r

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            GuardPlugin()  # type: ignore[abstract]

    def test_abstract_requires_name(self) -> None:
        class Incomplete(GuardPlugin):
            @property
            def version(self) -> str:
                return "1.0"

            def check(self, tool_name, args, kwargs):
                return GuardResult(allowed=True)

        with pytest.raises(TypeError):
            Incomplete()

    def test_abstract_requires_version(self) -> None:
        class Incomplete(GuardPlugin):
            @property
            def name(self) -> str:
                return "x"

            def check(self, tool_name, args, kwargs):
                return GuardResult(allowed=True)

        with pytest.raises(TypeError):
            Incomplete()

    def test_abstract_requires_check(self) -> None:
        class Incomplete(GuardPlugin):
            @property
            def name(self) -> str:
                return "x"

            @property
            def version(self) -> str:
                return "1.0"

        with pytest.raises(TypeError):
            Incomplete()


# ---------------------------------------------------------------------------
# RedactorPlugin tests
# ---------------------------------------------------------------------------


class TestRedactorPlugin:
    def test_redact_no_match(self) -> None:
        r = SimpleRedactor()
        result = r.redact("clean text")
        assert result.text == "clean text"
        assert result.count == 0

    def test_redact_match(self) -> None:
        r = SimpleRedactor()
        result = r.redact("My SECRET is here and another SECRET")
        assert "[REDACTED]" in result.text
        assert result.count == 2

    def test_categories(self) -> None:
        r = SimpleRedactor()
        assert r.categories == ["test_secret"]

    def test_info(self) -> None:
        r = SimpleRedactor()
        info = r.info()
        assert info.kind == "redactor"
        assert info.name == "simple-redactor"

    def test_repr(self) -> None:
        r = SimpleRedactor()
        assert "simple-redactor" in repr(r)

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            RedactorPlugin()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# AuditBackendPlugin tests
# ---------------------------------------------------------------------------


class TestAuditBackendPlugin:
    def test_record_and_flush(self) -> None:
        b = BufferingAuditBackend()
        b.record({"tool_name": "search", "decision": "allowed"})
        b.record({"tool_name": "exec", "decision": "blocked"})
        assert len(b._entries) == 2
        b.flush()
        assert b._flushed is True

    def test_info(self) -> None:
        b = BufferingAuditBackend()
        info = b.info()
        assert info.kind == "audit_backend"
        assert info.name == "buffering-audit-backend"

    def test_repr(self) -> None:
        b = BufferingAuditBackend()
        assert "buffering-audit-backend" in repr(b)

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            AuditBackendPlugin()  # type: ignore[abstract]


# ---------------------------------------------------------------------------
# PluginLoadError tests
# ---------------------------------------------------------------------------


class TestPluginLoadError:
    def test_is_exception(self) -> None:
        err = PluginLoadError("something went wrong")
        assert isinstance(err, Exception)
        assert str(err) == "something went wrong"

    def test_can_chain(self) -> None:
        cause = ValueError("root cause")
        err = PluginLoadError("load failed")
        try:
            raise err from cause
        except PluginLoadError as e:
            assert e.__cause__ is cause

    def test_importable_from_enforcecore(self) -> None:
        from enforcecore import PluginLoadError as ImportedPLE

        assert ImportedPLE is PluginLoadError


# ---------------------------------------------------------------------------
# PluginManager.discover tests (no real entry points in test env)
# ---------------------------------------------------------------------------


class TestPluginManagerDiscover:
    def test_discover_empty(self) -> None:
        """In the test env there are no enforcecore.guards entry points."""
        manager = PluginManager()
        plugins = manager.discover()
        # Should return a list (possibly empty — no real plugins installed)
        assert isinstance(plugins, list)

    def test_discover_returns_plugin_info_objects(self) -> None:
        """If entry points exist they must be PluginInfo instances."""
        manager = PluginManager()
        for info in manager.discover():
            assert isinstance(info, PluginInfo)
            assert info.kind in ("guard", "redactor", "audit_backend")

    def test_discover_with_mocked_entry_points(self) -> None:
        """Mocked discovery returns PluginInfo for each entry point."""
        mock_ep = MagicMock(spec=importlib.metadata.EntryPoint)
        mock_ep.name = "test-guard"
        mock_ep.value = "tests.plugins.test_plugin_ecosystem:AllowGuard"
        mock_ep.dist = MagicMock()
        mock_ep.dist.version = "0.1.0"

        def fake_entry_points(group: str):
            if group == "enforcecore.guards":
                return [mock_ep]
            return []

        with patch(
            "enforcecore.plugins.manager.importlib.metadata.entry_points", fake_entry_points
        ):
            manager = PluginManager()
            infos = manager.discover()

        assert len(infos) == 1
        assert infos[0].name == "test-guard"
        assert infos[0].kind == "guard"
        assert infos[0].version == "0.1.0"

    def test_discover_no_dist_version(self) -> None:
        """Entry points without a dist object get empty version string."""
        mock_ep = MagicMock(spec=importlib.metadata.EntryPoint)
        mock_ep.name = "no-ver-guard"
        mock_ep.value = "some.module:SomeGuard"
        del mock_ep.dist  # AttributeError path

        def fake_entry_points(group: str):
            if group == "enforcecore.guards":
                return [mock_ep]
            return []

        with patch(
            "enforcecore.plugins.manager.importlib.metadata.entry_points", fake_entry_points
        ):
            manager = PluginManager()
            infos = manager.discover()

        assert infos[0].version == ""


# ---------------------------------------------------------------------------
# PluginManager.load_all tests
# ---------------------------------------------------------------------------


class TestPluginManagerLoadAll:
    def _make_ep(
        self,
        name: str,
        cls: type,
        group_key: str = "guard",
        version: str = "1.0.0",
    ) -> MagicMock:
        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = name
        ep.value = f"{cls.__module__}:{cls.__qualname__}"
        ep.load.return_value = cls
        ep.dist = MagicMock()
        ep.dist.version = version
        ep._group_key = group_key
        return ep

    def _patch(self, eps_by_group: dict[str, list]) -> Any:
        import itertools

        def fake_eps(group: str):
            key_map = {
                "enforcecore.guards": "guard",
                "enforcecore.redactors": "redactor",
                "enforcecore.audit_backends": "audit_backend",
            }
            kind = key_map.get(group, "")
            return [
                ep
                for ep in itertools.chain.from_iterable(eps_by_group.values())
                if ep._group_key == kind
            ]

        return patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps)

    def test_load_all_empty(self) -> None:
        with patch(
            "enforcecore.plugins.manager.importlib.metadata.entry_points",
            return_value=[],
        ):
            manager = PluginManager()
            n = manager.load_all()
        assert n == 0
        assert manager.guards == []

    def test_load_all_guard(self) -> None:
        ep = self._make_ep("allow-guard", AllowGuard, "guard")
        with self._patch({"guard": [ep]}):
            manager = PluginManager()
            n = manager.load_all()
        assert n == 1
        assert len(manager.guards) == 1
        assert manager.guards[0].name == "allow-guard"

    def test_load_all_redactor(self) -> None:
        ep = self._make_ep("simple-redactor", SimpleRedactor, "redactor")
        with self._patch({"redactor": [ep]}):
            manager = PluginManager()
            n = manager.load_all()
        assert n == 1
        assert len(manager.redactors) == 1
        assert manager.redactors[0].name == "simple-redactor"

    def test_load_all_audit_backend(self) -> None:
        ep = self._make_ep("buf-backend", BufferingAuditBackend, "audit_backend")
        with self._patch({"audit_backend": [ep]}):
            manager = PluginManager()
            n = manager.load_all()
        assert n == 1
        assert len(manager.audit_backends) == 1

    def test_load_all_mixed(self) -> None:
        guard_ep = self._make_ep("g", AllowGuard, "guard")
        redact_ep = self._make_ep("r", SimpleRedactor, "redactor")
        backend_ep = self._make_ep("b", BufferingAuditBackend, "audit_backend")
        with self._patch(
            {"guard": [guard_ep], "redactor": [redact_ep], "audit_backend": [backend_ep]}
        ):
            manager = PluginManager()
            n = manager.load_all()
        assert n == 3
        assert len(manager.guards) == 1
        assert len(manager.redactors) == 1
        assert len(manager.audit_backends) == 1

    def test_load_all_bad_import_raises(self) -> None:
        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = "broken-guard"
        ep.value = "nonexistent.module:SomeGuard"
        ep.load.side_effect = ImportError("no module named nonexistent")
        ep.dist = None
        ep._group_key = "guard"

        def fake_eps(group: str):
            return [ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            manager = PluginManager()
            with pytest.raises(PluginLoadError, match="Failed to import"):
                manager.load_all()

    def test_load_all_bad_import_ignored(self) -> None:
        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = "broken-guard"
        ep.value = "nonexistent.module:SomeGuard"
        ep.load.side_effect = ImportError("no module")
        ep.dist = None
        ep._group_key = "guard"

        def fake_eps(group: str):
            return [ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            manager = PluginManager()
            n = manager.load_all(ignore_errors=True)
        assert n == 0

    def test_load_all_wrong_base_class_raises(self) -> None:
        class NotAGuard:
            pass

        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = "fake-guard"
        ep.value = "tests:NotAGuard"
        ep.load.return_value = NotAGuard
        ep.dist = None
        ep._group_key = "guard"

        def fake_eps(group: str):
            return [ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            manager = PluginManager()
            with pytest.raises(PluginLoadError, match="must be a subclass"):
                manager.load_all()

    def test_load_all_init_error_raises(self) -> None:
        class CrashGuard(GuardPlugin):
            def __init__(self) -> None:
                raise RuntimeError("boom")

            @property
            def name(self) -> str:
                return "crash"

            @property
            def version(self) -> str:
                return "1.0"

            def check(self, tn, args, kwargs):
                return GuardResult(allowed=True)

        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = "crash-guard"
        ep.value = "tests:CrashGuard"
        ep.load.return_value = CrashGuard
        ep.dist = None
        ep._group_key = "guard"

        def fake_eps(group: str):
            return [ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            manager = PluginManager()
            with pytest.raises(PluginLoadError, match="Failed to instantiate"):
                manager.load_all()


# ---------------------------------------------------------------------------
# PluginManager.load (by name) tests
# ---------------------------------------------------------------------------


class TestPluginManagerLoad:
    def test_load_by_name(self) -> None:
        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = "my-guard"
        ep.load.return_value = AllowGuard
        ep.dist = MagicMock()
        ep.dist.version = "1.0.0"

        def fake_eps(group: str):
            return [ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            manager = PluginManager()
            manager.load("my-guard")

        assert len(manager.guards) == 1

    def test_load_not_found_raises(self) -> None:
        with patch(
            "enforcecore.plugins.manager.importlib.metadata.entry_points",
            return_value=[],
        ):
            manager = PluginManager()
            with pytest.raises(PluginLoadError, match="No plugin named"):
                manager.load("nonexistent")


# ---------------------------------------------------------------------------
# PluginManager properties tests
# ---------------------------------------------------------------------------


class TestPluginManagerProperties:
    def test_guards_returns_copy(self) -> None:
        manager = PluginManager()
        copy1 = manager.guards
        copy2 = manager.guards
        assert copy1 is not copy2

    def test_redactors_returns_copy(self) -> None:
        manager = PluginManager()
        assert manager.redactors is not manager.redactors

    def test_audit_backends_returns_copy(self) -> None:
        manager = PluginManager()
        assert manager.audit_backends is not manager.audit_backends

    def test_repr_empty(self) -> None:
        manager = PluginManager()
        r = repr(manager)
        assert "PluginManager" in r
        assert "guards=0" in r
        assert "redactors=0" in r
        assert "audit_backends=0" in r


# ---------------------------------------------------------------------------
# CLI: enforcecore plugin list
# ---------------------------------------------------------------------------


class TestCLIPluginList:
    def _runner(self):
        from enforcecore.cli.main import app

        return CliRunner(), app

    def test_plugin_list_no_plugins(self) -> None:
        runner, app = self._runner()
        with patch(
            "enforcecore.plugins.manager.importlib.metadata.entry_points",
            return_value=[],
        ):
            result = runner.invoke(app, ["plugin", "list"])
        assert result.exit_code == 0
        assert "No EnforceCore plugins found" in result.output

    def test_plugin_list_with_plugins(self) -> None:
        runner, app = self._runner()
        mock_ep = MagicMock(spec=importlib.metadata.EntryPoint)
        mock_ep.name = "test-guard"
        mock_ep.value = "tests:AllowGuard"
        mock_ep.dist = MagicMock()
        mock_ep.dist.version = "1.0.0"

        def fake_eps(group: str):
            return [mock_ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            result = runner.invoke(app, ["plugin", "list"])
        assert result.exit_code == 0
        assert "test-guard" in result.output

    def test_plugin_list_kind_filter(self) -> None:
        runner, app = self._runner()
        guard_ep = MagicMock(spec=importlib.metadata.EntryPoint)
        guard_ep.name = "g1"
        guard_ep.value = "tests:AllowGuard"
        guard_ep.dist = None

        redact_ep = MagicMock(spec=importlib.metadata.EntryPoint)
        redact_ep.name = "r1"
        redact_ep.value = "tests:SimpleRedactor"
        redact_ep.dist = None

        def fake_eps(group: str):
            if group == "enforcecore.guards":
                return [guard_ep]
            if group == "enforcecore.redactors":
                return [redact_ep]
            return []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            result = runner.invoke(app, ["plugin", "list", "--kind", "redactor"])
        assert result.exit_code == 0
        assert "r1" in result.output
        # guard should be filtered out
        assert "g1" not in result.output


# ---------------------------------------------------------------------------
# CLI: enforcecore plugin info
# ---------------------------------------------------------------------------


class TestCLIPluginInfo:
    def _runner(self):
        from enforcecore.cli.main import app

        return CliRunner(), app

    def test_plugin_info_not_found(self) -> None:
        runner, app = self._runner()
        with patch(
            "enforcecore.plugins.manager.importlib.metadata.entry_points",
            return_value=[],
        ):
            result = runner.invoke(app, ["plugin", "info", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_plugin_info_found(self) -> None:
        runner, app = self._runner()
        ep = MagicMock(spec=importlib.metadata.EntryPoint)
        ep.name = "allow-guard"
        ep.value = "tests.plugins.test_plugin_ecosystem:AllowGuard"
        ep.load.return_value = AllowGuard
        ep.dist = MagicMock()
        ep.dist.version = "1.0.0"

        def fake_eps(group: str):
            return [ep] if group == "enforcecore.guards" else []

        with patch("enforcecore.plugins.manager.importlib.metadata.entry_points", fake_eps):
            result = runner.invoke(app, ["plugin", "info", "allow-guard"])
        assert result.exit_code == 0
        assert "allow-guard" in result.output


# ---------------------------------------------------------------------------
# Public API assertions (Tier 1)
# ---------------------------------------------------------------------------


class TestPublicAPIPluginEcosystem:
    def test_version_is_190(self) -> None:
        assert enforcecore.__version__ == "1.9.0"

    def test_all_count_is_58(self) -> None:
        assert len(enforcecore.__all__) == 58, (
            f"Expected 58 symbols in __all__, got {len(enforcecore.__all__)}. "
            f"Current: {sorted(enforcecore.__all__)}"
        )

    def test_audit_backend_plugin_in_all(self) -> None:
        assert "AuditBackendPlugin" in enforcecore.__all__

    def test_guard_plugin_in_all(self) -> None:
        assert "GuardPlugin" in enforcecore.__all__

    def test_plugin_load_error_in_all(self) -> None:
        assert "PluginLoadError" in enforcecore.__all__

    def test_plugin_manager_in_all(self) -> None:
        assert "PluginManager" in enforcecore.__all__

    def test_redactor_plugin_in_all(self) -> None:
        assert "RedactorPlugin" in enforcecore.__all__

    def test_top_level_imports(self) -> None:
        from enforcecore import (
            AuditBackendPlugin,
            GuardPlugin,
            PluginLoadError,
            PluginManager,
            RedactorPlugin,
        )

        assert issubclass(GuardPlugin, object)
        assert issubclass(RedactorPlugin, object)
        assert issubclass(AuditBackendPlugin, object)
        assert PluginManager is not None
        assert issubclass(PluginLoadError, Exception)

    def test_all_sorted(self) -> None:
        names = [n for n in enforcecore.__all__ if not n.startswith("_")]
        assert names == sorted(names), "Non-dunder entries in __all__ must be sorted"

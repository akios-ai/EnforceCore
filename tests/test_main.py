# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore/__main__.py.

Covers:
- main() calls CLI app successfully
- main() ImportError fallback prints version + install hint, exits 1
- main() re-raises SystemExit from CLI import guard
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


class TestMainEntryPoint:
    def test_main_calls_cli_app(self) -> None:
        """main() invokes the CLI app when enforcecore.cli.main is importable."""
        mock_app = MagicMock()

        with patch.dict(
            sys.modules,
            {"enforcecore.cli.main": MagicMock(app=mock_app)},
        ):
            import importlib

            import enforcecore.__main__ as main_mod

            importlib.reload(main_mod)
            main_mod.main()

        mock_app.assert_called_once()

    def test_main_import_error_prints_version_and_exits(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """main() prints version + install hint and exits 1 if CLI not installed."""
        # Block the CLI import by setting its module entry to None
        saved = sys.modules.get("enforcecore.cli.main", ...)
        sys.modules["enforcecore.cli.main"] = None  # type: ignore[assignment]
        try:
            import importlib

            import enforcecore.__main__ as main_mod

            importlib.reload(main_mod)
            with pytest.raises(SystemExit) as exc_info:
                main_mod.main()
            assert exc_info.value.code == 1
            captured = capsys.readouterr()
            assert "pip install enforcecore[cli]" in captured.out
        finally:
            if saved is ...:
                sys.modules.pop("enforcecore.cli.main", None)
            else:
                sys.modules["enforcecore.cli.main"] = saved  # type: ignore[assignment]
            # Restore the real module
            import importlib

            import enforcecore.__main__ as main_mod

            importlib.reload(main_mod)

    def test_main_system_exit_reraise(self) -> None:
        """main() re-raises SystemExit from the CLI (clean exit)."""
        mock_app = MagicMock(side_effect=SystemExit(0))

        saved = sys.modules.get("enforcecore.cli.main", ...)
        try:
            sys.modules["enforcecore.cli.main"] = MagicMock(app=mock_app)
            import importlib

            import enforcecore.__main__ as main_mod

            importlib.reload(main_mod)
            with pytest.raises(SystemExit) as exc_info:
                main_mod.main()
            assert exc_info.value.code == 0
        finally:
            if saved is ...:
                sys.modules.pop("enforcecore.cli.main", None)
            else:
                sys.modules["enforcecore.cli.main"] = saved  # type: ignore[assignment]
            import importlib

            import enforcecore.__main__ as main_mod

            importlib.reload(main_mod)


class TestMainModuleIfNameMain:
    def test_module_can_be_imported(self) -> None:
        """enforcecore.__main__ can be imported without side effects."""
        import enforcecore.__main__

        assert hasattr(enforcecore.__main__, "main")
        assert callable(enforcecore.__main__.main)

    def test_main_function_exists(self) -> None:
        from enforcecore.__main__ import main

        assert callable(main)

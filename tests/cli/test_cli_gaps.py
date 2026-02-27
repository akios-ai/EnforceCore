# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Coverage gap tests for enforcecore/cli/main.py.

Targets:
- compliance webhook path: --webhook-url without --webhook-token → Exit(1)
- compliance webhook path: ComplianceError from send_webhook → Exit(1)
- plugin info with redactor → categories_str displayed
- plugin info with PluginLoadError → error panel
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from enforcecore.cli.main import app
from enforcecore.plugins.base import PluginInfo

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_reporter(
    *,
    send_webhook_raises: Exception | None = None,
    export_raises: Exception | None = None,
) -> MagicMock:
    """Return a mock ComplianceReporter with configurable side-effects."""
    from enforcecore.compliance.types import ComplianceError  # noqa: F401 — needed for isinstance

    mock_report = MagicMock()
    mock_report.to_json.return_value = '{"compliance_score": 1.0}'

    instance = MagicMock()
    if export_raises is not None:
        instance.export.side_effect = export_raises
    else:
        instance.export.return_value = mock_report

    if send_webhook_raises is not None:
        instance.send_webhook.side_effect = send_webhook_raises
    else:
        instance.send_webhook.return_value = None

    return instance


# ---------------------------------------------------------------------------
# audit export — webhook error paths
# ---------------------------------------------------------------------------


class TestAuditExportWebhookErrors:
    """audit export: webhook validation and ComplianceError handling."""

    def test_webhook_url_without_token_exits_1(self) -> None:
        """--webhook-url without --webhook-token prints error and exits 1."""
        mock_instance = _make_mock_reporter()
        mock_class = MagicMock(return_value=mock_instance)

        with patch("enforcecore.compliance.reporter.ComplianceReporter", mock_class):
            result = runner.invoke(
                app,
                [
                    "audit",
                    "export",
                    "--format",
                    "soc2",
                    "--period",
                    "2026",
                    "--webhook-url",
                    "http://vanta.example/api/upload",
                ],
            )

        assert result.exit_code == 1
        assert "webhook-token" in (result.output or "").lower()

    def test_compliance_error_from_send_webhook_exits_1(self) -> None:
        """ComplianceError from send_webhook prints 'Webhook failed' and exits 1."""
        from enforcecore.compliance.types import ComplianceError

        mock_instance = _make_mock_reporter(send_webhook_raises=ComplianceError("upstream timeout"))
        mock_class = MagicMock(return_value=mock_instance)

        with patch("enforcecore.compliance.reporter.ComplianceReporter", mock_class):
            result = runner.invoke(
                app,
                [
                    "audit",
                    "export",
                    "--format",
                    "soc2",
                    "--period",
                    "2026",
                    "--webhook-url",
                    "http://vanta.example/api/upload",
                    "--webhook-token",
                    "BEARER_TOKEN",
                ],
            )

        assert result.exit_code == 1
        # Output or stderr should mention the webhook failure
        combined = (result.output or "") + (result.stdout or "")
        assert "webhook" in combined.lower() or "failed" in combined.lower()

    def test_compliance_error_from_export_exits_1(self) -> None:
        """ComplianceError from reporter.export itself exits 1."""
        from enforcecore.compliance.types import ComplianceError

        mock_instance = _make_mock_reporter(export_raises=ComplianceError("audit trail unreadable"))
        mock_class = MagicMock(return_value=mock_instance)

        with patch("enforcecore.compliance.reporter.ComplianceReporter", mock_class):
            result = runner.invoke(
                app,
                [
                    "audit",
                    "export",
                    "--format",
                    "soc2",
                    "--period",
                    "2026",
                ],
            )

        assert result.exit_code == 1

    def test_audit_export_success_prints_json(self) -> None:
        """Successful audit export (no output file) prints JSON to stdout."""
        mock_instance = _make_mock_reporter()
        mock_class = MagicMock(return_value=mock_instance)

        with patch("enforcecore.compliance.reporter.ComplianceReporter", mock_class):
            result = runner.invoke(
                app,
                [
                    "audit",
                    "export",
                    "--format",
                    "soc2",
                    "--period",
                    "2026",
                ],
            )

        assert result.exit_code == 0

    def test_webhook_with_valid_token_calls_send_webhook(self) -> None:
        """With both --webhook-url and --webhook-token, send_webhook is called."""
        mock_instance = _make_mock_reporter()
        mock_class = MagicMock(return_value=mock_instance)

        with patch("enforcecore.compliance.reporter.ComplianceReporter", mock_class):
            result = runner.invoke(
                app,
                [
                    "audit",
                    "export",
                    "--format",
                    "soc2",
                    "--period",
                    "2026",
                    "--webhook-url",
                    "http://vanta.example/api/upload",
                    "--webhook-token",
                    "TOKEN",
                ],
            )

        assert result.exit_code == 0
        mock_instance.send_webhook.assert_called_once()


# ---------------------------------------------------------------------------
# plugin info — redactor with categories, and PluginLoadError
# ---------------------------------------------------------------------------


class TestPluginInfoCommand:
    """plugin info: categories_str and PluginLoadError panel."""

    def _invoke_plugin_info(
        self,
        plugin_name: str,
        *,
        kind: str = "guard",
        categories: list[str] | None = None,
        load_raises: Exception | None = None,
    ) -> CliRunner:
        """Invoke 'plugin info <name>' with mocked PluginManager."""
        info = PluginInfo(
            name=plugin_name,
            kind=kind,
            version="1.0.0",
            package=f"fake_pkg:{plugin_name.replace('-', '_').title()}",
        )

        mock_manager = MagicMock()
        mock_manager.discover.return_value = [info]

        if load_raises is not None:
            mock_manager.load.side_effect = load_raises
        else:
            mock_manager.load.return_value = None

        if kind == "guard":
            guard_inst = MagicMock()
            mock_manager.guards = [guard_inst]
            mock_manager.redactors = []
            mock_manager.audit_backends = []
        elif kind == "redactor":
            redactor_inst = MagicMock()
            redactor_inst.categories = categories or []
            mock_manager.guards = []
            mock_manager.redactors = [redactor_inst]
            mock_manager.audit_backends = []
        else:
            backend_inst = MagicMock()
            mock_manager.guards = []
            mock_manager.redactors = []
            mock_manager.audit_backends = [backend_inst]

        with patch("enforcecore.plugins.manager.PluginManager", return_value=mock_manager):
            return runner.invoke(app, ["plugin", "info", plugin_name])

    def test_plugin_not_found_exits_1(self) -> None:
        """Unknown plugin name exits 1 with 'not found' message."""
        mock_manager = MagicMock()
        mock_manager.discover.return_value = []  # nothing discovered

        with patch("enforcecore.plugins.manager.PluginManager", return_value=mock_manager):
            result = runner.invoke(app, ["plugin", "info", "nonexistent-plugin"])

        assert result.exit_code == 1
        assert "not found" in (result.output or "").lower()

    def test_guard_plugin_shows_panel(self) -> None:
        """Guard plugin info shows panel with name and version."""
        result = self._invoke_plugin_info("my-guard", kind="guard")
        assert result.exit_code == 0
        assert "my-guard" in (result.output or "")

    def test_redactor_plugin_shows_categories(self) -> None:
        """Redactor plugin with categories shows them in the info panel."""
        result = self._invoke_plugin_info(
            "email-redactor",
            kind="redactor",
            categories=["email", "phone", "ssn"],
        )
        assert result.exit_code == 0
        output = result.output or ""
        assert "email-redactor" in output
        # categories_str is displayed in the panel when categories exist
        assert "email" in output

    def test_redactor_plugin_no_categories(self) -> None:
        """Redactor plugin with empty categories still renders the panel."""
        result = self._invoke_plugin_info(
            "plain-redactor",
            kind="redactor",
            categories=[],
        )
        assert result.exit_code == 0
        assert "plain-redactor" in (result.output or "")

    def test_audit_backend_plugin_shows_panel(self) -> None:
        """Audit backend plugin info shows panel."""
        result = self._invoke_plugin_info("my-backend", kind="audit_backend")
        assert result.exit_code == 0
        assert "my-backend" in (result.output or "")

    def test_plugin_load_error_shown_in_panel(self) -> None:
        """PluginLoadError during load is reflected in the panel (not a crash)."""
        from enforcecore.plugins.manager import PluginLoadError

        result = self._invoke_plugin_info(
            "broken-guard",
            kind="guard",
            load_raises=PluginLoadError("missing dependency: fancy_ml"),
        )
        # Command completes without crashing — exits 0 with error text in panel
        output = result.output or ""
        assert "broken-guard" in output
        # The load error message must appear somewhere in the panel
        assert "load error" in output.lower() or "missing dependency" in output.lower()

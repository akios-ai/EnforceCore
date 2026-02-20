"""Tests for enforcecore.core.config — Settings and configuration."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

from enforcecore.core.config import Settings


class TestSettings:
    def test_defaults(self) -> None:
        s = Settings()
        assert s.default_policy is None
        assert s.audit_enabled is True
        assert s.audit_path == Path("./audit_logs")
        assert s.redaction_enabled is True
        assert s.log_level == "INFO"
        assert s.fail_open is False
        assert s.cost_budget_usd is None

    def test_fail_open_default_is_false(self) -> None:
        """Fail-closed is the secure default."""
        s = Settings()
        assert s.fail_open is False

    def test_env_override(self) -> None:
        env = {
            "ENFORCECORE_LOG_LEVEL": "DEBUG",
            "ENFORCECORE_FAIL_OPEN": "true",
            "ENFORCECORE_AUDIT_ENABLED": "false",
            "ENFORCECORE_COST_BUDGET_USD": "50.0",
        }
        with patch.dict(os.environ, env, clear=False):
            s = Settings()
            assert s.log_level == "DEBUG"
            assert s.fail_open is True
            assert s.audit_enabled is False
            assert s.cost_budget_usd == 50.0

    def test_env_prefix(self) -> None:
        """All config is prefixed with ENFORCECORE_."""
        assert Settings.model_config["env_prefix"] == "ENFORCECORE_"

    def test_settings_singleton_exists(self) -> None:
        from enforcecore.core.config import settings

        assert isinstance(settings, Settings)

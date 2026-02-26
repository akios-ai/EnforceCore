# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for SandboxConfig and SandboxStrategy."""

import pytest

from enforcecore.sandbox.config import (
    _DEFAULT_ALLOWED_ENV_VARS,
    SandboxConfig,
    SandboxStrategy,
)


class TestSandboxStrategy:
    def test_values(self) -> None:
        assert SandboxStrategy.NONE.value == "none"
        assert SandboxStrategy.SUBPROCESS.value == "subprocess"

    def test_from_string(self) -> None:
        assert SandboxStrategy("none") == SandboxStrategy.NONE
        assert SandboxStrategy("subprocess") == SandboxStrategy.SUBPROCESS

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            SandboxStrategy("wasm")


class TestSandboxConfig:
    def test_default_is_disabled(self) -> None:
        config = SandboxConfig()
        assert config.strategy == SandboxStrategy.NONE
        assert not config.enabled
        assert config.max_memory_mb is None
        assert config.max_cpu_seconds is None

    def test_disabled_factory(self) -> None:
        config = SandboxConfig.disabled()
        assert config.strategy == SandboxStrategy.NONE
        assert not config.enabled

    def test_subprocess_default_factory(self) -> None:
        config = SandboxConfig.subprocess_default()
        assert config.strategy == SandboxStrategy.SUBPROCESS
        assert config.enabled
        assert config.max_memory_mb == 512
        assert config.max_cpu_seconds == 60.0

    def test_subprocess_enabled(self) -> None:
        config = SandboxConfig(strategy=SandboxStrategy.SUBPROCESS)
        assert config.enabled

    def test_default_allowed_env_vars(self) -> None:
        config = SandboxConfig()
        assert "PATH" in config.allowed_env_vars
        assert "PYTHONPATH" in config.allowed_env_vars

    def test_custom_allowed_env_vars(self) -> None:
        config = SandboxConfig(allowed_env_vars=["PATH", "MY_VAR"])
        assert config.allowed_env_vars == ["PATH", "MY_VAR"]

    def test_working_directory_default_none(self) -> None:
        config = SandboxConfig()
        assert config.working_directory is None

    def test_full_config(self) -> None:
        config = SandboxConfig(
            strategy=SandboxStrategy.SUBPROCESS,
            max_memory_mb=256,
            max_cpu_seconds=10.0,
            allowed_env_vars=["PATH"],
            working_directory="/tmp",
        )
        assert config.strategy == SandboxStrategy.SUBPROCESS
        assert config.max_memory_mb == 256
        assert config.max_cpu_seconds == 10.0
        assert config.allowed_env_vars == ["PATH"]
        assert config.working_directory == "/tmp"
        assert config.enabled

    def test_default_allowed_env_vars_content(self) -> None:
        # Validate the module-level constant is reasonable
        assert len(_DEFAULT_ALLOWED_ENV_VARS) >= 2
        assert "PATH" in _DEFAULT_ALLOWED_ENV_VARS

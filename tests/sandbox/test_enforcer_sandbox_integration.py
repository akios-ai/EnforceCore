# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Integration tests: Enforcer + subprocess sandbox via policy.

Tests that the sandbox integrates correctly with the full enforcement
pipeline when enabled via policy YAML.
"""

import pytest

from enforcecore import Enforcer, Policy


# Module-level functions (picklable — required for subprocess sandbox)
def _square(x: int) -> int:
    return x * x


async def _async_echo_msg(msg: str) -> str:
    return f"echo:{msg}"


def _forbidden_func() -> str:
    return "should not run"


def _make_sandbox_policy(
    *,
    enabled: bool = True,
    strategy: str = "subprocess",
    max_cpu_seconds: float = 10.0,
) -> Policy:
    """Build an in-memory policy with sandbox config."""
    data = {
        "name": "sandbox-test",
        "version": "1.0",
        "rules": {
            "allowed_tools": ["compute", "echo", "async_echo"],
            "sandbox": {
                "enabled": enabled,
                "strategy": strategy,
                "max_cpu_seconds": max_cpu_seconds,
            },
        },
    }
    return Policy.from_dict(data)


# ---------------------------------------------------------------------------
# SandboxPolicyConfig unit tests
# ---------------------------------------------------------------------------


class TestSandboxPolicyConfig:
    def test_default_disabled(self) -> None:
        policy = Policy.from_dict({"name": "p", "rules": {}})
        cfg = policy.rules.sandbox
        assert not cfg.enabled
        assert cfg.strategy == "subprocess"  # default strategy string

    def test_enabled_via_dict(self) -> None:
        policy = _make_sandbox_policy(enabled=True)
        cfg = policy.rules.sandbox
        assert cfg.enabled
        assert cfg.strategy == "subprocess"

    def test_to_sandbox_config_disabled(self) -> None:
        policy = Policy.from_dict({"name": "p", "rules": {}})
        sandbox_config = policy.rules.sandbox.to_sandbox_config()
        assert not sandbox_config.enabled

    def test_to_sandbox_config_subprocess(self) -> None:
        from enforcecore.sandbox.config import SandboxStrategy

        policy = _make_sandbox_policy(max_cpu_seconds=15.0)
        sandbox_config = policy.rules.sandbox.to_sandbox_config()
        assert sandbox_config.enabled
        assert sandbox_config.strategy == SandboxStrategy.SUBPROCESS
        assert sandbox_config.max_cpu_seconds == 15.0

    def test_to_sandbox_config_unknown_strategy_defaults_subprocess(self) -> None:
        from enforcecore.sandbox.config import SandboxStrategy

        policy = Policy.from_dict(
            {
                "name": "p",
                "rules": {
                    "sandbox": {
                        "enabled": True,
                        "strategy": "invalid_strategy",
                    }
                },
            }
        )
        sandbox_config = policy.rules.sandbox.to_sandbox_config()
        # Unknown strategy falls back to subprocess
        assert sandbox_config.strategy == SandboxStrategy.SUBPROCESS

    def test_allowed_env_vars_policy(self) -> None:
        policy = Policy.from_dict(
            {
                "name": "p",
                "rules": {
                    "sandbox": {
                        "enabled": True,
                        "strategy": "subprocess",
                        "allowed_env_vars": ["PATH", "MY_VAR"],
                    }
                },
            }
        )
        sandbox_config = policy.rules.sandbox.to_sandbox_config()
        assert sandbox_config.allowed_env_vars == ["PATH", "MY_VAR"]


# ---------------------------------------------------------------------------
# Enforcer sandbox routing
# ---------------------------------------------------------------------------


class TestEnforcerSandboxRouting:
    def test_sandbox_disabled_uses_normal_path(self) -> None:
        """When sandbox is disabled, _sandbox slot is None."""
        policy = Policy.from_dict(
            {
                "name": "no-sandbox",
                "rules": {"allowed_tools": ["compute"]},
            }
        )
        enforcer = Enforcer(policy)
        assert enforcer._sandbox is None

    def test_sandbox_enabled_creates_sandbox(self) -> None:
        """When sandbox is enabled, _sandbox is a SubprocessSandbox instance."""
        from enforcecore.sandbox.runner import SubprocessSandbox

        policy = _make_sandbox_policy(enabled=True)
        enforcer = Enforcer(policy)
        assert isinstance(enforcer._sandbox, SubprocessSandbox)

    def test_enforce_sync_with_sandbox(self) -> None:
        """@enforce with sandbox policy runs tool in subprocess."""
        policy = _make_sandbox_policy()
        enforcer = Enforcer(policy)

        result = enforcer.enforce_sync(_square, 7, tool_name="compute")
        assert result == 49

    def test_enforce_async_with_sandbox(self) -> None:
        """enforce_async with sandbox policy runs async tool in subprocess."""
        import asyncio

        policy = _make_sandbox_policy()
        enforcer = Enforcer(policy)

        result = asyncio.run(
            enforcer.enforce_async(_async_echo_msg, "test", tool_name="async_echo")
        )
        assert result == "echo:test"

    def test_enforce_blocked_tool_never_reaches_sandbox(self) -> None:
        """Policy violations are raised before sandbox execution."""
        from enforcecore.core.types import ToolDeniedError

        policy = Policy.from_dict(
            {
                "name": "deny-test",
                "rules": {
                    "denied_tools": ["forbidden"],
                    "sandbox": {"enabled": True, "strategy": "subprocess"},
                },
            }
        )
        enforcer = Enforcer(policy)

        with pytest.raises(ToolDeniedError):
            enforcer.enforce_sync(_forbidden_func, tool_name="forbidden")


# ---------------------------------------------------------------------------
# Policy merge with sandbox
# ---------------------------------------------------------------------------


class TestPolicySandboxMerge:
    def test_sandbox_override_wins(self) -> None:
        """When override has sandbox.enabled, it wins over base."""
        base = Policy.from_dict({"name": "base", "rules": {}})
        override = Policy.from_dict(
            {
                "name": "override",
                "rules": {
                    "sandbox": {
                        "enabled": True,
                        "strategy": "subprocess",
                        "max_cpu_seconds": 20.0,
                    }
                },
            }
        )
        merged = Policy.merge(base, override)
        assert merged.rules.sandbox.enabled
        assert merged.rules.sandbox.max_cpu_seconds == 20.0

    def test_sandbox_two_enabled_policies_override_wins(self) -> None:
        """When both base and override enable sandbox, override config wins."""
        base = Policy.from_dict(
            {
                "name": "base",
                "rules": {
                    "sandbox": {
                        "enabled": True,
                        "strategy": "subprocess",
                        "max_cpu_seconds": 30.0,
                    }
                },
            }
        )
        override = Policy.from_dict(
            {
                "name": "override",
                "rules": {
                    "sandbox": {
                        "enabled": True,
                        "strategy": "subprocess",
                        "max_cpu_seconds": 5.0,
                    }
                },
            }
        )
        merged = Policy.merge(base, override)
        # Override's cpu seconds wins
        assert merged.rules.sandbox.enabled
        assert merged.rules.sandbox.max_cpu_seconds == 5.0

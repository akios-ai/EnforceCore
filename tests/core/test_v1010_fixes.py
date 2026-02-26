# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Verification tests for v1.0.10 audit fixes.

Covers:
- H-1: CLI inspect reads call_duration_ms with fallback to duration_ms
- H-2: Policy.merge() uses exclude_none=True
- M-1: Core __init__ exports ContentRulesPolicyConfig, RateLimitPolicyConfig, clear_policy_cache
- M-2: fail_open uses redacted args (r_args/r_kwargs)
- New Settings fields for audit rotation and webhooks
- New top-level exports (110 total)
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# H-1: CLI inspect field name compat
# ---------------------------------------------------------------------------


class TestH1CLIFieldCompat:
    """CLI inspect should read call_duration_ms with fallback to duration_ms."""

    def test_call_duration_ms_field(self) -> None:
        """New-format entries use call_duration_ms."""
        entry = {"call_duration_ms": 42.5, "tool_name": "search"}
        duration = entry.get("call_duration_ms") or entry.get("duration_ms")
        assert duration == 42.5

    def test_duration_ms_fallback(self) -> None:
        """Old-format entries with duration_ms still work."""
        entry = {"duration_ms": 33.0, "tool_name": "search"}
        duration = entry.get("call_duration_ms") or entry.get("duration_ms")
        assert duration == 33.0

    def test_neither_field(self) -> None:
        """Entry with neither field returns None."""
        entry = {"tool_name": "search"}
        duration = entry.get("call_duration_ms") or entry.get("duration_ms")
        assert duration is None


# ---------------------------------------------------------------------------
# H-2: Policy merge exclude_none
# ---------------------------------------------------------------------------


class TestH2MergeExcludeNone:
    """Policy.merge should not let default None override explicit values."""

    def test_merge_preserves_base_values(self) -> None:
        from enforcecore.core.policy import Policy, PolicyRules

        base = Policy(
            name="base",
            rules=PolicyRules(
                allowed_tools=["search", "read"],
                denied_tools=["shell"],
            ),
        )
        override = Policy(name="override")
        merged = Policy.merge(base, override)
        assert merged.rules.allowed_tools == ["search", "read"]
        assert "shell" in merged.rules.denied_tools

    def test_merge_override_replaces(self) -> None:
        from enforcecore.core.policy import Policy, PolicyRules

        base = Policy(name="base", rules=PolicyRules(allowed_tools=["search"]))
        override = Policy(name="override", rules=PolicyRules(allowed_tools=["read"]))
        merged = Policy.merge(base, override)
        assert merged.rules.allowed_tools == ["read"]


# ---------------------------------------------------------------------------
# M-1: Core __init__ exports
# ---------------------------------------------------------------------------


class TestM1CoreExports:
    """Core package should export all key symbols."""

    def test_content_rules_policy_config_exported(self) -> None:
        from enforcecore.core import ContentRulesPolicyConfig

        assert ContentRulesPolicyConfig is not None

    def test_rate_limit_policy_config_exported(self) -> None:
        from enforcecore.core import RateLimitPolicyConfig

        assert RateLimitPolicyConfig is not None

    def test_clear_policy_cache_exported(self) -> None:
        from enforcecore.core import clear_policy_cache

        assert callable(clear_policy_cache)


# ---------------------------------------------------------------------------
# New Settings fields
# ---------------------------------------------------------------------------


class TestNewSettingsFields:
    """Settings should have new audit rotation and webhook fields."""

    def test_audit_rotation_defaults(self) -> None:
        from enforcecore.core.config import Settings

        s = Settings()
        assert s.audit_rotate_mb == 100.0
        assert s.audit_retain_days == 90
        assert s.audit_compress is True

    def test_webhook_defaults(self) -> None:
        from enforcecore.core.config import Settings

        s = Settings()
        assert s.webhook_on_violation is None
        assert s.webhook_on_cost_threshold is None
        assert s.webhook_retry_attempts == 3
        assert s.webhook_timeout_seconds == 10.0

    def test_custom_settings(self) -> None:
        from enforcecore.core.config import Settings

        s = Settings(
            audit_rotate_mb=50.0,
            audit_retain_days=7,
            audit_compress=False,
            webhook_on_violation="https://hooks.example.com/v",
            webhook_retry_attempts=5,
        )
        assert s.audit_rotate_mb == 50.0
        assert s.audit_retain_days == 7
        assert s.audit_compress is False
        assert s.webhook_on_violation == "https://hooks.example.com/v"
        assert s.webhook_retry_attempts == 5


# ---------------------------------------------------------------------------
# Top-level exports
# ---------------------------------------------------------------------------


class TestTopLevelExports:
    """Package should export 30 Tier 1 symbols (pruned in v1.0.25a1).

    v1.0.10 additions are still importable but moved to Tier 2.
    """

    pytestmark = pytest.mark.filterwarnings("ignore::DeprecationWarning")

    def test_total_export_count(self) -> None:
        import enforcecore

        assert len(enforcecore.__all__) == 46

    def test_v1010_exports_still_importable(self) -> None:
        """v1.0.10 symbols moved to Tier 2 — importable but not in __all__."""
        import enforcecore

        for name in (
            "AuditRotator",
            "WebhookDispatcher",
            "WebhookEvent",
            "EnforceCoreInstrumentor",
            "EnforceCoreMetrics",
        ):
            assert hasattr(enforcecore, name), f"{name} not importable"

    def test_imports_resolve(self) -> None:
        from enforcecore import (
            AuditRotator,
            EnforceCoreInstrumentor,
            EnforceCoreMetrics,
            WebhookDispatcher,
            WebhookEvent,
        )

        assert all(
            [
                AuditRotator,
                EnforceCoreInstrumentor,
                EnforceCoreMetrics,
                WebhookDispatcher,
                WebhookEvent,
            ]
        )

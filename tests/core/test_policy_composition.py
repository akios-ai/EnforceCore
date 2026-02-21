"""Tests for policy composition, merge, extends, and dry-run.

Covers:
- Policy.merge() — scalar override, list union, deep merge
- extends directive in YAML — single-level inheritance
- Policy.dry_run() — preview decisions without executing
- _deep_merge helper
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore.core.policy import (
    ContentRulesPolicyConfig,
    NetworkPolicy,
    PIIRedactionConfig,
    Policy,
    PolicyLoadError,
    PolicyRules,
    RateLimitPolicyConfig,
    _deep_merge,
)

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# _deep_merge
# ---------------------------------------------------------------------------


class TestDeepMerge:
    def test_simple_override(self) -> None:
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self) -> None:
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        override = {"a": {"y": 99, "z": 100}}
        result = _deep_merge(base, override)
        assert result == {"a": {"x": 1, "y": 99, "z": 100}, "b": 3}

    def test_none_values_ignored(self) -> None:
        base = {"a": 1, "b": 2}
        override = {"a": None, "b": 3}
        result = _deep_merge(base, override)
        assert result == {"a": 1, "b": 3}

    def test_empty_override(self) -> None:
        base = {"a": 1}
        result = _deep_merge(base, {})
        assert result == {"a": 1}

    def test_empty_base(self) -> None:
        result = _deep_merge({}, {"a": 1})
        assert result == {"a": 1}

    def test_deeply_nested(self) -> None:
        base = {"a": {"b": {"c": {"d": 1}}}}
        override = {"a": {"b": {"c": {"e": 2}}}}
        result = _deep_merge(base, override)
        assert result == {"a": {"b": {"c": {"d": 1, "e": 2}}}}


# ---------------------------------------------------------------------------
# Policy.merge()
# ---------------------------------------------------------------------------


class TestPolicyMerge:
    def test_name_override(self) -> None:
        base = Policy(name="base", version="1.0")
        override = Policy(name="override", version="2.0")
        merged = Policy.merge(base, override)
        assert merged.name == "override"
        assert merged.version == "2.0"

    def test_denied_tools_union(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(denied_tools=["shell", "rm"]),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(denied_tools=["rm", "hack"]),
        )
        merged = Policy.merge(base, override)
        assert set(merged.rules.denied_tools) == {"shell", "rm", "hack"}

    def test_allowed_tools_override_wins(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(allowed_tools=["a", "b"]),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(allowed_tools=["c"]),
        )
        merged = Policy.merge(base, override)
        assert merged.rules.allowed_tools == ["c"]

    def test_pii_override(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(
                pii_redaction=PIIRedactionConfig(enabled=False),
            ),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(
                pii_redaction=PIIRedactionConfig(enabled=True, categories=["email"]),
            ),
        )
        merged = Policy.merge(base, override)
        assert merged.rules.pii_redaction.enabled is True
        assert merged.rules.pii_redaction.categories == ["email"]

    def test_network_denied_domains_union(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(
                network=NetworkPolicy(denied_domains=["evil.com"]),
            ),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(
                network=NetworkPolicy(denied_domains=["bad.org"]),
            ),
        )
        merged = Policy.merge(base, override)
        assert set(merged.rules.network.denied_domains) == {"evil.com", "bad.org"}

    def test_content_rules_patterns_union(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(
                    block_patterns=[{"name": "rule_a", "pattern": "a"}],
                ),
            ),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(
                    block_patterns=[{"name": "rule_b", "pattern": "b"}],
                ),
            ),
        )
        merged = Policy.merge(base, override)
        names = [p["name"] for p in merged.rules.content_rules.block_patterns]
        assert "rule_a" in names
        assert "rule_b" in names

    def test_content_rules_override_wins_on_same_name(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(
                    block_patterns=[{"name": "shared", "pattern": "old"}],
                ),
            ),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(
                    block_patterns=[{"name": "shared", "pattern": "new"}],
                ),
            ),
        )
        merged = Policy.merge(base, override)
        assert len(merged.rules.content_rules.block_patterns) == 1
        assert merged.rules.content_rules.block_patterns[0]["pattern"] == "new"

    def test_rate_limits_per_tool_merge(self) -> None:
        base = Policy(
            name="base",
            rules=PolicyRules(
                rate_limits=RateLimitPolicyConfig(
                    per_tool={"search": {"max_calls": 10, "window_seconds": 60}},
                ),
            ),
        )
        override = Policy(
            name="override",
            rules=PolicyRules(
                rate_limits=RateLimitPolicyConfig(
                    per_tool={"calc": {"max_calls": 5, "window_seconds": 30}},
                ),
            ),
        )
        merged = Policy.merge(base, override)
        assert "search" in merged.rules.rate_limits.per_tool
        assert "calc" in merged.rules.rate_limits.per_tool

    def test_on_violation_override(self) -> None:
        from enforcecore.core.types import ViolationAction

        base = Policy(name="base", on_violation=ViolationAction.LOG)
        override = Policy(name="override", on_violation=ViolationAction.BLOCK)
        merged = Policy.merge(base, override)
        assert merged.on_violation == ViolationAction.BLOCK


# ---------------------------------------------------------------------------
# extends directive
# ---------------------------------------------------------------------------


class TestExtendsDirective:
    def test_extends_loads_base(self, tmp_path: Path) -> None:
        base = tmp_path / "base.yaml"
        base.write_text("name: base\nversion: '1.0'\nrules:\n  denied_tools: [shell]\n")
        child = tmp_path / "child.yaml"
        child.write_text("extends: base.yaml\nname: child\nrules:\n  denied_tools: [hack]\n")
        policy = Policy.from_file(child)
        assert policy.name == "child"
        assert set(policy.rules.denied_tools) == {"shell", "hack"}

    def test_extends_nested(self, tmp_path: Path) -> None:
        grandparent = tmp_path / "gp.yaml"
        grandparent.write_text("name: gp\nrules:\n  denied_tools: [a]\n")
        parent = tmp_path / "parent.yaml"
        parent.write_text("extends: gp.yaml\nname: parent\nrules:\n  denied_tools: [b]\n")
        child = tmp_path / "child.yaml"
        child.write_text("extends: parent.yaml\nname: child\nrules:\n  denied_tools: [c]\n")

        policy = Policy.from_file(child)
        assert policy.name == "child"
        assert set(policy.rules.denied_tools) == {"a", "b", "c"}

    def test_extends_missing_base(self, tmp_path: Path) -> None:
        child = tmp_path / "child.yaml"
        child.write_text("extends: nonexistent.yaml\nname: child\n")
        with pytest.raises(PolicyLoadError):
            Policy.from_file(child)

    def test_extends_preserves_base_settings(self, tmp_path: Path) -> None:
        base = tmp_path / "base.yaml"
        base.write_text(
            "name: base\n"
            "rules:\n"
            "  denied_tools: [shell]\n"
            "  pii_redaction:\n"
            "    enabled: true\n"
            "    categories: [email, phone]\n"
        )
        child = tmp_path / "child.yaml"
        child.write_text(
            "extends: base.yaml\n"
            "name: child\n"
            "rules:\n"
            "  denied_tools: [x]\n"
            "  pii_redaction:\n"
            "    enabled: true\n"
        )
        policy = Policy.from_file(child)
        assert policy.rules.pii_redaction.enabled is True
        # denied_tools from both should be merged
        assert set(policy.rules.denied_tools) == {"shell", "x"}

    def test_no_extends_works_normally(self, tmp_path: Path) -> None:
        f = tmp_path / "plain.yaml"
        f.write_text("name: plain\nversion: '1.0'\n")
        policy = Policy.from_file(f)
        assert policy.name == "plain"


# ---------------------------------------------------------------------------
# Policy.dry_run()
# ---------------------------------------------------------------------------


class TestPolicyDryRun:
    def test_allowed_tool(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(allowed_tools=["search_web"]),
        )
        result = policy.dry_run("search_web")
        assert result["decision"] == "allowed"
        assert result["tool"] == "search_web"
        assert result["policy"] == "test"

    def test_denied_tool(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(denied_tools=["shell"]),
        )
        result = policy.dry_run("shell")
        assert result["decision"] == "blocked"

    def test_not_in_allowed_list(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(allowed_tools=["a"]),
        )
        result = policy.dry_run("b")
        assert result["decision"] == "blocked"

    def test_content_rules_in_dry_run(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=True),
            ),
        )
        result = policy.dry_run("tool", command="rm -rf /")
        assert "content_violations" in result
        assert len(result["content_violations"]) > 0

    def test_pii_info_in_dry_run(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                pii_redaction=PIIRedactionConfig(enabled=True, categories=["email"]),
            ),
        )
        result = policy.dry_run("tool")
        assert "pii_redaction" in result
        assert result["pii_redaction"]["categories"] == ["email"]

    def test_rate_limit_info_in_dry_run(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                rate_limits=RateLimitPolicyConfig(
                    enabled=True,
                    per_tool={"search": {"max_calls": 10, "window_seconds": 60}},
                ),
            ),
        )
        result = policy.dry_run("search")
        assert "rate_limit" in result

    def test_network_info_in_dry_run(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                network=NetworkPolicy(
                    enabled=True,
                    allowed_domains=["api.example.com"],
                ),
            ),
        )
        result = policy.dry_run("tool")
        assert "network_policy" in result

    def test_dry_run_no_side_effects(self) -> None:
        """Dry run should not modify the policy or raise exceptions."""
        policy = Policy(
            name="test",
            rules=PolicyRules(denied_tools=["x"]),
        )
        result = policy.dry_run("x")
        assert result["decision"] == "blocked"
        # Policy unchanged
        assert policy.name == "test"


# ---------------------------------------------------------------------------
# Policy.extends field
# ---------------------------------------------------------------------------


class TestExtendsField:
    def test_extends_field_default_none(self) -> None:
        policy = Policy(name="test")
        assert policy.extends is None

    def test_extends_field_set(self) -> None:
        policy = Policy(name="test", extends="base.yaml")
        assert policy.extends == "base.yaml"

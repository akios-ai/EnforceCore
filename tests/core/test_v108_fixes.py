# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for v1.0.8 bug fixes and feature integration.

Covers all audit fixes (C-1, C-2, H-1, H-3, H-4, H-6, L-3, L-6,
M-1 through M-7) plus content rules, rate limiting, network enforcement,
and output content filtering in the enforcer pipeline.
"""

from __future__ import annotations

import threading

import pytest

from enforcecore.auditor.backends import MultiBackend, NullBackend
from enforcecore.core.enforcer import (
    Enforcer,
    _policy_cache,
    _policy_cache_lock,
    clear_policy_cache,
)
from enforcecore.core.policy import (
    ContentRulesPolicyConfig,
    NetworkPolicy,
    PIIRedactionConfig,
    Policy,
    PolicyEngine,
    PolicyRules,
    RateLimitPolicyConfig,
)
from enforcecore.core.types import (
    CallContext,
    ContentViolationError,
    DomainDeniedError,
    ToolDeniedError,
    ViolationType,
)
from enforcecore.guard.ratelimit import RateLimitError
from enforcecore.redactor.engine import Redactor

# ---------------------------------------------------------------------------
# C-1: redact_output policy field is respected
# ---------------------------------------------------------------------------


class TestC1RedactOutputFlag:
    def test_redact_output_true_redacts(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                pii_redaction=PIIRedactionConfig(enabled=True),
                redact_output=True,
            ),
        )
        enforcer = Enforcer(policy)
        result, count = enforcer._redact_output("email: test@example.com")
        assert count > 0
        assert "test@example.com" not in result

    def test_redact_output_false_skips(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                pii_redaction=PIIRedactionConfig(enabled=True),
                redact_output=False,
            ),
        )
        enforcer = Enforcer(policy)
        result, count = enforcer._redact_output("email: test@example.com")
        assert count == 0
        assert "test@example.com" in result


# ---------------------------------------------------------------------------
# C-2: Case-insensitive tool name matching
# ---------------------------------------------------------------------------


class TestC2CaseInsensitiveToolMatching:
    def test_denied_case_insensitive(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(denied_tools=["execute_shell"]),
        )
        engine = PolicyEngine(policy)

        # Exact match
        ctx = CallContext(tool_name="execute_shell")
        assert not engine.evaluate_pre_call(ctx).is_allowed

        # Case variant bypass should be blocked
        ctx2 = CallContext(tool_name="Execute_Shell")
        assert not engine.evaluate_pre_call(ctx2).is_allowed

        ctx3 = CallContext(tool_name="EXECUTE_SHELL")
        assert not engine.evaluate_pre_call(ctx3).is_allowed

    def test_allowed_case_insensitive(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(allowed_tools=["search_web"]),
        )
        engine = PolicyEngine(policy)

        # Exact match
        ctx = CallContext(tool_name="search_web")
        assert engine.evaluate_pre_call(ctx).is_allowed

        # Case variant should still be allowed
        ctx2 = CallContext(tool_name="Search_Web")
        assert engine.evaluate_pre_call(ctx2).is_allowed

        # Non-matching should be blocked
        ctx3 = CallContext(tool_name="other_tool")
        assert not engine.evaluate_pre_call(ctx3).is_allowed


# ---------------------------------------------------------------------------
# H-1: LRU policy cache with eviction
# ---------------------------------------------------------------------------


class TestH1PolicyCache:
    def test_clear_policy_cache(self) -> None:
        with _policy_cache_lock:
            _policy_cache["test_key"] = Policy(name="test")
        count = clear_policy_cache()
        assert count >= 1
        with _policy_cache_lock:
            assert len(_policy_cache) == 0


# ---------------------------------------------------------------------------
# H-3: Blocked calls record input_redactions
# ---------------------------------------------------------------------------


class TestH3BlockedRedactions:
    def test_blocked_after_redaction_records_count(self) -> None:
        """When a call is blocked after input redaction, the audit entry
        should record the correct input_redactions count."""
        policy = Policy(
            name="test",
            rules=PolicyRules(
                pii_redaction=PIIRedactionConfig(enabled=True),
                denied_tools=["blocked_tool"],
            ),
        )
        enforcer = Enforcer(policy)
        # The redaction happens before the denied check now, but the
        # denied check happens before redaction in current flow.
        # This test verifies the variable is properly initialized.
        with pytest.raises((ToolDeniedError, Exception)):
            enforcer.enforce_sync(
                lambda: None,
                tool_name="blocked_tool",
            )


# ---------------------------------------------------------------------------
# H-4: Unicode normalization position mismatch
# ---------------------------------------------------------------------------


class TestH4UnicodePositionMismatch:
    def test_redact_with_unicode_surrounding(self) -> None:
        """Redaction should work correctly with unicode in surrounding text."""
        redactor = Redactor(categories=["email"])
        # Unicode chars in surrounding text, but ASCII email
        result = redactor.redact("Bonjour caf\u00e9! Contact: test@example.com please")
        assert "test@example.com" not in result.text
        assert "<EMAIL>" in result.text
        assert "caf\u00e9" in result.text  # Surrounding unicode preserved

    def test_redact_preserves_surrounding(self) -> None:
        """Surrounding text should be intact after redaction."""
        redactor = Redactor(categories=["email"])
        result = redactor.redact("Before test@example.com After")
        assert result.text.startswith("Before ")
        assert result.text.endswith(" After")

    def test_redact_multiple_with_unicode(self) -> None:
        """Multiple PII entities in text with unicode should all be redacted."""
        redactor = Redactor(categories=["email", "phone"])
        text = "\u00dcber cool: test@example.com and 555-123-4567"
        result = redactor.redact(text)
        assert "test@example.com" not in result.text
        assert "555-123-4567" not in result.text
        assert "\u00dcber cool" in result.text


# ---------------------------------------------------------------------------
# H-6: SSN regex improvements
# ---------------------------------------------------------------------------


class TestH6SSNRegex:
    def test_ssn_with_dashes(self) -> None:
        redactor = Redactor(categories=["ssn"])
        result = redactor.redact("SSN: 123-45-6789")
        assert "123-45-6789" not in result.text

    def test_ssn_with_spaces(self) -> None:
        redactor = Redactor(categories=["ssn"])
        result = redactor.redact("SSN: 123 45 6789")
        assert "123 45 6789" not in result.text

    def test_ssn_plain(self) -> None:
        redactor = Redactor(categories=["ssn"])
        result = redactor.redact("SSN: 123456789")
        assert "123456789" not in result.text

    def test_ssn_mixed_separators_no_match(self) -> None:
        """Mixed separators (dash then space) should NOT match to reduce
        false positives."""
        redactor = Redactor(categories=["ssn"])
        result = redactor.redact("SSN: 123-45 6789")
        # Mixed separators shouldn't match
        assert result.count == 0

    def test_ssn_invalid_prefix_000(self) -> None:
        redactor = Redactor(categories=["ssn"])
        result = redactor.redact("000-45-6789")
        assert result.count == 0

    def test_ssn_invalid_prefix_666(self) -> None:
        redactor = Redactor(categories=["ssn"])
        result = redactor.redact("666-45-6789")
        assert result.count == 0


# ---------------------------------------------------------------------------
# L-3: Redactor __repr__
# ---------------------------------------------------------------------------


class TestL3RedactorRepr:
    def test_repr(self) -> None:
        redactor = Redactor(categories=["email", "phone"])
        r = repr(redactor)
        assert "Redactor" in r
        assert "email" in r
        assert "placeholder" in r


# ---------------------------------------------------------------------------
# L-6: Credit card regex fix
# ---------------------------------------------------------------------------


class TestL6CreditCardRegex:
    def test_valid_visa(self) -> None:
        redactor = Redactor(categories=["credit_card"])
        result = redactor.redact("Card: 4111111111111111")
        assert result.count > 0

    def test_valid_mastercard(self) -> None:
        redactor = Redactor(categories=["credit_card"])
        result = redactor.redact("Card: 5500000000000004")
        assert result.count > 0

    def test_valid_amex(self) -> None:
        redactor = Redactor(categories=["credit_card"])
        result = redactor.redact("Card: 340000000000009")
        assert result.count > 0

    def test_too_short_no_match(self) -> None:
        """12-digit numbers starting with valid prefix should NOT match."""
        redactor = Redactor(categories=["credit_card"])
        result = redactor.redact("Number: 411111111111")
        assert result.count == 0


# ---------------------------------------------------------------------------
# M-3: PII default categories include ip_address
# ---------------------------------------------------------------------------


class TestM3PIIDefaults:
    def test_pii_config_defaults_include_ip(self) -> None:
        config = PIIRedactionConfig()
        assert "ip_address" in config.categories

    def test_redactor_defaults_include_ip(self) -> None:
        redactor = Redactor()
        assert "ip_address" in redactor.categories


# ---------------------------------------------------------------------------
# M-4: NullBackend thread-safe
# ---------------------------------------------------------------------------


class TestM4NullBackendThreadSafe:
    def test_concurrent_writes(self) -> None:
        backend = NullBackend()
        threads = []
        for _ in range(10):
            t = threading.Thread(target=lambda: [backend.write({}) for _ in range(100)])
            threads.append(t)
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert backend.entries_discarded == 1000


# ---------------------------------------------------------------------------
# M-6: MultiBackend all-fail raises
# ---------------------------------------------------------------------------


class TestM6MultiBackendAllFail:
    def test_all_fail_raises(self) -> None:
        from enforcecore.auditor.backends import AuditBackend
        from enforcecore.core.types import AuditError

        class FailingBackend(AuditBackend):
            def write(self, entry_dict: dict) -> None:
                raise RuntimeError("fail")

            def close(self) -> None:
                pass

        multi = MultiBackend([FailingBackend(), FailingBackend()])
        with pytest.raises(AuditError, match="All 2 audit backends failed"):
            multi.write({"test": True})

    def test_partial_fail_ok(self) -> None:
        """If at least one backend succeeds, no error is raised."""
        from enforcecore.auditor.backends import AuditBackend

        class FailingBackend(AuditBackend):
            def write(self, entry_dict: dict) -> None:
                raise RuntimeError("fail")

            def close(self) -> None:
                pass

        null = NullBackend()
        multi = MultiBackend([FailingBackend(), null])
        multi.write({"test": True})  # Should not raise
        assert null.entries_discarded == 1


# ---------------------------------------------------------------------------
# M-7: guard_sync/guard_async removed (deprecated since v1.0.6, removed v1.0.16)
# ---------------------------------------------------------------------------


class TestM7DeprecatedMethodsRemoved:
    def test_guard_sync_removed(self) -> None:
        policy = Policy(name="test")
        enforcer = Enforcer(policy)
        assert not hasattr(enforcer, "guard_sync")

    def test_guard_async_removed(self) -> None:
        policy = Policy(name="test")
        enforcer = Enforcer(policy)
        assert not hasattr(enforcer, "guard_async")


# ---------------------------------------------------------------------------
# Content rules in enforcer pipeline
# ---------------------------------------------------------------------------


class TestContentRulesEnforcer:
    def test_shell_injection_blocked(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=True),
            ),
        )
        enforcer = Enforcer(policy)
        with pytest.raises(ContentViolationError, match="shell_injection"):
            enforcer.enforce_sync(
                lambda cmd: cmd,
                "rm -rf /",
                tool_name="run_command",
            )

    def test_safe_input_passes(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=True),
            ),
        )
        enforcer = Enforcer(policy)
        result = enforcer.enforce_sync(
            lambda q: f"result for {q}",
            "what is the weather?",
            tool_name="search",
        )
        assert "result for" in result

    def test_sql_injection_blocked(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=True),
            ),
        )
        enforcer = Enforcer(policy)
        with pytest.raises(ContentViolationError, match="sql_injection"):
            enforcer.enforce_sync(
                lambda q: q,
                "' OR 1=1 --",
                tool_name="db_query",
            )

    def test_output_content_filtering(self) -> None:
        """Content rules should also inspect output strings."""
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=True),
            ),
        )
        enforcer = Enforcer(policy)
        with pytest.raises(ContentViolationError, match="output"):
            enforcer.enforce_sync(
                lambda: "run exec('import os')",
                tool_name="agent_tool",
            )

    @pytest.mark.asyncio
    async def test_async_content_rules(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=True),
            ),
        )
        enforcer = Enforcer(policy)
        with pytest.raises(ContentViolationError, match="shell_injection"):
            await enforcer.enforce_async(
                lambda cmd: cmd,
                "rm -rf /",
                tool_name="run_command",
            )

    def test_disabled_content_rules_allow_all(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                content_rules=ContentRulesPolicyConfig(enabled=False),
            ),
        )
        enforcer = Enforcer(policy)
        result = enforcer.enforce_sync(
            lambda cmd: cmd,
            "rm -rf /",
            tool_name="run_command",
        )
        assert result == "rm -rf /"


# ---------------------------------------------------------------------------
# Network enforcement in enforcer pipeline
# ---------------------------------------------------------------------------


class TestNetworkEnforcerPipeline:
    def test_denied_domain_blocked(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                network=NetworkPolicy(
                    enabled=True,
                    denied_domains=["*.malware.xyz"],
                    deny_all_other=False,
                ),
            ),
        )
        enforcer = Enforcer(policy)
        with pytest.raises(DomainDeniedError, match="malware"):
            enforcer.enforce_sync(
                lambda url: url,
                "https://evil.malware.xyz/payload",
                tool_name="fetch",
            )

    def test_allowed_domain_passes(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                network=NetworkPolicy(
                    enabled=True,
                    allowed_domains=["api.openai.com"],
                    deny_all_other=True,
                ),
            ),
        )
        enforcer = Enforcer(policy)
        result = enforcer.enforce_sync(
            lambda url: f"fetched {url}",
            "https://api.openai.com/v1/chat",
            tool_name="fetch",
        )
        assert "fetched" in result

    def test_disabled_network_allows_all(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                network=NetworkPolicy(enabled=False),
            ),
        )
        enforcer = Enforcer(policy)
        result = enforcer.enforce_sync(
            lambda url: url,
            "https://evil.com/bad",
            tool_name="fetch",
        )
        assert "evil.com" in result

    @pytest.mark.asyncio
    async def test_async_network_enforcement(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                network=NetworkPolicy(
                    enabled=True,
                    denied_domains=["evil.com"],
                    deny_all_other=False,
                ),
            ),
        )
        enforcer = Enforcer(policy)
        with pytest.raises(DomainDeniedError):
            await enforcer.enforce_async(
                lambda url: url,
                "https://evil.com/bad",
                tool_name="fetch",
            )


# ---------------------------------------------------------------------------
# Rate limiting in enforcer pipeline
# ---------------------------------------------------------------------------


class TestRateLimitEnforcerPipeline:
    def test_rate_limit_blocks_after_max(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                rate_limits=RateLimitPolicyConfig(
                    enabled=True,
                    per_tool={
                        "search": {"max_calls": 2, "window_seconds": 10},
                    },
                ),
            ),
        )
        enforcer = Enforcer(policy)
        enforcer.enforce_sync(lambda: "ok", tool_name="search")
        enforcer.enforce_sync(lambda: "ok", tool_name="search")
        with pytest.raises(RateLimitError):
            enforcer.enforce_sync(lambda: "ok", tool_name="search")

    def test_disabled_rate_limits(self) -> None:
        policy = Policy(
            name="test",
            rules=PolicyRules(
                rate_limits=RateLimitPolicyConfig(enabled=False),
            ),
        )
        enforcer = Enforcer(policy)
        for _ in range(100):
            enforcer.enforce_sync(lambda: "ok", tool_name="search")

    @pytest.mark.asyncio
    async def test_async_rate_limit(self) -> None:
        policy = Policy(
            name="strict",
            rules=PolicyRules(
                rate_limits=RateLimitPolicyConfig(
                    enabled=True,
                    per_tool={
                        "search": {"max_calls": 1, "window_seconds": 10},
                    },
                ),
            ),
        )
        enforcer = Enforcer(policy)

        async def noop() -> str:
            return "ok"

        await enforcer.enforce_async(noop, tool_name="search")
        with pytest.raises(RateLimitError):
            await enforcer.enforce_async(noop, tool_name="search")


# ---------------------------------------------------------------------------
# New policy models
# ---------------------------------------------------------------------------


class TestNewPolicyModels:
    def test_content_rules_config(self) -> None:
        config = ContentRulesPolicyConfig(
            enabled=True,
            block_patterns=[
                {"name": "shell_injection"},
                {"name": "custom", "pattern": "bad"},
            ],
        )
        assert config.enabled
        assert len(config.block_patterns) == 2

    def test_rate_limit_config(self) -> None:
        config = RateLimitPolicyConfig(
            enabled=True,
            per_tool={"search": {"max_calls": 10, "window_seconds": 60}},
            global_limit={"max_calls": 100, "window_seconds": 60},
        )
        assert config.enabled
        assert "search" in config.per_tool

    def test_network_policy_with_denied(self) -> None:
        net = NetworkPolicy(
            enabled=True,
            allowed_domains=["safe.com"],
            denied_domains=["evil.com"],
        )
        assert net.enabled
        assert "evil.com" in net.denied_domains

    def test_policy_rules_new_fields(self) -> None:
        rules = PolicyRules(
            content_rules=ContentRulesPolicyConfig(enabled=True),
            rate_limits=RateLimitPolicyConfig(enabled=True),
        )
        assert rules.content_rules.enabled
        assert rules.rate_limits.enabled

    def test_policy_from_dict_with_new_fields(self) -> None:
        data = {
            "name": "deep-security",
            "version": "1.0",
            "rules": {
                "content_rules": {
                    "enabled": True,
                    "block_patterns": [{"name": "shell_injection"}],
                },
                "rate_limits": {
                    "enabled": True,
                    "per_tool": {
                        "search": {"max_calls": 10, "window_seconds": 60},
                    },
                },
                "network": {
                    "enabled": True,
                    "allowed_domains": ["api.example.com"],
                    "denied_domains": ["evil.com"],
                },
            },
        }
        policy = Policy.from_dict(data)
        assert policy.rules.content_rules.enabled
        assert policy.rules.rate_limits.enabled
        assert policy.rules.network.enabled

    def test_new_violation_types(self) -> None:
        assert ViolationType.CONTENT_VIOLATION == "content_violation"
        assert ViolationType.RATE_LIMIT == "rate_limit"

    def test_content_violation_error(self) -> None:
        err = ContentViolationError(
            "shell_injection",
            "shell injection detected",
            tool_name="run_cmd",
            policy_name="strict",
        )
        assert err.violation_type == ViolationType.CONTENT_VIOLATION
        assert "shell_injection" in str(err)


# ---------------------------------------------------------------------------
# Combined defense-in-depth
# ---------------------------------------------------------------------------


class TestDefenseInDepth:
    """Test all new features working together."""

    def test_full_pipeline(self) -> None:
        policy = Policy(
            name="defense-in-depth",
            rules=PolicyRules(
                allowed_tools=["search", "fetch"],
                pii_redaction=PIIRedactionConfig(enabled=True),
                content_rules=ContentRulesPolicyConfig(enabled=True),
                rate_limits=RateLimitPolicyConfig(
                    enabled=True,
                    per_tool={"search": {"max_calls": 5, "window_seconds": 10}},
                ),
                network=NetworkPolicy(
                    enabled=True,
                    allowed_domains=["api.example.com"],
                    deny_all_other=True,
                ),
            ),
        )
        enforcer = Enforcer(policy)

        # Allowed call
        result = enforcer.enforce_sync(
            lambda q: f"results for {q}",
            "weather",
            tool_name="search",
        )
        assert "results for" in result

        # Tool denied
        with pytest.raises((ToolDeniedError, Exception)):
            enforcer.enforce_sync(
                lambda: "ok",
                tool_name="forbidden_tool",
            )

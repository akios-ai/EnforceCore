"""Integration tests: PII redaction in the enforcer pipeline."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from enforcecore.core.enforcer import Enforcer

if TYPE_CHECKING:
    from enforcecore.core.policy import Policy

# =========================================================================
# Helpers
# =========================================================================


def _echo(*args: str, **kwargs: str) -> str:
    """Simple sync function that echoes its first arg."""
    return args[0] if args else next(iter(kwargs.values()), "")


async def _async_echo(*args: str, **kwargs: str) -> str:
    """Async version of echo."""
    return args[0] if args else next(iter(kwargs.values()), "")


def _return_pii() -> str:
    """Function that returns PII in output."""
    return "Contact john@example.com or call 555-123-4567"


async def _async_return_pii() -> str:
    """Async function that returns PII."""
    return "Contact john@example.com or call 555-123-4567"


# =========================================================================
# Sync enforcer + PII redaction
# =========================================================================


class TestEnforcerSyncRedaction:
    """enforce_sync with PII redaction enabled."""

    def test_input_redaction(self, pii_redaction_policy: Policy) -> None:
        """String args containing PII should be redacted before the call."""
        enforcer = Enforcer(pii_redaction_policy)

        # _echo receives the redacted version
        result = enforcer.enforce_sync(_echo, "send to john@example.com", tool_name="echo")
        assert "john@example.com" not in result
        assert "<EMAIL>" in result

    def test_kwargs_redaction(self, pii_redaction_policy: Policy) -> None:
        """Keyword arguments should also be redacted."""
        enforcer = Enforcer(pii_redaction_policy)

        def grab_kwarg(*, message: str = "") -> str:
            return message

        result = enforcer.enforce_sync(grab_kwarg, tool_name="grab", message="call 555-123-4567")
        assert "555-123-4567" not in result
        assert "<PHONE>" in result

    def test_output_redaction(self, pii_redaction_policy: Policy) -> None:
        """PII in output is redacted after the call."""
        enforcer = Enforcer(pii_redaction_policy)
        result = enforcer.enforce_sync(_return_pii, tool_name="pii_out")
        assert "john@example.com" not in result
        assert "<EMAIL>" in result
        assert "<PHONE>" in result

    def test_no_pii_passes_through(self, pii_redaction_policy: Policy) -> None:
        """Non-PII content is unchanged."""
        enforcer = Enforcer(pii_redaction_policy)
        result = enforcer.enforce_sync(_echo, "hello world", tool_name="echo")
        assert result == "hello world"

    def test_non_string_args_unchanged(self, pii_redaction_policy: Policy) -> None:
        """Non-string args are not touched by redaction."""

        def add(a: int, b: int) -> int:
            return a + b

        enforcer = Enforcer(pii_redaction_policy)
        result = enforcer.enforce_sync(add, 2, 3, tool_name="add")
        assert result == 5

    def test_non_string_output_unchanged(self, pii_redaction_policy: Policy) -> None:
        """Non-string output is not touched by redaction."""

        def get_number() -> int:
            return 42

        enforcer = Enforcer(pii_redaction_policy)
        result = enforcer.enforce_sync(get_number, tool_name="num")
        assert result == 42


# =========================================================================
# Async enforcer + PII redaction
# =========================================================================


class TestEnforcerAsyncRedaction:
    """enforce_async with PII redaction enabled."""

    @pytest.mark.asyncio
    async def test_input_redaction_async(self, pii_redaction_policy: Policy) -> None:
        enforcer = Enforcer(pii_redaction_policy)
        result = await enforcer.enforce_async(_async_echo, "SSN: 123-45-6789", tool_name="echo")
        assert "123-45-6789" not in result
        assert "<SSN>" in result

    @pytest.mark.asyncio
    async def test_output_redaction_async(self, pii_redaction_policy: Policy) -> None:
        enforcer = Enforcer(pii_redaction_policy)
        result = await enforcer.enforce_async(_async_return_pii, tool_name="pii_out")
        assert "john@example.com" not in result
        assert "<EMAIL>" in result

    @pytest.mark.asyncio
    async def test_no_pii_async(self, pii_redaction_policy: Policy) -> None:
        enforcer = Enforcer(pii_redaction_policy)
        result = await enforcer.enforce_async(_async_echo, "safe text", tool_name="echo")
        assert result == "safe text"


# =========================================================================
# Redaction disabled
# =========================================================================


class TestRedactionDisabled:
    """When PII redaction is disabled, data passes through untouched."""

    def test_no_redaction_when_disabled(self, allow_all_policy: Policy) -> None:
        """allow_all policy has pii_redaction.enabled=false."""
        enforcer = Enforcer(allow_all_policy)
        text = "send to john@example.com"
        result = enforcer.enforce_sync(_echo, text, tool_name="echo")
        assert result == text  # Unchanged — no redaction

    def test_redactor_is_none_when_disabled(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert enforcer._redactor is None


# =========================================================================
# Mask strategy integration
# =========================================================================


class TestMaskStrategy:
    """Mask strategy through the enforcer pipeline."""

    def test_mask_email(self, pii_mask_policy: Policy) -> None:
        enforcer = Enforcer(pii_mask_policy)
        result = enforcer.enforce_sync(_echo, "john@example.com", tool_name="echo")
        assert result == "****@****.***"

    def test_mask_phone(self, pii_mask_policy: Policy) -> None:
        enforcer = Enforcer(pii_mask_policy)
        result = enforcer.enforce_sync(_echo, "call 555-123-4567", tool_name="echo")
        assert "***-***-****" in result


# =========================================================================
# Multiple PII in single call
# =========================================================================


class TestMultiplePII:
    """Multiple PII entities in one call."""

    def test_multiple_categories_redacted(self, pii_redaction_policy: Policy) -> None:
        enforcer = Enforcer(pii_redaction_policy)
        text = (
            "Email: john@example.com, SSN: 123-45-6789, IP: 192.168.1.1, Card: 4111-1111-1111-1111"
        )
        result = enforcer.enforce_sync(_echo, text, tool_name="multi")
        assert "<EMAIL>" in result
        assert "<SSN>" in result
        assert "<IP_ADDRESS>" in result
        assert "<CREDIT_CARD>" in result
        # All PII should be gone
        assert "john@example.com" not in result
        assert "123-45-6789" not in result
        assert "192.168.1.1" not in result
        assert "4111-1111-1111-1111" not in result


# =========================================================================
# Build redactor from policy
# =========================================================================


class TestBuildRedactor:
    """Redactor is correctly built from policy configuration."""

    def test_redactor_created_when_enabled(self, pii_redaction_policy: Policy) -> None:
        enforcer = Enforcer(pii_redaction_policy)
        assert enforcer._redactor is not None

    def test_redactor_none_when_disabled(self, allow_all_policy: Policy) -> None:
        enforcer = Enforcer(allow_all_policy)
        assert enforcer._redactor is None

    def test_redactor_categories_from_policy(self, pii_redaction_policy: Policy) -> None:
        enforcer = Enforcer(pii_redaction_policy)
        redactor = enforcer._redactor
        assert redactor is not None
        assert "email" in redactor.categories
        assert "phone" in redactor.categories

    def test_mask_policy_creates_mask_redactor(self, pii_mask_policy: Policy) -> None:
        from enforcecore.core.types import RedactionStrategy

        enforcer = Enforcer(pii_mask_policy)
        redactor = enforcer._redactor
        assert redactor is not None
        assert redactor.strategy == RedactionStrategy.MASK

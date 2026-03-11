# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.integrations.langchain — LangChain callback handler."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from enforcecore.core.types import ToolDeniedError

if TYPE_CHECKING:
    import types

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# Module-level import safety
# ---------------------------------------------------------------------------


class TestModuleImport:
    """Verify the adapter module can be imported without the framework."""

    def test_import_succeeds_without_langchain(self) -> None:
        """Importing the module should work even without langchain-core."""
        import enforcecore.integrations.langchain as mod

        assert hasattr(mod, "EnforceCoreCallbackHandler")

    def test_handler_raises_without_langchain(
        self,
        monkeypatch: pytest.MonkeyPatch,
        allow_all_policy: Policy,
    ) -> None:
        """Creating a handler without langchain-core gives a clear error."""
        import sys

        # Ensure langchain_core is NOT in sys.modules
        monkeypatch.delitem(sys.modules, "langchain_core", raising=False)
        monkeypatch.delitem(sys.modules, "langchain_core.callbacks", raising=False)
        monkeypatch.delitem(sys.modules, "langchain_core.callbacks.base", raising=False)

        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        with pytest.raises(ImportError, match="pip install langchain-core"):
            EnforceCoreCallbackHandler(policy=allow_all_policy)


# ---------------------------------------------------------------------------
# PII redaction in prompts (on_llm_start)
# ---------------------------------------------------------------------------


class TestOnLLMStart:
    """PII redaction in LLM prompts via on_llm_start."""

    def test_redacts_pii_in_prompts(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """PII in prompts should be redacted in-place."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=pii_redaction_policy)
        prompts = ["My email is alice@example.com and SSN 123-45-6789"]
        handler.on_llm_start({}, prompts)

        # The prompt should be modified in-place
        assert "alice@example.com" not in prompts[0]
        assert "123-45-6789" not in prompts[0]
        assert handler.total_input_redactions >= 2

    def test_no_redaction_when_disabled(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """With redact_inputs=False, prompts should remain untouched."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(
            policy=pii_redaction_policy, redact_inputs=False
        )
        original = "My email is alice@example.com"
        prompts = [original]
        handler.on_llm_start({}, prompts)

        assert prompts[0] == original
        assert handler.total_input_redactions == 0

    def test_no_pii_no_redaction(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """Clean text should pass through unchanged."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=pii_redaction_policy)
        prompts = ["What is the weather in Paris?"]
        handler.on_llm_start({}, prompts)

        assert prompts[0] == "What is the weather in Paris?"
        assert handler.total_input_redactions == 0


# ---------------------------------------------------------------------------
# PII redaction in responses (on_llm_end)
# ---------------------------------------------------------------------------


class TestOnLLMEnd:
    """PII redaction in LLM responses via on_llm_end."""

    def test_redacts_pii_in_responses(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """PII in LLM response generations should be redacted."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler
        from tests.integrations.conftest import MockGeneration, MockLLMResult

        handler = EnforceCoreCallbackHandler(policy=pii_redaction_policy)

        gen = MockGeneration(text="Contact alice@example.com for info")
        response = MockLLMResult(generations=[[gen]])
        handler.on_llm_end(response)

        assert "alice@example.com" not in gen.text
        assert handler.total_output_redactions >= 1

    def test_no_redaction_when_disabled(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """With redact_outputs=False, responses should remain untouched."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler
        from tests.integrations.conftest import MockGeneration, MockLLMResult

        handler = EnforceCoreCallbackHandler(
            policy=pii_redaction_policy, redact_outputs=False
        )

        original = "Contact alice@example.com"
        gen = MockGeneration(text=original)
        response = MockLLMResult(generations=[[gen]])
        handler.on_llm_end(response)

        assert gen.text == original
        assert handler.total_output_redactions == 0


# ---------------------------------------------------------------------------
# Tool policy enforcement (on_tool_start)
# ---------------------------------------------------------------------------


class TestOnToolStart:
    """Tool allow/deny enforcement via on_tool_start."""

    def test_allowed_tool_passes(
        self,
        mock_langchain_callbacks: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """An allowed tool should pass without raising."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=allow_all_policy)
        # Should not raise
        handler.on_tool_start({"name": "search_web"}, "query text")
        assert handler.total_events == 1

    def test_denied_tool_raises(
        self,
        mock_langchain_callbacks: types.ModuleType,
        deny_all_policy: Policy,
    ) -> None:
        """A denied tool should raise ToolDeniedError."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=deny_all_policy)
        with pytest.raises(ToolDeniedError):
            handler.on_tool_start({"name": "search_web"}, "query")

    def test_specific_tools_policy(
        self,
        mock_langchain_callbacks: types.ModuleType,
        specific_tools_policy: Policy,
    ) -> None:
        """Only tools in the allowed list should pass."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=specific_tools_policy)

        # search_web is in allowed list
        handler.on_tool_start({"name": "search_web"}, "query")
        assert handler.total_events == 1

        # execute_shell is NOT in allowed list
        with pytest.raises(ToolDeniedError):
            handler.on_tool_start({"name": "execute_shell"}, "rm -rf /")


# ---------------------------------------------------------------------------
# Error handlers (on_llm_error, on_tool_error)
# ---------------------------------------------------------------------------


class TestErrorHandlers:
    """Error callback methods should not crash."""

    def test_on_llm_error_does_not_crash(
        self,
        mock_langchain_callbacks: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """on_llm_error should log the error without raising."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=allow_all_policy)
        handler.on_llm_error(RuntimeError("LLM API timeout"))
        assert handler.total_events == 1

    def test_on_tool_error_does_not_crash(
        self,
        mock_langchain_callbacks: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """on_tool_error should log the error without raising."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=allow_all_policy)
        handler.on_tool_error(ValueError("Tool failed"))
        assert handler.total_events == 1

    def test_on_tool_end_logs_event(
        self,
        mock_langchain_callbacks: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """on_tool_end should increment the event counter."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=allow_all_policy)
        handler.on_tool_end("tool output text")
        assert handler.total_events == 1


# ---------------------------------------------------------------------------
# Chain callbacks (on_chain_start, on_chain_end)
# ---------------------------------------------------------------------------


class TestChainCallbacks:
    """Chain-level redaction callbacks."""

    def test_on_chain_start_redacts_inputs(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """PII in chain inputs should be redacted in-place."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=pii_redaction_policy)
        inputs: dict[str, Any] = {"query": "Email alice@example.com please"}
        handler.on_chain_start({}, inputs)

        assert "alice@example.com" not in inputs["query"]
        assert handler.total_input_redactions >= 1

    def test_on_chain_end_redacts_outputs(
        self,
        mock_langchain_callbacks: types.ModuleType,
        pii_redaction_policy: Policy,
    ) -> None:
        """PII in chain outputs should be redacted in-place."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=pii_redaction_policy)
        outputs: dict[str, Any] = {"result": "Found user alice@example.com"}
        handler.on_chain_end(outputs)

        assert "alice@example.com" not in outputs["result"]
        assert handler.total_output_redactions >= 1


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


class TestConfiguration:
    """Handler configuration and policy loading."""

    def test_policy_from_yaml_path(
        self,
        mock_langchain_callbacks: types.ModuleType,
        fixtures_dir: Any,
    ) -> None:
        """Should accept a string path to a YAML policy file."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(
            policy=str(fixtures_dir / "allow_all.yaml")
        )
        assert handler.policy.name is not None

    def test_no_policy_uses_default(
        self,
        mock_langchain_callbacks: types.ModuleType,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without a policy arg, should use ENFORCECORE_DEFAULT_POLICY."""
        from enforcecore.core.config import settings
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler
        from tests.conftest import FIXTURES_DIR

        monkeypatch.setattr(settings, "default_policy", FIXTURES_DIR / "allow_all.yaml")

        handler = EnforceCoreCallbackHandler()
        assert handler.policy is not None

    def test_no_policy_no_default_raises(
        self,
        mock_langchain_callbacks: types.ModuleType,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Without a policy and no default, should raise PolicyLoadError."""
        from enforcecore.core.config import settings
        from enforcecore.core.types import PolicyLoadError
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        monkeypatch.setattr(settings, "default_policy", None)

        with pytest.raises(PolicyLoadError, match="No policy provided"):
            EnforceCoreCallbackHandler()

    def test_event_counter_accumulates(
        self,
        mock_langchain_callbacks: types.ModuleType,
        allow_all_policy: Policy,
    ) -> None:
        """Event counter should accumulate across multiple callback calls."""
        from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

        handler = EnforceCoreCallbackHandler(policy=allow_all_policy)
        handler.on_llm_start({}, ["prompt"])
        handler.on_llm_end(object())
        handler.on_tool_end("output")
        assert handler.total_events == 3

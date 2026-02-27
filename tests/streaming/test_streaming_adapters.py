# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for enforcecore.streaming.adapters."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from enforcecore.core.policy import Policy
from enforcecore.streaming.adapters import (
    EnforceCoreStreamingCallback,
    autogen_stream_enforce,
    langgraph_stream_enforce,
)

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator

    from enforcecore.streaming.core import StreamEnforcementResult

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _policy(name: str) -> Policy:
    return Policy.from_file(str(FIXTURES / f"{name}.yaml"))


async def _gen(*tokens: str) -> AsyncGenerator[str, None]:
    for tok in tokens:
        yield tok


# ---------------------------------------------------------------------------
# AutoGen adapter
# ---------------------------------------------------------------------------


class TestAutoGenStreamEnforce:
    def test_clean_stream_passes_through(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async for tok in autogen_stream_enforce(
                _gen("Hello ", "world!"),
                policy=policy,
                redact=True,
            ):
                parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert output == "Hello world!"

    def test_pii_redacted(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async for tok in autogen_stream_enforce(
                _gen("Email alice@example.com"),
                policy=policy,
                redact=True,
            ):
                parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert "alice@example.com" not in output
        assert "[EMAIL]" in output

    def test_redact_false(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async for tok in autogen_stream_enforce(
                _gen("alice@example.com"),
                policy=policy,
                redact=False,
            ):
                parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert output == "alice@example.com"

    def test_result_out_populated(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async for _ in autogen_stream_enforce(
                _gen("no pii here"),
                policy=policy,
                result_out=result_out,
            ):
                pass

        asyncio.run(run())
        assert len(result_out) == 1
        assert result_out[0].tool_name == "autogen_stream"

    def test_custom_tool_name(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async for _ in autogen_stream_enforce(
                _gen("hello"),
                policy=policy,
                tool_name="my_agent",
                result_out=result_out,
            ):
                pass

        asyncio.run(run())
        assert result_out[0].tool_name == "my_agent"

    def test_empty_stream(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async for tok in autogen_stream_enforce(_gen(), policy=policy):
                parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert output == ""

    def test_multiple_pii_redacted(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async for tok in autogen_stream_enforce(
                _gen("alice@example.com and 192.168.1.1"),
                policy=policy,
                redact=True,
            ):
                parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert "alice@example.com" not in output
        assert "192.168.1.1" not in output


# ---------------------------------------------------------------------------
# LangGraph adapter
# ---------------------------------------------------------------------------


async def _event_gen(*events: object) -> AsyncGenerator[object, None]:
    for e in events:
        yield e


class TestLangGraphStreamEnforce:
    def test_string_events_redacted(self) -> None:
        policy = _policy("allow_all")

        async def run() -> list[str]:
            events: list[str] = []
            async with langgraph_stream_enforce(
                _event_gen("Hello ", "alice@example.com", "!"),
                policy=policy,
                redact=True,
            ) as safe:
                async for e in safe:
                    events.append(str(e))
            return events

        collected = asyncio.run(run())
        full = "".join(collected)
        assert "alice@example.com" not in full
        assert "[EMAIL]" in full

    def test_non_string_events_pass_through(self) -> None:
        policy = _policy("allow_all")
        ev1 = {"type": "chunk", "content": "hello"}
        ev2 = {"type": "end"}

        async def run() -> list[object]:
            events: list[object] = []
            async with langgraph_stream_enforce(
                _event_gen(ev1, ev2),
                policy=policy,
                redact=True,
            ) as safe:
                async for e in safe:
                    events.append(e)
            return events

        collected = asyncio.run(run())
        assert collected[0] is ev1
        assert collected[1] is ev2

    def test_token_extractor_applied(self) -> None:
        policy = _policy("allow_all")
        events = [
            {"delta": "alice@example.com"},
            {"delta": " hello"},
        ]

        async def run() -> list[str]:
            results: list[str] = []
            async with langgraph_stream_enforce(
                _event_gen(*events),
                policy=policy,
                token_extractor=lambda e: e.get("delta") if isinstance(e, dict) else None,
                redact=True,
            ) as safe:
                async for chunk in safe:
                    results.append(str(chunk))
            return results

        collected = asyncio.run(run())
        full = "".join(collected)
        assert "alice@example.com" not in full

    def test_redact_false_no_redaction(self) -> None:
        policy = _policy("allow_all")

        async def run() -> str:
            parts: list[str] = []
            async with langgraph_stream_enforce(
                _event_gen("alice@example.com"),
                policy=policy,
                redact=False,
            ) as safe:
                async for e in safe:
                    parts.append(str(e))
            return "".join(parts)

        output = asyncio.run(run())
        assert output == "alice@example.com"

    def test_result_out_populated(self) -> None:
        policy = _policy("allow_all")
        result_out: list[StreamEnforcementResult] = []

        async def run() -> None:
            async with langgraph_stream_enforce(
                _event_gen("hello"),
                policy=policy,
                result_out=result_out,
            ) as safe:
                async for _ in safe:
                    pass

        asyncio.run(run())
        assert len(result_out) == 1

    def test_empty_graph_stream(self) -> None:
        policy = _policy("allow_all")

        async def run() -> list[object]:
            results: list[object] = []
            async with langgraph_stream_enforce(_event_gen(), policy=policy) as safe:
                async for e in safe:
                    results.append(e)
            return results

        assert asyncio.run(run()) == []


# ---------------------------------------------------------------------------
# LangChain adapter
# ---------------------------------------------------------------------------


class TestEnforceCoreStreamingCallback:
    def test_raises_import_error_without_langchain(self) -> None:
        """When langchain-core is not installed, constructor must raise ImportError."""
        # Temporarily hide langchain_core from sys.modules
        original = sys.modules.get("langchain_core")
        sys.modules["langchain_core"] = None  # type: ignore[assignment]
        # Also hide the submodule path checked in the constructor
        original_cb = sys.modules.get("langchain_core.callbacks")
        sys.modules["langchain_core.callbacks"] = None  # type: ignore[assignment]

        try:
            with pytest.raises(ImportError, match="langchain-core"):
                EnforceCoreStreamingCallback(policy=_policy("allow_all"))
        finally:
            # Restore
            if original is None:
                del sys.modules["langchain_core"]
            else:
                sys.modules["langchain_core"] = original
            if original_cb is None:
                sys.modules.pop("langchain_core.callbacks", None)
            else:
                sys.modules["langchain_core.callbacks"] = original_cb

    def test_last_result_none_before_stream(self) -> None:
        """last_result is None before any stream has been processed."""
        # Mock langchain_core so the constructor succeeds
        fake_lc = ModuleType("langchain_core")
        fake_cb = ModuleType("langchain_core.callbacks")
        fake_cb.BaseCallbackHandler = object  # type: ignore[attr-defined]

        with patch.dict(
            sys.modules,
            {"langchain_core": fake_lc, "langchain_core.callbacks": fake_cb},
        ):
            callback = EnforceCoreStreamingCallback(policy=_policy("allow_all"))
            assert callback.last_result is None

    def test_on_llm_new_token_stream_yields_tokens(self) -> None:
        """on_llm_new_token_stream yields redacted tokens from the generator."""
        fake_lc = ModuleType("langchain_core")
        fake_cb = ModuleType("langchain_core.callbacks")
        fake_cb.BaseCallbackHandler = object  # type: ignore[attr-defined]

        async def run() -> str:
            parts: list[str] = []
            with patch.dict(
                sys.modules,
                {"langchain_core": fake_lc, "langchain_core.callbacks": fake_cb},
            ):
                callback = EnforceCoreStreamingCallback(
                    policy=_policy("allow_all"),
                    redact=True,
                )
            async for tok in callback.on_llm_new_token_stream(_gen("alice@example.com and hello")):
                parts.append(tok)
            return "".join(parts)

        output = asyncio.run(run())
        assert "alice@example.com" not in output
        assert "[EMAIL]" in output

    def test_last_result_set_after_stream(self) -> None:
        """last_result is populated after on_llm_new_token_stream completes."""
        fake_lc = ModuleType("langchain_core")
        fake_cb = ModuleType("langchain_core.callbacks")
        fake_cb.BaseCallbackHandler = object  # type: ignore[attr-defined]

        async def run() -> StreamEnforcementResult | None:
            with patch.dict(
                sys.modules,
                {"langchain_core": fake_lc, "langchain_core.callbacks": fake_cb},
            ):
                callback = EnforceCoreStreamingCallback(policy=_policy("allow_all"))
            async for _ in callback.on_llm_new_token_stream(_gen("hello world")):
                pass
            return callback.last_result

        result = asyncio.run(run())
        assert result is not None
        assert result.tool_name == "langchain_stream"

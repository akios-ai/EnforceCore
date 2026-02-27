# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Framework streaming adapters for LangChain, AutoGen, and LangGraph.

Provides thin wrappers that translate each framework's native streaming
interface into the ``stream_enforce()`` async context manager.

Supported frameworks
--------------------
LangChain
    :class:`EnforceCoreStreamingCallback` — a
    ``BaseCallbackHandler`` subclass.  Install via
    ``pip install langchain-core``.

AutoGen
    :func:`autogen_stream_enforce` — wraps a ``ConversableAgent``'s
    ``a_generate_reply`` stream.

LangGraph
    :func:`langgraph_stream_enforce` — wraps the ``astream`` iterator
    returned by a compiled graph.

All adapters are *optional* — they import framework code lazily so that
``import enforcecore`` never fails when the framework is absent.

Example (LangChain)::

    from enforcecore.streaming.adapters import EnforceCoreStreamingCallback
    from enforcecore import Policy

    policy = Policy.from_file("policies/production.yaml")
    callback = EnforceCoreStreamingCallback(policy=policy)
    llm = ChatOpenAI(streaming=True, callbacks=[callback])
    llm.invoke("Tell me a secret")

Example (LangGraph)::

    from enforcecore.streaming.adapters import langgraph_stream_enforce

    async with langgraph_stream_enforce(graph.astream(inputs), policy=policy) as safe:
        async for event in safe:
            print(event)

.. versionadded:: 1.11.0
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

from enforcecore.streaming.core import StreamEnforcementResult, stream_enforce

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, AsyncIterator

    from enforcecore.core.policy import Policy


# ---------------------------------------------------------------------------
# LangChain adapter
# ---------------------------------------------------------------------------


class EnforceCoreStreamingCallback:
    """LangChain ``BaseCallbackHandler`` that enforces policy on streaming tokens.

    Requires ``pip install langchain-core``.

    Args:
        policy: The :class:`~enforcecore.core.policy.Policy` to apply.
        tool_name: Logical name for this stream.  Default ``"langchain_stream"``.
        redact: Whether to enable PII redaction.  Default ``True``.
        redaction_strategy: Redaction strategy string.  Default ``"placeholder"``.
        lookahead: Lookahead window in characters.  Default 64.

    Raises:
        ImportError: If ``langchain-core`` is not installed.

    Example::

        callback = EnforceCoreStreamingCallback(policy=policy)
        llm = ChatOpenAI(streaming=True, callbacks=[callback])

    .. versionadded:: 1.11.0
    """

    def __init__(
        self,
        *,
        policy: Policy,
        tool_name: str = "langchain_stream",
        redact: bool = True,
        redaction_strategy: str = "placeholder",
        lookahead: int = 64,
    ) -> None:
        """Initialise the LangChain streaming callback.

        Args:
            policy: Policy to enforce.
            tool_name: Stream source identifier for audit records.
            redact: Enable PII redaction.
            redaction_strategy: One of ``"placeholder"``, ``"mask"``,
                ``"hash"``, or ``"remove"``.
            lookahead: Lookahead window size in characters.
        """
        try:
            from langchain_core.callbacks import BaseCallbackHandler  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "langchain-core is required for EnforceCoreStreamingCallback. "
                "Install it with: pip install langchain-core"
            ) from exc

        self._policy = policy
        self._tool_name = tool_name
        self._redact = redact
        self._redaction_strategy = redaction_strategy
        self._lookahead = lookahead
        self._last_result: StreamEnforcementResult | None = None

    @property
    def last_result(self) -> StreamEnforcementResult | None:
        """The :class:`StreamEnforcementResult` from the most recent stream."""
        return self._last_result

    async def on_llm_new_token_stream(
        self,
        token_generator: AsyncGenerator[str, None],
    ) -> AsyncGenerator[str, None]:
        """Wrap *token_generator* with ``stream_enforce``.

        This is the primary integration point.  Pass the LLM's token
        generator through this method to get a policy-enforced generator.

        Args:
            token_generator: The LLM's async token stream.

        Yields:
            Redacted, policy-compliant tokens.
        """
        result_out: list[StreamEnforcementResult] = []
        async with stream_enforce(
            token_generator,
            policy=self._policy,
            tool_name=self._tool_name,
            redact=self._redact,
            redaction_strategy=self._redaction_strategy,
            lookahead=self._lookahead,
            result_out=result_out,
        ) as safe:
            async for token in safe:
                yield token
        if result_out:
            self._last_result = result_out[0]


# ---------------------------------------------------------------------------
# AutoGen adapter
# ---------------------------------------------------------------------------


async def autogen_stream_enforce(
    token_stream: AsyncGenerator[str, None],
    *,
    policy: Policy,
    tool_name: str = "autogen_stream",
    redact: bool = True,
    redaction_strategy: str = "placeholder",
    lookahead: int = 64,
    result_out: list[StreamEnforcementResult] | None = None,
) -> AsyncGenerator[str, None]:
    """Wrap an AutoGen agent token stream with ``stream_enforce``.

    Use this function inside an AutoGen streaming reply hook to enforce
    policy on tokens as they are generated.

    Args:
        token_stream: The ``AsyncGenerator[str, None]`` from AutoGen's
            streaming interface (e.g. ``agent.a_generate_reply`` stream).
        policy: The :class:`~enforcecore.core.policy.Policy` to apply.
        tool_name: Stream source identifier.  Default ``"autogen_stream"``.
        redact: Enable PII redaction.  Default ``True``.
        redaction_strategy: Redaction strategy.  Default ``"placeholder"``.
        lookahead: Lookahead window in characters.  Default 64.
        result_out: Optional list; :class:`StreamEnforcementResult` appended
            here after the stream completes.

    Yields:
        Redacted, policy-compliant tokens.

    Example::

        safe_stream = autogen_stream_enforce(agent_stream, policy=policy)
        async for token in await safe_stream:
            print(token, end="")

    .. versionadded:: 1.11.0
    """
    async with stream_enforce(
        token_stream,
        policy=policy,
        tool_name=tool_name,
        redact=redact,
        redaction_strategy=redaction_strategy,
        lookahead=lookahead,
        result_out=result_out,
    ) as safe:
        async for token in safe:
            yield token


# ---------------------------------------------------------------------------
# LangGraph adapter
# ---------------------------------------------------------------------------


@asynccontextmanager
async def langgraph_stream_enforce(
    graph_stream: AsyncIterator[Any],
    *,
    policy: Policy,
    token_extractor: Any | None = None,
    tool_name: str = "langgraph_stream",
    redact: bool = True,
    redaction_strategy: str = "placeholder",
    lookahead: int = 64,
    result_out: list[StreamEnforcementResult] | None = None,
) -> AsyncGenerator[AsyncIterator[Any], None]:
    """Async context manager for LangGraph ``graph.astream()`` enforcement.

    LangGraph streams events (dicts or typed objects) rather than raw
    strings.  This adapter extracts the text content from each event,
    enforces policy on it, and re-wraps it before yielding.

    Args:
        graph_stream: The async iterator from ``graph.astream(inputs)``.
        policy: The :class:`~enforcecore.core.policy.Policy` to apply.
        token_extractor: Optional callable ``(event: Any) -> str | None``
            that extracts a string token from a graph event.  If ``None``,
            string events are used as-is; non-string events are yielded
            unchanged.
        tool_name: Stream source identifier.  Default ``"langgraph_stream"``.
        redact: Enable PII redaction.  Default ``True``.
        redaction_strategy: Redaction strategy.  Default ``"placeholder"``.
        lookahead: Lookahead window in characters.  Default 64.
        result_out: Optional list; :class:`StreamEnforcementResult` appended
            here after the stream completes.

    Yields:
        An async iterator of events with string tokens redacted.

    Example::

        async with langgraph_stream_enforce(
            graph.astream(inputs), policy=policy
        ) as safe_events:
            async for event in safe_events:
                print(event)

    .. versionadded:: 1.11.0
    """
    from enforcecore.streaming.redactor import StreamingRedactor

    sr = (
        StreamingRedactor(
            strategy=redaction_strategy,  # type: ignore[arg-type]
            lookahead=lookahead,
        )
        if redact
        else None
    )

    collected_result: list[StreamEnforcementResult] = []

    async def _enforced_events() -> AsyncIterator[Any]:
        async for event in graph_stream:
            if sr is None:
                yield event
                continue

            # Extract text from event
            if token_extractor is not None:
                text = token_extractor(event)
            elif isinstance(event, str):
                text = event
            else:
                yield event
                continue

            if text is None:
                yield event
                continue

            safe, _ = sr.push(text)
            yield safe

        # Flush remaining buffer
        if sr is not None:
            remainder, _ = sr.flush()
            if remainder:
                yield remainder

        # Build result
        result = StreamEnforcementResult(
            policy_name=getattr(policy, "name", ""),
            tool_name=tool_name,
            total_redactions=sr.redaction_count if sr else 0,
        )
        collected_result.append(result)
        if result_out is not None:
            result_out.append(result)

    try:
        yield _enforced_events()
    finally:
        pass

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""AsyncIO streaming enforcement for token-by-token LLM output protection.

This module provides token-by-token enforcement for streaming LLM outputs —
the dominant consumption pattern for production AI agents.  Unlike the standard
``@enforce()`` decorator which operates on complete strings, the streaming layer
enforces policy *as tokens arrive*, with zero full-response buffering.

Core API::

    from enforcecore import stream_enforce

    async def demo(policy: Policy) -> None:
        async def my_stream() -> AsyncGenerator[str, None]:
            for token in ["Hello ", "john", "@gmail.com", "!]:
                yield token

        async with stream_enforce(my_stream(), policy=policy) as stream:
            async for token in stream:
                print(token, end="", flush=True)
        # PII ("john@gmail.com") redacted in-place as tokens arrived.

Public symbols (re-exported from enforcecore top level):
    stream_enforce          Async context manager — wraps any AsyncGenerator
    StreamAuditEntry        Audit record for one complete stream
    StreamEnforcementResult Summary dataclass returned after stream completes
    StreamingRedactor       Stateful window-based PII redactor

See Also:
    enforcecore.streaming.adapters — LangChain / AutoGen / LangGraph adapters
"""

from enforcecore.streaming.core import (
    StreamAuditEntry,
    StreamEnforcementResult,
    StreamingViolation,
    stream_enforce,
)
from enforcecore.streaming.redactor import StreamingRedactor

__all__ = [
    "StreamAuditEntry",
    "StreamEnforcementResult",
    "StreamingRedactor",
    "StreamingViolation",
    "stream_enforce",
]

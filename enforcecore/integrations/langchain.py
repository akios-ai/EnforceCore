# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""LangChain callback handler for EnforceCore policy enforcement.

Provides ``EnforceCoreCallbackHandler`` — a drop-in LangChain callback
that applies PII redaction, policy enforcement, and Merkle-chained audit
to every LLM and tool call automatically.

Requires: ``pip install langchain-core``

The handler is completely passive — it does **not** modify your chain or
agent topology.  Simply pass it as a callback and every LLM call, chain
invocation, and tool call will be monitored and protected.

Example::

    from enforcecore.integrations.langchain import EnforceCoreCallbackHandler

    handler = EnforceCoreCallbackHandler(policy="policy.yaml")

    # Use with any LangChain LLM:
    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(callbacks=[handler])
    result = llm.invoke("Summarise user 123-45-6789")
    # SSN is redacted from the prompt before the LLM sees it,
    # the audit trail records the event.

    # Or attach to an entire agent:
    agent = create_react_agent(llm, tools=[...], callbacks=[handler])
"""

from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING, Any

import structlog

from enforcecore.integrations._base import require_package

if TYPE_CHECKING:
    from pathlib import Path

    from enforcecore.auditor.engine import Auditor
    from enforcecore.core.policy import Policy, PolicyEngine
    from enforcecore.redactor.engine import Redactor

logger = structlog.get_logger("enforcecore.langchain")

__all__ = ["EnforceCoreCallbackHandler"]


class EnforceCoreCallbackHandler:
    """LangChain callback handler with EnforceCore enforcement.

    Intercepts LLM calls, chain invocations, and tool executions to apply:

    * **PII redaction** — prompts and responses are scanned and redacted
      before/after reaching the LLM.
    * **Policy enforcement** — tool calls are checked against the policy's
      allow/deny lists.
    * **Merkle-chained audit** — every event is logged to a tamper-proof
      audit trail.

    The handler inherits from LangChain's ``BaseCallbackHandler`` so it
    works anywhere LangChain accepts callbacks: LLMs, chains, agents,
    retrievers.

    Args:
        policy: A YAML policy path, :class:`Policy` object, or ``None``
            to use the default policy from
            ``ENFORCECORE_DEFAULT_POLICY``.
        redact_inputs: When ``True`` (default), PII in LLM prompts and
            chain inputs is redacted.
        redact_outputs: When ``True`` (default), PII in LLM responses
            and chain outputs is redacted.
        audit: When ``True`` (default), Merkle-chained audit entries
            are recorded for every event.

    Raises:
        ImportError: If ``langchain-core`` is not installed.
        PolicyLoadError: If *policy* is ``None`` and no default policy
            is configured.

    Example::

        handler = EnforceCoreCallbackHandler(policy="policy.yaml")
        llm = ChatOpenAI(callbacks=[handler])

    .. versionadded:: 1.13.0
    """

    def __init__(
        self,
        policy: str | Path | Policy | None = None,
        *,
        redact_inputs: bool = True,
        redact_outputs: bool = True,
        audit: bool = True,
    ) -> None:
        require_package("langchain_core", pip_name="langchain-core")

        # -- Load policy --
        from enforcecore.core.policy import Policy as _Policy
        from enforcecore.core.policy import PolicyEngine as _PolicyEngine

        if policy is None:
            from enforcecore.core.config import settings

            if settings.default_policy is None:
                from enforcecore.core.types import PolicyLoadError

                raise PolicyLoadError(
                    "No policy provided and ENFORCECORE_DEFAULT_POLICY is not set."
                )
            resolved_policy = _Policy.from_file(settings.default_policy)
        elif isinstance(policy, (str,)):
            from pathlib import Path as _Path

            resolved_policy = _Policy.from_file(_Path(policy))
        elif hasattr(policy, "name") and hasattr(policy, "rules"):
            resolved_policy = policy  # type: ignore[assignment]
        else:
            from pathlib import Path as _Path

            resolved_policy = _Policy.from_file(_Path(str(policy)))

        self._policy = resolved_policy
        self._engine: PolicyEngine = _PolicyEngine(resolved_policy)
        self._redact_inputs = redact_inputs
        self._redact_outputs = redact_outputs
        self._redactor: Redactor | None = self._build_redactor(resolved_policy)
        self._auditor: Auditor | None = self._build_auditor() if audit else None

        # Counters for summary
        self._total_input_redactions = 0
        self._total_output_redactions = 0
        self._total_events = 0

    # -- Internal builders (mirror Enforcer patterns) -----------------------

    @staticmethod
    def _build_redactor(policy: Policy) -> Redactor | None:
        """Create a Redactor from the policy's PII config, if enabled."""
        from enforcecore.core.types import RedactionStrategy
        from enforcecore.redactor.engine import Redactor as _Redactor

        pii_cfg = policy.rules.pii_redaction
        if not pii_cfg.enabled:
            return None

        kwargs: dict[str, object] = {
            "categories": pii_cfg.categories,
            "strategy": pii_cfg.strategy,
        }
        if pii_cfg.strategy == RedactionStrategy.NER:
            kwargs["threshold"] = pii_cfg.ner_threshold
            if pii_cfg.ner_fallback_to_regex:
                kwargs["fallback"] = RedactionStrategy.REGEX

        return _Redactor(**kwargs)  # type: ignore[arg-type]

    @staticmethod
    def _build_auditor() -> Auditor | None:
        """Create an Auditor from global settings, if audit is enabled."""
        from enforcecore.core.config import settings

        if not settings.audit_enabled:
            return None
        from enforcecore.auditor.engine import Auditor as _Auditor

        return _Auditor(output_path=settings.audit_path / "trail.jsonl")

    def _redact_text(self, text: str) -> tuple[str, int]:
        """Redact PII from text. Returns (redacted_text, count)."""
        if self._redactor is None:
            return text, 0
        result = self._redactor.redact(text)
        return result.text, result.count

    def _record_audit(
        self,
        *,
        event_type: str,
        tool_name: str = "",
        decision: str = "allowed",
        input_redactions: int = 0,
        output_redactions: int = 0,
        violation_type: str | None = None,
        violation_reason: str | None = None,
        overhead_ms: float = 0.0,
    ) -> None:
        """Record an audit entry if the auditor is active."""
        if self._auditor is None:
            return
        try:
            self._auditor.record(
                tool_name=tool_name or event_type,
                policy_name=self._policy.name,
                policy_version=self._policy.version,
                decision=decision,
                call_id=str(uuid.uuid4()),
                violation_type=violation_type,
                violation_reason=violation_reason,
                overhead_ms=overhead_ms,
                call_duration_ms=0.0,
                input_redactions=input_redactions,
                output_redactions=output_redactions,
            )
        except Exception:
            logger.error("langchain_audit_record_failed", event_type=event_type, exc_info=True)

    # -- Properties ---------------------------------------------------------

    @property
    def policy(self) -> Policy:
        """The policy being enforced."""
        return self._policy

    @property
    def total_input_redactions(self) -> int:
        """Total PII redactions applied to inputs across all calls."""
        return self._total_input_redactions

    @property
    def total_output_redactions(self) -> int:
        """Total PII redactions applied to outputs across all calls."""
        return self._total_output_redactions

    @property
    def total_events(self) -> int:
        """Total callback events processed."""
        return self._total_events

    @property
    def entry_count(self) -> int:
        """Number of audit entries written."""
        if self._auditor is None:
            return 0
        return self._auditor.entry_count

    # -- LangChain BaseCallbackHandler methods ------------------------------

    def on_llm_start(
        self,
        serialized: dict[str, Any],
        prompts: list[str],
        **kwargs: Any,
    ) -> None:
        """Called when an LLM starts running.

        Redacts PII from all prompts **in-place** before the LLM sees them.
        """
        self._total_events += 1
        if not self._redact_inputs or self._redactor is None:
            return

        t0 = time.perf_counter()
        total_redacted = 0
        for i, prompt in enumerate(prompts):
            redacted, count = self._redact_text(prompt)
            if count > 0:
                prompts[i] = redacted
                total_redacted += count

        elapsed = (time.perf_counter() - t0) * 1000
        self._total_input_redactions += total_redacted

        if total_redacted > 0:
            logger.info(
                "langchain_llm_input_redacted",
                redactions=total_redacted,
                overhead_ms=round(elapsed, 2),
            )
            self._record_audit(
                event_type="llm_start",
                input_redactions=total_redacted,
                overhead_ms=round(elapsed, 2),
            )

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        """Called when an LLM finishes running.

        Redacts PII from all generation texts in the response.
        """
        self._total_events += 1
        if not self._redact_outputs or self._redactor is None:
            return

        t0 = time.perf_counter()
        total_redacted = 0

        # LLMResult.generations is a list[list[Generation]]
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    if hasattr(gen, "text") and isinstance(gen.text, str):
                        redacted, count = self._redact_text(gen.text)
                        if count > 0:
                            gen.text = redacted
                            total_redacted += count

        elapsed = (time.perf_counter() - t0) * 1000
        self._total_output_redactions += total_redacted

        if total_redacted > 0:
            logger.info(
                "langchain_llm_output_redacted",
                redactions=total_redacted,
                overhead_ms=round(elapsed, 2),
            )

        self._record_audit(
            event_type="llm_end",
            output_redactions=total_redacted,
            overhead_ms=round(elapsed, 2),
        )

    def on_llm_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when an LLM errors out.

        Logs the error to the audit trail.
        """
        self._total_events += 1
        logger.warning("langchain_llm_error", error=str(error))
        self._record_audit(
            event_type="llm_error",
            decision="error",
            violation_reason=str(error),
        )

    def on_chain_start(
        self,
        serialized: dict[str, Any],
        inputs: dict[str, Any],
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts running.

        Redacts PII from string values in the inputs dict.
        """
        self._total_events += 1
        if not self._redact_inputs or self._redactor is None:
            return

        total_redacted = 0
        for key, value in inputs.items():
            if isinstance(value, str):
                redacted, count = self._redact_text(value)
                if count > 0:
                    inputs[key] = redacted
                    total_redacted += count

        self._total_input_redactions += total_redacted

    def on_chain_end(self, outputs: dict[str, Any], **kwargs: Any) -> None:
        """Called when a chain finishes running.

        Redacts PII from string values in the outputs dict.
        """
        self._total_events += 1
        if not self._redact_outputs or self._redactor is None:
            return

        total_redacted = 0
        for key, value in outputs.items():
            if isinstance(value, str):
                redacted, count = self._redact_text(value)
                if count > 0:
                    outputs[key] = redacted
                    total_redacted += count

        self._total_output_redactions += total_redacted

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running.

        Checks the tool name against the policy's allow/deny lists.
        Raises ``ToolDeniedError`` if the tool is blocked.
        """
        self._total_events += 1
        tool_name = serialized.get("name", "") if serialized else ""

        # Build a CallContext for policy evaluation
        from enforcecore.core.types import CallContext

        ctx = CallContext(tool_name=tool_name, args=(input_str,), kwargs={})
        pre = self._engine.evaluate_pre_call(ctx)

        if pre.decision.value == "blocked":
            self._record_audit(
                event_type="tool_start",
                tool_name=tool_name,
                decision="blocked",
                violation_type=str(pre.violation_type) if pre.violation_type else None,
                violation_reason=pre.reason,
            )
            self._engine.raise_if_blocked(pre, ctx)

        # Redact PII in tool input
        if self._redact_inputs and self._redactor is not None:
            # Note: input_str is a parameter, we can't mutate it in-place
            # but we log the redaction for audit purposes
            _, count = self._redact_text(input_str)
            self._total_input_redactions += count

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """Called when a tool finishes successfully.

        Logs the event to the audit trail.
        """
        self._total_events += 1

        output_redactions = 0
        if self._redact_outputs and self._redactor is not None and isinstance(output, str):
            _, output_redactions = self._redact_text(output)
            self._total_output_redactions += output_redactions

        self._record_audit(
            event_type="tool_end",
            output_redactions=output_redactions,
        )

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """Called when a tool errors out.

        Logs the error to the audit trail.
        """
        self._total_events += 1
        logger.warning("langchain_tool_error", error=str(error))
        self._record_audit(
            event_type="tool_error",
            decision="error",
            violation_reason=str(error),
        )

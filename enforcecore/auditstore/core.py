"""
Core abstractions for audit storage.

AuditEntry: Immutable audit log entry
AuditStore: Main facade for audit storage with backend abstraction
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .backends.base import AuditBackend


@dataclass
class AuditEntry:
    """Immutable audit log entry."""

    entry_id: str
    timestamp: datetime
    policy_name: str
    policy_version: str
    tool_name: str
    decision: str  # "allowed" | "blocked" | "redacted"

    # Call metadata
    call_duration_ms: float
    enforcement_overhead_ms: float

    # PII & redaction
    input_redactions: int
    output_redactions: int
    redacted_categories: list[str] = field(default_factory=list)

    # Cost tracking
    cost_usd: float | None = None
    tokens_used: int | None = None

    # Violation details (if blocked)
    violation_type: str | None = None
    violation_reason: str | None = None

    # Merkle chain (set by backend)
    merkle_hash: str | None = None
    parent_hash: str | None = None
    chain_index: int | None = None

    # Additional metadata
    context: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        policy_name: str,
        policy_version: str,
        tool_name: str,
        decision: str,
        call_duration_ms: float,
        enforcement_overhead_ms: float,
        input_redactions: int = 0,
        output_redactions: int = 0,
        **kwargs: Any,
    ) -> AuditEntry:
        """Create new audit entry with auto-generated ID."""
        return cls(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.now(tz=UTC),
            policy_name=policy_name,
            policy_version=policy_version,
            tool_name=tool_name,
            decision=decision,
            call_duration_ms=call_duration_ms,
            enforcement_overhead_ms=enforcement_overhead_ms,
            input_redactions=input_redactions,
            output_redactions=output_redactions,
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to serializable dict."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "tool_name": self.tool_name,
            "decision": self.decision,
            "call_duration_ms": self.call_duration_ms,
            "enforcement_overhead_ms": self.enforcement_overhead_ms,
            "input_redactions": self.input_redactions,
            "output_redactions": self.output_redactions,
            "redacted_categories": self.redacted_categories,
            "cost_usd": self.cost_usd,
            "tokens_used": self.tokens_used,
            "violation_type": self.violation_type,
            "violation_reason": self.violation_reason,
            "merkle_hash": self.merkle_hash,
            "parent_hash": self.parent_hash,
            "chain_index": self.chain_index,
            "context": self.context,
        }


class AuditStore:
    """Main interface for audit storage with backend abstraction."""

    def __init__(self, backend: AuditBackend, verify_on_read: bool = True) -> None:
        """Initialize audit store with backend."""
        self.backend = backend
        self.verify_on_read = verify_on_read

    def record(
        self,
        *,
        external_hash: str | None = None,
        external_prev_hash: str | None = None,
        **kwargs: Any,
    ) -> AuditEntry:
        """Record an enforced call.

        Args:
            external_hash: Pre-computed Merkle hash from an external system
                (e.g. AKIOS). When provided, the backend stores this hash
                AS-IS instead of computing its own.  This enables consumers
                with a different hashing scheme to use EnforceCore backends
                for storage while preserving their own chain integrity.
            external_prev_hash: Pre-computed previous/parent hash from the
                external system.  Must be provided together with
                ``external_hash``.
            **kwargs: Fields forwarded to :meth:`AuditEntry.create`.

        Returns:
            The recorded ``AuditEntry`` with Merkle fields populated.

        .. versionchanged:: 1.12.0
           Added ``external_hash`` and ``external_prev_hash`` for
           cross-system Merkle bridge support.
        """
        entry = AuditEntry.create(**kwargs)

        # When an external hash is provided, set it on the entry BEFORE
        # handing to the backend so backends can detect the pre-set hash
        # and skip their own computation.
        if external_hash is not None:
            entry.merkle_hash = external_hash
            entry.parent_hash = external_prev_hash

        return self.backend.record(entry)

    def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Retrieve entry by ID with optional verification."""
        entry = self.backend.get_entry(entry_id)
        if entry and self.verify_on_read:
            self.verify_entry(entry)
        return entry

    def list_entries(
        self,
        policy_name: str | None = None,
        tool_name: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        decision: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """Query entries with flexible filters."""
        return self.backend.list_entries(
            policy_name=policy_name,
            tool_name=tool_name,
            start_time=start_time,
            end_time=end_time,
            decision=decision,
            limit=limit,
            offset=offset,
        )

    def verify_chain(
        self,
        start_index: int = 0,
        end_index: int | None = None,
        *,
        skip_entry_hash: bool = False,
    ) -> bool:
        """Verify Merkle chain integrity.

        Args:
            start_index: First chain index to verify.
            end_index: Last chain index to verify (inclusive).
            skip_entry_hash: When ``True``, only verify chain linkage
                (``parent_hash`` → previous ``merkle_hash``) without
                recomputing individual entry hashes.  Useful when entries
                were recorded with ``external_hash`` from a system that
                uses a different hashing scheme.

        Returns:
            ``True`` if the chain (or linkage) is valid.

        .. versionchanged:: 1.12.0
           Added ``skip_entry_hash`` for external-hash verification.
        """
        return self.backend.verify_chain(
            start_index, end_index, skip_entry_hash=skip_entry_hash,
        )

    def verify_entry(self, entry: AuditEntry) -> bool:
        """Verify single entry's Merkle hash."""
        # Delegates to backend for verification logic
        return self.backend.verify_entry(entry)

    def export(self, format: str = "jsonl") -> str:
        """Export entries for backup/migration."""
        return self.backend.export(format)

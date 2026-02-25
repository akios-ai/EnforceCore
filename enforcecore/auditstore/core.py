"""
Core abstractions for audit storage.

AuditEntry: Immutable audit log entry
AuditStore: Main facade for audit storage with backend abstraction
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

import uuid

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
        **kwargs,
    ) -> AuditEntry:
        """Create new audit entry with auto-generated ID."""
        return cls(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
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

    def record(self, **kwargs) -> AuditEntry:
        """Record an enforced call."""
        entry = AuditEntry.create(**kwargs)
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
        self, start_index: int = 0, end_index: int | None = None
    ) -> bool:
        """Verify Merkle chain integrity."""
        return self.backend.verify_chain(start_index, end_index)

    def verify_entry(self, entry: AuditEntry) -> bool:
        """Verify single entry's Merkle hash."""
        # Delegates to backend for verification logic
        return self.backend.verify_entry(entry)

    def export(self, format: str = "jsonl") -> str:
        """Export entries for backup/migration."""
        return self.backend.export(format)

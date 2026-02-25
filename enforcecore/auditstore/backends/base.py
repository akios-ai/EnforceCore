"""Abstract backend interface for audit storage."""

from abc import ABC, abstractmethod
from datetime import datetime

from ..core import AuditEntry


class AuditBackend(ABC):
    """Abstract interface for audit storage backends."""

    @abstractmethod
    def record(self, entry: AuditEntry) -> AuditEntry:
        """Record an audit entry, return with merkle hash set."""
        pass

    @abstractmethod
    def get_entry(self, entry_id: str) -> AuditEntry | None:
        """Retrieve single entry by ID."""
        pass

    @abstractmethod
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
        """Query entries with filters."""
        pass

    @abstractmethod
    def get_chain_tail(self) -> AuditEntry | None:
        """Get last entry in Merkle chain."""
        pass

    @abstractmethod
    def verify_chain(
        self,
        start_index: int = 0,
        end_index: int | None = None,
    ) -> bool:
        """Verify Merkle chain integrity in range."""
        pass

    @abstractmethod
    def verify_entry(self, entry: AuditEntry) -> bool:
        """Verify single entry's Merkle hash."""
        pass

    @abstractmethod
    def export(self, format: str = "jsonl") -> str:
        """Export all entries (for backup/migration)."""
        pass

    def _compute_merkle_hash(self, entry: AuditEntry, parent_hash: str | None = None) -> str:
        """Compute Merkle hash for entry.

        This is a helper that backends should use consistently.
        """
        import hashlib
        import json

        data = {
            "entry_id": entry.entry_id,
            "timestamp": entry.timestamp.isoformat(),
            "policy_name": entry.policy_name,
            "tool_name": entry.tool_name,
            "decision": entry.decision,
            "violation_type": entry.violation_type,
            "parent_hash": parent_hash or "0" * 64,  # Genesis hash
        }

        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

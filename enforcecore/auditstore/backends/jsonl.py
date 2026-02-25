"""JSONL file backend for audit storage (existing implementation)."""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..core import AuditEntry
from .base import AuditBackend


class JSONLBackend(AuditBackend):
    """JSONL file backend - compatible with existing Auditor implementation."""

    def __init__(self, path: str = "audit_logs/trail.jsonl"):
        """Initialize JSONL backend."""
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, entry: AuditEntry) -> AuditEntry:
        """Write entry to JSONL file with Merkle hash."""
        # Get previous entry for Merkle chaining
        last_entry = self.get_chain_tail()

        # Compute Merkle hash
        parent_hash = last_entry.merkle_hash if last_entry else None
        entry.merkle_hash = self._compute_merkle_hash(entry, parent_hash)
        entry.parent_hash = parent_hash
        entry.chain_index = (last_entry.chain_index + 1) if last_entry else 0

        # Append to file
        with open(self.path, "a") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        return entry

    def get_entry(self, entry_id: str) -> Optional[AuditEntry]:
        """Retrieve entry by ID from JSONL file."""
        if not self.path.exists():
            return None

        with open(self.path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("entry_id") == entry_id:
                    return self._dict_to_entry(data)

        return None

    def list_entries(
        self,
        policy_name: Optional[str] = None,
        tool_name: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        decision: Optional[str] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """Query entries from JSONL file."""
        if not self.path.exists():
            return []

        entries = []
        with open(self.path, "r") as f:
            for line in f:
                if not line.strip():
                    continue
                data = json.loads(line)

                # Apply filters
                if policy_name and data.get("policy_name") != policy_name:
                    continue
                if tool_name and data.get("tool_name") != tool_name:
                    continue
                if decision and data.get("decision") != decision:
                    continue

                if start_time or end_time:
                    ts = datetime.fromisoformat(data.get("timestamp", ""))
                    if start_time and ts < start_time:
                        continue
                    if end_time and ts > end_time:
                        continue

                entries.append(self._dict_to_entry(data))

        # Sort by timestamp descending, apply pagination
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[offset : offset + limit]

    def get_chain_tail(self) -> Optional[AuditEntry]:
        """Get last entry in file (chain tail)."""
        if not self.path.exists():
            return None

        last_entry = None
        with open(self.path, "r") as f:
            for line in f:
                if line.strip():
                    last_entry = json.loads(line)

        return self._dict_to_entry(last_entry) if last_entry else None

    def verify_chain(
        self,
        start_index: int = 0,
        end_index: Optional[int] = None,
    ) -> bool:
        """Verify Merkle chain integrity."""
        if not self.path.exists():
            return True

        entries = []
        with open(self.path, "r") as f:
            for line in f:
                if line.strip():
                    entries.append(self._dict_to_entry(json.loads(line)))

        if not entries:
            return True

        if end_index is None:
            end_index = len(entries) - 1

        for i in range(max(0, start_index), min(end_index + 1, len(entries))):
            entry = entries[i]
            parent_hash = entries[i - 1].merkle_hash if i > 0 else None
            expected_hash = self._compute_merkle_hash(entry, parent_hash)

            if entry.merkle_hash != expected_hash:
                return False

        return True

    def verify_entry(self, entry: AuditEntry) -> bool:
        """Verify single entry's Merkle hash."""
        stored = self.get_entry(entry.entry_id)
        if not stored:
            return False

        # Re-compute hash with parent
        expected_hash = self._compute_merkle_hash(entry, entry.parent_hash)
        return entry.merkle_hash == expected_hash

    def export(self, format: str = "jsonl") -> str:
        """Export entries."""
        if not self.path.exists():
            return ""

        if format == "jsonl":
            with open(self.path, "r") as f:
                return f.read()

        raise ValueError(f"Unsupported export format: {format}")

    def _dict_to_entry(self, data: dict) -> AuditEntry:
        """Convert dict to AuditEntry."""
        return AuditEntry(
            entry_id=data.get("entry_id", ""),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.utcnow().isoformat())),
            policy_name=data.get("policy_name", ""),
            policy_version=data.get("policy_version", ""),
            tool_name=data.get("tool_name", ""),
            decision=data.get("decision", ""),
            call_duration_ms=data.get("call_duration_ms", 0.0),
            enforcement_overhead_ms=data.get("enforcement_overhead_ms", 0.0),
            input_redactions=data.get("input_redactions", 0),
            output_redactions=data.get("output_redactions", 0),
            redacted_categories=data.get("redacted_categories", []),
            cost_usd=data.get("cost_usd"),
            tokens_used=data.get("tokens_used"),
            violation_type=data.get("violation_type"),
            violation_reason=data.get("violation_reason"),
            merkle_hash=data.get("merkle_hash"),
            parent_hash=data.get("parent_hash"),
            chain_index=data.get("chain_index"),
            context=data.get("context", {}),
        )

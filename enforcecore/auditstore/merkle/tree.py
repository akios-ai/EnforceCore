"""Merkle tree implementation for audit trail verification."""

import hashlib
import json
from typing import Any, Dict, List, Optional

from ..core import AuditEntry


class MerkleTree:
    """Merkle tree for audit trail verification and tamper-evidence."""

    @staticmethod
    def compute_hash(entry: AuditEntry, parent_hash: Optional[str] = None) -> str:
        """Compute Merkle hash for an entry.

        This creates a SHA256 hash of the entry data combined with parent hash,
        creating a chain where any modification breaks the chain.
        """
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

    @staticmethod
    def verify_chain(entries: List[AuditEntry]) -> bool:
        """Verify entire chain integrity.

        Returns True if all entries form a valid Merkle chain.
        """
        for i, entry in enumerate(entries):
            parent_hash = entries[i - 1].merkle_hash if i > 0 else None
            expected_hash = MerkleTree.compute_hash(entry, parent_hash)

            if entry.merkle_hash != expected_hash:
                return False

        return True

    @staticmethod
    def verify_entry(entry: AuditEntry, prev_entry: Optional[AuditEntry] = None) -> bool:
        """Verify single entry's Merkle hash.

        Args:
            entry: Entry to verify
            prev_entry: Optional previous entry in chain (for validation)
        """
        parent_hash = prev_entry.merkle_hash if prev_entry else None
        expected_hash = MerkleTree.compute_hash(entry, parent_hash)
        return entry.merkle_hash == expected_hash

    @staticmethod
    def generate_proof(entries: List[AuditEntry], target_index: int) -> Dict[str, Any]:
        """Generate proof that entry at target_index is in chain.

        This proves that the entry hasn't been tampered with and is part
        of the chain at the specified position.
        """
        if target_index >= len(entries):
            raise ValueError(
                f"Target index {target_index} out of bounds (chain length: {len(entries)})"
            )

        proof = {
            "target_index": target_index,
            "target_entry_id": entries[target_index].entry_id,
            "target_hash": entries[target_index].merkle_hash,
            "chain_length": len(entries),
            "path": [],  # Simplified — full chain is the proof in MVP
            "chain_valid": MerkleTree.verify_chain(entries),
        }

        return proof

    @staticmethod
    def detect_tampering(entries: List[AuditEntry], start_index: int = 0) -> Optional[int]:
        """Detect tampering by finding broken hash chain.

        Returns the index of the first tampered entry, or None if chain is valid.
        """
        for i in range(start_index, len(entries)):
            parent_hash = entries[i - 1].merkle_hash if i > 0 else None
            expected_hash = MerkleTree.compute_hash(entries[i], parent_hash)

            if entries[i].merkle_hash != expected_hash:
                return i

        return None

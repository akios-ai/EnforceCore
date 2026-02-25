"""SQLite backend for audit storage (local deployment)."""

import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from ..core import AuditEntry
from .base import AuditBackend


class SQLiteBackend(AuditBackend):
    """SQLite backend for local development and deployment."""

    def __init__(self, db_path: str = "audit.db", verify_merkle: bool = True):
        """Initialize SQLite backend."""
        self.db_path = Path(db_path)
        self.verify_merkle = verify_merkle
        self._init_schema()

    def _init_schema(self):
        """Create tables if not exists."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Main audit table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_entries (
                entry_id TEXT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                policy_name TEXT NOT NULL,
                policy_version TEXT,
                tool_name TEXT NOT NULL,
                decision TEXT NOT NULL,
                call_duration_ms REAL,
                enforcement_overhead_ms REAL,
                input_redactions INTEGER,
                output_redactions INTEGER,
                redacted_categories TEXT,
                cost_usd REAL,
                tokens_used INTEGER,
                violation_type TEXT,
                violation_reason TEXT,
                merkle_hash TEXT,
                parent_hash TEXT,
                chain_index INTEGER,
                context TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Merkle chain verification table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merkle_chain (
                chain_index INTEGER PRIMARY KEY,
                entry_id TEXT UNIQUE NOT NULL,
                merkle_hash TEXT NOT NULL,
                parent_hash TEXT,
                verified_at DATETIME,
                verification_passed BOOLEAN,
                FOREIGN KEY (entry_id) REFERENCES audit_entries(entry_id)
            )
        """)

        # Indices for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_entries(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_policy ON audit_entries(policy_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tool ON audit_entries(tool_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_decision ON audit_entries(decision)")

        conn.commit()
        conn.close()

    def record(self, entry: AuditEntry) -> AuditEntry:
        """Insert entry with Merkle chain."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Compute Merkle hash
        entry.merkle_hash = self._compute_merkle_hash(entry)
        last_entry = self.get_chain_tail()
        entry.parent_hash = last_entry.merkle_hash if last_entry else None
        entry.chain_index = (last_entry.chain_index + 1) if last_entry else 0

        # Insert entry
        cursor.execute(
            """
            INSERT INTO audit_entries VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                entry.entry_id,
                entry.timestamp.isoformat(),
                entry.policy_name,
                entry.policy_version,
                entry.tool_name,
                entry.decision,
                entry.call_duration_ms,
                entry.enforcement_overhead_ms,
                entry.input_redactions,
                entry.output_redactions,
                ",".join(entry.redacted_categories),
                entry.cost_usd,
                entry.tokens_used,
                entry.violation_type,
                entry.violation_reason,
                entry.merkle_hash,
                entry.parent_hash,
                entry.chain_index,
                str(entry.context),
            ),
        )

        # Record in Merkle chain table
        cursor.execute(
            """
            INSERT INTO merkle_chain (chain_index, entry_id, merkle_hash, parent_hash)
            VALUES (?, ?, ?, ?)
        """,
            (entry.chain_index, entry.entry_id, entry.merkle_hash, entry.parent_hash),
        )

        conn.commit()
        conn.close()
        return entry

    def get_entry(self, entry_id: str) -> Optional[AuditEntry]:
        """Retrieve entry by ID."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM audit_entries WHERE entry_id = ?", (entry_id,))
        row = cursor.fetchone()
        conn.close()

        return self._row_to_entry(row) if row else None

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
        """Query with flexible filters."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM audit_entries WHERE 1=1"
        params = []

        if policy_name:
            query += " AND policy_name = ?"
            params.append(policy_name)
        if tool_name:
            query += " AND tool_name = ?"
            params.append(tool_name)
        if decision:
            query += " AND decision = ?"
            params.append(decision)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time.isoformat())
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return [self._row_to_entry(row) for row in rows]

    def get_chain_tail(self) -> Optional[AuditEntry]:
        """Get last entry in chain."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM audit_entries ORDER BY chain_index DESC LIMIT 1")
        row = cursor.fetchone()
        conn.close()

        return self._row_to_entry(row) if row else None

    def verify_chain(self, start_index: int = 0, end_index: Optional[int] = None) -> bool:
        """Verify Merkle chain integrity."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT MAX(chain_index) FROM merkle_chain")
        max_index = cursor.fetchone()[0]

        if max_index is None:
            conn.close()
            return True

        if end_index is None:
            end_index = max_index

        for i in range(start_index, min(end_index + 1, max_index + 1)):
            cursor.execute(
                "SELECT entry_id, merkle_hash, parent_hash FROM merkle_chain WHERE chain_index = ?",
                (i,),
            )
            row = cursor.fetchone()

            if not row:
                conn.close()
                return False

            entry_id, merkle_hash, parent_hash = row

            # Verify hash matches entry
            entry = self.get_entry(entry_id)
            if not entry or entry.merkle_hash != merkle_hash:
                conn.close()
                return False

            # Verify parent hash matches previous entry
            if i > 0:
                cursor.execute(
                    "SELECT merkle_hash FROM merkle_chain WHERE chain_index = ?",
                    (i - 1,),
                )
                prev_row = cursor.fetchone()
                if not prev_row or prev_row[0] != parent_hash:
                    conn.close()
                    return False

        conn.close()
        return True

    def verify_entry(self, entry: AuditEntry) -> bool:
        """Verify single entry's Merkle hash."""
        stored = self.get_entry(entry.entry_id)
        if not stored:
            return False

        expected_hash = self._compute_merkle_hash(entry, entry.parent_hash)
        return entry.merkle_hash == expected_hash

    def export(self, format: str = "jsonl") -> str:
        """Export entries."""
        if format == "jsonl":
            import json

            entries = self.list_entries(limit=999999)
            return "\n".join(json.dumps(e.to_dict()) for e in entries)

        raise ValueError(f"Unsupported export format: {format}")

    def _row_to_entry(self, row: tuple) -> AuditEntry:
        """Convert SQL row to AuditEntry."""
        (
            entry_id,
            timestamp,
            policy_name,
            policy_version,
            tool_name,
            decision,
            call_duration_ms,
            enforcement_overhead_ms,
            input_redactions,
            output_redactions,
            redacted_categories,
            cost_usd,
            tokens_used,
            violation_type,
            violation_reason,
            merkle_hash,
            parent_hash,
            chain_index,
            context,
            _,
        ) = row

        return AuditEntry(
            entry_id=entry_id,
            timestamp=datetime.fromisoformat(timestamp),
            policy_name=policy_name,
            policy_version=policy_version or "",
            tool_name=tool_name,
            decision=decision,
            call_duration_ms=call_duration_ms or 0.0,
            enforcement_overhead_ms=enforcement_overhead_ms or 0.0,
            input_redactions=input_redactions or 0,
            output_redactions=output_redactions or 0,
            redacted_categories=(redacted_categories or "").split(",")
            if redacted_categories
            else [],
            cost_usd=cost_usd,
            tokens_used=tokens_used,
            violation_type=violation_type,
            violation_reason=violation_reason,
            merkle_hash=merkle_hash,
            parent_hash=parent_hash,
            chain_index=chain_index,
            context={},
        )

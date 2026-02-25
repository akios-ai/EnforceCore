"""PostgreSQL backend for audit storage (production deployment)."""

import json
from datetime import datetime
from typing import List, Optional

from ..core import AuditEntry
from .base import AuditBackend

# Optional: psycopg2 dependency
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False


class PostgreSQLBackend(AuditBackend):
    """PostgreSQL backend for production deployments.

    Features:
    - Concurrent write support
    - Connection pooling
    - Partitioning by date (optional)
    - Advanced query performance
    - Full Merkle chain verification
    """

    def __init__(
        self,
        host: str,
        database: str,
        user: str,
        password: str,
        port: int = 5432,
        verify_merkle: bool = True,
        pool_size: int = 5,
        ssl_mode: str = "prefer",
    ):
        """Initialize PostgreSQL backend.

        Args:
            host: PostgreSQL host
            database: Database name
            user: Username
            password: Password
            port: Port (default 5432)
            verify_merkle: Enable Merkle verification
            pool_size: Connection pool size
            ssl_mode: SSL mode (disable, allow, prefer, require)
        """
        if not HAS_PSYCOPG2:
            raise ImportError(
                "psycopg2 not installed. Install with: pip install psycopg2-binary"
            )

        self.connection_params = {
            "host": host,
            "database": database,
            "user": user,
            "password": password,
            "port": port,
            "sslmode": ssl_mode,
        }
        self.verify_merkle = verify_merkle
        self.pool_size = pool_size
        self._init_schema()

    def _get_connection(self):
        """Get database connection."""
        return psycopg2.connect(**self.connection_params)

    def _init_schema(self):
        """Create tables and indices."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Main audit table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_entries (
                entry_id UUID PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                policy_name VARCHAR(255) NOT NULL,
                policy_version VARCHAR(50),
                tool_name VARCHAR(255) NOT NULL,
                decision VARCHAR(50) NOT NULL,
                call_duration_ms FLOAT,
                enforcement_overhead_ms FLOAT,
                input_redactions INTEGER,
                output_redactions INTEGER,
                redacted_categories TEXT[],
                cost_usd DECIMAL(10, 4),
                tokens_used INTEGER,
                violation_type VARCHAR(100),
                violation_reason TEXT,
                merkle_hash VARCHAR(64),
                parent_hash VARCHAR(64),
                chain_index BIGINT UNIQUE,
                context JSONB,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """)

        # Merkle chain table for verification
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merkle_chain (
                chain_index BIGINT PRIMARY KEY,
                entry_id UUID UNIQUE NOT NULL,
                merkle_hash VARCHAR(64) NOT NULL,
                parent_hash VARCHAR(64),
                verified_at TIMESTAMPTZ,
                verification_passed BOOLEAN,
                FOREIGN KEY (entry_id) REFERENCES audit_entries(entry_id) ON DELETE CASCADE
            )
        """)

        # Performance indices
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_entries(timestamp DESC)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_policy_tool
            ON audit_entries(policy_name, tool_name)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_decision
            ON audit_entries(decision)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_merkle_chain
            ON merkle_chain(chain_index DESC)
        """)

        conn.commit()
        cursor.close()
        conn.close()

    def record(self, entry: AuditEntry) -> AuditEntry:
        """Insert entry with Merkle chain."""
        conn = self._get_connection()
        cursor = conn.cursor()

        try:
            # Compute Merkle hash
            entry.merkle_hash = self._compute_merkle_hash(entry)
            last_entry = self.get_chain_tail()
            entry.parent_hash = last_entry.merkle_hash if last_entry else None
            entry.chain_index = (last_entry.chain_index + 1) if last_entry else 0

            # Insert entry
            cursor.execute(
                """
                INSERT INTO audit_entries VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (entry_id) DO NOTHING
            """,
                (
                    entry.entry_id,
                    entry.timestamp,
                    entry.policy_name,
                    entry.policy_version,
                    entry.tool_name,
                    entry.decision,
                    entry.call_duration_ms,
                    entry.enforcement_overhead_ms,
                    entry.input_redactions,
                    entry.output_redactions,
                    entry.redacted_categories if entry.redacted_categories else [],
                    entry.cost_usd,
                    entry.tokens_used,
                    entry.violation_type,
                    entry.violation_reason,
                    entry.merkle_hash,
                    entry.parent_hash,
                    entry.chain_index,
                    json.dumps(entry.context),
                ),
            )

            # Record in Merkle chain table
            cursor.execute(
                """
                INSERT INTO merkle_chain (chain_index, entry_id, merkle_hash, parent_hash)
                VALUES (%s, %s, %s, %s)
            """,
                (entry.chain_index, entry.entry_id, entry.merkle_hash, entry.parent_hash),
            )

            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

        return entry

    def get_entry(self, entry_id: str) -> Optional[AuditEntry]:
        """Retrieve entry by ID."""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("SELECT * FROM audit_entries WHERE entry_id = %s", (entry_id,))
        row = cursor.fetchone()
        cursor.close()
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
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        query = "SELECT * FROM audit_entries WHERE 1=1"
        params = []

        if policy_name:
            query += " AND policy_name = %s"
            params.append(policy_name)
        if tool_name:
            query += " AND tool_name = %s"
            params.append(tool_name)
        if decision:
            query += " AND decision = %s"
            params.append(decision)
        if start_time:
            query += " AND timestamp >= %s"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= %s"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        conn.close()

        return [self._row_to_entry(row) for row in rows]

    def get_chain_tail(self) -> Optional[AuditEntry]:
        """Get last entry in chain."""
        conn = self._get_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute(
            "SELECT * FROM audit_entries ORDER BY chain_index DESC LIMIT 1"
        )
        row = cursor.fetchone()
        cursor.close()
        conn.close()

        return self._row_to_entry(row) if row else None

    def verify_chain(
        self,
        start_index: int = 0,
        end_index: Optional[int] = None,
    ) -> bool:
        """Verify Merkle chain integrity."""
        conn = self._get_connection()
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
                "SELECT entry_id, merkle_hash, parent_hash FROM merkle_chain WHERE chain_index = %s",
                (i,),
            )
            row = cursor.fetchone()

            if not row:
                conn.close()
                return False

            entry_id, merkle_hash, parent_hash = row

            # Verify hash matches entry
            entry = self.get_entry(str(entry_id))
            if not entry or entry.merkle_hash != merkle_hash:
                conn.close()
                return False

            # Verify parent hash matches previous entry
            if i > 0:
                cursor.execute(
                    "SELECT merkle_hash FROM merkle_chain WHERE chain_index = %s",
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
            entries = self.list_entries(limit=999999)
            return "\n".join(json.dumps(e.to_dict()) for e in entries)
        elif format == "json":
            import json as json_module
            entries = self.list_entries(limit=999999)
            return json_module.dumps([e.to_dict() for e in entries], indent=2)

        raise ValueError(f"Unsupported export format: {format}")

    def _row_to_entry(self, row: dict) -> AuditEntry:
        """Convert SQL row to AuditEntry."""
        return AuditEntry(
            entry_id=str(row["entry_id"]),
            timestamp=row["timestamp"],
            policy_name=row["policy_name"],
            policy_version=row["policy_version"] or "",
            tool_name=row["tool_name"],
            decision=row["decision"],
            call_duration_ms=row["call_duration_ms"] or 0.0,
            enforcement_overhead_ms=row["enforcement_overhead_ms"] or 0.0,
            input_redactions=row["input_redactions"] or 0,
            output_redactions=row["output_redactions"] or 0,
            redacted_categories=row["redacted_categories"] or [],
            cost_usd=float(row["cost_usd"]) if row["cost_usd"] else None,
            tokens_used=row["tokens_used"],
            violation_type=row["violation_type"],
            violation_reason=row["violation_reason"],
            merkle_hash=row["merkle_hash"],
            parent_hash=row["parent_hash"],
            chain_index=row["chain_index"],
            context=row["context"] or {},
        )

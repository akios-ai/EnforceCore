"""Adapters for integrating auditstore backends with Auditor.

This module provides bridge adapters that allow the new auditstore backends
to work seamlessly with the existing Auditor API. It maintains backward
compatibility while enabling PostgreSQL, SQLite, and other backends.

Example::

    from enforcecore.auditor import Auditor
    from enforcecore.auditstore.backends import PostgreSQLBackend
    from enforcecore.auditstore.adapters import AuditStoreBackendAdapter

    # Use PostgreSQL backend with Auditor
    auditstore_backend = PostgreSQLBackend(
        host="localhost",
        database="enforcecore",
        user="postgres",
    )
    adapter = AuditStoreBackendAdapter(auditstore_backend)
    auditor = Auditor(backend=adapter)

    # Use normally
    entry = auditor.record(
        tool_name="search",
        policy_name="strict",
        decision="allowed",
    )
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from enforcecore.auditor.backends import AuditBackend as AuditorBackend
from enforcecore.core.types import AuditError

logger = structlog.get_logger("enforcecore.auditstore.adapters")


class AuditStoreBackendAdapter(AuditorBackend):
    """Adapter that bridges auditstore backends to the Auditor API.

    Translates between Auditor's dict-based write interface and auditstore's
    AuditEntry-based interface. Enables using new backends (PostgreSQL, etc.)
    with existing Auditor code.

    This adapter:
    - Converts Auditor's dict format to auditstore.AuditEntry
    - Handles Merkle chain computation automatically
    - Maintains thread-safety
    - Provides transparent backend routing

    Example::

        backend = PostgreSQLBackend(host="localhost", database="enforcecore")
        adapter = AuditStoreBackendAdapter(backend)
        auditor = Auditor(backend=adapter)
        auditor.record(tool_name="search", policy_name="strict")
    """

    __slots__ = ("_auditstore_backend", "_entry_count", "_last_hash")

    def __init__(self, auditstore_backend: Any) -> None:
        """Initialize adapter with an auditstore backend.

        Args:
            auditstore_backend: An instance of AuditStore backend
                (PostgreSQLBackend, SQLiteBackend, JSONLBackend, etc.)
                Must implement the auditstore backend interface:
                - record(entry: AuditEntry) -> AuditEntry
                - get_entry(entry_id: str) -> Optional[AuditEntry]
                - close()
        """
        self._auditstore_backend = auditstore_backend
        self._last_hash = ""
        self._entry_count = 0

    def write(self, entry_dict: dict[str, Any]) -> None:
        """Write an entry via the auditstore backend.

        Args:
            entry_dict: Dictionary representation of an AuditEntry from Auditor.
                Expected fields: entry_id, timestamp, tool_name, policy_name,
                decision, previous_hash, entry_hash, etc.

        Raises:
            AuditError: If the write fails.
        """
        try:
            from enforcecore.auditstore.core import AuditEntry

            # Convert Auditor's dict to auditstore.AuditEntry
            # Auditor uses "overhead_ms" and "entry_hash", auditstore uses slightly different names
            timestamp_str = entry_dict.get("timestamp", "")
            if isinstance(timestamp_str, str):
                # Parse ISO format timestamp
                try:
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    timestamp = datetime.now(UTC)
            else:
                timestamp = datetime.now(UTC)

            entry = AuditEntry(
                entry_id=entry_dict.get("entry_id", ""),
                timestamp=timestamp,
                policy_name=entry_dict.get("policy_name", ""),
                policy_version=entry_dict.get("policy_version", ""),
                tool_name=entry_dict.get("tool_name", ""),
                decision=entry_dict.get("decision", "allowed"),
                call_duration_ms=entry_dict.get("call_duration_ms", 0.0),
                enforcement_overhead_ms=entry_dict.get("overhead_ms", 0.0),
                input_redactions=entry_dict.get("input_redactions", 0),
                output_redactions=entry_dict.get("output_redactions", 0),
                violation_type=entry_dict.get("violation_type"),
                violation_reason=entry_dict.get("violation_reason"),
                # Merkle fields from Auditor
                merkle_hash=entry_dict.get("entry_hash"),
                parent_hash=entry_dict.get("previous_hash"),
            )

            # Record to auditstore backend
            recorded_entry = self._auditstore_backend.record(entry)

            # Track state for potential resume operations
            self._last_hash = recorded_entry.merkle_hash or ""
            self._entry_count += 1

            logger.debug(
                "auditstore_adapter_write",
                entry_id=entry.entry_id,
                backend=type(self._auditstore_backend).__name__,
                chain_index=recorded_entry.chain_index,
            )

        except Exception as exc:
            msg = f"Failed to write audit entry via auditstore backend: {exc}"
            raise AuditError(msg) from exc

    def close(self) -> None:
        """Close the underlying auditstore backend."""
        try:
            if hasattr(self._auditstore_backend, "close"):
                self._auditstore_backend.close()
            logger.debug(
                "auditstore_adapter_closed",
                backend=type(self._auditstore_backend).__name__,
                entries_written=self._entry_count,
            )
        except Exception as exc:
            logger.warning(
                "auditstore_adapter_close_error",
                error=str(exc),
            )

    def __repr__(self) -> str:
        backend_name = type(self._auditstore_backend).__name__
        return f"AuditStoreBackendAdapter(backend={backend_name}, entries={self._entry_count})"

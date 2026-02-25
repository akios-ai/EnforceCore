"""
Pluggable audit storage system for EnforceCore.

Supports multiple backends (JSONL, SQLite, PostgreSQL) with:
- Merkle chain verification for tamper-evidence
- Compliance query templates (EU AI Act, HIPAA, SOX)
- Regulatory report generation

Usage:
    from enforcecore.auditstore import AuditStore
    from enforcecore.auditstore.backends import PostgreSQLBackend

    backend = PostgreSQLBackend(host="...", database="...")
    store = AuditStore(backend=backend)
    store.record(tool_name="search", decision="allowed", ...)
"""

from .core import AuditEntry, AuditStore
from .backends.base import AuditBackend
from .adapters import AuditStoreBackendAdapter

__version__ = "1.2.0"
__all__ = [
    "AuditEntry",
    "AuditStore",
    "AuditBackend",
    "AuditStoreBackendAdapter",
]

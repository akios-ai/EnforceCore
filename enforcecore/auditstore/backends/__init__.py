"""Audit storage backends."""

from .base import AuditBackend
from .jsonl import JSONLBackend
from .sqlite import SQLiteBackend

try:
    from .postgresql import PostgreSQLBackend

    HAS_POSTGRESQL = True
except ImportError:
    HAS_POSTGRESQL = False
    PostgreSQLBackend = None

__all__ = [
    "AuditBackend",
    "JSONLBackend",
    "SQLiteBackend",
]

if HAS_POSTGRESQL:
    __all__.append("PostgreSQLBackend")

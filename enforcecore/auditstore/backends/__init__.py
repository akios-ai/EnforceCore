"""Audit storage backends."""

from .base import AuditBackend
from .jsonl import JSONLBackend
from .sqlite import SQLiteBackend

try:
    from .postgresql import PostgreSQLBackend

    HAS_POSTGRESQL = True
except ImportError:  # pragma: no cover
    HAS_POSTGRESQL = False
    PostgreSQLBackend = None  # type: ignore[assignment,misc]

__all__ = [
    "AuditBackend",
    "JSONLBackend",
    "SQLiteBackend",
]

if HAS_POSTGRESQL:
    __all__.append("PostgreSQLBackend")

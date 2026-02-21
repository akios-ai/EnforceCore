# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Pluggable audit trail backends for EnforceCore.

Provides an abstract base class and built-in implementations for audit
trail storage. The default ``JsonlBackend`` preserves the existing JSONL
behavior. Custom backends can route audit entries to any destination.

Built-in backends:
- ``JsonlBackend``     -- Append-only JSONL files (default, existing behavior)
- ``NullBackend``      -- Discard all entries (for testing / benchmarking)
- ``CallbackBackend``  -- Send entries to a user-provided callable

Example::

    from enforcecore.auditor.backends import CallbackBackend

    entries = []
    backend = CallbackBackend(entries.append)
    auditor = Auditor(backend=backend)

To create a custom backend::

    from enforcecore.auditor.backends import AuditBackend

    class S3Backend(AuditBackend):
        def write(self, entry_dict: dict) -> None:
            s3.put_object(Body=json.dumps(entry_dict), ...)

        def close(self) -> None:
            pass  # flush buffers if any
"""

from __future__ import annotations

import abc
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import Callable

logger = structlog.get_logger("enforcecore.auditor.backends")


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class AuditBackend(abc.ABC):
    """Abstract base class for audit trail backends.

    Every backend must implement ``write()`` and ``close()``. The
    ``write()`` method receives a dict representation of an ``AuditEntry``
    (all fields serialized). Implementations should be thread-safe.
    """

    @abc.abstractmethod
    def write(self, entry_dict: dict[str, Any]) -> None:
        """Write a single audit entry.

        Args:
            entry_dict: Dictionary representation of an AuditEntry,
                including the computed ``entry_hash`` and ``previous_hash``.

        Raises:
            AuditError: If the write fails and cannot be retried.
        """

    @abc.abstractmethod
    def close(self) -> None:
        """Close the backend, flushing any buffered writes.

        Called when the Auditor is garbage-collected or explicitly closed.
        """

    def __enter__(self) -> AuditBackend:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# JsonlBackend (default)
# ---------------------------------------------------------------------------


class JsonlBackend(AuditBackend):
    """Append-only JSONL file backend.

    This is the default backend and preserves the existing behavior of
    the Auditor. Each entry is written as a single JSON line.

    Thread-safe: writes are protected by a lock and the file is opened
    in append mode.
    """

    __slots__ = ("_lock", "_path")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def write(self, entry_dict: dict[str, Any]) -> None:
        """Append entry as a JSON line to the file."""
        line = json.dumps(entry_dict, default=str, separators=(",", ":"))
        with self._lock, self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def close(self) -> None:
        """No-op for file-based backend (OS handles flushing)."""

    def __repr__(self) -> str:
        return f"JsonlBackend(path={self._path!r})"


# ---------------------------------------------------------------------------
# NullBackend (testing / benchmarking)
# ---------------------------------------------------------------------------


class NullBackend(AuditBackend):
    """Backend that discards all entries.

    Useful for testing and benchmarking where audit output is not needed
    but the audit pipeline should still execute.
    """

    __slots__ = ("_count", "_lock")

    def __init__(self) -> None:
        self._count = 0
        self._lock = threading.Lock()

    def write(self, entry_dict: dict[str, Any]) -> None:
        """Discard the entry, only increment counter."""
        with self._lock:
            self._count += 1

    def close(self) -> None:
        """No-op."""

    @property
    def entries_discarded(self) -> int:
        """Number of entries that were discarded."""
        with self._lock:
            return self._count

    def __repr__(self) -> str:
        return f"NullBackend(discarded={self._count})"


# ---------------------------------------------------------------------------
# CallbackBackend (custom pipelines)
# ---------------------------------------------------------------------------


class CallbackBackend(AuditBackend):
    """Backend that sends entries to a user-provided callable.

    The callable receives the entry dict. This enables piping audit
    entries to any destination: queues, databases, HTTP endpoints, etc.

    Example::

        # Send to a list
        entries = []
        backend = CallbackBackend(entries.append)

        # Send to a queue
        backend = CallbackBackend(queue.put)

        # Send via HTTP
        def send_to_api(entry):
            requests.post("https://audit.example.com/entries", json=entry)
        backend = CallbackBackend(send_to_api)
    """

    __slots__ = ("_callback", "_count", "_lock", "_on_error")

    def __init__(
        self,
        callback: Callable[[dict[str, Any]], Any],
        *,
        on_error: Callable[[Exception, dict[str, Any]], None] | None = None,
    ) -> None:
        """Initialize with a callback function.

        Args:
            callback: Function to call with each entry dict.
            on_error: Optional error handler. Called with (exception, entry_dict)
                if the callback raises. If not provided, errors are logged and
                re-raised.
        """
        self._callback = callback
        self._on_error = on_error
        self._count = 0
        self._lock = threading.Lock()

    def write(self, entry_dict: dict[str, Any]) -> None:
        """Send the entry to the callback."""
        try:
            self._callback(entry_dict)
            with self._lock:
                self._count += 1
        except Exception as exc:
            if self._on_error is not None:
                self._on_error(exc, entry_dict)
            else:
                logger.error(
                    "callback_backend_error",
                    exc_info=True,
                )
                raise

    def close(self) -> None:
        """No-op (user manages callback lifecycle)."""

    @property
    def entries_sent(self) -> int:
        """Number of entries successfully sent to the callback."""
        return self._count

    def __repr__(self) -> str:
        return f"CallbackBackend(callback={self._callback!r}, sent={self._count})"


# ---------------------------------------------------------------------------
# Multi-backend (fan-out)
# ---------------------------------------------------------------------------


class MultiBackend(AuditBackend):
    """Fan-out backend that writes to multiple backends simultaneously.

    Useful for sending audit entries to both a local file and a remote
    service at the same time.

    Example::

        backend = MultiBackend([
            JsonlBackend("audit.jsonl"),
            CallbackBackend(send_to_siem),
        ])
    """

    __slots__ = ("_backends",)

    def __init__(self, backends: list[AuditBackend]) -> None:
        if not backends:
            msg = "MultiBackend requires at least one backend"
            raise ValueError(msg)
        self._backends = list(backends)

    def write(self, entry_dict: dict[str, Any]) -> None:
        """Write to all backends. Logs errors but continues.

        Raises:
            AuditError: If ALL backends fail to write.
        """
        errors: list[Exception] = []
        for backend in self._backends:
            try:
                backend.write(entry_dict)
            except Exception as exc:
                errors.append(exc)
                logger.error(
                    "multi_backend_write_error",
                    backend=repr(backend),
                    exc_info=True,
                )
        if len(errors) == len(self._backends):
            from enforcecore.core.types import AuditError

            raise AuditError(f"All {len(self._backends)} audit backends failed to write")

    def close(self) -> None:
        """Close all backends."""
        for backend in self._backends:
            try:
                backend.close()
            except Exception:
                logger.error(
                    "multi_backend_close_error",
                    backend=repr(backend),
                    exc_info=True,
                )

    @property
    def backend_count(self) -> int:
        return len(self._backends)

    def __repr__(self) -> str:
        return f"MultiBackend(backends={self._backends!r})"

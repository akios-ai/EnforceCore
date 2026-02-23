# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Hash-only witness backends for tamper-evident audit trails.

A *witness* receives the hash of each audit entry as it is written.
Because the witness stores only hashes (not the full entry), the data
overhead is negligible.  If an attacker with filesystem access rebuilds
the Merkle chain, the witness retains the original hashes, making the
tampering detectable.

This design was directly informed by guidance from Prof. Dan S. Wallach
(Rice University), co-author of Crosby & Wallach (2009) "Efficient Data
Structures for Tamper-Evident Logging" (USENIX Security).

Built-in witnesses:

- ``CallbackWitness``  — send hashes to a user-provided callable (queue,
  HTTP endpoint, database, etc.)
- ``FileWitness``      — append hashes to a separate file (simple, works
  when the witness file is on a different volume or owned by a different user)
- ``LogWitness``       — emit hashes via Python ``logging`` (routes to
  syslog, journald, or any configured handler)

Example::

    from enforcecore.auditor.witness import CallbackWitness

    hashes = []
    witness = CallbackWitness(hashes.append)
    auditor = Auditor(output_path="audit.jsonl", witness=witness)

To verify a trail against a witness::

    from enforcecore.auditor.witness import verify_with_witness

    result = verify_with_witness("audit.jsonl", witness_hashes=hashes)
    assert result.is_valid
"""

from __future__ import annotations

import abc
import json
import logging
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from collections.abc import Callable

logger = structlog.get_logger("enforcecore.auditor.witness")


# ---------------------------------------------------------------------------
# Witness record — what gets sent to the witness
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class WitnessRecord:
    """A lightweight record sent to the witness.

    Contains only hashes and identifiers — never the full entry content.
    This keeps the witness data footprint minimal (~200 bytes per entry).
    """

    entry_id: str
    entry_hash: str
    previous_hash: str
    sequence: int  # 1-based position in the chain
    timestamp: str


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class WitnessBackend(abc.ABC):
    """Abstract base class for hash-only witnesses.

    A witness receives a :class:`WitnessRecord` for every audit entry
    written by the :class:`Auditor`.  Implementations must be thread-safe.
    """

    @abc.abstractmethod
    def publish(self, record: WitnessRecord) -> None:
        """Publish a witness record.

        Args:
            record: The hash record to publish.

        Raises:
            Exception: On failure.  The Auditor logs the error but does
                not block the audit write (fail-open for witnesses).
        """

    @abc.abstractmethod
    def close(self) -> None:
        """Release any resources held by the witness."""

    def __enter__(self) -> WitnessBackend:
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# CallbackWitness
# ---------------------------------------------------------------------------


class CallbackWitness(WitnessBackend):
    """Witness that sends records to a user-provided callable.

    The simplest way to integrate with external systems:

    - Send to a message queue: ``CallbackWitness(queue.put)``
    - Send via HTTP: ``CallbackWitness(post_to_api)``
    - Collect in memory: ``CallbackWitness(my_list.append)``

    Example::

        hashes = []
        witness = CallbackWitness(hashes.append)
        auditor = Auditor(output_path="audit.jsonl", witness=witness)
        auditor.record(tool_name="search", policy_name="strict")
        assert len(hashes) == 1
        assert hashes[0].entry_hash != ""
    """

    __slots__ = ("_callback", "_count", "_lock")

    def __init__(self, callback: Callable[[WitnessRecord], Any]) -> None:
        self._callback = callback
        self._count = 0
        self._lock = threading.Lock()

    def publish(self, record: WitnessRecord) -> None:
        self._callback(record)
        with self._lock:
            self._count += 1

    def close(self) -> None:
        """No-op — caller manages the callback lifecycle."""

    @property
    def records_published(self) -> int:
        with self._lock:
            return self._count

    def __repr__(self) -> str:
        return f"CallbackWitness(published={self._count})"


# ---------------------------------------------------------------------------
# FileWitness
# ---------------------------------------------------------------------------


class FileWitness(WitnessBackend):
    """Witness that appends hash records to a separate file.

    Best used when the witness file is on a different volume, owned by a
    different user, or protected with ``chattr +a`` (append-only).

    File format: one JSON object per line (JSONL), containing only hashes::

        {"entry_id":"...","entry_hash":"a1b2...","previous_hash":"","sequence":1,"timestamp":"..."}
    """

    __slots__ = ("_lock", "_path")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def publish(self, record: WitnessRecord) -> None:
        line = json.dumps(
            {
                "entry_id": record.entry_id,
                "entry_hash": record.entry_hash,
                "previous_hash": record.previous_hash,
                "sequence": record.sequence,
                "timestamp": record.timestamp,
            },
            separators=(",", ":"),
        )
        with self._lock, self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def close(self) -> None:
        """No-op."""

    @property
    def path(self) -> Path:
        return self._path

    def load_hashes(self) -> list[str]:
        """Load all witnessed hashes in order.

        Returns:
            List of entry_hash strings in chronological order.
        """
        if not self._path.exists():
            return []
        hashes: list[str] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    hashes.append(data["entry_hash"])
        return hashes

    def __repr__(self) -> str:
        return f"FileWitness(path={self._path!r})"


# ---------------------------------------------------------------------------
# LogWitness (syslog / journald / Python logging)
# ---------------------------------------------------------------------------


class LogWitness(WitnessBackend):
    """Witness that emits hash records via Python's ``logging`` module.

    This routes witness hashes to whatever handlers are configured on the
    logger — syslog, journald, file handlers, etc.  Since syslog is
    typically managed by a separate daemon (rsyslogd, systemd-journald),
    it provides process-level separation from the application.

    Example::

        import logging
        logging.basicConfig(level=logging.INFO)
        witness = LogWitness()  # uses "enforcecore.witness" logger
    """

    __slots__ = ("_count", "_lock", "_logger")

    def __init__(self, logger_name: str = "enforcecore.witness") -> None:
        self._logger = logging.getLogger(logger_name)
        self._count = 0
        self._lock = threading.Lock()

    def publish(self, record: WitnessRecord) -> None:
        self._logger.info(
            "witness hash=%s prev=%s seq=%d id=%s",
            record.entry_hash,
            record.previous_hash or "(root)",
            record.sequence,
            record.entry_id,
        )
        with self._lock:
            self._count += 1

    def close(self) -> None:
        """No-op."""

    @property
    def records_published(self) -> int:
        with self._lock:
            return self._count

    def __repr__(self) -> str:
        return f"LogWitness(published={self._count})"


# ---------------------------------------------------------------------------
# Witness verification
# ---------------------------------------------------------------------------


@dataclass
class WitnessVerificationResult:
    """Result of verifying an audit trail against a witness."""

    is_valid: bool = True
    trail_entries: int = 0
    witness_entries: int = 0
    matched: int = 0
    mismatched: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def error_count(self) -> int:
        return len(self.errors)


def verify_with_witness(
    trail_path: str | Path,
    *,
    witness_hashes: list[str] | None = None,
    witness_file: str | Path | None = None,
) -> WitnessVerificationResult:
    """Verify an audit trail against witness hashes.

    Compares the entry hashes in the audit trail with the hashes
    recorded by a witness.  If an attacker rebuilt the Merkle chain,
    the hashes will differ from what the witness recorded.

    Args:
        trail_path: Path to the JSONL audit trail file.
        witness_hashes: List of witnessed entry hashes (in order).
            Provide this OR ``witness_file``, not both.
        witness_file: Path to a FileWitness JSONL file.

    Returns:
        A ``WitnessVerificationResult`` with match/mismatch details.

    Example::

        result = verify_with_witness("audit.jsonl", witness_hashes=hashes)
        if not result.is_valid:
            print("TAMPER DETECTED — trail hashes differ from witness!")
    """
    result = WitnessVerificationResult()

    # Load witness hashes
    if witness_hashes is not None and witness_file is not None:
        result.is_valid = False
        result.errors.append("Provide witness_hashes OR witness_file, not both")
        return result

    w_hashes: list[str]
    if witness_hashes is not None:
        w_hashes = list(witness_hashes)
    elif witness_file is not None:
        fw = FileWitness(witness_file)
        w_hashes = fw.load_hashes()
    else:
        result.is_valid = False
        result.errors.append("No witness data provided")
        return result

    result.witness_entries = len(w_hashes)

    # Load trail hashes
    trail = Path(trail_path)
    if not trail.exists():
        result.is_valid = False
        result.errors.append(f"Audit trail not found: {trail}")
        return result

    trail_hashes: list[str] = []
    with trail.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data = json.loads(line)
                trail_hashes.append(data.get("entry_hash", ""))

    result.trail_entries = len(trail_hashes)

    # Compare
    if len(trail_hashes) != len(w_hashes):
        result.is_valid = False
        result.errors.append(
            f"Entry count mismatch: trail has {len(trail_hashes)}, witness has {len(w_hashes)}"
        )

    for i, (t_hash, w_hash) in enumerate(zip(trail_hashes, w_hashes, strict=False)):
        if t_hash == w_hash:
            result.matched += 1
        else:
            result.mismatched += 1
            result.is_valid = False
            result.errors.append(
                f"Entry {i + 1}: trail hash={t_hash[:16]}... "
                f"witness hash={w_hash[:16]}... — MISMATCH"
            )

    if result.is_valid and result.matched > 0:
        logger.info(
            "witness_verification_passed",
            entries=result.matched,
        )

    return result

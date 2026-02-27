# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Merkle-chained audit trail engine.

Provides tamper-proof, cryptographically verifiable audit logs for every
enforced call. Each audit entry is SHA-256 hashed and chained to the
previous entry, forming a Merkle chain. Any modification to a past entry
breaks the chain and is detectable.

Design:
- **Append-only JSONL** — one JSON object per line, human-readable
- **SHA-256 Merkle chain** — each entry's hash includes the previous hash
- **Zero external deps** — stdlib only (hashlib, json, pathlib)
- **Thread-safe** — file writes protected by a lock
- **Fail-closed** — audit errors block the call (unless fail_open=True)

Usage::

    from enforcecore.auditor import Auditor, verify_trail

    # Write entries
    auditor = Auditor(output_path="audit.jsonl")
    entry = auditor.record(
        tool_name="search_web",
        policy_name="strict",
        decision="allowed",
        call_id="uuid-...",
    )

    # Verify the trail
    result = verify_trail("audit.jsonl")
    assert result.is_valid
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from enforcecore.core.types import AuditError

logger = structlog.get_logger("enforcecore.auditor")


# ---------------------------------------------------------------------------
# Audit entry
# ---------------------------------------------------------------------------


@dataclass
class AuditEntry:
    """A single audit trail entry.

    Each entry records the full context of an enforced call: what was called,
    what policy was applied, what the decision was, timing, and redaction
    counts. The ``entry_hash`` chains this entry to the previous one.
    """

    # Identity
    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    call_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    # Call metadata
    tool_name: str = ""
    policy_name: str = ""
    policy_version: str = ""
    tenant_id: str | None = None  # populated when using MultiTenantEnforcer

    # Decision
    decision: str = "allowed"  # allowed | blocked
    violation_type: str | None = None
    violation_reason: str | None = None

    # Timing (milliseconds)
    overhead_ms: float = 0.0
    call_duration_ms: float = 0.0

    # Redaction summary
    input_redactions: int = 0
    output_redactions: int = 0

    # Merkle chain
    previous_hash: str = ""  # Hash of the previous entry ("" for first)
    entry_hash: str = ""  # SHA-256 of this entry's content + previous_hash

    def compute_hash(self) -> str:
        """Compute the SHA-256 hash of this entry's content.

        The hash covers all fields EXCEPT ``entry_hash`` itself,
        ensuring the hash is deterministic and self-consistent.
        """
        data = asdict(self)
        data.pop("entry_hash", None)
        # Canonical JSON: sorted keys, no whitespace
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def seal(self) -> AuditEntry:
        """Compute and set the entry hash. Returns self for chaining."""
        self.entry_hash = self.compute_hash()
        return self

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dictionary (for JSON output).

        Validates that the resulting dict is JSON-serializable.  If any
        field contains a non-serializable value (``datetime``, ``bytes``,
        ``set``, custom object), raises :class:`AuditError`.

        .. versionchanged:: 1.0.0
           Added JSON-safety validation.
        """
        d = asdict(self)
        try:
            json.dumps(d, sort_keys=True)
        except (TypeError, ValueError) as exc:
            raise AuditError(f"AuditEntry contains non-JSON-safe data: {exc}") from exc
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditEntry:
        """Deserialize from a dictionary."""
        valid_names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in valid_names})

    def to_json(self) -> str:
        """Serialize to a single JSON line (no trailing newline)."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Verification result
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    """Result of verifying an audit trail."""

    is_valid: bool = True
    total_entries: int = 0
    chain_intact: bool = True
    root_hash: str = ""  # Hash of the first entry
    head_hash: str = ""  # Hash of the last entry
    errors: list[str] = field(default_factory=list)
    entries_checked: int = 0

    @property
    def error_count(self) -> int:
        return len(self.errors)


# ---------------------------------------------------------------------------
# Auditor — writes entries
# ---------------------------------------------------------------------------


class Auditor:
    """Merkle-chained audit trail writer.

    Writes audit entries to a JSONL file. Each entry is SHA-256 hashed
    and chained to the previous entry. Thread-safe via a lock.

    Example::

        auditor = Auditor(output_path="audit.jsonl")
        entry = auditor.record(
            tool_name="search_web",
            policy_name="strict",
            decision="allowed",
        )
        print(entry.entry_hash)  # "a1b2c3..."
    """

    __slots__ = (
        "_backend",
        "_entry_count",
        "_immutable",
        "_last_hash",
        "_lock",
        "_output_path",
        "_witness",
    )

    def __init__(
        self,
        output_path: str | Path | None = None,
        *,
        backend: Any | None = None,
        witness: Any | None = None,
        immutable: bool = False,
    ) -> None:
        """Initialize the auditor.

        Args:
            output_path: Path to the JSONL file. Created if it doesn't exist.
                Parent directories are created automatically. Ignored if
                ``backend`` is provided.
            backend: Optional pluggable audit backend (v1.0.7+). Must
                implement ``write(entry_dict)`` and ``close()``. If not
                provided, defaults to a ``JsonlBackend`` writing to
                ``output_path``.
            witness: Optional hash-only witness backend (v1.0.0b4+). Must
                implement ``publish(record)`` and ``close()``.  The witness
                receives only entry hashes, not full content.  See
                :mod:`enforcecore.auditor.witness` for built-in witnesses.
            immutable: If ``True``, set the OS-level append-only attribute
                on the audit file after creation (v1.0.0b4+).  Requires
                ``CAP_LINUX_IMMUTABLE`` on Linux or root on macOS.  In
                Docker, run with ``--cap-add LINUX_IMMUTABLE``.  If the
                platform does not support it, a warning is logged but
                the auditor continues without protection.

        .. versionchanged:: 1.0.0b4
           Added ``witness`` and ``immutable`` parameters.
        """
        self._lock = threading.Lock()
        self._last_hash = ""
        self._entry_count = 0
        self._witness = witness
        self._immutable = immutable

        # Set up backend
        if backend is not None:
            self._backend = backend
            self._output_path = Path(output_path) if output_path else None
        else:
            if output_path is None:
                msg = "Either output_path or backend must be provided"
                raise AuditError(msg)
            self._output_path = Path(output_path)
            self._backend = None  # Use legacy direct file writes

        # Resume chain from existing file
        if (
            self._output_path is not None
            and self._output_path.exists()
            and self._output_path.stat().st_size > 0
        ):
            self._resume_chain()

        # Apply append-only protection after file creation
        if self._immutable and self._output_path is not None:
            self._apply_immutable()

    def _resume_chain(self) -> None:
        """Read the last entry from an existing file to resume the chain.

        Uses reverse seeking for efficiency on large files. Reads in
        binary mode to avoid undefined behavior with text-mode ``seek()``,
        then decodes to UTF-8.

        .. versionchanged:: 1.0.0
           Increased read-back window from 8 KB to 64 KB; uses binary
           mode for seeking; retries with doubled window on failure.
        """
        assert self._output_path is not None  # Guarded by caller
        window = 65536  # 64 KB
        try:
            last_line = ""
            count = 0
            file_size = self._output_path.stat().st_size

            with self._output_path.open("rb") as fb:
                if file_size > window:
                    # Seek near the end in binary mode (well-defined behavior)
                    seek_pos = max(0, file_size - window)
                    fb.seek(seek_pos)
                    fb.readline()  # Discard partial line
                    tail_bytes = fb.read()
                    tail_text = tail_bytes.decode("utf-8", errors="replace")

                    # Find the last non-empty line
                    found = False
                    for line in tail_text.splitlines():
                        line = line.strip()
                        if line:
                            last_line = line
                            found = True

                    # Retry with doubled window if no valid line found
                    if not found and file_size > window * 2:
                        fb.seek(max(0, file_size - window * 2))
                        fb.readline()
                        tail_bytes = fb.read()
                        tail_text = tail_bytes.decode("utf-8", errors="replace")
                        for line in tail_text.splitlines():
                            line = line.strip()
                            if line:
                                last_line = line

                    # Count entries separately (still need total count)
                    fb.seek(0)
                    count = sum(1 for ln in fb if ln.strip())
                else:
                    # Small file — read all lines
                    for raw_line in fb:
                        line = raw_line.decode("utf-8", errors="replace").strip()
                        if line:
                            last_line = line
                            count += 1

            if last_line:
                data = json.loads(last_line)
                self._last_hash = data.get("entry_hash", "")
                self._entry_count = count
                logger.debug(
                    "audit_chain_resumed",
                    path=str(self._output_path),
                    entries=count,
                )
        except (json.JSONDecodeError, OSError) as exc:
            msg = f"Failed to resume audit chain from {self._output_path}: {exc}"
            raise AuditError(msg) from exc

    def _apply_immutable(self) -> None:
        """Apply OS-level append-only protection to the audit file.

        Logs a warning and continues if the platform doesn't support it
        or if permissions are insufficient.  Never raises — this is a
        best-effort hardening measure.
        """
        try:
            from enforcecore.auditor.immutable import (
                AppendOnlyError,
                protect_append_only,
            )

            # Ensure the file exists (create if needed)
            assert self._output_path is not None  # Guarded by caller
            self._output_path.parent.mkdir(parents=True, exist_ok=True)
            if not self._output_path.exists():
                self._output_path.touch()

            protect_append_only(self._output_path)
        except AppendOnlyError as exc:
            logger.warning(
                "append_only_failed",
                path=str(self._output_path),
                error=str(exc),
                hint="Audit trail will continue without OS-level protection",
            )
        except Exception as exc:
            logger.warning(
                "append_only_unexpected_error",
                path=str(self._output_path),
                error=str(exc),
            )

    @property
    def output_path(self) -> Path | None:
        return self._output_path

    @property
    def backend(self) -> Any | None:
        """The audit backend, if using pluggable backends."""
        return self._backend

    @property
    def witness(self) -> Any | None:
        """The witness backend, if configured."""
        return self._witness

    @property
    def immutable(self) -> bool:
        """Whether append-only protection is enabled."""
        return self._immutable

    @property
    def last_hash(self) -> str:
        return self._last_hash

    @property
    def entry_count(self) -> int:
        return self._entry_count

    def record(
        self,
        *,
        tool_name: str,
        policy_name: str,
        policy_version: str = "",
        decision: str = "allowed",
        call_id: str = "",
        violation_type: str | None = None,
        violation_reason: str | None = None,
        overhead_ms: float = 0.0,
        call_duration_ms: float = 0.0,
        input_redactions: int = 0,
        output_redactions: int = 0,
        tenant_id: str | None = None,
    ) -> AuditEntry:
        """Record an audit entry and append it to the trail.

        Args:
            tool_name: Name of the tool that was called.
            policy_name: Name of the policy that was applied.
            policy_version: Version of the policy.
            decision: "allowed" or "blocked".
            call_id: UUID of the enforcement call.
            violation_type: Type of violation (if blocked).
            violation_reason: Reason for the violation.
            overhead_ms: Enforcement overhead in milliseconds.
            call_duration_ms: Tool call duration in milliseconds.
            input_redactions: Number of PII entities redacted from inputs.
            output_redactions: Number of PII entities redacted from outputs.

        Returns:
            The sealed ``AuditEntry`` with its Merkle hash.

        Raises:
            AuditError: If the entry cannot be written to disk.
        """
        with self._lock:
            entry = AuditEntry(
                call_id=call_id or str(uuid.uuid4()),
                tool_name=tool_name,
                policy_name=policy_name,
                policy_version=policy_version,
                decision=decision,
                violation_type=violation_type,
                violation_reason=violation_reason,
                overhead_ms=overhead_ms,
                call_duration_ms=call_duration_ms,
                input_redactions=input_redactions,
                output_redactions=output_redactions,
                tenant_id=tenant_id,
                previous_hash=self._last_hash,
            )
            entry.seal()

            self._write_entry(entry)
            self._last_hash = entry.entry_hash
            self._entry_count += 1

            logger.debug(
                "audit_entry_recorded",
                entry_id=entry.entry_id,
                tool=tool_name,
                decision=decision,
                chain_length=self._entry_count,
            )

        # Publish to witness OUTSIDE the lock so slow witnesses
        # (e.g. HTTP callbacks) don't block subsequent audit writes.
        if self._witness is not None:
            self._publish_to_witness(entry)

        return entry

    # ── Convenience wrappers ──────────────────────────────────────────

    def log(
        self,
        tool_name: str,
        policy_name: str,
        *,
        decision: str = "allowed",
        **kwargs: Any,
    ) -> AuditEntry:
        """Shorthand for :meth:`record` with a simpler signature.

        Example::

            auditor.log("search_web", "strict")
            auditor.log("run_sql", "strict", decision="blocked",
                        violation_reason="SQL injection detected")

        .. versionadded:: 1.1.1
        """
        return self.record(
            tool_name=tool_name,
            policy_name=policy_name,
            decision=decision,
            **kwargs,
        )

    def verify(self) -> VerificationResult:
        """Verify the integrity of *this* auditor's trail.

        Convenience wrapper around :func:`verify_trail` using the
        auditor's ``output_path``.

        Returns:
            A ``VerificationResult`` — check ``.is_valid``.

        Raises:
            AuditError: If no ``output_path`` is configured.

        .. versionadded:: 1.1.1
        """
        if self._output_path is None:
            raise AuditError(
                "Cannot verify: auditor was created with a backend, not an output_path"
            )
        return verify_trail(self._output_path)

    def _publish_to_witness(self, entry: AuditEntry) -> None:
        """Send entry hash to the witness backend.

        Never raises — witness failures are logged but do not block
        the audit write.
        """
        witness = self._witness
        if witness is None:
            return
        try:
            from enforcecore.auditor.witness import WitnessRecord

            record = WitnessRecord(
                entry_id=entry.entry_id,
                entry_hash=entry.entry_hash,
                previous_hash=entry.previous_hash,
                sequence=self._entry_count,
                timestamp=entry.timestamp,
            )
            witness.publish(record)
        except Exception as exc:
            logger.warning(
                "witness_publish_failed",
                entry_id=entry.entry_id,
                error=str(exc),
            )

    def _write_entry(self, entry: AuditEntry) -> None:
        """Append an entry to the backend or JSONL file."""
        try:
            if self._backend is not None:
                # Use pluggable backend
                self._backend.write(entry.to_dict())
            elif self._output_path is not None:
                # Legacy direct file write
                self._output_path.parent.mkdir(parents=True, exist_ok=True)
                with self._output_path.open("a", encoding="utf-8") as f:
                    f.write(entry.to_json() + "\n")
                    f.flush()
        except OSError as exc:
            msg = f"Failed to write audit entry: {exc}"
            raise AuditError(msg) from exc


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def verify_trail(
    path: str | Path,
    *,
    skip_entry_hash: bool = False,
) -> VerificationResult:
    """Verify the integrity of an audit trail file.

    Reads every entry, recomputes hashes, and checks the Merkle chain.
    Any modification to any entry will be detected.

    Args:
        path: Path to the JSONL audit file.
        skip_entry_hash: When ``True``, only verify chain linkage
            (``previous_hash`` continuity) without recomputing individual
            entry hashes from the payload.  This is useful when the trail
            was written by an external system (e.g. AKIOS) that uses a
            different hashing scheme.  Chain ordering is still verified.

    Returns:
        A ``VerificationResult`` with details about the verification.

    Example::

        result = verify_trail("audit.jsonl")
        if result.is_valid:
            print(f"Trail OK — {result.total_entries} entries, chain intact")
        else:
            for error in result.errors:
                print(f"  ERROR: {error}")

    .. versionchanged:: 1.12.0
       Added ``skip_entry_hash`` for cross-system Merkle bridge.
    """
    filepath = Path(path)
    result = VerificationResult()

    if not filepath.exists():
        result.is_valid = False
        result.chain_intact = False
        result.errors.append(f"Audit file not found: {filepath}")
        return result

    if filepath.stat().st_size == 0:
        # Empty file is technically valid (no entries)
        return result

    previous_hash = ""

    try:
        with filepath.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                result.total_entries += 1

                # Parse
                try:
                    data = json.loads(line)
                except json.JSONDecodeError as exc:
                    result.is_valid = False
                    result.errors.append(f"Line {line_num}: invalid JSON — {exc}")
                    continue

                entry = AuditEntry.from_dict(data)
                stored_hash = entry.entry_hash

                # Verify hash (skip if caller opted out for external hashes)
                if not skip_entry_hash:
                    computed = entry.compute_hash()
                    if computed != stored_hash:
                        result.is_valid = False
                        result.chain_intact = False
                        result.errors.append(
                            f"Line {line_num}: hash mismatch — entry '{entry.entry_id}' "
                            f"stored={stored_hash[:16]}... computed={computed[:16]}..."
                        )

                # Verify chain linkage
                if entry.previous_hash != previous_hash:
                    result.is_valid = False
                    result.chain_intact = False
                    result.errors.append(
                        f"Line {line_num}: chain broken — entry '{entry.entry_id}' "
                        f"expected previous_hash={previous_hash[:16] or '(empty)'}... "
                        f"got={entry.previous_hash[:16] or '(empty)'}..."
                    )

                # Track chain
                if result.total_entries == 1:
                    result.root_hash = stored_hash

                result.head_hash = stored_hash
                previous_hash = stored_hash
                result.entries_checked += 1

    except OSError as exc:
        result.is_valid = False
        result.errors.append(f"Failed to read audit file: {exc}")

    if result.total_entries > 0 and not result.errors:
        logger.info(
            "audit_trail_verified",
            path=str(filepath),
            entries=result.total_entries,
            root_hash=result.root_hash[:16],
            head_hash=result.head_hash[:16],
        )

    return result


# ---------------------------------------------------------------------------
# Load entries (utility)
# ---------------------------------------------------------------------------


def load_trail(path: str | Path, *, max_entries: int | None = None) -> list[AuditEntry]:
    """Load entries from an audit trail file.

    Args:
        path: Path to the JSONL audit file.
        max_entries: Maximum number of entries to load.  ``None`` loads all.
            When set, returns the *most recent* entries (from the end of
            the file).

    Returns:
        A list of ``AuditEntry`` objects in chronological order.

    Raises:
        AuditError: If the file cannot be read or parsed.
    """
    filepath = Path(path)
    if not filepath.exists():
        msg = f"Audit file not found: {filepath}"
        raise AuditError(msg)

    entries: list[AuditEntry] = []
    try:
        with filepath.open("r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(AuditEntry.from_dict(data))
                except (json.JSONDecodeError, TypeError) as exc:
                    msg = f"Invalid entry at line {line_num}: {exc}"
                    raise AuditError(msg) from exc
    except OSError as exc:
        msg = f"Failed to read audit file {filepath}: {exc}"
        raise AuditError(msg) from exc

    if max_entries is not None and len(entries) > max_entries:
        entries = entries[-max_entries:]

    return entries

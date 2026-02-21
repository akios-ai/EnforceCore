# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Audit trail rotation, retention, and compression.

Provides automatic management of audit JSONL files:

- **Rotation**: Size-based rotation (split files when they exceed a threshold).
- **Retention**: Time-based cleanup (delete trails older than a configured age).
- **Compression**: Gzip completed (rotated) trail files to save disk space.

Usage::

    from enforcecore.auditor.rotation import AuditRotator

    rotator = AuditRotator(
        directory="./audit_logs",
        max_file_size_mb=50,
        max_age_days=90,
        compress=True,
    )

    # Check and rotate if needed
    rotator.rotate_if_needed()

    # Clean up old files
    rotator.enforce_retention()
"""

from __future__ import annotations

import gzip
import shutil
import time
from datetime import UTC, datetime
from pathlib import Path

import structlog

logger = structlog.get_logger("enforcecore.auditor.rotation")


class AuditRotator:
    """Manages audit trail file rotation, retention, and compression.

    Thread-safe: rotation and cleanup are idempotent and safe to call
    from multiple threads (uses atomic file rename).

    Args:
        directory: Directory containing audit JSONL files.
        max_file_size_mb: Maximum size in MB before rotating. Default 100.
        max_age_days: Maximum age in days before cleanup. Default 90.
            Set to 0 to disable retention enforcement.
        compress: Whether to gzip rotated files. Default True.
        file_pattern: Glob pattern for audit files. Default ``*.jsonl``.
    """

    __slots__ = (
        "_compress",
        "_directory",
        "_file_pattern",
        "_max_age_days",
        "_max_file_size_bytes",
    )

    def __init__(
        self,
        directory: str | Path,
        *,
        max_file_size_mb: float = 100.0,
        max_age_days: int = 90,
        compress: bool = True,
        file_pattern: str = "*.jsonl",
    ) -> None:
        self._directory = Path(directory)
        self._max_file_size_bytes = int(max_file_size_mb * 1024 * 1024)
        self._max_age_days = max_age_days
        self._compress = compress
        self._file_pattern = file_pattern

    @property
    def directory(self) -> Path:
        return self._directory

    @property
    def max_file_size_mb(self) -> float:
        return self._max_file_size_bytes / (1024 * 1024)

    @property
    def max_age_days(self) -> int:
        return self._max_age_days

    def rotate_if_needed(self, path: Path | None = None) -> Path | None:
        """Check if a file exceeds the size limit and rotate it.

        If *path* is ``None``, checks all matching files in the directory.
        Returns the path to the rotated (archived) file, or ``None`` if
        no rotation was needed.
        """
        if path is not None:
            return self._maybe_rotate(path)

        rotated: Path | None = None
        if self._directory.exists():
            for f in sorted(self._directory.glob(self._file_pattern)):
                result = self._maybe_rotate(f)
                if result is not None:
                    rotated = result
        return rotated

    def _maybe_rotate(self, path: Path) -> Path | None:
        """Rotate a single file if it exceeds the size threshold."""
        if not path.exists():
            return None

        size = path.stat().st_size
        if size < self._max_file_size_bytes:
            return None

        # Generate rotated filename: audit.jsonl -> audit.2025-02-21T12-00-00.jsonl
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H-%M-%S")
        rotated_name = f"{path.stem}.{ts}{path.suffix}"
        rotated_path = path.parent / rotated_name

        # Atomic rename
        path.rename(rotated_path)
        logger.info(
            "audit_file_rotated",
            original=str(path),
            rotated=str(rotated_path),
            size_mb=round(size / (1024 * 1024), 2),
        )

        # Compress if configured
        if self._compress:
            compressed = self._compress_file(rotated_path)
            return compressed

        return rotated_path

    def enforce_retention(self) -> list[Path]:
        """Delete audit files older than the configured retention period.

        Returns a list of deleted file paths.
        """
        if self._max_age_days <= 0:
            return []

        if not self._directory.exists():
            return []

        cutoff = time.time() - (self._max_age_days * 86400)
        deleted: list[Path] = []

        # Check both .jsonl and .jsonl.gz files
        for pattern in (self._file_pattern, f"{self._file_pattern}.gz"):
            for f in self._directory.glob(pattern):
                try:
                    mtime = f.stat().st_mtime
                    if mtime < cutoff:
                        f.unlink()
                        deleted.append(f)
                        logger.info(
                            "audit_file_deleted",
                            path=str(f),
                            age_days=round((time.time() - mtime) / 86400, 1),
                        )
                except OSError as exc:
                    logger.warning("audit_file_delete_failed", path=str(f), error=str(exc))

        return deleted

    def compress_completed(self) -> list[Path]:
        """Compress all rotated (non-active) JSONL files.

        Active files (without a timestamp in the name) are skipped.
        Returns a list of compressed file paths.
        """
        if not self._directory.exists():
            return []

        compressed: list[Path] = []
        for f in self._directory.glob(self._file_pattern):
            # Skip files that look like active/current logs (no timestamp)
            # Rotated files have a timestamp: audit.2025-02-21T12-00-00.jsonl
            if "T" not in f.stem:
                continue
            result = self._compress_file(f)
            compressed.append(result)

        return compressed

    def _compress_file(self, path: Path) -> Path:
        """Gzip a file and remove the original."""
        gz_path = path.with_suffix(path.suffix + ".gz")
        with open(path, "rb") as f_in, gzip.open(gz_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
        path.unlink()
        logger.info(
            "audit_file_compressed",
            original=str(path),
            compressed=str(gz_path),
        )
        return gz_path

    def get_stats(self) -> dict[str, int | float]:
        """Return statistics about audit files in the directory."""
        if not self._directory.exists():
            return {"total_files": 0, "total_size_mb": 0.0, "compressed_files": 0}

        total_files = 0
        total_size = 0
        compressed = 0

        for pattern in (self._file_pattern, f"{self._file_pattern}.gz"):
            for f in self._directory.glob(pattern):
                total_files += 1
                total_size += f.stat().st_size
                if f.suffix == ".gz":
                    compressed += 1

        return {
            "total_files": total_files,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "compressed_files": compressed,
        }

    def __repr__(self) -> str:
        return (
            f"AuditRotator(dir={self._directory!r}, "
            f"max_size_mb={self.max_file_size_mb}, "
            f"max_age_days={self._max_age_days}, "
            f"compress={self._compress})"
        )

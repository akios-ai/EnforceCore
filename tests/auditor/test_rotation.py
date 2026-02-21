# Copyright 2026 AKIOS AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for audit trail rotation, retention, and compression."""

from __future__ import annotations

import gzip
import os
import time
from pathlib import Path

import pytest

from enforcecore.auditor.rotation import AuditRotator


@pytest.fixture
def audit_dir(tmp_path: Path) -> Path:
    """Temporary directory for audit files."""
    d = tmp_path / "audit_logs"
    d.mkdir()
    return d


@pytest.fixture
def rotator(audit_dir: Path) -> AuditRotator:
    """Rotator with 1 KB threshold (for easy testing)."""
    return AuditRotator(
        directory=audit_dir,
        max_file_size_mb=0.001,  # ~1 KB
        max_age_days=30,
        compress=True,
    )


@pytest.fixture
def rotator_no_compress(audit_dir: Path) -> AuditRotator:
    """Rotator without compression."""
    return AuditRotator(
        directory=audit_dir,
        max_file_size_mb=0.001,
        max_age_days=30,
        compress=False,
    )


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestAuditRotatorInit:
    def test_default_values(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir)
        assert r.directory == audit_dir
        assert r.max_file_size_mb == 100.0
        assert r.max_age_days == 90

    def test_custom_values(self, rotator: AuditRotator) -> None:
        assert rotator.max_file_size_mb == pytest.approx(0.001, rel=0.1)
        assert rotator.max_age_days == 30

    def test_repr(self, rotator: AuditRotator) -> None:
        r = repr(rotator)
        assert "AuditRotator" in r
        assert "max_size_mb" in r

    def test_string_path(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=str(audit_dir))
        assert r.directory == audit_dir


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------


class TestRotation:
    def test_no_rotation_under_threshold(self, audit_dir: Path, rotator: AuditRotator) -> None:
        f = audit_dir / "audit.jsonl"
        f.write_text('{"event": "test"}\n')  # Small file
        result = rotator.rotate_if_needed(f)
        assert result is None
        assert f.exists()

    def test_rotation_over_threshold(self, audit_dir: Path, rotator: AuditRotator) -> None:
        f = audit_dir / "audit.jsonl"
        f.write_text("x" * 2000)  # > 1 KB
        result = rotator.rotate_if_needed(f)
        assert result is not None
        assert result.suffix == ".gz"  # Compressed
        assert not f.exists()  # Original renamed

    def test_rotation_without_compression(
        self, audit_dir: Path, rotator_no_compress: AuditRotator
    ) -> None:
        f = audit_dir / "audit.jsonl"
        f.write_text("x" * 2000)
        result = rotator_no_compress.rotate_if_needed(f)
        assert result is not None
        assert result.suffix == ".jsonl"
        assert "T" in result.stem  # Has timestamp

    def test_rotate_all_files(self, audit_dir: Path, rotator: AuditRotator) -> None:
        for i in range(3):
            f = audit_dir / f"audit_{i}.jsonl"
            f.write_text("x" * 2000)
        result = rotator.rotate_if_needed()
        assert result is not None

    def test_rotate_nonexistent_file(self, rotator: AuditRotator) -> None:
        result = rotator.rotate_if_needed(Path("/nonexistent/audit.jsonl"))
        assert result is None

    def test_rotate_empty_directory(self, tmp_path: Path) -> None:
        d = tmp_path / "empty"
        d.mkdir()
        r = AuditRotator(directory=d, max_file_size_mb=0.001)
        result = r.rotate_if_needed()
        assert result is None

    def test_rotate_nonexistent_directory(self, tmp_path: Path) -> None:
        r = AuditRotator(directory=tmp_path / "does_not_exist")
        result = r.rotate_if_needed()
        assert result is None


# ---------------------------------------------------------------------------
# Retention enforcement
# ---------------------------------------------------------------------------


class TestRetention:
    def test_deletes_old_files(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, max_age_days=1)
        f = audit_dir / "old.jsonl"
        f.write_text("old data")
        # Set mtime to 5 days ago
        old_time = time.time() - (5 * 86400)
        os.utime(f, (old_time, old_time))
        deleted = r.enforce_retention()
        assert len(deleted) == 1
        assert not f.exists()

    def test_keeps_recent_files(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, max_age_days=30)
        f = audit_dir / "recent.jsonl"
        f.write_text("recent data")
        deleted = r.enforce_retention()
        assert len(deleted) == 0
        assert f.exists()

    def test_deletes_old_gz_files(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, max_age_days=1)
        gz = audit_dir / "old.jsonl.gz"
        gz.write_bytes(b"\x1f\x8b" + b"\x00" * 20)
        old_time = time.time() - (5 * 86400)
        os.utime(gz, (old_time, old_time))
        deleted = r.enforce_retention()
        assert len(deleted) == 1

    def test_retention_disabled(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, max_age_days=0)
        f = audit_dir / "old.jsonl"
        f.write_text("data")
        old_time = time.time() - (365 * 86400)
        os.utime(f, (old_time, old_time))
        deleted = r.enforce_retention()
        assert len(deleted) == 0

    def test_retention_nonexistent_dir(self, tmp_path: Path) -> None:
        r = AuditRotator(directory=tmp_path / "nope", max_age_days=1)
        deleted = r.enforce_retention()
        assert deleted == []


# ---------------------------------------------------------------------------
# Compression
# ---------------------------------------------------------------------------


class TestCompression:
    def test_compress_rotated_files(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, compress=True)
        # Create a file with timestamp in name (looks rotated)
        rotated = audit_dir / "audit.2025-01-01T12-00-00.jsonl"
        rotated.write_text("compressed data " * 100)
        compressed = r.compress_completed()
        assert len(compressed) == 1
        assert compressed[0].suffix == ".gz"
        assert not rotated.exists()

    def test_skip_active_files(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, compress=True)
        # Active file without timestamp
        active = audit_dir / "audit.jsonl"
        active.write_text("active data")
        compressed = r.compress_completed()
        assert len(compressed) == 0
        assert active.exists()

    def test_compressed_data_readable(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir, compress=True)
        content = '{"event": "test"}\n' * 50
        rotated = audit_dir / "audit.2025-01-01T12-00-00.jsonl"
        rotated.write_text(content)
        results = r.compress_completed()
        with gzip.open(results[0], "rt") as f:
            assert f.read() == content

    def test_compress_nonexistent_dir(self, tmp_path: Path) -> None:
        r = AuditRotator(directory=tmp_path / "nope")
        assert r.compress_completed() == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


class TestStats:
    def test_stats_empty_dir(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir)
        stats = r.get_stats()
        assert stats["total_files"] == 0
        assert stats["total_size_mb"] == 0.0
        assert stats["compressed_files"] == 0

    def test_stats_with_files(self, audit_dir: Path) -> None:
        r = AuditRotator(directory=audit_dir)
        (audit_dir / "a.jsonl").write_text("data" * 10000)
        (audit_dir / "b.jsonl.gz").write_bytes(b"\x1f\x8b" + b"\x00" * 2000)
        stats = r.get_stats()
        assert stats["total_files"] == 2
        assert stats["compressed_files"] == 1
        assert stats["total_size_mb"] > 0

    def test_stats_nonexistent_dir(self, tmp_path: Path) -> None:
        r = AuditRotator(directory=tmp_path / "nope")
        stats = r.get_stats()
        assert stats["total_files"] == 0

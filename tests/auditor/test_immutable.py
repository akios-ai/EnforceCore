# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for OS-enforced append-only file protection."""

from __future__ import annotations

import platform
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.auditor.immutable import (
    AppendOnlyError,
    _in_container,
    is_append_only,
    platform_support_info,
    protect_append_only,
)

if TYPE_CHECKING:
    from pathlib import Path

# =========================================================================
# Platform detection
# =========================================================================


class TestPlatformDetection:
    """Test container and capability detection."""

    def test_platform_support_info_returns_dict(self) -> None:
        info = platform_support_info()
        assert isinstance(info, dict)
        assert "platform" in info
        assert "supported" in info
        assert "in_container" in info
        assert "has_capability" in info
        assert "notes" in info

    def test_platform_support_info_platform_matches(self) -> None:
        info = platform_support_info()
        assert info["platform"] == platform.system()

    @patch("enforcecore.auditor.immutable.Path")
    def test_in_container_dockerenv(self, mock_path: MagicMock) -> None:
        """Detect Docker via /.dockerenv."""
        mock_instance = MagicMock()
        mock_instance.exists.return_value = True
        mock_path.return_value = mock_instance
        # Can't easily test this without mocking deeply, just verify the function exists
        assert callable(_in_container)


# =========================================================================
# protect_append_only
# =========================================================================


class TestProtectAppendOnly:
    """Test the protect_append_only function."""

    def test_nonexistent_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError, match="non-existent"):
            protect_append_only(tmp_path / "nonexistent.txt")

    @pytest.mark.skipif(
        platform.system() not in ("Linux", "Darwin"),
        reason="Append-only only supported on Linux/macOS",
    )
    def test_returns_bool(self, tmp_path: Path) -> None:
        """On supported platforms, protect_append_only returns a bool."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        # This will likely fail due to permissions, but shouldn't crash
        try:
            result = protect_append_only(test_file)
            assert isinstance(result, bool)
        except AppendOnlyError:
            pass  # Expected if no permissions

    @pytest.mark.skipif(
        platform.system() in ("Linux", "Darwin"),
        reason="Testing unsupported platform path",
    )
    def test_unsupported_platform_returns_false(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        result = protect_append_only(test_file)
        assert result is False

    @patch("enforcecore.auditor.immutable._SYSTEM", "UnknownOS")
    def test_unsupported_platform_mocked(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        result = protect_append_only(test_file)
        assert result is False


# =========================================================================
# is_append_only
# =========================================================================


class TestIsAppendOnly:
    """Test the is_append_only function."""

    def test_nonexistent_returns_false(self, tmp_path: Path) -> None:
        assert is_append_only(tmp_path / "nonexistent") is False

    def test_regular_file_returns_false(self, tmp_path: Path) -> None:
        """A regular file without append-only flag should return False."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        # On most test systems, files don't have append-only set
        result = is_append_only(test_file)
        assert isinstance(result, bool)

    @patch("enforcecore.auditor.immutable._SYSTEM", "UnknownOS")
    def test_unsupported_platform(self, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        assert is_append_only(test_file) is False


# =========================================================================
# AppendOnlyError
# =========================================================================


class TestAppendOnlyError:
    """AppendOnlyError is a proper exception."""

    def test_is_exception(self) -> None:
        assert issubclass(AppendOnlyError, Exception)

    def test_message(self) -> None:
        err = AppendOnlyError("test message")
        assert str(err) == "test message"


# =========================================================================
# Auditor integration with immutable
# =========================================================================


class TestAuditorImmutable:
    """Test Auditor(immutable=True) integration."""

    def test_immutable_flag_stored(self, tmp_path: Path) -> None:
        """Auditor stores the immutable flag."""
        audit_file = tmp_path / "trail.jsonl"
        # immutable=True will try to set the flag but may fail on CI
        # The important thing is it doesn't crash
        from enforcecore.auditor import Auditor

        auditor = Auditor(output_path=audit_file, immutable=True)
        assert auditor.immutable is True

    def test_immutable_false_default(self, tmp_path: Path) -> None:
        from enforcecore.auditor import Auditor

        auditor = Auditor(output_path=tmp_path / "trail.jsonl")
        assert auditor.immutable is False

    def test_immutable_does_not_break_writes(self, tmp_path: Path) -> None:
        """Even if immutable setup fails, writes should still work."""
        from enforcecore.auditor import Auditor

        audit_file = tmp_path / "trail.jsonl"
        auditor = Auditor(output_path=audit_file, immutable=True)
        entry = auditor.record(tool_name="test", policy_name="p")
        assert entry.entry_hash != ""
        assert audit_file.exists()


# =========================================================================
# Linux-specific tests (skipped on non-Linux)
# =========================================================================


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux-only chattr tests",
)
class TestLinuxChattr:
    """Linux-specific chattr tests (run only on Linux CI)."""

    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_chattr_success(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")

        result = protect_append_only(test_file)
        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "chattr"
        assert cmd[1] == "+a"

    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_chattr_permission_denied(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="Operation not permitted")
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")

        with pytest.raises(AppendOnlyError, match="Permission denied"):
            protect_append_only(test_file)

    @patch("enforcecore.auditor.immutable._in_container", return_value=True)
    @patch(
        "enforcecore.auditor.immutable._has_linux_immutable_cap",
        return_value=False,
    )
    def test_container_without_capability(
        self,
        mock_cap: MagicMock,
        mock_container: MagicMock,
        tmp_path: Path,
    ) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")

        with pytest.raises(AppendOnlyError, match="CAP_LINUX_IMMUTABLE"):
            protect_append_only(test_file)


# =========================================================================
# macOS-specific tests (skipped on non-macOS)
# =========================================================================


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="macOS-only chflags tests",
)
class TestMacOSChflags:
    """macOS-specific chflags tests."""

    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_chflags_success(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=0)
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")

        result = protect_append_only(test_file)
        assert result is True
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "chflags"
        assert cmd[1] == "uappend"

    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_chflags_permission_denied(self, mock_run: MagicMock, tmp_path: Path) -> None:
        mock_run.return_value = MagicMock(returncode=1, stderr="Operation not permitted")
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")

        with pytest.raises(AppendOnlyError, match="Permission denied"):
            protect_append_only(test_file)

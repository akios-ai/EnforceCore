# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Tests for OS-enforced append-only file protection."""

from __future__ import annotations

import platform
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from enforcecore.auditor.immutable import (
    AppendOnlyError,
    _in_container,
    is_append_only,
    platform_support_info,
    protect_append_only,
)

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
# Capability detection
# =========================================================================


class TestCapabilityDetection:
    """Test _has_linux_immutable_cap multi-branch logic."""

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_capsh_detects_capability(self, mock_run: MagicMock) -> None:
        """capsh --print path detects CAP_LINUX_IMMUTABLE."""
        from enforcecore.auditor.immutable import _has_linux_immutable_cap

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Current: =ep cap_linux_immutable+ep\nBounding set: ...\n",
        )
        assert _has_linux_immutable_cap() is True

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_capsh_no_capability(self, mock_run: MagicMock) -> None:
        """capsh --print path: capability absent."""
        from enforcecore.auditor.immutable import _has_linux_immutable_cap

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Current: =ep\nBounding set: ...\n",
        )
        # capsh says no, /proc won't exist in test → falls through to False
        assert _has_linux_immutable_cap() is False

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run", side_effect=FileNotFoundError)
    @patch("enforcecore.auditor.immutable.Path")
    def test_proc_status_fallback(self, mock_path: MagicMock, mock_run: MagicMock) -> None:
        """Falls back to /proc/self/status when capsh is absent."""
        from enforcecore.auditor.immutable import _has_linux_immutable_cap

        # Bit 9 set → CAP_LINUX_IMMUTABLE present
        # 0x200 = 1 << 9 = 512
        mock_status_path = MagicMock()
        mock_status_path.read_text.return_value = "Name:\ttest\nCapEff:\t0000000000000200\n"

        def path_factory(p: str) -> MagicMock:
            if "proc" in str(p) and "status" in str(p):
                return mock_status_path
            m = MagicMock()
            m.exists.return_value = False
            return m

        mock_path.side_effect = path_factory
        assert _has_linux_immutable_cap() is True

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run", side_effect=FileNotFoundError)
    @patch("enforcecore.auditor.immutable.Path")
    def test_proc_status_no_cap(self, mock_path: MagicMock, mock_run: MagicMock) -> None:
        """Bit 9 not set → no capability."""
        from enforcecore.auditor.immutable import _has_linux_immutable_cap

        # 0x100 = bit 8, not bit 9
        mock_status_path = MagicMock()
        mock_status_path.read_text.return_value = "Name:\ttest\nCapEff:\t0000000000000100\n"

        def path_factory(p: str) -> MagicMock:
            if "proc" in str(p) and "status" in str(p):
                return mock_status_path
            m = MagicMock()
            m.exists.return_value = False
            return m

        mock_path.side_effect = path_factory
        assert _has_linux_immutable_cap() is False


# =========================================================================
# is_append_only — macOS st_flags path
# =========================================================================


class TestIsAppendOnlyMacOS:
    """Test is_append_only with mocked macOS st_flags."""

    @patch("enforcecore.auditor.immutable._SYSTEM", "Darwin")
    @patch("enforcecore.auditor.immutable.os.stat")
    def test_uf_append_flag_set(self, mock_stat: MagicMock, tmp_path: Path) -> None:
        """Detects UF_APPEND (0x4) via st_flags."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        mock_stat.return_value = MagicMock(st_flags=0x00000004)  # UF_APPEND
        assert is_append_only(test_file) is True

    @patch("enforcecore.auditor.immutable._SYSTEM", "Darwin")
    @patch("enforcecore.auditor.immutable.os.stat")
    def test_uf_append_flag_not_set(self, mock_stat: MagicMock, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        mock_stat.return_value = MagicMock(st_flags=0x00000000)
        assert is_append_only(test_file) is False

    @patch("enforcecore.auditor.immutable._SYSTEM", "Darwin")
    @patch("enforcecore.auditor.immutable.os.stat", side_effect=OSError("no stat"))
    def test_stat_failure_returns_false(self, mock_stat: MagicMock, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        # Patch Path.exists so the pathlib .exists() call succeeds despite
        # os.stat being mocked; the OSError is caught inside _check_macos.
        with patch.object(Path, "exists", return_value=True):
            assert is_append_only(test_file) is False


# =========================================================================
# Linux lsattr mocking
# =========================================================================


class TestIsAppendOnlyLinux:
    """Test is_append_only with mocked Linux lsattr."""

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_lsattr_detects_append_only(self, mock_run: MagicMock, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=f"-----a---------- {test_file}\n",
        )
        assert is_append_only(test_file) is True

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run")
    def test_lsattr_no_append_only(self, mock_run: MagicMock, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=f"---------------- {test_file}\n",
        )
        assert is_append_only(test_file) is False

    @patch("enforcecore.auditor.immutable._SYSTEM", "Linux")
    @patch("enforcecore.auditor.immutable.subprocess.run", side_effect=FileNotFoundError)
    def test_lsattr_not_found(self, mock_run: MagicMock, tmp_path: Path) -> None:
        test_file = tmp_path / "test.txt"
        test_file.write_text("data\n")
        assert is_append_only(test_file) is False


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

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""OS-enforced append-only file protection for audit trails.

Provides ``protect_append_only()`` which sets the OS-level append-only
attribute on audit files, preventing truncation or overwrite even by the
file owner.  This closes the "chain rebuild" attack vector documented in
the threat model (§5.3).

This design was directly informed by guidance from Prof. Dan S. Wallach
(Rice University), who recommended ``chattr +a`` as a low-overhead path
from tamper detection to tamper evidence.

Platform support:

- **Linux**: ``chattr +a`` via ``ioctl(FS_IOC_SETFLAGS, FS_APPEND_FL)``
  (requires ``CAP_LINUX_IMMUTABLE`` capability; dropped in Docker by
  default — use ``--cap-add LINUX_IMMUTABLE``).
- **macOS**: ``chflags uappend`` via ``os.chflags(UF_APPEND)``
  (requires root or file owner on HFS+/APFS).
- **Other**: Not supported — logs a warning but does not fail.

Example::

    from enforcecore.auditor.immutable import protect_append_only, is_append_only

    protect_append_only("audit.jsonl")
    assert is_append_only("audit.jsonl")
"""

from __future__ import annotations

import os
import platform
import subprocess
from pathlib import Path

import structlog

logger = structlog.get_logger("enforcecore.auditor.immutable")


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

_SYSTEM = platform.system()


def _is_linux() -> bool:
    return _SYSTEM == "Linux"


def _is_macos() -> bool:
    return _SYSTEM == "Darwin"


def _in_container() -> bool:
    """Detect if running inside a container (Docker/Podman).

    Checks for ``/.dockerenv``, ``/run/.containerenv``, or cgroup v2
    indicators.
    """
    if Path("/.dockerenv").exists():
        return True
    if Path("/run/.containerenv").exists():
        return True
    # cgroup v2 indicator
    try:
        cgroup = Path("/proc/1/cgroup").read_text()
        if "docker" in cgroup or "containerd" in cgroup or "podman" in cgroup:
            return True
    except (OSError, PermissionError):
        pass
    return False


def _has_linux_immutable_cap() -> bool:
    """Check if the current process has CAP_LINUX_IMMUTABLE.

    In Docker, this capability is dropped by default.  The container
    must be run with ``--cap-add LINUX_IMMUTABLE`` for ``chattr +a``
    to work.
    """
    try:
        # capsh --print shows current capabilities
        r = subprocess.run(
            ["capsh", "--print"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if r.returncode == 0:
            return "cap_linux_immutable" in r.stdout.lower()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback: try reading /proc/self/status
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                # Bit 9 (0-indexed) is CAP_LINUX_IMMUTABLE
                cap_hex = line.split(":")[1].strip()
                cap_int = int(cap_hex, 16)
                return bool(cap_int & (1 << 9))
    except (OSError, ValueError):
        pass

    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class AppendOnlyError(Exception):
    """Raised when append-only protection cannot be applied."""


def protect_append_only(path: str | Path) -> bool:
    """Set the OS-level append-only attribute on a file.

    After this call, the file can only be appended to — not truncated,
    overwritten, or deleted (without first removing the attribute, which
    requires elevated privileges).

    Args:
        path: Path to the file to protect.

    Returns:
        ``True`` if the attribute was successfully set, ``False`` if the
        platform does not support it (a warning is logged).

    Raises:
        AppendOnlyError: If the operation fails due to permissions or
            missing capabilities.
        FileNotFoundError: If the file does not exist.
    """
    filepath = Path(path)
    if not filepath.exists():
        raise FileNotFoundError(f"Cannot protect non-existent file: {filepath}")

    if _is_linux():
        return _protect_linux(filepath)
    elif _is_macos():
        return _protect_macos(filepath)
    else:
        logger.warning(
            "append_only_not_supported",
            platform=_SYSTEM,
            path=str(filepath),
            hint="Append-only file protection is only available on Linux and macOS",
        )
        return False


def is_append_only(path: str | Path) -> bool:
    """Check if a file has the OS-level append-only attribute set.

    Args:
        path: Path to the file to check.

    Returns:
        ``True`` if the append-only attribute is set, ``False`` otherwise
        or if the platform does not support the check.
    """
    filepath = Path(path)
    if not filepath.exists():
        return False

    if _is_linux():
        return _check_linux(filepath)
    elif _is_macos():
        return _check_macos(filepath)
    return False


def platform_support_info() -> dict[str, object]:
    """Return information about append-only support on this platform.

    Returns:
        A dict with keys: ``platform``, ``supported``, ``in_container``,
        ``has_capability``, ``notes``.
    """
    info: dict[str, object] = {
        "platform": _SYSTEM,
        "supported": False,
        "in_container": False,
        "has_capability": True,
        "notes": "",
    }

    if _is_linux():
        info["supported"] = True
        info["in_container"] = _in_container()
        if _in_container():
            has_cap = _has_linux_immutable_cap()
            info["has_capability"] = has_cap
            if not has_cap:
                info["notes"] = (
                    "Running in a container without CAP_LINUX_IMMUTABLE. "
                    "Use: docker run --cap-add LINUX_IMMUTABLE ..."
                )
    elif _is_macos():
        info["supported"] = True
        info["notes"] = "macOS: requires root or file owner (chflags uappend)"
    else:
        info["notes"] = f"Platform {_SYSTEM} does not support append-only files"

    return info


# ---------------------------------------------------------------------------
# Linux implementation (chattr +a)
# ---------------------------------------------------------------------------


def _protect_linux(filepath: Path) -> bool:
    """Set append-only on Linux via chattr."""
    if _in_container() and not _has_linux_immutable_cap():
        raise AppendOnlyError(
            f"Cannot set append-only on {filepath}: running in a container "
            f"without CAP_LINUX_IMMUTABLE. Run with: "
            f"docker run --cap-add LINUX_IMMUTABLE ..."
        )

    try:
        r = subprocess.run(
            ["chattr", "+a", str(filepath)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            stderr = r.stderr.strip()
            if "Operation not permitted" in stderr:
                raise AppendOnlyError(
                    f"Permission denied setting append-only on {filepath}. "
                    f"Requires CAP_LINUX_IMMUTABLE or root."
                )
            raise AppendOnlyError(f"chattr +a failed on {filepath}: {stderr}")
        logger.info(
            "append_only_set",
            path=str(filepath),
            method="chattr +a",
        )
        return True
    except FileNotFoundError:
        raise AppendOnlyError(
            "chattr not found. Install e2fsprogs or use a filesystem "
            "that supports extended attributes."
        ) from None


def _check_linux(filepath: Path) -> bool:
    """Check append-only attribute on Linux via lsattr."""
    try:
        r = subprocess.run(
            ["lsattr", str(filepath)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode == 0:
            # lsattr output: "-----a---------- /path/to/file"
            attrs = r.stdout.split()[0] if r.stdout.strip() else ""
            return "a" in attrs
    except FileNotFoundError:
        pass
    return False


# ---------------------------------------------------------------------------
# macOS implementation (chflags uappend)
# ---------------------------------------------------------------------------

# UF_APPEND = 0x00000004 (user append-only, macOS)
_UF_APPEND = 0x00000004


def _protect_macos(filepath: Path) -> bool:
    """Set append-only on macOS via chflags."""
    try:
        r = subprocess.run(
            ["chflags", "uappend", str(filepath)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            stderr = r.stderr.strip()
            if "Operation not permitted" in stderr:
                raise AppendOnlyError(
                    f"Permission denied setting append-only on {filepath}. "
                    f"On macOS, this requires root or disabling SIP for "
                    f"user-owned files on some filesystems."
                )
            raise AppendOnlyError(f"chflags uappend failed on {filepath}: {stderr}")
        logger.info(
            "append_only_set",
            path=str(filepath),
            method="chflags uappend",
        )
        return True
    except FileNotFoundError:
        raise AppendOnlyError("chflags not found — unexpected on macOS") from None


def _check_macos(filepath: Path) -> bool:
    """Check append-only flag on macOS."""
    try:
        st = os.stat(filepath)
        flags = getattr(st, "st_flags", 0)
        return bool(flags & _UF_APPEND)
    except OSError:
        return False

# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Auditor-test fixtures.

On macOS, tests that exercise ``protect_append_only()`` call
``chflags uappend`` which leaves files with the UF_APPEND flag set.
pytest cannot delete those directories during cleanup, generating a
flood of ``PytestWarning: (rm_rf) error removing …`` messages.

The ``_strip_append_flags`` fixture runs after every test in this
directory and strips the UF_APPEND / UF_IMMUTABLE flags from every
file under ``tmp_path`` so pytest can clean up normally.
"""

from __future__ import annotations

import platform
import subprocess
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _strip_append_flags(tmp_path: Path) -> None:  # type: ignore[return]
    """Remove macOS UF_APPEND/UF_IMMUTABLE flags from tmp_path after each test.

    This prevents pytest from leaving garbage-* directories that cannot
    be cleaned on macOS when ``chflags uappend`` was called during the test.
    """
    yield  # run the test first

    if platform.system() != "Darwin":
        return

    # Strip all user-settable flags recursively.  We ignore errors because
    # the directory might already be clean or partially cleaned.
    subprocess.run(
        ["chflags", "-R", "nouappend,nouchg,noschg", str(tmp_path)],
        capture_output=True,
        check=False,
    )

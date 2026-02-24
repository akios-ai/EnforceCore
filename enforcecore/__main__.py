# Copyright 2026 AKIOUD AI
# SPDX-License-Identifier: Apache-2.0
"""Allow ``python -m enforcecore`` to launch the CLI.

Falls back to a version/help message when the ``cli`` extra is not installed.
"""

from __future__ import annotations

import sys


def main() -> None:
    """Entry-point for ``python -m enforcecore``."""
    try:
        from enforcecore.cli.main import app

        app()
    except SystemExit:
        # Re-raise clean exit from the CLI import guard
        raise
    except ImportError:
        import enforcecore

        print(f"EnforceCore v{enforcecore.__version__}")
        print()
        print("The CLI requires extra dependencies. Install them with:")
        print()
        print("    pip install enforcecore[cli]")
        sys.exit(1)


if __name__ == "__main__":
    main()

"""Allow ``python -m benchmarks`` as an alias for ``python -m benchmarks.run``."""

from __future__ import annotations

from benchmarks.run import main

if __name__ == "__main__":
    main()

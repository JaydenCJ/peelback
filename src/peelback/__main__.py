"""Allow ``python -m peelback`` to behave exactly like the console script."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())

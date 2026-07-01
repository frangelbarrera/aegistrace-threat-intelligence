"""Backward-compatible entry point.

This module lives at the repository root so that ``python main.py``
keeps working exactly as it did before the package restructure. It
delegates to :func:`aegistrace.main.run`.
"""

from __future__ import annotations

import sys

from aegistrace.cli import main

if __name__ == "__main__":
    sys.exit(main())

"""Logging configuration for AegisTrace.

Provides a single ``get_logger`` helper that every module should use so
that all log records share the same format and verbosity. Logging goes to
stderr by default; an optional rotating file handler can be enabled via
the ``AEGISTRACE_LOG_FILE`` environment variable.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from typing import Final

_DEFAULT_FORMAT: Final[str] = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_CONFIGURED: bool = False


def _configure_root() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return

    level_name = os.getenv("AEGISTRACE_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    log_file = os.getenv("AEGISTRACE_LOG_FILE")
    if log_file:
        handlers.append(
            RotatingFileHandler(log_file, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
        )

    logging.basicConfig(level=level, format=_DEFAULT_FORMAT, handlers=handlers, force=True)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a configured logger with the given hierarchical name."""
    _configure_root()
    return logging.getLogger(name)

"""Diagnostic log: <out>/lazyios.log, owner-only, rotated, never sent anywhere.

Holds what the screen keeps short: tracebacks of unexpected errors and library warnings. It
never gets packet payloads; at the default level (warning) it stays empty in normal use.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .files import private_dir

FILE = "lazyios.log"
MAX_BYTES = 512 * 1024
BACKUPS = 3
LEVELS = ("debug", "info", "warning", "error")
log = logging.getLogger("lazyios")


class PrivateRotatingHandler(RotatingFileHandler):
    """RotatingFileHandler whose files (the rotated ones too) are created 0600."""

    def _open(self):  # type: ignore[no-untyped-def]
        fd = os.open(self.baseFilename, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        return os.fdopen(fd, "a", encoding=self.encoding or "utf-8", errors=self.errors)


def setup(folder: Path, level: str = "warning") -> Path:
    """Send this process's log records (lazyios and its libraries) to folder/lazyios.log."""
    path = private_dir(folder) / FILE
    handler = PrivateRotatingHandler(path, maxBytes=MAX_BYTES, backupCount=BACKUPS,
                                     encoding="utf-8", delay=True)  # fmt: skip
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    for old in [h for h in root.handlers if isinstance(h, PrivateRotatingHandler)]:
        root.removeHandler(old)
        old.close()
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper()))
    return path

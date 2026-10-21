"""Output files: captures, screenshots and reports hold private data, so owner-only."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import BinaryIO


def private_dir(path: Path) -> Path:
    """Create path (and parents) and make it owner-only, also when it already existed.
    On Windows the user profile ACLs already keep other users out."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        path.chmod(0o700)
    return path


def create_private(path: Path) -> BinaryIO:
    """Open a new file for writing, 0600; refuses to reuse or follow an existing path."""
    private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def write_private(path: Path, data: bytes) -> Path:
    with create_private(path) as out:
        out.write(data)
    return path

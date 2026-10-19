"""Open files with an external program."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

WIRESHARK_WINDOWS = Path(r"C:\Program Files\Wireshark\Wireshark.exe")


def find_wireshark() -> str | None:
    if found := shutil.which("wireshark"):
        return found
    if sys.platform == "win32" and WIRESHARK_WINDOWS.exists():
        return str(WIRESHARK_WINDOWS)
    return None


def open_default(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(path.resolve())  # noqa: S606
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path.resolve())])


def open_capture(path: Path) -> str:
    """Open a capture in Wireshark if present, else with the OS handler; returns the program."""
    if wireshark := find_wireshark():
        subprocess.Popen([wireshark, "-r", str(path.resolve())])
        return "wireshark"
    open_default(path)
    return "default viewer"

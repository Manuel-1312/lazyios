"""Reaching usbmuxd, and what to tell the user when it is missing."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

HOST = ("127.0.0.1", 27015)  # usbmuxd on Windows
START_WAIT = 6.0
_QUIET = getattr(subprocess, "CREATE_NO_WINDOW", 0)

HINTS = {
    "win32": (
        "install Apple Devices from the Microsoft Store "
        "(winget install 9NP83LWLPZ9K -s msstore) or iTunes, then replug the iphone"
    ),
    "darwin": "usbmuxd comes with macOS: replug the iphone and try again",
    "linux": "install usbmuxd (sudo apt install usbmuxd, or your distro's package) and replug",
}


def hint(platform: str | None = None) -> str:
    return HINTS.get(platform or sys.platform, HINTS["linux"])


def reachable() -> bool:
    try:
        socket.create_connection(HOST, timeout=1).close()
    except OSError:
        return False
    return True


def _launcher() -> Path | None:
    """Apple Devices store app launcher; its folder cannot be listed but the path works."""
    try:
        out = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "(Get-AppxPackage AppleInc.AppleDevices).InstallLocation",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=_QUIET,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    path = Path(out) / "AppleMobileDeviceLauncher.exe" if out else None
    return path if path is not None and path.exists() else None


def _itunes_service_stopped() -> bool:
    try:
        out = subprocess.run(
            ["sc", "query", "Apple Mobile Device Service"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=_QUIET,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return "STOPPED" in out


def start_apple_devices() -> str | None:
    """Windows failure path: try to bring usbmuxd up; None when it answers, else a message."""
    if sys.platform != "win32" or reachable():
        return None if sys.platform == "win32" else hint()
    if launcher := _launcher():
        subprocess.Popen([str(launcher)], creationflags=_QUIET)
        deadline = time.monotonic() + START_WAIT
        while time.monotonic() < deadline:
            if reachable():
                return None
            time.sleep(0.5)
        return "started Apple Devices but usbmuxd did not answer, try again in a moment"
    if _itunes_service_stopped():
        return (
            "the Apple Mobile Device Service is stopped: start it from services.msc (needs admin)"
        )
    return hint()

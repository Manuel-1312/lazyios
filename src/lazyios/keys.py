"""Configurable shortcuts: <out>/keys.json maps binding ids to keys, e.g.

    {"capture": "c", "devices": "ctrl+d", "quit": "ctrl+q"}

An id applies wherever that binding appears (capture is space in three tabs). The file is
untrusted input: an unknown id or a strange key rejects it as a whole and defaults apply.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .files import read_config

FILE = "keys.json"
IDS = (
    "quit", "help", "devices", "capture", "filter", "refresh", "export", "open", "sort",
    "kill", "launch", "monitor", "audit", "pause", "clear", "reconnect", "trackers",
    "new-only", "criteria", "watch-processes", "screenshot", "coords", "fps",
    "clear-condition", "clear-location", "grow", "shrink", "level",
)  # fmt: skip
_KEY = re.compile(r"[A-Za-z0-9_+]{1,30}(?:,[A-Za-z0-9_+]{1,30}){0,3}")


def parse(text: str) -> dict[str, str]:
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"not valid JSON (line {getattr(e, 'lineno', '?')})") from None
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object of id: key")
    if unknown := sorted(str(k) for k in set(data) - set(IDS)):
        raise ValueError(f"unknown ids: {', '.join(unknown)[:80]}")
    for name, key in data.items():
        if not isinstance(key, str) or not _KEY.fullmatch(key):
            raise ValueError(f"{name}: {str(key)[:30]!r} is not a key like 'c', 'f5' or 'ctrl+d'")
    return dict(data)


def load(folder: Path) -> tuple[dict[str, str], str | None]:
    return read_config(folder / FILE, parse, {})

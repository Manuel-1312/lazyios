"""Session history: what each app talked to in earlier captures, kept locally to compare against.

One owner-only JSON file per capture in <out>/sessions. Only named domains are kept (addresses
change too often to compare), never payloads or IPs. Files are read back as untrusted input.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .backend import App
from .files import write_private
from .parsing import clean_text, sanitize_host
from .privacy import HostRow

FORMAT = 1
KEEP = 30  # sessions kept on disk; older ones are deleted
BASELINE = 10  # sessions of the same device a capture is compared with
MAX_FILE = 4 * 1024 * 1024
MAX_APPS = 2000
MAX_DOMAINS = 2000
COMM_LEN = 16  # the kernel keeps this much of a process name, and pcapd reports that


@dataclass(frozen=True)
class AppHistory:
    version: str | None
    domains: dict[str, str]  # domain -> category, "" when not in the tracker data
    bytes: int = 0


@dataclass(frozen=True)
class Session:
    started: str
    udid: str
    apps: dict[str, AppHistory]
    seconds: float = 0.0  # first to last packet


@dataclass
class Change:
    """How an app's traffic differs from the earlier sessions of the same device."""

    known: bool = False  # the app shows up in at least one earlier session
    new_domains: list[str] = field(default_factory=list)
    new_trackers: list[str] = field(default_factory=list)
    previous_version: str | None = None


def versions_by_process(apps: Iterable[App]) -> dict[str, str]:
    """Process name -> app version, only where the name points at exactly one app (every Flutter
    app is called Runner, for one) and the version is known."""
    seen: dict[str, set[str]] = {}
    for app in apps:
        if app.executable:
            for name in {app.executable, app.executable[:COMM_LEN]}:
                seen.setdefault(name, set()).add(f"{app.bundle_id}\x00{app.version}")
    return {
        name: next(iter(found)).split("\x00", 1)[1]
        for name, found in seen.items()
        if len(found) == 1 and next(iter(found)).split("\x00", 1)[1]
    }


def snapshot(
    rows: Iterable[HostRow], versions: dict[str, str], udid: str, when: datetime
) -> dict[str, Any]:
    rows = list(rows)
    apps: dict[str, dict[str, Any]] = {}
    for r in rows:
        entry = apps.setdefault(
            r.process, {"version": versions.get(r.process), "bytes": 0, "domains": {}}
        )
        entry["bytes"] += r.bytes
        if r.source != "ip":
            entry["domains"][r.domain] = r.category
    seconds = max(r.last for r in rows) - min(r.first for r in rows) if rows else 0.0
    return {
        "format": FORMAT,
        "started": when.isoformat(timespec="seconds"),
        "udid": udid,
        "seconds": round(seconds, 3),
        "apps": apps,
    }


def save(folder: Path, data: dict[str, Any], keep: int = KEEP, now: datetime | None = None) -> Path:
    """Write one session and delete the oldest beyond `keep`."""
    now = now or datetime.now()
    path = folder / f"session-{now.strftime('%Y%m%d-%H%M%S-%f')[:-3]}.json"
    write_private(path, (json.dumps(data, indent=1) + "\n").encode())
    files = sorted(folder.glob("session-*.json"))
    for old in files[: max(0, len(files) - keep)]:
        old.unlink(missing_ok=True)
    return path


def parse(text: str) -> Session | None:
    """A session from file content; None for anything that is not exactly the expected shape."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        return None
    started, udid, apps = data.get("started"), data.get("udid"), data.get("apps")
    if not (isinstance(started, str) and isinstance(udid, str) and isinstance(apps, dict)):
        return None
    seconds = data.get("seconds", 0.0)
    if len(apps) > MAX_APPS or not _count(seconds, float):
        return None
    out: dict[str, AppHistory] = {}
    for name, entry in apps.items():
        if not (isinstance(name, str) and isinstance(entry, dict)):
            return None
        version, domains, size = entry.get("version"), entry.get("domains"), entry.get("bytes", 0)
        if version is not None and not isinstance(version, str) or not _count(size, int):
            return None
        if not isinstance(domains, dict) or len(domains) > MAX_DOMAINS:
            return None
        clean = {
            host: clean_text(category, 32)
            for domain, category in domains.items()
            if isinstance(category, str) and (host := sanitize_host(domain))
        }
        out[clean_text(name)] = AppHistory(clean_text(version) if version else None, clean, size)
    return Session(clean_text(started, 32), clean_text(udid), out, float(seconds))


def _count(value: object, kind: type) -> bool:
    """A non-negative int (or, for float, any non-negative number); never a bool."""
    numbers = (int, float) if kind is float else (int,)
    return not isinstance(value, bool) and isinstance(value, numbers) and value >= 0


def load(folder: Path, limit: int = KEEP) -> list[Session]:
    """The newest sessions, oldest first; unreadable or malformed files are skipped."""
    if not folder.is_dir():
        return []
    sessions: list[Session] = []
    for path in sorted(folder.glob("session-*.json"))[-limit:]:
        try:
            if path.stat().st_size > MAX_FILE:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if (session := parse(text)) is not None:
            sessions.append(session)
    return sessions


def baseline(sessions: list[Session], udid: str | None, limit: int = BASELINE) -> list[Session]:
    """The latest sessions of this device (all of them when the device is not known yet)."""
    mine = [s for s in sessions if udid is None or s.udid == udid]
    return mine[-limit:]


def domains_by_app(earlier: list[Session]) -> dict[str, set[str]]:
    history: dict[str, set[str]] = {}
    for session in earlier:
        for name, app in session.apps.items():
            history.setdefault(name, set()).update(app.domains)
    return history


def compare(rows: Iterable[HostRow], earlier: list[Session]) -> dict[str, Change]:
    """Per app: named domains not contacted in the earlier sessions, and the trackers among them."""
    history = domains_by_app(earlier)
    last_version = {  # oldest first, so the latest version wins
        name: app.version for s in earlier for name, app in s.apps.items() if app.version
    }
    changes: dict[str, Change] = {}
    for r in rows:
        change = changes.setdefault(
            r.process, Change(r.process in history, previous_version=last_version.get(r.process))
        )
        if r.source == "ip" or r.domain in history.get(r.process, ()):
            continue
        if r.domain not in change.new_domains:
            change.new_domains.append(r.domain)
            if r.tracker:
                change.new_trackers.append(r.domain)
    return changes

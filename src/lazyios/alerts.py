"""Alert rules for domains seen during a capture, read from <out>/alerts.json.

    {
      "new_tracker": true,       a tracker the app did not contact in earlier sessions
      "tracker": false,          any tracker, new or not
      "new_domain": false,       any named domain the app did not contact before
      "watch": ["facebook.com"]  these domains and their subdomains, always
    }

"new" needs history: an app with no earlier session never raises a new_* alert, or the first
capture would flag everything. The file is untrusted input: unknown keys or wrong types make it
rejected as a whole (defaults apply) and the reason is shown.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from pathlib import Path

from .files import read_config
from .parsing import sanitize_host
from .privacy import HostRow

FILE = "alerts.json"
MAX_FILE = 64 * 1024
MAX_WATCH = 500


@dataclass(frozen=True)
class AlertRules:
    new_tracker: bool = True
    tracker: bool = False
    new_domain: bool = False
    watch: tuple[str, ...] = ()

    def reason(self, row: HostRow, history: set[str] | None) -> str | None:
        """Why this (app, domain) row alerts, or None. history: the app's domains from earlier
        sessions, None when the app has none."""
        if row.source == "ip":
            return None
        if any(row.domain == w or row.domain.endswith("." + w) for w in self.watch):
            return "watched domain"
        new = history is not None and row.domain not in history
        if row.tracker and self.new_tracker and new:
            return f"new {row.category} tracker"
        if row.tracker and self.tracker:
            return f"{row.category} tracker"
        if self.new_domain and new:
            return "new domain"
        return None


def parse(text: str) -> AlertRules:
    """Raises ValueError with a message fit for the user."""
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"not valid JSON (line {getattr(e, 'lineno', '?')})") from None
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    known = {f.name for f in fields(AlertRules)}
    if unknown := sorted(set(data) - known):
        raise ValueError(f"unknown keys: {', '.join(map(str, unknown))[:80]}")
    for key in known - {"watch"}:
        if key in data and not isinstance(data[key], bool):
            raise ValueError(f"{key} must be true or false")
    watch = data.get("watch", [])
    if not isinstance(watch, list) or len(watch) > MAX_WATCH:
        raise ValueError(f"watch must be a list of at most {MAX_WATCH} domains")
    hosts = []
    for item in watch:
        host = sanitize_host(item) if isinstance(item, str) else None
        if host is None or "." not in host:
            raise ValueError(f"watch: {str(item)[:40]!r} is not a domain")
        hosts.append(host)
    return AlertRules(
        new_tracker=data.get("new_tracker", True),
        tracker=data.get("tracker", False),
        new_domain=data.get("new_domain", False),
        watch=tuple(dict.fromkeys(hosts)),
    )


def load(folder: Path) -> tuple[AlertRules, str | None]:
    """The rules in folder/alerts.json, or the defaults; the second item says what went wrong."""
    return read_config(folder / FILE, parse, AlertRules(), MAX_FILE)

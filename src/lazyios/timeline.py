"""Forensic timeline: one bounded, time-ordered list of what happened during the session.

Times are epoch seconds. Packet-based events (connections, interfaces) carry the device's capture
timestamp; everything else the computer's clock when lazyios saw it. Exports write both an ISO
8601 time with the UTC offset and the raw epoch value.
"""

from __future__ import annotations

import re
import time as clock
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .backend import LogLine, Process
from .files import Scrub, write_tables
from .parsing import clean_text

MAX_EVENTS = 20000
SYSLOG_WINDOW = 60.0  # one syslog error event per process per minute, with a count
KINDS = (
    "device", "error", "capture", "condition", "network", "connection",
    "app", "process", "syslog", "alert", "anomaly",
)  # fmt: skip


@dataclass(eq=False)  # identity: two identical lines are two events
class Event:
    time: float
    kind: str
    summary: str
    app: str = ""
    detail: str = ""
    source: str = "lazyios"
    count: int = 1
    seq: int = 0  # order of arrival: breaks ties, the clock ticks ~15 ms apart on Windows


def iso(when: float) -> str:
    return datetime.fromtimestamp(when).astimezone().isoformat(timespec="milliseconds")


class Timeline:
    def __init__(self) -> None:
        self.version = 0
        self._seq = 0
        self._events: deque[Event] = deque(maxlen=MAX_EVENTS)
        self._open_syslog: dict[tuple[str, str], Event] = {}  # (process, level) -> event

    def events(self) -> list[Event]:
        return list(self._events)

    def add(self, kind: str, summary: str, *, when: float | None = None, app: str = "",
            detail: str = "", source: str = "lazyios") -> Event:  # fmt: skip
        event = Event(
            clock.time() if when is None else when,
            kind,
            clean_text(summary, 200),
            clean_text(app),
            clean_text(detail, 500),
            source,
            seq=self._seq,
        )
        self._seq += 1
        self._events.append(event)
        self.version += 1
        return event

    def syslog(self, line: LogLine, when: float | None = None) -> None:
        """Faults one by one; errors folded into one event per process per minute."""
        if line.level not in ("error", "fault"):
            return
        now = clock.time() if when is None else when
        detail = f"device time {line.time}: {line.message}"
        if line.level == "fault":
            self.add("syslog", f"fault: {line.message}", when=now, app=line.process,
                     detail=detail, source="syslog")  # fmt: skip
            return
        key = (line.process, line.level)
        event = self._open_syslog.get(key)
        if event is not None and now - event.time < SYSLOG_WINDOW:
            event.count += 1
            event.summary = f"{event.count} errors within {SYSLOG_WINDOW:g} s"
            event.detail = clean_text(f"last, {detail}", 500)
            self.version += 1
            return
        if len(self._open_syslog) > 1000:
            self._open_syslog.clear()
        self._open_syslog[key] = self.add(
            "syslog", f"error: {line.message}", when=now, app=line.process, detail=detail,
            source="syslog",
        )  # fmt: skip


def process_events(
    before: dict[int, Process], now: dict[int, Process], when: float, interval: float
) -> list[tuple[str, str, str, str]]:
    """(kind, summary, app, detail) for processes that started or exited between two lists.
    A start has the device's own start time; an exit is only known to fall in the interval."""
    out = []
    for pid in sorted(now.keys() - before.keys()):
        p = now[pid]
        kind = "app" if p.is_app else "process"
        out.append((kind, f"started (pid {pid})", p.name, f"start time on device {p.started}"))
    for pid in sorted(before.keys() - now.keys()):
        p = before[pid]
        kind = "app" if p.is_app else "process"
        out.append((kind, f"exited (pid {pid})", p.name,
                    f"gone in the {interval:g} s before {iso(when)}"))  # fmt: skip
    return out


_RELATIVE = re.compile(r"^(\d+)([smh])$")
_CLOCK = re.compile(r"^(\d{1,2}):(\d{2})(?::(\d{2}))?$")
FIELDS = ("kind", "app", "since", "until", "last")


def _clock_time(value: str, today: datetime) -> float | None:
    m = _CLOCK.match(value)
    if not m or int(m[1]) > 23 or int(m[2]) > 59 or int(m[3] or 0) > 59:
        return None
    moment = today.replace(hour=int(m[1]), minute=int(m[2]), second=int(m[3] or 0), microsecond=0)
    return moment.timestamp()


@dataclass(frozen=True)
class Query:
    kinds: frozenset[str] = frozenset()
    app: str = ""
    since: float | None = None
    until: float | None = None
    words: tuple[str, ...] = ()

    def matches(self, e: Event) -> bool:
        if self.kinds and e.kind not in self.kinds:
            return False
        if self.app and self.app not in e.app.lower():
            return False
        if self.since is not None and e.time < self.since:
            return False
        if self.until is not None and e.time > self.until:
            return False
        text = f"{e.kind} {e.app} {e.summary} {e.detail}".lower()
        return all(w in text for w in self.words)


def parse_query(text: str, now: float | None = None) -> Query:
    """`kind:app,process` `app:maps` `since:10:05` `until:10:30:15` (today) `last:5m` (s, m, h)
    and free words. A field that does not parse is searched as a plain word."""
    now = clock.time() if now is None else now
    today = datetime.fromtimestamp(now)
    kinds: set[str] = set()
    app, since, until, words = "", None, None, []
    for word in text.lower().split():
        key, sep, value = word.partition(":")
        if sep and key == "kind" and (wanted := set(value.split(",")) & set(KINDS)):
            kinds |= wanted
        elif sep and key == "app" and value:
            app = value
        elif sep and key in ("since", "until") and (t := _clock_time(value, today)) is not None:
            since, until = (t, until) if key == "since" else (since, t + 0.999)
        elif sep and key == "last" and (m := _RELATIVE.match(value)):
            unit = {"s": 1, "m": 60, "h": 3600}[m[2]]
            since = (today - timedelta(seconds=int(m[1]) * unit)).timestamp()
        else:
            words.append(word)
    return Query(frozenset(kinds), app, since, until, tuple(words))


def report_rows(events: Iterable[Event]) -> list[dict[str, Any]]:
    return [
        {
            "time": iso(e.time),
            "epoch": round(e.time, 3),
            "kind": e.kind,
            "source": e.source,
            "app": e.app,
            "summary": e.summary,
            "detail": e.detail,
            "count": e.count,
        }
        for e in events
    ]


def write_timeline(
    events: list[Event],
    query: str,
    folder: Path,
    now: datetime | None = None,
    scrub: Scrub | None = None,
) -> tuple[Path, Path, Path]:
    now = now or datetime.now()
    data = report_rows(events)
    document = {
        "generated": now.astimezone().isoformat(timespec="seconds"),
        "filter": query,
        "clocks": "packet events use the device capture timestamp, others the computer clock",
        "events": data,
    }
    header = list(data[0]) if data else []
    return write_tables(
        folder / f"timeline-{now.strftime('%Y%m%d-%H%M%S-%f')[:-3]}",
        document,
        header,
        (list(r.values()) for r in data),
        scrub=scrub,
    )

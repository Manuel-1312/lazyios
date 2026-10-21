"""Anomaly rules over the capture. Every finding states what was measured and against what, so
it can be checked by hand; thresholds come from <out>/anomaly.json (all keys optional).

Rules:
- spike: an app's bytes in one window are `spike_factor` times its median window and at least
  `spike_min_kb`, once it has `spike_history` windows behind it
- beacon: `beacon_count` connections from an app to one address and port at a steady interval
  (spread at most `beacon_jitter` of the mean, mean at least `beacon_min_interval_s`)
- fanout: `fanout_count` domains an app never used in earlier sessions, within `fanout_window_s`
  (apps without history are skipped: everything would be new)
- change: at the end of a capture, an app's bytes per minute are `change_factor` times its median
  over at least `change_sessions` earlier sessions, and at least `change_min_kb` in total
Background activity is not judged: no interface lazyios uses says whether an app is in front.
"""

from __future__ import annotations

import json
import math
import statistics
from collections import deque
from dataclasses import dataclass, fields, replace
from itertools import pairwise
from pathlib import Path

from .files import read_config
from .flows import Flow
from .privacy import HostRow
from .sessions import Session

FILE = "anomaly.json"
RULES = ("spike", "beacon", "fanout", "change")
MAX_KEYS = 5000  # per-app / per-destination state is dropped past this
MIN_SECONDS = 60.0  # shorter captures give no reliable rate


@dataclass(frozen=True)
class Thresholds:
    window_s: float = 10.0
    spike_factor: float = 5.0
    spike_min_kb: float = 1024.0
    spike_history: int = 6
    beacon_count: int = 6
    beacon_jitter: float = 0.1
    beacon_min_interval_s: float = 5.0
    fanout_count: int = 10
    fanout_window_s: float = 60.0
    change_factor: float = 10.0
    change_min_kb: float = 512.0
    change_sessions: int = 3
    cooldown_s: float = 300.0
    rules: tuple[str, ...] = RULES


# key -> (lowest, highest) accepted
LIMITS: dict[str, tuple[float, float]] = {
    "window_s": (1, 3600), "spike_factor": (1.5, 1000), "spike_min_kb": (1, 10**7),
    "spike_history": (2, 360), "beacon_count": (3, 100), "beacon_jitter": (0.001, 1),
    "beacon_min_interval_s": (0.1, 86400), "fanout_count": (2, 10000),
    "fanout_window_s": (1, 86400), "change_factor": (1.5, 1000), "change_min_kb": (1, 10**8),
    "change_sessions": (1, 30), "cooldown_s": (0, 86400),
}  # fmt: skip


@dataclass(frozen=True)
class Finding:
    rule: str
    app: str
    summary: str
    detail: str
    time: float


def parse(text: str) -> Thresholds:
    """Raises ValueError with a message fit for the user."""
    try:
        data = json.loads(text)
    except ValueError as e:
        raise ValueError(f"not valid JSON (line {getattr(e, 'lineno', '?')})") from None
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object")
    known = {f.name for f in fields(Thresholds)}
    if unknown := sorted(set(data) - known):
        raise ValueError(f"unknown keys: {', '.join(map(str, unknown))[:80]}")
    values: dict[str, object] = {}
    for key, (low, high) in LIMITS.items():
        if key not in data:
            continue
        value = data[key]
        whole = isinstance(getattr(Thresholds, key), int)
        if isinstance(value, bool) or not isinstance(value, int if whole else (int, float)):
            raise ValueError(f"{key} must be a {'whole ' if whole else ''}number")
        if not low <= value <= high:
            raise ValueError(f"{key} must be between {low:g} and {high:g}")
        values[key] = value
    if "rules" in data:
        rules = data["rules"]
        if not isinstance(rules, list) or not all(r in RULES for r in rules):
            raise ValueError(f"rules must be a list drawn from {', '.join(RULES)}")
        values["rules"] = tuple(dict.fromkeys(rules))
    return replace(Thresholds(), **values)  # type: ignore[arg-type]


def load(folder: Path) -> tuple[Thresholds, str | None]:
    return read_config(folder / FILE, parse, Thresholds())


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


class Detector:
    def __init__(self, t: Thresholds | None = None, history: dict[str, set[str]] | None = None):
        self.t = t or Thresholds()
        self.history = history or {}
        self.findings: deque[Finding] = deque(maxlen=200)  # drained by the app
        self._window: dict[str, list[float]] = {}  # app -> [window start, bytes]
        self._past: dict[str, deque[float]] = {}  # app -> bytes of its earlier windows
        self._starts: dict[tuple[str, str, int | None], deque[float]] = {}
        self._fresh: dict[str, deque[tuple[float, str]]] = {}  # app -> (time, new domain)
        self._fired: dict[tuple[str, str], float] = {}

    def _report(
        self, rule: str, key: str, app: str, summary: str, detail: str, when: float
    ) -> None:
        last = self._fired.get((rule, key))
        if last is not None and when - last < self.t.cooldown_s:
            return
        if len(self._fired) > MAX_KEYS:
            self._fired.clear()
        self._fired[(rule, key)] = when
        self.findings.append(Finding(rule, app, summary, detail, when))

    def packet(self, app: str, length: int, when: float) -> None:
        if "spike" not in self.t.rules or app in ("", "-"):
            return
        w = self.t.window_s
        current = self._window.get(app)
        if current is None:
            if len(self._window) > MAX_KEYS:
                self._window.clear()
                self._past.clear()
            self._window[app] = [when - when % w, float(length)]
            return
        if when < current[0] + w:
            current[1] += length
            return
        past = self._past.setdefault(app, deque(maxlen=360))
        self._judge_window(app, current[0], current[1], past)
        past.append(current[1])
        idle = min(int((when - current[0]) // w) - 1, past.maxlen or 0)
        past.extend([0.0] * max(0, idle))  # windows without traffic count as zero
        self._window[app] = [when - when % w, float(length)]

    def _judge_window(self, app: str, start: float, size: float, past: deque[float]) -> None:
        if len(past) < self.t.spike_history:
            return
        median = statistics.median(past)
        if size < max(self.t.spike_min_kb * 1024, self.t.spike_factor * median):
            return
        ratio = f"{size / median:.1f}x" if median else "far above"
        self._report(
            "spike", app, app,
            f"{_size(size)} in {self.t.window_s:g} s, {ratio} its median",
            f"median {_size(median)} over the last {len(past)} windows of {self.t.window_s:g} s;"
            f" threshold max({self.t.spike_factor:g} x median, {self.t.spike_min_kb:g} KB)",
            start + self.t.window_s,
        )  # fmt: skip

    def connection(self, flow: Flow) -> None:
        """A new connection (first packet of a new flow)."""
        if "beacon" not in self.t.rules or flow.process == "-":
            return
        key = (flow.process, flow.remote_ip, flow.rport)
        starts = self._starts.get(key)
        if starts is None:
            if len(self._starts) > MAX_KEYS:
                self._starts.clear()
            starts = self._starts[key] = deque(maxlen=self.t.beacon_count)
        starts.append(flow.first)
        if len(starts) < self.t.beacon_count:
            return
        gaps = [b - a for a, b in pairwise(starts)]
        mean = sum(gaps) / len(gaps)  # floats: statistics.pstdev is exact and far slower
        spread = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
        if mean < self.t.beacon_min_interval_s or spread > self.t.beacon_jitter * mean:
            return
        where = flow.name or flow.remote
        self._report(
            "beacon", f"{flow.process}\x00{flow.remote}", flow.process,
            f"{len(starts)} connections to {where} every {mean:.1f} s (+-{spread:.1f} s)",
            f"{flow.proto} {flow.remote}; spread {spread / mean:.1%} of the interval,"
            f" limit {self.t.beacon_jitter:.0%}",
            flow.first,
        )  # fmt: skip

    def domain(self, row: HostRow) -> None:
        """A new (app, domain) row of the capture."""
        if "fanout" not in self.t.rules or row.source == "ip":
            return
        known = self.history.get(row.process)
        if known is None or row.domain in known:
            return
        fresh = self._fresh.get(row.process)
        if fresh is None:
            if len(self._fresh) > MAX_KEYS:
                self._fresh.clear()
            fresh = self._fresh[row.process] = deque(maxlen=self.t.fanout_count * 4)
        if any(d == row.domain for _, d in fresh):
            return
        fresh.append((row.first, row.domain))
        recent = [d for t, d in fresh if row.first - t <= self.t.fanout_window_s]
        if len(recent) >= self.t.fanout_count:
            self._report(
                "fanout", row.process, row.process,
                f"{len(recent)} never-seen domains within {self.t.fanout_window_s:g} s",
                "not in its earlier sessions: " + ", ".join(recent[-8:]),
                row.first,
            )  # fmt: skip

    def session_end(self, rows: list[HostRow], earlier: list[Session]) -> None:
        if "change" not in self.t.rules or not rows:
            return
        seconds = max(r.last for r in rows) - min(r.first for r in rows)
        if seconds < MIN_SECONDS:
            return
        totals: dict[str, int] = {}
        for r in rows:
            totals[r.process] = totals.get(r.process, 0) + r.bytes
        end = max(r.last for r in rows)
        for app, size in totals.items():
            rates = [
                s.apps[app].bytes / s.seconds * 60
                for s in earlier
                if app in s.apps and s.seconds >= MIN_SECONDS
            ]
            if len(rates) < self.t.change_sessions or size < self.t.change_min_kb * 1024:
                continue
            now, median = size / seconds * 60, statistics.median(rates)
            if now < self.t.change_factor * max(median, 1.0):
                continue
            self._report(
                "change", app, app,
                f"{_size(now)}/min against a median of {_size(median)}/min",
                f"{len(rates)} earlier sessions of this device; limit {self.t.change_factor:g} x",
                end,
            )  # fmt: skip

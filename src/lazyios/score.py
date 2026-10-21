"""Privacy score per app, from the rows of the capture. Every point taken off comes with a reason.

Criteria (also in the help screen and in every export):
- start at 100
- each distinct tracker domain: ads -12, analytics -8, telemetry -5
- half that when the name only comes from a DNS answer (CDN addresses are shared, so the app
  may have been talking to another site on the same address)
- trackers take off at most 75
- -10 when 10% or more of the app's bytes went to trackers
- unknown domains and bare addresses take nothing off: there is no evidence either way
Grades: A 90+, B 75+, C 60+, D 40+, F below.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .files import write_tables
from .privacy import HostRow
from .sessions import Change

WEIGHTS = {"ads": 12, "analytics": 8, "telemetry": 5}
DNS_FACTOR = 0.5
TRACKER_CAP = 75
SHARE_LIMIT, SHARE_PENALTY = 0.10, 10
GRADES = ((90, "A"), (75, "B"), (60, "C"), (40, "D"), (0, "F"))
CRITERIA = [
    "start at 100",
    "each distinct tracker domain: ads -12, analytics -8, telemetry -5",
    "half when the name only comes from a DNS answer (shared CDN addresses)",
    "trackers take off at most 75",
    "-10 when 10% or more of the app's bytes went to trackers",
    "unknown domains and bare addresses take nothing off",
    "grades: A 90+, B 75+, C 60+, D 40+, F below",
]
SORTS = ("score", "trackers", "app")


def kind(row: HostRow) -> str:
    """tracker (in the data as ads/analytics/telemetry), known (in the data, other category),
    unknown (a name lazyios has no data for) or unnamed (only an address)."""
    if row.source == "ip":
        return "unnamed"
    if row.tracker:
        return "tracker"
    return "known" if row.category else "unknown"


@dataclass
class AppScore:
    app: str
    score: int = 100
    trackers: list[str] = field(default_factory=list)
    tracker_companies: list[str] = field(default_factory=list)
    companies: list[str] = field(default_factory=list)
    known: int = 0
    unknown: int = 0
    unnamed: int = 0
    bytes: int = 0
    tracker_bytes: int = 0
    reasons: list[str] = field(default_factory=list)
    change: Change | None = None
    version: str | None = None

    @property
    def grade(self) -> str:
        return next(letter for floor, letter in GRADES if self.score >= floor)

    @property
    def tracker_share(self) -> float:
        return self.tracker_bytes / self.bytes if self.bytes else 0.0

    @property
    def updated(self) -> bool:
        """The app has a different version than in the last session that recorded one."""
        previous = self.change.previous_version if self.change else None
        return bool(self.version and previous and self.version != previous)

    @property
    def new_trackers(self) -> list[str]:
        return self.change.new_trackers if self.change and self.change.known else []


def score_apps(
    rows: Iterable[HostRow],
    changes: dict[str, Change] | None = None,
    versions: dict[str, str] | None = None,
) -> list[AppScore]:
    apps: dict[str, AppScore] = {}
    penalties: dict[str, float] = {}
    for r in rows:
        app = apps.setdefault(r.process, AppScore(r.process))
        app.bytes += r.bytes
        what = kind(r)
        if what == "unnamed":
            app.unnamed += 1
            continue
        if r.company and r.company not in app.companies:
            app.companies.append(r.company)
        if what != "tracker":
            app.known += what == "known"
            app.unknown += what == "unknown"
            continue
        app.tracker_bytes += r.bytes
        if r.domain in app.trackers:
            continue
        app.trackers.append(r.domain)
        if r.company and r.company not in app.tracker_companies:
            app.tracker_companies.append(r.company)
        cost = WEIGHTS[r.category] * (DNS_FACTOR if r.source == "dns" else 1.0)
        penalties[r.process] = penalties.get(r.process, 0.0) + cost
        via = " (dns only, half)" if r.source == "dns" else ""
        app.reasons.append(f"-{cost:g} {r.category}: {r.domain}{via}")
    for name, app in apps.items():
        taken = penalties.get(name, 0.0)
        if taken > TRACKER_CAP:
            app.reasons.append(f"trackers capped at -{TRACKER_CAP}")
            taken = TRACKER_CAP
        if app.tracker_share >= SHARE_LIMIT:
            taken += SHARE_PENALTY
            app.reasons.append(f"-{SHARE_PENALTY} {app.tracker_share:.0%} of bytes to trackers")
        app.score = max(0, round(100 - taken))
        app.change = (changes or {}).get(name)
        app.version = (versions or {}).get(name)
    return list(apps.values())


def sort_scores(scores: Iterable[AppScore], mode: str) -> list[AppScore]:
    keys = {
        "score": lambda a: (a.score, -len(a.trackers), a.app.lower()),
        "trackers": lambda a: (-len(a.trackers), a.score, a.app.lower()),
        "app": lambda a: a.app.lower(),
    }
    return sorted(scores, key=keys.get(mode, keys["score"]))


def top_companies(scores: Iterable[AppScore], n: int = 3) -> list[tuple[str, int]]:
    """Tracker companies by how many apps send them traffic."""
    counts: dict[str, int] = {}
    for app in scores:
        for company in app.tracker_companies:
            counts[company] = counts.get(company, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]


def report_rows(scores: Iterable[AppScore]) -> list[dict[str, Any]]:
    return [
        {
            "app": a.app,
            "version": a.version or "",
            "score": a.score,
            "grade": a.grade,
            "trackers": a.trackers,
            "tracker_companies": a.tracker_companies,
            "companies": a.companies,
            "known_domains": a.known,
            "unknown_domains": a.unknown,
            "unnamed_addresses": a.unnamed,
            "bytes": a.bytes,
            "tracker_bytes": a.tracker_bytes,
            "new_domains": a.change.new_domains if a.change and a.change.known else [],
            "new_trackers": a.new_trackers,
            "previous_version": (a.change.previous_version or "") if a.change else "",
            "updated": a.updated,
            "reasons": a.reasons,
        }
        for a in scores
    ]


def write_scores(
    scores: list[AppScore], folder: Path, now: datetime | None = None
) -> tuple[Path, Path, Path]:
    now = now or datetime.now()
    data = report_rows(scores)
    document = {
        "generated": now.isoformat(timespec="seconds"),
        "criteria": CRITERIA,
        "top_tracker_companies": dict(top_companies(scores, 10)),
        "apps": data,
    }
    header = list(data[0]) if data else []
    return write_tables(
        folder / f"score-{now.strftime('%Y%m%d-%H%M%S-%f')[:-3]}",
        document,
        header,
        (["; ".join(v) if isinstance(v, list) else v for v in r.values()] for r in data),
    )

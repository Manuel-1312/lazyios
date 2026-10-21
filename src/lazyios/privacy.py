"""Which app talks to which domain: tracker lookup and per-app aggregation of captured packets."""

from __future__ import annotations

import json
from collections import OrderedDict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from .backend import Packet
from .files import write_tables
from .parsing import clean_text, parse_dns_answers, parse_tls_sni, split_endpoint

MAX_ROWS = 2000
MAX_NAMES = 10000
MAX_FLOWS = 512  # per row; the flow count stops growing past this
MAX_ROW_IPS = 16
MAX_ADDED = 1000
KERNEL_PID = 0xFFFFFFFF
EPHEMERAL = 49152
DNS_PORTS = (53, 5353)
TRACKER_CATEGORIES = frozenset({"ads", "analytics", "telemetry"})
SORTS = ("bytes", "flows", "app", "domain")
# how a name was tied to an address, weakest first: none, a DNS answer for that address (shared
# by every site on a CDN address), the name the app itself sent in its TLS ClientHello
SOURCES = ("ip", "dns", "sni")
DATA = Path(__file__).with_name("data") / "trackers.json"


class TrackerDB:
    """Domain -> (category, company), loaded on first lookup."""

    def __init__(self, data: dict[str, list[str]] | None = None) -> None:
        self._data = data

    @property
    def data(self) -> dict[str, list[str]]:
        if self._data is None:
            try:
                self._data = json.loads(DATA.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._data = {}
        return self._data

    def lookup(self, host: str) -> tuple[str, str] | None:
        """Walks a.b.example.com -> b.example.com -> example.com, never below two labels."""
        labels = host.split(".")
        if ":" in host or labels[-1].isdigit():  # an address, not a name
            return None
        for i in range(len(labels) - 1):
            hit = self.data.get(".".join(labels[i:]))
            if hit and len(hit) == 2:
                return hit[0], hit[1]
        return None


@dataclass
class HostRow:
    process: str
    domain: str
    category: str = ""
    company: str = ""
    bytes: int = 0
    first: float = 0.0
    last: float = 0.0
    ips: list[str] = field(default_factory=list)
    source: str = "ip"
    flow_keys: set[tuple[int | None, str, int | None, str]] = field(default_factory=set)

    @property
    def tracker(self) -> bool:
        return self.category in TRACKER_CATEGORIES

    @property
    def flows(self) -> int:
        return len(self.flow_keys)

    def absorb(self, other: HostRow) -> None:
        self.bytes += other.bytes
        self.first = min(self.first, other.first)
        self.last = max(self.last, other.last)
        self.flow_keys.update(list(other.flow_keys)[: MAX_FLOWS - len(self.flow_keys)])
        for ip in other.ips:
            if ip not in self.ips and len(self.ips) < MAX_ROW_IPS:
                self.ips.append(ip)


def remote_is_dst(src: str, sport: int | None, dst: str, dport: int | None) -> bool:
    """Guess the direction: the side on a service port is the remote one, else the public one."""
    if sport is not None and dport is not None and (sport < EPHEMERAL) != (dport < EPHEMERAL):
        return dport < EPHEMERAL
    return not (ip_address(src).is_global and not ip_address(dst).is_global)


def _remember(cache: OrderedDict[Any, str], key: Any, value: str) -> None:
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > MAX_NAMES:
        cache.popitem(last=False)


class HostAggregator:
    """Fed every captured packet; keeps one row per (app, domain), bounded."""

    def __init__(self, trackers: TrackerDB | None = None) -> None:
        self.trackers = trackers or TrackerDB()
        self.version = 0  # bumped whenever the rows change
        self.latest = 0.0
        self._rows: OrderedDict[tuple[str, str], HostRow] = OrderedDict()
        self._names: OrderedDict[str, str] = OrderedDict()  # ip -> name, from DNS answers
        self._sni: OrderedDict[tuple[str, str], str] = OrderedDict()  # (app, ip) -> TLS name
        self._bare: dict[str, set[str]] = {}  # ip -> apps with a row under that bare address
        self.added: deque[HostRow] = deque(maxlen=MAX_ADDED)  # new rows, drained by alerts

    def reset(self) -> None:
        self._rows.clear()
        self._names.clear()
        self._sni.clear()
        self._bare.clear()
        self.added.clear()
        self.latest = 0.0
        self.version += 1

    def rows(self) -> list[HostRow]:
        return list(self._rows.values())

    def summary(self) -> tuple[int, int, int]:
        """(apps, domains, tracker domains)."""
        return summarize(self._rows.values())

    def name_for(self, process: str, ip: str) -> tuple[str, str]:
        """(name, source) for an address as seen by an app; (ip, "ip") when no name is known."""
        if name := self._sni.get((process, ip)):
            return name, "sni"
        if name := self._names.get(ip):
            return name, "dns"
        return ip, "ip"

    def feed(self, p: Packet) -> None:
        if p.proto not in ("tcp", "udp", "icmp", "icmp6"):
            return
        src, sport = split_endpoint(p.src)
        dst, dport = split_endpoint(p.dst)
        if p.proto == "udp" and p.payload and sport in DNS_PORTS:
            self._learn_dns(p.payload, p.time)
        process = clean_text(p.process)
        if p.pid == KERNEL_PID or not process:
            return
        try:
            outbound = remote_is_dst(src, sport, dst, dport)
        except ValueError:
            return
        remote, rport, lport = (dst, dport, sport) if outbound else (src, sport, dport)
        if p.proto == "tcp" and p.payload[:1] == b"\x16" and (name := parse_tls_sni(p.payload)):
            self._learn_sni(process, remote, name, p.time)
        row = self._row(process, *self.name_for(process, remote), p.time)
        row.bytes += p.length
        row.first, row.last = min(row.first, p.time), max(row.last, p.time)
        self.latest = max(self.latest, p.time)
        if len(row.flow_keys) < MAX_FLOWS:
            row.flow_keys.add((lport, remote, rport, p.proto))
        if remote not in row.ips and len(row.ips) < MAX_ROW_IPS:
            row.ips.append(remote)
        self.version += 1

    def _row(self, process: str, domain: str, source: str, when: float) -> HostRow:
        key = (process, domain)
        row = self._rows.get(key)
        if row is None:
            row = HostRow(process, domain, first=when, last=when, source=source)
            if hit := self.trackers.lookup(domain):
                row.category, row.company = hit
            self._rows[key] = row
            self.added.append(row)
            if source == "ip":
                self._bare.setdefault(domain, set()).add(process)
            while len(self._rows) > MAX_ROWS:
                self._unbare(self._rows.popitem(last=False)[1])
        else:
            self._rows.move_to_end(key)
            if SOURCES.index(source) > SOURCES.index(row.source):
                row.source = source
        return row

    def _unbare(self, row: HostRow) -> None:
        if row.source == "ip" and (apps := self._bare.get(row.domain)) is not None:
            apps.discard(row.process)
            if not apps:
                del self._bare[row.domain]

    def _rename(self, process: str, ip: str, name: str, source: str, when: float) -> None:
        """Move the traffic an app sent to a bare address under the name learned for it."""
        if bare := self._rows.pop((process, ip), None):
            self._unbare(bare)
            self._row(process, name, source, when).absorb(bare)
            self.version += 1

    def _learn_dns(self, payload: bytes, when: float) -> None:
        seen: set[str] = set()
        for ip, name in parse_dns_answers(payload):
            if ip not in seen:  # the first name for an address is the one the app asked for
                seen.add(ip)
                _remember(self._names, ip, name)
                for process in list(self._bare.get(ip, ())):  # answer arrived after the traffic
                    self._rename(process, ip, name, "dns", when)

    def _learn_sni(self, process: str, ip: str, name: str, when: float) -> None:
        _remember(self._sni, (process, ip), name)
        self._rename(process, ip, name, "sni", when)  # traffic seen before the name


def summarize(rows: Iterable[HostRow]) -> tuple[int, int, int]:
    rows = list(rows)
    return (
        len({r.process for r in rows}),
        len({r.domain for r in rows}),
        len({r.domain for r in rows if r.tracker}),
    )


def sort_rows(rows: Iterable[HostRow], mode: str) -> list[HostRow]:
    """bytes and flows put trackers first; app and domain are plain alphabetical."""
    keys = {
        "bytes": lambda r: (not r.tracker, -r.bytes),
        "flows": lambda r: (not r.tracker, -r.flows, -r.bytes),
        "app": lambda r: (r.process.lower(), -r.bytes),
        "domain": lambda r: (r.domain, r.process.lower()),
    }
    return sorted(rows, key=keys.get(mode, keys["bytes"]))


def _stamp(when: float) -> str:
    return datetime.fromtimestamp(when).isoformat(timespec="seconds")


def report_rows(rows: Iterable[HostRow]) -> list[dict[str, Any]]:
    return [
        {
            "app": r.process,
            "domain": r.domain,
            "category": r.category,
            "company": r.company,
            "tracker": r.tracker,
            "flows": r.flows,
            "bytes": r.bytes,
            "first_seen": _stamp(r.first),
            "last_seen": _stamp(r.last),
            "source": r.source,
            "ips": r.ips,
        }
        for r in rows
    ]


def write_report(
    rows: list[HostRow], folder: Path, now: datetime | None = None
) -> tuple[Path, Path]:
    """Write privacy-<stamp>.json, .csv and .sha256 into folder; returns (json path, csv path)."""
    now = now or datetime.now()
    data = report_rows(rows)
    summary = dict(zip(("apps", "domains", "trackers"), summarize(rows), strict=True))
    document = {"generated": _stamp(now.timestamp()), "summary": summary, "rows": data}
    header = list(report_rows([HostRow("", "")])[0])
    json_path, csv_path, _ = write_tables(
        folder / f"privacy-{now.strftime('%Y%m%d-%H%M%S-%f')[:-3]}",
        document,
        header,
        ([*list(r.values())[:-1], " ".join(r["ips"])] for r in data),
    )
    return json_path, csv_path

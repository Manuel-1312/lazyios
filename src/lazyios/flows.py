"""Network inspector: one row per connection seen in the capture, with bytes each way.

Built on pcapd packets because they carry the pid and process of every packet. The DVT
NetworkMonitor reports pid -2 for every connection on iOS 27, so it cannot attribute traffic.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .backend import Packet
from .files import write_tables
from .parsing import clean_text, split_endpoint
from .privacy import KERNEL_PID, HostAggregator, remote_is_dst

MAX_FLOWS = 5000
MAX_DESTS = 10000
ACTIVE = 10.0  # seconds without packets before a connection counts as idle
SORTS = ("last", "bytes", "app")
CONFIDENCE = {"sni": "high", "dns": "medium", "ip": "none"}
FIELDS = ("app", "domain", "ip", "port", "proto")
_PROTOS = ("tcp", "udp", "icmp", "icmp6")


@dataclass
class Flow:
    pid: int
    process: str
    proto: str
    interface: str
    local: str  # endpoint on the phone, ip:port
    remote: str  # the other end, ip:port (bare ip for icmp)
    remote_ip: str
    rport: int | None
    first: float
    last: float
    domain: str = ""
    source: str = "ip"
    tx_bytes: int = 0
    rx_bytes: int = 0
    tx_packets: int = 0
    rx_packets: int = 0
    seen: int = 1  # connections this app opened to this destination so far, this one included

    @property
    def bytes(self) -> int:
        return self.tx_bytes + self.rx_bytes

    @property
    def new(self) -> bool:
        """First connection from this app to this address and port in the session."""
        return self.seen == 1

    @property
    def confidence(self) -> str:
        return CONFIDENCE[self.source]

    @property
    def name(self) -> str:
        """The domain when one is known, else empty."""
        return self.domain if self.source != "ip" else ""


class FlowTable:
    """Fed every captured packet after the HostAggregator, whose DNS and SNI names it reuses."""

    def __init__(self, names: HostAggregator) -> None:
        self.names = names
        self.version = 0
        self.latest = 0.0
        self._flows: OrderedDict[tuple[int, str, str, str], Flow] = OrderedDict()
        self._dests: OrderedDict[tuple[str, str, int | None], int] = OrderedDict()
        # (proto, local, remote) -> the app flow on that socket
        self._owners: dict[tuple[str, str, str], tuple[int, str, str, str]] = {}

    def reset(self) -> None:
        self._flows.clear()
        self._dests.clear()
        self._owners.clear()
        self.latest = 0.0
        self.version += 1

    def rows(self) -> list[Flow]:
        return list(self._flows.values())

    def feed(self, p: Packet) -> None:
        if p.proto not in _PROTOS:
            return
        src, sport = split_endpoint(p.src)
        dst, dport = split_endpoint(p.dst)
        try:
            outbound = remote_is_dst(src, sport, dst, dport)
        except ValueError:
            return
        local, remote = (p.src, p.dst) if outbound else (p.dst, p.src)
        rip, rport = (dst, dport) if outbound else (src, sport)
        process = "-" if p.pid == KERNEL_PID else clean_text(p.process) or "-"
        key = (p.pid, p.proto, local, remote)
        if p.pid == KERNEL_PID and (owner := self._owners.get(key[1:])) in self._flows:
            key = owner  # pktap left the pid off, but protocol and both endpoints are that app's
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(
                p.pid, process, p.proto, clean_text(p.interface), local, remote, rip, rport,
                first=p.time, last=p.time, seen=self._count(process, rip, rport),
            )  # fmt: skip
            self._flows[key] = flow
            if p.pid != KERNEL_PID:
                self._owners[key[1:]] = key
            while len(self._flows) > MAX_FLOWS:
                old, _ = self._flows.popitem(last=False)
                if self._owners.get(old[1:]) == old:
                    del self._owners[old[1:]]
        else:
            self._flows.move_to_end(key)
        if flow.source != "sni":  # a better name may have arrived since the last packet
            flow.domain, flow.source = self.names.name_for(flow.process, rip)
        if outbound:
            flow.tx_bytes += p.length
            flow.tx_packets += 1
        else:
            flow.rx_bytes += p.length
            flow.rx_packets += 1
        flow.first, flow.last = min(flow.first, p.time), max(flow.last, p.time)
        self.latest = max(self.latest, p.time)
        self.version += 1

    def _count(self, process: str, ip: str, port: int | None) -> int:
        dest = (process, ip, port)
        seen = self._dests.pop(dest, 0) + 1
        self._dests[dest] = seen
        while len(self._dests) > MAX_DESTS:
            self._dests.popitem(last=False)
        return seen

    def active(self, flow: Flow) -> bool:
        return self.latest - flow.last < ACTIVE

    def summary(self) -> dict[str, int]:
        rows = self.rows()
        return {
            "connections": len(rows),
            "active": sum(self.active(f) for f in rows),
            "new_destinations": sum(f.new for f in rows),
            "tx_bytes": sum(f.tx_bytes for f in rows),
            "rx_bytes": sum(f.rx_bytes for f in rows),
        }


def _field(flow: Flow, key: str) -> tuple[str, ...]:
    if key == "app":
        return (flow.process.lower(),)
    if key == "domain":
        return (flow.name,)
    if key == "ip":
        return (flow.remote_ip.lower(), split_endpoint(flow.local)[0].lower())
    if key == "port":
        return (str(flow.rport), str(split_endpoint(flow.local)[1]))
    return (flow.proto,)


def matches(flow: Flow, query: str) -> bool:
    """Every word must match. `app:` `domain:` `ip:` (substring), `port:` `proto:` (exact);
    any other word, IPv6 addresses included, is searched in all of them."""
    for word in query.lower().split():
        key, sep, value = word.partition(":")
        if sep and key in FIELDS and value:
            fields = _field(flow, key)
            exact = key in ("port", "proto")
            if not any(value == f if exact else value in f for f in fields):
                return False
        elif not any(word in f for k in FIELDS for f in _field(flow, k)):
            return False
    return True


def sort_flows(rows: Iterable[Flow], mode: str) -> list[Flow]:
    keys = {
        "last": lambda f: -f.last,
        "bytes": lambda f: -f.bytes,
        "app": lambda f: (f.process.lower(), -f.last),
    }
    return sorted(rows, key=keys.get(mode, keys["last"]))


def _stamp(when: float) -> str:
    return datetime.fromtimestamp(when).isoformat(timespec="seconds")


def report_rows(rows: Iterable[Flow]) -> list[dict[str, Any]]:
    return [
        {
            "app": f.process,
            "pid": f.pid,
            "proto": f.proto,
            "interface": f.interface,
            "local": f.local,
            "remote": f.remote,
            "domain": f.name,
            "domain_source": f.source,
            "confidence": f.confidence,
            "tx_bytes": f.tx_bytes,
            "rx_bytes": f.rx_bytes,
            "tx_packets": f.tx_packets,
            "rx_packets": f.rx_packets,
            "seen": f.seen,
            "first_seen": _stamp(f.first),
            "last_seen": _stamp(f.last),
        }
        for f in rows
    ]


def write_flows(
    table: FlowTable, rows: list[Flow], folder: Path, now: datetime | None = None
) -> tuple[Path, Path, Path]:
    """connections-<stamp>.json, .csv and .sha256 in folder."""
    now = now or datetime.now()
    data = report_rows(rows)
    document = {
        "generated": _stamp(now.timestamp()),
        "summary": table.summary(),
        "confidence": {
            "high": "name the app sent in its TLS ClientHello (SNI) on this connection",
            "medium": "a DNS answer for this address; CDNs share addresses between sites",
            "none": "no name seen for this address",
        },
        "rows": data,
    }
    header = list(report_rows([Flow(0, "", "", "", "", "", "", None, 0.0, 0.0)])[0])
    return write_tables(
        folder / f"connections-{now.strftime('%Y%m%d-%H%M%S-%f')[:-3]}",
        document,
        header,
        (list(r.values()) for r in data),
    )

"""Backend with canned data for --demo, screenshots and tests."""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import random
import struct
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from pathlib import Path

from .backend import (
    App,
    BackendError,
    Battery,
    Condition,
    DeviceInfo,
    DevModeOffError,
    NoDeviceError,
    Packet,
    Process,
    undo_all,
)
from .files import create_private

# 1x1 PNG, enough for the tools tab to have something to save
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

# process, image, pid, messages
_DAEMONS = [
    (
        "SpringBoard",
        "SpringBoard",
        64,
        ["icon list updated", "scene 0x5f1 activated", "dock layout committed"],
    ),
    (
        "locationd",
        "CoreLocation",
        81,
        ["fix accuracy 65.0", "client registered", "wifi scan requested"],
    ),
    ("apsd", "libxpc.dylib", 122, ["keepalive ok", "token refreshed", "connection established"]),
    ("Safari", "WebKit", 912, ["page load finished", "network process ready", "cache trimmed"]),
    (
        "mediaserverd",
        "MediaToolbox",
        77,
        ["audio route changed", "session activated", "volume 0.50"],
    ),
    ("backboardd", "CoreBrightness", 63, ["ALS lux=312", "brightness 0.62", "display on"]),
    (
        "mDNSResponder",
        "mDNSResponder",
        70,
        ["query for apple.com", "cache hit", "interface en0 up"],
    ),
    ("symptomsd", "SymptomEvaluator", 98, ["wifi quality ok", "flow stats updated"]),
    ("CommCenter", "CoreTelephony", 88, ["signal bars 4", "registered on network"]),
    ("powerd", "powerd", 55, ["battery 64%", "assertion released", "charger attached"]),
    ("trustd", "Security", 101, ["ocsp cache refreshed", "trust eval ok"]),
    ("cloudd", "CloudKit", 140, ["sync started", "zone fetch complete"]),
]
_BAD = [
    ("Safari", "WebKit", 912, "error", "web content process terminated"),
    ("cloudd", "CloudKit", 140, "error", "request failed: timed out"),
    ("kernel", "Sandbox", 0, "fault", "deny file-read-data /private/var/db"),
]
_LEVELS = ("debug", "info", "notice")


def _log_line(rng: random.Random, when: float) -> str:
    stamp = time.strftime("%b %d %H:%M:%S", time.localtime(when))
    if rng.random() < 0.03:
        proc, image, pid, level, msg = rng.choice(_BAD)
    else:
        proc, image, pid, msgs = rng.choice(_DAEMONS)
        level, msg = rng.choices(_LEVELS, (3, 4, 4))[0], rng.choice(msgs)
    return f"{stamp} iPhone-demo {proc}({image})[{pid}] <{level.capitalize()}>: {msg}"


_PROCS = [
    ("launchd", 1, False),
    ("SpringBoard", 64, True),
    ("backboardd", 63, False),
    ("locationd", 81, False),
    ("mediaserverd", 77, False),
    ("apsd", 122, False),
    ("Safari", 912, True),
    ("Preferences", 1021, True),
    ("Maps", 1033, True),
    ("sharingd", 140, False),
]

_APPS = [
    App("FitTrack", "com.example.fittrack", "4.2", "FitTrack"),
    App("Maps", "com.example.maps", "3.2.1", "Maps"),
    App("NewsDaily", "com.example.newsdaily", "12.0.3", "NewsDaily"),
    App("Notes", "com.example.notes", "1.9", "Notes"),
    App("PhotoBox", "com.example.photobox", "2.8", "PhotoBox"),
    App("QuickChat", "com.example.quickchat", "5.1", "QuickChat"),
    App("Terminal", "com.example.terminal", "2.0.4", "Terminal"),
    App("Weather", "com.example.weather", "7.1", "Weather"),
    App("Weatherly", "com.example.weatherly", "3.3", "Weatherly"),
]

_CONDITIONS = [
    Condition("SlowNetworkCondition", "network", "SlowNetwork3G", "3G network", "1 Mbps, 100 ms"),
    Condition("SlowNetworkCondition", "network", "SlowNetworkEdge", "edge network", "0.2 Mbps"),
    Condition(
        "SlowNetworkCondition", "network", "SlowNetwork100PctLoss", "100% loss", "no traffic"
    ),
    Condition("ThermalCondition", "thermal", "ThermalSerious", "thermal serious", "serious"),
    Condition("ThermalCondition", "thermal", "ThermalCritical", "thermal critical", "critical"),
]


def _ipv4(proto: int, src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    if proto == 17:
        l4 = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    else:
        flags = 0x18 if payload else 0x10
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 1024, 0, 0)
    body = l4 + payload
    head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), 0, 0, 64, proto, 0, src, dst)
    return head + body


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def _dns_response(qname: str, ip: str, cname: str | None = None, v6: str | None = None) -> bytes:
    """A DNS answer for qname, through a CNAME hop when given; names point back by compression."""
    question = _dns_name(qname) + struct.pack("!HH", 1, 1)
    owner, records, count = b"\xc0\x0c", b"", 1 + bool(cname) + bool(v6)
    if cname:
        target = _dns_name(cname)
        records += owner + struct.pack("!HHIH", 5, 1, 300, len(target)) + target
        owner = struct.pack("!H", 0xC000 | (12 + len(question) + 12))  # the CNAME target
    records += owner + struct.pack("!HHIH", 1, 1, 60, 4) + ipaddress.IPv4Address(ip).packed
    if v6:
        records += owner + struct.pack("!HHIH", 28, 1, 60, 16) + ipaddress.IPv6Address(v6).packed
    return struct.pack("!HHHHHH", 0x1234, 0x8180, 1, count, 0, 0) + question + records


def _client_hello(host: str) -> bytes:
    name = host.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0, len(sni)) + sni
    exts += struct.pack("!HHHH", 10, 4, 2, 0x001D) + struct.pack("!HHBH", 43, 3, 2, 0x0304)
    body = struct.pack("!H", 0x0303) + bytes(range(32)) + b"\x20" + bytes(32)
    body += struct.pack("!HHH", 4, 0x1301, 0x1302) + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hello = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hello)) + hello


LOCAL = "192.168.0.204"
RESOLVER = "192.168.0.1"
# app, pid, [(host, cname)]; a host of None is a bare address nobody looked up
_TRAFFIC = [
    ("FitTrack", 1101, [
        ("api.fittrack.example", None), ("sync.fittrack.example", None),
        ("static.fittrack.example", None),
        ("cdn.fittrack.example", "cdn.fittrack.example.edge.example"),
        ("gateway.icloud.com", None), ("app-measurement.com", None), ("graph.facebook.com", None),
        ("api.mixpanel.com", None), ("firebase-settings.crashlytics.com", None),
    ]),
    ("NewsDaily", 1102, [
        ("api.newsdaily.example", None), ("fonts.newsdaily.example", None),
        ("video.newsdaily.example", None),
        ("img.newsdaily.example", "img.newsdaily.example.edge.example"),
        ("googleads.g.doubleclick.net", None), ("app.adjust.com", None),
        ("sdk.iad-01.braze.com", None),
    ]),
    ("PhotoBox", 1103, [
        ("api.photobox.example", None), ("upload.photobox.example", None),
        ("cdn.photobox.example", "cdn.photobox.example.edge.example"), ("gateway.icloud.com", None),
        ("firebase-settings.crashlytics.com", None), ("api2.branch.io", None), (None, None),
    ]),
    ("Weatherly", 1104, [
        ("api.weatherly.example", None), ("radar.weatherly.example", None),
        ("tiles.weatherly.example", "tiles.weatherly.example.edge.example"),
        ("googleads.g.doubleclick.net", None), ("app-measurement.com", None),
    ]),
    ("QuickChat", 1105, [
        ("chat.quickchat.example", None), ("push.quickchat.example", None),
        ("media.quickchat.example", "media.quickchat.example.edge.example"),
        ("api.mixpanel.com", None), ("sdk.iad-01.braze.com", None),
    ]),
    ("cloudd", 140, [("gateway.icloud.com", None)]),
    ("apsd", 122, [("courier.push.apple.com", None)]),
]  # fmt: skip
_HOSTS = sorted({h for _, _, hosts in _TRAFFIC for h, _ in hosts if h})
_BLOCKS = ("203.0.113", "198.51.100", "192.0.2")  # documentation ranges, never real servers


def _address(host: str | None) -> str:
    i = _HOSTS.index(host) if host else len(_HOSTS)
    return f"{_BLOCKS[i // 254 % 3]}.{i % 254 + 1}"


# process, pid, outbound, protocol, remote port, payload, remote address
Frame = tuple[str, int, bool, str, int, bytes, str]


def _open_flow(
    proc: str, pid: int, host: str | None, cname: str | None, resolved: set[str]
) -> list[Frame]:
    """Frames that start a connection: the DNS answer (once per host), then the first segments."""
    ip = _address(host)
    if host is None:
        return [(proc, pid, True, "udp", 443, bytes(1200), ip)]
    frames: list[Frame] = []
    if host not in resolved:
        resolved.add(host)
        v6 = f"2001:db8::{ip.rsplit('.', 1)[1]}" if len(resolved) % 3 == 0 else None
        answer = _dns_response(host, ip, cname, v6)
        frames.append(("mDNSResponder", 70, False, "udp", 53, answer, RESOLVER))
    frames.append((proc, pid, True, "tcp", 443, b"", ip))
    frames.append((proc, pid, True, "tcp", 443, _client_hello(host), ip))
    return frames


def _pcap_header() -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101)


class FakeBackend:
    def __init__(
        self,
        *,
        has_device: bool = True,
        developer: bool = True,
        problem: BackendError | None = None,
        interval: float = 0.05,
    ) -> None:
        self.has_device = has_device
        self.developer = developer
        self.problem = problem
        self.interval = interval
        self.tunnel_open = False
        self.active_condition: Condition | None = None
        self.location: tuple[float, float] | None = None
        self.killed: list[int] = []
        self.launched: list[str] = []
        self.cleared_conditions = 0
        self.cleared_locations = 0
        self.captures = 0
        self.closed = False
        self.on_reset: Callable[[], None] | None = None
        self.clear_failures = 0
        self.condition_clear_hangs = False
        self.close_timeout = 5.0
        self._cond_dirty = self._loc_dirty = False
        self._battery = 64

    def _need_device(self) -> None:
        if self.problem is not None:
            raise self.problem
        if not self.has_device:
            raise NoDeviceError("no device connected")

    async def device_info(self) -> DeviceInfo:
        self._need_device()
        return DeviceInfo(
            "iPhone", "iPhone18,1", "27.2", "24B5089g", "DEMO00000000", "02:00:00:aa:bb:cc",
            "00000000-DEMO000000000000",
        )  # fmt: skip

    async def battery(self) -> Battery:
        self._need_device()
        return Battery(self._battery, 248, True, 20, "pd charger")

    async def developer_mode(self) -> bool:
        self._need_device()
        return self.developer

    async def syslog(self) -> AsyncIterator[str]:
        self._need_device()
        rng = random.Random(11)
        when = time.time()
        while True:
            await asyncio.sleep(self.interval)
            when += rng.random() * 0.8
            yield _log_line(rng, when)

    async def open_tunnel(self) -> None:
        self._need_device()
        if not self.developer:
            raise DevModeOffError("developer mode is off")
        await asyncio.sleep(self.interval)
        self.tunnel_open = True

    async def processes(self) -> list[Process]:
        await self.open_tunnel()
        return [Process(pid, name, app, "10-19 08:12:00") for name, pid, app in _PROCS]

    async def kill(self, pid: int) -> None:
        await self.open_tunnel()
        self.killed.append(pid)

    async def launch(self, bundle_id: str) -> int:
        await self.open_tunnel()
        self.launched.append(bundle_id)
        return 4242

    async def apps(self) -> list[App]:
        self._need_device()
        return list(_APPS)

    async def capture(self, path: Path) -> AsyncIterator[Packet]:
        self._need_device()
        self.captures += 1
        rng = random.Random(7)
        fresh = [(proc, pid, host, cname) for proc, pid, hosts in _TRAFFIC for host, cname in hosts]
        rng.shuffle(fresh)
        ports: dict[tuple[str, str], int] = {}  # (process, remote address) -> local port
        flows: list[tuple[str, int, str | None]] = []
        resolved: set[str] = set()
        queue: deque[Frame] = deque()
        with create_private(path) as out:
            out.write(_pcap_header())
            while True:
                await asyncio.sleep(self.interval)
                if not queue:
                    if fresh and (not flows or rng.random() < 0.7):
                        proc, pid, host, cname = fresh.pop()
                        flows.append((proc, pid, host))
                        queue.extend(_open_flow(proc, pid, host, cname, resolved))
                    else:
                        proc, pid, host = rng.choice(flows)
                        size = rng.choice((0, 32, 120, 517, 1200, 1400))
                        proto = "udp" if host is None else "tcp"
                        if rng.random() < 0.15:  # the app opens another connection
                            ports.pop((proc, _address(host)), None)
                        frame = (proc, pid, rng.random() < 0.4, proto, 443, bytes(size))
                        queue.append((*frame, _address(host)))
                    if rng.random() < 0.1:  # local chatter no app owns
                        queue.append(
                            ("", 0xFFFFFFFF, True, "udp", 57621, bytes(60), "192.168.0.255")
                        )
                proc, pid, outbound, proto, port, payload, remote = queue.popleft()
                if (proc, remote) not in ports:
                    ports[proc, remote] = rng.randint(49152, 65535)
                local = ports[proc, remote]
                src, dst = (LOCAL, remote) if outbound else (remote, LOCAL)
                sp, dp = (local, port) if outbound else (port, local)
                raw = _ipv4(
                    6 if proto == "tcp" else 17,
                    ipaddress.IPv4Address(src).packed,
                    ipaddress.IPv4Address(dst).packed,
                    sp,
                    dp,
                    payload,
                )
                now = time.time()
                out.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6), len(raw), len(raw)))
                out.write(raw)
                out.flush()
                yield Packet(
                    now,
                    pid,
                    proc,
                    "en0",
                    proto,
                    f"{src}:{sp}",
                    f"{dst}:{dp}",
                    len(raw) + 14,
                    payload,
                )

    async def conditions(self) -> list[Condition]:
        await self.open_tunnel()
        return list(_CONDITIONS)

    async def set_condition(self, condition: Condition) -> None:
        await self.open_tunnel()
        self._cond_dirty = True
        self.active_condition = condition

    async def clear_condition(self) -> None:
        await asyncio.shield(self._clear_condition())

    async def _clear_condition(self) -> None:
        if not self._cond_dirty:
            return
        if self.condition_clear_hangs:
            await asyncio.sleep(3600)
        await self._clear_step()
        self.cleared_conditions += 1
        self.active_condition = None
        self._cond_dirty = False

    async def _clear_step(self) -> None:
        await asyncio.sleep(self.interval)
        if self.clear_failures:
            self.clear_failures -= 1
            raise BackendError("clear failed")

    async def screenshot(self) -> bytes:
        await self.open_tunnel()
        return _PNG

    async def set_location(self, lat: float, lon: float) -> None:
        await self.open_tunnel()
        self._loc_dirty = True
        self.location = (lat, lon)

    async def clear_location(self) -> None:
        await asyncio.shield(self._clear_location())

    async def _clear_location(self) -> None:
        if not self._loc_dirty:
            return
        await self._clear_step()
        self.cleared_locations += 1
        self.location = None
        self._loc_dirty = False

    async def fps(self) -> AsyncIterator[int]:
        await self.open_tunnel()
        rng = random.Random(3)
        while True:
            await asyncio.sleep(self.interval)
            yield rng.choice((60, 60, 59, 58, 120, 117, 61))

    async def close(self) -> None:
        self.closed = True
        await undo_all(self._clear_condition, self._clear_location, timeout=self.close_timeout)

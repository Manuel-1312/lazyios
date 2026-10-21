"""Pure helpers: syslog lines, packet headers, DNS and TLS names, filters."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from functools import lru_cache
from ipaddress import IPv4Address, IPv6Address

from .backend import LogLine

_SYSLOG = re.compile(
    r"^(?P<time>\w{3}\s+\d+\s+[\d:]{8})\s+\S+\s+"
    r"(?P<proc>[^\[\]]+?)(?:\((?P<image>[^)]*)\))?\[(?P<pid>\d+)\]\s+"
    r"<(?P<level>\w+)>:\s?(?P<msg>.*)$",
    re.DOTALL,
)

LEVELS = ("debug", "info", "notice", "warning", "error", "fault")


def parse_syslog_line(raw: str) -> LogLine:
    """Split a syslog relay line; lines that do not match keep the raw text as the message."""
    raw = raw.rstrip("\r\n\x00")
    m = _SYSLOG.match(raw)
    if not m:
        return LogLine("", "", 0, "", raw, raw)
    return LogLine(
        m["time"][-8:],
        m["proc"],
        int(m["pid"]),
        m["level"].lower(),
        m["msg"],
        raw,
    )


def matches_filter(text: str, *fields: str) -> bool:
    """Case-insensitive substring match over the given fields; empty text matches all."""
    needle = text.strip().lower()
    return not needle or any(needle in f.lower() for f in fields)


@dataclass(frozen=True)
class IpInfo:
    proto: str
    src: str
    dst: str
    payload: bytes = b""


_PROTOS = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 58: "icmp6"}


def _endpoint(addr: str, ports: bytes | None, v6: bool) -> str:
    if ports is None:
        return addr
    port = struct.unpack("!H", ports)[0]
    return f"[{addr}]:{port}" if v6 else f"{addr}:{port}"


_EXT_HEADERS = (0, 43, 44, 60)


def _skip_ext_headers(data: bytes) -> tuple[int, bytes] | None:
    """Walk IPv6 extension headers; returns (final protocol, payload) or None if truncated."""
    proto, off, later_fragment = data[6], 40, False
    for _ in range(8):
        if proto not in _EXT_HEADERS:
            break
        if len(data) < off + 8:
            return None
        if proto == 44:
            size = 8
            later_fragment = (
                later_fragment or struct.unpack("!H", data[off + 2 : off + 4])[0] >> 3 != 0
            )
        else:
            size = (data[off + 1] + 1) * 8
        proto, off = data[off], off + size
        if off > len(data):
            return None
    return proto, b"" if later_fragment else data[off:]


def link_offset(frame_pre_length: int, interface: str) -> int:
    """Offset of the IP header in a pcapd frame (a synthetic 14-byte Ethernet header is added
    by the library when the device sends none, and for cellular)."""
    return 14 if not frame_pre_length or interface == "pdp_ip" else frame_pre_length


def parse_ip_packet(data: bytes) -> IpInfo | None:
    """Parse an IPv4/IPv6 packet (no link header); None when it is not parseable."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4 and len(data) >= 20:
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        proto_num = data[9]
        src, dst = str(IPv4Address(data[12:16])), str(IPv4Address(data[16:20]))
        total = struct.unpack("!H", data[2:4])[0]
        if ihl <= total <= len(data):  # drop link padding
            data = data[:total]
        frag = struct.unpack("!H", data[6:8])[0] & 0x1FFF
        l4 = data[ihl:] if frag == 0 else b""
        v6 = False
    elif version == 6 and len(data) >= 40:
        size = struct.unpack("!H", data[4:6])[0]
        if size > 0 and 40 + size <= len(data):
            data = data[: 40 + size]
        src, dst = str(IPv6Address(data[8:24])), str(IPv6Address(data[24:40]))
        walked = _skip_ext_headers(data)
        if walked is None:
            return None
        proto_num, l4 = walked
        v6 = True
    else:
        return None
    proto = _PROTOS.get(proto_num, f"ip/{proto_num}")
    has_ports = proto_num in (6, 17) and len(l4) >= 4
    return IpInfo(
        proto,
        _endpoint(src, l4[0:2] if has_ports else None, v6),
        _endpoint(dst, l4[2:4] if has_ports else None, v6),
        _l4_payload(proto_num, l4),
    )


def _l4_payload(proto_num: int, l4: bytes) -> bytes:
    if proto_num == 6 and len(l4) >= 20:
        offset = (l4[12] >> 4) * 4
        return l4[offset:] if 20 <= offset <= len(l4) else b""
    return l4[8:] if proto_num == 17 else b""


def split_endpoint(endpoint: str) -> tuple[str, int | None]:
    """'1.2.3.4:443', '[::1]:443' or a bare address -> (address, port)."""
    if endpoint.startswith("["):
        addr, _, port = endpoint[1:].partition("]:")
    elif endpoint.count(":") == 1:
        addr, _, port = endpoint.partition(":")
    else:
        return endpoint, None
    return addr, int(port) if port.isascii() and port.isdigit() else None


_HOST = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")


def sanitize_host(name: str | None) -> str | None:
    """Lowercased host name if it only has [A-Za-z0-9._-]; None for anything else."""
    if not name or len(name) > 254:
        return None
    name = name.removesuffix(".").lower()
    return name if len(name) <= 253 and _HOST.fullmatch(name) else None


@lru_cache(maxsize=8192)  # called for every packet with the same few process names
def clean_text(value: str, limit: int = 64) -> str:
    """Printable characters only, bounded: for names that come from the device."""
    return "".join(c for c in value[:limit] if c.isprintable())


DNS_MAX_JUMPS = 16
DNS_MAX_QUESTIONS = 4
DNS_MAX_RECORDS = 64
_DNS_CHAIN = 8


def _dns_name(data: bytes, off: int) -> tuple[str, int] | None:
    """Read a (possibly compressed) name; returns (name, offset after it) or None."""
    labels: list[str] = []
    end, jumps, total = None, 0, 0
    while off < len(data):
        n = data[off]
        if n == 0:
            return ".".join(labels).lower(), off + 1 if end is None else end
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                return None
            end = off + 2 if end is None else end
            jumps += 1
            if jumps > DNS_MAX_JUMPS:
                return None
            off = (n & 0x3F) << 8 | data[off + 1]
            continue
        total += n + 1
        if n & 0xC0 or total > 255 or off + 1 + n > len(data):
            return None
        labels.append(data[off + 1 : off + 1 + n].decode("latin-1"))
        off += 1 + n
    return None


def parse_dns_answers(payload: bytes) -> list[tuple[str, str]]:
    """(ip, name) pairs from a DNS response. A CNAME chain gives one pair per name in it, the
    original question name first. Names are sanitized; malformed input gives what was safe."""
    try:
        return _dns_answers(payload)
    except (struct.error, IndexError, ValueError):
        return []


def _dns_answers(data: bytes) -> list[tuple[str, str]]:
    if len(data) < 12:
        return []
    _, flags, questions, answers = struct.unpack_from("!HHHH", data)
    if not flags & 0x8000 or flags >> 11 & 0xF or questions > DNS_MAX_QUESTIONS:
        return []
    off = 12
    asked: set[str] = set()
    for _ in range(questions):
        read = _dns_name(data, off)
        if read is None or read[1] + 4 > len(data):
            return []
        asked.add(read[0])
        off = read[1] + 4
    addrs: list[tuple[str, str]] = []
    aliases: list[tuple[str, str]] = []  # (owner, cname target)
    parents: dict[str, str] = {}  # cname target -> the name that points at it
    for _ in range(min(answers, DNS_MAX_RECORDS)):
        read = _dns_name(data, off)
        if read is None or read[1] + 10 > len(data):
            break
        owner, off = read
        kind, _, _, size = struct.unpack_from("!HHIH", data, off)
        off += 10
        if off + size > len(data):
            break
        if kind == 1 and size == 4:
            addrs.append((str(IPv4Address(data[off : off + 4])), owner))
        elif kind == 28 and size == 16:
            addrs.append((str(IPv6Address(data[off : off + 16])), owner))
        elif kind == 5 and (target := _dns_name(data, off)):
            aliases.append((owner, target[0]))
            parents.setdefault(target[0], owner)
        off += size
    reachable = set(asked)  # names the question leads to; answers for other names are forged
    for _ in range(_DNS_CHAIN):
        reachable |= {target for owner, target in aliases if owner in reachable}
    out: list[tuple[str, str]] = []
    for ip, owner in addrs:
        if owner not in reachable:
            continue
        chain = [owner]
        while len(chain) < _DNS_CHAIN and (parent := parents.get(chain[-1])) not in (None, *chain):
            if parent not in reachable:
                break
            chain.append(parent)  # type: ignore[arg-type]
        for name in reversed(chain):
            if (host := sanitize_host(name)) and (ip, host) not in out:
                out.append((ip, host))
    return out


def parse_tls_sni(payload: bytes) -> str | None:
    """Server name of a TLS ClientHello; None when absent, malformed or cut off before it."""
    try:
        return _tls_sni(payload)
    except (struct.error, IndexError, ValueError):
        return None


def _tls_sni(d: bytes) -> str | None:
    if len(d) < 44 or d[0] != 22 or d[5] != 1:  # handshake record, ClientHello
        return None
    off = 43 + 1 + d[43]  # skip version, random, session id
    off += 2 + struct.unpack_from("!H", d, off)[0]  # cipher suites
    off += 1 + d[off]  # compression methods
    end = min(len(d), off + 2 + struct.unpack_from("!H", d, off)[0])
    off += 2
    while off + 4 <= end:
        kind, size = struct.unpack_from("!HH", d, off)
        off += 4
        if kind == 0:  # server_name: list length, entry type (0 = host_name), length, name
            _, entry, length = struct.unpack_from("!HBH", d, off)
            name = d[off + 5 : off + 5 + length]
            if entry != 0 or len(name) < length:
                return None
            return sanitize_host(name.decode("ascii"))
        off += size
    return None

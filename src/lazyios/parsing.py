"""Pure helpers: syslog lines, packet headers, filters."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
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
        frag = struct.unpack("!H", data[6:8])[0] & 0x1FFF
        l4 = data[ihl:] if frag == 0 else b""
        v6 = False
    elif version == 6 and len(data) >= 40:
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
    )

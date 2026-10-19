import struct

import pytest

from lazyios.parsing import link_offset, matches_filter, parse_ip_packet, parse_syslog_line
from lazyios.tabs.tools import parse_coords

LINE = "Oct 19 03:43:47 iPhone-2 ReportCrashService(libxpc.dylib)[660] <Notice>: Session created."


def test_syslog_line_fields():
    line = parse_syslog_line(LINE)
    assert line.time == "03:43:47"
    assert line.process == "ReportCrashService"
    assert line.pid == 660
    assert line.level == "notice"
    assert line.message == "Session created."


def test_syslog_line_without_image():
    line = parse_syslog_line("Oct  9 00:00:01 iPhone kernel[0] <Error>: boom: x <y>")
    assert (line.process, line.pid, line.level, line.message) == (
        "kernel",
        0,
        "error",
        "boom: x <y>",
    )


def test_syslog_process_with_spaces():
    line = parse_syslog_line("Oct 19 03:43:47 iPhone Some App[12] <Info>: hi")
    assert line.process == "Some App"


@pytest.mark.parametrize("raw", ["garbage", "", "Oct 19 <Notice>: nope"])
def test_syslog_fallback_keeps_raw(raw):
    line = parse_syslog_line(raw)
    assert line.level == ""
    assert line.message == raw


def test_filter_matching():
    assert matches_filter("", "anything")
    assert matches_filter("  ", "anything")
    assert matches_filter("SPRING", "SpringBoard", "msg")
    assert matches_filter("crash", "proc", "App Crashed")
    assert not matches_filter("zzz", "proc", "msg")


def ipv4(proto: int, payload: bytes, src=(10, 0, 0, 7), dst=(17, 253, 144, 10), ihl=5) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl,
        0,
        ihl * 4 + len(payload),
        0,
        0,
        64,
        proto,
        0,
        bytes(src),
        bytes(dst),
    )
    return header + b"\x00" * ((ihl - 5) * 4) + payload


def ipv6(next_header: int, payload: bytes) -> bytes:
    src = bytes.fromhex("fe800000000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    return struct.pack("!IHBB", 6 << 28, len(payload), next_header, 64) + src + dst + payload


def ports(sport: int, dport: int) -> bytes:
    return struct.pack("!HH", sport, dport) + b"\x00" * 16


def test_ipv4_tcp():
    info = parse_ip_packet(ipv4(6, ports(50000, 443)))
    assert (info.proto, info.src, info.dst) == ("tcp", "10.0.0.7:50000", "17.253.144.10:443")


def test_ipv4_udp_with_options():
    info = parse_ip_packet(ipv4(17, ports(5353, 53), ihl=7))
    assert (info.proto, info.src, info.dst) == ("udp", "10.0.0.7:5353", "17.253.144.10:53")


def test_ipv4_icmp_has_no_ports():
    info = parse_ip_packet(ipv4(1, b"\x08\x00\x00\x00"))
    assert (info.proto, info.src, info.dst) == ("icmp", "10.0.0.7", "17.253.144.10")


def test_ipv6_tcp_and_udp():
    tcp = parse_ip_packet(ipv6(6, ports(51000, 443)))
    assert (tcp.proto, tcp.src, tcp.dst) == ("tcp", "[fe80::1]:51000", "[2001:db8::2]:443")
    udp = parse_ip_packet(ipv6(17, ports(1, 2)))
    assert (udp.proto, udp.src, udp.dst) == ("udp", "[fe80::1]:1", "[2001:db8::2]:2")


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"\x45",
        b"\x45" + b"\x00" * 10,
        b"\x60" + b"\x00" * 20,
        b"\x10" * 40,
        b"\x41" + b"\x00" * 30,
    ],
)
def test_unparseable_packets_return_none(data):
    assert parse_ip_packet(data) is None


def test_truncated_l4_keeps_addresses():
    info = parse_ip_packet(ipv4(6, b"\x01"))
    assert (info.proto, info.src) == ("tcp", "10.0.0.7")


def test_link_offset():
    assert link_offset(14, "en0") == 14
    assert link_offset(4, "lo0") == 4
    assert link_offset(0, "utun3") == 14
    assert link_offset(4, "pdp_ip") == 14


def test_parse_coords():
    assert parse_coords("40.7", "-74.0") == (40.7, -74.0)
    assert parse_coords("91", "0") is None
    assert parse_coords("x", "0") is None


def test_ipv6_hop_by_hop_then_tcp():
    hop = bytes([6, 0]) + bytes(6)  # next header tcp, length 0 -> 8 bytes
    info = parse_ip_packet(ipv6(0, hop + ports(1234, 80)))
    assert (info.proto, info.src, info.dst) == ("tcp", "[fe80::1]:1234", "[2001:db8::2]:80")


def test_ipv6_truncated_extension_header():
    assert parse_ip_packet(ipv6(0, bytes([6, 0, 0]))) is None
    assert parse_ip_packet(ipv6(0, bytes([6, 3]) + bytes(6))) is None


def test_ipv6_later_fragment_has_no_ports():
    frag = bytes([6, 0, 0, 8, 0, 0, 0, 1])  # offset 1
    info = parse_ip_packet(ipv6(44, frag + ports(1, 2)))
    assert (info.proto, info.src) == ("tcp", "fe80::1")

import random
import struct
from dataclasses import replace

import pytest
from test_parsing import ipv4, ports

from lazyios import privacy
from lazyios.backend import Packet
from lazyios.fake import _client_hello, _dns_name, _dns_response
from lazyios.parsing import (
    clean_text,
    parse_dns_answers,
    parse_ip_packet,
    parse_tls_sni,
    sanitize_host,
    split_endpoint,
)
from lazyios.privacy import HostAggregator, TrackerDB, sort_rows

HEADER = struct.pack("!HHHHHH", 1, 0x8180, 1, 1, 0, 0)
QUESTION = _dns_name("a.example.com") + struct.pack("!HH", 1, 1)


def a_record(owner: bytes, ip: bytes = bytes([203, 0, 113, 9])) -> bytes:
    return owner + struct.pack("!HHIH", 1, 1, 60, 4) + ip


# DNS


def test_dns_a_and_aaaa_and_cname_chain():
    plain = _dns_response("api.example.com", "203.0.113.5")
    assert parse_dns_answers(plain) == [("203.0.113.5", "api.example.com")]
    chain = _dns_response(
        "cdn.example.com", "203.0.113.6", "cdn.example.com.edge.net", "2001:db8::6"
    )
    assert parse_dns_answers(chain) == [
        ("203.0.113.6", "cdn.example.com"),
        ("203.0.113.6", "cdn.example.com.edge.net"),
        ("2001:db8::6", "cdn.example.com"),
        ("2001:db8::6", "cdn.example.com.edge.net"),
    ]


def test_dns_names_are_lowercased_and_sanitized():
    data = _dns_response("API.Example.COM", "203.0.113.5")
    assert parse_dns_answers(data) == [("203.0.113.5", "api.example.com")]
    hostile = _dns_response("[red]x.example.com", "203.0.113.5")
    assert parse_dns_answers(hostile) == []


def forged(qname: str, owner: str, ip: str = "8.8.8.8", cname_to: str | None = None) -> bytes:
    question = _dns_name(qname) + struct.pack("!HH", 1, 1)
    records = b""
    if cname_to:
        target = _dns_name(cname_to)
        records += _dns_name(owner) + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        owner = cname_to
    records += a_record(_dns_name(owner), bytes(map(int, ip.split("."))))
    count = 2 if cname_to else 1
    return struct.pack("!HHHHHH", 1, 0x8180, 1, count, 0, 0) + question + records


def test_dns_answer_for_an_unasked_name_is_dropped():
    assert parse_dns_answers(forged("evil.test", "icloud.com")) == []
    assert parse_dns_answers(forged("evil.test", "evil.test")) == [("8.8.8.8", "evil.test")]


def test_dns_cname_must_start_at_the_question():
    ok = forged("cdn.example.com", "cdn.example.com", cname_to="edge.example.net")
    assert parse_dns_answers(ok) == [
        ("8.8.8.8", "cdn.example.com"),
        ("8.8.8.8", "edge.example.net"),
    ]
    assert parse_dns_answers(forged("evil.test", "other.test", cname_to="edge.net")) == []


def test_dns_ignores_queries_and_other_opcodes():
    data = bytearray(_dns_response("api.example.com", "203.0.113.5"))
    data[2] = 0x01  # QR=0
    assert parse_dns_answers(bytes(data)) == []
    data[2:4] = struct.pack("!H", 0x8980)  # response, opcode 1
    assert parse_dns_answers(bytes(data)) == []


def test_dns_pointer_loop_and_out_of_range_pointer():
    loop_question = HEADER + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    assert parse_dns_answers(loop_question) == []
    loop_answer = HEADER + QUESTION + a_record(struct.pack("!H", 0xC000 | (12 + len(QUESTION))))
    assert parse_dns_answers(loop_answer) == []
    far = HEADER + QUESTION + a_record(b"\xff\xff")
    assert parse_dns_answers(far) == []
    two = HEADER + QUESTION + a_record(b"\xc0\x0c") + a_record(b"\xff\xff")
    assert parse_dns_answers(struct.pack("!HHHHHH", 1, 0x8180, 1, 2, 0, 0) + two[12:]) == [
        ("203.0.113.9", "a.example.com")
    ]


def test_dns_truncated_input_never_raises():
    data = _dns_response(
        "cdn.example.com", "203.0.113.6", "cdn.example.com.edge.net", "2001:db8::6"
    )
    full = parse_dns_answers(data)
    for cut in range(len(data)):
        got = parse_dns_answers(data[:cut])
        assert all(pair in full for pair in got)
    assert parse_dns_answers(data[:20]) == []


def test_dns_oversized_label_and_name():
    reserved = HEADER + b"\x46" + b"a" * 70 + b"\x00" + struct.pack("!HH", 1, 1)
    assert parse_dns_answers(reserved) == []
    label = bytes([63]) + b"a" * 63
    long_name = HEADER + label * 5 + b"\x00" + struct.pack("!HH", 1, 1)
    assert parse_dns_answers(long_name + a_record(b"\xc0\x0c")) == []


def test_dns_record_count_is_capped():
    count = 300
    records = b"".join(
        a_record(b"\xc0\x0c", bytes([10, 0, i // 256, i % 256])) for i in range(count)
    )
    data = struct.pack("!HHHHHH", 1, 0x8180, 1, count, 0, 0) + QUESTION + records
    assert len(parse_dns_answers(data)) == 64
    claims_many = (
        struct.pack("!HHHHHH", 1, 0x8180, 1, 65535, 0, 0) + QUESTION + a_record(b"\xc0\x0c")
    )
    assert len(parse_dns_answers(claims_many)) == 1


def test_parsers_survive_random_bytes():
    rng = random.Random(5)
    seed = _dns_response("a.example.com", "203.0.113.5")
    hello = _client_hello("a.example.com")
    for _ in range(3000):
        for base in (seed, hello, b""):
            data = bytearray(base or rng.randbytes(rng.randint(0, 80)))
            for _ in range(rng.randint(1, 6)):
                if data:
                    data[rng.randrange(len(data))] = rng.randrange(256)
            parse_dns_answers(bytes(data))
            parse_tls_sni(bytes(data))


# TLS


def test_tls_sni_from_client_hello():
    assert parse_tls_sni(_client_hello("Graph.Facebook.com")) == "graph.facebook.com"


def test_tls_sni_truncated():
    hello = _client_hello("app.adjust.com")
    sni_end = hello.index(b"app.adjust.com") + len(b"app.adjust.com")
    assert parse_tls_sni(hello[:sni_end]) == "app.adjust.com"  # later extensions are not needed
    for cut in range(sni_end):
        assert parse_tls_sni(hello[:cut]) is None
    assert parse_tls_sni(b"") is None


def test_tls_rejects_other_records():
    hello = bytearray(_client_hello("app.adjust.com"))
    hello[0] = 23  # application data
    assert parse_tls_sni(bytes(hello)) is None
    hello[0], hello[5] = 22, 2  # ServerHello
    assert parse_tls_sni(bytes(hello)) is None


@pytest.mark.parametrize(
    "name",
    ["[red]x.com", "a\x1b[31mb.com", "bad name.com", "x" * 300 + ".com", "a..b", ".a.com", ""],
)
def test_hostile_names_are_rejected(name):
    assert sanitize_host(name) is None
    assert parse_tls_sni(_client_hello(name)) is None


def test_sanitize_host_normalizes():
    assert sanitize_host("Example.COM.") == "example.com"
    assert sanitize_host("a_b-c.example.com") == "a_b-c.example.com"
    assert sanitize_host(None) is None
    assert sanitize_host("é.com") is None


def test_clean_text_and_split_endpoint():
    assert clean_text("a\x1b[31m\nb") == "a[31mb"
    assert len(clean_text("x" * 500)) == 64
    assert split_endpoint("1.2.3.4:443") == ("1.2.3.4", 443)
    assert split_endpoint("[2001:db8::1]:53") == ("2001:db8::1", 53)
    assert split_endpoint("2001:db8::1") == ("2001:db8::1", None)
    assert split_endpoint("-") == ("-", None)
    assert split_endpoint("1.2.3.4:²") == ("1.2.3.4", None)


# L4 payload


def test_payload_of_tcp_and_udp():
    tcp = (
        struct.pack("!HHIIBBHHH", 5000, 443, 0, 0, 0x60, 0x18, 1024, 0, 0) + b"\x00" * 4 + b"hello"
    )
    assert parse_ip_packet(ipv4(6, tcp)).payload == b"hello"
    udp = struct.pack("!HHHH", 5000, 53, 8 + 3, 0) + b"abc"
    assert parse_ip_packet(ipv4(17, udp)).payload == b"abc"


def test_payload_respects_bounds():
    bad_offset = struct.pack("!HHIIBBHHH", 1, 2, 0, 0, 0xF0, 0x10, 0, 0, 0) + b"xx"
    assert parse_ip_packet(ipv4(6, bad_offset)).payload == b""
    assert parse_ip_packet(ipv4(6, ports(1, 2)[:10])).payload == b""
    assert parse_ip_packet(ipv4(17, b"\x00\x01")).payload == b""
    padded = ipv4(17, struct.pack("!HHHH", 1, 53, 11, 0) + b"abc") + b"\x00" * 6  # link padding
    assert parse_ip_packet(padded).payload == b"abc"


# tracker data and aggregation

DB = TrackerDB({"tracker.net": ["analytics", "Tracker Inc"], "com": ["ads", "Everyone"]})
PHONE = "192.168.0.204"


def pkt(proc="App", pid=7, proto="tcp", src=None, dst=None, payload=b"", length=100, when=1.0):
    return Packet(when, pid, proc, "en0", proto, src or f"{PHONE}:50000", dst or "203.0.113.5:443",
                  length, payload)  # fmt: skip


def answer(host, ip, **kw):
    return pkt("mDNSResponder", 70, "udp", "192.168.0.1:53", f"{PHONE}:50001",
                _dns_response(host, ip, **kw))  # fmt: skip


def test_tracker_classification():
    db = TrackerDB()

    def tracker(host):
        hit = db.lookup(host)
        return bool(hit) and hit[0] in privacy.TRACKER_CATEGORIES

    for host in ("app-measurement.com", "graph.facebook.com", "api.mixpanel.com",
                 "app.adjust.com", "googleads.g.doubleclick.net", "sdk.iad-01.braze.com",
                 "firebaselogging-pa.googleapis.com", "o1.ingest.sentry.io"):  # fmt: skip
        assert tracker(host), host
    for host in ("mtalk.google.com", "fcm.googleapis.com", "yahoo.com", "samsungapps.com",
                 "whatsapp.net", "chat.google.com", "gateway.icloud.com"):  # fmt: skip
        assert not tracker(host), host


def test_tracker_lookup_walks_suffixes():
    assert DB.lookup("a.b.tracker.net") == ("analytics", "Tracker Inc")
    assert DB.lookup("tracker.net") == ("analytics", "Tracker Inc")
    assert DB.lookup("tracker.net.evil.org") is None
    assert DB.lookup("x.com") is None  # never below two labels
    assert DB.lookup("203.0.113.5") is None
    assert DB.lookup("2001:db8::1") is None


def test_bundled_data_loads():
    db = TrackerDB()
    assert db.lookup("sdk.iad-01.braze.com")
    assert db.lookup("api2.branch.io")
    assert db.lookup("gateway.icloud.com") is not None
    assert db.lookup("api.fittrack.example") is None
    assert all(len(v) == 2 for v in db.data.values())


def test_dns_answer_names_the_flow_and_flags_the_tracker():
    agg = HostAggregator(DB)
    agg.feed(answer("sdk.tracker.net", "203.0.113.5"))
    agg.feed(pkt(length=300))
    agg.feed(pkt(src="203.0.113.5:443", dst=f"{PHONE}:50000", length=700, when=2.0))
    agg.feed(pkt(src=f"{PHONE}:50002", when=3.0))
    (row,) = [r for r in agg.rows() if r.process == "App"]
    assert (row.domain, row.category, row.company) == (
        "sdk.tracker.net",
        "analytics",
        "Tracker Inc",
    )
    assert row.tracker
    assert (row.flows, row.bytes, row.first, row.last) == (2, 1100, 1.0, 3.0)
    assert row.ips == ["203.0.113.5"]


def test_sni_wins_and_absorbs_the_bare_address_row():
    agg = HostAggregator(DB)
    agg.feed(pkt(length=60))  # SYN before any name is known
    assert [r.domain for r in agg.rows()] == ["203.0.113.5"]
    agg.feed(pkt(payload=_client_hello("api.tracker.net"), length=500, when=2.0))
    (row,) = agg.rows()
    assert (row.domain, row.bytes, row.first) == ("api.tracker.net", 560, 1.0)
    other = pkt("Other", 8)
    agg.feed(other)  # the name is per app, another app sees the DNS map only
    assert {(r.process, r.domain) for r in agg.rows()} == {
        ("App", "api.tracker.net"),
        ("Other", "203.0.113.5"),
    }


def test_kernel_packets_are_ignored_for_rows_but_dns_is_learned():
    agg = HostAggregator(DB)
    dns = answer("sdk.tracker.net", "203.0.113.5")
    agg.feed(replace(dns, pid=0xFFFFFFFF, process=""))
    agg.feed(pkt("", 0xFFFFFFFF))
    agg.feed(pkt("", 7))
    agg.feed(pkt("App", 0xFFFFFFFF))
    assert agg.rows() == []
    agg.feed(pkt())
    assert agg.rows()[0].domain == "sdk.tracker.net"


def test_rows_and_names_are_bounded(monkeypatch):
    monkeypatch.setattr(privacy, "MAX_ROWS", 5)
    monkeypatch.setattr(privacy, "MAX_NAMES", 8)
    agg = HostAggregator(DB)
    for i in range(40):
        agg.feed(answer(f"h{i}.example.org", f"203.0.113.{i + 1}"))
        agg.feed(pkt(dst=f"203.0.113.{i + 1}:443", when=float(i)))
    assert len(agg.rows()) == 5
    assert len(agg._names) == 8
    assert [r.domain for r in agg.rows()][-1] == "h39.example.org"
    for i in range(40):
        agg.feed(pkt(payload=_client_hello(f"s{i}.example.org"), dst=f"198.51.100.{i + 1}:443"))
    assert len(agg._sni) <= 8


def test_flow_set_is_capped(monkeypatch):
    monkeypatch.setattr(privacy, "MAX_FLOWS", 10)
    agg = HostAggregator(DB)
    for port in range(50000, 50100):
        agg.feed(pkt(src=f"{PHONE}:{port}"))
    assert agg.rows()[0].flows == 10


def test_summary_counts_and_reset():
    agg = HostAggregator(DB)
    agg.feed(answer("sdk.tracker.net", "203.0.113.5"))
    agg.feed(answer("www.fine.org", "203.0.113.6"))
    agg.feed(pkt("A", 1))
    agg.feed(pkt("B", 2))
    agg.feed(pkt("B", 2, dst="203.0.113.6:443"))
    assert agg.summary() == (3, 3, 1)  # the resolver's own traffic counts as an app
    agg.reset()
    assert agg.summary() == (0, 0, 0) and agg.rows() == []


def test_csv_cells(tmp_path):
    from lazyios.privacy import HostRow, write_report

    _, csv_path = write_report([HostRow("A", "x.example", bytes=1, first=1.0, last=1.0)], tmp_path)
    line = csv_path.read_text(encoding="utf-8").splitlines()[1]
    assert line.startswith("A,x.example,,,False,0,1,")  # empty cells stay empty


def test_sort_modes():
    agg = HostAggregator(DB)
    agg.feed(answer("sdk.tracker.net", "203.0.113.5"))
    agg.feed(answer("www.fine.org", "203.0.113.6"))
    agg.feed(pkt("Zed", 1, length=10))
    agg.feed(pkt("Abe", 2, dst="203.0.113.6:443", length=5000))
    rows = [r for r in agg.rows() if r.process != "mDNSResponder"]
    assert [r.domain for r in sort_rows(rows, "bytes")] == ["sdk.tracker.net", "www.fine.org"]
    assert [r.process for r in sort_rows(rows, "app")] == ["Abe", "Zed"]
    assert [r.domain for r in sort_rows(rows, "domain")] == ["sdk.tracker.net", "www.fine.org"]
    assert len(sort_rows(rows, "flows")) == 2


def test_aggregator_ignores_junk_packets():
    agg = HostAggregator(DB)
    for p in (
        Packet(1.0, 1, "App", "en0", "other", "-", "-", 10),
        Packet(1.0, 1, "App", "en0", "tcp", "nonsense", "also:nonsense", 10),
        Packet(1.0, 1, "App", "en0", "udp", "1.2.3.4:53", "5.6.7.8:1", 10, b"\xff" * 40),
    ):
        agg.feed(p)
    assert [r.domain for r in agg.rows()] == ["5.6.7.8"]  # the junk payload is just ignored

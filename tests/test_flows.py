import csv
import hashlib
import json
from datetime import datetime

from test_privacy import DB, PHONE, answer, pkt

from lazyios import flows as flows_module
from lazyios.backend import Packet
from lazyios.fake import _client_hello
from lazyios.flows import FlowTable, matches, sort_flows, write_flows
from lazyios.privacy import KERNEL_PID, HostAggregator


def table() -> tuple[HostAggregator, FlowTable]:
    agg = HostAggregator(DB)
    return agg, FlowTable(agg)


def feed(agg: HostAggregator, flows: FlowTable, *packets: Packet) -> None:
    for p in packets:  # the order the app uses: names first, then flows
        agg.feed(p)
        flows.feed(p)


def inbound(**kw) -> Packet:
    return pkt(src="203.0.113.5:443", dst=f"{PHONE}:50000", **kw)


def test_bytes_each_way_land_on_one_connection():
    agg, flows = table()
    feed(agg, flows, pkt(length=100), inbound(length=1500), inbound(length=1500))
    [flow] = flows.rows()
    assert (flow.local, flow.remote, flow.remote_ip, flow.rport) == (
        f"{PHONE}:50000", "203.0.113.5:443", "203.0.113.5", 443,
    )  # fmt: skip
    assert (flow.tx_bytes, flow.rx_bytes, flow.tx_packets, flow.rx_packets) == (100, 3000, 1, 2)
    assert flow.bytes == 3100


def test_new_and_recurrent_destinations():
    agg, flows = table()
    feed(agg, flows, pkt(src=f"{PHONE}:50000"), pkt(src=f"{PHONE}:50001"))
    feed(agg, flows, pkt(src=f"{PHONE}:50002", dst="198.51.100.7:443"))
    first, second, other = flows.rows()
    assert (first.seen, first.new) == (1, True)
    assert (second.seen, second.new) == (2, False)  # the app came back to the same place
    assert other.new
    assert flows.summary()["new_destinations"] == 2


def test_same_ports_from_two_apps_are_two_connections():
    agg, flows = table()
    feed(agg, flows, pkt("A", 1), pkt("B", 2))
    assert sorted(f.process for f in flows.rows()) == ["A", "B"]


def test_domain_confidence_upgrades_from_dns_to_sni():
    agg, flows = table()
    feed(agg, flows, pkt())
    assert (flows.rows()[0].name, flows.rows()[0].confidence) == ("", "none")
    feed(agg, flows, answer("cdn.example.org", "203.0.113.5"), pkt())
    flow = next(f for f in flows.rows() if f.process == "App")
    assert (flow.name, flow.source, flow.confidence) == ("cdn.example.org", "dns", "medium")
    feed(agg, flows, pkt(payload=_client_hello("api.example.org")))
    assert (flow.name, flow.source, flow.confidence) == ("api.example.org", "sni", "high")
    feed(agg, flows, answer("other.example.org", "203.0.113.5"), pkt())
    assert flow.name == "api.example.org"  # a later DNS answer never overrides the app's SNI


def test_sni_from_another_app_is_not_borrowed():
    agg, flows = table()
    feed(agg, flows, pkt("A", 1, payload=_client_hello("a.example.org")), pkt("B", 2))
    b = next(f for f in flows.rows() if f.process == "B")
    assert b.source == "ip"


def test_kernel_and_junk_packets():
    agg, flows = table()
    feed(
        agg,
        flows,
        pkt("", KERNEL_PID, "udp", f"{PHONE}:57621", "192.168.0.255:57621"),
        Packet(1.0, 1, "App", "en0", "other", "-", "-", 10),
        Packet(1.0, 1, "App", "en0", "tcp", "nonsense", "also:nonsense", 10),
    )
    [flow] = flows.rows()
    assert flow.process == "-"


def test_connections_and_destinations_are_bounded(monkeypatch):
    monkeypatch.setattr(flows_module, "MAX_FLOWS", 10)
    monkeypatch.setattr(flows_module, "MAX_DESTS", 5)
    agg, flows = table()
    for port in range(50000, 50050):
        feed(agg, flows, pkt(src=f"{PHONE}:{port}", dst=f"203.0.113.{port % 40 + 1}:443"))
    assert len(flows.rows()) == 10
    assert len(flows._dests) == 5


def test_active_and_reset():
    agg, flows = table()
    feed(agg, flows, pkt(when=1.0), pkt(src=f"{PHONE}:50001", when=100.0))
    old, fresh = flows.rows()
    assert not flows.active(old) and flows.active(fresh)
    assert flows.summary()["active"] == 1
    version = flows.version
    flows.reset()
    assert flows.rows() == [] and flows.version > version


def test_query_fields_and_words():
    agg, flows = table()
    feed(agg, flows, answer("api.example.org", "203.0.113.5"), pkt("Maps", 9))
    feed(agg, flows, pkt("Notes", 8, "udp", dst="[2001:db8::7]:53"))
    maps = next(f for f in flows.rows() if f.process == "Maps")
    notes = next(f for f in flows.rows() if f.process == "Notes")
    assert matches(maps, "") and matches(maps, "maps")
    assert matches(maps, "app:map proto:tcp port:443 domain:example ip:203.0.113")
    assert not matches(maps, "port:44")  # ports are exact
    assert not matches(maps, "proto:tc")
    assert not matches(maps, "maps proto:udp")  # every word must match
    assert matches(notes, "2001:db8::7") and matches(notes, "ip:2001:db8")
    assert matches(notes, "port:53 proto:udp")
    assert matches(maps, "port:50000")  # the local port counts too
    assert not matches(notes, "domain:example")
    assert matches(maps, "unknown:thing") is False


def test_sort_modes():
    agg, flows = table()
    feed(agg, flows, pkt("Zed", 1, length=10, when=5.0), pkt("Abe", 2, length=900, when=1.0))
    rows = flows.rows()
    assert [f.process for f in sort_flows(rows, "last")] == ["Zed", "Abe"]
    assert [f.process for f in sort_flows(rows, "bytes")] == ["Abe", "Zed"]
    assert [f.process for f in sort_flows(rows, "app")] == ["Abe", "Zed"]


def test_export_has_confidence_and_a_checksum(tmp_path):
    agg, flows = table()
    feed(agg, flows, pkt("=cmd|' /c calc'!A1", 3, payload=_client_hello("api.example.org")))
    feed(agg, flows, pkt(src=f"{PHONE}:50001", dst="198.51.100.9:443"))
    json_path, csv_path, sums = write_flows(
        flows, flows.rows(), tmp_path, datetime(2026, 10, 21, 12, 0, 0)
    )
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert doc["summary"]["connections"] == 2
    assert {r["confidence"] for r in doc["rows"]} == {"high", "none"}
    assert "medium" in doc["confidence"]
    cells = list(csv.reader(csv_path.open(encoding="utf-8")))
    assert cells[0][:3] == ["app", "pid", "proto"]
    assert cells[1][0].startswith("'=")  # no formula in a spreadsheet
    lines = sums.read_text().splitlines()
    for line, path in zip(lines, (json_path, csv_path), strict=True):
        assert line == f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"


def test_kernel_packets_on_an_app_socket_belong_to_that_app():
    agg, flows = table()
    feed(agg, flows, pkt("ChatGPT", 5, "udp", length=1200))
    feed(agg, flows, inbound(proc="", pid=KERNEL_PID, proto="udp", length=900))
    [flow] = flows.rows()
    assert (flow.process, flow.tx_bytes, flow.rx_bytes) == ("ChatGPT", 1200, 900)
    feed(agg, flows, inbound(proc="", pid=KERNEL_PID, proto="tcp"))  # other protocol: no match
    assert [f.process for f in flows.rows()] == ["ChatGPT", "-"]


def test_socket_owners_are_dropped_with_their_flow(monkeypatch):
    monkeypatch.setattr(flows_module, "MAX_FLOWS", 3)
    agg, flows = table()
    for port in range(50000, 50010):
        feed(agg, flows, pkt(src=f"{PHONE}:{port}"))
    assert len(flows._owners) == 3

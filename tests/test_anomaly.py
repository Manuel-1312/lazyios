import json

import pytest

from lazyios import anomaly
from lazyios.anomaly import Detector, Thresholds, load, parse
from lazyios.flows import Flow
from lazyios.privacy import HostRow
from lazyios.sessions import AppHistory, Session

KB = 1024


def flow(when, app="QuickChat", remote="203.0.113.9", port=443, name="push.example"):
    return Flow(1, app, "tcp", "en0", "192.168.0.2:50000", f"{remote}:{port}", remote, port,
                when, when, domain=name, source="sni" if name else "ip")  # fmt: skip


def row(domain, when, app="App"):
    return HostRow(app, domain, "", "", 10, when, when, source="sni")


def rules(*names) -> Detector:
    return Detector(Thresholds(rules=names))


# config


def test_parse_valid_and_defaults():
    t = parse(json.dumps({"spike_factor": 3, "beacon_count": 4, "rules": ["beacon", "beacon"]}))
    assert t.spike_factor == 3 and t.beacon_count == 4 and t.rules == ("beacon",)
    assert parse("{}") == Thresholds()


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ("[]", "expected a JSON object"),
        ('{"spike_facter": 3}', "unknown keys: spike_facter"),
        ('{"spike_factor": true}', "spike_factor must be a number"),
        ('{"beacon_count": 4.5}', "beacon_count must be a whole number"),
        ('{"spike_factor": 1}', "between 1.5 and 1000"),
        ('{"rules": ["spike", "magic"]}', "rules must be a list"),
        ('{"rules": "spike"}', "rules must be a list"),
    ],
)
def test_parse_rejects(data, message):
    with pytest.raises(ValueError, match=message):
        parse(data)


def test_load_reports_problems(tmp_path):
    assert load(tmp_path) == (Thresholds(), None)
    (tmp_path / "anomaly.json").write_text('{"window_s": 0}', encoding="utf-8")
    thresholds, problem = load(tmp_path)
    assert thresholds == Thresholds() and "window_s must be between" in problem


# spike


def test_spike_needs_history_then_flags_a_big_window():
    d = rules("spike")
    for i in range(7):  # seven 10 s windows of ~10 KB
        d.packet("App", 10 * KB, i * 10.0)
    d.packet("App", 3000 * KB, 70.0)  # a 3 MB window...
    assert not d.findings
    d.packet("App", 1, 80.0)  # ...is judged when it closes
    [f] = d.findings
    assert f.rule == "spike" and f.app == "App" and "its median" in f.summary
    assert "median 10.0 KB over the last 7 windows" in f.detail


def test_no_spike_below_the_floor_or_without_history():
    d = rules("spike")
    d.packet("App", 3000 * KB, 0.0)
    d.packet("App", 1, 10.0)
    assert not d.findings  # no history
    for i in range(2, 10):
        d.packet("App", 10, i * 10.0)
    d.packet("App", 500 * KB, 100.0)  # 50000x the median but under 1 MB
    d.packet("App", 1, 110.0)
    assert not d.findings


def test_idle_windows_count_as_zero():
    d = rules("spike")
    d.packet("App", 10, 0.0)
    d.packet("App", 10, 100.0)  # nine idle windows in between
    assert list(d._past["App"]) == [10.0] + [0.0] * 9


# beacon


def test_beacon_at_a_steady_interval():
    d = rules("beacon")
    for i, jitter in enumerate((0, 0.2, -0.1, 0.1, 0, -0.2)):
        d.connection(flow(i * 30.0 + jitter))
    [f] = d.findings
    assert f.rule == "beacon" and "6 connections to push.example every 30.0 s" in f.summary
    d.connection(flow(180.0))
    assert len(d.findings) == 1  # cooldown


def test_no_beacon_when_irregular_or_too_fast():
    irregular = rules("beacon")
    for when in (0, 5, 40, 41, 90, 200):
        irregular.connection(flow(float(when)))
    fast = rules("beacon")
    for i in range(6):
        fast.connection(flow(i * 1.0))
    kernel = rules("beacon")
    for i in range(6):
        kernel.connection(flow(i * 30.0, app="-"))
    assert not irregular.findings and not fast.findings and not kernel.findings


# fanout


def test_fanout_of_never_seen_domains_needs_history():
    d = Detector(Thresholds(rules=("fanout",), fanout_count=3), {"App": {"old.example"}})
    d.domain(row("old.example", 0.0))
    d.domain(row("a.example", 1.0))
    d.domain(row("a.example", 2.0))  # the same domain twice counts once
    d.domain(row("b.example", 3.0))
    assert not d.findings
    d.domain(row("c.example", 4.0))
    [f] = d.findings
    assert "3 never-seen domains within 60 s" in f.summary and "c.example" in f.detail
    d.domain(row("x.example", 1.0, app="NoHistory"))
    d.domain(row("y.example", 2.0, app="NoHistory"))
    d.domain(row("z.example", 3.0, app="NoHistory"))
    assert len(d.findings) == 1


def test_fanout_window():
    d = Detector(Thresholds(rules=("fanout",), fanout_count=3), {"App": set()})
    for i, name in enumerate(("a", "b", "c")):
        d.domain(row(f"{name}.example", i * 100.0))
    assert not d.findings


# change


def session(seconds, size, app="App"):
    return Session("", "U", {app: AppHistory(None, {}, size)}, seconds)


def test_change_against_earlier_sessions():
    earlier = [session(600, 600 * KB)] * 3  # 60 KB per minute
    rows = [HostRow("App", "a.example", bytes=60 * 1024 * KB, first=0.0, last=120.0)]
    d = rules("change")
    d.session_end(rows, earlier)
    [f] = d.findings
    assert "30.0 MB/min against a median of 60.0 KB/min" in f.summary
    assert "3 earlier sessions" in f.detail


def test_no_change_without_enough_history_or_time():
    rows = [HostRow("App", "a.example", bytes=60 * 1024 * KB, first=0.0, last=120.0)]
    few = rules("change")
    few.session_end(rows, [session(600, 600 * KB)] * 2)
    short_history = rules("change")
    short_history.session_end(rows, [session(30, 600 * KB)] * 3)
    short_now = rules("change")
    short_now.session_end([HostRow("App", "a", bytes=10**9, first=0.0, last=30.0)],
                          [session(600, 600 * KB)] * 3)  # fmt: skip
    assert not (few.findings or short_history.findings or short_now.findings)


def test_state_is_bounded(monkeypatch):
    monkeypatch.setattr(anomaly, "MAX_KEYS", 10)
    d = Detector()
    for i in range(50):
        d.packet(f"App{i}", 10, 0.0)
        d.connection(flow(0.0, app=f"App{i}"))
    assert len(d._window) <= 11 and len(d._starts) <= 11

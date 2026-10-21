import hashlib
import json
from datetime import datetime

from lazyios import timeline as timeline_module
from lazyios.backend import LogLine, Process
from lazyios.timeline import Event, Timeline, iso, parse_query, process_events, write_timeline

NOON = datetime(2026, 10, 21, 12, 0, 0).timestamp()


def log(level="error", process="wifid", message="scan failed"):
    return LogLine("12:00:00", process, 70, level, message)


def test_events_are_bounded_and_cleaned(monkeypatch):
    monkeypatch.setattr(timeline_module, "MAX_EVENTS", 3)
    t = Timeline()
    for i in range(5):
        t.add("device", f"e{i}\x1b[31m", when=float(i), app="A\x00")
    assert [e.summary for e in t.events()] == ["e2[31m", "e3[31m", "e4[31m"]
    assert t.events()[0].app == "A"


def test_syslog_errors_fold_per_process_and_minute_faults_do_not():
    t = Timeline()
    t.syslog(log(), NOON)
    t.syslog(log(message="again"), NOON + 10)
    t.syslog(log(message="third"), NOON + 59)
    t.syslog(log(process="dasd"), NOON + 20)
    t.syslog(log(level="info"), NOON + 21)
    t.syslog(log(level="fault", message="crash"), NOON + 22)
    t.syslog(log(level="fault", message="crash"), NOON + 23)
    t.syslog(log(message="later"), NOON + 61)
    events = t.events()
    wifid = [e for e in events if e.app == "wifid"]
    assert [e.count for e in wifid] == [3, 1, 1, 1]  # folded errors, two faults, a new minute
    assert wifid[0].summary == "3 errors within 60 s" and "third" in wifid[0].detail
    assert sum(e.app == "dasd" for e in events) == 1
    assert all(e.source == "syslog" for e in events)


def test_process_starts_and_exits():
    before = {1: Process(1, "launchd", False, ""), 9: Process(9, "Maps", True, "10-21 11:59:00")}
    now = {1: before[1], 7: Process(7, "Notes", True, "10-21 12:00:01"),
           8: Process(8, "cfprefsd", False, "10-21 12:00:02")}  # fmt: skip
    events = process_events(before, now, NOON, 5.0)
    assert events[0] == ("app", "started (pid 7)", "Notes", "start time on device 10-21 12:00:01")
    assert events[1][:3] == ("process", "started (pid 8)", "cfprefsd")
    assert events[2][:3] == ("app", "exited (pid 9)", "Maps")
    assert "in the 5 s before" in events[2][3]


def test_query_fields():
    now = NOON
    q = parse_query("kind:app,anomaly,bogus app:map since:11:00 until:11:30 crash", now)
    assert q.kinds == {"app", "anomaly"} and q.app == "map" and q.words == ("crash",)
    assert q.since == datetime(2026, 10, 21, 11, 0).timestamp()
    assert q.until == datetime(2026, 10, 21, 11, 30).timestamp() + 0.999
    inside = Event(q.since + 60, "app", "crash report", app="Maps")
    assert q.matches(inside)
    assert not q.matches(Event(q.since - 1, "app", "crash", app="Maps"))
    assert not q.matches(Event(q.since + 60, "syslog", "crash", app="Maps"))
    assert parse_query("last:5m", now).since == now - 300
    assert parse_query("last:2h", now).since == now - 7200
    assert parse_query("since:25:00 kind:nothing", now).words == ("since:25:00", "kind:nothing")


def test_export_has_offset_times_epoch_and_checksum(tmp_path):
    events = [Event(NOON, "device", "connected", app="iPhone18,1"), Event(NOON + 1.5, "app", "=x")]
    json_path, csv_path, sums = write_timeline(events, "kind:app", tmp_path, datetime(2026, 10, 21))
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert doc["filter"] == "kind:app" and "device capture timestamp" in doc["clocks"]
    first = doc["events"][0]
    assert first["time"] == iso(NOON) and first["epoch"] == NOON
    assert first["time"][-6] in "+-"  # an explicit UTC offset
    assert "'=x" in csv_path.read_text(encoding="utf-8")
    line = sums.read_text().splitlines()[0]
    assert line.startswith(hashlib.sha256(json_path.read_bytes()).hexdigest())


def test_events_with_the_same_time_keep_their_order():
    t = Timeline()
    for name in ("a", "b", "c"):
        t.add("capture", name, when=1.0)  # the Windows clock often gives equal times
    newest = sorted(t.events(), key=lambda e: (e.time, e.seq), reverse=True)
    assert [e.summary for e in newest] == ["c", "b", "a"]

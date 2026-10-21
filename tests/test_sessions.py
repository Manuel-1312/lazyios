import json
import stat
import sys
from datetime import datetime

import pytest

from lazyios import sessions
from lazyios.backend import App
from lazyios.privacy import HostRow
from lazyios.sessions import (
    baseline,
    compare,
    load,
    parse,
    save,
    snapshot,
    versions_by_process,
)

WHEN = datetime(2026, 10, 21, 12, 0, 0)


def row(app, domain, category="", source="sni"):
    return HostRow(app, domain, category, "", 10, 1.0, 1.0, source=source)


def session_json(udid="U1", apps=None, started="2026-10-20T10:00:00") -> str:
    return json.dumps({"format": 1, "started": started, "udid": udid, "apps": apps or {}})


def test_versions_skip_shared_executables_and_match_truncated_names():
    apps = [
        App("Maps", "com.a.maps", "3.2", "Maps"),
        App("Flutter one", "com.a.one", "1.0", "Runner"),
        App("Flutter two", "com.a.two", "2.0", "Runner"),
        App("Long", "com.a.long", "9.1", "VeryLongExecutableName"),
        App("NoVersion", "com.a.nov", "", "NoVersion"),
    ]
    found = versions_by_process(apps)
    assert found["Maps"] == "3.2"
    assert "Runner" not in found  # two apps share it: no version is better than a wrong one
    assert found["VeryLongExecutab"] == "9.1"  # what pcapd reports, 16 characters
    assert "NoVersion" not in found


def test_snapshot_keeps_names_not_addresses():
    data = snapshot(
        [row("A", "x.example", "ads"), row("A", "203.0.113.5", source="ip")],
        {"A": "1.0"},
        "U1",
        WHEN,
    )
    assert data["apps"] == {"A": {"version": "1.0", "bytes": 20, "domains": {"x.example": "ads"}}}
    assert data["seconds"] == 0.0
    assert parse(json.dumps(data)) is not None


def test_save_keeps_the_newest(tmp_path):
    for i in range(5):
        save(tmp_path, json.loads(session_json()), keep=3, now=datetime(2026, 1, 1, 0, 0, i))
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == [f"session-20260101-00000{i}-000.json" for i in (2, 3, 4)]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_session_files_are_owner_only(tmp_path):
    path = save(tmp_path / "sessions", json.loads(session_json()), now=WHEN)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "text",
    [
        "not json",
        "[]",
        json.dumps({"format": 2, "started": "", "udid": "", "apps": {}}),
        json.dumps({"format": 1, "started": 1, "udid": "", "apps": {}}),
        session_json(apps={"A": []}),
        session_json(apps={"A": {"version": 3, "domains": {}}}),
        session_json(apps={"A": {"version": None, "domains": []}}),
    ],
)
def test_malformed_sessions_are_rejected(text):
    assert parse(text) is None


def test_hostile_names_in_a_session_are_cleaned():
    text = session_json(
        apps={"A\x1b[31m": {"version": None, "domains": {"[red]x": "ads", "ok.example": 5,
                                                         "Fine.Example": "ads"}}}
    )  # fmt: skip
    session = parse(text)
    assert session is not None
    [(name, app)] = session.apps.items()
    assert name.isprintable() and app.domains == {"fine.example": "ads"}


def test_limits_reject_huge_sessions(monkeypatch):
    monkeypatch.setattr(sessions, "MAX_APPS", 2)
    apps = {f"A{i}": {"version": None, "domains": {}} for i in range(3)}
    assert parse(session_json(apps=apps)) is None


def test_load_skips_bad_and_oversized_files(tmp_path, monkeypatch):
    (tmp_path / "session-1.json").write_text(session_json(), encoding="utf-8")
    (tmp_path / "session-2.json").write_text("{broken", encoding="utf-8")
    (tmp_path / "session-3.json").write_bytes(b"\xff\xfe")
    (tmp_path / "session-4.json").write_text(session_json(udid="U2"), encoding="utf-8")
    assert [s.udid for s in load(tmp_path)] == ["U1", "U2"]
    monkeypatch.setattr(sessions, "MAX_FILE", 10)
    assert load(tmp_path) == []
    assert load(tmp_path / "missing") == []


def test_baseline_is_per_device():
    a1, b1, a2 = (parse(session_json(udid=u)) for u in ("A", "B", "A"))
    assert baseline([a1, b1, a2], "A") == [a1, a2]
    assert baseline([a1, b1, a2], None, limit=2) == [b1, a2]


def test_compare_finds_new_domains_trackers_and_the_last_version():
    old = parse(session_json(apps={"App": {"version": "1.0", "domains": {"api.app.example": ""}}}))
    newer = parse(session_json(apps={"App": {"version": "1.1", "domains": {}}}))
    rows = [
        row("App", "api.app.example"),
        row("App", "sdk.tracker.net", "analytics", source="dns"),
        row("App", "cdn.app.example"),
        row("App", "203.0.113.7", source="ip"),
        row("Other", "x.example"),
    ]
    changes = compare(rows, [old, newer])
    app = changes["App"]
    assert app.known and app.previous_version == "1.1"
    assert app.new_domains == ["sdk.tracker.net", "cdn.app.example"]
    assert app.new_trackers == ["sdk.tracker.net"]
    assert not changes["Other"].known

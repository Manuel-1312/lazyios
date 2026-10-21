import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from rich.text import Text
from textual.widgets import DataTable, RichLog, Static, TabbedContent

from lazyios import usbmuxd
from lazyios.app import LazyiosApp
from lazyios.backend import BackendError, NotTrustedError, UsbmuxdError
from lazyios.fake import FakeBackend
from lazyios.tabs.logs import LogsTab
from lazyios.tabs.network import NetworkTab
from lazyios.tabs.privacy import PrivacyTab
from lazyios.tabs.processes import ProcessesTab

SIZE = (120, 40)
DEMO = "00000000-DEMO000000000000"  # the demo device: its files go here


async def until(pilot, check: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not check():
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError
        await pilot.pause(0.02)


def make(tmp_path: Path, **kwargs) -> tuple[LazyiosApp, FakeBackend]:
    backend = FakeBackend(interval=0.01, **kwargs)
    switch = lambda udid: FakeBackend(udid, interval=0.01)  # noqa: E731
    return LazyiosApp(backend, tmp_path, make_backend=switch), backend


def text_of(app: LazyiosApp, selector: str) -> str:
    return str(app.query_one(selector, Static).content)


async def test_boots_and_shows_device(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.pause()
        assert app.info.name == "iPhone"
        assert "iPhone18,1" in text_of(app, "#status")
        assert "DEMO00000000" in text_of(app, "#view")


async def test_tab_switching(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tabs = app.query_one(TabbedContent)
        for key, name in zip(
            "1234567890",
            (
                "overview",
                "logs",
                "processes",
                "apps",
                "network",
                "tools",
                "privacy",
                "conns",
                "score",
                "timeline",
            ),
            strict=True,
        ):
            await pilot.press(key)
            await until(pilot, lambda name=name: tabs.active == name)


async def test_logs_arrive_and_filter_narrows(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("2")
        logs = app.query_one(LogsTab)
        await until(pilot, lambda: len(logs.buffer) > 20)
        log = logs.query_one(RichLog)
        await until(pilot, lambda: len(log.lines) > 5)
        await pilot.press("slash")
        await pilot.press(*"safari")
        await pilot.pause(0.5)  # filter is debounced
        assert log.lines
        assert all("Safari" in line.text for line in log.lines)
        assert len(log.lines) < len(logs.buffer)


async def test_log_buffer_is_bounded(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE):
        logs = app.query_one(LogsTab)
        from lazyios.tabs.logs import BUFFER

        for i in range(BUFFER + 1000):
            logs.add(logs.buffer[0] if logs.buffer else _line(i))
        assert len(logs.buffer) == BUFFER


def _line(i: int):
    from lazyios.parsing import parse_syslog_line

    return parse_syslog_line(f"Oct 19 12:00:00 d proc[{i}] <Info>: m")


async def test_kill_needs_confirmation(tmp_path):
    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("3")
        tab = app.query_one(ProcessesTab)
        await until(pilot, lambda: tab.query_one(DataTable).row_count > 0)
        await pilot.press("k")
        await pilot.pause()
        await pilot.press("n")
        await pilot.pause()
        assert backend.killed == []
        await pilot.press("k")
        await pilot.pause()
        await pilot.press("y")
        await until(pilot, lambda: backend.killed)
        assert backend.killed == [1]


async def test_enter_on_default_button_does_not_kill(tmp_path):
    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("3")
        await until(pilot, lambda: app.query_one(ProcessesTab).query_one(DataTable).row_count > 0)
        await pilot.press("k")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert backend.killed == []


async def test_condition_is_cleared_on_quit(tmp_path):
    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("5")
        tab = app.query_one(NetworkTab)
        await until(pilot, lambda: tab.conditions)
        table = tab.query_one("#conditions", DataTable)
        table.focus()
        await pilot.press("enter")
        await until(pilot, lambda: backend.active_condition is not None)
        assert backend.active_condition.profile_id == "SlowNetwork3G"
        assert "cond SlowNetwork3G" in text_of(app, "#status")
        await pilot.press("q")
    assert backend.active_condition is None
    assert backend.cleared_conditions >= 1
    assert backend.closed


async def test_location_is_cleared_on_quit(tmp_path):
    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("6")
        await pilot.pause()
        await pilot.press("l", *"40.7", "enter", *"-74", "enter")
        await until(pilot, lambda: backend.location is not None)
        assert backend.location == (40.7, -74.0)
        await pilot.press("q")
    assert backend.location is None
    assert backend.cleared_locations >= 1


async def test_capture_writes_pcap(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("5")
        tab = app.query_one(NetworkTab)
        await pilot.press("space")
        await until(pilot, lambda: tab.count > 3)
        await pilot.press("space")
        await until(pilot, lambda: not tab.capturing)
        assert tab.last_path is not None
        data = tab.last_path.read_bytes()
        assert data[:4] == b"\xd4\xc3\xb2\xa1"
        assert len(data) > 24
        assert tab.query_one("#packets", DataTable).row_count == tab.count


async def test_capture_table_is_capped(tmp_path):
    from lazyios.backend import Packet

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tab = app.query_one(NetworkTab)
        app.pending = [Packet(1.0, 1, "p", "en0", "tcp", "a", "b", 10) for _ in range(1200)]
        tab.flush()
        await pilot.pause()
        assert tab.query_one("#packets", DataTable).row_count == 1000
        assert tab.count == 1200


async def test_screenshot_is_saved(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("6")
        await pilot.pause()
        await pilot.press("s")
        await until(pilot, lambda: list((tmp_path / DEMO / "screenshots").glob("*.png")))
        assert next((tmp_path / DEMO / "screenshots").glob("*.png")).read_bytes()[:4] == b"\x89PNG"


async def test_no_device_state(tmp_path):
    app, _ = make(tmp_path, has_device=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.2)
        assert app.info is None
        assert "no device" in text_of(app, "#status")
        assert "no device" in text_of(app, "#view")
        await pilot.press("3")
        await pilot.pause(0.2)
        assert "no device" in str(app.query_one(ProcessesTab).query_one(".notice", Static).content)
        await pilot.press("1", "r")
        await pilot.pause(0.2)


async def test_developer_mode_off_shows_inline_message(tmp_path):
    app, backend = make(tmp_path, developer=False)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("3")
        await pilot.pause(0.2)
        notice = app.query_one(ProcessesTab).query_one(".notice", Static)
        assert "developer mode is off" in str(notice.content)
        assert not backend.tunnel_open


async def test_help_screen(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("question_mark")
        await pilot.pause()
        assert app.screen.__class__.__name__ == "Help"
        await pilot.press("escape")
        await pilot.pause()
        assert app.screen.__class__.__name__ != "Help"


async def test_narrow_terminal_uses_compact_logo(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.pause()
        view = text_of(app, "#view")
        assert "▓▒░ lazyios ░▒▓" in view
        assert "▒███████▒" not in view


@pytest.mark.parametrize("flag", ["--udid", "--out"])
def test_cli_args(flag, tmp_path):
    from lazyios.__main__ import parse_args

    args = parse_args([flag, str(tmp_path), "--demo"])
    assert args.demo


async def dirty_backend() -> FakeBackend:
    backend = FakeBackend(interval=0.01)
    await backend.set_condition((await backend.conditions())[0])
    await backend.set_location(1.0, 2.0)
    return backend


async def test_failed_clear_keeps_state_and_close_retries():
    backend = await dirty_backend()
    backend.clear_failures = 1
    with pytest.raises(BackendError):
        await backend.clear_condition()
    assert backend.active_condition is not None
    await backend.close()
    assert backend.active_condition is None
    assert backend.location is None


async def test_cancelled_clear_still_completes():
    backend = await dirty_backend()
    task = asyncio.create_task(backend.clear_condition())
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.2)
    assert backend.active_condition is None


async def test_close_clears_location_when_condition_clear_hangs():
    backend = await dirty_backend()
    backend.condition_clear_hangs = True
    backend.close_timeout = 0.3
    await backend.close()
    assert backend.location is None
    assert backend.active_condition is not None


def test_main_closes_backend_when_app_did_not(monkeypatch, tmp_path):
    import lazyios.__main__ as entry

    backend = FakeBackend(interval=0.01)
    backend._cond_dirty = True

    class Dead:
        def __init__(self, *args, **kwargs):
            pass

        def run(self):
            raise RuntimeError("terminal gone")

    monkeypatch.setattr(entry, "make_backend", lambda args, udid=None: backend)
    monkeypatch.setattr(entry, "LazyiosApp", Dead)
    with pytest.raises(RuntimeError):
        entry.main(["--demo", "--out", str(tmp_path)])
    assert backend.closed


async def test_usbmuxd_unreachable_screen(tmp_path):
    app, _ = make(tmp_path, problem=UsbmuxdError("usbmuxd not reachable"))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.3)
        view = text_of(app, "#view")
        assert "usbmuxd is not reachable" in view
        assert usbmuxd.hint() in view


async def test_not_trusted_screen(tmp_path):
    app, _ = make(tmp_path, problem=NotTrustedError("not trusted"))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.3)
        assert "tap Trust" in text_of(app, "#view")


async def test_no_device_screen_has_cable_hint(tmp_path):
    app, _ = make(tmp_path, has_device=False)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause(0.3)
        assert "data cable" in text_of(app, "#view")


async def test_developer_mode_off_hint_on_overview(tmp_path):
    app, _ = make(tmp_path, developer=False)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.battery is not None)
        await pilot.pause(0.2)
        assert "developer mode" in text_of(app, "#view")


def test_install_hints_per_os():
    assert "winget install 9NP83LWLPZ9K" in usbmuxd.hint("win32")
    assert "apt install usbmuxd" in usbmuxd.hint("linux")
    assert "macOS" in usbmuxd.hint("darwin")


def test_version_and_selftest(capsys):
    from lazyios.__main__ import selftest

    assert selftest() == 0
    assert "selftest ok" in capsys.readouterr().out


def privacy_rows(tab) -> list[tuple[str, ...]]:
    table = tab.query_one("#table", DataTable)
    return [tuple(c.plain for c in table.get_row_at(i)) for i in range(table.row_count)]


async def start_privacy(pilot, app, rows: int = 12) -> PrivacyTab:
    await pilot.press("7", "space")
    tab = app.query_one(PrivacyTab)
    await until(pilot, lambda: len(app.aggregator.rows()) >= rows)
    tab.refresh_view(force=True)
    await pilot.pause()
    return tab


async def test_privacy_tab_shows_rows_and_summary(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tab = app.query_one(PrivacyTab)
        await pilot.press("7")
        assert "press space to start a capture" in str(tab.query_one(".notice").content)
        await start_privacy(pilot, app)
        assert tab.query_one("#table", DataTable).row_count >= 12
        assert "apps ::" in text_of(app, "#summary") and "trackers" in text_of(app, "#summary")
        assert "capture on" in text_of(app, "#status")
        assert not tab.query_one(".notice").display
        categories = {row[2] for row in privacy_rows(tab)}
        assert categories & {"ads", "analytics"}
        await pilot.press("space")
        await until(pilot, lambda: not app.capturing)
        assert "capture on" not in text_of(app, "#status")


async def test_privacy_trackers_only_and_sort_cycle(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tab = await start_privacy(pilot, app, rows=20)
        await pilot.press("space")
        await until(pilot, lambda: not app.capturing)
        total = tab.query_one("#table", DataTable).row_count
        await pilot.press("t")
        await pilot.pause()
        shown = privacy_rows(tab)
        assert 0 < len(shown) < total
        assert {row[2] for row in shown} <= {"ads", "analytics", "social", "telemetry"}
        assert "trackers only" in text_of(app, "#summary")
        await pilot.press("t")
        await pilot.pause()
        assert tab.query_one("#table", DataTable).row_count == total
        seen = []
        for _ in range(4):
            seen.append(tab.sort)
            await pilot.press("s")
            await pilot.pause()
        assert seen == ["bytes", "flows", "app", "domain"]
        assert tab.sort == "bytes"
        await pilot.press("s", "s")
        await pilot.pause()
        apps = [row[0] for row in privacy_rows(tab)]
        assert apps == sorted(apps, key=str.lower)


async def test_privacy_keys_are_text_in_the_filter(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tab = await start_privacy(pilot, app)
        await pilot.press("slash", "t", "e", "s", "space")
        await pilot.pause()
        assert tab.query_one("#filter").value == "tes "
        assert (tab.sort, tab.trackers_only) == ("bytes", False)
        assert tab.last_report is None


async def test_privacy_filter_narrows(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tab = await start_privacy(pilot, app, rows=20)
        total = tab.query_one("#table", DataTable).row_count
        await pilot.press("slash", *"quick")
        await pilot.pause()
        shown = privacy_rows(tab)
        assert 0 < len(shown) < total
        assert all("quickchat" in " ".join(row).lower() for row in shown)


async def test_privacy_export_writes_json_and_csv(tmp_path, monkeypatch):
    import csv
    import json

    from lazyios import opener

    opened = []
    monkeypatch.setattr(opener, "open_default", opened.append)
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("7", "e")
        await pilot.pause()
        assert not (tmp_path / DEMO / "reports").exists()  # nothing captured yet
        await start_privacy(pilot, app, rows=15)
        await pilot.press("e")
        await pilot.pause()
        (report,) = (tmp_path / DEMO / "reports").glob("*.json")
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["summary"]["apps"] >= 3
        assert {"app", "domain", "category", "company", "tracker", "flows", "bytes", "ips"} <= set(
            data["rows"][0]
        )
        with report.with_suffix(".csv").open(newline="", encoding="utf-8") as f:
            table = list(csv.DictReader(f))
        assert len(table) == len(data["rows"])
        assert any(row["tracker"] == "True" for row in table)
        await pilot.press("o")
        await pilot.pause()
        assert opened == [report.with_suffix(".csv")]


def test_report_neutralizes_spreadsheet_formulas(tmp_path):
    from lazyios.privacy import HostRow, write_report

    row = HostRow("=cmd|' /c calc'!A1", "-evil.example", bytes=5, first=1.0, last=2.0)
    _, csv_path = write_report([row], tmp_path)
    line = csv_path.read_text(encoding="utf-8").splitlines()[1]
    assert line.startswith("'=cmd") and ",'-evil.example," in line


async def test_privacy_renders_hostile_names_literally(tmp_path):
    from lazyios.backend import Packet
    from lazyios.fake import _dns_response

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        tab = app.query_one(PrivacyTab)
        dns = _dns_response("[red]evil.example.com", "203.0.113.5")
        for p in (
            Packet(
                1.0, 70, "mDNSResponder", "en0", "udp", "192.168.0.1:53", "192.168.0.204:5", 90, dns
            ),
            Packet(
                1.0,
                9,
                "[bold]App\x1b[31m",
                "en0",
                "tcp",
                "192.168.0.204:5",
                "203.0.113.5:443",
                90,
            ),
        ):
            app.aggregator.feed(p)
        await pilot.press("7")
        tab.refresh_view(force=True)
        await pilot.pause()
        rows = privacy_rows(tab)
        assert ("[bold]App[31m", "203.0.113.5") in {row[:2] for row in rows}
        assert all("evil" not in cell for row in rows for cell in row)
        table = tab.query_one("#table", DataTable)
        assert all(isinstance(c, Text) for i in range(table.row_count) for c in table.get_row_at(i))


async def test_capture_is_shared_between_tabs(tmp_path):
    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        network = app.query_one(NetworkTab)
        await pilot.press("5", "space")
        await until(pilot, lambda: network.count > 5)
        assert app.capturing and network.capturing and "capture on" in text_of(app, "#status")
        await pilot.press("7")
        await until(pilot, lambda: app.aggregator.rows())
        await pilot.press("space")  # stop from the other tab
        await until(pilot, lambda: not app.capturing)
        assert backend.captures == 1
        assert network.count == network.query_one("#packets", DataTable).row_count
        before = app.aggregator.rows()
        await pilot.press("space")  # a new capture starts clean
        await pilot.pause(0.1)
        assert backend.captures == 2
        assert not any(row is old for row in app.aggregator.rows() for old in before)
        await pilot.press("space")
        await until(pilot, lambda: not app.capturing)


async def test_logs_reconnect_after_the_device_comes_back(tmp_path, monkeypatch):
    from lazyios.backend import NoDeviceError
    from lazyios.tabs import logs as logs_module

    monkeypatch.setattr(logs_module, "RETRY", (0.05,))
    app, backend = make(tmp_path, problem=NoDeviceError("no device connected"))
    reported: list[Exception] = []
    app.report = reported.append  # type: ignore[method-assign]
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("2")
        tab = app.query_one(LogsTab)
        notice = tab.query_one(".notice", Static)
        await until(pilot, lambda: "retrying" in str(notice.content))
        await pilot.pause(0.3)  # several failed retries
        assert len(reported) == 1  # one notification, not one per retry
        backend.problem = None
        await until(pilot, lambda: len(tab.buffer) > 5)
        await until(pilot, lambda: not notice.display)


async def test_logs_r_reconnects_now(tmp_path, monkeypatch):
    from lazyios.backend import NoDeviceError
    from lazyios.tabs import logs as logs_module

    monkeypatch.setattr(logs_module, "RETRY", (3600.0,))
    app, backend = make(tmp_path, problem=NoDeviceError("no device connected"))
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("2")
        tab = app.query_one(LogsTab)
        await until(pilot, lambda: "retrying" in str(tab.query_one(".notice", Static).content))
        backend.problem = None
        await pilot.press("r")
        await until(pilot, lambda: len(tab.buffer) > 5)


async def test_capture_stops_at_the_size_limit(tmp_path):
    backend = FakeBackend(interval=0.001)
    app = LazyiosApp(backend, tmp_path, max_capture=4000)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("5")
        await pilot.press("space")
        await until(pilot, lambda: app.last_capture is not None and not app.capturing)
        assert 0 < app.last_capture.stat().st_size <= 4000


def test_max_capture_flag():
    from lazyios.__main__ import parse_args

    assert parse_args(["--max-capture-mb", "5"]).max_capture_mb == 5
    assert parse_args([]).max_capture_mb == 1024
    for bad in ("0", "-1", "1.5", "²"):
        with pytest.raises(SystemExit):
            parse_args(["--max-capture-mb", bad])


async def test_screenshots_in_the_same_second_do_not_collide(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("6")
        await pilot.pause()
        await pilot.press("s")
        await until(pilot, lambda: len(list((tmp_path / DEMO / "screenshots").glob("*.png"))) == 1)
        await pilot.press("s")
        await until(pilot, lambda: len(list((tmp_path / DEMO / "screenshots").glob("*.png"))) == 2)


async def test_conns_tab_follows_the_capture_and_filters(tmp_path):
    from lazyios.tabs.conns import ConnsTab

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("8")
        tab = app.query_one(ConnsTab)
        table = tab.query_one("#table", DataTable)
        assert "space" in str(tab.query_one(".notice", Static).content)
        await pilot.press("space")
        await until(pilot, lambda: table.row_count > 8, timeout=10)
        assert any(f.source == "sni" for f in app.flows.rows())
        assert any(f.new for f in app.flows.rows())
        await pilot.press("space")
        await until(pilot, lambda: not app.capturing)
        await pilot.press("slash", *"proto:udp", "enter")
        await pilot.pause(0.2)
        shown = [f for f in tab.items if tab.matches(f, "proto:udp")]
        assert 0 < table.row_count == len(shown) < len(tab.items)
        await pilot.press("e")
        await until(pilot, lambda: tab.last_report is not None)
        names = sorted(p.suffix for p in (tmp_path / DEMO / "reports").glob("connections-*"))
        assert names == [".csv", ".json", ".sha256"]


async def test_conns_new_only_toggle(tmp_path):
    from lazyios.tabs.conns import ConnsTab

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("8", "space")
        await until(pilot, lambda: len(app.flows.rows()) > 20, timeout=15)
        await pilot.press("space")
        await until(pilot, lambda: not app.capturing)
        tab = app.query_one(ConnsTab)
        everything = tab.query_one("#table", DataTable).row_count
        await pilot.press("n")
        await pilot.pause(0.2)
        assert all(tab.accepts(f) == f.new for f in tab.items)
        assert tab.query_one("#table", DataTable).row_count <= everything


async def demo_capture(app: LazyiosApp, pilot, tab: str, rows: int = 15) -> None:
    await until(pilot, lambda: app.info is not None)
    await pilot.press(tab, "space")
    await until(pilot, lambda: len(app.aggregator.rows()) > rows, timeout=15)
    await pilot.press("space")
    await until(pilot, lambda: not app.capturing)
    await pilot.pause(0.2)


async def test_score_tab_rates_apps_and_exports(tmp_path):
    from lazyios.tabs.score import ScoreTab

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("9")
        tab = app.query_one(ScoreTab)
        assert "space" in str(tab.query_one(".notice", Static).content)
        await demo_capture(app, pilot, "9")
        assert tab.query_one("#table", DataTable).row_count == len(tab.items) > 3
        assert any(a.trackers and a.score < 100 for a in tab.items)
        assert all(a.change is not None and not a.change.known for a in tab.items)  # no history
        assert "first capture" in str(tab.query_one("#why", Static).content)
        await pilot.press("c")
        await pilot.pause()
        assert "start at 100" in str(app.screen.query(Static).last().content)
        await pilot.press("escape", "e")
        await until(pilot, lambda: tab.last_report is not None)
        assert len(list((tmp_path / DEMO / "reports").glob("score-*"))) == 3


async def test_capture_saves_history_and_the_next_one_compares(tmp_path):
    from datetime import datetime

    from lazyios import sessions
    from lazyios.tabs.score import ScoreTab

    old = {"api.fittrack.example": "", "gateway.icloud.com": ""}
    seed = sessions.snapshot([], {}, "00000000-DEMO000000000000", datetime(2026, 1, 1))
    seed["apps"] = {"FitTrack": {"version": "4.1", "domains": old}}
    sessions.save(tmp_path / DEMO / "sessions", seed, now=datetime(2026, 1, 1))
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await demo_capture(app, pilot, "9", rows=25)
        fit = next(a for a in app.query_one(ScoreTab).items if a.app == "FitTrack")
        assert fit.change.known and fit.updated  # 4.1 in the history, 4.2 on the "device"
        assert "api.fittrack.example" not in fit.change.new_domains
        assert set(fit.new_trackers) <= set(fit.trackers) and fit.new_trackers
        assert len(list((tmp_path / DEMO / "sessions").glob("session-*.json"))) == 2
        assert len(app.sessions) == 2


async def test_alerts_fire_for_watched_domains(tmp_path):
    (tmp_path / "alerts.json").write_text('{"watch": ["doubleclick.net"]}', encoding="utf-8")
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await demo_capture(app, pilot, "9", rows=30)
        await until(pilot, lambda: any("doubleclick" in a[2] for a in app.alerts), timeout=10)
        assert all(reason == "watched domain" for *_, reason in app.alerts)


async def test_bad_alerts_file_warns_and_keeps_defaults(tmp_path):
    from lazyios.alerts import AlertRules

    (tmp_path / "alerts.json").write_text('{"watch": "x"}', encoding="utf-8")
    app, _ = make(tmp_path)
    notes: list[str] = []
    app.notify = lambda message, **_: notes.append(message)  # type: ignore[method-assign]
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
    assert app.rules == AlertRules()
    assert any("alerts.json" in n for n in notes)


async def test_keep_sessions_zero_writes_no_history(tmp_path):
    backend = FakeBackend(interval=0.01)
    app = LazyiosApp(backend, tmp_path, keep_sessions=0)
    async with app.run_test(size=SIZE) as pilot:
        await demo_capture(app, pilot, "7")
    assert not (tmp_path / DEMO / "sessions").exists()


def test_keep_sessions_flag():
    from lazyios.__main__ import parse_args

    assert parse_args(["--keep-sessions", "0"]).keep_sessions == 0
    assert parse_args([]).keep_sessions == 30
    with pytest.raises(SystemExit):
        parse_args(["--keep-sessions", "-1"])


async def test_timeline_collects_device_capture_and_contacts(tmp_path):
    from lazyios.tabs.timeline import TimelineTab

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await demo_capture(app, pilot, "0", rows=10)
        tab = app.query_one(TimelineTab)
        await until(pilot, lambda: tab.query_one("#table", DataTable).row_count > 5)
        kinds = {e.kind for e in app.timeline.events()}
        assert {"device", "capture", "connection", "network"} <= kinds
        assert any(e.summary.startswith("first contact:") and e.app for e in app.timeline.events())
        assert tab.items == sorted(tab.items, key=lambda e: (e.time, e.seq), reverse=True)
        await pilot.press("slash", *"kind:capture", "enter")
        table = tab.query_one("#table", DataTable)
        assert sum(e.kind == "capture" for e in app.timeline.events()) == 2
        await until(pilot, lambda: table.row_count == 2)  # the table refreshes once a second
        await pilot.press("e")
        await until(pilot, lambda: tab.last_report is not None)
        doc = __import__("json").loads(
            next((tmp_path / DEMO / "reports").glob("timeline-*.json")).read_text(encoding="utf-8")
        )
        assert [e["kind"] for e in doc["events"]] == ["capture", "capture"]


async def test_timeline_follows_syslog_errors_and_processes(tmp_path, monkeypatch):
    from lazyios import app as app_module

    monkeypatch.setattr(app_module, "PROCESS_POLL", 0.05)
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("0")  # starts the syslog stream without opening the logs tab
        await until(pilot, lambda: any(e.kind == "syslog" for e in app.timeline.events()), 15)
        await pilot.press("p")

        def maps(verb: str) -> bool:
            return any(e.kind == "app" and e.app == "Maps" and verb in e.summary
                       for e in app.timeline.events())  # fmt: skip

        await until(pilot, lambda: maps("exited") and maps("started"))  # demo Maps comes and goes
        await pilot.press("p")
        await until(pilot, lambda: not app.watching_processes)
        # syslog keeps flowing, so "watch stopped" need not be the newest event
        assert any(e.summary == "watch stopped" for e in app.timeline.events())


async def test_conditions_and_errors_reach_the_timeline(tmp_path):
    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("5")
        table = app.query_one(NetworkTab).query_one("#conditions", DataTable)
        await until(pilot, lambda: table.row_count > 0)
        await pilot.press("enter")
        await until(pilot, lambda: backend.active_condition is not None)
        await pilot.press("x")
        await until(pilot, lambda: backend.active_condition is None)
        await pilot.pause(0.1)
        conditions = [e.summary for e in app.timeline.events() if e.kind == "condition"]
        assert conditions[0].startswith("set ") and conditions[-1] == "cleared"
        app.report(BackendError("boom"))
        assert app.timeline.events()[-1].kind == "error"


async def test_device_loss_is_on_the_timeline(tmp_path):
    from lazyios.backend import NoDeviceError

    app, backend = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        backend.problem = NoDeviceError("no device connected")
        await app.refresh_device()
        backend.problem = None
        await app.refresh_device()
        device = [e.summary for e in app.timeline.events() if e.kind == "device"]
        assert device[0].startswith("connected") and device[1].startswith("lost: no device")
        assert device[2].startswith("connected")


async def test_anomaly_findings_go_to_timeline_and_toast(tmp_path):
    from lazyios.anomaly import Finding

    app, _ = make(tmp_path)
    notes: list[str] = []
    app.notify = lambda message, **_: notes.append(message)  # type: ignore[method-assign]
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
        app.detector.findings.append(Finding("beacon", "QuickChat", "6 connections", "d", 1.0))
        app.check_new_rows()
        [event] = [e for e in app.timeline.events() if e.kind == "anomaly"]
        assert event.summary == "beacon: 6 connections" and event.app == "QuickChat"
        assert any("QuickChat: beacon" in n for n in notes)


async def test_bad_anomaly_file_warns(tmp_path):
    (tmp_path / "anomaly.json").write_text('{"window_s": "ten"}', encoding="utf-8")
    app, _ = make(tmp_path)
    notes: list[str] = []
    app.notify = lambda message, **_: notes.append(message)  # type: ignore[method-assign]
    async with app.run_test(size=SIZE) as pilot:
        await pilot.pause()
    assert any("anomaly.json: window_s must be a number" in n for n in notes)


async def test_timeline_follows_the_newest_unless_you_scroll(tmp_path):
    from lazyios.tabs.timeline import TimelineTab

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("0")
        tab = app.query_one(TimelineTab)
        for i in range(5):
            app.timeline.add("capture", f"e{i}")
        tab.refresh_view(force=True)
        table = tab.query_one("#table", DataTable)
        app.timeline.add("capture", "newest")
        tab.refresh_view(force=True)
        assert table.cursor_row == 0 and tab.selected().summary == "newest"
        await pilot.press("down", "down")
        picked = tab.selected()
        app.timeline.add("capture", "even newer")
        tab.refresh_view(force=True)
        assert tab.selected() is picked  # you moved away from the top: your row stays put


def test_device_folder_names_are_safe():
    from lazyios.app import device_folder

    assert device_folder("00008150-000808590AE2401C") == "00008150-000808590AE2401C"
    assert device_folder("../../etc/passwd") == "etcpasswd"
    assert device_folder("") == device_folder("../") == "unknown-device"
    assert len(device_folder("a" * 500)) == 64


async def test_overview_shows_battery_health_and_thermal(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.pause()
        view = text_of(app, "#view")
        assert "98% (3862 of 3945 mAh design)" in view
        assert "3.87 V  +450 mA" in view
        assert "thermal" in view and "not reported" in view


async def test_security_audit_opens_and_exports(tmp_path):
    from lazyios.screens import AuditScreen

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("a")
        await until(pilot, lambda: isinstance(app.screen, AuditScreen))
        text = " ".join(str(s.content) for s in app.screen.query(Static))
        assert "computer backups" in text and "[medium]" in text  # the demo is unencrypted
        assert "Example VPN (Example Corp)" in text
        await pilot.press("e")
        await until(pilot, lambda: list((tmp_path / DEMO / "reports").glob("audit-*.json")))
        await pilot.press("escape")
        assert not isinstance(app.screen, AuditScreen)


async def test_process_monitor_shows_cpu_and_memory(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("3")
        tab = app.query_one(ProcessesTab)
        await until(pilot, lambda: tab.items)
        await pilot.press("m")
        await until(pilot, lambda: any(s.cpu for s in tab.usage.values()))
        await until(pilot, lambda: "cores" in text_of(app, "#perf"))
        assert tab.query_one("#cpu-spark").display
        cpus = [tab.usage[p.pid].cpu or 0 for p in tab.items]
        assert cpus == sorted(cpus, reverse=True)  # busiest first
        assert len(tab.cpu_history) == 120
        await pilot.press("m")
        await until(pilot, lambda: not tab.monitoring)
        assert not tab.query_one("#cpu-spark").display and tab.max_shown is None


async def test_switching_devices_starts_a_clean_session(tmp_path):
    from lazyios.screens import DevicePicker

    app, first = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await demo_capture(app, pilot, "8", rows=5)
        assert app.aggregator.rows()
        await pilot.press("d")
        await until(pilot, lambda: isinstance(app.screen, DevicePicker))
        table = app.screen.query_one(DataTable)
        assert table.row_count == 2
        await pilot.press("down", "enter")
        await until(pilot, lambda: app.info is not None and app.info.product_type == "iPad16,3")
        assert first.closed and app.backend is not first
        assert app.aggregator.rows() == [] and app.flows.rows() == []
        assert [e.summary for e in app.timeline.events() if e.kind == "device"][-1].startswith(
            "switched to 00000000-DEMO000000000001"
        )
        await pilot.press("8", "space")
        await until(pilot, lambda: app.flows.rows())
        await pilot.press("space")
        await until(pilot, lambda: not app.capturing)
        assert app.last_capture.parent == tmp_path / "00000000-DEMO000000000001" / "captures"
    assert list((tmp_path / DEMO / "captures").glob("*.pcap"))  # the first device kept its own


async def test_plugged_devices_are_noticed_and_the_lost_one_reconnects(tmp_path):
    from lazyios.backend import NoDeviceError

    app, backend = make(tmp_path)
    notes: list[str] = []
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        app.notify = lambda message, **_: notes.append(message)  # type: ignore[method-assign]
        plugged = [DEMO]

        async def ids() -> list[str]:
            return list(plugged)

        backend.device_ids = ids  # type: ignore[method-assign]
        await app._poll_devices()  # first look: just remembers
        plugged.append("NEW-DEVICE")
        await app._poll_devices()
        assert any("NEW-DEVICE" in n for n in notes)
        backend.problem = NoDeviceError("no device connected")
        await app.refresh_device()
        plugged.remove(DEMO)
        await app._poll_devices()
        assert app.info is None
        backend.problem = None
        plugged.append(DEMO)
        await app._poll_devices()  # the cable is back: reconnect without waiting for the tick
        assert app.info is not None
        kinds = [e.summary.split(":")[0] for e in app.timeline.events() if e.kind == "device"]
        assert kinds.count("plugged in") == 2 and "unplugged" in kinds


async def test_command_palette_lists_tabs_and_actions(tmp_path):
    from textual.command import CommandPalette

    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        titles = [c.title for c in app.get_system_commands(app.screen)]
        assert "go to timeline" in titles and "security audit" in titles and "devices" in titles
        await pilot.press("ctrl+p")
        await until(pilot, lambda: isinstance(app.screen, CommandPalette))
        await pilot.press("escape")
        app._tab_action("privacy", "toggle_trackers")
        await pilot.pause(0.1)
        assert app.query_one(TabbedContent).active == "privacy"
        assert app.query_one(PrivacyTab).trackers_only


async def test_keys_file_rebinds_actions(tmp_path):
    (tmp_path / "keys.json").write_text('{"capture": "c"}', encoding="utf-8")
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("5", "c")
        await until(pilot, lambda: app.capturing)
        await pilot.press("c")
        await until(pilot, lambda: not app.capturing)


async def test_contextual_help_and_activity_in_the_status(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await until(pilot, lambda: app.info is not None)
        await pilot.press("2", "question_mark")
        await pilot.pause()
        text = "\n".join(str(s.content) for s in app.screen.query(Static))
        assert "keys :: logs" in text and text.index(" logs ") < text.index(" global")
        await pilot.press("escape", "3", "m")
        await until(pilot, lambda: "monitor" in text_of(app, "#status"))
        await pilot.press("m")
        await until(pilot, lambda: "monitor" not in text_of(app, "#status"))


async def test_logs_level_filter_and_pane_resize(tmp_path):
    app, _ = make(tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("2")
        logs = app.query_one(LogsTab)
        await until(pilot, lambda: len(logs.buffer) > 200)
        for _ in range(3):
            await pilot.press("v")
        assert logs.level == "error" and "[error and up]" in str(
            logs.query_one(".head", Static).content
        )
        await pilot.pause(0.3)
        assert all(line.text.split()[2] in ("error", "fault")
                   for line in logs.query_one(RichLog).lines if line.text.strip())  # fmt: skip
        await pilot.press("5")
        conditions = app.query_one(NetworkTab).query_one("#conditions", DataTable)
        await pilot.press("right_square_bracket", "right_square_bracket")
        assert conditions.styles.height.value == 13
        for _ in range(20):
            await pilot.press("left_square_bracket")
        assert conditions.styles.height.value == 5


async def test_anonymized_exports_and_kept_files(tmp_path):
    backend = FakeBackend(interval=0.01)
    app = LazyiosApp(backend, tmp_path, anonymize=frozenset({"ips", "domains", "ids"}),
                     keep_files=1)  # fmt: skip
    async with app.run_test(size=SIZE) as pilot:
        await demo_capture(app, pilot, "8", rows=15)
        await pilot.press("e")
        reports = tmp_path / DEMO / "reports"
        await until(pilot, lambda: list(reports.glob("connections-*.json")))
        text = next(reports.glob("connections-*.json")).read_text(encoding="utf-8")
        assert "203.0.113." not in text and "192.168.0.204" not in text
        assert "fittrack.example" not in text  # first-party names are hidden
        assert "doubleclick.net" in text or "app-measurement.com" in text  # trackers stay
        await pilot.press("6", "s")
        shots = tmp_path / DEMO / "screenshots"
        await until(pilot, lambda: len(list(shots.glob("*.png"))) == 1)
        await pilot.press("s")
        await pilot.pause(0.5)
        assert len(list(shots.glob("*.png"))) == 1  # --keep-files 1


def test_explain_unexpected_errors():
    from lazyios.app import explain

    assert "timed out" in explain("launch", TimeoutError())
    assert "permission denied writing /x" in explain("shot", PermissionError(13, "no", "/x"))
    assert explain("capture", KeyError("k")).endswith("details in lazyios.log")


def test_new_cli_flags(tmp_path):
    from lazyios.__main__ import main, parse_args

    args = parse_args(["--anonymize", "all", "--keep-files", "3", "--log-level", "debug"])
    assert args.anonymize == {"ips", "domains", "ids"} and args.keep_files == 3
    for bad in (["--anonymize", "emails"], ["--keep-files", "-2"], ["--log-level", "loud"]):
        with pytest.raises(SystemExit):
            parse_args(bad)
    not_a_folder = tmp_path / "file"
    not_a_folder.write_text("x")
    with pytest.raises(SystemExit, match="is not a folder"):
        main(["--demo", "--out", str(not_a_folder)])

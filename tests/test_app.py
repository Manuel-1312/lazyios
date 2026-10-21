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


async def until(pilot, check: Callable[[], bool], timeout: float = 5.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not check():
        if asyncio.get_running_loop().time() > deadline:
            raise TimeoutError
        await pilot.pause(0.02)


def make(tmp_path: Path, **kwargs) -> tuple[LazyiosApp, FakeBackend]:
    backend = FakeBackend(interval=0.01, **kwargs)
    return LazyiosApp(backend, tmp_path), backend


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
            "12345678",
            ("overview", "logs", "processes", "apps", "network", "tools", "privacy", "conns"),
            strict=True,
        ):
            await pilot.press(key)
            await pilot.pause()
            assert tabs.active == name


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
        for i in range(6000):
            logs.add(logs.buffer[0] if logs.buffer else _line(i))
        assert len(logs.buffer) == 5000


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
        await until(pilot, lambda: list((tmp_path / "screenshots").glob("*.png")))
        assert next((tmp_path / "screenshots").glob("*.png")).read_bytes()[:4] == b"\x89PNG"


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


def test_main_closes_backend_when_app_did_not(monkeypatch):
    import lazyios.__main__ as entry

    backend = FakeBackend(interval=0.01)
    backend._cond_dirty = True

    class Dead:
        def __init__(self, *args):
            pass

        def run(self):
            raise RuntimeError("terminal gone")

    monkeypatch.setattr(entry, "make_backend", lambda args: backend)
    monkeypatch.setattr(entry, "LazyiosApp", Dead)
    with pytest.raises(RuntimeError):
        entry.main(["--demo"])
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
        assert not (tmp_path / "reports").exists()  # nothing captured yet
        await start_privacy(pilot, app, rows=15)
        await pilot.press("e")
        await pilot.pause()
        (report,) = (tmp_path / "reports").glob("*.json")
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
        before = len(app.aggregator.rows())
        await pilot.press("space")  # a new capture starts clean
        await pilot.pause(0.1)
        assert backend.captures == 2 and len(app.aggregator.rows()) <= before
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
        await until(pilot, lambda: len(list((tmp_path / "screenshots").glob("*.png"))) == 1)
        await pilot.press("s")
        await until(pilot, lambda: len(list((tmp_path / "screenshots").glob("*.png"))) == 2)


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
        names = sorted(p.suffix for p in (tmp_path / "reports").glob("connections-*"))
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

import asyncio
from collections.abc import Callable
from pathlib import Path

import pytest
from textual.widgets import DataTable, RichLog, Static, TabbedContent

from lazyios import usbmuxd
from lazyios.app import LazyiosApp
from lazyios.backend import BackendError, NotTrustedError, UsbmuxdError
from lazyios.fake import FakeBackend
from lazyios.tabs.logs import LogsTab
from lazyios.tabs.network import NetworkTab
from lazyios.tabs.processes import ProcessesTab

SIZE = (120, 40)


async def until(pilot, check: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not check():
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
            "123456", ("overview", "logs", "processes", "apps", "network", "tools"), strict=True
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
        tab.pending = [Packet(1.0, 1, "p", "en0", "tcp", "a", "b", 10) for _ in range(1200)]
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

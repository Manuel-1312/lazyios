from __future__ import annotations

import time
from collections import deque
from contextlib import aclosing
from pathlib import Path

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.widgets import Input, Sparkline, Static
from textual.worker import Worker

from .. import opener
from ..art import header
from ..backend import BackendError
from .base import TabBody

SAMPLES = 60


def parse_coords(lat: str, lon: str) -> tuple[float, float] | None:
    try:
        la, lo = float(lat), float(lon)
    except ValueError:
        return None
    return (la, lo) if -90 <= la <= 90 and -180 <= lo <= 180 else None


class ToolsTab(TabBody):
    title = "tools"
    can_focus = True
    BINDINGS = [
        Binding("s", "screenshot", "screenshot"),
        Binding("o", "open_screenshot", "open"),
        Binding("l", "edit_location", "coords"),
        Binding("x", "clear_location", "clear loc"),
        Binding("f", "toggle_fps", "fps"),
        Binding("escape", "focus_self", show=False),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.last_shot: Path | None = None
        self.samples: deque[int] = deque([0] * SAMPLES, maxlen=SAMPLES)
        self._fps_worker: Worker[None] | None = None
        self.fps_running = False

    def compose(self) -> ComposeResult:
        yield Static("", classes="notice")
        yield Static(header("screenshot"), classes="head")
        yield Static("s take   o open", id="shot")
        yield Static(header("location"), classes="head")
        with Horizontal(id="coords"):
            yield Input(placeholder="lat", id="lat")
            yield Input(placeholder="lon", id="lon")
        yield Static("l edit   enter set   x clear", id="locinfo")
        yield Static(header("fps"), classes="head")
        yield Static("f start", id="fpsinfo")
        yield Sparkline(list(self.samples), id="spark")

    def on_mount(self) -> None:
        self.query_one(".notice").display = False

    async def load(self) -> None:
        if message := await self.lazy.open_dvt():
            self.notice(message)

    def action_focus_self(self) -> None:
        self.focus()

    async def _ready(self) -> bool:
        if message := await self.lazy.open_dvt():
            self.notice(message)
            return False
        self.notice("")
        return True

    def action_screenshot(self) -> None:
        self.lazy.run_task(self._screenshot(), group="shot")

    async def _screenshot(self) -> None:
        if not await self._ready():
            return
        try:
            data = await self.lazy.backend.screenshot()
        except BackendError as e:
            self.lazy.report(e)
            return
        path = (
            self.lazy.out_dir / "screenshots" / f"screenshot-{time.strftime('%Y%m%d-%H%M%S')}.png"
        )
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        self.last_shot = path
        self.query_one("#shot", Static).update(f"saved {path}   (o open)")

    def action_open_screenshot(self) -> None:
        if self.last_shot is None:
            self.app.notify("no screenshot yet", severity="warning")
            return
        try:
            opener.open_default(self.last_shot)
        except OSError as e:
            self.app.notify(f"cannot open: {e}", severity="error", markup=False)

    def action_edit_location(self) -> None:
        self.query_one("#lat", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "lat":
            self.query_one("#lon", Input).focus()
            return
        coords = parse_coords(
            self.query_one("#lat", Input).value, self.query_one("#lon", Input).value
        )
        if coords is None:
            self.app.notify("lat must be -90..90 and lon -180..180", severity="error")
            return
        self.focus()
        self.lazy.run_task(self._set_location(*coords), group="location")

    async def _set_location(self, lat: float, lon: float) -> None:
        if not await self._ready():
            return
        try:
            await self.lazy.backend.set_location(lat, lon)
        except BackendError as e:
            self.lazy.report(e)
            return
        self.query_one("#locinfo", Static).update(f"simulating {lat:.5f}, {lon:.5f}   (x clear)")

    def session_reset(self) -> None:
        self.query_one("#locinfo", Static).update("session reset   (l edit)")

    def action_clear_location(self) -> None:
        self.lazy.run_task(self._clear_location(), group="location")

    async def _clear_location(self) -> None:
        try:
            await self.lazy.backend.clear_location()
        except BackendError as e:
            self.lazy.report(e)
            return
        self.query_one("#locinfo", Static).update("location real   (l edit)")

    def action_toggle_fps(self) -> None:
        if self._fps_worker is not None and self.fps_running:
            self._fps_worker.cancel()
            return
        self._fps_worker = self.lazy.run_task(self._fps(), group="fps")

    async def _fps(self) -> None:
        if not await self._ready():
            return
        self.fps_running = True
        info = self.query_one("#fpsinfo", Static)
        spark = self.query_one("#spark", Sparkline)
        try:
            async with aclosing(self.lazy.backend.fps()) as values:
                async for value in values:
                    self.samples.append(value)
                    spark.data = list(self.samples)
                    info.update(f"{value:>3} fps   (f stop)")
        except BackendError as e:
            self.lazy.report(e)
        finally:
            self.fps_running = False
            info.update("stopped   (f start)")

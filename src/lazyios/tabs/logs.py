from __future__ import annotations

import asyncio
from collections import deque
from contextlib import aclosing

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.timer import Timer
from textual.widgets import Input, RichLog, Static

from ..art import header
from ..backend import BackendError, LogLine
from ..parsing import matches_filter, parse_syslog_line
from ..theme import ACID, BONE, DIM, GRAY, RED
from .base import TabBody

BUFFER = 5000
FLUSH = 0.2
WHO_WIDTH = 22
DEBOUNCE = 0.2
RETRY = (2.0, 5.0, 10.0, 30.0)  # seconds between reconnects, the last one repeats

_SHORT = {"warning": "warn"}
_LEVEL_STYLE = {
    "debug": DIM,
    "info": GRAY,
    "notice": BONE,
    "warning": f"bold {BONE}",
    "error": f"bold {RED}",
    "fault": f"bold black on {RED}",
}


def _who(line: LogLine) -> str:
    who = f"{line.process}[{line.pid}]"
    return who if len(who) <= WHO_WIDTH else who[: WHO_WIDTH - 1] + "…"


def render_line(line: LogLine) -> Text:
    if not line.level:
        return Text(line.raw, style=DIM)
    style = _LEVEL_STYLE.get(line.level, BONE)
    quiet = line.level in ("debug", "info")
    return Text.assemble(
        (f"{line.time} ", DIM),
        (f"{_who(line):<{WHO_WIDTH}} ", GRAY if quiet else BONE),
        (f"{_SHORT.get(line.level, line.level):<6} ", style),
        (line.message, style if line.level in ("error", "fault") or quiet else BONE),
    )


class LogsTab(TabBody):
    title = "logs"
    focus_id = "#log"
    BINDINGS = [
        Binding("slash", "focus_filter", "filter"),
        Binding("p", "pause", "pause"),
        Binding("c", "clear", "clear"),
        Binding("r", "reconnect", "reconnect"),
        Binding("escape", "focus_log", show=False),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.buffer: deque[LogLine] = deque(maxlen=BUFFER)
        self.pending: list[LogLine] = []
        self.paused = False
        self._debounce: Timer | None = None

    def compose(self) -> ComposeResult:
        yield Static(header("logs"), classes="head")
        yield Input(placeholder="/ filter process or message", id="filter")
        yield Static("", classes="notice")
        yield RichLog(id="log", max_lines=BUFFER, wrap=False, markup=False, highlight=False)

    def on_mount(self) -> None:
        self.query_one(".notice").display = False
        self.set_interval(FLUSH, self.flush)

    async def load(self) -> None:
        """Follow syslog; when the stream drops (unplug, lock, relay restart) reconnect with
        backoff. Only the first failure of a run pops a notification."""
        failures = 0
        while True:
            try:
                async with aclosing(self.lazy.backend.syslog()) as lines:
                    async for raw in lines:
                        if failures:
                            failures = 0
                            self.notice("")
                        self.add(parse_syslog_line(raw))
                problem = "syslog stream ended"
            except BackendError as e:
                if not failures:
                    self.lazy.report(e)
                problem = str(e)
            delay = RETRY[min(failures, len(RETRY) - 1)]
            failures += 1
            self.notice(f"{problem} :: retrying in {delay:g}s (r now)")
            await asyncio.sleep(delay)

    def add(self, line: LogLine) -> None:
        self.buffer.append(line)
        self.pending.append(line)

    def _visible(self, line: LogLine) -> bool:
        needle = self.query_one("#filter", Input).value
        return matches_filter(needle, line.process, line.message, "" if line.level else line.raw)

    def flush(self) -> None:
        batch, self.pending = self.pending, []
        if self.paused:
            return
        log = self.query_one(RichLog)
        for line in batch:
            if self._visible(line):
                log.write(render_line(line), scroll_end=False)
        if batch:
            log.scroll_end(animate=False)

    def rerender(self) -> None:
        self.pending = []
        log = self.query_one(RichLog)
        log.clear()
        for line in self.buffer:
            if self._visible(line):
                log.write(render_line(line), scroll_end=False)
        log.scroll_end(animate=False)

    def on_input_changed(self, event: Input.Changed) -> None:
        if self._debounce is not None:
            self._debounce.stop()
        self._debounce = self.set_timer(DEBOUNCE, self.rerender)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_focus_log()

    def action_pause(self) -> None:
        self.paused = not self.paused
        head = header("logs") + ("  [paused]" if self.paused else "")
        self.query_one(".head", Static).update(Text(head, style=ACID if self.paused else ""))
        if not self.paused:
            self.rerender()

    def action_clear(self) -> None:
        self.buffer.clear()
        self.pending = []
        self.query_one(RichLog).clear()

    def action_reconnect(self) -> None:
        self.notice("")
        self.lazy.run_task(self.load(), group=f"load-{self.id}")  # replaces the running stream

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_focus_log(self) -> None:
        self.query_one(RichLog).focus()

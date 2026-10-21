from __future__ import annotations

from collections import deque
from datetime import datetime
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Static

from .. import opener
from ..art import header
from ..backend import BackendError, Condition, Packet
from ..parsing import clean_text
from ..theme import ACID, GRAY, RED
from .base import TabBody

MAX_ROWS = 1000
FLUSH = 0.25
COLUMNS = (
    ("time", False),
    ("process", False),
    ("if", False),
    ("proto", False),
    ("src -> dst", False),
    ("len", True),
)


def packet_cells(p: Packet) -> tuple[Text | str, ...]:
    """Text cells, so device-supplied names are never read as markup."""
    stamp = datetime.fromtimestamp(p.time).strftime("%H:%M:%S.%f")[:-3]
    name = clean_text(p.process)
    return (
        stamp,
        Text(f"{name}({p.pid})" if p.pid != 0xFFFFFFFF else name or "-"),
        Text(clean_text(p.interface)),
        Text(p.proto),
        Text(f"{p.src} -> {p.dst}"),
        Text(str(p.length), justify="right"),
    )


class NetworkTab(TabBody):
    title = "network"
    focus_id = "#conditions"
    BINDINGS = [
        Binding("space", "toggle_capture", "capture"),
        Binding("o", "open_capture", "open"),
        Binding("x", "clear_condition", "clear cond"),
        Binding("r", "reload", "refresh"),
    ]

    def __init__(self, **kwargs: object) -> None:
        super().__init__(**kwargs)
        self.count = 0
        self.keys: deque[int] = deque()
        self.conditions: list[Condition] = []

    @property
    def capturing(self) -> bool:
        return self.lazy.capturing

    @property
    def last_path(self) -> Path | None:
        return self.lazy.last_capture

    def compose(self) -> ComposeResult:
        yield Static(header("capture"), classes="head")
        yield Static("stopped :: space to start", id="capinfo")
        yield DataTable(id="packets", cursor_type="none")
        yield Static(header("conditions"), classes="head")
        yield Static("", classes="notice")
        yield DataTable(id="conditions", cursor_type="row")

    def on_mount(self) -> None:
        packets = self.query_one("#packets", DataTable)
        for label, right in COLUMNS:
            packets.add_column(Text(label, justify="right" if right else "left"), key=label)
        conds = self.query_one("#conditions", DataTable)
        conds.add_column("", key="mark", width=2)
        conds.add_column("group", key="group")
        conds.add_column("profile", key="name")
        conds.add_column("id", key="id")
        self.query_one(".notice").display = False
        self.set_interval(FLUSH, self.flush)

    async def load(self) -> None:
        if message := await self.lazy.open_dvt():
            self.notice(message)
            return
        try:
            self.conditions = await self.lazy.backend.conditions()
        except BackendError as e:
            self.notice(str(e))
            self.lazy.report(e)
            return
        self.notice("")
        self.render_conditions()

    def render_conditions(self) -> None:
        table = self.query_one("#conditions", DataTable)
        active = self.lazy.backend.active_condition
        row = table.cursor_row
        table.clear()
        for c in self.conditions:
            on = active is not None and active.profile_id == c.profile_id
            mark = Text("*", style=f"bold {RED}") if on else Text(" ")
            table.add_row(
                mark, c.group, Text(c.name, style=RED if on else ""), c.profile_id, key=c.profile_id
            )
        if self.conditions:
            table.move_cursor(row=min(row, len(self.conditions) - 1))

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "conditions":
            return
        if condition := next(
            (c for c in self.conditions if c.profile_id == event.row_key.value), None
        ):
            self.lazy.run_task(self._apply(condition), group="condition")

    async def _apply(self, condition: Condition) -> None:
        try:
            await self.lazy.backend.set_condition(condition)
        except BackendError as e:
            self.lazy.report(e)
            return
        self.lazy.update_status()
        self.render_conditions()
        self.app.notify(
            f"condition active: {condition.profile_id}", severity="warning", markup=False
        )

    def action_clear_condition(self) -> None:
        self.lazy.run_task(self._clear(), group="condition")

    async def _clear(self) -> None:
        try:
            await self.lazy.backend.clear_condition()
        except BackendError as e:
            self.lazy.report(e)
        self.lazy.update_status()
        self.render_conditions()

    def action_toggle_capture(self) -> None:
        self.lazy.toggle_capture()

    def action_reload(self) -> None:
        self.lazy.run_task(self.load(), group=f"load-{self.id}")

    def reset(self) -> None:
        self.count = 0
        self.query_one("#packets", DataTable).clear()
        self.keys.clear()

    def flush(self) -> None:
        batch, self.lazy.pending = self.lazy.pending, []
        packets = self.query_one("#packets", DataTable)
        if len(batch) >= MAX_ROWS:  # burst: the table would be replaced anyway
            self.count += len(batch) - MAX_ROWS
            batch = batch[-MAX_ROWS:]
            packets.clear()
            self.keys.clear()
        for packet in batch:
            self.count += 1
            packets.add_row(*packet_cells(packet), key=str(self.count))
            self.keys.append(self.count)
            if len(self.keys) > MAX_ROWS:
                packets.remove_row(str(self.keys.popleft()))
        if batch:
            packets.scroll_end(animate=False)
        state = Text(
            "capturing" if self.capturing else "stopped", style=ACID if self.capturing else GRAY
        )
        info = Text.assemble(state, f" :: {self.count} packets")
        if self.last_path is not None:
            info.append(f" :: {self._short_path(self.last_path)}", style=GRAY)
        self.query_one("#capinfo", Static).update(info)

    def _short_path(self, path: Path) -> str:
        """Home as ~, then just the file name if it still does not fit."""
        try:
            text = "~/" + path.relative_to(Path.home()).as_posix()
        except ValueError:
            text = str(path)
        room = self.size.width - 30
        return text if len(text) <= room else path.name

    def action_open_capture(self) -> None:
        if self.last_path is None or not self.last_path.exists():
            self.app.notify("no capture yet", severity="warning")
            return
        try:
            program = opener.open_capture(self.last_path)
        except OSError as e:
            self.app.notify(f"cannot open: {e}", severity="error", markup=False)
            return
        self.app.notify(f"opened in {program}", markup=False)

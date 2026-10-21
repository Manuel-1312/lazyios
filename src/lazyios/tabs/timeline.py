from __future__ import annotations

from datetime import datetime
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Input, Static, TabbedContent

from ..art import header
from ..theme import ACID, BONE, DIM, GRAY, RED
from ..timeline import Event, Query, iso, parse_query, write_timeline
from .base import ReportOpener, TableTab
from .logs import LogsTab
from .privacy import fit

REFRESH = 1.0
KIND_STYLE = {
    "error": f"bold {RED}", "anomaly": f"bold {RED}", "alert": RED, "device": ACID,
    "condition": ACID, "capture": BONE, "network": BONE, "app": BONE,
}  # fmt: skip
HINT = "events gather here: device, capture, connections, syslog errors, alerts, anomalies"


class TimelineTab(ReportOpener, TableTab[Event]):
    title = "timeline"
    max_shown = 1000
    columns = (("time", False), ("kind", False), ("app", False), ("what", False), ("n", True))
    BINDINGS = [
        Binding("slash", "focus_filter", "filter"),
        Binding("space", "toggle_capture", "capture"),
        Binding("p", "toggle_processes", "processes"),
        Binding("e", "export", "export"),
        Binding("o", "open_report", "open"),
        Binding("escape", "focus_table", show=False),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._seen = -1
        self._query_text: str | None = None
        self._query = Query()

    def compose(self) -> ComposeResult:
        yield Static(header(self.title), classes="head")
        yield Static("", id="summary")
        yield Input(
            placeholder="/ filter  kind:app,anomaly  app:  since:10:05  until:10:30  last:5m",
            id="filter",
        )
        yield Static("", classes="notice")
        yield DataTable(id="table", cursor_type="row")
        yield Static("", id="detail")

    def on_mount(self) -> None:
        self.set_interval(REFRESH, self.refresh_view)

    def activate(self) -> None:
        super().activate()
        self.lazy.query_one(LogsTab).ensure_stream()  # the logs tab owns the syslog stream
        self.refresh_view(force=True)

    async def load(self) -> None:
        self.refresh_view(force=True)

    def reset_device(self) -> None:
        super().reset_device()
        self._seen = -1
        self.last_report = None

    def key(self, item: Event) -> str:
        return str(id(item))

    def matches(self, item: Event, needle: str) -> bool:
        if needle != self._query_text:
            self._query_text, self._query = needle, parse_query(needle)
        return self._query.matches(item)

    def render_rows(self) -> None:
        self._query_text = None  # relative times ("last:5m") move with the clock
        table = self.query_one(DataTable)
        following = table.cursor_row <= 0  # on the newest row: stay there as new ones arrive
        super().render_rows()
        if following and table.row_count:
            table.move_cursor(row=0)
        self.update_detail()

    def cells(self, item: Event) -> tuple[Any, ...]:
        app_width, what_width = (14, 40) if self.size.width < 110 else (20, 70)
        return (
            Text(datetime.fromtimestamp(item.time).strftime("%H:%M:%S.%f")[:-3], style=GRAY),
            Text(item.kind, style=KIND_STYLE.get(item.kind, GRAY)),
            Text(item.app[:app_width], style=BONE),
            Text(fit(item.summary, what_width), style=BONE if item.kind != "syslog" else GRAY),
            Text(str(item.count) if item.count > 1 else "", style=GRAY, justify="right"),
        )  # fmt: skip

    def refresh_view(self, force: bool = False) -> None:
        app = self.lazy
        if not force and app.query_one(TabbedContent).active != "timeline":
            return
        notice = self.query_one(".notice", Static)
        empty = not app.timeline.events()
        notice.update(Text(HINT, style=GRAY) if empty else "")
        notice.display = empty
        if force or app.timeline.version != self._seen:
            self._seen = app.timeline.version
            self.set_items(sorted(app.timeline.events(), key=lambda e: e.time, reverse=True))
            self.update_summary()

    def update_summary(self) -> None:
        app = self.lazy
        events = self.items
        anomalies = sum(1 for e in events if e.kind == "anomaly")
        line = Text(no_wrap=True, overflow="ellipsis")
        for value, style in (
            (f"{len(events)} events", BONE),
            (f"{anomalies} anomalies", RED if anomalies else GRAY),
            ("processes " + ("watched" if app.watching_processes else "off (p)"),
             ACID if app.watching_processes else GRAY),
            ("capture " + ("on" if app.capturing else "off (space)"),
             ACID if app.capturing else GRAY),
            ("newest first", DIM),
        ):  # fmt: skip
            line.append(":: ", style=DIM)
            line.append(value + " ", style=style)
        self.query_one("#summary", Static).update(line)

    def update_detail(self) -> None:
        item = self.selected()
        detail = self.query_one("#detail", Static)
        if item is None:
            detail.update("")
            return
        line = Text.assemble(
            (iso(item.time), GRAY),
            (f"  {item.source}  ", DIM),
            (item.detail or item.summary, BONE),
        )
        line.truncate(max(10, self.size.width - 2), overflow="ellipsis")
        detail.update(line)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.update_detail()

    def action_toggle_capture(self) -> None:
        self.lazy.toggle_capture()

    def action_toggle_processes(self) -> None:
        self.lazy.toggle_process_watch()

    def action_export(self) -> None:
        needle = self.query_one("#filter", Input).value
        query = parse_query(needle)
        events = sorted(
            (e for e in self.lazy.timeline.events() if query.matches(e)), key=lambda e: e.time
        )
        if not events:
            self.app.notify("nothing to export", severity="warning")
            return
        try:
            json_path, csv_path, _ = write_timeline(
                events, needle, self.lazy.device_dir / "reports"
            )
        except OSError as e:
            self.app.notify(f"cannot write report: {e}", severity="error", markup=False)
            return
        self.last_report = csv_path
        self.app.notify(f"saved {json_path} (+ .csv, .sha256), o to open", markup=False)

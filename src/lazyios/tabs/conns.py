from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Input, Static, TabbedContent

from ..art import header
from ..flows import SORTS, Flow, matches, sort_flows, write_flows
from ..theme import ACID, BONE, DIM, GRAY
from .base import ReportOpener, TableTab
from .privacy import VIA, age, clock, fit, human_bytes

REFRESH = 1.0
NARROW = (10, 16, 13)  # app, domain, remote
WIDE = (16, 30, 26)
WIDE_FROM = 110
CAVEAT = Text(
    "via: sni = name the app sent, dns = DNS answer (shared on CDNs), - = no name",
    style=DIM,
    no_wrap=True,
    overflow="ellipsis",
)
HINT = "press space to start a capture (shared with network and privacy)"


class ConnsTab(ReportOpener, TableTab[Flow]):
    title = "connections"
    max_shown = 500
    columns = (
        ("app", False),
        ("domain", False),
        ("via", False),
        ("remote", False),
        ("proto", False),
        ("up", True),
        ("down", True),
        ("seen", True),
        ("idle", True),
    )
    BINDINGS = [
        Binding("slash", "focus_filter", "filter", id="filter"),
        Binding("space", "toggle_capture", "capture", id="capture"),
        Binding("s", "cycle_sort", "sort", id="sort"),
        Binding("n", "toggle_new", "new only", id="new-only"),
        Binding("e", "export", "export", id="export"),
        Binding("o", "open_report", "open", id="open"),
        Binding("escape", "focus_table", show=False),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.sort = SORTS[0]
        self.new_only = False
        self._seen = -1

    def compose(self) -> ComposeResult:
        yield Static(header(self.title), classes="head")
        yield Static("", id="summary")
        yield Input(placeholder="/ filter  app:  domain:  ip:  port:443  proto:udp", id="filter")
        yield Static("", classes="notice")
        yield DataTable(id="table", cursor_type="row")
        yield Static("", id="detail")
        yield Static(CAVEAT, id="caveat")

    def on_mount(self) -> None:
        self.set_interval(REFRESH, self.refresh_view)

    def activate(self) -> None:
        super().activate()
        self.refresh_view(force=True)

    async def load(self) -> None:
        self.refresh_view(force=True)

    def reset_device(self) -> None:
        super().reset_device()
        self._seen = -1
        self.last_report = None

    def key(self, item: Flow) -> str:
        return f"{item.pid}\x00{item.proto}\x00{item.local}\x00{item.remote}"

    def matches(self, item: Flow, needle: str) -> bool:
        return matches(item, needle)

    def accepts(self, item: Flow) -> bool:
        return item.new or not self.new_only

    def cells(self, item: Flow) -> tuple[Any, ...]:
        app, domain, remote = NARROW if self.size.width < WIDE_FROM else WIDE
        flows = self.lazy.flows
        style = BONE if flows.active(item) else GRAY
        return (
            Text(fit(item.process, app), style=style),
            Text(fit(item.name or "-", domain), style=style if item.name else GRAY),
            Text(VIA[item.source], style=GRAY),
            Text(fit(item.remote, remote), style=style),
            Text(item.proto, style=GRAY),
            Text(human_bytes(item.tx_bytes), style=style, justify="right"),
            Text(human_bytes(item.rx_bytes), style=style, justify="right"),
            Text("new" if item.new else str(item.seen), style=ACID if item.new else GRAY,
                 justify="right"),
            Text(age(flows.latest - item.last), style=GRAY, justify="right"),
        )  # fmt: skip

    def render_rows(self) -> None:
        super().render_rows()
        self.update_detail()

    def refresh_view(self, force: bool = False) -> None:
        flows = self.lazy.flows
        if not force and self.lazy.query_one(TabbedContent).active != "conns":
            return
        notice = self.query_one(".notice", Static)
        message = "" if self.lazy.capturing or flows.rows() else HINT
        notice.update(Text(message, style=GRAY) if message else "")
        notice.display = bool(message)
        if force or flows.version != self._seen:
            self._seen = flows.version
            self.set_items(sort_flows(flows.rows(), self.sort))
            self.update_summary()

    def update_summary(self) -> None:
        s = self.lazy.flows.summary()
        line = Text(no_wrap=True, overflow="ellipsis")
        for value, style in (
            (f"{s['connections']} conns", BONE),
            (f"{s['active']} active", BONE),
            (f"{s['new_destinations']} new", ACID if s["new_destinations"] else BONE),
            (f"up {human_bytes(s['tx_bytes'])} down {human_bytes(s['rx_bytes'])}", BONE),
        ):
            line.append(":: ", style=DIM)
            line.append(value + " ", style=style)
        line.append("::", style=DIM)
        line.append(f"  sort {self.sort}", style=GRAY)
        if self.new_only:
            line.append("  new only", style=ACID)
        self.query_one("#summary", Static).update(line)

    def update_detail(self) -> None:
        item = self.selected()
        detail = self.query_one("#detail", Static)
        if item is None:
            detail.update("")
            return
        name = f"{item.name} ({item.source}, {item.confidence})" if item.name else "no name"
        pid = "-" if item.process == "-" else str(item.pid)
        detail.update(
            Text.assemble(
                (name, BONE if item.name else GRAY),
                (f"  pid {pid} ", GRAY),
                (f"{item.local} -> {item.remote}", BONE),
                (f"  {item.interface}  pkts {item.tx_packets}/{item.rx_packets}", GRAY),
                ("  first ", GRAY),
                (clock(item.first), BONE),
                no_wrap=True,
                overflow="ellipsis",
            )
        )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.update_detail()

    def action_toggle_capture(self) -> None:
        self.lazy.toggle_capture()

    def action_cycle_sort(self) -> None:
        self.sort = SORTS[(SORTS.index(self.sort) + 1) % len(SORTS)]
        self.refresh_view(force=True)

    def action_toggle_new(self) -> None:
        self.new_only = not self.new_only
        self.refresh_view(force=True)

    def action_export(self) -> None:
        flows = self.lazy.flows
        rows = sort_flows(flows.rows(), self.sort)
        if not rows:
            self.app.notify("nothing to export yet", severity="warning")
            return
        try:
            json_path, csv_path, _ = write_flows(
                flows, rows, self.lazy.device_dir / "reports", scrub=self.lazy.scrub
            )
        except OSError as e:
            self.app.notify(f"cannot write report: {e}", severity="error", markup=False)
            return
        self.last_report = csv_path
        self.lazy.saved(csv_path.parent, "connections")
        self.app.notify(f"saved {json_path} (+ .csv, .sha256), o to open", markup=False)

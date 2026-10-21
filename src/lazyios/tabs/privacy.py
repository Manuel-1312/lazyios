from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Input, Static, TabbedContent

from .. import opener
from ..art import header
from ..privacy import SORTS, HostRow, sort_rows, summarize, write_report
from ..theme import BONE, DIM, GRAY, RED
from .base import TableTab

REFRESH = 1.0
NARROW = (11, 20, 9, 9)  # app, domain, category, company
WIDE = (16, 36, 12, 18)
WIDE_FROM = 100
CAVEAT = Text(
    "names: unauthenticated DNS + TLS SNI; DoH, ECH, QUIC, Relay show as bare IPs", style=DIM
)
VIA = {"sni": "sni", "dns": "dns", "ip": "-"}
HINT = "press space to start a capture, then use your apps"


def fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def human_bytes(n: int) -> str:
    size = float(n)
    for unit in ("B", "K", "M", "G"):
        if size < 1024 or unit == "G":
            return f"{size:.0f}{unit}" if unit == "B" or size >= 10 else f"{size:.1f}{unit}"
        size /= 1024
    return ""


def age(seconds: float) -> str:
    s = max(0, int(seconds))
    return f"{s}s" if s < 60 else f"{s // 60}m" if s < 3600 else f"{s // 3600}h"


def clock(when: float) -> str:
    return datetime.fromtimestamp(when).strftime("%H:%M:%S")


class PrivacyTab(TableTab[HostRow]):
    title = "privacy"
    columns = (
        ("app", False),
        ("domain", False),
        ("category", False),
        ("company", False),
        ("via", False),
        ("flows", True),
        ("bytes", True),
        ("last", True),
    )
    BINDINGS = [
        Binding("slash", "focus_filter", "filter"),
        Binding("space", "toggle_capture", "capture"),
        Binding("s", "cycle_sort", "sort"),
        Binding("t", "toggle_trackers", "trackers"),
        Binding("e", "export", "export"),
        Binding("o", "open_report", "open"),
        Binding("escape", "focus_table", show=False),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.sort = SORTS[0]
        self.trackers_only = False
        self.last_report: Path | None = None
        self._seen = -1

    def compose(self) -> ComposeResult:
        yield Static(header(self.title), classes="head")
        yield Static("", id="summary")
        yield Input(placeholder="/ filter", id="filter")
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

    def key(self, item: HostRow) -> str:
        return f"{item.process}\x00{item.domain}"

    def haystack(self, item: HostRow) -> tuple[str, ...]:
        return (item.process, item.domain, item.category, item.company)

    def accepts(self, item: HostRow) -> bool:
        return item.tracker or not self.trackers_only

    def cells(self, item: HostRow) -> tuple[Any, ...]:
        app, domain, category, company = NARROW if self.size.width < WIDE_FROM else WIDE
        bare = item.domain in item.ips  # no name known, only the address
        style = GRAY if bare else BONE
        return (
            Text(fit(item.process, app), style=style),
            Text(fit(item.domain, domain), style=style),
            Text(item.category or "-", style=RED if item.tracker else GRAY),
            Text(fit(item.company or "-", company), style=style if item.company else GRAY),
            Text(VIA[item.source], style=GRAY),
            Text(str(item.flows), style=style, justify="right"),
            Text(human_bytes(item.bytes), style=style, justify="right"),
            Text(age(self.lazy.aggregator.latest - item.last), style=GRAY, justify="right"),
        )

    def render_rows(self) -> None:
        super().render_rows()
        self.update_detail()

    def refresh_view(self, force: bool = False) -> None:
        agg = self.lazy.aggregator
        if not force and self.lazy.query_one(TabbedContent).active != "privacy":
            return
        notice = self.query_one(".notice", Static)
        capturing = self.lazy.capturing
        message = "" if capturing or agg.rows() else HINT
        notice.update(Text(message, style=GRAY) if message else "")
        notice.display = bool(message)
        if force or agg.version != self._seen:
            self._seen = agg.version
            self.set_items(sort_rows(agg.rows(), self.sort))
            self.update_summary()

    def update_summary(self) -> None:
        apps, domains, trackers = summarize(self.items)
        line = Text(no_wrap=True, overflow="ellipsis")
        for value in (f"{apps} apps", f"{domains} domains"):
            line.append(":: ", style=DIM)
            line.append(value + " ")
        line.append(":: ", style=DIM)
        line.append(f"{trackers} trackers ", style=RED if trackers else BONE)
        line.append("::", style=DIM)
        line.append(f"  sort {self.sort}", style=GRAY)
        if self.trackers_only:
            line.append("  trackers only", style=RED)
        self.query_one("#summary", Static).update(line)

    def update_detail(self) -> None:
        item = self.selected()
        detail = self.query_one("#detail", Static)
        if item is None:
            detail.update("")
            return
        more = f" +{item.flows - len(item.ips)}" if item.flows > len(item.ips) > 3 else ""
        detail.update(
            Text.assemble(
                ("ips ", GRAY),
                (", ".join(item.ips[:3]) + more, BONE),
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

    def action_toggle_trackers(self) -> None:
        self.trackers_only = not self.trackers_only
        self.refresh_view(force=True)

    def action_export(self) -> None:
        rows = sort_rows(self.lazy.aggregator.rows(), self.sort)
        if not rows:
            self.app.notify("nothing to export yet", severity="warning")
            return
        try:
            json_path, csv_path = write_report(rows, self.lazy.out_dir / "reports")
        except OSError as e:
            self.app.notify(f"cannot write report: {e}", severity="error", markup=False)
            return
        self.last_report = csv_path
        self.app.notify(f"report saved: {json_path} (+ .csv), o to open", markup=False)

    def action_open_report(self) -> None:
        if self.last_report is None or not self.last_report.exists():
            self.app.notify("no report yet: press e", severity="warning")
            return
        try:
            opener.open_default(self.last_report)
        except OSError as e:
            self.app.notify(f"cannot open: {e}", severity="error", markup=False)
            return
        self.app.notify("opened report")

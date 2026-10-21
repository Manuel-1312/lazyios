from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Input, Static, TabbedContent

from ..art import header
from ..score import CRITERIA, SORTS, AppScore, score_apps, sort_scores, top_companies, write_scores
from ..screens import TextScreen
from ..sessions import compare
from ..theme import ACID, BONE, DIM, GRAY, RED
from .base import ReportOpener, TableTab
from .privacy import fit, human_bytes

REFRESH = 1.0
GRADE_STYLE = {"A": ACID, "B": BONE, "C": BONE, "D": RED, "F": f"bold {RED}"}
HINT = "press space to start a capture; scores and comparisons fill in as apps talk"
ABOUT = (
    "score\n" + "\n".join(f"  {line}" for line in CRITERIA) + "\n\nnew\n"
    "  domains an app did not contact in the last sessions of this device\n"
    "  (history in <out>/sessions, one file per capture, --keep-sessions)\n"
    "  an app with no history shows 'first'; nothing is called new then\n"
    "\nalerts (<out>/alerts.json)\n"
    '  {"new_tracker": true, "tracker": false, "new_domain": false,\n'
    '   "watch": ["facebook.com"]}\n'
)


class ScoreTab(ReportOpener, TableTab[AppScore]):
    title = "score"
    columns = (
        ("app", False),
        ("score", True),
        ("", False),
        ("trackers", True),
        ("companies", True),
        ("unknown", True),
        ("new", False),
        ("to trk", True),
        ("bytes", True),
    )
    BINDINGS = [
        Binding("slash", "focus_filter", "filter"),
        Binding("space", "toggle_capture", "capture"),
        Binding("s", "cycle_sort", "sort"),
        Binding("c", "criteria", "criteria"),
        Binding("e", "export", "export"),
        Binding("o", "open_report", "open"),
        Binding("escape", "focus_table", show=False),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.sort = SORTS[0]
        self._seen = (-1, -1)

    def compose(self) -> ComposeResult:
        yield Static(header(self.title), classes="head")
        yield Static("", id="summary")
        yield Input(placeholder="/ filter app", id="filter")
        yield Static("", classes="notice")
        yield DataTable(id="table", cursor_type="row")
        yield Static("", id="why")

    def on_mount(self) -> None:
        self.set_interval(REFRESH, self.refresh_view)

    def activate(self) -> None:
        super().activate()
        self.refresh_view(force=True)

    async def load(self) -> None:
        self.refresh_view(force=True)

    def key(self, item: AppScore) -> str:
        return item.app

    def haystack(self, item: AppScore) -> tuple[str, ...]:
        return (item.app, *item.trackers, *item.tracker_companies)

    def cells(self, item: AppScore) -> tuple[Any, ...]:
        width = 16 if self.size.width < 100 else 24
        return (
            Text(fit(item.app, width), style=BONE),
            Text(str(item.score), style=GRADE_STYLE[item.grade], justify="right"),
            Text(item.grade, style=GRADE_STYLE[item.grade]),
            Text(str(len(item.trackers)), style=RED if item.trackers else GRAY, justify="right"),
            Text(str(len(item.companies)), style=GRAY, justify="right"),
            Text(str(item.unknown), style=GRAY, justify="right"),
            self._new_cell(item),
            Text(f"{item.tracker_share:.0%}", style=RED if item.tracker_share else GRAY,
                 justify="right"),
            Text(human_bytes(item.bytes), style=GRAY, justify="right"),
        )  # fmt: skip

    def _new_cell(self, item: AppScore) -> Text:
        change = item.change
        if change is None or not change.known:
            return Text("first", style=DIM)
        if item.new_trackers:
            return Text(f"+{len(item.new_trackers)} trk", style=f"bold {RED}")
        if change.new_domains:
            return Text(f"+{len(change.new_domains)}", style=ACID)
        return Text("-", style=GRAY)

    def scores(self) -> list[AppScore]:
        app = self.lazy
        rows = app.aggregator.rows()
        return score_apps(rows, compare(rows, app.baseline), app.versions)

    def render_rows(self) -> None:
        super().render_rows()
        self.update_why()

    def refresh_view(self, force: bool = False) -> None:
        app = self.lazy
        if not force and app.query_one(TabbedContent).active != "score":
            return
        notice = self.query_one(".notice", Static)
        message = "" if app.capturing or app.aggregator.rows() else HINT
        notice.update(Text(message, style=GRAY) if message else "")
        notice.display = bool(message)
        state = (app.aggregator.version, len(app.alerts))
        if force or state != self._seen:
            self._seen = state
            self.set_items(sort_scores(self.scores(), self.sort))
            self.update_summary()

    def update_summary(self) -> None:
        scored = self.items
        with_trackers = sum(1 for a in scored if a.trackers)
        line = Text(no_wrap=True, overflow="ellipsis")
        alerts = len(self.lazy.alerts)
        parts = [
            (f"{len(scored)} apps", BONE),
            (f"{with_trackers} with trackers", BONE),
            (f"{alerts} alerts", RED if alerts else GRAY),
            (f"vs {len(self.lazy.baseline)} sessions", GRAY),
            (f"sort {self.sort}", GRAY),
        ]
        if top := top_companies(scored):  # last: the part a narrow terminal may cut
            parts.append(("top " + ", ".join(f"{c} ({n})" for c, n in top), RED))
        for value, style in parts:
            line.append(":: ", style=DIM)
            line.append(value + " ", style=style)
        self.query_one("#summary", Static).update(line)

    def update_why(self) -> None:
        item = self.selected()
        why = self.query_one("#why", Static)
        if item is None:
            why.update("")
            return
        reasons = "; ".join(item.reasons) or "nothing taken off"
        lines = [Text.assemble(("why ", GRAY), (reasons, BONE))]
        change = item.change
        if change is not None and change.known:
            update = f"after update {change.previous_version} -> {item.version}  "
            lines.append(
                Text.assemble(
                    (update if item.updated else "", ACID),
                    ("new ", GRAY),
                    (", ".join(change.new_domains) or "none", RED if item.new_trackers else BONE),
                )
            )
        else:
            lines.append(Text("first capture with this app: nothing to compare yet", style=DIM))
        hits = [f"{domain} ({reason})" for _, app, domain, reason in self.lazy.alerts
                if app == item.app]  # fmt: skip
        if hits:
            lines.append(Text.assemble(("alerts ", GRAY), (", ".join(hits), RED)))
        for line in lines:  # one row each: Textual would wrap them into the next one
            line.truncate(max(10, self.size.width - 2), overflow="ellipsis")
        why.update(Text("\n").join(lines))

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self.update_why()

    def action_toggle_capture(self) -> None:
        self.lazy.toggle_capture()

    def action_cycle_sort(self) -> None:
        self.sort = SORTS[(SORTS.index(self.sort) + 1) % len(SORTS)]
        self.refresh_view(force=True)

    def action_criteria(self) -> None:
        self.app.push_screen(TextScreen("how the score works", ABOUT))

    def action_export(self) -> None:
        scored = sort_scores(self.scores(), self.sort)
        if not scored:
            self.app.notify("nothing to export yet", severity="warning")
            return
        try:
            json_path, csv_path, _ = write_scores(scored, self.lazy.out_dir / "reports")
        except OSError as e:
            self.app.notify(f"cannot write report: {e}", severity="error", markup=False)
            return
        self.last_report = csv_path
        self.app.notify(f"saved {json_path} (+ .csv, .sha256), o to open", markup=False)

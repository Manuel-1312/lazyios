"""Shared tab behaviour."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Generic, TypeVar

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.events import Resize
from textual.widgets import DataTable, Input, Static

from .. import opener
from ..art import header
from ..parsing import matches_filter
from ..theme import RED

if TYPE_CHECKING:
    from ..app import LazyiosApp

T = TypeVar("T")


class TabBody(Vertical):
    """Body of one tab: loads once on first activation, can show an inline notice."""

    title: ClassVar[str] = ""
    focus_id: ClassVar[str] = ""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._loaded = False

    @property
    def lazy(self) -> LazyiosApp:
        return self.app  # type: ignore[return-value]

    def activate(self) -> None:
        if not self._loaded:
            self._loaded = True
            self.lazy.run_task(self.load(), group=f"load-{self.id}")
        (self.query_one(self.focus_id) if self.focus_id else self).focus()

    async def load(self) -> None:
        """Fetch the initial data."""

    def reset_device(self) -> None:
        """Another device was picked: forget what was shown, load again on next activation."""
        self._loaded = False

    def notice(self, message: str) -> None:
        widget = self.query_one(".notice", Static)
        widget.update(Text(message, style=f"bold {RED}") if message else "")
        widget.display = bool(message)


class TableTab(TabBody, Generic[T]):
    """A filterable table over a list of items (processes, apps)."""

    focus_id = "#table"
    columns: ClassVar[tuple[tuple[str, bool], ...]] = ()
    max_shown: ClassVar[int | None] = None
    BINDINGS = [
        Binding("slash", "focus_filter", "filter", id="filter"),
        Binding("r", "reload", "refresh", id="refresh"),
        Binding("escape", "focus_table", show=False),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.items: list[T] = []

    def key(self, item: T) -> str:
        raise NotImplementedError

    def cells(self, item: T) -> tuple[Any, ...]:
        raise NotImplementedError

    def haystack(self, item: T) -> tuple[str, ...]:
        raise NotImplementedError

    def accepts(self, item: T) -> bool:
        """Extra per-tab row filter, applied together with the text filter."""
        return True

    def matches(self, item: T, needle: str) -> bool:
        """The text filter; tabs with a query syntax override it."""
        return matches_filter(needle, *self.haystack(item))

    def compose(self) -> ComposeResult:
        yield Static(header(self.title), classes="head")
        yield Input(placeholder="/ filter", id="filter")
        yield Static("", classes="notice")
        yield DataTable(id="table", cursor_type="row")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for label, right in self.columns:
            table.add_column(Text(label, justify="right" if right else "left"), key=label)
        self.query_one(".notice").display = False

    def selected(self) -> T | None:
        table = self.query_one(DataTable)
        if not table.row_count:
            return None
        row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value
        return next((i for i in self.items if self.key(i) == row_key), None)

    def reset_device(self) -> None:
        super().reset_device()
        self.set_items([])

    def set_items(self, items: list[T]) -> None:
        self.items = items
        self.render_rows()

    def render_rows(self) -> None:
        table = self.query_one(DataTable)
        keep = self.selected()
        needle = self.query_one("#filter", Input).value
        table.clear()
        shown = [i for i in self.items if self.accepts(i) and self.matches(i, needle)]
        if self.max_shown is not None:  # keeps rebuilding the table cheap on long captures
            shown = shown[: self.max_shown]
        for item in shown:
            table.add_row(*self.cells(item), key=self.key(item))
        if keep is not None:
            with_key = [self.key(i) for i in shown]
            if self.key(keep) in with_key:
                table.move_cursor(row=with_key.index(self.key(keep)))
        self.query_one(".head", Static).update(
            f"{header(self.title)}  {len(shown)}/{len(self.items)}"
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.render_rows()

    def on_resize(self, event: Resize) -> None:
        if self.items:  # some tabs size their columns to the width
            self.render_rows()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.action_focus_table()

    def action_focus_filter(self) -> None:
        self.query_one("#filter", Input).focus()

    def action_focus_table(self) -> None:
        self.query_one(DataTable).focus()

    def action_reload(self) -> None:
        self.lazy.run_task(self.load(), group=f"load-{self.id}")


class ReportOpener:
    """For tabs that export reports: `o` opens the last one with the OS handler."""

    app: Any
    last_report: Path | None = None

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

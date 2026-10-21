"""Modal screens: confirm, prompt, help, device picker, security audit."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Input, Static

from .art import header
from .audit import Check, summary, write_audit
from .backend import DeviceSummary
from .files import Scrub
from .theme import ACID, BONE, DIM, GRAY, RED

GLOBAL_HELP = """\
 global
   1-9, 0     switch tab
   q          quit (clears condition and location)
   ?          this help
   d          devices: pick another connected device
   /          focus the filter, esc to leave it
   r          refresh (logs: reconnect now)
   ctrl+p     command palette: every action by name
"""
TAB_HELP = {
    "overview": """\
 overview    a security audit (e to export it)
""",
    "logs": """\
 logs        p pause/resume   c clear   r reconnect
             v lowest level shown: all, notice, warning, error
""",
    "processes": """\
 processes   k kill   l launch by bundle id   m live cpu and memory
""",
    "apps": """\
 apps        enter launch
""",
    "network": """\
 network     space start/stop capture   o open capture
             enter apply condition      x clear condition   r reload
             [ ] smaller / bigger conditions pane
""",
    "tools": """\
 tools       s screenshot   o open it   l coordinates
             enter set location   x clear location   f fps
""",
    "privacy": """\
 privacy     space start/stop capture   s sort   t trackers only
             e export report   o open it   / filter
""",
    "conns": """\
 conns       space start/stop capture   s sort   n new destinations only
             e export (json, csv, sha256)   o open it
             / filter: words, or app: domain: ip: port:443 proto:udp
""",
    "score": """\
 score       privacy score per app, new domains vs earlier sessions
             s sort   c how the score works   e export   o open it
""",
    "timeline": """\
 timeline    device, capture, first contacts, syslog errors, conditions,
             alerts and anomalies, newest first   p watch processes
             / kind:app,anomaly app:x since:10:05 until:10:30 last:5m
             e export (what the filter shows)   o open it
""",
}
HELP = GLOBAL_HELP + "\n" + "".join(TAB_HELP.values())


class Confirm(ModalScreen[bool]):
    BINDINGS = [
        Binding("y", "answer(True)", "yes"),
        Binding("n,escape", "answer(False)", "no"),
    ]

    def __init__(self, question: str) -> None:
        super().__init__()
        self.question = question

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(self.question, classes="dialog-title")
            with Horizontal(classes="dialog-buttons"):
                yield Button("no", id="no")
                yield Button("yes", id="yes", variant="error")

    def on_mount(self) -> None:
        self.query_one("#no", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes")

    def action_answer(self, value: bool) -> None:
        self.dismiss(value)


class Prompt(ModalScreen[str | None]):
    BINDINGS = [Binding("escape", "cancel", "cancel")]

    def __init__(self, title: str, placeholder: str = "") -> None:
        super().__init__()
        self.title_text = title
        self.placeholder = placeholder

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(self.title_text, classes="dialog-title")
            yield Input(placeholder=self.placeholder)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class TextScreen(ModalScreen[None]):
    BINDINGS = [Binding("escape,question_mark,q", "dismiss", "close")]

    def __init__(self, title: str, text: str) -> None:
        super().__init__()
        self.title_text = title
        self.text = text

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(header(self.title_text), classes="dialog-title")
            yield Static(self.text, markup=False)


class Help(TextScreen):
    """The current tab's keys first, then the global ones and the other tabs."""

    def __init__(self, tab: str | None = None) -> None:
        mine = TAB_HELP.get(tab or "", "")
        rest = "".join(v for k, v in TAB_HELP.items() if k != tab)
        text = (f"{mine}\n" if mine else "") + GLOBAL_HELP + "\n" + rest
        super().__init__(f"keys :: {tab}" if mine else "keys", text)


class DevicePicker(ModalScreen[str | None]):
    """Connected devices; enter switches to the highlighted one."""

    BINDINGS = [Binding("escape", "dismiss(None)", "cancel")]

    def __init__(self, devices: list[DeviceSummary], current: str | None) -> None:
        super().__init__()
        self.devices = devices
        self.current = current

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Static(header("devices"), classes="dialog-title")
            yield DataTable(id="devices", cursor_type="row")
            yield Static("enter switch   esc cancel", classes="dialog-hint")

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for label in ("", "name", "model", "ios", "link", "udid"):
            table.add_column(label)
        for d in self.devices:
            mark = Text("*", style=ACID) if d.udid == self.current else Text(" ")
            name = Text(d.name or "-") if d.trusted else Text("not trusted: unlock it, tap Trust",
                                                                 style=RED)  # fmt: skip
            table.add_row(mark, name, d.product_type or "-", d.version or "-", d.connection,
                          Text(d.udid, style=GRAY), key=d.udid)  # fmt: skip
        if not self.devices:
            self.query_one(".dialog-hint", Static).update("no device found   esc close")
        table.focus()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        device = next((d for d in self.devices if d.udid == event.row_key.value), None)
        if device is not None and not device.trusted:
            self.app.notify("unlock that device and tap Trust first", severity="warning")
            return
        self.dismiss(event.row_key.value)


_STATUS = {"attention": ("!", RED), "ok": ("ok", ACID), "info": ("i", BONE), "unknown": ("?", GRAY)}
_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def audit_text(checks: list[Check]) -> Text:
    """Attention items first, most severe first; then the rest."""
    counts = summary(checks)
    lines = [Text.assemble(("needs attention: ", GRAY), (
        ", ".join(f"{n} {sev}" for sev, n in counts.items() if n) or "nothing", RED
        if any(counts.values()) else ACID))]  # fmt: skip
    ordered = sorted(checks, key=lambda c: (c.status != "attention", _ORDER[c.severity]))
    for c in ordered:
        mark, style = _STATUS[c.status]
        severity = f" [{c.severity}]" if c.status == "attention" else ""
        lines += [
            Text(),
            Text.assemble((f"{mark:>2} ", style), (c.title, f"bold {BONE}"), (severity, style)),
            Text.assemble(("   ", ""), (c.evidence, GRAY)),
            Text.assemble(("   ", ""), (c.why, BONE)),
        ]
        if c.action:
            lines.append(Text.assemble(("   -> ", DIM), (c.action, ACID)))
    lines += [Text(), Text("values the device reports to a trusted computer; no system files"
                           " are read, so nothing here proves a compromise or rules one out",
                           style=DIM)]  # fmt: skip
    return Text("\n").join(lines)


class AuditScreen(ModalScreen[None]):
    BINDINGS = [
        Binding("escape,q", "dismiss", "close"),
        Binding("e", "export", "export"),
    ]

    def __init__(
        self,
        checks: list[Check],
        device: str,
        folder: Path,
        scrub: Scrub | None = None,
        saved: Callable[[Path, str], None] | None = None,
    ) -> None:
        super().__init__()
        self.checks = checks
        self.device = device
        self.folder = folder
        self.scrub = scrub  # anonymizes the export when set
        self.saved = saved  # told about the written report (retention)

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog wide"):
            yield Static(header(f"security audit :: {self.device}"), classes="dialog-title")
            yield Static(audit_text(self.checks))
            yield Static("e export   esc close", classes="dialog-hint")

    def action_export(self) -> None:
        try:
            json_path, _, _ = write_audit(self.checks, self.device, self.folder, scrub=self.scrub)
        except OSError as e:
            self.app.notify(f"cannot write report: {e}", severity="error", markup=False)
            return
        if self.saved is not None:
            self.saved(self.folder, "audit")
        self.app.notify(f"saved {json_path} (+ .csv, .sha256)", markup=False)

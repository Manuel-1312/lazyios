"""Modal screens: confirm, prompt, help."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from .art import header

HELP = """\
 global
   1-9, 0     switch tab
   q          quit (clears condition and location)
   ?          this help
   /          focus the filter, esc to leave it
   r          refresh (logs: reconnect now)

 logs        p pause/resume   c clear   r reconnect
 processes   k kill   l launch by bundle id
 apps        enter launch
 network     space start/stop capture   o open capture
             enter apply condition      x clear condition   r reload
 tools       s screenshot   o open it   l coordinates
             enter set location   x clear location   f fps
 privacy     space start/stop capture   s sort   t trackers only
             e export report   o open it   / filter
 conns       space start/stop capture   s sort   n new destinations only
             e export (json, csv, sha256)   o open it
             / filter: words, or app: domain: ip: port:443 proto:udp
 score       privacy score per app, new domains vs earlier sessions
             s sort   c how the score works   e export   o open it
 timeline    device, capture, first contacts, syslog errors, conditions,
             alerts and anomalies, newest first   p watch processes
             / kind:app,anomaly app:x since:10:05 until:10:30 last:5m
             e export (what the filter shows)   o open it
"""


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
    def __init__(self) -> None:
        super().__init__("keys", HELP)

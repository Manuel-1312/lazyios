from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.events import Resize
from textual.widgets import Static

from .. import usbmuxd
from ..art import LOGO, LOGO_COMPACT, LOGO_HEIGHT, LOGO_WIDTH, TAG, bar, header
from ..backend import BackendError, NoDeviceError, NotTrustedError, UsbmuxdError
from ..theme import ACID, BONE, DIM, GRAY, RED
from .base import TabBody


def _row(label: str, value: str, style: str = BONE) -> Text:
    return Text.assemble(("  " + label.ljust(10), GRAY), (value, style))


class OverviewTab(TabBody):
    title = "overview"
    BINDINGS = [Binding("r", "reload", "refresh")]
    can_focus = True

    def compose(self) -> ComposeResult:
        yield Static(id="view")

    def on_mount(self) -> None:
        self.render_view()

    def on_resize(self, event: Resize) -> None:
        self.render_view()

    def action_reload(self) -> None:
        self.lazy.run_task(self.lazy.refresh_device(verbose=True), group="refresh")

    def _logo(self) -> Text:
        if self.size.width >= LOGO_WIDTH + 2 and self.size.height >= LOGO_HEIGHT + 19:
            return Text(LOGO, style=ACID, no_wrap=True)
        return Text(LOGO_COMPACT, style=ACID, no_wrap=True)

    def render_view(self) -> None:
        app = self.lazy
        info, battery = app.info, app.battery
        parts: list[Text] = [self._logo(), Text(TAG, style=DIM), Text()]
        if info is None:
            parts += [Text(header("device"), style=ACID), *_problem_lines(app.problem)]
        else:
            parts += [
                Text(header("device"), style=ACID),
                _row("name", info.name),
                _row("model", info.product_type),
                _row("ios", f"{info.version} ({info.build})"),
                _row("serial", info.serial),
                _row("wifi mac", info.wifi_mac),
                _row("udid", info.udid),
                Text(),
                Text(header("battery"), style=ACID),
            ]
            if battery is None:
                parts.append(_row("level", "n/a", GRAY))
            else:
                parts += [
                    _row("level", f"{battery.percent:>3}% {bar(battery.percent, 20)}", ACID),
                    _row("cycles", str(battery.cycles)),
                    _row("power", _power(battery.charging, battery.watts, battery.adapter)),
                ]
            dev = app.dev_mode
            parts += [
                Text(),
                Text(header("developer"), style=ACID),
                _row(
                    "mode",
                    "n/a" if dev is None else "on" if dev else "off",
                    GRAY if dev is None else BONE if dev else RED,
                ),
                _row("link", "usb"),
            ]
            if dev is False:
                parts.append(
                    Text(
                        "  settings > privacy & security > developer mode, then restart", style=GRAY
                    )
                )
        self.query_one("#view", Static).update(Text("\n").join(parts))


def _problem_lines(problem: BackendError | None) -> list[Text]:
    """What to do when no device is available, by kind of failure."""
    if isinstance(problem, UsbmuxdError):
        title, todo = "usbmuxd is not reachable", usbmuxd.hint()
    elif isinstance(problem, NotTrustedError):
        title, todo = "iphone not trusted", "unlock it and tap Trust, then press r"
    elif problem is None or isinstance(problem, NoDeviceError):
        title = "no device"
        todo = "plug in an unlocked iphone with a data cable and press r"
    else:
        title, todo = "device error", str(problem)
    return [Text(f"  {title}", style=f"bold {RED}"), Text(f"  {todo}", style=GRAY)]


def _power(charging: bool, watts: int | None, adapter: str) -> str:
    state = "charging" if charging else "on battery"
    extra = ", ".join(x for x in (adapter, f"{watts} w" if watts else "") if x)
    return f"{state} ({extra})" if extra else state

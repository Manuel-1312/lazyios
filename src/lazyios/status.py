"""Top status line."""

from __future__ import annotations

from rich.text import Text

from .art import bar
from .backend import Battery, Condition, DeviceInfo
from .theme import ACID, BONE, DIM, GRAY, RED


def status_line(
    info: DeviceInfo | None,
    battery: Battery | None,
    dev_mode: bool | None,
    condition: Condition | None,
    tunnel: str = "off",
) -> Text:
    text = Text(no_wrap=True, overflow="ellipsis")

    def seg(value: str, style: str = BONE) -> None:
        text.append(":: ", style=DIM)
        text.append(value, style=style)
        text.append(" ")

    if info is None:
        seg("no device", RED)
    else:
        seg(info.product_type)
        seg(f"ios {info.version} ({info.build})", GRAY)
    if battery is not None:
        level = f"bat {battery.percent}% {bar(battery.percent)}" + (
            " chrg" if battery.charging else ""
        )
        seg(level, ACID)
    if dev_mode is not None:
        seg("dev on" if dev_mode else "dev off", BONE if dev_mode else RED)
    if tunnel == "opening":
        seg("opening tunnel...", ACID)
    if condition is None:
        seg("cond none", GRAY)
    else:
        seg(f"cond {condition.profile_id}", f"bold {BONE} on {RED}")
    text.append("::", style=DIM)
    return text

from __future__ import annotations

from typing import Any

from rich.text import Text
from textual.binding import Binding

from ..backend import BackendError, Process
from ..screens import Confirm, Prompt
from ..theme import BONE, GRAY
from .base import TableTab


class ProcessesTab(TableTab[Process]):
    title = "processes"
    columns = (("pid", True), ("name", False), ("app", False), ("started", False))
    BINDINGS = [
        *TableTab.BINDINGS,
        Binding("k", "kill", "kill"),
        Binding("l", "launch", "launch"),
    ]

    def key(self, item: Process) -> str:
        return str(item.pid)

    def cells(self, item: Process) -> tuple[Any, ...]:
        return (
            Text(str(item.pid), justify="right"),
            Text(item.name, style=BONE if item.is_app else GRAY),
            "yes" if item.is_app else "-",
            item.started,
        )

    def haystack(self, item: Process) -> tuple[str, ...]:
        return (item.name, str(item.pid))

    async def load(self) -> None:
        if message := await self.lazy.open_dvt():
            self.notice(message)
            return
        try:
            processes = await self.lazy.backend.processes()
        except BackendError as e:
            self.notice(str(e))
            self.lazy.report(e)
            return
        self.notice("")
        self.set_items(sorted(processes, key=lambda p: p.pid))

    def action_kill(self) -> None:
        process = self.selected()
        if process is None:
            return

        def done(confirmed: bool | None) -> None:
            if confirmed:
                self.lazy.run_task(self._kill(process), group="kill")

        self.app.push_screen(Confirm(f"kill {process.name} [{process.pid}]?"), done)

    async def _kill(self, process: Process) -> None:
        try:
            await self.lazy.backend.kill(process.pid)
        except BackendError as e:
            self.lazy.report(e)
            return
        self.app.notify(f"killed {process.name} [{process.pid}]")
        await self.load()

    def action_launch(self) -> None:
        def done(bundle_id: str | None) -> None:
            if bundle_id:
                self.lazy.run_task(self.lazy.launch(bundle_id), group="launch")

        self.app.push_screen(Prompt("launch bundle id", "com.apple.Preferences"), done)

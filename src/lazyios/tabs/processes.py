from __future__ import annotations

from collections import deque
from contextlib import aclosing
from typing import Any

from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.widgets import DataTable, Input, Sparkline, Static
from textual.worker import Worker

from ..art import header
from ..backend import BackendError, Process, ProcSample, SysSample
from ..screens import Confirm, Prompt
from ..theme import ACID, BONE, DIM, GRAY
from .base import TableTab
from .privacy import human_bytes

HISTORY = 120  # samples of total CPU kept for the sparkline, about two minutes
MONITOR_ROWS = 300  # busiest processes shown while the monitor runs


def _rate(value: float | None) -> Text:
    """Bytes per second; ACID from 100 KB/s up."""
    if value is None:
        return Text("-", style=GRAY, justify="right")
    return Text(f"{human_bytes(value)}/s", style=ACID if value >= 100 * 1024 else GRAY,
                justify="right")  # fmt: skip


class ProcessesTab(TableTab[Process]):
    title = "processes"
    columns = (
        ("pid", True),
        ("name", False),
        ("app", False),
        ("started", False),
        ("cpu %", True),
        ("memory", True),
        ("in/s", True),
        ("out/s", True),
    )
    BINDINGS = [
        *TableTab.BINDINGS,
        Binding("k", "kill", "kill", id="kill"),
        Binding("l", "launch", "launch", id="launch"),
        Binding("m", "toggle_monitor", "cpu/mem/net", id="monitor"),
    ]

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.usage: dict[int, ProcSample] = {}
        self.cpu_history: deque[float] = deque([0.0] * HISTORY, maxlen=HISTORY)
        self.monitoring = False
        self._monitor: Worker[None] | None = None

    def compose(self) -> ComposeResult:
        yield Static(header(self.title), classes="head")
        yield Static("", id="perf")
        yield Sparkline(list(self.cpu_history), id="cpu-spark")
        yield Input(placeholder="/ filter", id="filter")
        yield Static("", classes="notice")
        yield DataTable(id="table", cursor_type="row")

    def on_mount(self) -> None:  # Textual also runs TableTab.on_mount (columns) on its own
        self.query_one("#cpu-spark").display = False
        self.query_one("#perf", Static).update(Text("m live cpu, memory and network", style=DIM))

    def key(self, item: Process) -> str:
        return str(item.pid)

    def cells(self, item: Process) -> tuple[Any, ...]:
        sample = self.usage.get(item.pid)
        cpu = sample.cpu if sample else None
        memory = sample.memory if sample else None
        rx, tx = (sample.rx, sample.tx) if sample else (None, None)
        return (
            Text(str(item.pid), justify="right"),
            Text(item.name, style=BONE if item.is_app else GRAY),
            "yes" if item.is_app else "-",
            item.started,
            Text("-" if cpu is None else f"{cpu:.1f}", style=ACID if cpu and cpu >= 10 else GRAY,
                 justify="right"),
            Text("-" if memory is None else human_bytes(memory), style=GRAY, justify="right"),
            _rate(rx),
            _rate(tx),
        )  # fmt: skip

    def haystack(self, item: Process) -> tuple[str, ...]:
        return (item.name, str(item.pid))

    def reset_device(self) -> None:
        super().reset_device()
        self.usage = {}
        self.cpu_history.extend([0.0] * HISTORY)

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

    def action_toggle_monitor(self) -> None:
        if self._monitor is not None and self.monitoring:
            self._monitor.cancel()
            return
        self._monitor = self.lazy.run_task(self._run_monitor(), group="monitor")

    async def _run_monitor(self) -> None:
        if message := await self.lazy.open_dvt():
            self.notice(message)
            return
        self.monitoring = True
        self.lazy.update_status()
        self.max_shown = MONITOR_ROWS
        self.query_one("#cpu-spark").display = True
        try:
            async with aclosing(self.lazy.backend.sysmon()) as samples:
                async for sample in samples:
                    self.show_sample(sample)
        except BackendError as e:
            self.lazy.report(e)
        finally:
            self.monitoring = False
            self.lazy.update_status()
            self.max_shown = None
            self.query_one("#cpu-spark").display = False
            self.query_one("#perf", Static).update(Text("monitor stopped :: m to start", style=DIM))

    def show_sample(self, sample: SysSample) -> None:
        """Busiest processes first; processes the list did not have yet are added."""
        self.usage = {p.pid: p for p in sample.processes}
        known = {p.pid: p for p in self.items}
        merged = [known.get(s.pid) or Process(s.pid, s.name, False, "") for s in sample.processes]
        merged.sort(key=lambda p: -(self.usage[p.pid].cpu or 0.0))
        self.set_items(merged)
        if sample.cpu is not None:
            self.cpu_history.append(sample.cpu)
            self.query_one("#cpu-spark", Sparkline).data = list(self.cpu_history)
        cpu = "-" if sample.cpu is None else f"{sample.cpu:.0f}%"
        memory = "-" if sample.memory is None else f"{sample.memory:.0%}"
        rx = sum(p.rx or 0 for p in sample.processes)
        tx = sum(p.tx or 0 for p in sample.processes)
        net = (
            Text.assemble(
                ("  in ", GRAY), (f"{human_bytes(rx)}/s", BONE),
                ("  out ", GRAY), (f"{human_bytes(tx)}/s", BONE), ("  usb tunnel not counted", DIM),
            )
            if sample.net
            else Text("  net n/a", style=DIM)
        )  # fmt: skip
        self.query_one("#perf", Static).update(
            Text.assemble(
                ("cpu ", GRAY), (cpu, ACID), (f" of {sample.cores} cores", GRAY),
                ("  memory ", GRAY), (memory, BONE), (" in use, iOS keeps it full", DIM),
                net, (f"  {len(sample.processes)} processes", GRAY), ("  m stop", DIM),
            )
        )  # fmt: skip

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
        self.app.notify(f"killed {process.name} [{process.pid}]", markup=False)
        await self.load()

    def action_launch(self) -> None:
        def done(bundle_id: str | None) -> None:
            if bundle_id:
                self.lazy.run_task(self.lazy.launch(bundle_id), group="launch")

        self.app.push_screen(Prompt("launch bundle id", "com.apple.Preferences"), done)

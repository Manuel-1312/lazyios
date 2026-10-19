from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from contextlib import suppress
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Static, TabbedContent, TabPane
from textual.worker import Worker

from .backend import Backend, BackendError, Battery, DeviceInfo, DevModeOffError
from .screens import Help
from .status import status_line
from .tabs.apps import AppsTab
from .tabs.base import TabBody
from .tabs.logs import LogsTab
from .tabs.network import NetworkTab
from .tabs.overview import OverviewTab
from .tabs.processes import ProcessesTab
from .tabs.tools import ToolsTab
from .theme import UNDERGROUND

TABS: list[tuple[str, type[TabBody]]] = [
    ("overview", OverviewTab),
    ("logs", LogsTab),
    ("processes", ProcessesTab),
    ("apps", AppsTab),
    ("network", NetworkTab),
    ("tools", ToolsTab),
]
BATTERY_REFRESH = 30
SHUTDOWN_TIMEOUT = 15
DEV_OFF = "developer mode is off: enable it in settings > privacy & security"


class LazyiosApp(App[None]):
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = False
    TITLE = "lazyios"
    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("ctrl+c", "quit", "quit", show=False, priority=True),
        Binding("question_mark", "help", "help"),
        *(Binding(str(n), f"tab({n})", name, show=False) for n, (name, _) in enumerate(TABS, 1)),
    ]

    def __init__(self, backend: Backend, out_dir: Path) -> None:
        super().__init__()
        self.backend = backend
        self.out_dir = out_dir
        self.info: DeviceInfo | None = None
        self.battery: Battery | None = None
        self.dev_mode: bool | None = None
        self.tunnel = "off"
        self.problem: BackendError | None = None

    def compose(self) -> ComposeResult:
        yield Static(id="status")
        with TabbedContent(initial="overview"):
            for n, (name, tab) in enumerate(TABS, 1):
                with TabPane(f"{n} {name}", id=name):
                    yield tab(id=f"{name}-tab")
        yield Footer(show_command_palette=False)

    def on_mount(self) -> None:
        self.register_theme(UNDERGROUND)
        self.theme = UNDERGROUND.name
        self.backend.on_reset = self._on_reset
        self.update_status()
        self.run_task(self.refresh_device(), group="refresh")
        self.set_interval(BATTERY_REFRESH, self.tick)

    async def on_unmount(self) -> None:
        """Undo device-side state (condition, location) and close the sessions."""
        with suppress(Exception):
            await asyncio.wait_for(self.backend.close(), SHUTDOWN_TIMEOUT)

    def _on_reset(self) -> None:
        """The backend dropped its device session: clear what the UI showed for it."""
        self.tunnel = "off"
        self.update_status()
        self.query_one(NetworkTab).render_conditions()
        self.query_one(ToolsTab).session_reset()

    def run_task(self, coro: Coroutine[Any, Any, None], *, group: str) -> Worker[None]:
        return self.run_worker(
            self._guarded(coro, group), group=group, exclusive=True, exit_on_error=False
        )

    async def _guarded(self, coro: Coroutine[Any, Any, None], group: str) -> None:
        try:
            await coro
        except BackendError as e:
            self.report(e)
        except Exception as e:  # keep tracebacks and library internals off the screen
            self.report(BackendError(f"{group.split('-')[0]} failed: {type(e).__name__}"))

    def report(self, error: Exception) -> None:
        self.notify(str(error), title="error", severity="error", timeout=6)

    def tick(self) -> None:
        self.run_task(self.refresh_device(battery_only=self.info is not None), group="refresh")

    async def refresh_device(self, *, verbose: bool = False, battery_only: bool = False) -> None:
        try:
            if not battery_only:
                self.info = await self.backend.device_info()
                self.dev_mode = await self.backend.developer_mode()
            self.battery = await self.backend.battery()
            self.problem = None
        except BackendError as e:
            self.info = self.battery = self.dev_mode = None
            self.problem = e
            if verbose:
                self.report(e)
        self.update_status()
        self.query_one(OverviewTab).render_view()

    def update_status(self) -> None:
        self.query_one("#status", Static).update(
            status_line(
                self.info, self.battery, self.dev_mode, self.backend.active_condition, self.tunnel
            )
        )

    async def open_dvt(self) -> str | None:
        """Open the tunnel if needed; returns a message when developer services are unavailable."""
        if self.dev_mode is False:
            return DEV_OFF
        if self.backend.tunnel_open:
            return None
        self.tunnel = "opening"
        self.update_status()
        try:
            await self.backend.open_tunnel()
        except DevModeOffError:
            self.dev_mode = False
            return DEV_OFF
        except BackendError as e:
            self.report(e)
            return str(e)
        finally:
            self.tunnel = "on" if self.backend.tunnel_open else "off"
            self.update_status()
        return None

    async def launch(self, bundle_id: str) -> None:
        if message := await self.open_dvt():
            self.notify(message, severity="error")
            return
        pid = await self.backend.launch(bundle_id)
        self.notify(f"launched {bundle_id} (pid {pid})")

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        event.pane.query_one(TabBody).activate()

    def action_tab(self, number: int) -> None:
        self.query_one(TabbedContent).active = TABS[number - 1][0]

    def action_help(self) -> None:
        self.push_screen(Help())

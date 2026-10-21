from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Coroutine
from contextlib import aclosing, suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Static, TabbedContent, TabPane
from textual.worker import Worker

from . import alerts, sessions
from .backend import Backend, BackendError, Battery, DeviceInfo, DevModeOffError, Packet
from .flows import FlowTable
from .privacy import HostAggregator, HostRow
from .screens import Help
from .status import status_line
from .tabs.apps import AppsTab
from .tabs.base import TabBody
from .tabs.conns import ConnsTab
from .tabs.logs import LogsTab
from .tabs.network import NetworkTab
from .tabs.overview import OverviewTab
from .tabs.privacy import PrivacyTab
from .tabs.processes import ProcessesTab
from .tabs.score import ScoreTab
from .tabs.tools import ToolsTab
from .theme import UNDERGROUND

TABS: list[tuple[str, type[TabBody]]] = [
    ("overview", OverviewTab),
    ("logs", LogsTab),
    ("processes", ProcessesTab),
    ("apps", AppsTab),
    ("network", NetworkTab),
    ("tools", ToolsTab),
    ("privacy", PrivacyTab),
    ("conns", ConnsTab),
    ("score", ScoreTab),
]
BATTERY_REFRESH = 30
SHUTDOWN_TIMEOUT = 15
MB = 1024 * 1024
MAX_CAPTURE_MB = 1024
# upper bounds for the file and per-packet overhead: the device path writes pcapng (block
# headers, padding, sometimes a synthetic link header), the demo writes classic pcap
PCAP_HEADER, PCAP_RECORD = 256, 48
ALERT_CHECK = 1.0
MAX_ALERTS = 200
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

    def __init__(
        self,
        backend: Backend,
        out_dir: Path,
        max_capture: int = MAX_CAPTURE_MB * MB,
        keep_sessions: int = sessions.KEEP,
    ) -> None:
        super().__init__()
        self.backend = backend
        self.out_dir = out_dir
        self.max_capture = max_capture  # bytes on disk, a capture stops past it
        self.keep_sessions = keep_sessions  # 0: never write session history
        self.sessions: list[sessions.Session] = []  # earlier captures, oldest first
        self.baseline: list[sessions.Session] = []  # what the running capture is compared with
        self.history: dict[str, set[str]] = {}  # app -> domains in the baseline
        self.versions: dict[str, str] = {}  # process name -> app version
        self.rules = alerts.AlertRules()
        self.alerts: deque[tuple[float, str, str, str]] = deque(maxlen=MAX_ALERTS)
        self.info: DeviceInfo | None = None
        self.battery: Battery | None = None
        self.dev_mode: bool | None = None
        self.tunnel = "off"
        self.problem: BackendError | None = None
        self.capturing = False
        self.last_capture: Path | None = None
        self.pending: list[Packet] = []  # captured, not yet shown in the packet table
        self.aggregator = HostAggregator()
        self.flows = FlowTable(self.aggregator)  # reads the names the aggregator learns
        self._capture_worker: Worker[None] | None = None

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
        self.set_interval(ALERT_CHECK, self.check_alerts)
        self.sessions = sessions.load(self.out_dir / "sessions")
        self.rules, problem = alerts.load(self.out_dir)
        if problem:
            self.notify(problem, title="alerts", severity="warning", timeout=10, markup=False)

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
        self.notify(str(error), title="error", severity="error", timeout=6, markup=False)

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
                self.info,
                self.battery,
                self.dev_mode,
                self.backend.active_condition,
                self.tunnel,
                self.capturing,
            )
        )

    def toggle_capture(self) -> None:
        """Start or stop the one capture that feeds the packet table and the privacy tab."""
        if self._capture_worker is not None and self.capturing:
            self._capture_worker.cancel()
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
        self.last_capture = self.out_dir / "captures" / f"capture-{stamp}.pcap"
        self.capturing = True
        self.pending = []
        self.aggregator.reset()
        self.flows.reset()
        self.alerts.clear()
        self.baseline = sessions.baseline(self.sessions, self.info.udid if self.info else None)
        self.history = sessions.domains_by_app(self.baseline)
        self.run_task(self._load_versions(), group="versions")
        self.query_one(NetworkTab).reset()
        self.update_status()
        self._capture_worker = self.run_task(self._capture(self.last_capture), group="capture")

    async def _capture(self, path: Path) -> None:
        size = PCAP_HEADER
        try:
            async with aclosing(self.backend.capture(path)) as packets:
                async for packet in packets:
                    self.pending.append(packet)
                    self.aggregator.feed(packet)
                    self.flows.feed(packet)
                    size += PCAP_RECORD + packet.length
                    if size > self.max_capture:
                        self.notify(
                            f"capture stopped: file reached the {self.max_capture // MB} MB limit"
                            " (--max-capture-mb)",
                            severity="warning",
                            timeout=10,
                        )
                        break
        except BackendError as e:
            self.report(e)
        finally:
            self.capturing = False
            self.update_status()
            self.query_one(NetworkTab).flush()
            self.check_alerts()
            self._save_session()
            self.query_one(PrivacyTab).refresh_view(force=True)
            self.query_one(ConnsTab).refresh_view(force=True)
            self.query_one(ScoreTab).refresh_view(force=True)

    async def _load_versions(self) -> None:
        """App versions for the session history; without them updates just go unnoticed."""
        with suppress(BackendError):
            self.versions = sessions.versions_by_process(await self.backend.apps())

    def _save_session(self) -> None:
        rows = self.aggregator.rows()
        if not self.keep_sessions or not any(r.source != "ip" for r in rows):
            return
        udid = self.info.udid if self.info else ""
        data = sessions.snapshot(rows, self.versions, udid, datetime.now())
        try:
            sessions.save(self.out_dir / "sessions", data, self.keep_sessions)
        except OSError as e:
            self.notify(f"cannot save session history: {e}", severity="error", markup=False)
            return
        if (session := sessions.parse(json.dumps(data))) is not None:
            self.sessions = [*self.sessions, session][-self.keep_sessions :]

    def check_alerts(self) -> None:
        """New (app, domain) rows against the alert rules; one toast per check, not per row."""
        hits: list[tuple[HostRow, str]] = []
        while self.aggregator.added:
            row = self.aggregator.added.popleft()
            if reason := self.rules.reason(row, self.history.get(row.process)):
                hits.append((row, reason))
                self.alerts.append((row.first, row.process, row.domain, reason))
        if not hits:
            return
        lines = [f"{row.process} -> {row.domain} ({reason})" for row, reason in hits[:3]]
        if len(hits) > 3:
            lines.append(f"+{len(hits) - 3} more in the score tab")
        self.notify("\n".join(lines), title="alert", severity="warning", timeout=8, markup=False)

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
            self.notify(message, severity="error", markup=False)
            return
        pid = await self.backend.launch(bundle_id)
        self.notify(f"launched {bundle_id} (pid {pid})", markup=False)

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        event.pane.query_one(TabBody).activate()

    def action_tab(self, number: int) -> None:
        self.query_one(TabbedContent).active = TABS[number - 1][0]

    def action_help(self) -> None:
        self.push_screen(Help())

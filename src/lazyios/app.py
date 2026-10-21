from __future__ import annotations

import asyncio
import json
import os
import time
from collections import deque
from collections.abc import Callable, Coroutine, Iterable
from contextlib import aclosing, suppress
from datetime import datetime
from pathlib import Path
from typing import Any

from textual.app import App, ComposeResult, SystemCommand
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Footer, Static, TabbedContent, TabPane
from textual.worker import Worker

from . import alerts, anomaly, keys, sessions
from .anonymize import Anonymizer
from .backend import (
    Backend,
    BackendError,
    Battery,
    DeviceInfo,
    DevModeOffError,
    Packet,
    Process,
)
from .diagnostics import log
from .files import Scrub, prune
from .flows import FlowTable
from .parsing import clean_text
from .privacy import KERNEL_PID, HostAggregator, TrackerDB
from .screens import DevicePicker, Help
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
from .tabs.timeline import TimelineTab
from .tabs.tools import ToolsTab
from .theme import UNDERGROUND
from .timeline import Timeline, process_events

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
    ("timeline", TimelineTab),
]
BATTERY_REFRESH = 30
SHUTDOWN_TIMEOUT = 15
MB = 1024 * 1024
MAX_CAPTURE_MB = 1024
# Darwin interface name prefixes, for the timeline
INTERFACES = {
    "en": "Wi-Fi or Ethernet", "pdp_ip": "cellular", "utun": "tunnel (VPN, Private Relay, system)",
    "ipsec": "VPN", "awdl": "Apple Wireless Direct Link", "llw": "low latency Wi-Fi",
    "lo": "loopback", "bridge": "bridge", "ap": "personal hotspot",
}  # fmt: skip
# upper bounds for the file and per-packet overhead: the device path writes pcapng (block
# headers, padding, sometimes a synthetic link header), the demo writes classic pcap
PCAP_HEADER, PCAP_RECORD = 256, 48
ALERT_CHECK = 1.0
PROCESS_POLL = 5.0  # seconds between process lists while the timeline watches them
MAX_ALERTS = 200
DEVICE_POLL = 5.0  # seconds between looks at which devices are plugged in
WORKER_STOP = 5.0
DEV_OFF = "developer mode is off: enable it in settings > privacy & security"


def explain(what: str, e: Exception) -> str:
    """A short message for an unexpected error; the full one is in the diagnostic log."""
    if isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        return f"{what} timed out: is the device unlocked and still plugged in?"
    if isinstance(e, PermissionError):
        return f"{what}: permission denied writing {e.filename or 'a file'}"
    if isinstance(e, OSError):
        return f"{what}: {e.strerror or type(e).__name__}"
    return f"{what} failed ({type(e).__name__}), details in lazyios.log"


def device_folder(udid: str) -> str:
    """Folder name for one device's files: its UDID, reduced to letters, digits and dashes."""
    safe = "".join(c for c in udid if c.isascii() and (c.isalnum() or c == "-"))[:64]
    return safe or "unknown-device"


class LazyiosApp(App[None]):
    CSS_PATH = "app.tcss"
    ENABLE_COMMAND_PALETTE = True  # ctrl+p
    TITLE = "lazyios"
    BINDINGS = [
        Binding("q", "quit", "quit", id="quit"),
        Binding("ctrl+c", "quit", "quit", show=False, priority=True),
        Binding("question_mark", "help", "help", id="help"),
        Binding("d", "devices", "devices", id="devices"),
        *(
            Binding(str(n % 10), f"tab({n})", name, show=False)
            for n, (name, _) in enumerate(TABS, 1)
        ),
    ]

    def __init__(
        self,
        backend: Backend,
        out_dir: Path,
        max_capture: int = MAX_CAPTURE_MB * MB,
        keep_sessions: int = sessions.KEEP,
        make_backend: Callable[[str], Backend] | None = None,
        keep_files: int = 0,
        anonymize: frozenset[str] = frozenset(),
    ) -> None:
        super().__init__()
        self.keep_files = keep_files  # per device and kind; 0 keeps everything
        self.anonymize = anonymize  # kinds of values pseudonymized in exports
        self._anon_key = os.urandom(32)  # one key per run: pseudonyms match across its reports
        self.backend = backend
        self.make_backend = make_backend  # a backend for another device, to switch to it
        self.known_devices: set[str] | None = None  # UDIDs usbmuxd listed last time
        self.last_udid: str | None = None  # the device this app last talked to
        self.out_dir = out_dir
        self.max_capture = max_capture  # bytes on disk, a capture stops past it
        self.keep_sessions = keep_sessions  # 0: never write session history
        self.sessions: list[sessions.Session] = []  # earlier captures, oldest first
        self.baseline: list[sessions.Session] = []  # what the running capture is compared with
        self.history: dict[str, set[str]] = {}  # app -> domains in the baseline
        self.versions: dict[str, str] = {}  # process name -> app version
        self.rules = alerts.AlertRules()
        self.alerts: deque[tuple[float, str, str, str]] = deque(maxlen=MAX_ALERTS)
        self.timeline = Timeline()
        self.thresholds = anomaly.Thresholds()
        self.detector = anomaly.Detector(self.thresholds)
        self.watching_processes = False
        self._interfaces: set[str] = set()
        self._process_worker: Worker[None] | None = None
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
                with TabPane(f"{n % 10} {name}", id=name):
                    yield tab(id=f"{name}-tab")
        yield Footer(show_command_palette=False)

    def on_mount(self) -> None:
        self.register_theme(UNDERGROUND)
        self.theme = UNDERGROUND.name
        self.backend.on_reset = self._on_reset
        self.update_status()
        self.run_task(self.refresh_device(), group="refresh")
        self.set_interval(BATTERY_REFRESH, self.tick)
        self.set_interval(ALERT_CHECK, self.check_new_rows)
        self.set_interval(DEVICE_POLL, self.poll_devices)
        self.rules, problem = alerts.load(self.out_dir)
        self.thresholds, trouble = anomaly.load(self.out_dir)
        keymap, bad_keys = keys.load(self.out_dir)
        if keymap:
            self.set_keymap(keymap)
        for title, text in (("alerts", problem), ("anomaly", trouble), ("keys", bad_keys)):
            if text:
                self.notify(text, title=title, severity="warning", timeout=10, markup=False)

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
            log.exception("%s failed", group)  # the traceback goes to the diagnostic log
            self.report(BackendError(explain(group.split("-")[0], e)))

    def report(self, error: Exception) -> None:
        self.timeline.add("error", str(error))
        self.notify(str(error), title="error", severity="error", timeout=6, markup=False)

    def tick(self) -> None:
        self.run_task(self.refresh_device(battery_only=self.info is not None), group="refresh")

    async def refresh_device(self, *, verbose: bool = False, battery_only: bool = False) -> None:
        had = self.info
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
            if had is not None:
                self.timeline.add("device", f"lost: {e}", app=had.product_type)
        if self.info is not None and self.info.udid != self.last_udid:
            self.last_udid = self.info.udid
            self.sessions = sessions.load(self.device_dir / "sessions")
        if had is None and self.info is not None:
            i = self.info
            self.timeline.add("device", f"connected: ios {i.version} ({i.build})",
                              app=i.product_type, detail=f"{i.name}")  # fmt: skip
        self.update_status()
        self.query_one(OverviewTab).render_view()

    @property
    def device_dir(self) -> Path:
        """Where this device's captures, screenshots, reports and sessions go."""
        return self.out_dir / device_folder(self.info.udid if self.info else self.last_udid or "")

    @property
    def scrub(self) -> Scrub | None:
        """The anonymizer for exports, or None when --anonymize was not given."""
        if not self.anonymize:
            return None
        info = self.info
        identifiers = [str(Path.home()), Path.home().name]
        if info is not None:
            identifiers += [info.name, info.serial, info.wifi_mac, info.udid]
        trackers = TrackerDB()
        return Anonymizer(
            self.anonymize, lambda d: trackers.lookup(d) is not None, identifiers, self._anon_key
        ).scrub

    def saved(self, folder: Path, prefix: str) -> None:
        """A file of this kind was just written: apply --keep-files."""
        with suppress(OSError):
            prune(folder, prefix, self.keep_files)

    def activity(self) -> tuple[str, ...]:
        running = []
        if self.query_one(ProcessesTab).monitoring:
            running.append("monitor")
        if self.watching_processes:
            running.append("watching processes")
        if self.query_one(ToolsTab).fps_running:
            running.append("fps")
        return tuple(running)

    def update_status(self) -> None:
        self.query_one("#status", Static).update(
            status_line(
                self.info,
                self.battery,
                self.dev_mode,
                self.backend.active_condition,
                self.tunnel,
                self.capturing,
                self.activity(),
            )
        )

    def toggle_capture(self) -> None:
        """Start or stop the one capture that feeds the packet table and the privacy tab."""
        if self._capture_worker is not None and self.capturing:
            self._capture_worker.cancel()
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
        self.last_capture = self.device_dir / "captures" / f"capture-{stamp}.pcap"
        self.capturing = True
        self.pending = []
        self.aggregator.reset()
        self.flows.reset()
        self.alerts.clear()
        self.baseline = sessions.baseline(self.sessions, self.info.udid if self.info else None)
        self.history = sessions.domains_by_app(self.baseline)
        self.run_task(self._load_versions(), group="versions")
        self.detector = anomaly.Detector(self.thresholds, self.history)
        self._interfaces.clear()
        self.timeline.add("capture", "started", detail=str(self.last_capture), source="capture")
        self.query_one(NetworkTab).reset()
        self.update_status()
        self._capture_worker = self.run_task(self._capture(self.last_capture), group="capture")

    async def _capture(self, path: Path) -> None:
        size, count = PCAP_HEADER, 0
        try:
            async with aclosing(self.backend.capture(path)) as packets:
                async for packet in packets:
                    count += 1
                    self.pending.append(packet)
                    self.aggregator.feed(packet)
                    if flow := self.flows.feed(packet):
                        self.detector.connection(flow)
                    name = "-" if packet.pid == KERNEL_PID else clean_text(packet.process)
                    self.detector.packet(name, packet.length, packet.time)
                    if packet.interface not in self._interfaces:
                        self._interface_seen(packet.interface, packet.time)
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
            self.detector.session_end(self.aggregator.rows(), self.baseline)
            self.check_new_rows()
            self.timeline.add("capture", f"stopped after {count} packets", source="capture")
            self.saved(path.parent, "capture")
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
            sessions.save(self.device_dir / "sessions", data, self.keep_sessions)
        except OSError as e:
            self.notify(f"cannot save session history: {e}", severity="error", markup=False)
            return
        if (session := sessions.parse(json.dumps(data))) is not None:
            self.sessions = [*self.sessions, session][-self.keep_sessions :]

    def _interface_seen(self, name: str, when: float) -> None:
        self._interfaces.add(name)
        kind = next((v for k, v in INTERFACES.items() if name.startswith(k)), "other")
        self.timeline.add("network", f"traffic on {clean_text(name)}", when=when, detail=kind,
                          source="capture")  # fmt: skip

    def check_new_rows(self) -> None:
        """New (app, domain) rows and anomaly findings since the last check go to the timeline,
        the alert rules and the detector; one toast per check, not one per hit."""
        lines: list[str] = []
        while self.aggregator.added:
            row = self.aggregator.added.popleft()
            name = row.domain if row.source != "ip" else f"{row.domain} (no name yet)"
            self.timeline.add("connection", f"first contact: {name}", when=row.first,
                              app=row.process, detail=f"name via {row.source}",
                              source="capture")  # fmt: skip
            self.detector.domain(row)
            if reason := self.rules.reason(row, self.history.get(row.process)):
                self.alerts.append((row.first, row.process, row.domain, reason))
                self.timeline.add("alert", f"{row.domain}: {reason}", when=row.first,
                                  app=row.process, source="alerts")  # fmt: skip
                lines.append(f"{row.process} -> {row.domain} ({reason})")
        while self.detector.findings:
            f = self.detector.findings.popleft()
            self.timeline.add("anomaly", f"{f.rule}: {f.summary}", when=f.time, app=f.app,
                              detail=f.detail, source="anomaly")  # fmt: skip
            lines.append(f"{f.app}: {f.rule}, {f.summary}")
        if not lines:
            return
        shown = lines[:3] + ([f"+{len(lines) - 3} more in the timeline"] if len(lines) > 3 else [])
        self.notify("\n".join(shown), title="alert", severity="warning", timeout=8, markup=False)

    def toggle_process_watch(self) -> None:
        """Poll the process list and put starts and exits on the timeline (developer mode)."""
        if self._process_worker is not None and self.watching_processes:
            self._process_worker.cancel()
            return
        self._process_worker = self.run_task(self._watch_processes(), group="processes-watch")

    async def _watch_processes(self) -> None:
        if message := await self.open_dvt():
            self.notify(message, severity="error", markup=False)
            return
        self.watching_processes = True
        self.update_status()
        self.timeline.add("process", "watch started", source="dvt")
        before: dict[int, Process] | None = None
        try:
            while True:
                now = {p.pid: p for p in await self.backend.processes()}
                if before is not None:
                    for kind, summary, name, detail in process_events(
                        before, now, time.time(), PROCESS_POLL
                    ):
                        self.timeline.add(kind, summary, app=name, detail=detail, source="dvt")
                before = now
                await asyncio.sleep(PROCESS_POLL)
        finally:
            self.watching_processes = False
            self.update_status()
            self.timeline.add("process", "watch stopped", source="dvt")

    def poll_devices(self) -> None:
        self.run_task(self._poll_devices(), group="devices")

    async def _poll_devices(self) -> None:
        """Note plugs and unplugs; when this app's device comes back, reconnect right away."""
        try:
            found = set(await self.backend.device_ids())
        except BackendError:
            return  # refresh_device explains usbmuxd problems
        before, self.known_devices = self.known_devices, found
        if before is None:
            return
        current = self.info.udid if self.info else self.last_udid
        for udid in sorted(found - before):
            self.timeline.add("device", f"plugged in: {udid}")
            if udid != current:
                self.notify(f"device plugged in: {udid}  (d to switch)", markup=False)
        for udid in sorted(before - found):
            self.timeline.add("device", f"unplugged: {udid}")
        if self.info is None and current in found - before:
            await self.refresh_device()

    def action_devices(self) -> None:
        self.run_task(self._pick_device(), group="devices-pick")

    async def _pick_device(self) -> None:
        found = await self.backend.devices()
        current = self.info.udid if self.info else None

        def chosen(udid: str | None) -> None:
            if udid and udid != current:
                self.run_task(self.switch_device(udid), group="switch")

        self.push_screen(DevicePicker(found, current), chosen)

    async def switch_device(self, udid: str) -> None:
        """Close this device (undoing conditions and location, saving its session) and start a
        clean session on another one. Nothing from one device's session carries over."""
        if self.make_backend is None:
            self.notify("switching devices is not available here", severity="warning")
            return
        others = [w for w in self.workers if w.group != "switch"]
        for worker in others:
            worker.cancel()
        for worker in others:
            with suppress(Exception):
                await asyncio.wait_for(worker.wait(), WORKER_STOP)
        with suppress(Exception):
            await asyncio.wait_for(self.backend.close(), SHUTDOWN_TIMEOUT)
        self.backend = self.make_backend(udid)
        self.backend.on_reset = self._on_reset
        self.info = self.battery = self.dev_mode = self.problem = None
        self.tunnel, self.capturing, self.watching_processes = "off", False, False
        self.last_capture, self.pending, self.known_devices = None, [], None
        self.aggregator.reset()
        self.flows.reset()
        self.alerts.clear()
        self.sessions, self.baseline, self.history, self.versions = [], [], {}, {}
        self.timeline = Timeline()
        for body in self.query(TabBody):
            body.reset_device()
        self.update_status()
        await self.refresh_device(verbose=True)
        self.timeline.add("device", f"switched to {udid}")
        if (pane := self.query_one(TabbedContent).active_pane) is not None:
            for body in pane.query(TabBody):
                body.activate()

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
        for body in event.pane.query(TabBody):  # none while the app is shutting down
            body.activate()

    def action_tab(self, number: int) -> None:
        self.query_one(TabbedContent).active = TABS[number - 1][0]

    def action_help(self) -> None:
        self.push_screen(Help(self.query_one(TabbedContent).active))

    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        """What ctrl+p offers: every tab and the main actions, by name."""
        for n, (name, _) in enumerate(TABS, 1):
            yield SystemCommand(f"go to {name}", f"tab {n % 10}", lambda n=n: self.action_tab(n))
        tab_actions = (
            ("start or stop the capture", "network", "toggle_capture"),
            ("export the privacy report", "privacy", "export"),
            ("export the connections", "conns", "export"),
            ("export the privacy scores", "score", "export"),
            ("export the timeline", "timeline", "export"),
            ("watch process starts and exits", "timeline", "toggle_processes"),
            ("live cpu and memory", "processes", "toggle_monitor"),
            ("security audit", "overview", "audit"),
            ("take a screenshot", "tools", "screenshot"),
            ("clear the network condition", "network", "clear_condition"),
            ("clear the simulated location", "tools", "clear_location"),
            ("reconnect the syslog", "logs", "reconnect"),
            ("how the privacy score works", "score", "criteria"),
        )
        for title, tab, action in tab_actions:
            yield SystemCommand(title, f"in {tab}", lambda t=tab, a=action: self._tab_action(t, a))
        yield SystemCommand("devices", "list them, switch to another", self.action_devices)
        yield SystemCommand("help", "keys of every tab", self.action_help)
        yield SystemCommand("quit", "clears condition and location first", self.exit)

    def _tab_action(self, tab: str, action: str) -> None:
        self.query_one(TabbedContent).active = tab
        body = self.query_one(f"#{tab}-tab", TabBody)
        self.call_later(getattr(body, f"action_{action}"))

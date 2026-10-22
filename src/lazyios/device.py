"""Real backend over pymobiledevice3."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

from pymobiledevice3 import usbmux as mux
from pymobiledevice3.exceptions import (
    ConnectionFailedToUsbmuxdError,
    ConnectionTerminatedError,
    NoDeviceConnectedError,
    NotPairedError,
    PairingError,
    PyMobileDevice3Exception,
)
from pymobiledevice3.exceptions import NotTrustedError as LibNotTrustedError
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.remote.userspace_tunnel import UserspaceRsdTunnel
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.dvt.instruments.condition_inducer import ConditionInducer
from pymobiledevice3.services.dvt.instruments.device_info import DeviceInfo as DvtDeviceInfo
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.graphics import Graphics
from pymobiledevice3.services.dvt.instruments.location_simulation import LocationSimulation
from pymobiledevice3.services.dvt.instruments.network_statistics import NetworkStatistics
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.dvt.instruments.sysmontap import Sysmontap
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.mobile_config import MobileConfigService
from pymobiledevice3.services.pcapd import DevicePacket, PcapdService
from pymobiledevice3.services.syslog import SyslogService

from . import usbmuxd
from .backend import (
    App,
    AuditFacts,
    BackendError,
    Battery,
    Condition,
    DeviceInfo,
    DeviceSummary,
    DevModeOffError,
    NoDeviceError,
    NotTrustedError,
    Packet,
    Process,
    ProcSample,
    SysSample,
    UsbmuxdError,
    undo_all,
)
from .files import create_private
from .parsing import clean_text, link_offset, parse_ip_packet

LAUNCH_TIMEOUT = 15
PAYLOAD_MAX = 2048  # enough for a DNS answer or the start of a TLS ClientHello
SYSMON_MS = 1000
NET_TIMEOUT = 2.0  # one NetworkStatistics call; about 80 ms for 450 processes
NET_FAILS = 3  # consecutive failed ticks before network stats are given up
NET_MAX_GAP = 10.0  # seconds between two records of a pid that still give a rate
NET_TUNNEL = frozenset({"remotepairingdeviced", "lockdownd", "DTServiceHub"})  # our own link

log = logging.getLogger(__name__)


@asynccontextmanager
async def _guard(what: str):
    """Turn library and socket errors into BackendError with a short message."""
    try:
        yield
    except BackendError:
        raise
    except NoDeviceConnectedError as e:
        raise NoDeviceError("no device connected") from e
    except ConnectionFailedToUsbmuxdError as e:
        raise UsbmuxdError(f"usbmuxd not reachable: {usbmuxd.hint()}") from e
    except (NotPairedError, LibNotTrustedError, PairingError) as e:
        raise NotTrustedError("not trusted: unlock the iphone and tap Trust") from e
    except (PyMobileDevice3Exception, OSError, EOFError, ValueError, KeyError) as e:
        raise BackendError(f"{what}: {e or type(e).__name__}") from e


def _text(line: str | bytes) -> str:
    return line if isinstance(line, str) else line.decode("utf-8", "replace")


def _packet(p: DevicePacket) -> Packet:
    info = parse_ip_packet(p.data[link_offset(p.frame_pre_length, p.interface_name) :])
    return Packet(
        time=p.seconds + p.microseconds / 1e6 if p.seconds else time.time(),
        pid=p.pid,
        process=p.comm,
        interface=p.interface_name,
        proto=info.proto if info else "other",
        src=info.src if info else "-",
        dst=info.dst if info else "-",
        length=len(p.data),
        payload=info.payload[:PAYLOAD_MAX] if info and info.proto in ("tcp", "udp") else b"",
    )


class DeviceBackend:
    def __init__(self, udid: str | None = None) -> None:
        self.udid = udid
        self.closed = False
        self.on_reset: Callable[[], None] | None = None
        self._ld: LockdownClient | None = None
        self._ld_lock = asyncio.Lock()
        self._lock = asyncio.Lock()  # serialises DVT session open/reset/set/clear
        self._tunnel: UserspaceRsdTunnel | None = None
        self._dvt: DvtProvider | None = None
        self._info_svc: DvtDeviceInfo | None = None
        self._cond_svc: ConditionInducer | None = None
        self._loc_svc: LocationSimulation | None = None
        # device-side state, kept apart from the handles so a lost handle never hides it
        self._cond_dirty = self._loc_dirty = False
        self._cond_gen = self._loc_gen = 0
        self._active: Condition | None = None
        self._seen_udid: str | None = None

    @property
    def tunnel_open(self) -> bool:
        return self._dvt is not None

    @property
    def active_condition(self) -> Condition | None:
        return self._active

    async def _new_lockdown(self) -> LockdownClient:
        return await create_using_usbmux(serial=self.udid)

    async def _lockdown(self) -> LockdownClient:
        async with self._ld_lock:
            if self._ld is None:
                self._ld = await self._new_lockdown()
            return self._ld

    async def _drop_lockdown(self) -> None:
        async with self._ld_lock:
            ld, self._ld = self._ld, None
        if ld is not None:
            with suppress(Exception):
                await ld.close()

    async def device_info(self) -> DeviceInfo:
        try:
            info = await self._device_info_usbmuxd()
        except NoDeviceError:
            if self._dvt is not None:  # unplugged: its DVT session is dead, do not reuse it
                await self._reset_tunnel()
            raise
        if self._seen_udid not in (None, info.udid) and self._dvt is not None:
            await self._reset_tunnel()  # another device took its place
        self._seen_udid = info.udid
        return info

    async def _device_info_usbmuxd(self) -> DeviceInfo:
        try:
            return await self._device_info()
        except UsbmuxdError:
            if (note := await asyncio.to_thread(usbmuxd.start_apple_devices)) is not None:
                raise UsbmuxdError(f"usbmuxd not reachable: {note}") from None
            return await self._device_info()

    async def _device_info(self) -> DeviceInfo:
        async with _guard("device info"):
            for attempt in (0, 1):
                try:
                    v: dict[str, Any] = await (await self._lockdown()).get_value()
                    break
                except Exception:
                    await self._drop_lockdown()  # stale connection: retry once on a fresh one
                    if attempt:
                        raise
            return DeviceInfo(
                name=v.get("DeviceName", ""),
                product_type=v.get("ProductType", ""),
                version=v.get("ProductVersion", ""),
                build=v.get("BuildVersion", ""),
                serial=v.get("SerialNumber", ""),
                wifi_mac=v.get("WiFiAddress", ""),
                udid=v.get("UniqueDeviceID", ""),
            )

    async def battery(self) -> Battery:
        async with _guard("battery"):
            ld = await self._lockdown()
            async with DiagnosticsService(ld) as diag:
                data = await diag.get_battery() or {}
            adapter = data.get("AdapterDetails") or {}
            details = data.get("BatteryData") or {}
            return Battery(
                percent=int(data.get("CurrentCapacity", 0)),
                cycles=int(data.get("CycleCount", 0)),
                charging=bool(data.get("IsCharging")),
                watts=adapter.get("Watts"),
                adapter=str(adapter.get("Description", "")),
                voltage_mv=_number(data.get("Voltage")),
                current_ma=_number(data.get("InstantAmperage", data.get("Amperage"))),
                design_mah=_number(details.get("DesignCapacity")),
                full_mah=_number(details.get("FullChargeCapacity")),
            )

    async def developer_mode(self) -> bool:
        async with _guard("developer mode"):
            return await (await self._lockdown()).get_developer_mode_status()

    async def syslog(self) -> AsyncIterator[str]:
        async with _guard("syslog"):
            ld = await self._new_lockdown()
            try:
                async with SyslogService(service_provider=ld) as service:
                    async for line in service.watch():
                        yield _text(line)
            finally:
                with suppress(Exception):
                    await ld.close()

    async def _open_locked(self) -> DvtProvider:
        if self._dvt is not None:
            return self._dvt
        if not await self.developer_mode():
            raise DevModeOffError("developer mode is off")
        tunnel = UserspaceRsdTunnel(serial=self.udid)
        try:
            dvt = DvtProvider(await tunnel.aopen())
            await dvt.connect()
        except BaseException:
            await tunnel.aclose()
            raise
        self._tunnel, self._dvt = tunnel, dvt
        return dvt

    async def open_tunnel(self) -> None:
        async with _guard("tunnel"), self._lock:
            await self._open_locked()

    @asynccontextmanager
    async def _dvt_guard(self, what: str):
        try:
            async with _guard(what):
                yield
        except BackendError as e:
            if isinstance(e.__cause__, (ConnectionTerminatedError, OSError, EOFError)):
                await self._reset_tunnel()
            raise

    async def _provider(self) -> DvtProvider:
        async with self._lock:
            return await self._open_locked()

    async def _reset_tunnel(self) -> None:
        async with self._lock:
            await self._reset_locked()

    async def _reset_locked(self) -> None:
        """Drop the DVT session; the dirty flags stay, so close() still clears the device."""
        dvt, tunnel = self._dvt, self._tunnel
        svcs = (self._cond_svc, self._loc_svc, self._info_svc)
        self._dvt = self._tunnel = self._cond_svc = self._loc_svc = self._info_svc = None
        self._active = None
        for svc in svcs:
            if svc is not None:
                with suppress(Exception):
                    await svc.close()
        if dvt is not None:
            with suppress(Exception):
                await dvt.close()
        if tunnel is not None:
            with suppress(Exception):
                await tunnel.aclose()
        if self.on_reset is not None:
            self.on_reset()

    async def _info_locked(self) -> DvtDeviceInfo:
        dvt = await self._open_locked()
        if self._info_svc is None:
            svc = DvtDeviceInfo(dvt)
            await svc.connect()
            self._info_svc = svc
        return self._info_svc

    async def processes(self) -> list[Process]:
        async with self._dvt_guard("process list"):
            async with self._lock:
                info = await self._info_locked()
            raw = await info.proclist()
            return [
                Process(
                    pid=p["pid"],
                    name=p.get("name", ""),
                    is_app=bool(p.get("isApplication")),
                    started=_stamp(p.get("startDate")),
                )
                for p in raw
            ]

    async def kill(self, pid: int) -> None:
        async with self._dvt_guard("kill"), ProcessControl(await self._provider()) as control:
            await control.kill(pid)

    async def launch(self, bundle_id: str) -> int:
        async with self._dvt_guard("launch"), ProcessControl(await self._provider()) as control:
            try:
                return await asyncio.wait_for(control.launch(bundle_id=bundle_id), LAUNCH_TIMEOUT)
            except asyncio.TimeoutError:  # not the builtin TimeoutError before 3.11
                raise BackendError("launch timed out: is the device unlocked?") from None

    async def apps(self) -> list[App]:
        async with _guard("app list"):
            ld = await self._lockdown()
            async with InstallationProxyService(lockdown=ld) as proxy:
                raw = await proxy.get_apps(application_type="User")
            apps = [
                App(
                    name=a.get("CFBundleDisplayName") or a.get("CFBundleName") or bid,
                    bundle_id=bid,
                    version=str(a.get("CFBundleShortVersionString", "")),
                    executable=str(a.get("CFBundleExecutable", "")),
                )
                for bid, a in raw.items()
                if bid
            ]
            return sorted(apps, key=lambda a: a.name.lower())

    async def capture(self, path: Path) -> AsyncIterator[Packet]:
        async with _guard("capture"):
            ld = await self._new_lockdown()
            try:
                service = PcapdService(lockdown=ld)
                queue: asyncio.Queue[DevicePacket | None] = asyncio.Queue()

                async def tee() -> AsyncIterator[DevicePacket]:
                    async for p in service.watch():
                        queue.put_nowait(p)
                        yield p

                try:
                    with create_private(path) as out:
                        writer = asyncio.create_task(service.write_to_pcap(out, tee()))
                        writer.add_done_callback(lambda _: queue.put_nowait(None))
                        try:
                            while (p := await queue.get()) is not None:
                                yield _packet(p)
                            writer.result()
                            raise BackendError("capture ended by device")
                        finally:
                            writer.cancel()
                            with suppress(asyncio.CancelledError, Exception):
                                await writer
                            out.flush()
                finally:
                    with suppress(Exception):
                        await service.close()
            finally:
                with suppress(Exception):
                    await ld.close()

    async def conditions(self) -> list[Condition]:
        async with self._dvt_guard("conditions"):
            async with ConditionInducer(await self._provider()) as inducer:
                groups = await inducer.list()
            return [
                Condition(
                    group_id=g.get("identifier", ""),
                    group=g.get("name") or g.get("identifier", ""),
                    profile_id=p.get("identifier", ""),
                    name=p.get("name", ""),
                    description=p.get("description", ""),
                )
                for g in groups
                for p in g.get("profiles", [])
            ]

    async def set_condition(self, condition: Condition) -> None:
        async with self._dvt_guard("condition"), self._lock:
            dvt = await self._open_locked()
            if self._cond_svc is None:
                svc = ConditionInducer(dvt)
                await svc.connect()
                self._cond_svc = svc
            self._cond_dirty = True
            self._cond_gen += 1
            await self._cond_svc.set(condition.profile_id)
            self._active = condition

    async def clear_condition(self) -> None:
        await asyncio.shield(self._clear_condition())  # a second keypress must not abort it

    async def _clear_condition(self) -> None:
        if not self._cond_dirty:
            self._active = None
            return
        async with self._dvt_guard("clear condition"):
            gen = self._cond_gen
            async with self._lock:
                info = await self._info_locked()
                svc = self._cond_svc
                if svc is None:  # handle lost in a reset
                    svc = ConditionInducer(self._dvt)
                    await svc.connect()
                    self._cond_svc = svc
            await svc.clear()
            await info.is_running_pid(0)  # round trip: the clear is fire-and-forget
            if gen == self._cond_gen:
                self._cond_dirty = False
                self._active = None
                if self._cond_svc is svc:
                    self._cond_svc = None
                with suppress(Exception):
                    await svc.close()

    async def screenshot(self) -> bytes:
        async with self._dvt_guard("screenshot"), Screenshot(await self._provider()) as shot:
            return await shot.get_screenshot()

    async def set_location(self, lat: float, lon: float) -> None:
        async with self._dvt_guard("location"), self._lock:
            dvt = await self._open_locked()
            if self._loc_svc is None:
                svc = LocationSimulation(dvt)
                await svc.connect()
                self._loc_svc = svc
            self._loc_dirty = True
            self._loc_gen += 1
            await self._loc_svc.set(lat, lon)

    async def clear_location(self) -> None:
        await asyncio.shield(self._clear_location())

    async def _clear_location(self) -> None:
        if not self._loc_dirty:
            return
        async with self._dvt_guard("clear location"):
            gen = self._loc_gen
            async with self._lock:
                info = await self._info_locked()
                svc = self._loc_svc
                if svc is None:
                    svc = LocationSimulation(self._dvt)
                    await svc.connect()
                    self._loc_svc = svc
            await svc.clear()
            await info.is_running_pid(0)
            if gen == self._loc_gen:
                self._loc_dirty = False
                if self._loc_svc is svc:
                    self._loc_svc = None
                with suppress(Exception):
                    await svc.close()

    async def fps(self) -> AsyncIterator[int]:
        async with self._dvt_guard("fps"), Graphics(await self._provider()) as graphics:
            async for value in graphics.fps():
                yield value

    async def sysmon(self) -> AsyncIterator[SysSample]:
        """CPU and memory, system-wide and per process, about once a second (developer mode)."""
        async with self._dvt_guard("monitor"):
            tap = await Sysmontap.create(await self._provider(), interval=SYSMON_MS)
            fields = list(tap.process_attributes_cls.__dataclass_fields__)
            system_fields = list(tap.system_attributes_cls.__dataclass_fields__)
            at = [fields.index(f) for f in ("pid", "name", "cpuUsage", "physFootprint")]
            cores, cpu, memory = 0, None, None
            async with tap, _NetSampler(await self._provider()) as net:
                async for row in tap:
                    if not isinstance(row, dict):
                        continue
                    if isinstance(usage := row.get("SystemCPUUsage"), dict):
                        cores = _number(row.get("CPUCount")) or 0
                        total = _number(usage.get("CPU_TotalLoad"))
                        cpu = min(100.0, total / cores) if cores and total is not None else None
                    if isinstance(values := row.get("System"), list):
                        names = row.get("SystemAttributes") or system_fields
                        named = dict(zip(names, values, strict=False))  # device data: may differ
                        used, size = (
                            _number(named.get("vmUsedCount")),
                            _number(named.get("physMemSize")),
                        )
                        memory = used / size if used is not None and size else None
                    if isinstance(processes := row.get("Processes"), dict):
                        samples = [_proc_sample(info, at) for info in processes.values()]
                        samples = [s for s in samples if s is not None]
                        rates = await net.sample({s.pid: s.name for s in samples})
                        yield SysSample(
                            time.time(), cores, cpu, memory,
                            tuple(replace(s, rx=r[0], tx=r[1]) if (r := rates.get(s.pid)) else s
                                  for s in samples),
                            net.on,
                        )  # fmt: skip

    async def device_ids(self) -> list[str]:
        async with _guard("device list"):
            return [d.serial for d in await mux.list_devices()]

    async def devices(self) -> list[DeviceSummary]:
        """Every device usbmuxd sees. Never pairs: a device without a pairing record on this
        computer is listed as untrusted instead of being asked to trust it."""
        async with _guard("device list"):
            found = await mux.list_devices()
        out = []
        for d in found:
            try:
                ld = await create_using_usbmux(
                    serial=d.serial, autopair=False, connection_type=d.connection_type
                )
            except (PyMobileDevice3Exception, OSError, EOFError):
                out.append(DeviceSummary(d.serial, d.connection_type, trusted=False))
                continue
            try:
                v = await ld.get_value()
            except (PyMobileDevice3Exception, OSError, EOFError):
                v = {}
            finally:
                with suppress(Exception):
                    await ld.close()
            out.append(
                DeviceSummary(
                    d.serial, d.connection_type, clean_text(str(v.get("DeviceName", ""))),
                    clean_text(str(v.get("ProductType", ""))),
                    clean_text(str(v.get("ProductVersion", ""))),
                )
            )  # fmt: skip
        return out

    async def audit_facts(self) -> AuditFacts:
        """Read-only lookups: lockdown values and the configuration profile list."""
        async with _guard("audit"):
            ld = await self._lockdown()
            v = await ld.get_value()
            wireless = await _domain(ld, "com.apple.mobile.wireless_lockdown")
            backup = await _domain(ld, "com.apple.mobile.backup")
            developer = None
            with suppress(PyMobileDevice3Exception, OSError):
                developer = await ld.get_developer_mode_status()
            profiles, supervised = None, None
            with suppress(PyMobileDevice3Exception, OSError, EOFError):
                async with MobileConfigService(ld) as config:  # only the two read requests
                    meta = (await config.get_profile_list()).get("ProfileMetadata") or {}
                    profiles = tuple(
                        (clean_text(str(key)), clean_text(str(m.get("PayloadDisplayName", ""))),
                         clean_text(str(m.get("PayloadOrganization", ""))))
                        for key, m in meta.items()
                        if isinstance(m, dict)
                    )  # fmt: skip
                    cloud = await config.get_cloud_configuration() or {}
                    supervised = _flag(cloud.get("IsSupervised"))
            return AuditFacts(
                version=clean_text(str(v.get("ProductVersion", ""))),
                build=clean_text(str(v.get("BuildVersion", ""))),
                developer_mode=developer,
                passcode=_flag(v.get("PasswordProtected")),
                activation=clean_text(str(v["ActivationState"]))
                if "ActivationState" in v
                else None,
                wifi_debugging=_flag(wireless.get("EnableWifiDebugging")),
                wifi_connections=_flag(wireless.get("EnableWifiConnections")),
                backup_encrypted=_flag(backup.get("WillEncrypt")),
                cloud_backup=_flag(backup.get("CloudBackupEnabled")),
                supervised=supervised,
                profiles=profiles,
            )

    async def close(self) -> None:
        """Undo device-side state first, then drop sessions; every step is best effort."""
        self.closed = True
        await undo_all(self._clear_condition, self._clear_location)
        with suppress(Exception):
            await self._reset_tunnel()
        await self._drop_lockdown()


def _number(value: Any) -> int | float | None:
    """A device-supplied number, or None for anything else (bools included)."""
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else bool(value) if value in (0, 1) else None


def _proc_sample(info: Any, at: list[int]) -> ProcSample | None:
    try:
        pid, name, cpu, memory = (info[i] for i in at)
    except (IndexError, KeyError, TypeError):
        return None
    if not isinstance(pid, int) or isinstance(pid, bool):
        return None
    cpu, memory = _number(cpu), _number(memory)
    return ProcSample(pid, clean_text(str(name or "")), cpu, int(memory) if memory else None)


def _net_counted(pid: int, name: str) -> bool:
    """The kernel and the daemons on our own link show lazyios's USB traffic: no rate for them."""
    return pid != 0 and name not in NET_TUNNEL


class _NetRates:
    """Bytes per second per pid from NetworkStatistics records, from the second one of a pid."""

    def __init__(self) -> None:
        self._seen: dict[int, float] = {}  # pid -> time of its previous record

    def update(self, records: Any, now: float) -> dict[int, tuple[float, float]]:
        seen, self._seen, rates = self._seen, {}, {}  # a pid that went away starts over
        for pid, record in records.items() if isinstance(records, dict) else ():
            if not isinstance(record, dict):
                continue
            stamp = getattr(record.get("time"), "utc", None)  # NSDate -> datetime
            stamp = stamp.timestamp() if isinstance(stamp, datetime) else now
            self._seen[pid] = stamp
            rx = _number(record.get("net.rx.bytes.delta"))
            tx = _number(record.get("net.tx.bytes.delta"))
            dt = stamp - seen.get(pid, stamp)  # 0 for a pid not seen before: its first record
            if 0 < dt <= NET_MAX_GAP and rx is not None and tx is not None:
                rates[pid] = (max(rx, 0) / dt, max(tx, 0) / dt)
        return rates


class _NetSampler:
    """Per-process network rates next to Sysmontap. A failed tick (timeout or bad reply) is
    skipped; NET_FAILS in a row turn it off for the rest of the session. A lost connection is
    not handled here. CPU and memory keep flowing either way."""

    def __init__(self, dvt: DvtProvider) -> None:
        self.on = True
        self._fails = 0
        self._dvt = dvt
        self._service: Any = None
        self._started: set[int] = set()
        self._rates = _NetRates()

    async def __aenter__(self) -> _NetSampler:
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._service is not None and self._started:
            with suppress(Exception):
                await asyncio.wait_for(
                    self._service.stop_sampling_for_pids_(sorted(self._started)), NET_TIMEOUT
                )

    async def sample(self, names: dict[int, str]) -> dict[int, tuple[float, float]]:
        """Rates for the pids in {pid: name}; empty while off, or until a second record per pid."""
        if not self.on:
            return {}
        pids = sorted(p for p, n in names.items() if _net_counted(p, n))
        try:
            if self._service is None:
                stats = NetworkStatistics(self._dvt, [])
                await stats.connect()
                self._service = stats.service
            if not self._started.issuperset(pids):
                # Whether a second start adds to the set or replaces it cannot be told on iOS
                # 27.2 (see docs/ARCHITECTURE.md); starting the whole set is right for the
                # sampled set either way. If a future iOS resets counters on start, one tick of
                # a known pid could be off. Marked first, so a cancel mid-start still stops them.
                self._started.update(pids)
                await asyncio.wait_for(self._service.start_sampling_for_pids_(pids), NET_TIMEOUT)
            records = await asyncio.wait_for(
                self._service.sample_attributes_for_pids_({}, pids), NET_TIMEOUT
            )
        except (asyncio.TimeoutError, TimeoutError) as e:  # transient; before OSError (3.11+)
            return self._failed(e)
        except (ConnectionTerminatedError, OSError, EOFError):
            raise  # the link is gone: the monitor ends through _dvt_guard
        except Exception as e:  # the library raises many kinds on a bad reply
            return self._failed(e)
        self._fails = 0
        return self._rates.update(records, time.monotonic())

    def _failed(self, error: BaseException) -> dict[int, tuple[float, float]]:
        self._fails += 1
        if self._fails >= NET_FAILS:
            log.warning("network stats off: %s", error or type(error).__name__)
            self.on = False
        return {}


async def _domain(ld: LockdownClient, domain: str) -> dict[str, Any]:
    try:
        value = await ld.get_value(domain=domain)
    except (PyMobileDevice3Exception, OSError, EOFError):
        return {}
    return value if isinstance(value, dict) else {}


def _stamp(value: datetime | None) -> str:
    return value.astimezone().strftime("%m-%d %H:%M:%S") if value else ""

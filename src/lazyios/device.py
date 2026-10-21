"""Real backend over pymobiledevice3."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import datetime
from pathlib import Path
from typing import Any

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
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.pcapd import DevicePacket, PcapdService
from pymobiledevice3.services.syslog import SyslogService

from . import usbmuxd
from .backend import (
    App,
    BackendError,
    Battery,
    Condition,
    DeviceInfo,
    DevModeOffError,
    NoDeviceError,
    NotTrustedError,
    Packet,
    Process,
    UsbmuxdError,
    undo_all,
)
from .parsing import link_offset, parse_ip_packet

LAUNCH_TIMEOUT = 15
PAYLOAD_MAX = 2048  # enough for a DNS answer or the start of a TLS ClientHello


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
            return Battery(
                percent=int(data.get("CurrentCapacity", 0)),
                cycles=int(data.get("CycleCount", 0)),
                charging=bool(data.get("IsCharging")),
                watts=adapter.get("Watts"),
                adapter=str(adapter.get("Description", "")),
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
            except TimeoutError:
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
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with path.open("wb") as out:
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

    async def close(self) -> None:
        """Undo device-side state first, then drop sessions; every step is best effort."""
        self.closed = True
        await undo_all(self._clear_condition, self._clear_location)
        with suppress(Exception):
            await self._reset_tunnel()
        await self._drop_lockdown()


def _stamp(value: datetime | None) -> str:
    return value.astimezone().strftime("%m-%d %H:%M:%S") if value else ""

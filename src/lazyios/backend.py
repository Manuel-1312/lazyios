"""Data types and the interface the UI uses to talk to a device."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class BackendError(Exception):
    """A device operation failed; the message is safe to show to the user."""


class NoDeviceError(BackendError):
    """No device is connected."""


class UsbmuxdError(BackendError):
    """usbmuxd (the USB multiplexer service) is not reachable."""


class NotTrustedError(BackendError):
    """The device has not trusted this computer, or is locked."""


class DevModeOffError(BackendError):
    """The operation needs Developer Mode."""


@dataclass(frozen=True)
class DeviceInfo:
    name: str
    product_type: str
    version: str
    build: str
    serial: str
    wifi_mac: str
    udid: str


@dataclass(frozen=True)
class Battery:
    percent: int
    cycles: int
    charging: bool
    watts: int | None = None
    adapter: str = ""
    voltage_mv: int | None = None
    current_ma: int | None = None  # positive while charging
    design_mah: int | None = None
    full_mah: int | None = None  # what a full charge holds today

    @property
    def health(self) -> float | None:
        """Full charge capacity against design capacity, the way Settings reports it."""
        if not self.design_mah or not self.full_mah:
            return None
        return self.full_mah / self.design_mah


@dataclass(frozen=True)
class ProcSample:
    pid: int
    name: str
    cpu: float | None  # percent of one core; None in the first sample
    memory: int | None  # physical footprint, bytes
    rx: float | None = None  # bytes per second received; None: unknown or left out
    tx: float | None = None  # bytes per second sent


@dataclass(frozen=True)
class SysSample:
    time: float
    cores: int
    cpu: float | None  # percent of all cores together, 0-100
    memory: float | None  # fraction of physical memory in use
    processes: tuple[ProcSample, ...] = ()
    net: bool = True  # False: per-process network rates are off, rx and tx stay None


@dataclass(frozen=True)
class DeviceSummary:
    udid: str
    connection: str  # USB or Network
    name: str = ""
    product_type: str = ""
    version: str = ""
    trusted: bool = True  # False: this computer has no pairing record for it


@dataclass(frozen=True)
class AuditFacts:
    """Raw security-relevant values; None where the device did not answer."""

    version: str
    build: str
    developer_mode: bool | None = None
    passcode: bool | None = None
    activation: str | None = None
    wifi_debugging: bool | None = None
    wifi_connections: bool | None = None
    backup_encrypted: bool | None = None
    cloud_backup: bool | None = None
    supervised: bool | None = None
    profiles: tuple[tuple[str, str, str], ...] | None = None  # (identifier, name, organization)


@dataclass(frozen=True)
class LogLine:
    time: str
    process: str
    pid: int
    level: str
    message: str
    raw: str = ""


@dataclass(frozen=True)
class Process:
    pid: int
    name: str
    is_app: bool
    started: str


@dataclass(frozen=True)
class App:
    name: str
    bundle_id: str
    version: str
    executable: str = ""  # CFBundleExecutable, the process name packets carry


@dataclass(frozen=True)
class Packet:
    time: float
    pid: int
    process: str
    interface: str
    proto: str
    src: str
    dst: str
    length: int
    payload: bytes = b""  # start of the TCP/UDP payload, for DNS and TLS parsing


@dataclass(frozen=True)
class Condition:
    group_id: str
    group: str
    profile_id: str
    name: str
    description: str


UNDO_TIMEOUT = 5.0


async def undo_all(*undos: Callable[[], Awaitable[None]], timeout: float = UNDO_TIMEOUT) -> None:
    """Run device-side undo steps concurrently, each with its own timeout; failures are ignored."""
    await asyncio.gather(
        *(asyncio.wait_for(undo(), timeout) for undo in undos), return_exceptions=True
    )


class Backend(Protocol):
    tunnel_open: bool
    active_condition: Condition | None
    closed: bool
    on_reset: Callable[[], None] | None

    async def device_info(self) -> DeviceInfo: ...
    async def battery(self) -> Battery: ...
    async def developer_mode(self) -> bool: ...
    def syslog(self) -> AsyncIterator[str]: ...
    async def open_tunnel(self) -> None: ...
    async def processes(self) -> list[Process]: ...
    async def kill(self, pid: int) -> None: ...
    async def launch(self, bundle_id: str) -> int: ...
    async def apps(self) -> list[App]: ...
    def capture(self, path: Path) -> AsyncIterator[Packet]: ...
    async def conditions(self) -> list[Condition]: ...
    async def set_condition(self, condition: Condition) -> None: ...
    async def clear_condition(self) -> None: ...
    async def screenshot(self) -> bytes: ...
    async def set_location(self, lat: float, lon: float) -> None: ...
    async def clear_location(self) -> None: ...
    def fps(self) -> AsyncIterator[int]: ...
    def sysmon(self) -> AsyncIterator[SysSample]: ...
    async def device_ids(self) -> list[str]: ...
    async def devices(self) -> list[DeviceSummary]: ...
    async def audit_facts(self) -> AuditFacts: ...
    async def close(self) -> None: ...

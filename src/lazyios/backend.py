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
    async def close(self) -> None: ...

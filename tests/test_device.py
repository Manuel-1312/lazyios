import pytest

from lazyios.backend import DeviceInfo, NoDeviceError
from lazyios.device import DeviceBackend


def _info(udid: str) -> DeviceInfo:
    return DeviceInfo("iPhone", "iPhone18,1", "27.2", "B", "S", "M", udid)


class Probe(DeviceBackend):
    """DeviceBackend with the usbmux side scripted and the tunnel reset counted."""

    def __init__(self, answers: list[DeviceInfo | Exception]) -> None:
        super().__init__()
        self.answers = answers
        self.resets = 0
        self._dvt = object()  # type: ignore[assignment]  # pretend a DVT session is open

    async def _device_info_usbmuxd(self) -> DeviceInfo:
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    async def _reset_tunnel(self) -> None:
        self.resets += 1
        self._dvt = None


async def test_unplug_drops_the_dvt_session():
    backend = Probe([_info("A"), NoDeviceError("no device connected")])
    await backend.device_info()
    assert backend.resets == 0
    with pytest.raises(NoDeviceError):
        await backend.device_info()
    assert backend.resets == 1


async def test_a_different_device_drops_the_old_session():
    backend = Probe([_info("A"), _info("A"), _info("B")])
    await backend.device_info()
    await backend.device_info()
    assert backend.resets == 0
    await backend.device_info()
    assert backend.resets == 1


async def test_no_reset_without_a_session():
    backend = Probe([NoDeviceError("no device connected")])
    backend._dvt = None
    with pytest.raises(NoDeviceError):
        await backend.device_info()
    assert backend.resets == 0

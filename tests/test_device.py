import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pymobiledevice3.exceptions import ConnectionTerminatedError

from lazyios import device
from lazyios.backend import DeviceInfo, NoDeviceError
from lazyios.device import DeviceBackend, _net_counted, _NetRates, _NetSampler


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


def test_device_values_are_checked_before_use():
    from lazyios.device import _flag, _number, _proc_sample

    assert _number(5) == 5 and _number(2.5) == 2.5
    assert _number(True) is None and _number("5") is None and _number(None) is None
    assert _flag(True) is True and _flag(0) is False and _flag(1) is True
    assert _flag("yes") is None and _flag(2) is None
    at = [0, 1, 2, 3]
    assert _proc_sample([7, "Maps\x1b[2J", 12.5, 1024], at).name == "Maps[2J"
    assert _proc_sample([7, "Maps", None, None], at).cpu is None
    assert _proc_sample(["7", "x", 1, 1], at) is None  # pid must be an int
    assert _proc_sample([True, "x", 1, 1], at) is None
    assert _proc_sample([7, "x"], at) is None  # short row
    assert _proc_sample(None, at) is None


def _record(rx: int, tx: int, at: datetime | None = None) -> dict:
    when = SimpleNamespace(utc=at) if at else None  # pymobiledevice3 sends an NSDate
    return {"net.rx.bytes.delta": rx, "net.tx.bytes.delta": tx, "time": when}


def test_net_rates_skip_the_first_record_of_a_pid():
    t0 = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
    at = lambda seconds: t0 + timedelta(seconds=seconds)  # noqa: E731
    rates = _NetRates()
    assert rates.update({7: _record(5000, 900, at(0))}, 0) == {}  # leftover from before the window
    out = rates.update({7: _record(3000, 500, at(2)), 8: _record(9, 9, at(2))}, 0)
    assert out == {7: (1500.0, 250.0)}  # delta over the seconds between the two records
    assert rates.update({8: _record(40, 0, at(3))}, 0) == {8: (40.0, 0.0)}  # 7 is not in this reply
    out = rates.update({7: _record(100, 100, at(4)), 8: _record(10, 0, at(4))}, 0)
    assert out == {8: (10.0, 0.0)}  # 7 is back: its first record again, no rate
    assert rates.update({7: _record(100, 100, at(5))}, 0) == {7: (100.0, 100.0)}


def test_net_rates_use_the_clock_without_a_record_time_and_reject_bad_gaps():
    rates = _NetRates()
    rates.update({1: _record(0, 0), 2: _record(0, 0), 3: _record(0, 0)}, 100.0)
    out = rates.update({1: _record(500, 100), 2: _record(-5, 0), 3: _record(1, 1)}, 102.0)
    assert out == {1: (250.0, 50.0), 2: (0.0, 0.0), 3: (0.5, 0.5)}  # a negative delta is 0
    assert rates.update({1: _record(500, 100)}, 102.0) == {}  # same instant: no division by 0
    assert rates.update({1: _record(500, 100)}, 500.0) == {}  # too long since the last record
    assert rates.update({1: {"time": None}, 2: "x"}, 501.0) == {}
    assert rates.update(None, 502.0) == {}


def test_the_kernel_and_our_own_link_get_no_rate():
    assert not _net_counted(0, "kernel_task")
    assert not _net_counted(412, "remotepairingdeviced") and not _net_counted(9, "lockdownd")
    assert not _net_counted(3984, "DTServiceHub")
    assert _net_counted(1, "launchd") and _net_counted(912, "Safari")


class FakeNetService:
    def __init__(self, fail: Exception | None = None, hang: bool = False) -> None:
        self.fail, self.hang, self.calls, self.stopped = fail, hang, [], []
        self.records: dict[int, dict] = {}

    async def start_sampling_for_pids_(self, pids: list[int]) -> None:
        self.calls.append(("start", pids))

    async def sample_attributes_for_pids_(self, attributes: dict, pids: list[int]) -> dict:
        self.calls.append(("sample", pids))
        if self.hang:
            await asyncio.sleep(10)
        if self.fail:
            raise self.fail
        seconds = sum(call == "sample" for call, _ in self.calls)  # one second per call
        when = SimpleNamespace(
            utc=datetime(2026, 10, 22, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        )
        return {pid: {**self.records.get(pid, _record(0, 0)), "time": when} for pid in pids}

    async def stop_sampling_for_pids_(self, pids: list[int]) -> None:
        self.stopped.append(pids)


async def test_net_sampler_starts_new_pids_and_stops_on_exit():
    service = FakeNetService()
    names = {0: "kernel_task", 1: "launchd", 5: "Safari", 6: "lockdownd"}
    async with _NetSampler(object()) as net:  # type: ignore[arg-type]
        net._service = service
        assert await net.sample(names) == {}  # the first record of every pid is dropped
        service.records = {5: _record(2000, 100)}
        out = await net.sample(names)
        assert out[5][0] > 0 and set(out) == {1, 5}
        names[9] = "Maps"  # a process that appeared
        await net.sample(names)
        await net.sample(names)
    starts = [pids for call, pids in service.calls if call == "start"]
    assert starts == [[1, 5], [1, 5, 9]]  # the whole set, never the excluded pids
    assert [pids for call, pids in service.calls if call == "sample"][0] == [1, 5]
    assert service.stopped == [[1, 5, 9]] and net.on


@pytest.mark.parametrize(
    "error", [ValueError("bad reply"), asyncio.TimeoutError(), TimeoutError("timed out")]
)
async def test_net_sampler_turns_off_after_three_failed_ticks_in_a_row(error, caplog):
    async with _NetSampler(object()) as net:  # type: ignore[arg-type]
        net._service = FakeNetService(fail=error)
        with caplog.at_level("WARNING", logger="lazyios.device"):
            for _ in range(2):  # a timeout, builtin or not, is transient: nothing is raised
                assert await net.sample({1: "launchd"}) == {} and net.on
            assert await net.sample({1: "launchd"}) == {} and not net.on
            assert await net.sample({1: "launchd"}) == {}
    assert len([r for r in caplog.records if "network stats off" in r.message]) == 1


async def test_net_sampler_survives_a_service_that_hangs_for_two_ticks(monkeypatch):
    monkeypatch.setattr(device, "NET_TIMEOUT", 0.01)
    async with _NetSampler(object()) as net:  # type: ignore[arg-type]
        net._service = FakeNetService(hang=True)
        assert await net.sample({1: "launchd"}) == {} and net.on
        assert await net.sample({1: "launchd"}) == {} and net.on
        assert await net.sample({1: "launchd"}) == {} and not net.on


async def test_a_good_tick_resets_the_failure_count():
    async with _NetSampler(object()) as net:  # type: ignore[arg-type]
        service = net._service = FakeNetService(fail=ValueError("bad reply"))
        await net.sample({1: "launchd"})
        await net.sample({1: "launchd"})
        service.fail = None
        await net.sample({1: "launchd"})  # recovered
        service.fail = ValueError("bad reply")
        await net.sample({1: "launchd"})
        await net.sample({1: "launchd"})
        assert net.on  # two failures since the last good tick, not four
        await net.sample({1: "launchd"})
        assert not net.on


async def test_net_sampler_lets_a_lost_connection_through():
    async with _NetSampler(object()) as net:  # type: ignore[arg-type]
        net._service = FakeNetService(fail=ConnectionTerminatedError())
        with pytest.raises(ConnectionTerminatedError):
            await net.sample({1: "launchd"})


@dataclass
class _Fields:
    pid: int = 0
    name: str = ""
    cpuUsage: float = 0.0
    physFootprint: int = 0


class FakeTap:
    process_attributes_cls = system_attributes_cls = _Fields

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return None

    async def __aiter__(self):
        for cpu in (1.0, 2.0, 3.0):
            yield {"Processes": {"1": [1, "launchd", cpu, 100], "5": [5, "Safari", cpu, 200]}}

    @staticmethod
    async def create(provider, interval):
        return FakeTap()


class SysmonProbe(DeviceBackend):
    async def _provider(self):
        return object()


async def test_sysmon_keeps_cpu_and_memory_when_network_sampling_cannot_start(monkeypatch):
    class Broken:
        def __init__(self, *args):
            pass

        async def connect(self):
            raise ValueError("no such channel")

    monkeypatch.setattr(device, "Sysmontap", FakeTap)
    monkeypatch.setattr(device, "NetworkStatistics", Broken)
    samples = [s async for s in SysmonProbe().sysmon()]
    assert [s.net for s in samples] == [True, True, False]  # given up on the third failed tick
    assert [p.cpu for p in samples[-1].processes] == [3.0, 3.0]
    assert all(p.rx is None and p.tx is None for s in samples for p in s.processes)


async def test_sysmon_fills_rates_from_the_second_record(monkeypatch):
    service = FakeNetService()
    service.records = {5: _record(4000, 0)}

    class Stats:
        def __init__(self, *args):
            self.service = service

        async def connect(self):
            return None

    monkeypatch.setattr(device, "Sysmontap", FakeTap)
    monkeypatch.setattr(device, "NetworkStatistics", Stats)
    samples = [s async for s in SysmonProbe().sysmon()]
    assert all(s.net for s in samples)
    assert all(p.rx is None for p in samples[0].processes)
    safari = {p.name: p for p in samples[-1].processes}["Safari"]
    assert safari.rx is not None and safari.rx > 0 and safari.tx == 0
    assert service.stopped  # sampling stops when the monitor ends

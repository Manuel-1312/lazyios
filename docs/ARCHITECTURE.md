# Architecture

## Today

```
__main__.py   CLI, picks the backend
backend.py    data types + Backend protocol (the only thing the UI knows about a device)
device.py     DeviceBackend over pymobiledevice3 (lockdown, pcapd, syslog, DVT over a userspace tunnel)
fake.py       FakeBackend: canned data for --demo, --selftest and every UI test
parsing.py    pure parsers: syslog, IPv4/IPv6, DNS answers, TLS SNI (fuzzed, bounded)
privacy.py    HostAggregator: packets -> (app, domain) rows, tracker lookup, JSON/CSV report
files.py      owner-only output files
app.py        Textual app: status line, workers, the one shared capture
tabs/         one widget per tab; TableTab gives filter + refresh to list tabs
```

Data flows one way: backend (acquisition) -> parsing/privacy (analysis) -> tabs (presentation).
Tabs never import pymobiledevice3; anything new goes through `Backend` so `FakeBackend` can
drive it in tests without an iPhone.

## Direction

New features keep that split instead of a rewrite:

- **acquisition**: new `Backend` methods, each with a `FakeBackend` twin.
- **analysis**: pure modules fed by data types (`flows.py` for connections, `anomaly.py` for
  rules), unit tested without Textual.
- **storage**: `files.py` for every file lazyios writes (permissions, no overwrite, size caps,
  SHA-256 sidecars).
- **presentation**: tabs stay thin; bounded buffers everywhere (deque / capped dicts).

## What the device actually exposes

Checked on an iPhone18,1 running iOS 27.2 with pymobiledevice3 11.36 (2026-10-21). Anything
not in this table is not promised.

| data | source | needs Developer Mode | verified |
| --- | --- | --- | --- |
| packets with pid + process name | `PcapdService` (lockdown) | no | yes |
| connections with pid, rx/tx bytes, RTT | DVT `NetworkMonitor` | yes | yes (96 connections, 311 updates in 8 s) |
| per-process CPU, memory (physFootprint, resident) | DVT `Sysmontap` | yes | yes (571 processes) |
| FPS | DVT `Graphics` | yes | yes (existing tools tab) |
| battery level, cycles, charger | `DiagnosticsService.get_battery` | no | yes |
| battery temperature | `get_battery` top level | - | **no** `Temperature` key on this build |
| syslog | `SyslogService` | no | yes |

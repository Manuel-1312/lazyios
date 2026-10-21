# Architecture

## Today

```
__main__.py   CLI, picks the backend
backend.py    data types + Backend protocol (the only thing the UI knows about a device)
device.py     DeviceBackend over pymobiledevice3 (lockdown, pcapd, syslog, DVT over a userspace tunnel)
fake.py       FakeBackend: canned data for --demo, --selftest and every UI test
parsing.py    pure parsers: syslog, IPv4/IPv6, DNS answers, TLS SNI (fuzzed, bounded)
privacy.py    HostAggregator: packets -> (app, domain) rows, tracker lookup, DNS/SNI names
flows.py      FlowTable: packets -> one row per connection, bytes each way, name confidence
score.py      privacy score per app from the privacy rows, with the reason for every point
sessions.py   local history of app -> domains per capture, compared with the next one
alerts.py     alert rules from <out>/alerts.json (validated, defaults on any error)
timeline.py   bounded event list, syslog folding, process start/exit diff, time queries
anomaly.py    spike, beacon, fanout and change rules with <out>/anomaly.json thresholds
files.py      owner-only output files, JSON/CSV reports with a SHA-256 file
app.py        Textual app: status line, workers, the one shared capture
tabs/         one widget per tab; TableTab gives filter + refresh to list tabs
```

Data flows one way: backend (acquisition) -> parsing/privacy (analysis) -> tabs (presentation).
Tabs never import pymobiledevice3; anything new goes through `Backend` so `FakeBackend` can
drive it in tests without an iPhone.

## Direction

New features keep that split instead of a rewrite:

- **acquisition**: new `Backend` methods, each with a `FakeBackend` twin.
- **analysis**: pure modules fed by data types (`flows.py`, later `anomaly.py` for rules), unit
  tested without Textual.

## Names and confidence

One capture feeds the packet table, `HostAggregator` and `FlowTable`, in that order. A domain is
tied to an address in one of three ways, and every row and export says which:

| source | confidence | meaning |
| --- | --- | --- |
| `sni` | high | the app sent this name in the TLS ClientHello of this connection |
| `dns` | medium | a DNS answer for this address; CDN addresses serve many sites |
| `ip` | none | no name seen (DoH, ECH, QUIC and Private Relay hide it) |

SNI is never borrowed across apps. A DNS answer that arrives after the traffic renames the rows
that only had the address. pktap sometimes leaves the pid off inbound packets; such a packet is
counted for an app only when protocol and both endpoints match that app's connection.
- **storage**: `files.py` for every file lazyios writes (permissions, no overwrite, size caps,
  SHA-256 sidecars).
- **presentation**: tabs stay thin; bounded buffers everywhere (deque / capped dicts).

## What the device actually exposes

Checked on an iPhone18,1 running iOS 27.2 with pymobiledevice3 11.36 (2026-10-21). Anything
not in this table is not promised.

| data | source | needs Developer Mode | verified |
| --- | --- | --- | --- |
| packets with pid + process name | `PcapdService` (lockdown) | no | yes |
| connections, rx/tx bytes, RTT | DVT `NetworkMonitor` | yes | yes, but **pid is -2 for every connection**, bytes are per-second deltas: no app attribution, so the inspector uses pcapd |
| per-process CPU, memory (physFootprint, resident) | DVT `Sysmontap` | yes | yes (571 processes) |
| FPS | DVT `Graphics` | yes | yes (existing tools tab) |
| battery level, cycles, charger | `DiagnosticsService.get_battery` | no | yes |
| battery temperature | `get_battery` top level | - | **no** `Temperature` key on this build |
| syslog | `SyslogService` | no | yes |
| app version by process name | `InstallationProxyService` `CFBundleExecutable` | no | yes (316 apps; 19 Flutter apps share `Runner`, so they get no version) |
| process names in packets | pcapd `comm` | no | yes, cut to 16 characters |
| process start times | DVT `proclist` `startDate` | yes | yes (641 of 642; a list takes ~1 s) |
| syslog volume | `SyslogService` | no | ~700-840 lines/s, ~30 errors/s on an idle phone |
| which app is in front | - | - | **not available** through these interfaces |

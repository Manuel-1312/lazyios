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
diffcmd.py    `lazyios diff OLD NEW`: two session files compared offline (text, --json, --html)
alerts.py     alert rules from <out>/alerts.json (validated, defaults on any error)
timeline.py   bounded event list, syslog folding, process start/exit diff, time queries
anomaly.py    spike, beacon, fanout and change rules with <out>/anomaly.json thresholds
audit.py      security checks from AuditFacts: evidence, why, action; never a verdict
anonymize.py  keyed pseudonyms for exports (--anonymize)
keys.py       <out>/keys.json: binding id -> key, validated
diagnostics.py <out>/lazyios.log, owner-only, rotated
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

## Performance

Synthetic traffic, 200k packets at 5000 packets/s, desktop CPU (`HostAggregator`, `FlowTable`
and `Detector` together): about 96k packets/s, 3.4x the 0.2 code once two hot spots went
(exact `statistics.pstdev` in the beacon rule, `clean_text` on every packet). With tables full
(2000 privacy rows, 5000 connections) a per-second refresh costs 4-7 ms. Every buffer has a
cap: 20000 syslog lines (5000 on screen), 20000 timeline events, 2000 privacy rows, 5000
connections, 1000 packet rows.

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
| connections, rx/tx bytes, RTT | DVT `NetworkMonitor` | yes | yes, but **pid is -2 for every connection**, bytes are per-second deltas: no app attribution, so the inspector uses pcapd (upstream confirms it: https://github.com/doronz88/pymobiledevice3/issues/2092) |
| per-process CPU, memory (physFootprint, resident) | DVT `Sysmontap` | yes | yes (571-671 processes); per-process `cpuUsage` is % of one core, `None` in the first sample |
| system CPU and memory | DVT `Sysmontap` | yes | yes: `CPU_TotalLoad` sums all cores (divide by `CPUCount`); memory as `vmUsedCount` / `physMemSize` pages |
| per-process network bytes in and out | DVT `NetworkStatistics` (`sampleAttributes:forPIDs:`, one call per tick) | yes | yes (457 pids in ~80 ms). A record per requested pid, even with no traffic: `net.rx.bytes`, `net.tx.bytes` (and `.packets`), each with `.delta`, plus `pid` and `time`. The first reply is left over from before the window, so a pid's first record is dropped; the next one can still span many seconds, so a gap over 10 s gives no rate. It counts our own USB tunnel: pid 0, `remotepairingdeviced`, `lockdownd` and `DTServiceHub` show hundreds of KB/s that are lazyios, so they get no rate. Ranking matches pcapd per app, absolute values are about 0.7x pcapd's: a gauge, not a measurement. `startSamplingForPIDs:` / `stopSamplingForPIDs:` changed nothing here: records and moving counters came back for pids never started, and after a stop. So on iOS 27.2 whether a second start adds to the set or replaces it cannot be told apart; lazyios starts the whole set whenever a new pid shows up, right either way |
| FPS | DVT `Graphics` | yes | yes (existing tools tab) |
| battery level, cycles, charger | `DiagnosticsService.get_battery` | no | yes |
| battery health, voltage, current | `get_battery` `BatteryData.DesignCapacity` / `FullChargeCapacity`, `Voltage`, `InstantAmperage` | no | yes |
| battery temperature, thermal state | `get_battery`, `BatteryData`, IORegistry `IOPMPowerSource` / `AppleSmartBattery` | - | **no** temperature in any of them on this build |
| syslog | `SyslogService` | no | yes |
| app version by process name | `InstallationProxyService` `CFBundleExecutable` | no | yes (316 apps; 19 Flutter apps share `Runner`, so they get no version) |
| process names in packets | pcapd `comm` | no | yes, cut to 16 characters |
| process start times | DVT `proclist` `startDate` | yes | yes (641 of 642; a list takes ~1 s) |
| syslog volume | `SyslogService` | no | ~700-840 lines/s, ~30 errors/s on an idle phone |
| which app is in front | - | - | **not available** through these interfaces |
| passcode set, activation | lockdown `PasswordProtected`, `ActivationState` | no | yes |
| debugging / sync over Wi-Fi | lockdown domain `com.apple.mobile.wireless_lockdown` | no | `EnableWifiDebugging` yes; `EnableWifiConnections` absent on this build |
| backup encryption | lockdown domain `com.apple.mobile.backup` `WillEncrypt` | no | yes |
| configuration profiles, supervision | `MobileConfigService` `GetProfileList`, `GetCloudConfiguration` (read requests only) | no | yes |
| connected devices | `usbmux.list_devices`, lockdown with `autopair=False` | no | yes; never triggers a Trust prompt |

## Session file format

`<out>/sessions/session-<stamp>.json`, one per capture, written owner-only and never overwritten.
`lazyios diff` and `lazyios report` read it as untrusted input through `sessions.parse`.

```json
{
  "format": 1,
  "started": "2026-10-21T10:00:00",
  "udid": "<device id>",
  "seconds": 312.5,
  "apps": {
    "Maps": {"version": "3.2", "bytes": 48213, "domains": {"a.example.com": "", "b.example.net": "ads"}}
  }
}
```

- `format` must be exactly `1`. Any other value, or a missing key, a wrong type, a negative or
  boolean number, is rejected: `parse` returns `None`, the TUI skips the file, the commands
  exit 2. `FORMAT` changes only for incompatible changes.
- `domains` maps a name to its tracker category (`ads`, `analytics`, `telemetry`, or `""` when
  the name is not in the tracker data). Only names learned from TLS SNI or DNS are stored:
  never IP addresses, never payloads.
- Limits: 4 MB per file, 2000 apps, 2000 domains per app; 30 files kept per folder.
  Names are cleaned (`clean_text`, `sanitize_host`) so a hostile file cannot inject control
  characters into the terminal or the HTML reports.
# Changelog

## Unreleased

- processes: `m` also shows how many bytes per second each process receives and sends
  (`up/s`, `down/s`) and the total in the status line, from the device's own counters, no
  capture needed; an approximate gauge, and lazyios's own USB traffic is left out

## 0.3.0

New tabs and tools
- conns (8): every connection from the capture with app, pid, endpoints, bytes up and down,
  new vs returning destinations, domain with a confidence level (TLS SNI, DNS or none),
  `app:` `domain:` `ip:` `port:` `proto:` filters, JSON/CSV export
- score (9): privacy score per app with the reason for every point, tracker companies,
  comparison with earlier captures of the same phone (new domains and trackers, app updates
  in between), configurable alerts (`alerts.json`)
- timeline (0): device, captures, first contacts, interfaces, syslog errors folded per process
  and minute, conditions, process starts and exits, alerts and anomalies; time filters
- anomaly rules: traffic spikes, beaconing, bursts of never-seen domains, big changes against
  earlier sessions, each with the numbers behind it (`anomaly.json`)
- processes: live CPU and memory per process (`m`)
- overview: battery health, voltage and current; security audit (`a`)
- devices: list and switch between connected devices (`d`), per-device folders, plugs and
  unplugs noticed, faster reconnection
- command palette (`ctrl+p`), configurable keys (`keys.json`), contextual help, level filter
  in logs (`v`), resizable conditions pane (`[` `]`), activity in the status line

Safety and privacy
- output files owner-only (0700 / 0600) and never overwritten
- reports come with a `.sha256` file
- `--anonymize` for exports, `--keep-files` and `--keep-sessions` retention,
  `--max-capture-mb` cap on capture size
- diagnostic log `lazyios.log` (owner-only, rotated) instead of tracebacks on screen

Fixes
- the syslog stream reconnects after an unplug instead of stopping for good
- a stale developer session is dropped when the phone is unplugged or replaced
- screenshots taken within the same second no longer overwrite each other
- a DNS answer that arrives after the traffic now names the rows it belongs to
- CSV export no longer fails on Windows in time zones west of UTC

Under the hood
- CI on Windows, Linux and macOS; release binaries built from `uv.lock` with hash-checked
  dependencies
- packet analysis about 3.4x faster (96k packets/s on a desktop CPU)
- more than 230 tests, all runnable without an iPhone

Note: captures, screenshots and reports now go to `~/lazyios/<udid>/...`; files written by
earlier versions stay in `~/lazyios/captures` and the like.

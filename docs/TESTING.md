# Testing

Run everything: `uv run --extra dev pytest` (about a minute), then `ruff check` and
`ruff format --check`. `lazyios --selftest` boots the demo headless and exits 0 or 1.

## Layers

| layer | what it proves | where |
| --- | --- | --- |
| pure analysis | parsers, aggregation, scoring, anomaly rules, session diff, anonymisation, report files | `test_parsing`, `test_privacy`, `test_flows`, `test_score`, `test_anomaly`, `test_sessions`, `test_diffcmd`, `test_anonymize`, `test_files`, `test_timeline`, `test_alerts`, `test_audit`, `test_settings` |
| device backend | the code around pymobiledevice3, against stubbed services | `test_device` |
| UI | keys, tabs, filters, exports and workers, driven by Textual's pilot on `FakeBackend` | `test_app` |
| boot | the app starts and the demo device loads | `--selftest`, in CI and in the release job |

## Rules
- A new feature goes through `Backend` with a `FakeBackend` twin, so it is testable without
  a phone. Pure modules take plain data and need no Textual.
- Anything read from disk or the network is untrusted: test the malformed, oversized and
  hostile cases next to the good one (see `test_diffcmd`).
- UI tests wait for state with `until(...)`, never a fixed sleep.
- Nothing is called "tested on a device" unless it ran on one. Mocks prove parsing and UI
  only; the device column in `ARCHITECTURE.md` records what was actually checked, with the
  iOS and pymobiledevice3 versions.

## CI
Ubuntu and Windows on Python 3.11, 3.12, 3.13, plus macOS on 3.12: lock check, lint, format,
pytest, selftest. Release adds a hash-checked build of the three binaries, each run with
`--version` and `--selftest`.

## Gaps
- `device.py` and `app.py` are only covered through fakes; USB unplug and tunnel recovery
  need hardware runs (not done).
- No long-capture memory test.
- No recorded real-device traces replayed as fixtures; adding anonymised ones would test the
  parsers against real packets.

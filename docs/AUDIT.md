# Technical audit

Static review of the repository at `fedb997` plus one full local run (242 tests, ruff clean,
Windows, Python 3.14). Nothing here was exercised against a real iPhone. Severity is about
impact on users, effort is a rough size for one person.

| # | Finding | Severity | Effort | Priority |
| --- | --- | --- | --- | --- |
| 1 | `tests/test_app.py::test_tab_switching` timed out once on windows/3.13 in CI (5 s `until`); passed on rerun and on the previous commit. Flaky UI timing, unrelated to the change under test | Medium | S | 1 |
| 2 | Actions are pinned by tag (`@v7`), not by commit SHA; the release job publishes binaries and uses `contents: write` | Medium | S | 2 |
| 3 | `ci.yml` never runs `--selftest`; it only runs in `release.yml`, so a broken boot of the demo is found at tag time | Low | S | 3 |
| 4 | Release assets have `SHA256SUMS` but no build provenance attestation | Low | S | 4 |
| 5 | `device.py` (622 lines) and `app.py` (521) hold most of the logic that is hard to test without hardware; only `FakeBackend` covers them | Medium | L | 5 |
| 6 | `except Exception` appears 4 times in `src/`; each should be checked for swallowed errors that never reach `lazyios.log` | Low | S | 6 |
| 7 | No non-interactive entry point existed (CI, scripts); `lazyios diff` is the first | Low | M | done in #11 |
| 8 | No Spanish documentation | Low | M | 7 |

## What is already solid

- Release pipeline installs from `uv.lock` with `--require-hashes`, runs `--version` and
  `--selftest` on each binary, and publishes `SHA256SUMS`.
- Output files are owner-only, never overwritten, JSON/CSV exports come with a SHA-256 file.
- Untrusted input (session files, `alerts.json`, `anomaly.json`, packets) is parsed with caps.
- Every buffer is bounded; performance numbers are in `ARCHITECTURE.md`.
- Attribution is split into SNI (high), DNS (medium) and none; no row claims intent.

## Not assessed

USB/tunnel reconnection behaviour, memory over long captures, and anything that needs a
device. Those need hardware runs before they can be called good or bad.

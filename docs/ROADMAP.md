# Roadmap

Twelve months, in order of what unblocks the next step. Dates are intentions, not promises.
Anything marked (device) needs a real iPhone before it can be called done; mocks only prove
the parsing and the UI.

## Now (months 1-2): trust the basics
- Merge the CI hardening from `AUDIT.md` (selftest in CI, flaky test, build attestation).
- First release with `lazyios diff` and its HTML and JSON output.
- Run the privacy capture on two or more iOS versions (device) and record what each exposes
  in `ARCHITECTURE.md`, as is already done for iOS 27.2.

## Next (months 3-5): make results portable
- Offline reports from saved sessions: one session as HTML, not only a diff.
- Stable JSON schema for sessions and exports, versioned, with a documented Python API for
  `sessions`, `privacy` and `flows` (they already are pure modules).
- Capture comparison inside the TUI using the same `diff` code, so both agree.
- Spanish README and tutorial that anyone can follow with `--demo`.

## Later (months 6-9): diagnosis
- Recurring-error summaries and a per-session recap built on `timeline` and `anomaly`.
- Performance diagnostics from `Sysmontap` and `NetworkStatistics` (device).
- Optional local AI summary: off by default, local model only, anonymised input
  (`anonymize.py`), and a switch that removes the code path entirely.

## Later still (months 10-12): reach
- Local web dashboard as an optional extra, bound to 127.0.0.1 only, never on by default.
  Worth building only if the offline reports show people want a browser view.
- Multiple devices in one run and named diagnostic profiles.
- Release notes, contribution guide and disclosure policy kept current with each release.

## Not planned
- Telemetry of any kind, including usage counts. Adoption is measured from public numbers
  (PyPI downloads, release downloads, GitHub stars and issues), never from the tool.
- Claims that an app spies on the user because it contacts a domain.
- Anything that changes or erases data on the phone.

## How adoption is judged
Real installs and issues from people other than the author, reproducible bug reports, and
contributors who land a change. No target star count.

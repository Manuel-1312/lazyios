# Backlog

Ordered by dependency, then value. Every item ships with a test; "(device)" items also need
a run on a real iPhone before they are called done. Context is in `ROADMAP.md`.

## Next

1. **Single-session report.** `lazyios report SESSION [--html FILE|--json]`, same safety rules
   as `diff` (escaped, no scripts, never overwrites).
   Done when: output for an empty, a normal and a hostile session file is tested; exit codes
   match `diff`.
2. **Stable session schema.** Document the `session-*.json` format and bump `FORMAT` only on
   incompatible changes; `diff` and `report` refuse unknown formats with a clear message.
   Needs: 1. Done when: a schema section in `ARCHITECTURE.md` and a test per rejected shape.
3. **Real-trace fixtures.** A few anonymised pcap excerpts (DNS, TLS ClientHello, QUIC) as test
   inputs for `parsing.py`. Done when: parsers are exercised on bytes that did not come from our
   own generator. Needs a capture from a real phone (device).
4. **Python API page.** Document `sessions`, `privacy` and `flows` as the public surface, with
   one runnable example. Needs: 2.
5. **Spanish README and demo walkthrough.** Done when someone can follow it with `--demo`.

## Later

- Capture comparison inside the TUI using `sessions.diff` so both views agree. Needs: 2.
- Recurring-error summary per session from `timeline` and `anomaly`.
- Per-process performance diagnostics (device).
- Optional local AI summary: off by default, local model only, anonymised input, and a switch
  that removes the code path.
- Local web dashboard bound to 127.0.0.1, only if the offline reports show demand.

## Done in 0.5.0
`lazyios diff` with `--json`, `--html`, `--fail-on-new-trackers`; `--selftest` in CI; build
attestation on releases; audit, roadmap, testing and releasing docs.

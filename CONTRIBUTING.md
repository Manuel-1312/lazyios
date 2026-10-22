# Contributing

Bug reports, device reports and pull requests are welcome.

## Reporting a bug

Use the bug report template and include the iOS version and build, the iPhone model, your OS,
the lazyios version (`lazyios --version`) and whether Developer Mode is on. A log helps:
run with `--log-level debug` and attach `lazyios.log` from the output folder. Check it first:
it can contain device names, process names and domains. `--anonymize all` pseudonymizes IPs,
domains and ids in exported reports.

Behaviour often changes between iOS betas. If something stopped working after an update,
say which build worked and which one does not.

## Development setup

Python 3.10 or newer (3.12 recommended):

    git clone https://github.com/Manuel-1312/lazyios
    cd lazyios
    python -m venv .venv
    .venv/bin/pip install -e ".[dev]"        # .venv\Scripts\pip on Windows

Run it without a phone:

    python -m lazyios --demo

## Before opening a pull request

    ruff check
    ruff format --check
    pytest

CI runs the same on Linux, macOS and Windows with Python 3.10, 3.12 and 3.13. Tests use the
fake backend in `src/lazyios/fake.py` and never need a device. If a change depends on what a
real iPhone returns, say which device and iOS build you tested it on, and update the
capability table in `docs/ARCHITECTURE.md` when you verify something new.

Keep pull requests small and focused, and add a line to `CHANGELOG.md` under a
`## Unreleased` heading.

## License

lazyios is GPL-3.0-or-later. By contributing you agree that your contribution is released
under the same license.

from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .anonymize import parse_kinds
from .app import MAX_CAPTURE_MB, MB, LazyiosApp
from .backend import Backend
from .diagnostics import LEVELS
from .diagnostics import setup as setup_logging
from .sessions import KEEP

CLOSE_TIMEOUT = 5


def _count(value: str, least: int = 0) -> int:
    if not (value.isascii() and value.isdigit()) or int(value) < least:
        raise argparse.ArgumentTypeError(f"must be a whole number of {least} or more")
    return int(value)


def _kinds(value: str) -> frozenset[str]:
    try:
        return parse_kinds(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None


def _positive(value: str) -> int:
    return _count(value, 1)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="lazyios", description="Inspect and control an iPhone over USB from the terminal."
    )
    parser.add_argument("--udid", help="target device when several are connected")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path.home() / "lazyios",
        help="output directory for captures and screenshots (default: ~/lazyios)",
    )
    parser.add_argument(
        "--max-capture-mb",
        type=_positive,
        default=MAX_CAPTURE_MB,
        metavar="MB",
        help=f"stop a capture when its pcap reaches this size (default: {MAX_CAPTURE_MB})",
    )
    parser.add_argument(
        "--keep-sessions",
        type=_count,
        default=KEEP,
        metavar="N",
        help=f"session history files kept for comparisons, 0 keeps none (default: {KEEP})",
    )
    parser.add_argument(
        "--keep-files",
        type=_count,
        default=0,
        metavar="N",
        help="per device, keep only the N newest captures, screenshots and reports of each kind;"
        " older ones are deleted (default: 0, keep everything)",
    )
    parser.add_argument(
        "--anonymize",
        type=_kinds,
        default=frozenset(),
        metavar="KINDS",
        help="pseudonymize exported reports: ips, domains (known trackers stay), ids, or all",
    )
    parser.add_argument(
        "--log-level",
        choices=LEVELS,
        default="warning",
        help="diagnostic log <out>/lazyios.log (default: warning)",
    )
    parser.add_argument("--version", action="version", version=f"lazyios {__version__}")
    parser.add_argument("--selftest", action="store_true", help="boot the demo headless and exit")
    parser.add_argument("--demo", action="store_true", help="run with fake data, no device needed")
    return parser.parse_args(argv)


def make_backend(args: argparse.Namespace, udid: str | None = None) -> Backend:
    """The backend for one device; udid overrides --udid (switching devices in the app)."""
    if args.demo:
        from .fake import FakeBackend

        return FakeBackend(udid)
    from .device import DeviceBackend

    return DeviceBackend(udid or args.udid)


async def _selftest() -> None:
    import pymobiledevice3.remote.userspace_tunnel  # noqa: F401

    from . import device  # noqa: F401
    from .fake import FakeBackend
    from .privacy import TrackerDB

    if not TrackerDB().lookup("sdk.iad-01.braze.com"):
        raise RuntimeError("tracker data missing")
    with tempfile.TemporaryDirectory() as out:
        app = LazyiosApp(FakeBackend(interval=0.01), Path(out))
        async with app.run_test(size=(100, 30)) as pilot:
            await pilot.pause(1.0)
            if app.info is None:
                raise RuntimeError("demo device did not load")


def selftest() -> int:
    try:
        asyncio.run(_selftest())
    except Exception as e:
        print(f"selftest failed: {type(e).__name__}: {e}")
        return 1
    print("selftest ok")
    return 0


def main(argv: Sequence[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["diff"]:
        from .diffcmd import run

        sys.exit(run(argv[1:]))
    if argv[:1] == ["report"]:
        from .reportcmd import run as run_report

        sys.exit(run_report(argv[1:]))
    args = parse_args(argv)
    if args.selftest:
        sys.exit(selftest())
    if args.out.exists() and not args.out.is_dir():
        sys.exit(f"lazyios: --out {args.out} exists and is not a folder")
    try:
        setup_logging(args.out, args.log_level)
    except OSError as e:
        sys.exit(f"lazyios: cannot write to {args.out}: {e.strerror or e}")
    backend = make_backend(args)
    try:
        with contextlib.suppress(KeyboardInterrupt):
            LazyiosApp(
                backend,
                args.out,
                args.max_capture_mb * MB,
                args.keep_sessions,
                make_backend=lambda udid: make_backend(args, udid),
                keep_files=args.keep_files,
                anonymize=args.anonymize,
            ).run()
    finally:
        if not backend.closed:  # the app's own shutdown did not run
            with contextlib.suppress(Exception):
                asyncio.run(asyncio.wait_for(backend.close(), CLOSE_TIMEOUT))


if __name__ == "__main__":
    main()

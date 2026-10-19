from __future__ import annotations

import argparse
import asyncio
import contextlib
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .app import LazyiosApp
from .backend import Backend

CLOSE_TIMEOUT = 5


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
    parser.add_argument("--version", action="version", version=f"lazyios {__version__}")
    parser.add_argument("--selftest", action="store_true", help="boot the demo headless and exit")
    parser.add_argument("--demo", action="store_true", help="run with fake data, no device needed")
    return parser.parse_args(argv)


def make_backend(args: argparse.Namespace) -> Backend:
    if args.demo:
        from .fake import FakeBackend

        return FakeBackend()
    from .device import DeviceBackend

    return DeviceBackend(args.udid)


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
    args = parse_args(argv)
    if args.selftest:
        sys.exit(selftest())
    backend = make_backend(args)
    try:
        with contextlib.suppress(KeyboardInterrupt):
            LazyiosApp(backend, args.out).run()
    finally:
        if not backend.closed:  # the app's own shutdown did not run
            with contextlib.suppress(Exception):
                asyncio.run(asyncio.wait_for(backend.close(), CLOSE_TIMEOUT))


if __name__ == "__main__":
    main()

"""`lazyios diff OLD NEW`: compare two saved session files without a device or the TUI."""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from .sessions import MAX_FILE, AppDiff, Session, diff, parse


def read_session(path: Path) -> Session:
    """A session file as untrusted input; raises ValueError with a message fit for the user."""
    try:
        if path.stat().st_size > MAX_FILE:
            raise ValueError(f"{path} is larger than {MAX_FILE // 1024 // 1024} MB")
        session = parse(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as e:
        raise ValueError(f"cannot read {path}: {type(e).__name__}") from None
    if session is None:
        raise ValueError(f"{path} is not a lazyios session file")
    return session


def render_text(old: Session, new: Session, changes: dict[str, AppDiff]) -> str:
    lines = [
        f"{old.started} -> {new.started}  ({len(changes)} apps changed)",
        "named domains only (TLS SNI or DNS); a new domain is a change, not a verdict",
    ]
    for name, d in changes.items():
        lines.append(f"\n{name}" + (f"  [{d.status} app]" if d.status != "changed" else ""))
        lines += [f"  + {h}" + ("  (tracker)" if h in d.new_trackers else "") for h in d.added]
        lines += [f"  - {h}" for h in d.removed]
    return "\n".join(lines)


def render_json(old: Session, new: Session, changes: dict[str, AppDiff]) -> str:
    doc = {
        "old": {"started": old.started, "udid": old.udid},
        "new": {"started": new.started, "udid": new.udid},
        "apps": {name: vars(d) for name, d in changes.items()},
    }
    return json.dumps(doc, indent=2)


def run(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lazyios diff", description="Compare two session-*.json files from <out>/sessions."
    )
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    try:
        old, new = read_session(args.old), read_session(args.new)
    except ValueError as e:
        print(f"lazyios diff: {e}")
        return 2
    changes = diff(old, new)
    print((render_json if args.json else render_text)(old, new, changes))
    return 0

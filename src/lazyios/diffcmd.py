"""`lazyios diff OLD NEW`: compare two saved session files without a device or the TUI."""

from __future__ import annotations

import argparse
import html
import json
from collections.abc import Sequence
from pathlib import Path

from .files import write_private
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


def render_html(old: Session, new: Session, changes: dict[str, AppDiff]) -> str:
    """One static page, no scripts or external loads; every value from the files is escaped."""
    esc = html.escape
    body = []
    for name, d in changes.items():
        items = [
            f"<li class='{'t' if h in d.new_trackers else 'a'}'>+ {esc(h)}"
            + (" <b>tracker</b>" if h in d.new_trackers else "")
            + "</li>"
            for h in d.added
        ] + [f"<li class='r'>- {esc(h)}</li>" for h in d.removed]
        tag = f" <i>{d.status} app</i>" if d.status != "changed" else ""
        body.append(f"<h2>{esc(name)}{tag}</h2><ul>{''.join(items)}</ul>")
    return page("lazyios diff", f"{esc(old.started)} &rarr; {esc(new.started)}", "".join(body))


def page(title: str, heading: str, body: str) -> str:
    """The static page both commands write; callers escape every value they pass in."""
    return (
        "<!doctype html><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy'"
        " content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        f"<title>{title}</title>"
        "<style>body{font:14px system-ui;margin:2em;max-width:50em}ul{font-family:monospace}"
        ".t{color:#b00}.r{color:#666}</style>"
        f"<h1>{heading}</h1>"
        "<p>Named domains only (TLS SNI or DNS). A domain is a fact about a connection, not a"
        " verdict about the app.</p>" + body
    )


def run(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lazyios diff", description="Compare two session-*.json files from <out>/sessions."
    )
    parser.add_argument("old", type=Path)
    parser.add_argument("new", type=Path)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--html", type=Path, metavar="FILE", help="also write a static HTML page")
    parser.add_argument(
        "--fail-on-new-trackers", action="store_true", help="exit 1 when a tracker domain is new"
    )
    args = parser.parse_args(argv)
    try:
        old, new = read_session(args.old), read_session(args.new)
        changes = diff(old, new)
        if args.html:
            write_private(args.html, render_html(old, new, changes).encode())
    except (ValueError, OSError) as e:
        print(f"lazyios diff: {e}")
        return 2
    print((render_json if args.json else render_text)(old, new, changes))
    return 1 if args.fail_on_new_trackers and any(d.new_trackers for d in changes.values()) else 0

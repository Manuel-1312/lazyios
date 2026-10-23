"""`lazyios report SESSION`: one saved session file as text, JSON or a static HTML page."""

from __future__ import annotations

import argparse
import html
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .diffcmd import page, read_session
from .files import write_private
from .privacy import TRACKER_CATEGORIES
from .sessions import Session


def summarize(session: Session) -> list[dict[str, Any]]:
    """One row per app, apps with the most tracker domains first, then by bytes."""
    rows = []
    for name, app in session.apps.items():
        trackers = sorted(d for d, cat in app.domains.items() if cat in TRACKER_CATEGORIES)
        rows.append(
            {
                "app": name,
                "version": app.version,
                "bytes": app.bytes,
                "domains": sorted(app.domains),
                "trackers": trackers,
            }
        )
    return sorted(rows, key=lambda r: (-len(r["trackers"]), -r["bytes"], r["app"]))


def render_text(session: Session, rows: list[dict[str, Any]]) -> str:
    lines = [f"{session.started}  ({len(rows)} apps, {session.seconds:.0f} s of capture)"]
    for r in rows:
        lines.append(
            f"\n{r['app']}  {r['bytes']} B, {len(r['domains'])} named domains, "
            f"{len(r['trackers'])} in the tracker list"
        )
        lines += [f"  {d}" + ("  (tracker)" if d in r["trackers"] else "") for d in r["domains"]]
    return "\n".join(lines)


def render_json(session: Session, rows: list[dict[str, Any]]) -> str:
    return json.dumps(
        {
            "started": session.started,
            "udid": session.udid,
            "seconds": session.seconds,
            "apps": rows,
        },
        indent=2,
    )


def render_html(session: Session, rows: list[dict[str, Any]]) -> str:
    esc = html.escape
    body = []
    for r in rows:
        items = "".join(
            f"<li class='{'t' if d in r['trackers'] else 'a'}'>{esc(d)}"
            + (" <b>tracker</b>" if d in r["trackers"] else "")
            + "</li>"
            for d in r["domains"]
        )
        body.append(
            f"<h2>{esc(r['app'])}</h2><p>{r['bytes']} B, {len(r['domains'])} named domains, "
            f"{len(r['trackers'])} in the tracker list</p><ul>{items}</ul>"
        )
    return page("lazyios report", esc(session.started), "".join(body))


def run(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="lazyios report", description="Show one session-*.json file from <out>/sessions."
    )
    parser.add_argument("session", type=Path)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--html", type=Path, metavar="FILE", help="also write a static HTML page")
    args = parser.parse_args(argv)
    try:
        session = read_session(args.session)
        rows = summarize(session)
        if args.html:
            write_private(args.html, render_html(session, rows).encode())
    except (ValueError, OSError) as e:
        print(f"lazyios report: {e}")
        return 2
    print((render_json if args.json else render_text)(session, rows))
    return 0

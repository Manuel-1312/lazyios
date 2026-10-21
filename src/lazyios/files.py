"""Output files: captures, screenshots and reports hold private data, so owner-only."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import sys
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Any, BinaryIO, TypeVar

T = TypeVar("T")


def private_dir(path: Path) -> Path:
    """Create path (and parents) and make it owner-only, also when it already existed.
    On Windows the user profile ACLs already keep other users out."""
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if sys.platform != "win32":
        path.chmod(0o700)
    return path


def create_private(path: Path) -> BinaryIO:
    """Open a new file for writing, 0600; refuses to reuse or follow an existing path."""
    private_dir(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(path, flags, 0o600), "wb")


def write_private(path: Path, data: bytes) -> Path:
    with create_private(path) as out:
        out.write(data)
    return path


def read_config(
    path: Path, parse: Callable[[str], T], default: T, max_file: int = 64 * 1024
) -> tuple[T, str | None]:
    """A settings file read as untrusted input. Returns the default plus the reason when the file
    is unusable; parse raises ValueError with a message fit for the user."""
    try:
        if not path.is_file():
            return default, None
        if path.stat().st_size > max_file:
            return default, f"{path.name} is larger than {max_file // 1024} KB, using defaults"
        return parse(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError) as e:
        return default, f"cannot read {path.name}: {type(e).__name__}, using defaults"
    except ValueError as e:
        return default, f"{path.name}: {e}, using defaults"


def csv_safe(value: Any) -> Any:
    """Keep spreadsheets from reading a cell as a formula."""
    return "'" + value if isinstance(value, str) and value.startswith(tuple("=+-@\t\r")) else value


def write_sums(paths: Sequence[Path], sums: Path) -> Path:
    """SHA-256 of each file in `sha256sum` format, so `sha256sum -c` (run in that folder)
    tells whether a report changed after it was written."""
    lines = (f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in paths)
    return write_private(sums, "".join(lines).encode())


def write_tables(
    base: Path, document: dict[str, Any], header: Sequence[str], rows: Iterable[Sequence[Any]]
) -> tuple[Path, Path, Path]:
    """base.json (the document), base.csv (header + rows) and base.sha256 over both."""
    json_path, csv_path = base.with_suffix(".json"), base.with_suffix(".csv")
    write_private(json_path, (json.dumps(document, indent=2) + "\n").encode())
    with io.TextIOWrapper(create_private(csv_path), encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        writer.writerow(header)
        writer.writerows([csv_safe(v) for v in row] for row in rows)
    return json_path, csv_path, write_sums([json_path, csv_path], base.with_suffix(".sha256"))

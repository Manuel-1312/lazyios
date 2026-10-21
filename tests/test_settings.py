"""Diagnostic log, configurable keys and file retention."""

import logging
import stat
import sys

import pytest

from lazyios import diagnostics, keys
from lazyios.files import prune


@pytest.fixture
def restore_logging():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for h in root.handlers:
        if h not in handlers:
            root.removeHandler(h)
            h.close()
    root.setLevel(level)


def test_log_file_gets_tracebacks_and_rotates(tmp_path, restore_logging, monkeypatch):
    monkeypatch.setattr(diagnostics, "MAX_BYTES", 2000)
    path = diagnostics.setup(tmp_path, "warning")
    log = logging.getLogger("lazyios")
    log.info("not at this level")
    try:
        raise ValueError("boom")
    except ValueError:
        log.exception("capture failed")
    for h in logging.getLogger().handlers:
        h.flush()
    text = path.read_text(encoding="utf-8")
    assert "capture failed" in text and "ValueError: boom" in text
    assert "not at this level" not in text
    for i in range(100):
        log.warning("line %d %s", i, "x" * 50)
    assert (tmp_path / "lazyios.log.1").exists()
    diagnostics.setup(tmp_path, "debug")  # setting up again replaces, never doubles, the handler
    assert sum(isinstance(h, diagnostics.PrivateRotatingHandler)
               for h in logging.getLogger().handlers) == 1  # fmt: skip


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_log_files_are_owner_only(tmp_path, restore_logging):
    path = diagnostics.setup(tmp_path / "out")
    logging.getLogger("lazyios").error("x")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_keys_file():
    assert keys.parse('{"capture": "c", "devices": "ctrl+d", "quit": "q,ctrl+q"}') == {
        "capture": "c", "devices": "ctrl+d", "quit": "q,ctrl+q"
    }  # fmt: skip
    for bad, message in (
        ('{"capture": "c", "warp": "w"}', "unknown ids: warp"),
        ('{"capture": "ctrl c"}', "is not a key"),
        ('{"capture": 3}', "is not a key"),
        ('["c"]', "expected a JSON object"),
    ):
        with pytest.raises(ValueError, match=message):
            keys.parse(bad)


def test_keys_load_reports_problems(tmp_path):
    assert keys.load(tmp_path) == ({}, None)
    (tmp_path / "keys.json").write_text('{"nope": "x"}', encoding="utf-8")
    keymap, problem = keys.load(tmp_path)
    assert keymap == {} and "unknown ids: nope" in problem


def test_prune_keeps_the_newest_groups(tmp_path):
    for stamp in ("20261021-100000-000", "20261021-110000-000", "20261021-120000-000"):
        for ext in ("json", "csv", "sha256"):
            (tmp_path / f"privacy-{stamp}.{ext}").write_text("x")
    (tmp_path / "score-20261021-090000-000.json").write_text("x")
    assert prune(tmp_path, "privacy", 0) == 0
    assert prune(tmp_path, "privacy", 2) == 3
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names[0] == "privacy-20261021-110000-000.csv" and len(names) == 7
    assert "score-20261021-090000-000.json" in names  # other kinds untouched
    assert prune(tmp_path / "missing", "privacy", 1) == 0

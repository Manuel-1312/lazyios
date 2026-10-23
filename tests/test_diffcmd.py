import json

import pytest

from lazyios.__main__ import main
from lazyios.diffcmd import read_session
from lazyios.sessions import diff, parse


def session(apps, started="2026-10-20T10:00:00") -> str:
    return json.dumps({"format": 1, "started": started, "udid": "U1", "apps": apps})


def app(**domains) -> dict:
    return {
        "version": None,
        "bytes": 0,
        "domains": {d.replace("_", "."): c for d, c in domains.items()},
    }


OLD = session({"Maps": app(a_com="", b_com="ads"), "Mail": app(m_com=""), "Old": app(o_com="")})
NEW = session(
    {
        "Maps": app(a_com="", c_com="analytics", d_com=""),
        "Mail": app(m_com=""),
        "Fresh": app(f_com=""),
    },
    started="2026-10-21T10:00:00",
)


def test_diff_reports_added_removed_and_trackers_only_for_changed_apps():
    changes = diff(parse(OLD), parse(NEW))
    assert set(changes) == {"Maps", "Old", "Fresh"}  # Mail is unchanged
    maps = changes["Maps"]
    assert (maps.added, maps.removed, maps.new_trackers) == (
        ["c.com", "d.com"],
        ["b.com"],
        ["c.com"],
    )
    assert changes["Old"].status == "gone" and changes["Fresh"].status == "new"


def test_cli_text_and_json(tmp_path, capsys):
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(OLD), b.write_text(NEW)
    with pytest.raises(SystemExit) as e:
        main(["diff", str(a), str(b), "--json"])
    assert e.value.code == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["apps"]["Maps"]["new_trackers"] == ["c.com"]
    with pytest.raises(SystemExit):
        main(["diff", str(a), str(b)])
    out = capsys.readouterr().out
    assert "+ c.com  (tracker)" in out and "- b.com" in out and "[new app]" in out


def test_html_escapes_and_fail_on_new_trackers(tmp_path):
    evil = session({"<script>x</script>": app(c_com="ads")}, started="2026-10-21T10:00:00")
    a, b, out = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "r.html"
    a.write_text(session({})), b.write_text(evil)
    with pytest.raises(SystemExit) as e:
        main(["diff", str(a), str(b), "--html", str(out), "--fail-on-new-trackers"])
    assert e.value.code == 1
    page = out.read_text()
    assert "<script>" not in page and "&lt;script&gt;" in page and "Content-Security-Policy" in page
    with pytest.raises(SystemExit) as e:  # never overwrites an existing report
        main(["diff", str(a), str(b), "--html", str(out)])
    assert e.value.code == 2


@pytest.mark.parametrize("content", ["not json", "{}", '{"format": 2}', "\xff"])
def test_bad_files_exit_2_without_traceback(tmp_path, capsys, content):
    bad = tmp_path / "bad.json"
    bad.write_text(content, encoding="latin-1")
    with pytest.raises(SystemExit) as e:
        main(["diff", str(bad), str(bad)])
    assert e.value.code == 2
    assert "Traceback" not in capsys.readouterr().out


def test_missing_and_oversized_files_are_refused(tmp_path):
    with pytest.raises(ValueError, match="cannot read"):
        read_session(tmp_path / "nope.json")
    big = tmp_path / "big.json"
    big.write_bytes(b" " * (4 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="larger"):
        read_session(big)

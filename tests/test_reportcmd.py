import json

import pytest

from lazyios.__main__ import main
from lazyios.reportcmd import summarize
from lazyios.sessions import parse


def session(apps) -> str:
    return json.dumps({"format": 1, "started": "2026-10-21T10:00:00", "udid": "U1", "apps": apps})


def app(size=0, **domains) -> dict:
    return {
        "version": None,
        "bytes": size,
        "domains": {d.replace("_", "."): c for d, c in domains.items()},
    }


SAMPLE = session(
    {
        "Maps": app(100, a_com="", b_com="ads"),
        "Mail": app(900, m_com=""),
        "Radio": app(10, r_com="analytics", s_com="telemetry"),
    }
)


def test_summarize_puts_most_trackers_first_then_bytes():
    rows = summarize(parse(SAMPLE))
    assert [r["app"] for r in rows] == ["Radio", "Maps", "Mail"]
    assert rows[0]["trackers"] == ["r.com", "s.com"]


def test_cli_text_json_and_html(tmp_path, capsys):
    src, out = tmp_path / "s.json", tmp_path / "r.html"
    src.write_text(SAMPLE)
    with pytest.raises(SystemExit) as e:
        main(["report", str(src), "--json", "--html", str(out)])
    assert e.value.code == 0
    assert json.loads(capsys.readouterr().out)["apps"][0]["app"] == "Radio"
    assert "b.com <b>tracker</b>" in out.read_text()
    with pytest.raises(SystemExit):
        main(["report", str(src)])
    assert "(tracker)" in capsys.readouterr().out


def test_hostile_names_are_escaped_and_existing_report_is_not_overwritten(tmp_path):
    src, out = tmp_path / "s.json", tmp_path / "r.html"
    src.write_text(session({"<script>x</script>": app(1, c_com="ads")}))
    with pytest.raises(SystemExit):
        main(["report", str(src), "--html", str(out)])
    page = out.read_text()
    assert "<script>" not in page and "&lt;script&gt;" in page
    with pytest.raises(SystemExit) as e:
        main(["report", str(src), "--html", str(out)])
    assert e.value.code == 2


@pytest.mark.parametrize("content", ["not json", "{}", '{"format": 2}'])
def test_bad_files_exit_2(tmp_path, capsys, content):
    bad = tmp_path / "bad.json"
    bad.write_text(content)
    with pytest.raises(SystemExit) as e:
        main(["report", str(bad)])
    assert e.value.code == 2
    assert "Traceback" not in capsys.readouterr().out

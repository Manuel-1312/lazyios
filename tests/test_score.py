import csv
import json
from datetime import datetime

from lazyios.privacy import HostRow
from lazyios.score import (
    AppScore,
    kind,
    score_apps,
    sort_scores,
    top_companies,
    write_scores,
)
from lazyios.sessions import Change


def row(app="App", domain="x.example", category="", company="", source="sni", size=100):
    return HostRow(app, domain, category, company, size, 1.0, 2.0, source=source)


def one(*rows: HostRow) -> AppScore:
    [score] = score_apps(rows)
    return score


def test_kinds_keep_trackers_known_unknown_and_unnamed_apart():
    assert kind(row(category="ads")) == "tracker"
    assert kind(row(category="cdn")) == "known"
    assert kind(row()) == "unknown"
    assert kind(row(domain="203.0.113.5", source="ip")) == "unnamed"


def test_clean_app_scores_100_and_unknowns_cost_nothing():
    app = one(row(), row(domain="203.0.113.9", source="ip"), row(domain="cdn.x", category="cdn"))
    assert (app.score, app.grade, app.reasons) == (100, "A", [])
    assert (app.known, app.unknown, app.unnamed) == (1, 1, 1)


def test_weights_per_category_and_dns_counts_half():
    app = one(
        row(domain="ads.t", category="ads", company="AdCo", size=1),
        row(domain="an.t", category="analytics", company="AnCo", size=1),
        row(domain="tel.t", category="telemetry", size=1, source="dns"),
        row(domain="big.example", size=10_000),
    )
    assert app.score == 100 - 12 - 8 - 2  # 2.5 rounds to 2 after the subtraction: 77.5 -> 78
    assert app.trackers == ["ads.t", "an.t", "tel.t"]
    assert app.tracker_companies == ["AdCo", "AnCo"]
    assert any("dns only, half" in r for r in app.reasons)


def test_same_tracker_twice_counts_once():
    assert one(row(domain="ads.t", category="ads"), row(domain="ads.t", category="ads")).score == 78


def test_tracker_cap_and_byte_share():
    rows = [row(domain=f"a{i}.t", category="ads", size=100) for i in range(10)]
    app = one(*rows)
    assert "trackers capped at -75" in app.reasons
    assert app.tracker_share == 1.0
    assert app.score == 100 - 75 - 10
    assert app.grade == "F"


def test_grades():
    for score, grade in (
        (100, "A"),
        (90, "A"),
        (89, "B"),
        (75, "B"),
        (60, "C"),
        (40, "D"),
        (0, "F"),
    ):
        assert AppScore("a", score=score).grade == grade


def test_updates_and_new_trackers_need_history():
    rows = [row(domain="ads.t", category="ads")]
    first = Change(known=False, new_domains=["ads.t"], new_trackers=["ads.t"])
    [app] = score_apps(rows, {"App": first}, {"App": "2.0"})
    assert app.new_trackers == []  # no earlier session, so nothing is "new"
    again = Change(
        known=True, new_domains=["ads.t"], new_trackers=["ads.t"], previous_version="1.9"
    )
    [app] = score_apps(rows, {"App": again}, {"App": "2.0"})
    assert app.new_trackers == ["ads.t"] and app.updated
    [app] = score_apps(rows, {"App": again}, {})
    assert not app.updated  # current version unknown: no update claimed


def test_sort_and_top_companies():
    scores = score_apps(
        [
            row("A", "ads.t", "ads", "Google"),
            row("B", "ads.t", "ads", "Google"),
            row("B", "m.t", "analytics", "Meta"),
            row("C"),
        ]
    )
    assert [a.app for a in sort_scores(scores, "score")] == ["B", "A", "C"]
    assert [a.app for a in sort_scores(scores, "trackers")] == ["B", "A", "C"]
    assert [a.app for a in sort_scores(scores, "app")] == ["A", "B", "C"]
    assert top_companies(scores) == [("Google", 2), ("Meta", 1)]


def test_export_explains_the_criteria(tmp_path):
    scores = score_apps([row("=evil", "ads.t", "ads", "AdCo")])
    json_path, csv_path, sums = write_scores(scores, tmp_path, datetime(2026, 10, 21))
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert doc["criteria"][0] == "start at 100"
    assert doc["apps"][0]["score"] == 78 and doc["top_tracker_companies"] == {"AdCo": 1}
    cells = list(csv.reader(csv_path.open(encoding="utf-8")))
    assert cells[1][0] == "'=evil" and "ads: ads.t" in cells[1][-1]
    assert sums.exists()

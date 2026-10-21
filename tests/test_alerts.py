import json

import pytest

from lazyios import alerts
from lazyios.alerts import AlertRules, load, parse
from lazyios.privacy import HostRow


def row(domain="sdk.tracker.net", category="analytics", source="sni"):
    return HostRow("App", domain, category, "", 1, 1.0, 1.0, source=source)


def test_default_rules_only_flag_new_trackers_for_apps_with_history():
    rules = AlertRules()
    assert rules.reason(row(), {"api.app.example"}) == "new analytics tracker"
    assert rules.reason(row(), {"sdk.tracker.net"}) is None  # seen before
    assert rules.reason(row(), None) is None  # no history: everything would be "new"
    assert rules.reason(row(category=""), {"x"}) is None


def test_optional_rules_and_watch_list():
    rules = AlertRules(new_tracker=False, tracker=True, new_domain=True, watch=("facebook.com",))
    assert rules.reason(row(), {"sdk.tracker.net"}) == "analytics tracker"
    assert rules.reason(row("cdn.app.example", ""), set()) == "new domain"
    assert rules.reason(row("graph.facebook.com", ""), None) == "watched domain"
    assert rules.reason(row("notfacebook.com", ""), None) is None
    assert rules.reason(row("203.0.113.5", "", "ip"), set()) is None  # bare addresses never


def test_parse_valid_file():
    rules = parse(json.dumps({"tracker": True, "watch": ["Facebook.com.", "facebook.com"]}))
    assert rules == AlertRules(tracker=True, watch=("facebook.com",))


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ("{nope", "not valid JSON"),
        ("[]", "expected a JSON object"),
        (json.dumps({"traker": True}), "unknown keys: traker"),
        (json.dumps({"tracker": "yes"}), "tracker must be true or false"),
        (json.dumps({"watch": "facebook.com"}), "watch must be a list"),
        (json.dumps({"watch": ["[red]x"]}), "is not a domain"),
        (json.dumps({"watch": ["localhost"]}), "is not a domain"),
        (json.dumps({"watch": [1]}), "is not a domain"),
    ],
)
def test_parse_rejects_bad_files(data, message):
    with pytest.raises(ValueError, match=message.replace("[", r"\[")):
        parse(data)


def test_load_falls_back_to_defaults_with_a_reason(tmp_path, monkeypatch):
    assert load(tmp_path) == (AlertRules(), None)
    (tmp_path / "alerts.json").write_text('{"tracker": 1}', encoding="utf-8")
    rules, problem = load(tmp_path)
    assert rules == AlertRules() and "tracker must be true or false" in problem
    monkeypatch.setattr(alerts, "MAX_FILE", 4)
    assert "larger than" in load(tmp_path)[1]

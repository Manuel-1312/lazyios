import pytest

from lazyios.anonymize import Anonymizer, parse_kinds

KEY = b"k" * 32


def anon(*kinds, **kw) -> Anonymizer:
    return Anonymizer(kinds, key=KEY, **kw)


def test_addresses_get_stable_pseudonyms_and_keep_their_ports():
    a = anon("ips")
    out = a.text("192.168.0.204:50000 -> 203.0.113.5:443, again 203.0.113.5")
    assert "203.0.113.5" not in out and "192.168.0.204" not in out
    assert out.count(a.text("203.0.113.5")) == 2  # the same address, the same pseudonym
    assert ":50000 -> " in out and out.split(", again ")[0].endswith(":443")
    v6 = a.text("[2001:db8::7]:443 and fe80::1")
    assert "2001:db8" not in v6 and "fe80::1" not in v6 and v6.startswith("[ip-")


def test_things_that_only_look_like_addresses_stay():
    a = anon("ips", "domains")
    for text in ("2026-10-21T09:52:08.123+02:00", "09:52:08", "version 1.2026.279", "::",
                 "127.0.0.1", "iOS 27.2 (24B5089g)", "12:00:00 50%"):  # fmt: skip
        assert a.text(text) == text


def test_domains_except_the_kept_ones():
    a = anon("domains", keep_domain=lambda d: d.endswith("doubleclick.net"))
    out = a.text("FitTrack -> api.fittrack.example, googleads.g.doubleclick.net")
    assert "fittrack.example" not in out and out.count(".invalid") == 1
    assert "googleads.g.doubleclick.net" in out
    assert a.text("FitTrack") == "FitTrack"  # app names are not domains


def test_identifiers():
    a = anon("ids", identifiers=["Manuel's iPhone", "DEMO00000000", "abc"])
    out = a.text("Manuel's iPhone 00008150-000808590AE2401C serial DEMO00000000 abc")
    assert "Manuel" not in out and "00008150-000808590AE2401C" not in out
    assert "DEMO00000000" not in out
    assert out.endswith(" abc")  # identifiers under 4 characters would hit ordinary words
    uuid = anon("ids").text("00000000-DEMO000000000000")
    assert uuid == "00000000-DEMO000000000000"  # not hex: not a UDID shape


def test_scrub_walks_reports_keys_included():
    a = anon("ips")
    doc = {"rows": [{"remote": "203.0.113.5:443", "bytes": 10}], "203.0.113.9": ("x", 1)}
    out = a.scrub(doc)
    assert out["rows"][0]["bytes"] == 10
    assert "203.0.113" not in str(out)
    assert isinstance(next(iter(v for k, v in out.items() if k != "rows")), tuple)


def test_runs_cannot_be_linked():
    one, two = Anonymizer({"ips"}), Anonymizer({"ips"})  # each with its own random key
    assert one.text("203.0.113.5") != two.text("203.0.113.5")


def test_only_the_chosen_kinds_change():
    text = "app 203.0.113.5 api.example.com"
    assert anon("ips").text(text).endswith("api.example.com")
    assert "203.0.113.5" in anon("domains").text(text)


def test_parse_kinds():
    assert parse_kinds("all") == {"ips", "domains", "ids"}
    assert parse_kinds("ips, ids") == {"ips", "ids"}
    for bad in ("", "ips,emails", "everything"):
        with pytest.raises(ValueError):
            parse_kinds(bad)

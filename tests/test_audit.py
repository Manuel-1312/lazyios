import json
from dataclasses import replace
from datetime import datetime

from lazyios.audit import assess, summary, write_audit
from lazyios.backend import AuditFacts
from lazyios.screens import audit_text

SAFE = AuditFacts(
    "27.2", "24B82", developer_mode=False, passcode=True, activation="Activated",
    wifi_debugging=False, wifi_connections=False, backup_encrypted=True, cloud_backup=True,
    supervised=False, profiles=(),
)  # fmt: skip


def by_id(facts: AuditFacts) -> dict:
    return {c.id: c for c in assess(facts)}


def test_a_careful_setup_needs_no_attention():
    checks = by_id(SAFE)
    assert summary(list(checks.values())) == {"high": 0, "medium": 0, "low": 0, "info": 0}
    assert checks["passcode"].status == checks["profiles"].status == "ok"
    assert "looks like a beta" not in checks["software"].evidence
    assert "wifi-sync" not in checks  # only listed when it is on


def test_risky_values_are_flagged_with_severity_and_action():
    risky = replace(
        SAFE, passcode=False, developer_mode=True, wifi_debugging=True, wifi_connections=True,
        backup_encrypted=False, supervised=True,
        profiles=(("com.corp.mdm", "Corp MDM", "Corp"), ("x.ca", "", "")),
    )  # fmt: skip
    checks = by_id(risky)
    assert (checks["passcode"].status, checks["passcode"].severity) == ("attention", "high")
    assert checks["passcode"].action.startswith("Settings")
    assert checks["developer-mode"].severity == "low"
    assert checks["wifi-debugging"].status == "attention"
    assert checks["wifi-sync"].status == "attention"
    assert checks["backup-encryption"].status == "attention"
    assert "2 installed: Corp MDM (Corp); x.ca" in checks["profiles"].evidence
    assert checks["supervision"].status == "info"
    assert summary(list(checks.values())) == {"high": 1, "medium": 3, "low": 2, "info": 0}


def test_unknown_values_are_not_guessed():
    blank = AuditFacts("27.2", "24B5089g")
    checks = by_id(blank)
    for key in ("passcode", "developer-mode", "backup-encryption", "profiles"):
        assert checks[key].status == "unknown"
    assert "wifi-debugging" not in checks
    assert "looks like a beta" in checks["software"].evidence


def test_never_claims_a_compromise_either_way():
    for facts in (SAFE, AuditFacts("1", "1A1")):
        jail = by_id(facts)["jailbreak"]
        assert jail.status == "unknown" and "nothing in this report is evidence" in jail.why
    text = str(audit_text(assess(SAFE)))
    assert "nothing here proves a compromise or rules one out" in text
    assert "needs attention: nothing" in text


def test_attention_comes_first_in_the_report():
    text = str(audit_text(assess(replace(SAFE, passcode=False))))
    assert text.index("passcode") < text.index("developer mode")
    assert "[high]" in text


def test_export(tmp_path):
    json_path, csv_path, sums = write_audit(
        assess(replace(SAFE, passcode=False)), "iPhone18,1 U1", tmp_path, datetime(2026, 10, 21)
    )
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    assert doc["device"] == "iPhone18,1 U1" and doc["attention"]["high"] == 1
    assert "no system files are read" in doc["scope"]
    assert csv_path.read_text(encoding="utf-8").startswith("id,title,status,severity")
    assert sums.exists()

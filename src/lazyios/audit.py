"""Security audit from what the device reports through its normal interfaces.

Each check says what was read, why it matters and what to do. Nothing here can show that a
device is or is not compromised: lazyios sees no system files, so it never claims either.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .backend import AuditFacts
from .files import Scrub, write_tables

SEVERITIES = ("high", "medium", "low", "info")
_BETA_BUILD = re.compile(r"^\d+[A-Z]\d+[a-z]$")  # seed builds end in a lowercase letter


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    status: str  # ok, attention, info, unknown
    severity: str  # high, medium, low, info: how much it matters when status is attention
    evidence: str
    why: str
    action: str = ""


def _unknown(id: str, title: str, why: str) -> Check:
    return Check(id, title, "unknown", "info", "the device did not answer", why)


def assess(f: AuditFacts) -> list[Check]:
    checks: list[Check] = []
    if f.passcode is None:
        checks.append(_unknown("passcode", "passcode", "a passcode protects the data at rest"))
    elif f.passcode:
        checks.append(
            Check(
                "passcode",
                "passcode",
                "ok",
                "high",
                "PasswordProtected = true",
                "a passcode is set, so the data at rest is protected by it",
            )
        )
    else:
        checks.append(Check(
            "passcode", "passcode", "attention", "high", "PasswordProtected = false",
            "no passcode: anyone holding the phone can unlock it, and data protection classes"
            " that depend on the passcode give no extra protection",
            "Settings > Face ID & Passcode > Turn Passcode On",
        ))  # fmt: skip
    if f.developer_mode is None:
        checks.append(_unknown("developer-mode", "developer mode", "it enables debug services"))
    else:
        checks.append(Check(
            "developer-mode", "developer mode", "attention" if f.developer_mode else "ok", "low",
            f"developer mode = {'on' if f.developer_mode else 'off'}",
            "on, a trusted computer can launch and kill apps, read the process list, simulate"
            " location and network conditions" if f.developer_mode
            else "off: the debug services above are not available",
            "turn it off when you are not developing: Settings > Privacy & Security"
            if f.developer_mode else "",
        ))  # fmt: skip
    if f.wifi_debugging is not None:
        checks.append(Check(
            "wifi-debugging", "debugging over Wi-Fi", "attention" if f.wifi_debugging else "ok",
            "medium", f"EnableWifiDebugging = {str(f.wifi_debugging).lower()}",
            "on, trusted computers on the same network reach the debug services without a"
            " cable" if f.wifi_debugging else "off: debug services need the cable",
            "turn it off in Xcode or Finder (Show this iPhone when on Wi-Fi)"
            if f.wifi_debugging else "",
        ))  # fmt: skip
    if f.wifi_connections:
        checks.append(Check(
            "wifi-sync", "sync over Wi-Fi", "attention", "low", "EnableWifiConnections = true",
            "trusted computers on the same network can reach the phone for sync and backups",
            "turn it off in Finder or iTunes if you do not use it",
        ))  # fmt: skip
    if f.backup_encrypted is None:
        checks.append(_unknown("backup-encryption", "computer backups",
                               "unencrypted backups hold your data in the clear"))  # fmt: skip
    else:
        checks.append(Check(
            "backup-encryption", "computer backups", "ok" if f.backup_encrypted else "attention",
            "medium", f"WillEncrypt = {str(f.backup_encrypted).lower()}",
            "backups made on a computer are encrypted" if f.backup_encrypted
            else "backups made on a computer are not encrypted: whoever gets the backup files"
            " reads messages, photos, health data and more",
            "" if f.backup_encrypted else "Finder or iTunes > Encrypt local backup",
        ))  # fmt: skip
    if f.profiles is None:
        checks.append(_unknown("profiles", "configuration profiles",
                               "profiles can add certificates, VPNs and management"))  # fmt: skip
    elif f.profiles:
        names = "; ".join(f"{n or i} ({o})" if o else (n or i) for i, n, o in f.profiles[:10])
        checks.append(Check(
            "profiles", "configuration profiles", "attention", "medium",
            f"{len(f.profiles)} installed: {names}",
            "a profile can install root certificates (and so read encrypted traffic), route"
            " traffic through a VPN or proxy, or put the phone under remote management",
            "check each one is expected: Settings > General > VPN & Device Management",
        ))  # fmt: skip
    else:
        checks.append(Check("profiles", "configuration profiles", "ok", "medium", "none installed",
                            "no profile adds certificates, VPNs or management"))  # fmt: skip
    if f.supervised:
        checks.append(Check(
            "supervision", "supervision", "info", "info", "IsSupervised = true",
            "the phone is supervised: an organization can apply restrictions and manage it",
            "expected on a work or school phone; ask its administrator otherwise",
        ))  # fmt: skip
    beta = bool(_BETA_BUILD.match(f.build))
    checks.append(Check(
        "software", "iOS version", "info", "info",
        f"iOS {f.version} ({f.build})" + (", build looks like a beta" if beta else ""),
        "lazyios works offline and cannot tell whether a newer version exists"
        + ("; beta builds carry more bugs than releases" if beta else ""),
        "Settings > General > Software Update",
    ))  # fmt: skip
    if f.activation and f.activation != "Activated":
        checks.append(Check("activation", "activation", "info", "info",
                            f"ActivationState = {f.activation}",
                            "the phone is not activated"))  # fmt: skip
    checks.append(Check(
        "pairing", "trusted computers", "info", "info", "this computer is trusted (paired)",
        "every trusted computer can read this kind of information and make backups",
        "to forget all of them: Settings > General > Transfer or Reset iPhone > Reset >"
        " Reset Location & Privacy",
    ))  # fmt: skip
    checks.append(Check(
        "jailbreak", "jailbreak or compromise", "unknown", "info", "not checked",
        "telling would need access to system files that a computer without a jailbreak does"
        " not have; nothing in this report is evidence either way",
    ))  # fmt: skip
    return checks


def summary(checks: list[Check]) -> dict[str, int]:
    return {
        sev: sum(c.status == "attention" and c.severity == sev for c in checks)
        for sev in SEVERITIES
    }


def report_rows(checks: list[Check]) -> list[dict[str, Any]]:
    return [
        {
            "id": c.id,
            "title": c.title,
            "status": c.status,
            "severity": c.severity,
            "evidence": c.evidence,
            "why": c.why,
            "action": c.action,
        }
        for c in checks
    ]


def write_audit(
    checks: list[Check],
    device: str,
    folder: Path,
    now: datetime | None = None,
    scrub: Scrub | None = None,
) -> tuple[Path, Path, Path]:
    now = now or datetime.now()
    data = report_rows(checks)
    document = {
        "generated": now.astimezone().isoformat(timespec="seconds"),
        "device": device,
        "attention": summary(checks),
        "scope": "values the device reports to a trusted computer; no system files are read",
        "checks": data,
    }
    return write_tables(
        folder / f"audit-{now.strftime('%Y%m%d-%H%M%S-%f')[:-3]}",
        document,
        list(data[0]) if data else [],
        (list(r.values()) for r in data),
        scrub=scrub,
    )

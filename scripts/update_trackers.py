"""Rebuild src/lazyios/data/trackers.json from the AdGuard companiesdb.

Only the AdGuard-authored files (source/trackers.json, source/companies.json) are used: the
merged dist/trackers.json also carries whotracks.me data, which is not CC BY-SA.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/AdguardTeam/companiesdb/main/source/"
OUT = Path(__file__).resolve().parent.parent / "src" / "lazyios" / "data" / "trackers.json"
HOST = re.compile(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+")

# companiesdb category id -> short name shown in the UI
CATEGORIES = {
    0: "media",
    1: "comments",
    2: "support",
    3: "ads",
    4: "ads",
    5: "essential",
    6: "analytics",
    7: "social",
    8: "misc",
    9: "cdn",
    10: "hosting",
    11: "unknown",
    12: "extensions",
    13: "email",
    14: "consent",
    15: "telemetry",
    101: "analytics",
}

# Mobile SDK endpoints, curated by hand for lazyios (not part of the AdGuard data).
EXTRA = {
    "app-measurement.com": ("analytics", "Google"),
    "firebaseinstallations.googleapis.com": ("analytics", "Google"),
    "firebase-settings.crashlytics.com": ("analytics", "Google"),
    "crashlytics.com": ("analytics", "Google"),
    "doubleclick.net": ("ads", "Google"),
    "googleadservices.com": ("ads", "Google"),
    "googlesyndication.com": ("ads", "Google"),
    "google-analytics.com": ("analytics", "Google"),
    "graph.facebook.com": ("ads", "Meta"),
    "connect.facebook.net": ("ads", "Meta"),
    "facebook.com": ("social", "Meta"),
    "facebook.net": ("social", "Meta"),
    "mixpanel.com": ("analytics", "Mixpanel"),
    "adjust.com": ("analytics", "Adjust"),
    "adjust.io": ("analytics", "Adjust"),
    "branch.io": ("analytics", "Branch"),
    "braze.com": ("analytics", "Braze"),
    "appsflyer.com": ("analytics", "AppsFlyer"),
    "amplitude.com": ("analytics", "Amplitude"),
    "segment.io": ("analytics", "Segment"),
    "segment.com": ("analytics", "Segment"),
    "sentry.io": ("analytics", "Sentry"),
    "onesignal.com": ("analytics", "OneSignal"),
    "kochava.com": ("analytics", "Kochava"),
    "singular.net": ("analytics", "Singular"),
    "unity3d.com": ("ads", "Unity"),
    "applovin.com": ("ads", "AppLovin"),
    "ironsrc.com": ("ads", "ironSource"),
    "admob.com": ("ads", "Google"),
    "moatads.com": ("ads", "Oracle"),
    "criteo.com": ("ads", "Criteo"),
    "taboola.com": ("ads", "Taboola"),
    "outbrain.com": ("ads", "Outbrain"),
    "datadoghq.com": ("telemetry", "Datadog"),
    "newrelic.com": ("telemetry", "New Relic"),
    "bugsnag.com": ("telemetry", "Bugsnag"),
    "instabug.com": ("telemetry", "Instabug"),
    "icloud.com": ("essential", "Apple"),
    "apple.com": ("essential", "Apple"),
    "mzstatic.com": ("cdn", "Apple"),
    "cloudfront.net": ("cdn", "Amazon"),
    "akamaized.net": ("cdn", "Akamai"),
    "fastly.net": ("cdn", "Fastly"),
}


# Reclassified after the build: push, messaging, device management and plain infrastructure
# that the source files label as tracking.
OVERRIDES = {
    **{d: ("support", "Google") for d in (
        "fcm.googleapis.com", "firebase.googleapis.com", "firebaseapp.com", "firebase.com",
        "android.com",
    )},
    **{d: ("misc", "Yahoo") for d in (
        "yahoo.com", "yahoo.net", "yahooapis.com", "yahoodns.net", "yahooinc.com",
    )},
    "markmonitor.com": ("misc", "MarkMonitor"),
    "taobao.com": ("misc", "Alibaba"),
    "realestate.com.au": ("misc", "REA Group"),
    "rea-group.com": ("misc", "REA Group"),
    "is.com": ("misc", "Unity"),
    **{d: ("support", "Samsung") for d in (
        "samsungapps.com", "findmymobile.samsung.com", "samsung-omc.com", "samsungdm.com",
        "samsungdms.net", "samsungdmroute.com", "samsungdiroute.net",
    )},
}  # fmt: skip


def fetch(name: str) -> dict:
    with urllib.request.urlopen(BASE + name, timeout=30) as response:  # noqa: S310
        return json.load(response)


def build() -> dict[str, list[str]]:
    trackers = fetch("trackers.json")
    companies = fetch("companies.json")["companies"]
    own = trackers["trackers"]
    out: dict[str, list[str]] = {}
    for domain, key in trackers["trackerDomains"].items():
        tracker = own.get(key)  # entries defined only in whotracks.me are left out
        domain = domain.lower().rstrip(".")
        if tracker is None or not HOST.fullmatch(domain):
            continue
        company = companies.get(tracker.get("companyId") or "", {}).get("name") or tracker["name"]
        out[domain] = [CATEGORIES.get(tracker["categoryId"], "unknown"), company]
    for domain, (category, company) in EXTRA.items():
        out.setdefault(domain, [category, company])
    for domain, (category, company) in OVERRIDES.items():
        out[domain] = [category, company]
    return dict(sorted(out.items()))


def main() -> None:
    data = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        json.dumps(data, separators=(",", ":"), ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"{len(data)} domains, {OUT.stat().st_size} bytes -> {OUT}")


if __name__ == "__main__":
    main()

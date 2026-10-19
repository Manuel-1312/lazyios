# Tracker data

`trackers.json` maps a domain to a category and a company.

Source: AdGuard companiesdb, https://github.com/AdguardTeam/companiesdb
(`source/trackers.json` and `source/companies.json`, the AdGuard-authored files).

License: Creative Commons Attribution-ShareAlike 4.0 International,
https://creativecommons.org/licenses/by-sa/4.0/

Modified: reduced to domain, category and company; category ids renamed to short labels.
The whotracks.me data that companiesdb merges into `dist/trackers.json` is not used.

A few mobile SDK endpoints were added by hand by the lazyios authors (listed in
`scripts/update_trackers.py`). They are facts about public hostnames, not taken from any list.

Further modification: an `OVERRIDES` table in `scripts/update_trackers.py` reclassifies push,
messaging, device-management and plain infrastructure domains (for example
`fcm.googleapis.com`, `yahoo.com`, `samsungapps.com`) as `support` or `misc`, and the `social`
category is not treated as tracking.

Regenerate with `python scripts/update_trackers.py`.

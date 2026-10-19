# lazyios

[![ci](https://github.com/Manuel-1312/lazyios/actions/workflows/ci.yml/badge.svg)](https://github.com/Manuel-1312/lazyios/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/lazyios)](https://pypi.org/project/lazyios/)
[![license](https://img.shields.io/badge/license-GPL--3.0--or--later-blue)](LICENSE)

Like lazygit, but for your iPhone. A keyboard-driven terminal app that talks to an iPhone over USB: read the system log, list and kill processes, launch apps, capture network traffic to a `.pcap`, throttle the network, take screenshots, fake a location, watch FPS. It runs on Windows, macOS and Linux, needs no jailbreak, no Xcode and no admin rights. Built on [Textual](https://github.com/Textualize/textual), using [pymobiledevice3](https://github.com/doronz88/pymobiledevice3) as a library.

![lazyios demo: logs, a live packet capture and the privacy tab](docs/demo.gif)

## Who is your iPhone talking to?

See which apps on your iPhone talk to which servers and trackers, live, without a proxy, a VPN profile or a jailbreak.

Press `space` to start a capture, use your phone, then open the `privacy` tab: every app gets one row per domain it contacted, with the tracker category and company when the domain is a known tracker, plus flows, bytes and last activity. Export the session as JSON and CSV with `e`.

How it works: the capture is the phone's own packet stream over USB. Domains come from the DNS answers the phone receives and from the server name in each TLS handshake; both are matched to the app that owns the connection. Tracker data is the [AdGuard companiesdb](https://github.com/AdguardTeam/companiesdb).

iOS has its own App Privacy Report (Settings > Privacy & Security) that logs domains per app after the fact. lazyios adds live per-connection data (bytes, flows, IPs) and an export you can diff, grep or open in a spreadsheet.

Limits, said plainly:

- Apps that use encrypted DNS, iCloud Private Relay, or QUIC without a visible DNS lookup show up as bare IP addresses.
- The capture only sees the phone's own traffic, and only while it is plugged in.
- Names come from unencrypted DNS answers and the TLS server name (SNI) seen on the wire. Neither is authenticated, so treat them as hints. DNS over HTTPS/TLS, Encrypted Client Hello, QUIC and iCloud Private Relay are invisible, and those rows fall back to the bare IP.
- "Tracker" means an ads, analytics or telemetry endpoint according to AdGuard's companiesdb. It is not a verdict on the app.

Tracker data: AdGuard companiesdb, [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/), reduced to domain, category and company (see `src/lazyios/data/TRACKERS-LICENSE.md`).

## Features

- overview: device info, battery (level, cycles, charger), developer mode state
- logs: live syslog with level colors, filter, pause, bounded buffer
- processes: list, filter, kill (with confirmation), launch by bundle id
- apps: installed user apps, launch with enter
- network: packet capture to a real `.pcap` with a live table, open in Wireshark; network, thermal and GPU conditions
- privacy: which app talks to which domain, known trackers flagged, filter, sort, JSON and CSV export
- tools: screenshot, location simulation, FPS sparkline
- `--demo` runs on fake data, no device needed

## Install

Easiest first.

**1. Download a binary.** Grab `lazyios-windows-x64.exe`, `lazyios-macos-arm64` or `lazyios-linux-x64` from the [Releases](https://github.com/Manuel-1312/lazyios/releases) page and run it from a terminal. Nothing else to install (on macOS and Linux run `chmod +x` first).
The Windows exe is not code-signed, so SmartScreen may say "Windows protected your PC": click *More info*, then *Run anyway*. To check the download, compare its hash with the `SHA256SUMS` file from the same release:

```
Get-FileHash lazyios-windows-x64.exe -Algorithm SHA256   # PowerShell
sha256sum -c SHA256SUMS --ignore-missing                  # Linux
shasum -a 256 -c SHA256SUMS --ignore-missing              # macOS
```

**2. One-liner.** Installs [uv](https://docs.astral.sh/uv/) if needed, then lazyios. No admin or sudo.

```
irm https://raw.githubusercontent.com/Manuel-1312/lazyios/main/install.ps1 | iex      # Windows
curl -LsSf https://raw.githubusercontent.com/Manuel-1312/lazyios/main/install.sh | sh  # macOS, Linux
```

**3. From PyPI.**

```
uv tool install --python 3.12 lazyios
pipx install --python python3.12 lazyios
```

Use Python 3.12: on newer versions a few pymobiledevice3 dependencies have no prebuilt wheels yet and pip tries to compile them.

## Requirements

- An iPhone that trusts this computer. Developer Mode must be on for processes, conditions and tools.
- Windows: the Apple Devices app (`winget install 9NP83LWLPZ9K -s msstore`) or iTunes, for usbmuxd. If Apple Devices is installed but not running, lazyios starts it for you.
- macOS: nothing extra.
- Linux: the `usbmuxd` package (`sudo apt install usbmuxd` or your distro's equivalent).
- Python 3.10+ only for the pip/uv installs.

## Usage

```
lazyios [--udid UDID] [--out DIR] [--demo]
lazyios --version
lazyios --selftest
python -m lazyios
```

Captures, screenshots and privacy reports go to `~/lazyios/captures`, `~/lazyios/screenshots` and `~/lazyios/reports` unless `--out` says otherwise.

| key | action |
| --- | --- |
| `1`-`7` | switch tab |
| `q` | quit |
| `?` | help |
| `/` | focus filter (`esc` to leave) |
| `r` | refresh |
| `p` / `c` | logs: pause, clear |
| `k` / `l` | processes: kill, launch by bundle id |
| `enter` | apps: launch; network: apply condition; tools: set location |
| `space` / `o` | network: start/stop capture, open it |
| `space` | privacy: start/stop the same capture |
| `s` / `t` | privacy: cycle sort, trackers only |
| `e` / `o` | privacy: export a report, open it |
| `x` | clear condition (network) or location (tools) |
| `s` / `o` | tools: screenshot, open it |
| `l` / `f` | tools: edit coordinates, start/stop FPS |

## Troubleshooting

**iPhone not detected on Windows.** Install Apple Devices from the Microsoft Store (or iTunes), plug the phone in with a data cable and unlock it. If the cable only charges, try another one.

**Failed to connect to usbmuxd.** usbmuxd is the service that talks to the phone over USB. On Windows open the Apple Devices app once (lazyios also tries to start it); with iTunes, start the "Apple Mobile Device Service" in `services.msc`. On Linux install the `usbmuxd` package and replug. macOS has it built in.

**"Trust This Computer" prompt.** Unlock the phone and tap *Trust*, then enter your passcode. Press `r` in lazyios to retry. If the prompt never shows, unplug, replug and unlock first.

**Developer Mode missing in Settings.** The switch under Settings > Privacy & Security stays hidden until the phone is asked to show it. With the phone plugged in and unlocked, run `uvx --python 3.12 pymobiledevice3 amfi reveal-developer-mode`, then turn Developer Mode on in Settings and let the phone restart.

**iOS 17+ tunnel / no admin.** Newer iOS versions need a tunnel for developer services. lazyios builds it inside the process with a userspace network stack, so no root or admin is needed. It opens on first use and takes a few seconds.

**Launching an app does nothing.** The phone has to be unlocked.

**"Microsoft Visual C++ 14.0 or greater is required" while installing.** pip picked a Python version that some dependencies have no prebuilt wheels for. Install with Python 3.12 (`uv tool install --python 3.12 ...`) or use the standalone binary.

## How it compares

libimobiledevice and `idevicesyslog` are single-purpose command line tools, and Xcode's Devices window needs a Mac. lazyios puts the common bits (logs, processes, apps, packet capture, network conditions) in one interactive terminal app that runs anywhere Python or the standalone binary does.

## Notes

- Capture files and privacy reports contain your traffic metadata (domains, IPs). Treat them as sensitive.
- An active condition is shown in red in the status line. Conditions and simulated location are cleared when you quit.

## Credits

[pymobiledevice3](https://github.com/doronz88/pymobiledevice3) by doronz88 and contributors does all the device work. The interface is [Textual](https://github.com/Textualize/textual).

## License

Copyright (C) 2026 Manuel Sánchez

GPL-3.0-or-later, see [LICENSE](LICENSE).

"""Logo, dividers and bars."""

LOGO = """\
 ██▓    ▄▄▄      ▒███████▒▓██   ██▓ ██▓ ▒█████    ██████
▓██▒   ▒████▄    ▒ ▒ ▒ ▄▀░ ▒██  ██▒▓██▒▒██▒  ██▒▒██    ▒
▒██░   ▒██  ▀█▄  ░ ▒ ▄▀▒░   ▒██ ██░▒██▒▒██░  ██▒░ ▓██▄
▒██░   ░██▄▄▄▄██   ▄▀▒   ░  ░ ▐██▓░░██░▒██   ██░  ▒   ██▒
░██████▒▓█   ▓██▒▒███████▒  ░ ██▒▓░░██░░ ████▓▒░▒██████▒▒
░ ▒░▓  ░▒▒   ▓▒█░░▒▒ ▓░▒░▒   ██▒▒▒ ░▓  ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
░ ░ ▒  ░ ▒   ▒▒ ░░░▒ ▒ ░ ▒ ▓██ ░▒░  ▒ ░  ░ ▒ ▒░ ░ ░▒  ░ ░
  ░ ░    ░   ▒   ░ ░ ░ ░ ░ ▒ ▒ ░░   ▒ ░░ ░ ░ ▒  ░  ░  ░
    ░  ░     ░  ░  ░ ░     ░ ░      ░      ░ ░        ░
                 ░         ░ ░"""

LOGO_COMPACT = "▓▒░ lazyios ░▒▓"
TAG = ":: iphone over usb :: no jailbreak :: no admin ::"

LOGO_WIDTH = max(len(line) for line in LOGO.splitlines())
LOGO_HEIGHT = len(LOGO.splitlines())


def header(title: str) -> str:
    return f"▓▒░ {title} ░▒▓"


def rule(title: str = "", width: int = 60) -> str:
    """Divider like ─┤ logs ├─────."""
    head = f"─┤ {title} ├" if title else ""
    return head + "─" * max(0, width - len(head))


def bar(percent: int, width: int = 10) -> str:
    """Shade-character level bar."""
    filled = round(max(0, min(100, percent)) * width / 100)
    return "▓" * filled + "░" * (width - filled)

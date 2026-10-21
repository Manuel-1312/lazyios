"""Optional anonymization of exported reports (--anonymize ips,domains,ids).

Pseudonyms are keyed hashes with a random key made at start: the same address gets the same
pseudonym across one run's reports, so they can still be compared, but runs cannot be linked.
Known tracker domains are kept: they are public and are what a privacy report is about.
Only exports change; the screen, captures (pcap) and session history stay as they are.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Callable, Iterable
from typing import Any

KINDS = ("ips", "domains", "ids")
_IPV4 = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?![\w.])")
_IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_HOST = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}(?![\w-])")
# UDIDs: 8-16 hex (new devices) and 40 hex (older), plus UUID-shaped ones
_UDID = re.compile(
    r"\b(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}|[0-9A-Fa-f]{40}|"
    r"[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})\b"
)


def parse_kinds(text: str) -> frozenset[str]:
    """'ips,domains' -> kinds; 'all' -> every kind. Raises ValueError for unknown ones."""
    wanted = {k.strip().lower() for k in text.split(",") if k.strip()}
    if wanted == {"all"}:
        return frozenset(KINDS)
    if not wanted or wanted - set(KINDS):
        raise ValueError(f"choose from {', '.join(KINDS)} or all")
    return frozenset(wanted)


class Anonymizer:
    def __init__(
        self,
        kinds: Iterable[str],
        keep_domain: Callable[[str], bool] = lambda _: False,
        identifiers: Iterable[str] = (),
        key: bytes | None = None,
    ) -> None:
        self.kinds = frozenset(kinds)
        self.keep_domain = keep_domain
        self.identifiers = sorted({i for i in identifiers if len(i) >= 4}, key=len, reverse=True)
        self._key = key or os.urandom(32)

    def _tag(self, kind: str, value: str) -> str:
        return hmac.new(
            self._key, f"{kind}\x00{value.lower()}".encode(), hashlib.sha256
        ).hexdigest()[:10]

    def _ip(self, m: re.Match[str]) -> str:
        text = m.group(0)
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text  # looked like an address but is not one (a time, a version)
        if ip.is_loopback or ip.is_unspecified:
            return text
        return f"ip-{self._tag('ip', text)}"

    def _host(self, m: re.Match[str]) -> str:
        name = m.group(0)
        if self.keep_domain(name.lower()):
            return name
        return f"host-{self._tag('host', name)}.invalid"

    def text(self, value: str) -> str:
        if "ids" in self.kinds:
            for ident in self.identifiers:  # longest first, so a name inside another goes later
                value = value.replace(ident, f"id-{self._tag('id', ident)}")
            value = _UDID.sub(lambda m: f"id-{self._tag('id', m.group(0))}", value)
        if "ips" in self.kinds:
            value = _IPV4.sub(self._ip, value)
            value = _IPV6.sub(self._ip, value)
        if "domains" in self.kinds:
            value = _HOST.sub(self._host, value)
        return value

    def scrub(self, value: Any) -> Any:
        """Every string inside dicts, lists and tuples, keys included."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, dict):
            return {self.scrub(k): self.scrub(v) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return type(value)(self.scrub(v) for v in value)
        return value

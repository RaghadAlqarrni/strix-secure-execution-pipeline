"""
Name resolution covering BOTH address families.

Two rules that this module exists to make explicit:

  1. Every lookup asks for A **and** AAAA. A resolver that only asks for A
     cannot enforce policy on the addresses a dual-stack client would actually
     use.

  2. ABSENCE of a family is not DENIAL of a family. If a name has no AAAA
     record, using its A record is normal. If a name HAS AAAA records and any of
     them is refused by policy, the whole request is refused — the PDP must not
     quietly fall back to IPv4. That distinction lives in pdp.py; this module's
     job is to report, faithfully and per-family, what the zone actually said.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field


@dataclass
class Resolution:
    host: str
    v4: list[str] = field(default_factory=list)
    v6: list[str] = field(default_factory=list)
    source: str = "system"
    error: str | None = None

    @property
    def empty(self) -> bool:
        return not self.v4 and not self.v6

    def all_answers(self) -> list[str]:
        return [*self.v6, *self.v4]


class Resolver:
    """System resolver (production path)."""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def resolve(self, host: str) -> Resolution:
        res = Resolution(host=host, source="system")
        old = socket.getdefaulttimeout()
        socket.setdefaulttimeout(self.timeout)
        try:
            try:
                infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            except socket.gaierror as exc:
                res.error = f"dns_error:{exc.errno}"
                return res
            for fam, _, _, _, sockaddr in infos:
                addr = sockaddr[0]
                if fam == socket.AF_INET6 and addr not in res.v6:
                    res.v6.append(addr)
                elif fam == socket.AF_INET and addr not in res.v4:
                    res.v4.append(addr)
            return res
        finally:
            socket.setdefaulttimeout(old)


class StaticResolver:
    """Deterministic zone used by the acceptance suites.

    Zone entries may be:
      ``{"v4": [...], "v6": [...]}``               — stable
      ``{"sequence": [ {...}, {...} ]}``           — successive lookups differ,
        which models a TTL flip / rebinding attack without a hostile nameserver.
    """

    def __init__(self, zone: dict) -> None:
        self.zone = zone
        self._calls: dict[str, int] = {}

    def resolve(self, host: str) -> Resolution:
        entry = self.zone.get(host)
        if entry is None:
            return Resolution(host=host, source="zone", error="nxdomain")
        if "sequence" in entry:
            n = self._calls.get(host, 0)
            self._calls[host] = n + 1
            seq = entry["sequence"]
            entry = seq[min(n, len(seq) - 1)]
        return Resolution(host=host, source="zone",
                          v4=list(entry.get("v4", [])), v6=list(entry.get("v6", [])))

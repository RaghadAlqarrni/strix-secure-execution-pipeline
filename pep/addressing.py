"""
Address-family-aware canonicalization and classification.

This module is the single place where "what address is this, and may we talk to
it" is decided. IPv4 and IPv6 go through the SAME code path — there is no
v4-only branch anywhere, because that is exactly how address-family bypasses get
introduced.

Design rules enforced here:
  * IPv4-mapped IPv6 (``::ffff:a.b.c.d``) is UNWRAPPED and judged by the
    embedded IPv4 address. Otherwise a blocked IPv4 could be smuggled past an
    IPv4-only check by re-encoding it as IPv6.
  * Other v4-in-v6 embeddings (6to4 ``2002::/16``, Teredo ``2001::/32``,
    NAT64 ``64:ff9b::/96``) are likewise unwrapped and judged by the embedded v4.
  * Deny decisions are made on address CLASS, not on a blocklist of literals.
  * Anything unparseable, ambiguous, or unrecognised is DENIED.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Literal

Family = Literal["ipv4", "ipv6"]

# v4-in-v6 embeddings that must be judged by their embedded IPv4 address.
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_ULA = ipaddress.ip_network("fc00::/7")


@dataclass(frozen=True)
class Pin:
    """A destination bound for the LIFETIME of one connection.

    The tuple is (family, ip, port). Once a connection is pinned, nothing may
    re-resolve it or switch address family. Carrying the family explicitly is
    what makes "no silent v6 -> v4 fallback" checkable rather than implied.
    """

    family: Family
    ip: str
    port: int

    def as_tuple(self) -> tuple[str, str, int]:
        return (self.family, self.ip, self.port)

    def __str__(self) -> str:
        host = f"[{self.ip}]" if self.family == "ipv6" else self.ip
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Verdict:
    ok: bool
    reason: str
    family: Family | None = None
    effective_ip: str | None = None   # post-unwrap address actually judged


def family_of(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Family:
    return "ipv4" if ip.version == 4 else "ipv6"


def unwrap_embedded_v4(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str | None]:
    """Return (address_to_judge, embedding_kind).

    An IPv6 address that carries an IPv4 address inside it is judged by that
    IPv4 address. Returns the original address and None when there is no
    embedding.
    """
    if ip.version != 6:
        return ip, None
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return mapped, "ipv4_mapped"
    sixto4 = getattr(ip, "sixtofour", None)
    if sixto4 is not None:
        return sixto4, "6to4"
    teredo = getattr(ip, "teredo", None)
    if teredo is not None:
        # teredo -> (server, client); the client address is the real endpoint
        return teredo[1], "teredo"
    if ip in _NAT64:
        embedded = ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
        return embedded, "nat64"
    return ip, None


def classify(ip_str: str, *, exemptions: frozenset[str] | set[str] = frozenset()) -> Verdict:
    """Decide whether an address may be a destination.

    ``exemptions`` lists literal addresses permitted despite being private —
    used for lab/internal targets that are explicitly authorized. It never
    exempts loopback, link-local, or unspecified addresses.
    """
    try:
        raw = ipaddress.ip_address(ip_str)
    except ValueError:
        return Verdict(False, "malformed_ip")

    judged, embedding = unwrap_embedded_v4(raw)
    fam = family_of(raw)                      # family of the address as given
    eff = str(judged)

    def deny(why: str) -> Verdict:
        tag = f"{why}_via_{embedding}" if embedding else why
        return Verdict(False, tag, fam, eff)

    # Classes that are never permitted, in EITHER family, and never exemptible.
    if judged.is_loopback:
        return deny("loopback_denied")
    if judged.is_link_local:
        return deny("link_local_denied")
    if judged.is_unspecified:
        return deny("unspecified_denied")
    if judged.is_multicast:
        return deny("multicast_denied")
    if judged.is_reserved:
        return deny("reserved_denied")

    # Everything above is HARD-denied and can never be exempted.
    # Below: ranges that are denied by default but MAY be exempted when an
    # operator explicitly authorizes that literal address.
    #
    # ULA (fc00::/7) and site-local (fec0::/10) are the IPv6 analogues of
    # RFC1918 and get the SAME treatment. Denying them more harshly than their
    # IPv4 counterpart would be an address-family inconsistency — the exact
    # class of bug this module exists to prevent.
    def exempt_or_deny(kind: str) -> Verdict:
        if ip_str in exemptions or eff in exemptions:
            return Verdict(True, f"{kind}_exempted", fam, eff)
        return deny(f"{kind}_denied")

    if judged.version == 6:
        if judged.is_site_local:                        # fec0::/10, deprecated
            return exempt_or_deny("site_local")
        if judged in _ULA:                              # fc00::/7
            return exempt_or_deny("unique_local")

    if judged.is_private:
        return exempt_or_deny("private")

    if embedding:
        # A public IPv4 smuggled inside IPv6 is still a family switch the policy
        # never authorized; surface it rather than quietly allowing it.
        return Verdict(True, f"public_ok_via_{embedding}", fam, eff)
    return Verdict(True, "public_ok", fam, eff)


def canonical_host(raw: str) -> str | None:
    """Canonicalize an authority component to a comparable form.

    Handles both families and both literal forms:
      ``EXAMPLE.COM.`` -> ``example.com``
      ``[2001:DB8::1]`` -> ``2001:db8::1``  (compressed, lowercase)
      ``0177.0.0.1``    -> rejected (ambiguous IPv4 encoding)
    Returns None when the value cannot be represented unambiguously.
    """
    if not raw:
        return None
    h = raw.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    h = h.rstrip(".")
    if not h or "/" in h or " " in h or "\\" in h:
        return None

    # IPv6 literal -> normalize via the address type (compresses, lowercases)
    if ":" in h:
        try:
            return str(ipaddress.ip_address(h))
        except ValueError:
            return None

    # IPv4 literal -> only accept the unambiguous dotted-quad form. Octal/hex/
    # integer encodings (0177.0.0.1, 0x7f.1, 2130706433) are rejected outright
    # rather than normalized, since acceptance would widen the parser surface.
    if h and all(c.isdigit() or c == "." for c in h):
        parts = h.split(".")
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            if any(len(p) > 1 and p[0] == "0" for p in parts):
                return None                     # leading zero => octal ambiguity
            try:
                return str(ipaddress.IPv4Address(h))
            except ValueError:
                return None
        return None                             # 3-part / integer forms rejected

    try:
        return h.encode("idna").decode("ascii")
    except Exception:
        try:
            h.encode("ascii")
        except Exception:
            return None
        return h


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

"""
Policy Decision Point — the single decision path for both address families.

The whole point of this module is that there is exactly ONE ``decide()``. IPv4
and IPv6 differ only as data (which family a Pin carries), never as control
flow, so an address-family bypass cannot hide in an unvisited branch.

Decision order (any failure is terminal — DEFAULT DENY):
    kill switch -> program identity -> authorization record -> budgets
    -> canonicalization -> IP-literal policy -> scope -> port -> CONNECT/method
    -> resolve (A + AAAA) -> validate EVERY answer in BOTH families
    -> family selection (absence != denial) -> pin -> credential binding
"""

from __future__ import annotations

import ipaddress
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from .addressing import Family, Pin, canonical_host, classify, is_ip_literal
from .resolver import Resolution


@dataclass
class Decision:
    allow: bool
    reason: str
    pin: Pin | None = None
    secret: str | None = None
    program_id: str | None = None
    resolution: Resolution | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class Budgets:
    """Thread-safe hierarchical counters. Exhaustion halts that scope.

    RESERVE IS ATOMIC, AND THAT IS THE WHOLE POINT.

    The previous design exposed would_exceed() and charge() as separate
    lock-taking calls. Each was individually thread-safe, and the pair was not:
    the PDP checked the cap, then spent ~100 lines on DNS resolution, address
    classification, family selection and credential validation, then charged.
    Every concurrent request cleared the cap before any of them incremented it.

    Measured on the shipped code: cap = 10, 64 concurrent decide() calls,
    64 ALLOWED — an overshoot of 54. The effective ceiling was cap +
    concurrency, i.e. cap + PEP_MAX_CONNECTIONS - 1.

    A budget that can be exceeded by the number of threads you throw at it is
    not a budget. This class now exposes ONE mutating operation that checks
    every cap and increments every counter under a single lock, or does
    neither. There is no way to spell the race any more.
    """

    def __init__(self) -> None:
        self._n: dict[str, int] = {}
        self._lock = threading.Lock()

    def reserve(self, specs: list[tuple[str, int | None]]) -> str | None:
        """Atomically check ALL caps and increment ALL counters, or do nothing.

        Returns None on success, or the key whose cap would have been exceeded.
        All-or-nothing: a partial reservation would let one scope be charged for
        a request another scope refused.
        """
        with self._lock:
            for key, cap in specs:
                if cap is not None and self._n.get(key, 0) >= cap:
                    return key
            for key, _cap in specs:
                self._n[key] = self._n.get(key, 0) + 1
        return None

    def peek(self, key: str) -> int:
        """Read-only. Never use this to decide whether to allow — that decision
        must go through reserve(), or the race returns."""
        with self._lock:
            return self._n.get(key, 0)

    def snapshot(self) -> dict[str, int]:
        with self._lock:
            return dict(self._n)


class PDP:
    def __init__(self, policy_provider, resolver, kill_file: str, budgets: Budgets | None = None):
        self._policy_provider = policy_provider   # callable -> dict (re-read = hot reload)
        self._resolver = resolver
        self._kill_file = kill_file
        self.budgets = budgets or Budgets()

    # ------------------------------------------------------------------ helpers
    def _program_for_source(self, src_ip: str, policy: dict) -> tuple[str | None, dict | None]:
        try:
            src = ipaddress.ip_address(src_ip)
        except ValueError:
            return None, None

        # DUAL-STACK LISTENER CANONICALIZATION.
        #
        # With the PEP bound to :: (IPV6_V6ONLY=0), an IPv4 peer is reported by
        # the kernel as ::ffff:a.b.c.d. Without this unwrap it matches no v4
        # CIDR, every IPv4 source resolves to NO_PROGRAM_FOR_SOURCE, and the
        # whole IPv4 suite fails closed.
        #
        # ONLY ipv4_mapped is unwrapped here, and that restriction is a security
        # decision, not an oversight. ipv4_mapped is produced by the LOCAL
        # KERNEL to describe the transport of an accepted connection — it is not
        # content the peer chose. 6to4, Teredo and NAT64 encodings are the
        # opposite: they are address CONTENT. The sandbox holds NET_ADMIN and
        # NET_RAW, so it can craft source addresses; unwrapping those forms here
        # would let a peer on the v6 network present an address whose embedded
        # IPv4 falls inside another program's CIDR and be mapped to that
        # program. addressing.unwrap_embedded_v4() unwraps all four forms
        # deliberately — that is correct for DESTINATIONS, where the question is
        # "what will this actually reach". It is wrong for SOURCES, where the
        # question is "who is this", so it is not used here.
        if src.version == 6:
            mapped = getattr(src, "ipv4_mapped", None)
            if mapped is not None:
                src = mapped

        for cidr, pid in (policy.get("networks") or {}).items():
            try:
                if src in ipaddress.ip_network(cidr):
                    return pid, (policy.get("programs") or {}).get(pid)
            except ValueError:
                continue
        return None, None

    @staticmethod
    def _in_scope(host: str, allow: list[str], deny: list[str]) -> bool:
        def match(pat: str) -> bool:
            p = pat.strip().lower().rstrip(".")
            if p.startswith("*."):
                suffix = p[1:]
                return host.endswith(suffix) and host.count(".") >= p.count(".")
            return host == p
        if any(match(d) for d in deny):
            return False
        if not allow:                    # empty allowlist denies, explicitly
            return False
        return any(match(a) for a in allow)

    # ------------------------------------------------------------------- decide
    def decide(self, *, src_ip: str, authority: str, port: int, method: str,
               session: str = "", asset: str = "", cred_id: str = "",
               pin: Pin | None = None) -> Decision:
        """One decision, both families.

        ``pin`` carries a bound established earlier in the SAME connection.
        Supplying it suppresses resolution entirely: one connection resolves
        once and stays bound to (family, ip, port) for its whole life.
        """
        try:
            policy = self._policy_provider()
        except Exception as exc:                       # fail closed
            return Decision(False, f"POLICY_UNAVAILABLE:{type(exc).__name__}")

        if os.path.exists(self._kill_file):
            return Decision(False, "KILL_SWITCH_ACTIVE")

        program_id, program = self._program_for_source(src_ip, policy)
        if program is None:
            return Decision(False, "NO_PROGRAM_FOR_SOURCE")

        rec = program.get("authorization") or {}
        for k in ("program_id", "verified_by", "verified_at", "expires_at", "status"):
            if k not in rec:
                return Decision(False, "AUTHORIZATION_INCOMPLETE", program_id=program_id)
        if rec.get("status") != "active":
            return Decision(False, f"AUTHORIZATION_STATUS_{rec['status']}", program_id=program_id)
        try:
            if float(rec["expires_at"]) <= time.time():
                return Decision(False, "AUTHORIZATION_EXPIRED", program_id=program_id)
        except (TypeError, ValueError):
            return Decision(False, "AUTHORIZATION_MALFORMED", program_id=program_id)

        akey = f"{program_id}/{asset}" if asset else None
        # The budget decision has MOVED TO THE END of this function, where it is
        # taken atomically with the charge. Two consequences, both wanted:
        #   * the race is gone — see Budgets.reserve();
        #   * a denial is now attributable to the control that actually refused.
        #     Previously an out-of-scope host with an exhausted budget returned
        #     BUDGET_EXHAUSTED_PROGRAM, so a test naming one control was answered
        #     by another. Scope, port and method are cheap and now decide first.

        host = canonical_host(authority)
        if host is None:
            return Decision(False, "HOST_NOT_CANONICALIZABLE", program_id=program_id)

        exemptions = set(program.get("private_ip_exemptions") or [])

        if is_ip_literal(host) and host not in set(program.get("explicit_ip_allowlist") or []):
            return Decision(False, "IP_LITERAL_DENIED", program_id=program_id)

        if not self._in_scope(host, program.get("scope_allow") or [],
                              program.get("scope_deny") or []):
            return Decision(False, "OUT_OF_SCOPE", program_id=program_id)

        if port not in (program.get("allowed_ports") or []):
            return Decision(False, "PORT_DENIED", program_id=program_id)

        if method.upper() == "CONNECT":
            if not program.get("allow_connect", False):
                return Decision(False, "CONNECT_DENIED_BY_POLICY", program_id=program_id)
        elif method.upper() not in (program.get("allowed_methods") or []):
            return Decision(False, "METHOD_DENIED", program_id=program_id)

        # ---------------------------------------------------------- destination
        allowed_families: set[str] = set(program.get("allowed_families") or ["ipv4", "ipv6"])

        if pin is not None:
            # Reuse the existing bound verbatim; never re-resolve mid-connection.
            if pin.family not in allowed_families:
                return Decision(False, f"FAMILY_NOT_ALLOWED:{pin.family}", program_id=program_id)
            v = classify(pin.ip, exemptions=exemptions)
            if not v.ok:
                return Decision(False, f"PIN_REJECTED:{v.reason}", program_id=program_id)
            if pin.ip not in set(program.get("authorized_ips") or []):
                return Decision(False, f"IP_NOT_AUTHORIZED:{pin.ip}", program_id=program_id)
            chosen = pin
            resolution = None
        else:
            try:
                resolution = self._resolver.resolve(host)
            except Exception as exc:                   # fail closed
                return Decision(False, f"DNS_FAILURE:{type(exc).__name__}", program_id=program_id)
            if resolution.error or resolution.empty:
                return Decision(False, f"DNS_NO_ANSWER:{resolution.error or 'empty'}",
                                program_id=program_id, resolution=resolution)

            # Validate EVERY answer in BOTH families. One bad answer anywhere
            # poisons the name — a split A/AAAA response must not be usable by
            # picking the half that happens to pass.
            for fam, answers in (("ipv6", resolution.v6), ("ipv4", resolution.v4)):
                for a in answers:
                    v = classify(a, exemptions=exemptions)
                    if not v.ok:
                        return Decision(
                            False, f"DNS_ANSWER_REJECTED:{fam}:{v.reason}:{a}",
                            program_id=program_id, resolution=resolution)

            # Family selection. ABSENCE of a family is not DENIAL of it:
            #   - AAAA present but family disallowed by policy -> DENY (no fallback)
            #   - AAAA absent                                  -> IPv4 is normal
            if resolution.v6 and "ipv6" not in allowed_families:
                return Decision(False, "FAMILY_NOT_ALLOWED:ipv6_present_but_disabled",
                                program_id=program_id, resolution=resolution)
            if resolution.v6:
                chosen_family: Family = "ipv6"
                chosen_ip = resolution.v6[0]
            elif resolution.v4:
                if "ipv4" not in allowed_families:
                    return Decision(False, "FAMILY_NOT_ALLOWED:ipv4",
                                    program_id=program_id, resolution=resolution)
                chosen_family, chosen_ip = "ipv4", resolution.v4[0]
            else:
                return Decision(False, "DNS_NO_USABLE_ANSWER", program_id=program_id,
                                resolution=resolution)

            if chosen_ip not in set(program.get("authorized_ips") or []):
                return Decision(False, f"IP_NOT_AUTHORIZED:{chosen_ip}",
                                program_id=program_id, resolution=resolution)
            chosen = Pin(family=chosen_family, ip=chosen_ip, port=port)

        # ---------------------------------------------------------- credentials
        secret = None
        if cred_id:
            cred = (policy.get("credentials") or {}).get(cred_id)
            if not cred:
                return Decision(False, "UNKNOWN_CREDENTIAL", program_id=program_id)
            if cred.get("program_id") != program_id:
                return Decision(False, "CREDENTIAL_WRONG_PROGRAM", program_id=program_id)
            if cred.get("asset_id") not in (asset, "*"):
                return Decision(False, "CREDENTIAL_WRONG_ASSET", program_id=program_id)
            if host not in (cred.get("destinations") or []):
                return Decision(False, "CREDENTIAL_WRONG_DESTINATION", program_id=program_id)
            secret = cred.get("secret")

        # Charge ONCE PER CONNECTION, not once per decide() call. The gateway
        # calls decide() twice for every request — once for CONNECT, once inside
        # the tunnel with the established pin. Both used to charge, so
        # max_requests=4 admitted only 2 requests. A pin means "this connection
        # was already authorized and already charged"; re-charging it counts the
        # same request twice.
        if pin is None:
            specs: list[tuple[str, int | None]] = [
                (program_id, program.get("max_requests"))]
            if akey:
                specs.append((akey, (program.get("asset_max_requests") or {}).get(asset)))
            exceeded = self.budgets.reserve(specs)
            if exceeded is not None:
                return Decision(False,
                                "BUDGET_EXHAUSTED_ASSET" if exceeded == akey
                                else "BUDGET_EXHAUSTED_PROGRAM",
                                program_id=program_id)
        # Phase 1 lifecycle binding. New policies should carry an explicit,
        # control-issued policy_generation. Historical lab policies fall back to
        # their control-issued authorization timestamp so E1-E9 remain runnable;
        # this fallback is a documented integration limit, not a release claim.
        generation = policy.get("policy_generation")
        if generation in (None, ""):
            generation = f"authorization-verified-at:{rec.get('verified_at', '')}"
        budget_binding = f"program:{program_id}|asset:{asset or 'none'}|reservation:connect"
        return Decision(True, "ALLOW", pin=chosen, secret=secret, program_id=program_id,
                        resolution=resolution,
                        detail={"canonical_host": host,
                                "policy_generation": str(generation),
                                "budget_binding": budget_binding})

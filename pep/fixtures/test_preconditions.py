#!/usr/bin/env python3
"""
PRECONDITION FIXTURES — the class of forgery the evidence battery cannot see.

The 22 evidence fixtures forge ARTIFACTS: audit records, hash chains, run_id
bindings. They ask "can the auditor be lied to about what happened?"

This suite asks a different question: "can a TEST report success when the thing
it was measuring never happened?" That failure mode lives upstream of the
auditor — the artifact is perfectly honest, it just records a conclusion the
test was never entitled to draw.

Every case below is one where the PREREQUISITE IS ABSENT but the raw
observation, taken naively, looks exactly like a successful BLOCK. Each must
resolve to NO_POSITIVE_CONTROL or INCONCLUSIVE — never PROVEN, never PASS.

This is not hypothetical. Before this remediation:
  * tcp6() returned "BLOCKED" for every exception, so B1/B2/B7 could pass with
    no IPv6 stack at all;
  * B7 probed bare fe80::1, which fails with EINVAL for lack of a scope id, and
    read that as enforcement;
  * PP10 accepted any BLOCK, and passed on an OUT_OF_SCOPE denial in a topology
    where rebind.lab was never provisioned.
All three shipped green.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, PEP)

# ipv6_transport reads these at import time; it is never executed here.
os.environ.setdefault("GW6", "fd00::1")
os.environ.setdefault("TGT6", "fd00::2")
os.environ.setdefault("GW_IP", "127.0.0.1")

import ipv6_transport as T                                       # noqa: E402
import pep_client as C                                           # noqa: E402

R: list[tuple[str, str, str, bool]] = []


def _iface_exists(name: str) -> bool:
    import socket as _s
    try:
        _s.if_nametoindex(name)
        return True
    except OSError:
        return False


def check(name: str, got: str, want: str) -> None:
    ok = got == want
    R.append((name, want, got, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name:56} want={want:22} got={got}",
          flush=True)


def main() -> int:
    print("PRECONDITION FIXTURES — a test must not pass when it never ran\n")

    print("-- tcp6(): distinct observations, never a blanket BLOCKED --")
    for obs in ("REACHABLE", "TIMEOUT", "NO_ROUTE", "PERMISSION_DENIED",
                "CONNECTION_REFUSED", "INVALID_ADDRESS", "NO_IPV6_STACK"):
        assert obs in (T.BLOCKING_OBSERVATIONS + T.INCONCLUSIVE_OBSERVATIONS
                       + ("REACHABLE",)), obs
    check("CONNECTION_REFUSED is NOT counted as blocking",
          str(("CONNECTION_REFUSED" in T.BLOCKING_OBSERVATIONS)), "False")
    check("INVALID_ADDRESS is NOT counted as blocking",
          str(("INVALID_ADDRESS" in T.BLOCKING_OBSERVATIONS)), "False")
    check("NO_IPV6_STACK is NOT counted as blocking",
          str(("NO_IPV6_STACK" in T.BLOCKING_OBSERVATIONS)), "False")

    print("\n-- tcp6() errno table (the actual fix for defect (a)) --")
    import errno as _e
    import socket as _sock

    def probe_with(exc):
        """Drive the REAL tcp6() with a specific failure from the real socket."""
        real_gai, real_sock = _sock.getaddrinfo, _sock.socket

        def fake_gai(host, port, *a, **k):
            if isinstance(exc, _sock.gaierror):
                raise exc
            return [(_sock.AF_INET6, _sock.SOCK_STREAM, 6, "", (host, port, 0, 0))]

        class FakeSock:
            def __init__(self, *a, **k):
                if isinstance(exc, OSError) and getattr(exc, "errno", None) == _e.EAFNOSUPPORT:
                    raise exc
            def settimeout(self, t): pass
            def connect(self, sa): raise exc
            def close(self): pass

        _sock.getaddrinfo, _sock.socket = fake_gai, FakeSock
        try:
            return T.tcp6("fd00::1", 443, timeout=1)
        finally:
            _sock.getaddrinfo, _sock.socket = real_gai, real_sock

    for err, want in ((_e.ETIMEDOUT, "TIMEOUT"),
                      (_e.ENETUNREACH, "NO_ROUTE"),
                      (_e.EHOSTUNREACH, "NO_ROUTE"),
                      (_e.ENETDOWN, "LINK_DOWN"),
                      (_e.EACCES, "PERMISSION_DENIED"),
                      (_e.EPERM, "PERMISSION_DENIED"),
                      (_e.ECONNREFUSED, "CONNECTION_REFUSED"),
                      (_e.EINVAL, "INVALID_ADDRESS"),
                      (_e.EAFNOSUPPORT, "NO_IPV6_STACK"),
                      (_e.ECONNRESET, "OTHER:ECONNRESET")):
        check(f"errno {_e.errorcode[err]:<14} -> {want}",
              probe_with(OSError(err, _e.errorcode[err])), want)
    check("socket.timeout            -> TIMEOUT",
          probe_with(_sock.timeout("timed out")), "TIMEOUT")
    check("gaierror                  -> INVALID_ADDRESS",
          probe_with(_sock.gaierror(-2, "Name or service not known")),
          "INVALID_ADDRESS")

    print("\n-- prerequisite ABSENT: every observation must fail closed --")
    for obs in ("TIMEOUT", "NO_ROUTE", "PERMISSION_DENIED", "CONNECTION_REFUSED",
                "INVALID_ADDRESS", "NO_IPV6_STACK", "REACHABLE"):
        check(f"no positive control + {obs}",
              T.enforcement_verdict(obs, control_ok=False), "NO_POSITIVE_CONTROL")

    print("\n-- prerequisite PRESENT: only real blocking observations prove --")
    check("control ok + TIMEOUT (netfilter DROP)",
          T.enforcement_verdict("TIMEOUT", True), "PROVEN")
    check("control ok + NO_ROUTE",
          T.enforcement_verdict("NO_ROUTE", True), "PROVEN")
    check("control ok + REACHABLE -> the boundary leaked",
          T.enforcement_verdict("REACHABLE", True), "FAILED_OPEN")
    check("control ok + CONNECTION_REFUSED (something answered)",
          T.enforcement_verdict("CONNECTION_REFUSED", True),
          "INCONCLUSIVE_CONNECTION_REFUSED")
    check("control ok + INVALID_ADDRESS (malformed probe)",
          T.enforcement_verdict("INVALID_ADDRESS", True),
          "INCONCLUSIVE_INVALID_ADDRESS")
    check("control ok + NO_IPV6_STACK (probe never ran)",
          T.enforcement_verdict("NO_IPV6_STACK", True),
          "INCONCLUSIVE_NO_IPV6_STACK")

    print("\n-- link-local probes must carry a scope id --")
    # The previous assertion here was ("%" in scoped or scoped == addr) == True,
    # which scoped_ll cannot fail: those are its only two return shapes. A no-op
    # scoped_ll — the pre-remediation behaviour — passed it. Assert the real
    # behaviour instead, against a KNOWN interface.
    import socket as _s
    have_lo = True
    try:
        _s.if_nametoindex("lo")
    except OSError:
        have_lo = False
    check("an already-scoped address is left alone",
          T.scoped_ll("fe80::1%eth0"), "fe80::1%eth0")
    if have_lo:
        # No eth0/eth1 in this environment and NO arbitrary-interface fallback,
        # so the address must come back UNSCOPED — which tcp6() then reports as
        # INVALID_ADDRESS (inconclusive), never as a blocking observation.
        out = T.scoped_ll("fe80::1")
        scoped_here = "%" in out
        check("unscoped when no eth0/eth1 exists (no arbitrary fallback)",
              str(out if not scoped_here else "SCOPED_TO_" + out.split("%")[1]),
              "fe80::1" if not any(_iface_exists(n) for n in ("eth0", "eth1"))
              else "SCOPED_TO_" + out.split("%")[1])
    check("an unscoped link-local is INCONCLUSIVE, never blocking",
          T.enforcement_verdict("INVALID_ADDRESS", True),
          "INCONCLUSIVE_INVALID_ADDRESS")

    print("\n-- blocked_by(): a denial must name the property under test --")
    mk = lambda reason, connect=403: {"reason": reason, "connect": connect,
                                      "status": 0, "err": "", "bytes": 0}
    check("SNI test + SNI_MISMATCH denial",
          C.blocked_by(mk("SNI_MISMATCH"), "SNI_MISMATCH"), "BLOCK")
    check("SNI test + OUT_OF_SCOPE denial (target not provisioned)",
          C.blocked_by(mk("OUT_OF_SCOPE"), "SNI_MISMATCH"),
          "BLOCKED_FOR_OTHER_REASON:OUT_OF_SCOPE")
    check("rebind test + UNKNOWN_CREDENTIAL denial",
          C.blocked_by(mk("UNKNOWN_CREDENTIAL"), "CREDENTIAL_WRONG_PROGRAM"),
          "BLOCKED_FOR_OTHER_REASON:UNKNOWN_CREDENTIAL")
    check("rebind test + DNS_NO_ANSWER denial (host never resolved)",
          C.blocked_by(mk("DNS_NO_ANSWER:NXDOMAIN"), "IP_NOT_AUTHORIZED"),
          "BLOCKED_FOR_OTHER_REASON:DNS_NO_ANSWER")
    check("a denial with NO reason at all",
          C.blocked_by(mk(""), "SNI_MISMATCH"), "BLOCKED_FOR_OTHER_REASON:none")
    check("not blocked at all is reported as-is, not as BLOCK",
          C.blocked_by({"reason": "", "connect": 200, "status": 200,
                        "err": "", "bytes": 1}, "SNI_MISMATCH"), "ALLOW")

    print("\n-- dual-stack listener: source canonicalization must not be a "
          "spoofing vector --")
    sys.path.insert(0, os.path.dirname(PEP))   # pdp.py uses package-relative imports
    from pep import pdp as P                                     # noqa: E402
    policy = {"networks": {"172.31.0.0/24": "prog_a"},
              "programs": {"prog_a": {}}}
    d = P.PDP(lambda: policy, None, "/nonexistent", P.Budgets())

    def prog(src):
        return d._program_for_source(src, policy)[0]

    # Required for the dual-stack listener to work at all: the kernel reports an
    # IPv4 peer on a :: socket as ::ffff:a.b.c.d.
    check("plain IPv4 source maps to its program", str(prog("172.31.0.50")), "prog_a")
    check("v4-mapped source maps to the SAME program",
          str(prog("::ffff:172.31.0.50")), "prog_a")

    # And the part that must NOT be "fixed" along with it. These encodings are
    # address CONTENT, not transport facts, and the sandbox holds NET_ADMIN +
    # NET_RAW. Unwrapping them for source attribution would let a peer on the v6
    # network claim membership of a v4 program by choosing its own address.
    check("6to4 source embedding an in-program v4 is NOT attributed",
          str(prog("2002:ac1f:0032::1")), "None")
    check("NAT64 source embedding an in-program v4 is NOT attributed",
          str(prog("64:ff9b::ac1f:32")), "None")
    check("unrelated v6 source is not attributed",
          str(prog("fd00:9a17:e9:2::50")), "None")

    ok = sum(1 for *_, g in R if g)
    print(f"\n  PRECONDITION FIXTURES: {ok}/{len(R)}")
    return 0 if ok == len(R) else 1


if __name__ == "__main__":
    raise SystemExit(main())

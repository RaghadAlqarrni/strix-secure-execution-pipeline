#!/usr/bin/env python3
"""
IPv6 ACCEPTANCE SUITE — the first mandatory gate for the production PEP.

Two layers, deliberately separated:

  LAYER A — POLICY LOGIC. Exercises the real decision path with IPv6 data. This
            runs anywhere, because deciding *about* an IPv6 address needs no
            IPv6 stack.

  LAYER B — TRANSPORT. Requires a kernel/container runtime with IPv6 actually
            enabled: real sockets, real routes, real TLS over v6.

This suite REFUSES TO PASS when Layer B cannot run. It does not "skip" those
rows, because a skipped row reads like a passed row three months later. If IPv6
is unavailable the overall verdict is NOT_PASSED and the exit status is
non-zero, so no pipeline can mistake IPv4 success for an IPv6 result.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pep.addressing import Pin, canonical_host, classify  # noqa: E402
from pep.pdp import PDP, Budgets  # noqa: E402
from pep.resolver import StaticResolver  # noqa: E402

PUB6 = "2606:4700:4700::1111"
# Routable and NOT in authorized_ips: A20 must be denied by the
# authorization control, not by the address classifier.
PUB6_EVIL = "2001:4860:4860::8888"
PUB4 = "93.184.216.34"
KILL = "/tmp/acc_stop_all"

rows: list[dict] = []


def denied_by(r, *prefixes):
    """A DENY counts only when the PDP's reason names the control under test.

    Every Layer A negative row asserted only ``not r.allow``. A mis-provisioned
    zone key silently turns a class-enforcement proof into a DNS failure that
    still reads green — the same defect PP10 and A20 had. The v4 client suite
    got attribution via blocked_by(); Layer A did not.
    """
    if r.allow:
        return "ALLOW"
    reason = r.reason or ""
    if reason.startswith(tuple(prefixes)):
        return "DENY"
    return f"DENIED_FOR_OTHER_REASON:{reason.split(':')[0] or 'none'}"


def rec(layer, tid, desc, expect, got, detail=""):
    ok = expect == got
    # ``status`` is the machine-readable verdict the Evidence Auditor whitelists
    # on. ``expect``/``got`` stay as human diagnostics. Unknown must never read
    # as pass, so a non-matching row carries its specific failure value.
    rows.append({"layer": layer, "id": tid, "desc": desc, "expect": expect,
                 "got": got, "status": "PROVEN" if ok else str(got),
                 "pass": ok, "detail": str(detail)[:200]})
    mark = "PASS" if ok else "FAIL"
    print(f"  {mark}  {tid:6} {desc:56} expect={expect:12} got={got}", flush=True)


# --------------------------------------------------------------------- LAYER A
def build_pdp() -> PDP:
    zone = {
        "v6pub.lab":    {"v6": [PUB6]},
        "v6loop.lab":   {"v6": ["::1"]},
        "v6ll.lab":     {"v6": ["fe80::1"]},
        "v6ula.lab":    {"v6": ["fc00::1"]},
        "v6mapped.lab": {"v6": ["::ffff:169.254.169.254"]},
        "v6site.lab":   {"v6": ["fec0::1"]},
        "v6to4.lab":    {"v6": ["2002:7f00:0001::1"]},      # 6to4 wrapping 127.0.0.1
        "splitbad6.lab": {"v4": [PUB4], "v6": ["::1"]},      # good A + blocked AAAA
        "splitbad4.lab": {"v6": [PUB6], "v4": ["127.0.0.1"]},  # good AAAA + blocked A
        "v4only.lab":   {"v4": [PUB4]},                      # absence of AAAA is normal
        # The flipped-to address must be PUBLIC and merely UNAUTHORIZED. It was
        # ::1, which classify() rejects as loopback long before the
        # authorized_ips check runs — so A20 was denied by the address
        # classifier and never exercised the rebinding control it names. Same
        # defect PP10 had. PUB6_EVIL is routable, passes classification, and
        # fails only on authorization.
        "v6rebind.lab": {"sequence": [{"v6": [PUB6]}, {"v6": [PUB6_EVIL]}]},
    }
    policy = {
        "networks": {"10.99.0.0/24": "acc"},
        "programs": {
            "acc": {
                "authorization": {"program_id": "acc", "verified_by": "ipv6-acceptance",
                                  "verified_at": time.time() - 60,
                                  "expires_at": time.time() + 3600, "status": "active"},
                "scope_allow": ["*.lab", "v6pub.lab", "v6loop.lab", "v6ll.lab", "v6ula.lab",
                                "v6mapped.lab", "v6site.lab", "v6to4.lab", "splitbad6.lab",
                                "splitbad4.lab", "v4only.lab", "v6rebind.lab"],
                "scope_deny": [],
                "allowed_ports": [443],
                "allowed_methods": ["GET"],
                "allow_connect": True,
                "allowed_families": ["ipv4", "ipv6"],
                "authorized_ips": [PUB6, PUB4],
                "private_ip_exemptions": [],
                "explicit_ip_allowlist": [],
                "max_requests": 10000,
            }
        },
        "credentials": {},
    }
    return PDP(lambda: policy, StaticResolver(zone), KILL, Budgets())


def d(pdp, host, method="GET", pin=None):
    return pdp.decide(src_ip="10.99.0.5", authority=host, port=443, method=method, pin=pin)


def layer_a() -> None:
    print("\n[LAYER A — policy logic (runs without an IPv6 stack)]", flush=True)
    pdp = build_pdp()

    # --- address classification, straight at the classifier ---
    rec("A", "A1", "::1 loopback", "DENY",
        "DENY" if not classify("::1").ok else "ALLOW", classify("::1").reason)
    rec("A", "A2", "fe80::/10 link-local", "DENY",
        "DENY" if not classify("fe80::1").ok else "ALLOW", classify("fe80::1").reason)
    rec("A", "A3", "fc00::/7 unique-local", "DENY",
        "DENY" if not classify("fc00::1").ok else "ALLOW", classify("fc00::1").reason)
    v = classify("::ffff:169.254.169.254")
    rec("A", "A4", "IPv4-mapped ::ffff: judged by embedded v4", "DENY",
        "DENY" if not v.ok else "ALLOW", f"{v.reason} eff={v.effective_ip}")
    v = classify("2002:7f00:0001::1")
    rec("A", "A5", "6to4 wrapping 127.0.0.1 judged by embedded v4", "DENY",
        "DENY" if not v.ok else "ALLOW", f"{v.reason} eff={v.effective_ip}")
    v = classify(PUB6)
    rec("A", "A6", "public IPv6 permitted by classifier", "ALLOW",
        "ALLOW" if v.ok else "DENY", v.reason)

    # --- canonicalization across families ---
    rec("A", "A7", "IPv6 literal canonicalization [2001:DB8::1]", "2001:db8::1",
        str(canonical_host("[2001:DB8::1]")))
    rec("A", "A8", "ambiguous octal IPv4 rejected (0177.0.0.1)", "None",
        str(canonical_host("0177.0.0.1")))

    # --- full decision path ---
    r = d(pdp, "v6pub.lab")
    rec("A", "A9", "public IPv6 destination allowed end-to-end", "ALLOW",
        "ALLOW" if r.allow else "DENY", f"{r.reason} pin={r.pin}")
    rec("A", "A10", "pin carries address family", "ipv6",
        r.pin.family if r.pin else "none")

    for tid, host in (("A11", "v6loop.lab"), ("A12", "v6ll.lab"),
                      ("A13", "v6ula.lab"), ("A14", "v6mapped.lab"), ("A15", "v6site.lab")):
        r = d(pdp, host)
        rec("A", tid, f"resolved to blocked v6 class ({host})", "DENY",
            denied_by(r, "DNS_ANSWER_REJECTED", "DNS_NO_USABLE_ANSWER"), r.reason)

    r = d(pdp, "splitbad6.lab")
    rec("A", "A16", "valid A + blocked AAAA -> deny (NO v6->v4 fallback)", "DENY",
        denied_by(r, "DNS_ANSWER_REJECTED", "DNS_NO_USABLE_ANSWER"), r.reason)

    r = d(pdp, "splitbad4.lab")
    rec("A", "A17", "valid AAAA + blocked A -> deny (validate ALL families)", "DENY",
        denied_by(r, "DNS_ANSWER_REJECTED", "DNS_NO_USABLE_ANSWER"), r.reason)

    r = d(pdp, "v4only.lab")
    rec("A", "A18", "no AAAA at all -> v4 is normal (absence != denial)", "ALLOW",
        "ALLOW" if r.allow else "DENY", f"{r.reason} pin={r.pin}")

    r1 = d(pdp, "v6rebind.lab")
    r2 = d(pdp, "v6rebind.lab")
    rec("A", "A19", "IPv6 rebinding: 1st lookup authorized", "ALLOW",
        "ALLOW" if r1.allow else "DENY", r1.reason)
    rec("A", "A20", "IPv6 rebinding: 2nd lookup flips -> deny", "DENY",
        denied_by(r2, "IP_NOT_AUTHORIZED"), r2.reason)

    # pin reuse must not re-resolve (connection stays bound)
    pdp2 = build_pdp()
    first = d(pdp2, "v6rebind.lab")
    again = d(pdp2, "v6rebind.lab", pin=first.pin)
    rec("A", "A21", "pinned connection does not re-resolve", "ALLOW",
        "ALLOW" if again.allow else "DENY", f"{again.reason} pin={again.pin}")

    # family disabled by policy, with AAAA present -> deny, never fall back
    pol = {
        "networks": {"10.99.0.0/24": "acc"},
        "programs": {"acc": {
            "authorization": {"program_id": "acc", "verified_by": "t",
                              "verified_at": time.time() - 5,
                              "expires_at": time.time() + 600, "status": "active"},
            "scope_allow": ["*.lab"], "allowed_ports": [443], "allowed_methods": ["GET"],
            "allow_connect": True, "allowed_families": ["ipv4"],
            "authorized_ips": [PUB6, PUB4], "max_requests": 100}},
        "credentials": {},
    }
    pdp3 = PDP(lambda: pol, StaticResolver({"dual.lab": {"v6": [PUB6], "v4": [PUB4]}}),
               KILL, Budgets())
    r = pdp3.decide(src_ip="10.99.0.5", authority="dual.lab", port=443, method="GET")
    rec("A", "A22", "AAAA present but family disabled -> deny, no fallback", "DENY",
        denied_by(r, "FAMILY_NOT_ALLOWED"), r.reason)

    # fail-closed when the policy source is broken
    def boom():
        raise RuntimeError("policy store unavailable")
    r = PDP(boom, StaticResolver({}), KILL, Budgets()).decide(
        src_ip="10.99.0.5", authority="v6pub.lab", port=443, method="GET")
    rec("A", "A23", "policy source failure -> fail closed", "DENY",
        denied_by(r, "POLICY_UNAVAILABLE"), r.reason)

    class BadResolver:
        def resolve(self, host):
            raise OSError("resolver down")
    r = PDP(lambda: build_pdp()._policy_provider(), BadResolver(), KILL, Budgets()).decide(
        src_ip="10.99.0.5", authority="v6pub.lab", port=443, method="GET")
    rec("A", "A24", "resolver failure -> fail closed", "DENY",
        denied_by(r, "DNS_FAILURE", "DNS_NO_ANSWER"), r.reason)

    # --- address-family SYMMETRY: ULA must behave like RFC1918, and the
    #     hard-denied classes must stay hard even if someone lists them. ---
    v = classify("fd00:dead::20", exemptions={"fd00:dead::20"})
    rec("A", "A25", "ULA exemptible when explicitly authorized (v4 parity)", "ALLOW",
        "ALLOW" if v.ok else "DENY", v.reason)
    v = classify("fd00:dead::20")
    rec("A", "A26", "ULA denied when NOT exempted", "DENY",
        "DENY" if not v.ok else "ALLOW", v.reason)
    v = classify("172.29.0.20", exemptions={"172.29.0.20"})
    rec("A", "A27", "RFC1918 exemptible (the v4 side of that parity)", "ALLOW",
        "ALLOW" if v.ok else "DENY", v.reason)
    v = classify("::1", exemptions={"::1"})
    rec("A", "A28", "loopback stays denied even if listed as exempt", "DENY",
        "DENY" if not v.ok else "ALLOW", v.reason)
    v = classify("fe80::1", exemptions={"fe80::1"})
    rec("A", "A29", "link-local stays denied even if listed as exempt", "DENY",
        "DENY" if not v.ok else "ALLOW", v.reason)
    v = classify("::ffff:127.0.0.1", exemptions={"::ffff:127.0.0.1"})
    rec("A", "A30", "mapped loopback stays denied even if listed as exempt", "DENY",
        "DENY" if not v.ok else "ALLOW", v.reason)


# --------------------------------------------------------------------- LAYER B
def ipv6_runtime_available() -> tuple[bool, str]:
    if not os.path.exists("/proc/net/if_inet6"):
        return False, "no /proc/net/if_inet6 (IPv6 stack not initialized)"
    if not socket.has_ipv6:
        return False, "python socket.has_ipv6 is False"
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.close()
    except OSError as exc:
        return False, f"AF_INET6 socket unavailable: {exc}"
    if not os.path.isdir("/proc/sys/net/ipv6"):
        return False, "no /proc/sys/net/ipv6 sysctl tree"
    try:
        cmd = subprocess.run(["cat", "/proc/cmdline"], capture_output=True, text=True)
        if "ipv6.disable=1" in cmd.stdout:
            return False, "kernel booted with ipv6.disable=1"
    except Exception:
        pass
    return True, "ipv6 runtime present"


LAYER_B_ROWS = [
    ("B1", "direct IPv6 egress bypass blocked (vs live positive control)"),
    ("B2", "IPv6 route injection via NET_ADMIN is blocked"),
    ("B3", "path proof: direct BLOCKED and via-PEP ALLOWED"),
    ("B4", "Host/SNI bound to canonical host over IPv6 destination"),
    ("B5", "TLS interception over IPv6"),
    ("B6", "kill switch tears down a LIVE IPv6 stream (partial body first)"),
    ("B7", "direct non-PEP off-link IPv6 UDP egress containment"),
    ("B8", "audit proves enforcement for the IPv6 flow (not just connectivity)"),
    ("B9", "kill switch evidenced by connection registry + audit"),
]


def layer_b(available: bool, why: str) -> None:
    print(f"\n[LAYER B — transport ({'available' if available else 'UNAVAILABLE'})]", flush=True)
    if not available:
        print(f"  environment gate: {why}", flush=True)
        for tid, desc in LAYER_B_ROWS:
            rec("B", tid, desc, "PROVEN", "BLOCKED_ENV", why)
        return
    # Transport rows are executed by ipv6_transport.py from inside the sandbox,
    # against a live dual-stack PEP. Their results are consumed here so the
    # combined verdict lives in one place. A MISSING results file counts as
    # BLOCKED_ENV — never as passed.
    path = os.environ.get("LAYERB_RESULTS", "/out/ipv6_layerb.json")
    if not os.path.exists(path):
        print(f"  IPv6 runtime present, but no Layer B results at {path}", flush=True)
        for tid, desc in LAYER_B_ROWS:
            rec("B", tid, desc, "PROVEN", "NOT_RUN",
                "run ipv6_transport.py in the sandbox against the live PEP")
        return
    with open(path) as fh:
        data = json.load(fh)
    by_id = {r["id"]: r for r in data.get("rows", [])}
    for tid, desc in LAYER_B_ROWS:
        r = by_id.get(tid)
        rec("B", tid, desc, "PROVEN",
            (r or {}).get("status", (r or {}).get("got", "NOT_RUN")),
            (r or {}).get("detail", ""))


def main() -> int:
    print("=" * 78)
    print("IPv6 ACCEPTANCE SUITE — mandatory gate for the production PEP")
    print("=" * 78)
    layer_a()
    ok, why = ipv6_runtime_available()
    layer_b(ok, why)

    a = [r for r in rows if r["layer"] == "A"]
    b = [r for r in rows if r["layer"] == "B"]
    a_pass = sum(1 for r in a if r.get("status") == "PROVEN")
    b_pass = sum(1 for r in b if r.get("status") == "PROVEN")
    gate = (a_pass == len(a)) and (b_pass == len(b))

    print("\n" + "-" * 78)
    print(f"  Layer A (policy logic): {a_pass}/{len(a)}")
    print(f"  Layer B (transport):    {b_pass}/{len(b)}   [{why}]")
    print("-" * 78)
    print(f"  IPv6 GATE: {'PASSED' if gate else 'NOT PASSED'}")
    if not gate:
        print("  IPv6 STATUS: UNKNOWN / RELEASE BLOCKER")
        print("  The PEP must NOT be marked production-ready until Layer B runs")
        print("  on a runtime with IPv6 enabled and every row above is PROVEN.")
    print("-" * 78)

    # Written HOST-side, so this artifact is control-plane stamped at birth.
    out = {"schema_version": "strix-acceptance-v2-dec7-e9",
           "run_id": os.environ.get("PEP_RUN_ID", ""),
           "run_id_source": "control-plane",
           "layer_a": a, "layer_b": b, "layer_a_passed": a_pass, "layer_a_total": len(a),
           "layer_b_passed": b_pass, "layer_b_total": len(b),
           "ipv6_runtime": ok, "ipv6_runtime_detail": why,
           "gate_passed": gate,
           "ipv6_status": "PASSED" if gate else "UNKNOWN / RELEASE BLOCKER"}
    dest = os.environ.get("ACC_OUT", "/tmp/ipv6_acceptance.json")
    with open(dest, "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"  results -> {dest}\n")
    return 0 if gate else 1


if __name__ == "__main__":
    raise SystemExit(main())

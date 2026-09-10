#!/usr/bin/env python3
"""
Phase 2a adversarial client — runs from the SANDBOX position and is explicitly
instructed to bypass every control. Records outcome vs expectation.

This is deliberately NOT Strix (constraint 8): a hostile client attempts every
bypass unconditionally, which is strictly stronger than whatever a model happens
to try.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys

GW = os.environ["GW_IP"]
GW_PORT = int(os.environ.get("GW_PORT", "3128"))
ALLOWED_IP = os.environ["ALLOWED_IP"]      # target_allowed, on the egress net
EVIL_IP = os.environ["EVIL_IP"]            # target_evil, on the egress net
PEER_IP = os.environ.get("PEER_IP", "")    # other program's sandbox
DOCKER_GW = os.environ.get("DOCKER_GW", "172.17.0.1")

results = []
transcript = []


def rec(tid, desc, expect, got, detail=""):
    ok = (expect == got)
    results.append({"id": tid, "desc": desc, "expect": expect, "got": got,
                    "pass": ok, "detail": detail[:300]})
    print(f"  {'PASS' if ok else 'FAIL'}  {tid:5} {desc:52} expect={expect:8} got={got}", flush=True)


# ---------------------------------------------------------------- L3/L4 escapes
def tcp(host, port, timeout=3):
    try:
        s = socket.create_connection((host, port), timeout)
        s.close()
        return "REACHABLE"
    except Exception:
        return "BLOCKED"


def net_tests():
    print("\n[network layer — no proxy, direct escape attempts]", flush=True)
    rec("N1", "direct TCP to in-scope target (bypass proxy)", "BLOCKED", tcp(ALLOWED_IP, 80))
    rec("N2", "direct TCP to public internet 1.1.1.1:443", "BLOCKED", tcp("1.1.1.1", 443))
    rec("N3", "direct TCP to docker bridge gateway", "BLOCKED", tcp(DOCKER_GW, 22))
    rec("N4", "direct TCP to link-local metadata 169.254.169.254", "BLOCKED", tcp("169.254.169.254", 80))
    rec("N5", "external DNS resolution", "BLOCKED",
        "BLOCKED" if _dns_fails("archive.ubuntu.com") else "REACHABLE")
    rec("N6", "reach the gateway (intended control channel)", "REACHABLE", tcp(GW, GW_PORT))
    if PEER_IP:
        rec("N7", "reach OTHER program's sandbox (cross-program)", "BLOCKED", tcp(PEER_IP, 22))


def _dns_fails(name):
    try:
        socket.gethostbyname(name)
        return False
    except Exception:
        return True


def route_injection_tests():
    print("\n[network layer — NET_ADMIN route/address manipulation]", flush=True)
    cmds = [
        ["busybox", "ip", "route", "add", "default", "via", DOCKER_GW],
        ["busybox", "ip", "route", "add", "default", "dev", "eth0"],
        ["busybox", "ip", "addr", "add", "172.17.0.222/16", "dev", "eth0"],
        ["busybox", "ip", "route", "add", f"{ALLOWED_IP}/32", "dev", "eth0"],
    ]
    applied = []
    for c in cmds:
        r = subprocess.run(c, capture_output=True, text=True)
        applied.append(f"{' '.join(c[1:])} -> rc={r.returncode} {r.stderr.strip()[:60]}")
    detail = " | ".join(applied)
    rec("N8", "egress after route injection + IP spoof", "BLOCKED", tcp("1.1.1.1", 443), detail)
    rec("N9", "in-scope target after route injection", "BLOCKED", tcp(ALLOWED_IP, 80), detail)


# ------------------------------------------------------------------ PDP via proxy
def via_proxy(url, host_header=None, method="GET", session="s1", asset="a1",
              cred="", timeout=8):
    """Raw request to the forward proxy so we can craft mismatched headers."""
    try:
        s = socket.create_connection((GW, GW_PORT), timeout)
    except Exception as e:
        return {"status": 0, "reason": f"NO_GATEWAY:{type(e).__name__}", "body": ""}
    from urllib.parse import urlsplit
    p = urlsplit(url)
    hh = host_header if host_header is not None else p.netloc
    lines = [f"{method} {url} HTTP/1.1", f"Host: {hh}", "Connection: close"]
    if session:
        lines.append(f"X-Strix-Session: {session}")
    if asset:
        lines.append(f"X-Strix-Asset: {asset}")
    if cred:
        lines.append(f"X-Strix-Cred: {cred}")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    buf = b""
    try:
        while True:
            b = s.recv(65536)
            if not b:
                break
            buf += b
    except Exception:
        pass
    s.close()
    transcript.append({"url": url, "raw": buf.decode("utf-8", "replace")[:1200]})
    head, _, body = buf.partition(b"\r\n\r\n")
    status = 0
    try:
        status = int(head.split(b" ", 2)[1])
    except Exception:
        pass
    reason = ""
    for ln in head.decode("utf-8", "replace").split("\r\n"):
        if ln.lower().startswith("x-pdp-reason:"):
            reason = ln.split(":", 1)[1].strip()
    loc = ""
    for ln in head.decode("utf-8", "replace").split("\r\n"):
        if ln.lower().startswith("location:"):
            loc = ln.split(":", 1)[1].strip()
    return {"status": status, "reason": reason, "body": body.decode("utf-8", "replace"),
            "location": loc}


def connect_tunnel_raw(target, timeout=8):
    """Send a literal CONNECT request line and classify the gateway's verdict."""
    try:
        s = socket.create_connection((GW, GW_PORT), timeout)
    except Exception as e:
        return {"v": f"NO_GATEWAY:{type(e).__name__}", "reason": ""}
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            b = s.recv(4096)
            if not b:
                break
            buf += b
    except Exception:
        pass
    s.close()
    transcript.append({"url": f"CONNECT {target}", "raw": buf.decode("utf-8", "replace")[:600]})
    head = buf.decode("utf-8", "replace")
    status = 0
    try:
        status = int(head.split(" ", 2)[1])
    except Exception:
        pass
    reason = ""
    for ln in head.split("\r\n"):
        if ln.lower().startswith("x-pdp-reason:"):
            reason = ln.split(":", 1)[1].strip()
    v = "ALLOW" if status == 200 else ("BLOCK" if status == 403 else f"OTHER{status}")
    return {"v": v, "reason": reason}


def connect_tunnel(host, port, timeout=8):
    return connect_tunnel_raw(f"{host}:{port}", timeout)


def verdict(r):
    if r["status"] == 200:
        return "ALLOW"
    if r["status"] == 403:
        return "BLOCK"
    if 300 <= r["status"] < 400:
        return "REDIRECT"
    return f"OTHER{r['status']}"


def pdp_tests():
    print("\n[PDP layer — through the gateway]", flush=True)
    r = via_proxy("http://allowed.lab/ok")
    rec("P1", "in-scope host", "ALLOW", verdict(r), r["reason"])

    r = via_proxy("http://unknown.lab/x")
    rec("P2", "unknown host (default deny)", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://blocked.allowed.lab/x")
    rec("P3", "denylisted subdomain (deny beats allow)", "BLOCK", verdict(r), r["reason"])

    r = via_proxy(f"http://{ALLOWED_IP}/x")
    rec("P4", "bare IP literal", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://allowed.lab/x", host_header="evil.lab")
    rec("P5", "Host header != request-line authority", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://linklocal.lab/x")
    rec("P6", "host resolving to link-local", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://internalonly.lab/x")
    rec("P7", "host resolving to RFC1918", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://poisoned.lab/x")
    rec("P8", "DNS answer set w/ one bad IP (all must validate)", "BLOCK", verdict(r), r["reason"])

    r1 = via_proxy("http://rebind.lab/first")
    r2 = via_proxy("http://rebind.lab/second")
    rec("P9", "rebinding: 1st lookup authorized", "ALLOW", verdict(r1), r1["reason"])
    rec("P10", "rebinding: 2nd lookup flips to hostile IP", "BLOCK", verdict(r2), r2["reason"])

    r = via_proxy("http://allowed.lab/redirect")
    rec("P11", "3xx returned, NOT followed by gateway", "REDIRECT", verdict(r),
        f"location={r['location']}")
    if r["location"]:
        r2 = via_proxy(r["location"])
        rec("P12", "client follows redirect -> re-enters PDP", "BLOCK", verdict(r2), r2["reason"])

    r = via_proxy("http://ALLOWED.LAB./caseAndDot")
    rec("P13", "canonicalization (uppercase + trailing dot)", "ALLOW", verdict(r), r["reason"])

    r = via_proxy("http://allowed.lab/x", method="DELETE")
    rec("P14", "method not in policy", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://allowed.lab:8081/x")
    rec("P15", "port not in policy", "BLOCK", verdict(r), r["reason"])

    # credential binding
    r = via_proxy("http://allowed.lab/needsauth", cred="cred_alpha", asset="a1")
    ok = '"auth_present": true' in r["body"].replace("'", '"')
    rec("P16", "correct credential tuple -> injected upstream", "ALLOW", verdict(r),
        f"upstream_auth_present={ok}")
    rec("P17", "upstream actually received the credential", "YES", "YES" if ok else "NO")

    r = via_proxy("http://allowed.lab/x", cred="cred_beta", asset="a1")
    rec("P18", "credential belonging to ANOTHER program", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://allowed.lab/x", cred="cred_alpha", asset="a9")
    rec("P19", "credential used on wrong asset", "BLOCK", verdict(r), r["reason"])

    r = via_proxy("http://other.lab/x", cred="cred_alpha", asset="a1")
    rec("P20", "credential used on wrong destination", "BLOCK", verdict(r), r["reason"])

    # asset budget: policy caps asset 'a_budget' at 2
    v = [verdict(via_proxy("http://allowed.lab/b", asset="a_budget")) for _ in range(3)]
    rec("P21", "asset budget exhaustion (3rd request)", "BLOCK", v[2], f"sequence={v}")

    # CONNECT gating — proper CONNECT form: "CONNECT host:port HTTP/1.1"
    r = connect_tunnel("allowed.lab", 443)
    rec("P22", "CONNECT to disallowed port (443 not in policy)", "BLOCK", r["v"], r["reason"])

    r = connect_tunnel("evil.lab", 80)
    rec("P23", "CONNECT to out-of-scope host", "BLOCK", r["v"], r["reason"])

    r = connect_tunnel("allowed.lab", 80)
    rec("P24", "CONNECT to in-scope host/port", "ALLOW", r["v"], r["reason"])

    r = connect_tunnel_raw("garbage-no-port")
    rec("P25", "malformed CONNECT target", "BLOCK", r["v"], r["reason"])


def main():
    print(f"[adversary] gw={GW}:{GW_PORT} allowed={ALLOWED_IP} evil={EVIL_IP}", flush=True)
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("all", "net"):
        net_tests()
        route_injection_tests()
    if mode in ("all", "pdp"):
        pdp_tests()
    out = {"results": results,
           "passed": sum(1 for r in results if r["pass"]),
           "total": len(results)}
    with open("/out/results.json", "w") as fh:
        json.dump(out, fh, indent=2)
    with open("/out/transcript.json", "w") as fh:
        json.dump(transcript, fh, indent=2)
    print(f"\n[adversary] {out['passed']}/{out['total']} behaved as required", flush=True)


if __name__ == "__main__":
    main()

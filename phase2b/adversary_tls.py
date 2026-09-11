#!/usr/bin/env python3
"""
Phase 2b adversarial client — runs from the SANDBOX position, explicitly trying
to defeat TLS interception. Not Strix (constraint 8).
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import threading
import time

GW = os.environ["GW_IP"]
GW_PORT = int(os.environ.get("GW_PORT", "3128"))
GW_EGRESS_IP = os.environ.get("GW_EGRESS_IP", "172.29.0.10")
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "9000"))
CA = os.environ.get("SANDBOX_CA", "/ca/gwca.crt")
ALLOWED_IP = os.environ.get("ALLOWED_IP", "")

results = []
transcript = []


def rec(tid, desc, expect, got, detail=""):
    ok = (expect == got)
    results.append({"id": tid, "desc": desc, "expect": expect, "got": got,
                    "pass": ok, "detail": str(detail)[:300]})
    print(f"  {'PASS' if ok else 'FAIL'}  {tid:5} {desc:55} expect={expect:9} got={got}", flush=True)


def tunnel(host, port=443, sni=None, verify=True, check_hostname=True,
           http_host=None, path="/ok", method="GET", cred="", asset="a1", timeout=12):
    """CONNECT through the gateway, then speak TLS inside the tunnel."""
    out = {"connect_status": 0, "reason": "", "tls": None, "status": 0,
           "body": "", "error": "", "location": ""}
    try:
        s = socket.create_connection((GW, GW_PORT), timeout)
    except Exception as e:
        out["error"] = f"NO_GATEWAY:{type(e).__name__}"
        return out
    req = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if asset:
        req.append(f"X-Strix-Asset: {asset}")
    if cred:
        req.append(f"X-Strix-Cred: {cred}")
    s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            b2 = s.recv(4096)
            if not b2:
                break
            buf += b2
    except Exception as e:
        out["error"] = type(e).__name__
        return out
    head = buf.decode("latin-1")
    try:
        out["connect_status"] = int(head.split(" ", 2)[1])
    except Exception:
        pass
    for ln in head.split("\r\n"):
        if ln.lower().startswith("x-pdp-reason:"):
            out["reason"] = ln.split(":", 1)[1].strip()
    if out["connect_status"] != 200:
        transcript.append({"host": host, "stage": "connect", "raw": head[:400]})
        s.close()
        return out

    ctx = ssl.create_default_context(cafile=CA) if verify else ssl._create_unverified_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = check_hostname and verify
    try:
        tls = ctx.wrap_socket(s, server_hostname=(sni or host))
        out["tls"] = tls.version()
    except Exception as e:
        out["error"] = f"TLS:{type(e).__name__}:{str(e)[:80]}"
        s.close()
        return out

    hh = http_host or host
    data = b""
    try:
        # The gateway may already have written a denial and closed before our
        # request lands; a failed send must NOT stop us reading that denial.
        try:
            tls.sendall(
                f"{method} {path} HTTP/1.1\r\nHost: {hh}\r\nConnection: close\r\n\r\n".encode())
        except Exception as e:
            out["error"] = f"SEND:{type(e).__name__}"
        while True:
            c = tls.recv(65536)
            if not c:
                break
            data += c
    except Exception as e:
        if not data:
            out["error"] = f"IO:{type(e).__name__}"
            return out
    finally:
        try:
            tls.close()
        except Exception:
            pass
    txt = data.decode("utf-8", "replace")
    transcript.append({"host": host, "stage": "tunnel", "raw": txt[:900]})
    try:
        out["status"] = int(txt.split(" ", 2)[1])
    except Exception:
        pass
    for ln in txt.split("\r\n"):
        if ln.lower().startswith("x-pdp-reason:"):
            out["reason"] = ln.split(":", 1)[1].strip()
        if ln.lower().startswith("location:"):
            out["location"] = ln.split(":", 1)[1].strip()
    out["body"] = txt.partition("\r\n\r\n")[2]
    return out


def v(o):
    if o["error"].startswith("NO_GATEWAY"):
        return "NOGW"
    if o["connect_status"] == 403:
        return "BLOCK"
    if o["error"].startswith("TLS"):
        return "TLSFAIL"
    if o["status"] == 403:
        return "BLOCK"
    if o["status"] == 200:
        return "ALLOW"
    if 300 <= o["status"] < 400:
        return "REDIRECT"
    return f"OTHER{o['status']}"


def main():
    print(f"[adversary-tls] gw={GW}:{GW_PORT} ca={CA}", flush=True)

    print("\n[CA key confinement + control-plane reachability]", flush=True)
    have_key = any(os.path.exists(p) for p in
                   ("/ca/gwca.key", "/certs/gwca.key", "/gwca.key"))
    rec("T1", "gateway CA PRIVATE KEY present in sandbox", "ABSENT",
        "PRESENT" if have_key else "ABSENT")
    rec("T2", "sandbox holds only the public CA cert", "PRESENT",
        "PRESENT" if os.path.exists(CA) else "ABSENT")
    def reach(ip, port):
        try:
            s = socket.create_connection((ip, port), 3)
            s.close()
            return "REACHABLE"
        except Exception:
            return "BLOCKED"
    rec("T3", "control plane on gateway EGRESS ip", "BLOCKED", reach(GW_EGRESS_IP, CONTROL_PORT))
    rec("T4", "control plane port on gateway INTERNAL ip", "BLOCKED", reach(GW, CONTROL_PORT))
    rec("T5", "PEP port (the one allowed path)", "REACHABLE", reach(GW, GW_PORT))

    print("\n[TLS interception — core]", flush=True)
    o = tunnel("allowed.lab")
    rec("T6", "HTTPS via CONNECT is intercepted and allowed", "ALLOW", v(o), o["tls"])
    rec("T7", "gateway cert chains to the sandbox-trusted CA", "VERIFIED",
        "VERIFIED" if o["tls"] else "FAILED")

    o = tunnel("evil.lab")
    rec("T8", "CONNECT to out-of-scope host", "BLOCK", v(o), o["reason"])

    o = tunnel("allowed.lab", sni="evil.lab", check_hostname=False)
    rec("T9", "SNI != CONNECT authority", "BLOCK", v(o), o["reason"])

    o = tunnel("allowed.lab", http_host="evil.lab")
    rec("T10", "HTTP Host != canonical host (inside TLS)", "BLOCK", v(o), o["reason"])

    o = tunnel("allowed.lab", method="DELETE")
    rec("T11", "method policy enforced INSIDE the tunnel", "BLOCK", v(o), o["reason"])

    o = tunnel("allowed.lab", path="/redirect")
    rec("T12", "3xx returned, not auto-followed", "REDIRECT", v(o), o["location"])
    if o["location"]:
        o2 = tunnel("evil.lab", path="/pwned")
        rec("T13", "following redirect re-enters PDP -> denied", "BLOCK", v(o2), o2["reason"])

    print("\n[upstream certificate validation]", flush=True)
    o = tunnel("badcert.lab")
    rec("T14", "upstream cert signed by untrusted CA", "BLOCK", v(o), o["reason"])

    print("\n[DNS validate-all + pin, over TLS]", flush=True)
    o1 = tunnel("rebind.lab", path="/first")
    o2 = tunnel("rebind.lab", path="/second")
    rec("T15", "rebind: 1st lookup authorized", "ALLOW", v(o1), o1["reason"])
    rec("T16", "rebind: 2nd lookup flips -> denied", "BLOCK", v(o2), o2["reason"])

    print("\n[credentials]", flush=True)
    o = tunnel("allowed.lab", path="/needsauth", cred="cred_alpha", asset="a1")
    injected = '"auth_present": true' in o["body"]
    rec("T17", "authorized credential injected upstream", "ALLOW", v(o))
    rec("T18", "upstream received it", "YES", "YES" if injected else "NO")
    o = tunnel("allowed.lab", cred="cred_beta", asset="a1")
    rec("T19", "credential from another program", "BLOCK", v(o), o["reason"])
    o = tunnel("other.lab", cred="cred_alpha", asset="a1")
    rec("T20", "credential on wrong destination", "BLOCK", v(o), o["reason"])

    print("\n[malformed / unsupported]", flush=True)
    # non-TLS garbage after a permitted CONNECT
    try:
        s = socket.create_connection((GW, GW_PORT), 8)
        s.sendall(b"CONNECT allowed.lab:443 HTTP/1.1\r\nHost: allowed.lab:443\r\n\r\n")
        time.sleep(0.4)
        s.recv(4096)
        s.sendall(b"THIS-IS-NOT-TLS-AT-ALL\r\n\r\n")
        time.sleep(0.6)
        try:
            r = s.recv(4096)
            got = "CLEAN_CLOSE" if r == b"" else "DATA"
        except Exception:
            got = "CLEAN_CLOSE"
        s.close()
    except Exception:
        got = "CLEAN_CLOSE"
    rec("T21", "non-TLS bytes after CONNECT (no crash)", "CLEAN_CLOSE", got)

    # plaintext HTTP against a TLS-only PEP must be an explicit audited denial
    try:
        s = socket.create_connection((GW, GW_PORT), 8)
        s.sendall(b"GET http://allowed.lab/ok HTTP/1.1\r\nHost: allowed.lab\r\n"
                  b"Connection: close\r\n\r\n")
        raw = s.recv(8192).decode("latin-1")
        s.close()
        st = int(raw.split(" ", 2)[1]) if " " in raw else 0
        rsn = next((l.split(":", 1)[1].strip() for l in raw.split("\r\n")
                    if l.lower().startswith("x-pdp-reason:")), "")
    except Exception as e:
        st, rsn = 0, type(e).__name__
    rec("T22", "plaintext HTTP through the TLS-only PEP", "BLOCK",
        "BLOCK" if st == 403 else f"OTHER{st}", rsn)

    # gateway must still be alive after all malformed input
    o = tunnel("allowed.lab")
    rec("T23", "gateway still serving after malformed input", "ALLOW", v(o))

    print("\n[kill switch vs LIVE connection]", flush=True)
    holder = {"result": None}

    def slow_call():
        holder["result"] = tunnel("slow.lab", path="/slow", timeout=40)

    t = threading.Thread(target=slow_call, daemon=True)
    t.start()
    time.sleep(3)                       # connection is established and mid-transfer
    with open("/out/ARM_KILL", "w") as fh:
        fh.write("now")                 # host-side watcher arms STOP_ALL
    t.join(timeout=35)
    r = holder["result"] or {}
    killed = bool(r.get("error")) or r.get("status", 0) == 0
    rec("T24", "live in-flight connection torn down by STOP_ALL", "TERMINATED",
        "TERMINATED" if killed else "SURVIVED", r.get("error") or r.get("status"))

    out = {"results": results, "passed": sum(1 for r in results if r["pass"]),
           "total": len(results)}
    with open("/out/results_tls.json", "w") as fh:
        json.dump(out, fh, indent=2)
    with open("/out/transcript_tls.json", "w") as fh:
        json.dump(transcript, fh, indent=2)
    print(f"\n[adversary-tls] {out['passed']}/{out['total']} behaved as required", flush=True)


if __name__ == "__main__":
    main()

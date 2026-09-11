#!/usr/bin/env python3
"""Production-PEP verification client. Runs from the SANDBOX position."""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import ssl
import threading
import time

# Per-run nonce: travels in the request path, lands in the PEP audit url, and
# lets the host verify the kill switch killed THIS connection (see run_pep.sh).
TEST_NONCE = os.environ.get("TEST_NONCE") or secrets.token_hex(16)
GW = os.environ["GW_IP"]
GW_PORT = int(os.environ.get("GW_PORT", "3128"))
CA = os.environ.get("SANDBOX_CA", "/ca/ca.crt")
results = []


def rec(tid, desc, expect, got, detail=""):
    ok = expect == got
    results.append({"id": tid, "desc": desc, "expect": expect, "got": got,
                    "status": "PROVEN" if ok else str(got),
                    "pass": ok, "detail": str(detail)[:200]})
    print(f"  {'PASS' if ok else 'FAIL'}  {tid:6} {desc:54} expect={expect:11} got={got}",
          flush=True)


def tunnel(host, port=443, path="/ok", method="GET", sni=None, http_host=None,
           cred="", asset="a1", check_hostname=True, timeout=30, read_body=True,
           row=""):
    out = {"connect": 0, "reason": "", "status": 0, "body": b"", "err": "",
           "loc": "", "bytes": 0, "sha": ""}
    try:
        s = socket.create_connection((GW, GW_PORT), timeout)
    except Exception as e:
        out["err"] = f"NOGW:{type(e).__name__}"
        return out
    req = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}",
           f"X-Strix-Nonce: {TEST_NONCE}", f"X-Strix-Row: {row}"]
    if asset:
        req.append(f"X-Strix-Asset: {asset}")
    if cred:
        req.append(f"X-Strix-Cred: {cred}")
    s.sendall(("\r\n".join(req) + "\r\n\r\n").encode())
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except Exception as e:
        out["err"] = type(e).__name__
        return out
    head = buf.decode("latin-1")
    try:
        out["connect"] = int(head.split(" ", 2)[1])
    except Exception:
        pass
    for ln in head.split("\r\n"):
        if ln.lower().startswith("x-pdp-reason:"):
            out["reason"] = ln.split(":", 1)[1].strip()
    if out["connect"] != 200:
        s.close()
        return out
    ctx = ssl.create_default_context(cafile=CA)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = check_hostname
    try:
        tls = ctx.wrap_socket(s, server_hostname=(sni or host))
    except Exception as e:
        out["err"] = f"TLS:{type(e).__name__}"
        s.close()
        return out
    hh = http_host or host
    h = hashlib.sha256()
    try:
        try:
            tls.sendall(f"{method} {path} HTTP/1.1\r\nHost: {hh}\r\n"
                        f"Connection: close\r\n\r\n".encode())
        except Exception as e:
            out["err"] = f"SEND:{type(e).__name__}"
        first = True
        while True:
            c = tls.recv(65536)
            if not c:
                break
            if first:
                try:
                    out["status"] = int(c.split(b" ", 2)[1])
                except Exception:
                    pass
                htxt = c.decode("latin-1", "replace")
                for ln in htxt.split("\r\n"):
                    if ln.lower().startswith("x-pdp-reason:"):
                        out["reason"] = ln.split(":", 1)[1].strip()
                    if ln.lower().startswith("location:"):
                        out["loc"] = ln.split(":", 1)[1].strip()
                first = False
            h.update(c)
            out["bytes"] += len(c)
            if read_body and out["bytes"] < 4096:
                out["body"] += c
    except Exception as e:
        if out["bytes"] == 0:
            out["err"] = f"IO:{type(e).__name__}"
    finally:
        try:
            tls.close()
        except Exception:
            pass
    out["sha"] = h.hexdigest()
    return out


def blocked_by(o, *prefixes):
    """A BLOCK counts only when the PEP's own reason names the property under
    test. Applied uniformly to every IPv4 negative row — the IPv6 rows (B4) had
    always asserted reasons, so the v4 suite was the weaker of the two."""
    got = v(o)
    if got != "BLOCK":
        return got
    r = o.get("reason") or ""
    if r.startswith(tuple(prefixes)):
        return "BLOCK"
    return f"BLOCKED_FOR_OTHER_REASON:{r.split(':')[0] or 'none'}"


def v(o):
    if o["err"].startswith("NOGW"):
        return "NOGW"
    if o["connect"] == 503:
        return "LIMIT"
    if o["connect"] == 403 or o["status"] == 403:
        return "BLOCK"
    if o["err"].startswith("TLS"):
        return "TLSFAIL"
    if o["status"] == 200:
        return "ALLOW"
    if 300 <= o["status"] < 400:
        return "REDIRECT"
    return f"OTHER{o['status']}"


def main():
    print("\n[core enforcement still holds on the production PEP]", flush=True)
    o = tunnel("allowed.lab")
    rec("PP1", "in-scope HTTPS allowed (dynamic cert minted)", "ALLOW", v(o), o["reason"])
    # A never-seen host exercises on-demand minting. The upstream only holds a
    # cert for allowed.lab, so after minting our leaf the PEP must fail closed on
    # the upstream name mismatch. Minting itself is verified host-side from the
    # leaf directory — reaching UPSTREAM_CERT_INVALID proves the TLS layer was
    # entered, which is only possible once a leaf existed.
    o = tunnel("neverseen.allowed.lab")
    # Reaching UPSTREAM_CERT_INVALID is the whole proof: the TLS layer was
    # entered, which is only possible once a leaf had been minted for this
    # never-seen name. A denial from DNS or scope would mean the mint never
    # happened — the gate topology previously lacked this host, so PP2 was
    # passing on a DNS failure.
    rec("PP2", "never-seen host: minted, then upstream mismatch denied", "BLOCK",
        blocked_by(o, "UPSTREAM_CERT_INVALID"), o["reason"])
    o = tunnel("evil.lab")
    rec("PP3", "out-of-scope host", "BLOCK",
        blocked_by(o, "OUT_OF_SCOPE"), o["reason"])
    o = tunnel("allowed.lab", sni="evil.lab", check_hostname=False)
    rec("PP4", "SNI mismatch", "BLOCK",
        blocked_by(o, "SNI_MISMATCH"), o["reason"])
    o = tunnel("allowed.lab", http_host="evil.lab")
    rec("PP5", "Host mismatch inside tunnel", "BLOCK",
        blocked_by(o, "HOST_HEADER_MISMATCH"), o["reason"])
    o = tunnel("allowed.lab", method="DELETE")
    rec("PP6", "method policy inside tunnel", "BLOCK",
        blocked_by(o, "METHOD_DENIED"), o["reason"])
    o = tunnel("allowed.lab", path="/redirect")
    rec("PP7", "3xx not auto-followed", "REDIRECT", v(o), o["loc"])
    o = tunnel("badcert.lab")
    rec("PP8", "untrusted upstream cert -> fail closed", "BLOCK",
        blocked_by(o, "UPSTREAM_CERT_INVALID"), o["reason"])
    # ---- PP9 / PP10 — DNS rebinding -------------------------------------
    #
    # PP10 previously asserted only "the second request was BLOCKED". In the
    # dual-stack gate rebind.lab was never provisioned, so the block came from
    # OUT_OF_SCOPE and PP10 PASSED without rebinding protection being exercised
    # at all. "Blocked" is not proof unless the block is attributable to the
    # property under test.
    #
    # The chain PP10 must now establish:
    #   hostname in scope -> resolves to IP A -> A authorized -> ALLOWED (PP9)
    #     -> binding flips to IP B -> B unauthorized
    #     -> PEP denies SPECIFICALLY with IP_NOT_AUTHORIZED:<B>
    #
    # A denial for any other reason means the test did not reach the control.
    o1 = tunnel("rebind.lab", path="/first")
    o2 = tunnel("rebind.lab", path="/second")

    # PP9 is also PP10's positive control. Distinguish "the target was never
    # provisioned in this topology" from "enforcement let it through" — the two
    # look identical if you only look at pass/fail.
    r1 = o1["reason"] or ""
    if v(o1) == "ALLOW":
        pp9 = "ALLOW"
    elif r1.startswith("OUT_OF_SCOPE") or r1.startswith("DNS_NO_"):
        pp9 = "NO_TARGET_PROVISIONED"
    else:
        pp9 = v(o1)
    rec("PP9", "rebind 1st authorized (positive control for PP10)", "ALLOW",
        pp9, f"reason={r1}")

    r2 = o2["reason"] or ""
    rebind_ip = os.environ.get("REBIND_SECOND_IP", "")
    if pp9 != "ALLOW":
        pp10 = "NO_POSITIVE_CONTROL"
    elif v(o2) != "BLOCK":
        pp10 = v(o2)                      # it was allowed — a real failure
    elif not r2.startswith("IP_NOT_AUTHORIZED:"):
        # Blocked, but for an unrelated reason: rebinding protection was never
        # the thing that stopped it.
        pp10 = f"BLOCKED_FOR_OTHER_REASON:{r2.split(':')[0]}"
    elif rebind_ip and not r2.endswith(rebind_ip):
        pp10 = f"WRONG_IP_IN_DENIAL:{r2}"
    else:
        pp10 = "BLOCK"
    rec("PP10", "rebind 2nd flips -> denied BY rebinding check", "BLOCK",
        pp10, f"reason={r2} expect_ip={rebind_ip or '<any>'}")
    o = tunnel("allowed.lab", path="/needsauth", cred="cred_alpha")
    rec("PP11", "authorized credential injected", "ALLOW", v(o))
    rec("PP12", "upstream saw credential", "YES",
        "YES" if b'"auth_present": true' in o["body"] else "NO")
    o = tunnel("allowed.lab", cred="cred_beta")
    rec("PP13", "credential from another program", "BLOCK",
        blocked_by(o, "CREDENTIAL_WRONG_PROGRAM"), o["reason"])

    print("\n[streaming]", flush=True)
    t0 = time.time()
    o = tunnel("allowed.lab", path="/big", timeout=60, read_body=False)
    dt = time.time() - t0
    rec("PP14", "2MB response streamed through", "ALLOW", v(o),
        f"{o['bytes']} bytes in {dt:.1f}s sha={o['sha'][:12]}")
    rec("PP15", "full body delivered (>=2MB)", "YES",
        "YES" if o["bytes"] >= 2 * 1024 * 1024 else f"NO({o['bytes']})")

    print("\n[concurrency limit]", flush=True)
    # POSITIVE CONTROL for PP16. The row asserts "excess connections are
    # rejected"; on the last real run it recorded limit=64 ok=0 — it proved the
    # limiter rejects while never showing the pool serves ANYTHING. A limiter
    # that rejects everything would have passed identically. Establish first
    # that a single connection succeeds.
    ctl = tunnel("allowed.lab", path="/ok", timeout=15)
    pool_serves = v(ctl) == "ALLOW"
    hits = {"limit": 0, "ok": 0, "other": 0}
    lock = threading.Lock()

    def hammer():
        r = tunnel("allowed.lab", path="/slow", timeout=25)
        with lock:
            if v(r) == "LIMIT":
                hits["limit"] += 1
            elif v(r) == "ALLOW":
                hits["ok"] += 1
            else:
                hits["other"] += 1

    ths = [threading.Thread(target=hammer, daemon=True) for _ in range(80)]
    for t in ths:
        t.start()
    time.sleep(6)
    rec("PP16", "excess connections rejected with audited 503", "YES",
        ("NO_POSITIVE_CONTROL" if not pool_serves else
         ("YES" if hits["limit"] > 0 else "NO")),
        f"limit={hits['limit']} ok={hits['ok']} pool_serves={pool_serves} "
        f"control={v(ctl)}")

    print("\n[kill switch vs live connections]", flush=True)
    # The pool was just saturated by PP16. Wait for it to drain first: a request
    # rejected with 503 would otherwise look like "terminated by kill switch",
    # which is a false positive, not a proof.
    for _ in range(120):
        probe = tunnel("allowed.lab", path="/ok", timeout=8)
        if v(probe) == "ALLOW":
            break
        time.sleep(1)
    else:
        rec("PP17", "kill switch: pool never drained (cannot test)", "TERMINATED",
            "POOL_SATURATED")
        probe = None

    if probe is not None:
        holder = {"partial": 0, "err": "", "status": 0, "clen": 0}

        def drip():
            # /drip sends a REAL partial body then stalls, so the stream is
            # provably live at the moment the switch is thrown.
            try:
                s = socket.create_connection((GW, GW_PORT), 45)
                s.sendall((f"CONNECT slow.lab:443 HTTP/1.1\r\nHost: slow.lab:443\r\n"
                           f"X-Strix-Asset: a1\r\nX-Strix-Nonce: {TEST_NONCE}\r\n"
                           f"X-Strix-Row: PP18\r\n\r\n").encode())
                b = b""
                while b"\r\n\r\n" not in b:
                    c = s.recv(4096)
                    if not c:
                        break
                    b += c
                if b" 200 " not in b:
                    holder["err"] = "CONNECT_" + b.split(b" ")[1].decode("latin-1", "replace")
                    return
                ctx = ssl.create_default_context(cafile=CA)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                tls = ctx.wrap_socket(s, server_hostname="slow.lab")
                tls.sendall(f"GET /drip HTTP/1.1\r\nHost: slow.lab\r\n"
                            f"Connection: close\r\n\r\n".encode())
                got = b""
                while True:
                    c = tls.recv(65536)
                    if not c:
                        break                      # clean EOF == torn down
                    got += c
                    if not holder["clen"] and b"\r\n\r\n" in got:
                        for ln in got.split(b"\r\n\r\n")[0].split(b"\r\n"):
                            if ln.lower().startswith(b"content-length:"):
                                holder["clen"] = int(ln.split(b":")[1])
                    holder["partial"] = len(got.partition(b"\r\n\r\n")[2])
            except Exception as e:
                holder["err"] = type(e).__name__

        t = threading.Thread(target=drip, daemon=True)
        t.start()
        for _ in range(80):
            if holder["partial"] > 0:
                break
            time.sleep(0.25)
        live = holder["partial"] > 0
        with open("/out/ARM_KILL", "w") as fh:
            fh.write("go")
        t.join(timeout=40)
        # A torn-down stream reaches the client as a CLEAN EOF, not an
        # exception. So the honest client-side signal is TRUNCATION: bytes were
        # received, but fewer than Content-Length promised. (Authoritative proof
        # is host-side in PP18 — the client's socket is not evidence.)
        truncated = live and holder["clen"] and holder["partial"] < holder["clen"]
        killed = bool(holder["err"]) or truncated
        rec("PP17", "kill switch tears down a LIVE stream (partial body first)",
            "TERMINATED",
            "TERMINATED" if (live and killed) else
            ("NO_LIVE_STREAM" if not live else "SURVIVED"),
            f"got={holder['partial']}/{holder['clen']} err={holder['err']}")
        with open("/out/pep_kill.json", "w") as fh:
            # NOTE: advisory only. The Evidence Auditor re-derives PP18 from the
            # raw host audit and ignores this file entirely.
            json.dump({"row_id": "PP18", "test_nonce": TEST_NONCE,
                       "origin": "sandbox", "run_id": None,
                       "partial_bytes": holder["partial"],
                       "content_length": holder["clen"], "err": holder["err"]}, fh)

    # The sandbox is NEVER told this execution's run_id, so it cannot stamp one.
    # run_id stays null here and is written by the control plane after collection
    # (stamp_artifacts.py). An artifact that arrives already bearing a run_id is
    # therefore self-labelled and the auditor rejects it (E8).
    out = {"results": results,
           "passed": sum(1 for r in results if r.get("status") == "PROVEN"),
           "total": len(results), "origin": "sandbox", "run_id": None,
           "test_nonce": TEST_NONCE}
    with open("/out/pep_results.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\n[pep-client] {out['passed']}/{out['total']} behaved as required", flush=True)


if __name__ == "__main__":
    main()

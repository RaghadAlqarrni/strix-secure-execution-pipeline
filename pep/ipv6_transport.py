#!/usr/bin/env python3
"""
IPv6 ACCEPTANCE — LAYER B (transport). Runs from the SANDBOX position.

These are the rows that make IPv6 real: actual AF_INET6 sockets, actual routes,
actual TLS over v6. They require a host booted WITHOUT ``ipv6.disable=1`` and a
dual-stack Docker topology. Nothing here is provable by reasoning about
addresses; that is Layer A's job.

Writes /out/ipv6_layerb.json, which ipv6_acceptance.py consumes for the combined
verdict. Absent that file, Layer B counts as BLOCKED_ENV — never as passed.
"""
from __future__ import annotations

import json
import os
import secrets
import socket
import ssl
import subprocess
import threading
import time

GW6 = os.environ["GW6"]                    # PEP address on the internal v6 net
GW_PORT = int(os.environ.get("GW_PORT", "3128"))
TGT6 = os.environ["TGT6"]                  # authorized target, v6, egress side
SLOW6_HOST = os.environ.get("SLOW6_HOST", "slow6.lab")
ALLOWED6_HOST = os.environ.get("ALLOWED6_HOST", "allowed6.lab")
EVIL6_HOST = os.environ.get("EVIL6_HOST", "evil6.lab")
CA = os.environ.get("SANDBOX_CA", "/ca/ca.crt")
B7_ADVISORY = os.environ.get("B7_ADVISORY", "/b7/b7_advisory.json")

# Unguessable per-run nonce. It travels in the request path, so it lands in the
# PEP's audit ``url`` AND inside the bytes covered by request_hash. The host-side
# verifier matches on THIS, not on hostname or timestamp — otherwise a valid but
# STALE IPv6 ALLOW from an earlier run would satisfy the check.
# ONE unguessable nonce per execution (contract: B8_nonce == B9_nonce). Which
# row a record belongs to is carried in a SEPARATE structural field (row_id),
# not as a string suffix — suffixes forced prose parsing and collided on
# prefixes ("abc-b3" vs "abc-b30").
TEST_NONCE = os.environ.get("TEST_NONCE") or secrets.token_hex(16)

rows: list[dict] = []


def rec(tid, desc, expect, got, detail=""):
    ok = expect == got
    rows.append({"layer": "B", "id": tid, "desc": desc, "expect": expect,
                 "got": got, "status": "PROVEN" if ok else str(got),
                 "pass": ok, "detail": str(detail)[:200]})
    print(f"  {'PASS' if ok else 'FAIL'}  {tid:6} {desc:56} expect={expect:12} got={got}",
          flush=True)


# ---------------------------------------------------------------------------
# TRANSPORT OBSERVATION LAYER
#
# tcp6() OBSERVES. It does not judge. The previous version was:
#
#     except Exception:
#         return "BLOCKED"
#
# which collapsed *every* failure into "BLOCKED" — no IPv6 stack, no route, a
# malformed address, a timeout, and an actively refused connection all became
# the same word. Three separate Layer B rows (B1, B2, B7) then treated that word
# as proof that enforcement had worked. A row could therefore PASS on a host
# where egress was wide open, simply because the probe never left the machine.
#
# Each observation below is a DIFFERENT fact about the world. Which of them
# constitutes proof is decided by each test, not here.
#
# The classification is not the point — the REASONING is. Four questions decide
# where each errno lands:
#     (1) What happened?
#     (2) Did the packet necessarily REACH the target?
#     (3) Did the boundary under test necessarily get an OPPORTUNITY to decide?
#     (4) Can this observation ALONE prove enforcement?
#
# REACHABLE            (1) three-way handshake completed.
#                      (2) yes. (3) yes. (4) it proves the OPPOSITE — nothing
#                      blocked it. -> FAILED_OPEN
#
# TIMEOUT              (1) sent, nothing ever came back (ETIMEDOUT / socket
#                      timeout). (2) it left the host; whether it arrived is
#                      unknown. (3) yes — a silent DROP is what a filtering
#                      boundary does. (4) YES, but only WITH a positive control:
#                      an unoccupied address times out identically.
#                      -> BLOCKING
#
# NO_ROUTE             (1) the kernel had no path (ENETUNREACH / EHOSTUNREACH).
#                      (2) no — refused locally, or an ICMP unreachable came
#                      back. (3) yes: on an --internal network, "no route out"
#                      IS the containment. (4) yes, with a positive control
#                      proving the same target is reachable THROUGH the PEP.
#                      -> BLOCKING
#
# CONNECTION_REFUSED   (1) an RST came back (ECONNREFUSED). (2) yes — something
#                      received it. (3) an endpoint ANSWERED, so the packet was
#                      not dropped. (4) NO. It proves reachability, not
#                      blocking; the refusing party may not even be the target.
#                      -> INCONCLUSIVE
#
# PERMISSION_DENIED    (1) the LOCAL stack refused to send (EACCES / EPERM —
#                      netfilter OUTPUT, seccomp, an LSM, a cgroup/connect6 BPF
#                      hook). (2) NO — it never left the sandbox. (3) NO — the
#                      boundary OUTSIDE the sandbox was never consulted.
#                      (4) no. Judging this as blocking would treat a local
#                      event as a remote one, the same error that (correctly)
#                      excludes CONNECTION_REFUSED. -> INCONCLUSIVE
#
# INVALID_ADDRESS      (1) the probe was malformed (EINVAL — e.g. link-local
#                      without a scope id — or gaierror). (2) no. (3) no.
#                      (4) no: this is a TEST DEFECT wearing a security result's
#                      clothes. -> INCONCLUSIVE
#
# NO_IPV6_STACK        (1) AF_INET6 unsupported (EAFNOSUPPORT). (2) no. (3) no.
#                      (4) no — the test did not run. -> INCONCLUSIVE
#
# LINK_DOWN            (1) the local interface is down (ENETDOWN). (2) no.
#                      (3) no. (4) no — apparatus failure. -> INCONCLUSIVE
#
# Note (2) and (3) diverge for NO_ROUTE: the packet may not leave, yet the
# absence of a route IS the boundary in this topology. That is why the partition
# cannot be derived from "did it leave the host" alone.
# ---------------------------------------------------------------------------
import errno as _errno

# Observations consistent with the boundary having dropped the packet. Note what
# is NOT here: CONNECTION_REFUSED (something replied), INVALID_ADDRESS and
# NO_IPV6_STACK (the probe never happened).
# Consistent with the packet having LEFT the sandbox and been dropped by the
# boundary under test.
BLOCKING_OBSERVATIONS = ("TIMEOUT", "NO_ROUTE")
# The probe never reached the boundary, so nothing about it was measured.
#   CONNECTION_REFUSED  something ANSWERED with a reset — not a drop
#   PERMISSION_DENIED   EACCES/EPERM on connect() is a LOCAL refusal (netfilter
#                       OUTPUT, seccomp, an LSM or a cgroup/connect6 BPF hook).
#                       The packet never left the sandbox, so the boundary
#                       OUTSIDE it never had an opportunity to decide. Grouping
#                       it with TIMEOUT judged a local event as if it were
#                       remote — inconsistent with the same reasoning that
#                       (correctly) excludes CONNECTION_REFUSED.
#   LINK_DOWN           the local interface is down: apparatus failure.
INCONCLUSIVE_OBSERVATIONS = ("INVALID_ADDRESS", "NO_IPV6_STACK",
                             "CONNECTION_REFUSED", "PERMISSION_DENIED",
                             "LINK_DOWN")


def tcp6(addr: str, port: int, timeout: float = 3.0) -> str:
    """Direct AF_INET6 connect, deliberately bypassing the PEP.

    Returns a DISTINGUISHABLE observation (see above), never a verdict.
    ``addr`` may carry a scope id (``fe80::1%eth0``); getaddrinfo resolves it
    into the sockaddr, which bare connect() cannot do for link-local.
    """
    s = None
    try:
        infos = socket.getaddrinfo(addr, port, socket.AF_INET6, socket.SOCK_STREAM)
        if not infos:
            return "INVALID_ADDRESS"
        family, socktype, proto, _canon, sockaddr = infos[0]
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        s.connect(sockaddr)
        return "REACHABLE"
    except socket.gaierror:
        return "INVALID_ADDRESS"
    except socket.timeout:
        return "TIMEOUT"
    except OSError as exc:
        e = exc.errno
        if e == _errno.ENETDOWN:
            return "LINK_DOWN"          # local interface down != enforcement
        if e in (_errno.ENETUNREACH, _errno.EHOSTUNREACH):
            return "NO_ROUTE"
        if e in (_errno.EACCES, _errno.EPERM):
            return "PERMISSION_DENIED"
        if e == _errno.ECONNREFUSED:
            return "CONNECTION_REFUSED"
        if e in (_errno.EINVAL, _errno.EAFNOSUPPORT):
            return ("NO_IPV6_STACK" if e == _errno.EAFNOSUPPORT else "INVALID_ADDRESS")
        if e == _errno.ETIMEDOUT:
            return "TIMEOUT"
        return f"OTHER:{_errno.errorcode.get(e, e)}"
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def enforcement_verdict(obs: str, control_ok: bool) -> str:
    """Map a transport OBSERVATION to a verdict for a NEGATIVE security test.

    The rule this encodes, and the reason it exists at module scope where it can
    be tested independently:

        "could not reach target"  !=  "the boundary blocked target"

    A negative result counts only when the probe demonstrably reached the point
    at which the control under test had an opportunity to decide. Anything else
    is INCONCLUSIVE or NO_POSITIVE_CONTROL — never PROVEN.
    """
    if not control_ok:
        return "NO_POSITIVE_CONTROL"
    if obs == "REACHABLE":
        return "FAILED_OPEN"
    if obs in BLOCKING_OBSERVATIONS:
        return "PROVEN"
    return f"INCONCLUSIVE_{obs}"


def scoped_ll(addr: str) -> str:
    """Attach this container's interface scope to a link-local address.

    ``fe80::`` addresses are NOT routable without a scope id: connecting to a
    bare ``fe80::1`` fails with EINVAL on most stacks. The old B7 read that
    EINVAL as "blocked" — so B7 would have passed on a host with link-local
    egress completely open. Returns the address unchanged if no interface can
    be determined, and the caller then sees INVALID_ADDRESS rather than a
    fabricated pass.
    """
    if "%" in addr:
        return addr
    for name in ("eth0", "eth1"):
        try:
            if socket.if_nametoindex(name):
                return f"{addr}%{name}"
        except OSError:
            continue
    # Deliberately NO "pick any interface" fallback. if_nameindex()[-1] returns
    # an arbitrary entry (it can be lo or a veth); a probe scoped to the wrong
    # link is meaningless, and if it happens to yield EHOSTUNREACH it would read
    # as PROVEN. Returning the address unscoped makes tcp6() report
    # INVALID_ADDRESS, which is inconclusive — the honest outcome.
    return addr


def tunnel6(host, port=443, path="/ok", method="GET", sni=None, http_host=None,
            check_hostname=True, timeout=30, asset="a1", row=""):
    """CONNECT to the PEP over IPv6, then TLS inside the tunnel."""
    out = {"connect": 0, "reason": "", "status": 0, "body": b"", "err": "", "bytes": 0}
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((GW6, GW_PORT))
    except Exception as e:
        out["err"] = f"NOGW:{type(e).__name__}"
        return out
    req = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}",
           f"X-Strix-Asset: {asset}",
           f"X-Strix-Nonce: {TEST_NONCE}", f"X-Strix-Row: {row}"]
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
                for ln in c.decode("latin-1", "replace").split("\r\n"):
                    if ln.lower().startswith("x-pdp-reason:"):
                        out["reason"] = ln.split(":", 1)[1].strip()
                first = False
            out["bytes"] += len(c)
            if len(out["body"]) < 2048:
                out["body"] += c
    except Exception as e:
        if out["bytes"] == 0:
            out["err"] = f"IO:{type(e).__name__}"
    finally:
        try:
            tls.close()
        except Exception:
            pass
    return out


def v(o):
    if o["err"].startswith("NOGW"):
        return "NOGW"
    if o["connect"] == 403 or o["status"] == 403:
        return "BLOCK"
    if o["err"].startswith("TLS"):
        return "TLSFAIL"
    if o["status"] == 200:
        return "ALLOW"
    if 300 <= o["status"] < 400:
        return "REDIRECT"
    return f"OTHER{o['status']}"


def main() -> int:
    print(f"\n[LAYER B — transport (live IPv6)]  nonce={TEST_NONCE[:12]}…", flush=True)

    # ---- POSITIVE CONTROL FIRST -------------------------------------------
    # A "BLOCKED" direct result is meaningless if the v6 target simply is not
    # listening. So establish first that the target IS live and IS reachable
    # THROUGH the PEP; only then does a direct-path failure prove enforcement
    # rather than absence. B1/B3 are therefore evaluated as a PAIR.
    via = tunnel6(ALLOWED6_HOST, path="/ok", row="B3")
    via_ok = v(via) == "ALLOW"
    # Raw v6 reachability of the PEP itself, independent of the tunnel logic.
    # This separates "the sandbox has no working IPv6 at all" from "the tunnel
    # was refused" — the two have completely different meanings and the old
    # code could not tell them apart.
    stack_obs = tcp6(GW6, GW_PORT, timeout=5)
    stack_ok = stack_obs == "REACHABLE"
    direct = tcp6(TGT6, 443)
    print(f"    control: v6-stack={stack_obs}  via-PEP={v(via)}  direct={direct}",
          flush=True)

    rec("B1", "direct IPv6 egress bypass blocked (vs live positive control)",
        "PROVEN",
        enforcement_verdict(direct, via_ok and stack_ok),
        f"direct={direct} via_pep={v(via)} v6_stack={stack_obs}")

    # B2 — NET_ADMIN route injection over v6 must not create a path. Re-checked
    # against the same positive control.
    # ROUTE injection only. The previous list also ran
    #     ip -6 addr add <TGT6>/128 dev eth0
    # which makes the target a LOCAL address of the sandbox — the probe is then
    # delivered to the sandbox itself, nothing listens there, and the result is
    # ECONNREFUSED. Under the old blanket-BLOCKED classifier that read as a
    # pass; it never tested egress at all.
    cmds = [
        ["busybox", "ip", "-6", "route", "add", "default", "dev", "eth0"],
        ["busybox", "ip", "-6", "route", "add", f"{TGT6}/128", "dev", "eth0"],
    ]
    applied = []
    for c in cmds:
        try:
            applied.append(f"rc={subprocess.run(c, capture_output=True, text=True).returncode}")
        except OSError as exc:
            # busybox missing would otherwise raise and kill the whole run.
            applied.append(f"err={type(exc).__name__}")
    after = tcp6(TGT6, 443)
    # A route-injection test is only meaningful if the injection commands
    # actually executed. rc!=0 on all three means busybox/NET_ADMIN was absent,
    # so nothing was injected and "still blocked" proves nothing.
    # Every entry in `applied` is now a ROUTE add, so rc=0 on any of them means a
    # route really was installed. The old guard accepted rc=0 from the addr-add,
    # i.e. it was satisfied precisely when no route had been injected.
    injected = any(a == "rc=0" for a in applied)
    rec("B2", "IPv6 route injection via NET_ADMIN is blocked", "PROVEN",
        (enforcement_verdict(after, via_ok and stack_ok) if injected
         else "NO_POSITIVE_CONTROL"),
        f"after_injection={after} injected={injected} " + " ".join(applied))

    # B3 — prove the PATH, not mere reachability: direct must be BLOCKED *and*
    # the PEP path must be ALLOWED, in the same run against the same target.
    rec("B3", "path proof: direct BLOCKED and via-PEP ALLOWED", "PROVEN",
        ("PROVEN" if (via_ok and direct in BLOCKING_OBSERVATIONS)
         else ("NO_POSITIVE_CONTROL" if not via_ok
               else ("FAILED_OPEN" if direct == "REACHABLE"
                     else f"INCONCLUSIVE_{direct}"))),
        f"via_pep={v(via)} direct={direct} bytes={via['bytes']}")

    # B4 — Host/SNI stay bound to the canonical host over a v6 destination.
    o = tunnel6(ALLOWED6_HOST, sni=EVIL6_HOST, check_hostname=False, row="B4")
    sni_ok = v(o) == "BLOCK" and "SNI_MISMATCH" in o["reason"]
    o2 = tunnel6(ALLOWED6_HOST, http_host=EVIL6_HOST, row="B4")
    host_ok = v(o2) == "BLOCK" and "HOST_HEADER_MISMATCH" in o2["reason"]
    rec("B4", "Host/SNI bound to canonical host over IPv6 destination", "PROVEN",
        "PROVEN" if (sni_ok and host_ok) else "FAILED",
        f"sni={o['reason']} host={o2['reason']}")

    # B5 — interception actually happened over v6 (body came from upstream via
    #      a TLS session the PEP terminated with its own minted leaf).
    o = tunnel6(ALLOWED6_HOST, path="/ok", row="B5")
    intercepted = v(o) == "ALLOW" and b'"target"' in o["body"]
    rec("B5", "TLS interception over IPv6", "PROVEN",
        "PROVEN" if intercepted else "FAILED", f"bytes={o['bytes']}")

    # B7 — owner-approved DEC-7 semantic amendment.
    #
    # The sandbox does NOT decide this row. A host-side harness observes the
    # exact UDP attempt before enforcement, identifies the pre-existing DROP
    # event, keeps an occupied receiver alive through C1/M/C2, and performs a
    # distinct calibration. This file reads only a host-owned advisory so the
    # Layer-B schema can carry B7. E9 later ignores the advisory verdict and
    # independently re-derives the claim from the raw host evidence.
    try:
        with open(B7_ADVISORY, encoding="utf-8") as fh:
            advisory = json.load(fh)
        if advisory.get("measurement_seen") is True:
            b7 = "FAILED_OPEN"
        elif advisory.get("ready_for_e9") is True:
            b7 = "PROVEN"
        else:
            b7 = str(advisory.get("status") or "APPARATUS_FAILURE")
        b7_detail = (f"host_advisory={advisory.get('status')} "
                     f"evidence_sha256={advisory.get('evidence_sha256', '')}")
    except Exception as exc:
        b7 = f"APPARATUS_FAILURE:{type(exc).__name__}"
        b7_detail = f"host advisory unreadable at {B7_ADVISORY}"
    if not (via_ok and stack_ok):
        b7 = "NO_POSITIVE_CONTROL"
    rec("B7", "direct non-PEP off-link IPv6 UDP egress containment",
        "PROVEN", b7, b7_detail)

    # B6 — LIVE-STREAM kill test over IPv6. The client must already have received
    # body bytes before the switch is thrown, otherwise "terminated" is
    # indistinguishable from "never connected". /drip sends a real partial body
    # and then stalls, so partial_bytes > 0 is the proof the stream was live.
    holder: dict = {"partial": 0, "err": "", "status": 0, "clen": 0}

    def drip():
        try:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(40)
            s.connect((GW6, GW_PORT))
            s.sendall((f"CONNECT {SLOW6_HOST}:443 HTTP/1.1\r\n"
                       f"Host: {SLOW6_HOST}:443\r\nX-Strix-Asset: a1\r\n"
                       f"X-Strix-Nonce: {TEST_NONCE}\r\nX-Strix-Row: B6\r\n\r\n").encode())
            b = b""
            while b"\r\n\r\n" not in b:
                c = s.recv(4096)
                if not c:
                    break
                b += c
            if b" 200 " not in b:
                holder["err"] = "CONNECT_DENIED"
                return
            ctx = ssl.create_default_context(cafile=CA)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            tls = ctx.wrap_socket(s, server_hostname=SLOW6_HOST)
            tls.sendall(f"GET /drip HTTP/1.1\r\nHost: {SLOW6_HOST}\r\n"
                        f"Connection: close\r\n\r\n".encode())
            got = b""
            while True:
                c = tls.recv(65536)
                if not c:
                    break                          # clean EOF == torn down
                got += c
                if holder["status"] == 0 and b" 200 " in got:
                    holder["status"] = 200
                if not holder["clen"] and b"\r\n\r\n" in got:
                    for ln in got.split(b"\r\n\r\n")[0].split(b"\r\n"):
                        if ln.lower().startswith(b"content-length:"):
                            holder["clen"] = int(ln.split(b":")[1])
                holder["partial"] = len(got.partition(b"\r\n\r\n")[2])
        except Exception as e:
            holder["err"] = type(e).__name__

    t = threading.Thread(target=drip, daemon=True)
    t.start()
    # wait until the stream is genuinely live (headers + some body received)
    for _ in range(60):
        if holder["partial"] > 0:
            break
        time.sleep(0.25)
    live = holder["partial"] > 0
    with open("/out/ARM_KILL", "w") as fh:
        fh.write("go")
    t.join(timeout=35)
    # clean EOF is what termination looks like client-side; truncation is the
    # honest signal. Authoritative proof is host-side (B9).
    truncated = live and holder["clen"] and holder["partial"] < holder["clen"]
    terminated = bool(holder["err"]) or truncated
    rec("B6", "kill switch tears down a LIVE IPv6 stream (partial body first)",
        "PROVEN",
        "PROVEN" if (live and terminated) else
        ("NO_LIVE_STREAM" if not live else "SURVIVED"),
        f"got={holder['partial']}/{holder['clen']} err={holder['err']}")
    # hand the observed partial-byte count to the host-side audit verifier
    with open("/out/b6_client.json", "w") as fh:
        json.dump({"partial_bytes": holder["partial"], "err": holder["err"],
                   "content_length": holder["clen"],
                   "live": live, "terminated": terminated,
                   "test_nonce": TEST_NONCE,
                   "origin": "sandbox", "run_id": None}, fh)

    passed = sum(1 for x in rows if x.get("status") == "PROVEN")
    # See pep_client.py: the sandbox has no access to the control-plane run_id.
    out = {"schema_version": "strix-layerb-v2-dec7-e9", "rows": rows,
           "passed": passed, "total": len(rows),
           "origin": "sandbox", "run_id": None, "test_nonce": TEST_NONCE}
    with open("/out/ipv6_layerb.json", "w") as fh:
        json.dump(out, fh, indent=2)
    print(f"\n[layer-b] {passed}/{len(rows)} proven", flush=True)
    return 0 if passed == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())

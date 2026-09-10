#!/usr/bin/env python3
"""
P1-1 PROOF -- phase2b/target_https.py accepts real IPv6 connections (P2-CRIT-1).

THE DEFECT (TRIAGE_UNIFIED.md, P2-CRIT-1)
  `srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)` inherits address_family =
  AF_INET. Every IPv6 connection the PEP forwarded to this target hit
  ECONNREFUSED before reaching application code -- not because the PEP's
  enforcement decision was wrong, but because the thing on the other side of
  it could not be reached over IPv6 at all. TRIAGE_UNIFIED.md's P3-CRIT-1
  names this as making E1/E3/E4 "jointly unpassable on any live run": no IPv6
  ALLOW record naming this target could physically exist, no matter how
  correct pdp.py's decision logic was.

WHAT THIS PROVES, AND WHAT IT DELIBERATELY DOES NOT
  This tests the TRANSPORT-level property only -- can a real TCP connection
  be established over both address families -- using target_https.py's own
  DualStackHTTPServer class directly. It does NOT exercise TLS and does NOT
  run inside the actual Docker sandbox topology. Those layers need a real
  dual-stack gate run, which this proof is not and does not claim to be.

ENVIRONMENT PRECONDITION -- CHECKED, NOT ASSUMED
  This proof needs a host kernel that can create AF_INET6 sockets at all. A
  container with no IPv6 stack fails BOTH the negative control's connection
  attempt AND the repaired class's own socket() call with the identical
  errno (EAFNOSUPPORT) -- so a naive negative-control PASS here would be a
  PASS for the wrong reason: not "AF_INET-only correctly refuses an IPv6
  peer" but "nothing in this container can speak IPv6 regardless of the
  code". That is precisely the "consistent with blocking does not exclude
  the mundane explanation" trap this project's methodology exists to catch,
  so capability is checked FIRST and the whole executed section is skipped
  and reported ENVIRONMENT-BLOCKED if it is absent, rather than let a
  misleading PASS or a crash stand.

NEGATIVE CONTROL (only run if the environment can test it)
  The exact pre-fix shape -- plain ThreadingHTTPServer(("0.0.0.0", PORT), H)
  -- is bound for real and an IPv6 connection is attempted against it. If
  that connection does NOT fail, this proof is not exercising the defect and
  its PASS on the repaired class is void.
"""
from __future__ import annotations

import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
ROOT = os.path.dirname(PEP)
PHASE2B = os.path.join(ROOT, "phase2b")
sys.path.insert(0, PHASE2B)

# target_https.py reads these at MODULE level (os.environ[...], no default) --
# they must exist before import. Values are inert for this proof: no TLS
# handshake is attempted, and CERT/KEY paths are never opened because H is
# never wrapped in an ssl.SSLContext here.
os.environ.setdefault("TARGET_NAME", "p1-proof")
os.environ.setdefault("TARGET_CERT", "/dev/null")
os.environ.setdefault("TARGET_KEY", "/dev/null")

import target_https  # noqa: E402  (phase2b/target_https.py)
from http.server import ThreadingHTTPServer  # noqa: E402


def ipv6_socket_capable() -> tuple[bool, str]:
    """Can this kernel create an AF_INET6 socket at all? Checked directly,
    not inferred from a connection attempt (which conflates 'no IPv6 stack'
    with 'nothing answered')."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.close()
        return True, "AF_INET6 socket() succeeded"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _try_connect(addr: str, port: int, timeout: float = 2.0) -> tuple[bool, str]:
    try:
        with socket.create_connection((addr, port), timeout=timeout):
            return True, "connected"
    except OSError as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _serve_in_background(srv) -> None:
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def under_test() -> bool:
    srv = target_https.DualStackHTTPServer(("::", 0), target_https.H)
    port = srv.socket.getsockname()[1]
    _serve_in_background(srv)
    try:
        v6_ok, v6_detail = _try_connect("::1", port)
        v4_ok, v4_detail = _try_connect("127.0.0.1", port)
    finally:
        srv.shutdown()
        srv.server_close()

    print('  UNDER TEST: target_https.DualStackHTTPServer(("::", 0), H)')
    print(f"    IPv6 connect to ::1:{port}       -> {'OK' if v6_ok else 'FAIL'}  ({v6_detail})")
    print(f"    IPv4 connect to 127.0.0.1:{port} -> {'OK' if v4_ok else 'FAIL'}  ({v4_detail})")
    ok = v6_ok and v4_ok
    print(f"    {'PASS' if ok else 'FAIL'} -- both families must reach the same listener")
    return ok


def negative_control() -> bool:
    srv = ThreadingHTTPServer(("0.0.0.0", 0), target_https.H)  # noqa: S104  (pre-fix shape)
    port = srv.socket.getsockname()[1]
    _serve_in_background(srv)
    try:
        v6_ok, v6_detail = _try_connect("::1", port)
    finally:
        srv.shutdown()
        srv.server_close()

    print('  NEGATIVE CONTROL: plain ThreadingHTTPServer(("0.0.0.0", 0), H)  (pre-fix shape)')
    print(f"    IPv6 connect to ::1:{port}       -> {'OK' if v6_ok else 'FAIL'}  ({v6_detail})")
    ok = not v6_ok
    print(f"    {'PASS' if ok else 'FAIL'} -- the control MUST refuse IPv6, "
          f"otherwise this proof never exercised P2-CRIT-1")
    return ok


def class_shape_check() -> bool:
    """Static corroboration that needs no IPv6 capability -- runs regardless."""
    cls = target_https.DualStackHTTPServer
    fam_ok = cls.address_family == socket.AF_INET6
    print("  STATIC (CODE-VERIFIED, no IPv6 capability needed):")
    print(f"    DualStackHTTPServer.address_family == socket.AF_INET6  -> {fam_ok}")
    return fam_ok


if __name__ == "__main__":
    print("-- P1-1: phase2b/target_https.py dual-stack bind (P2-CRIT-1) --\n")

    capable, detail = ipv6_socket_capable()
    print(f"  PRECONDITION: can this host create an AF_INET6 socket at all?")
    print(f"    {detail}")
    print()

    c = class_shape_check()
    print()

    if not capable:
        print("  EXECUTED negative control and under-test SKIPPED: this environment")
        print("  cannot create an AF_INET6 socket at all (client OR server side), so")
        print("  both would fail identically regardless of which code is running --")
        print("  a 'PASS' here would be evidence of nothing. Reporting the true state")
        print("  rather than a misleading green line.")
        print()
        print(f"  P1-1: ENVIRONMENT-BLOCKED (static shape check: "
              f"{'PASS' if c else 'FAIL'})")
        print("  Re-run this file on a real dual-stack host (e.g. the Ubuntu VM) to")
        print("  get an EXECUTION-VERIFIED result. Exit code reflects the static")
        print("  check only -- it is NOT a substitute for that run.")
        sys.exit(0 if c else 1)

    a = negative_control()
    print()
    b = under_test()
    ok = a and b and c
    print()
    print(f"  P1-1: {'PASS' if ok else 'FAIL'}   "
          f"(negative_control_fired={a}, repair_holds={b}, static={c})")
    print("  SCOPE: transport-level bind only (no TLS, no Docker sandbox). Not a")
    print("  substitute for a real dual-stack gate run.")
    sys.exit(0 if ok else 1)

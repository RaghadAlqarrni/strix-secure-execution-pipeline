#!/usr/bin/env python3
"""Phase 2b HTTPS test target. Local only. Reports what the GATEWAY sent upstream."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ["TARGET_NAME"]
CERT = os.environ["TARGET_CERT"]
KEY = os.environ["TARGET_KEY"]
PORT = int(os.environ.get("TARGET_PORT", "443"))
REDIRECT_TO = os.environ.get("REDIRECT_TO", "https://evil.lab/pwned")
SLOW_SECONDS = float(os.environ.get("SLOW_SECONDS", "20"))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a) -> None:
        print(f"[{NAME}] {self.command} {self.path} host={self.headers.get('Host')} "
              f"auth={'yes' if self.headers.get('Authorization') else 'no'}", flush=True)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", REDIRECT_TO)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/big"):
            # large body so streaming (vs buffering) is observable
            n = int(os.environ.get("BIG_BYTES", "2097152"))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(n))
            self.end_headers()
            block = b"A" * 65536
            sent = 0
            while sent < n:
                w = min(len(block), n - sent)
                try:
                    self.wfile.write(block[:w])
                except Exception:
                    return
                sent += w
            return
        if self.path.startswith("/drip"):
            # Headers + a REAL partial body, then stall. This is what makes a
            # kill-switch test a live-stream test: the client has already
            # received bytes when the switch is thrown, so termination cannot be
            # confused with "never connected".
            n = int(os.environ.get("DRIP_TOTAL", "1048576"))
            head = int(os.environ.get("DRIP_HEAD", "4096"))
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(n))
            self.end_headers()
            try:
                self.wfile.write(b"D" * head)
                self.wfile.flush()
            except Exception:
                return
            time.sleep(SLOW_SECONDS)
            try:
                self.wfile.write(b"D" * (n - head))
            except Exception:
                pass
            return
        if self.path.startswith("/slow"):
            # Headers first, then stall — lets the kill switch be tested against
            # a connection that is already established and mid-transfer.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "16")
            self.end_headers()
            time.sleep(SLOW_SECONDS)
            try:
                self.wfile.write(b"slow-body-done!!")
            except Exception:
                pass
            return
        auth = self.headers.get("Authorization")
        body = json.dumps({
            "target": NAME, "path": self.path,
            "host_header_seen": self.headers.get("Host"),
            "auth_present": bool(auth),
            "auth_fingerprint": hashlib.sha256(auth.encode()).hexdigest()[:12] if auth else None,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET


class DualStackHTTPServer(ThreadingHTTPServer):
    """Listener that accepts BOTH address families on one socket.

    P2-CRIT-1 (TRIAGE_UNIFIED.md): this target inherited
    ThreadingHTTPServer's address_family = AF_INET, so it was IPv4-ONLY —
    the same bug class already fixed in the PEP's own listener
    (pep/gateway.py's DualStackHTTPServer) and, until this fix, left here.

    The consequence was structural, not cosmetic: every IPv6 connection the
    PEP forwarded here hit ECONNREFUSED before reaching application code, so
    no IPv6 ALLOW record naming this target could ever exist. That is
    exactly what TRIAGE_UNIFIED.md's P3-CRIT-1 names as making E1/E3/E4
    "jointly unpassable on any live run" — not because the PEP's IPv6
    enforcement was broken, but because the thing on the other side of it
    could not be reached over IPv6 regardless of what the PEP decided. An
    IPv4-only host made this undetectable: the IPv4 suite passed 17/17 while
    the entire IPv6 path — PEP decision AND target reachability — silently
    did not exist.

    IPV6_V6ONLY is set EXPLICITLY, same rationale as the PEP listener: the
    platform default differs across kernels/distros, and IPv4 peers then
    arrive as ::ffff:a.b.c.d, which is fine here — this process only ever
    reflects back what it received (do_GET's body), it does not make any
    trust decision based on source address the way pdp.py does.
    """

    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


if __name__ == "__main__":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(CERT, KEY)

    # Dual-stack is the intended configuration. A host with no IPv6 must
    # still be able to run the IPv4 suite, so there is a fallback — but it
    # is LOUD, never silent. This process has no AuditLog (it runs on the
    # far side of the PEP boundary by design: a target's self-report is
    # advisory, never evidence — see audit_gate_evidence.py's E8 docstring),
    # so "loud" here means an unmistakable line on stdout, in container
    # logs, for whoever is reading the run — not an audit record. The actual
    # proof that IPv6 reached this target is the PEP's own ALLOW record
    # (pin_family=="ipv6"), which only a live IPv6 bind here can ever make
    # possible.
    try:
        srv = DualStackHTTPServer(("::", PORT), H)
        family = "dual-stack(::, v6only=0)"
    except OSError as exc:
        family = f"IPv4-ONLY(fallback: {type(exc).__name__}: {exc})"
        print(f"[{NAME}] *** DEGRADED: IPv6 bind failed ({exc}). Listening "
              f"IPv4-ONLY. This target cannot receive any IPv6 connection; "
              f"Layer B's IPv6 rows CANNOT pass while this line is showing.",
              flush=True)
        srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)  # noqa: S104

    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    bound = srv.socket.getsockname()[:2]
    print(f"[{NAME}] HTTPS {bound[0]}:{bound[1]} [{family}]", flush=True)
    srv.serve_forever()

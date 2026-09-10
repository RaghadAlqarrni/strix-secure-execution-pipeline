#!/usr/bin/env python3
"""
Phase 2b — TLS-intercepting Policy Enforcement Point (PROOF HARNESS).

Resolves A-1: CONNECT no longer blinds the L7 PDP. The gateway terminates TLS,
inspects HTTP, and restores Host consistency, redirect re-entry, method/path
policy, and request/response hashing for HTTPS.

Proof obligations implemented here (numbering follows the Phase 2 decision):
  1  CA private key is gateway-side only (never mounted into the sandbox)
  2  control plane binds to the egress interface only
  3  HTTPS cannot bypass the PDP via CONNECT
  4  SNI  != CONNECT authority        -> BLOCKED_BY_POLICY
  5  Host != canonical host           -> BLOCKED_BY_POLICY
  6  3xx is never auto-followed; each destination re-enters the PDP
  7  DNS: validate ALL answers, pin one IP, connect to the pin
  8  upstream certificate validation failure -> fail closed
  9  credential injected only AFTER authorization
 10  plaintext credentials never returned to the sandbox nor written to audit
 11  request/response hashes exist for HTTPS too
 12  malformed TLS / CONNECT / protocol -> explicit audited denial, never a crash
 13  kill switch tears down LIVE connections, not just new requests

Stdlib only.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from policy_gw import KILL_FILE, Decision, audit, canonical_host, load_policy, pdp

CERT_DIR = os.environ.get("PDP_CERTS", "/certs")
PEP_PORT = int(os.environ.get("PDP_PORT", "3128"))
CONTROL_IP = os.environ.get("PDP_CONTROL_IP", "127.0.0.1")
CONTROL_PORT = int(os.environ.get("PDP_CONTROL_PORT", "9000"))

_live: set[socket.socket] = set()
_live_lock = threading.Lock()


def track(sock: socket.socket) -> None:
    with _live_lock:
        _live.add(sock)


def untrack(sock: socket.socket) -> None:
    with _live_lock:
        _live.discard(sock)


def kill_watcher() -> None:
    """Obligation 13: when STOP_ALL appears, tear down every live socket."""
    armed = False
    while True:
        present = os.path.exists(KILL_FILE)
        if present and not armed:
            armed = True
            with _live_lock:
                victims = list(_live)
            for s in victims:
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
            audit({"decision": "KILL_SWITCH", "reason": "STOP_ALL_TORE_DOWN_LIVE_CONNECTIONS",
                   "connections_terminated": len(victims)})
        elif not present:
            armed = False
        time.sleep(0.25)


def leaf_paths(host: str) -> tuple[str, str] | None:
    crt = os.path.join(CERT_DIR, "leaf", f"{host}.crt")
    key = os.path.join(CERT_DIR, "leaf", f"{host}.key")
    return (crt, key) if os.path.exists(crt) and os.path.exists(key) else None


def read_http_request(sock: ssl.SSLSocket) -> tuple[str, str, dict[str, str], bytes] | None:
    """Minimal HTTP/1.1 request reader over the intercepted TLS stream."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            return None
        buf += chunk
        if len(buf) > 262144:
            return None
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    try:
        method, path, _ = lines[0].split(" ", 2)
    except ValueError:
        return None
    headers = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    body = rest
    need = int(headers.get("content-length") or 0)
    while len(body) < need:
        chunk = sock.recv(65536)
        if not chunk:
            break
        body += chunk
    return method, path, headers, body


def deny_over_tls(sock, reason: str, url: str, method: str) -> None:
    body = (f'{{"error":"BLOCKED_BY_POLICY","reason":"{reason}"}}').encode()
    resp = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
            b"X-PDP-Decision: BLOCKED_BY_POLICY\r\n"
            + f"X-PDP-Reason: {reason}\r\n".encode()
            + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
    try:
        sock.sendall(resp)
        # Closing while the peer still has unsent data pending makes the kernel
        # emit RST instead of FIN, which DISCARDS our send buffer — the sandbox
        # would then see a bare connection error instead of an explicit
        # BLOCKED_BY_POLICY. Drain briefly so the denial is actually delivered.
        sock.settimeout(1.0)
        try:
            while sock.recv(65536):
                pass
        except Exception:
            pass
    except Exception:
        pass
    audit({"decision": "BLOCKED_BY_POLICY", "reason": reason, "url": url,
           "method": method, "tls": True})


class TLSGateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "StrixPDP-TLS/0.1"

    def log_message(self, *a) -> None:
        pass

    def _deny_plain(self, reason: str, url: str, method: str) -> None:
        body = f'{{"error":"BLOCKED_BY_POLICY","reason":"{reason}"}}'.encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-PDP-Decision", "BLOCKED_BY_POLICY")
        self.send_header("X-PDP-Reason", reason)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        audit({"decision": "BLOCKED_BY_POLICY", "reason": reason, "url": url, "method": method})

    def __getattr__(self, name: str):
        # Obligation 12: no accidental 501 containment — every verb hits the PDP.
        if name.startswith("do_"):
            return lambda: self._deny_plain("UNSUPPORTED_PROTOCOL_OR_METHOD",
                                            self.path, name[3:])
        raise AttributeError(name)

    def do_GET(self) -> None:  # noqa: N802
        self._deny_plain("PLAINTEXT_HTTP_DISABLED_IN_PHASE2B", self.path, "GET")

    # ------------------------------------------------------------------ CONNECT
    def do_CONNECT(self) -> None:  # noqa: N802
        policy = load_policy()
        target = self.path
        host_raw, sep, p = target.rpartition(":")
        if not sep or not p.isdigit():
            return self._deny_plain("MALFORMED_CONNECT_TARGET", f"CONNECT {target}", "CONNECT")
        port = int(p)
        session = self.headers.get("X-Strix-Session", "")
        asset = self.headers.get("X-Strix-Asset", "")
        cred_id = self.headers.get("X-Strix-Cred", "")

        # Obligation 3: the tunnel request itself is a PDP decision.
        d = pdp(src_ip=self.client_address[0], host_raw=host_raw, port=port,
                method="CONNECT", session=session, asset=asset, cred_id=cred_id,
                policy=policy)
        if not d.allow:
            return self._deny_plain(d.reason, f"CONNECT {target}", "CONNECT")

        canon = canonical_host(host_raw)
        paths = leaf_paths(canon)
        if not paths:
            return self._deny_plain("NO_INTERCEPTION_CERT", f"CONNECT {target}", "CONNECT")

        self.send_response(200, "Connection Established")
        self.end_headers()

        seen_sni: list[str | None] = [None]

        def sni_cb(sslsock, sni, ctx):  # noqa: ANN001
            seen_sni[0] = sni

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(paths[0], paths[1])
        ctx.sni_callback = sni_cb

        raw = self.connection
        track(raw)
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            # Obligation 12: malformed / non-TLS bytes after CONNECT
            untrack(raw)
            audit({"decision": "BLOCKED_BY_POLICY", "reason": "MALFORMED_TLS_CLIENT_HELLO",
                   "detail": type(exc).__name__, "url": f"CONNECT {target}", "method": "CONNECT"})
            return
        track(tls)

        try:
            self._intercepted(tls, canon, port, d, session, asset, cred_id, policy, seen_sni[0])
        finally:
            untrack(tls)
            untrack(raw)
            try:
                tls.close()
            except Exception:
                pass
            self.close_connection = True

    def _intercepted(self, tls, canon, port, d, session, asset, cred_id, policy, sni) -> None:
        url_label = f"https://{canon}:{port}"

        # Obligation 4: SNI must match the authority the client asked to reach.
        if sni is not None and canonical_host(sni) != canon:
            return deny_over_tls(tls, f"SNI_MISMATCH:{sni}!={canon}", url_label, "CONNECT")

        req = read_http_request(tls)
        if req is None:
            audit({"decision": "BLOCKED_BY_POLICY", "reason": "MALFORMED_HTTP_IN_TUNNEL",
                   "url": url_label, "method": "?"})
            return
        method, path, headers, body = req

        # Obligation 5: Host header must equal the canonical host.
        hdr_host = canonical_host((headers.get("host") or "").split(":")[0])
        if hdr_host != canon:
            return deny_over_tls(tls, f"HOST_HEADER_MISMATCH:{hdr_host}!={canon}",
                                 url_label + path, method)

        # Re-run the PDP for the real method now that we can see it (obligation 3).
        # The pin from the CONNECT decision is passed through so this evaluation
        # does NOT re-resolve: one connection, one resolution, one address.
        d2 = pdp(src_ip=self.client_address[0], host_raw=canon, port=port, method=method,
                 session=session, asset=asset, cred_id=cred_id, policy=policy,
                 pinned_ip=d.pinned_ip)
        if not d2.allow:
            return deny_over_tls(tls, d2.reason, url_label + path, method)

        # Obligation 7: connect to the PINNED ip; validate the name against the
        # upstream CA. Obligation 8: verification failure fails closed.
        up_ctx = ssl.create_default_context(cafile=os.path.join(CERT_DIR, "upca.crt"))
        up_ctx.check_hostname = True
        up_ctx.verify_mode = ssl.CERT_REQUIRED
        try:
            plain = socket.create_connection((d2.pinned_ip, port), 10)
            track(plain)
            up = up_ctx.wrap_socket(plain, server_hostname=canon)
            track(up)
        except ssl.SSLCertVerificationError as exc:
            audit({"decision": "BLOCKED_BY_POLICY", "reason": "UPSTREAM_CERT_INVALID",
                   "detail": str(exc)[:160], "url": url_label + path, "method": method,
                   "pinned_ip": d2.pinned_ip})
            return deny_over_tls(tls, "UPSTREAM_CERT_INVALID", url_label + path, method)
        except Exception as exc:
            return deny_over_tls(tls, f"UPSTREAM_ERROR:{type(exc).__name__}",
                                 url_label + path, method)

        # Obligation 9: credential injected only after ALLOW; obligation 10: the
        # secret is never echoed to the sandbox and never written to audit.
        out = [f"{method} {path} HTTP/1.1", f"Host: {canon}", "Connection: close", "Accept: */*"]
        if d2.secret:
            out.append(f"Authorization: Bearer {d2.secret}")
        if body:
            out.append(f"Content-Length: {len(body)}")
        raw_req = ("\r\n".join(out) + "\r\n\r\n").encode() + body

        try:
            up.sendall(raw_req)
            chunks = []
            while True:
                b = up.recv(65536)
                if not b:
                    break
                chunks.append(b)
        except Exception as exc:
            audit({"decision": "CONNECTION_TERMINATED", "reason": type(exc).__name__,
                   "url": url_label + path, "method": method})
            return
        finally:
            for s in (up, plain):
                untrack(s)
                try:
                    s.close()
                except Exception:
                    pass

        raw_resp = b"".join(chunks)
        status = 0
        try:
            status = int(raw_resp.split(b" ", 2)[1])
        except Exception:
            pass

        # Obligation 11 (hashes over HTTPS) + obligation 6 (no auto-follow).
        audit({"decision": "ALLOW", "reason": "ALLOW", "url": url_label + path,
               "method": method, "src": self.client_address[0], "tls_intercepted": True,
               "canonical_host": canon, "sni": sni, "resolved": d2.resolved,
               "pinned_ip": d2.pinned_ip, "upstream_status": status,
               "redirect_followed": False, "credential_injected": bool(d2.secret),
               "request_hash": hashlib.sha256(raw_req).hexdigest(),
               "response_hash": hashlib.sha256(raw_resp).hexdigest()})
        try:
            tls.sendall(raw_resp)
        except Exception:
            pass


def control_plane() -> None:
    """Obligation 2: bound to the egress interface only — unreachable from any
    program network. Serves the audit tail to the operator, never to a sandbox."""
    srv = ThreadingHTTPServer((CONTROL_IP, CONTROL_PORT), _Control)
    srv.serve_forever()


class _Control(BaseHTTPRequestHandler):
    def log_message(self, *a) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        body = b'{"control_plane":"ok"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    threading.Thread(target=kill_watcher, daemon=True).start()
    threading.Thread(target=control_plane, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", PEP_PORT), TLSGateway)  # noqa: S104
    print(f"[pdp-tls] PEP :{PEP_PORT}  control {CONTROL_IP}:{CONTROL_PORT}  certs={CERT_DIR}",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

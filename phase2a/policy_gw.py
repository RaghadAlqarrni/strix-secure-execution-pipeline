#!/usr/bin/env python3
"""
Phase 2a Policy Gateway — Policy Enforcement Point (PROOF HARNESS, not production).

Implements the network decision chain from ARCHITECTURE_REVIEW.md §4.2:

  requested URL -> canonicalize -> resolve -> validate EVERY answer -> PIN one IP
  -> connect to pinned IP -> Host must equal canonical host -> response
  -> 3xx Location is NOT followed; the client's next request re-enters the chain.

Plus: deterministic authorization records, per-program/asset budgets, credential
binding (secret never leaves the gateway), append-only audit, external kill switch.

DEFAULT DENY: any unknown, ambiguous, malformed or unverifiable state -> BLOCKED_BY_POLICY.
Stdlib only. No outbound calls except those the PDP explicitly allows.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTROL_DIR = os.environ.get("PDP_CONTROL", "/control")
POLICY_PATH = os.path.join(CONTROL_DIR, "policy.json")
KILL_FILE = os.path.join(CONTROL_DIR, "STOP_ALL")
AUDIT_PATH = os.environ.get("PDP_AUDIT", "/control/audit.jsonl")
LISTEN_PORT = int(os.environ.get("PDP_PORT", "3128"))

_audit_lock = threading.Lock()
_budget_lock = threading.Lock()
_spend: dict[str, int] = {}          # counters: "<program>" and "<program>/<asset>"
_resolve_calls: dict[str, int] = {}  # for the DNS-rebinding simulation


def load_policy() -> dict:
    with open(POLICY_PATH) as fh:
        return json.load(fh)


def audit(entry: dict) -> None:
    entry["ts"] = time.time()
    with _audit_lock, open(AUDIT_PATH, "a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


# ---------------------------------------------------------------- canonicalize
def canonical_host(raw: str) -> str | None:
    """Lowercase, strip trailing dot, IDN->punycode. None if unrepresentable."""
    if not raw:
        return None
    h = raw.strip().lower().rstrip(".")
    if not h or "/" in h or " " in h:
        return None
    try:
        h = h.encode("idna").decode("ascii")
    except Exception:
        # Not IDN-encodable (e.g. already-ascii edge cases) -> only accept plain ascii
        try:
            h.encode("ascii")
        except Exception:
            return None
    return h


def host_in_scope(host: str, allowlist: list[str], denylist: list[str]) -> bool:
    """Formal wildcard semantics. Denylist always wins. Empty allowlist = DENY ALL."""
    def match(pat: str) -> bool:
        pat = pat.strip().lower().rstrip(".")
        if pat.startswith("*."):
            suffix = pat[1:]                    # ".example.com"
            return host.endswith(suffix) and host.count(".") >= pat.count(".")
        return host == pat

    if any(match(p) for p in denylist):
        return False
    if not allowlist:                            # explicit: empty allowlist denies
        return False
    return any(match(p) for p in allowlist)


# --------------------------------------------------------------------- resolve
def resolve(host: str, policy: dict) -> list[str]:
    """Controlled resolver. Uses a simulated zone so rebinding is deterministic.

    A zone value may be a list (stable) or {"sequence": [[...],[...]]} where each
    successive lookup returns the next answer set — this models a TTL flip /
    DNS-rebinding attack without needing a hostile nameserver.
    """
    zone = policy.get("dns_zone", {})
    if host not in zone:
        return []
    val = zone[host]
    if isinstance(val, dict) and "sequence" in val:
        n = _resolve_calls.get(host, 0)
        _resolve_calls[host] = n + 1
        seq = val["sequence"]
        return list(seq[min(n, len(seq) - 1)])
    return list(val)


def ip_is_allowed(ip_str: str, program: dict) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, "malformed_ip"
    # lab exemption: permits designated PRIVATE lab IPs to be used as targets.
    # Distinct from explicit_ip_allowlist, which governs bare IP-literal URLs.
    if ip_str in program.get("private_ip_exemptions", []):
        return True, "private_ip_exemption"
    if ip.is_loopback:
        return False, "loopback_denied"
    if ip.is_link_local:
        return False, "link_local_denied"
    if ip.is_private:
        return False, "rfc1918_denied"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return False, "reserved_denied"
    return True, "public_ok"


# ------------------------------------------------------------------------- PDP
class Decision:
    def __init__(self, allow: bool, reason: str, pinned_ip: str | None = None,
                 secret: str | None = None, resolved: list[str] | None = None):
        self.allow = allow
        self.reason = reason
        self.pinned_ip = pinned_ip
        self.secret = secret
        self.resolved = resolved or []


def pdp(*, src_ip: str, host_raw: str, port: int, method: str,
        session: str, asset: str, cred_id: str, policy: dict,
        pinned_ip: str | None = None) -> Decision:
    """``pinned_ip`` carries the pin established earlier in the same connection.

    Supplying it SUPPRESSES re-resolution: a connection resolves exactly once and
    is bound to that address for its whole life. Without this, a second PDP call
    (e.g. the inner request of an intercepted TLS tunnel) would resolve again and
    could bind to a different address than the one the tunnel was authorized
    against — found by the Phase 2b adversarial suite.
    """
    # 0. external kill switch — control plane, outside this process's control
    if os.path.exists(KILL_FILE):
        return Decision(False, "KILL_SWITCH_ACTIVE")

    # 1. identify program by source network (client cannot choose its own network)
    program_id = None
    for cidr, pid in policy.get("networks", {}).items():
        try:
            if ipaddress.ip_address(src_ip) in ipaddress.ip_network(cidr):
                program_id = pid
                break
        except ValueError:
            continue
    if program_id is None:
        return Decision(False, "NO_PROGRAM_FOR_SOURCE")
    program = policy.get("programs", {}).get(program_id)
    if not program:
        return Decision(False, "UNKNOWN_PROGRAM")

    # 2. deterministic authorization record
    rec = program.get("authorization") or {}
    required = ("program_id", "verified_by", "verified_at", "expires_at", "status")
    if not all(k in rec for k in required):
        return Decision(False, "AUTHORIZATION_INCOMPLETE")
    if rec.get("status") != "active":
        return Decision(False, f"AUTHORIZATION_STATUS_{rec.get('status')}")
    if float(rec.get("expires_at", 0)) <= time.time():
        return Decision(False, "AUTHORIZATION_EXPIRED")

    # 3. budgets (program and asset scoped)
    with _budget_lock:
        pkey = program_id
        akey = f"{program_id}/{asset}" if asset else None
        if _spend.get(pkey, 0) >= int(program.get("max_requests", 0)):
            return Decision(False, "BUDGET_EXHAUSTED_PROGRAM")
        acap = (program.get("asset_max_requests") or {}).get(asset)
        if acap is not None and _spend.get(akey, 0) >= int(acap):
            return Decision(False, "BUDGET_EXHAUSTED_ASSET")

    # 4. canonicalize
    host = canonical_host(host_raw)
    if host is None:
        return Decision(False, "HOST_NOT_CANONICALIZABLE")

    # 4b. bare IP literals are denied unless explicitly allowlisted
    try:
        ipaddress.ip_address(host)
        if host not in program.get("explicit_ip_allowlist", []):
            return Decision(False, "IP_LITERAL_DENIED")
    except ValueError:
        pass

    # 5. scope (default deny)
    if not host_in_scope(host, program.get("scope_allow", []), program.get("scope_deny", [])):
        return Decision(False, "OUT_OF_SCOPE")

    # 6. port / method policy
    if port not in program.get("allowed_ports", [80, 443]):
        return Decision(False, "PORT_DENIED")
    # CONNECT is a tunnel request, not a method applied to a resource. Once the
    # tunnel is up the gateway sees only ciphertext, so Host/redirect/method
    # enforcement is IMPOSSIBLE inside it. It therefore has its own switch and
    # defaults to DENY. See ARCHITECTURE_REVIEW "CONNECT blinds the L7 PDP".
    if method.upper() == "CONNECT":
        if not program.get("allow_connect", False):
            return Decision(False, "CONNECT_DENIED_BY_POLICY")
    elif method.upper() not in program.get("allowed_methods", ["GET", "HEAD"]):
        return Decision(False, "METHOD_DENIED")

    # 7. resolve, then validate EVERY returned address (one bad answer = deny).
    #    If a pin was already established for this connection, reuse it verbatim
    #    and do NOT resolve again.
    if pinned_ip is not None:
        answers = [pinned_ip]
        ok, why = ip_is_allowed(pinned_ip, program)
        if not ok:
            return Decision(False, f"PIN_REJECTED:{why}:{pinned_ip}", resolved=answers)
        pinned = pinned_ip
    else:
        answers = resolve(host, policy)
        if not answers:
            return Decision(False, "DNS_NO_ANSWER")
        for a in answers:
            ok, why = ip_is_allowed(a, program)
            if not ok:
                return Decision(False, f"DNS_ANSWER_REJECTED:{why}:{a}", resolved=answers)
        pinned = answers[0]

    # 7b. the resolved IP must itself be authorized for this program
    if pinned not in program.get("authorized_ips", []):
        return Decision(False, f"IP_NOT_AUTHORIZED:{pinned}", resolved=answers)

    # 8. credential binding — full tuple, secret never returned to the sandbox
    secret = None
    if cred_id:
        cred = policy.get("credentials", {}).get(cred_id)
        if not cred:
            return Decision(False, "UNKNOWN_CREDENTIAL", resolved=answers)
        if cred.get("program_id") != program_id:
            return Decision(False, "CREDENTIAL_WRONG_PROGRAM", resolved=answers)
        if cred.get("asset_id") not in (asset, "*"):
            return Decision(False, "CREDENTIAL_WRONG_ASSET", resolved=answers)
        if host not in cred.get("destinations", []):
            return Decision(False, "CREDENTIAL_WRONG_DESTINATION", resolved=answers)
        secret = cred.get("secret")

    with _budget_lock:
        _spend[program_id] = _spend.get(program_id, 0) + 1
        if asset:
            k = f"{program_id}/{asset}"
            _spend[k] = _spend.get(k, 0) + 1

    return Decision(True, "ALLOW", pinned_ip=pinned, secret=secret, resolved=answers)


# ----------------------------------------------------------------- proxy server
class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "StrixPDP/0.1"

    def log_message(self, *a) -> None:  # audit log is the record; keep stderr quiet
        pass

    def _deny(self, decision: Decision, url: str, method: str) -> None:
        body = json.dumps({
            "error": "BLOCKED_BY_POLICY", "reason": decision.reason, "url": url,
        }).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-PDP-Decision", "BLOCKED_BY_POLICY")
        self.send_header("X-PDP-Reason", decision.reason)
        self.end_headers()
        self.wfile.write(body)
        audit({"decision": "BLOCKED_BY_POLICY", "reason": decision.reason,
               "url": url, "method": method, "src": self.client_address[0],
               "resolved": decision.resolved})

    def _ctx(self) -> tuple[str, str, str]:
        return (self.headers.get("X-Strix-Session", ""),
                self.headers.get("X-Strix-Asset", ""),
                self.headers.get("X-Strix-Cred", ""))

    def _proxy(self, method: str) -> None:
        policy = load_policy()
        url = self.path
        parts = urllib.parse.urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return self._deny(Decision(False, "NON_ABSOLUTE_URI"), url, method)
        if parts.scheme != "http":
            return self._deny(Decision(False, f"SCHEME_DENIED:{parts.scheme}"), url, method)

        host_raw = parts.hostname or ""
        port = parts.port or 80
        session, asset, cred_id = self._ctx()

        # Host header must agree with the request-line authority (no split-brain)
        hdr_host = canonical_host((self.headers.get("Host") or "").split(":")[0])
        can_host = canonical_host(host_raw)
        if hdr_host and can_host and hdr_host != can_host:
            return self._deny(Decision(False, "HOST_HEADER_MISMATCH"), url, method)

        d = pdp(src_ip=self.client_address[0], host_raw=host_raw, port=port,
                method=method, session=session, asset=asset, cred_id=cred_id,
                policy=policy)
        if not d.allow:
            return self._deny(d, url, method)

        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length) if length else b""

        # connect to the PINNED IP — never re-resolve
        req = [f"{method} {parts.path or '/'}{('?' + parts.query) if parts.query else ''} HTTP/1.1",
               f"Host: {can_host}", "Connection: close", "Accept: */*"]
        if d.secret:  # credential injected HERE; never seen by the sandbox
            req.append(f"Authorization: Bearer {d.secret}")
        if payload:
            req.append(f"Content-Length: {len(payload)}")
        raw_req = ("\r\n".join(req) + "\r\n\r\n").encode() + payload

        try:
            up = socket.create_connection((d.pinned_ip, port), 10)
            up.sendall(raw_req)
            chunks = []
            while True:
                b = up.recv(65536)
                if not b:
                    break
                chunks.append(b)
            up.close()
        except Exception as exc:
            return self._deny(Decision(False, f"UPSTREAM_ERROR:{type(exc).__name__}"), url, method)

        raw_resp = b"".join(chunks)
        # Redirects are NOT followed. The 3xx is returned; the client's next
        # request re-enters the PDP from the top.
        status = 0
        try:
            status = int(raw_resp.split(b" ", 2)[1])
        except Exception:
            pass
        audit({"decision": "ALLOW", "reason": d.reason, "url": url, "method": method,
               "src": self.client_address[0], "canonical_host": can_host,
               "resolved": d.resolved, "pinned_ip": d.pinned_ip,
               "upstream_status": status, "redirect_followed": False,
               "credential_injected": bool(d.secret),
               "request_hash": hashlib.sha256(raw_req).hexdigest(),
               "response_hash": hashlib.sha256(raw_resp).hexdigest()})
        try:
            self.wfile.write(raw_resp)
        except Exception:
            pass
        self.close_connection = True

    def do_GET(self) -> None:  # noqa: N802
        self._proxy("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._proxy("POST")

    def __getattr__(self, name: str):
        """Route EVERY method through the PDP.

        Without this, an unimplemented verb (DELETE, PUT, ...) is rejected by
        BaseHTTPRequestHandler with 501 before the PDP runs. That happens to
        fail closed, but the denial is accidental and unaudited — so any verb
        without an explicit handler is dispatched into the PDP instead.
        """
        if name.startswith("do_"):
            method = name[3:]
            return lambda: self._proxy(method)
        raise AttributeError(name)

    def do_CONNECT(self) -> None:  # noqa: N802
        policy = load_policy()
        target = self.path
        host_raw, sep, p = target.rpartition(":")
        if not sep or not p.isdigit():
            return self._deny(Decision(False, "MALFORMED_CONNECT_TARGET"),
                              f"CONNECT {target}", "CONNECT")
        port = int(p)
        session, asset, cred_id = self._ctx()
        d = pdp(src_ip=self.client_address[0], host_raw=host_raw, port=port,
                method="CONNECT", session=session, asset=asset, cred_id=cred_id,
                policy=policy)
        if not d.allow:
            return self._deny(d, f"CONNECT {target}", "CONNECT")
        audit({"decision": "ALLOW", "reason": d.reason, "url": f"CONNECT {target}",
               "method": "CONNECT", "src": self.client_address[0],
               "pinned_ip": d.pinned_ip, "resolved": d.resolved})
        try:
            up = socket.create_connection((d.pinned_ip, port), 10)
        except Exception as exc:
            return self._deny(Decision(False, f"UPSTREAM_ERROR:{type(exc).__name__}"),
                              f"CONNECT {target}", "CONNECT")
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._relay(self.connection, up)

    @staticmethod
    def _relay(a: socket.socket, b: socket.socket) -> None:
        def pump(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except Exception:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
        t = threading.Thread(target=pump, args=(a, b), daemon=True)
        t.start()
        pump(b, a)
        t.join(timeout=5)


def main() -> None:
    os.makedirs(os.path.dirname(AUDIT_PATH), exist_ok=True)
    srv = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Gateway)  # noqa: S104
    print(f"[pdp] listening :{LISTEN_PORT} policy={POLICY_PATH} audit={AUDIT_PATH}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()

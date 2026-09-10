#!/usr/bin/env python3
"""Phase 2a test target. Local only. Reports what the GATEWAY sent upstream,
so credential injection can be proven without leaking the secret to the client."""
from __future__ import annotations

import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NAME = os.environ.get("TARGET_NAME", "target")
REDIRECT_TO = os.environ.get("REDIRECT_TO", "http://evil.lab/pwned")
PORT = int(os.environ.get("TARGET_PORT", "80"))


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a) -> None:
        print(f"[{NAME}] {self.command} {self.path} host={self.headers.get('Host')} "
              f"auth={'yes' if self.headers.get('Authorization') else 'no'}", flush=True)

    def _common(self) -> None:
        if self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", REDIRECT_TO)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        auth = self.headers.get("Authorization")
        body = json.dumps({
            "target": NAME,
            "path": self.path,
            "host_header_seen": self.headers.get("Host"),
            # prove a credential arrived WITHOUT echoing it back to the caller
            "auth_present": bool(auth),
            "auth_fingerprint": hashlib.sha256(auth.encode()).hexdigest()[:12] if auth else None,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self._common()

    def do_POST(self) -> None:  # noqa: N802
        self._common()


if __name__ == "__main__":
    print(f"[{NAME}] listening :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()  # noqa: S104

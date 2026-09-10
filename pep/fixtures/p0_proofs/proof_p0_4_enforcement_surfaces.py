#!/usr/bin/env python3
"""DEC-5 proof: drive P0 controls through PDP.decide() and Gateway.do_CONNECT().

Both halves carry deterministic negative controls.  A control that does not
reproduce the pre-repair failure makes this proof fail, never pass weakly.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(PEP))

from pep.audit import AuditLog
from pep.gateway import Gateway, Registry
from pep.pdp import Budgets, Decision, PDP
from pep.resolver import StaticResolver

CAP, N = 10, 64


def policy():
    return {"networks": {"127.0.0.0/8": "p"}, "programs": {"p": {
        "authorization": {"program_id": "p", "verified_by": "proof",
                          "verified_at": 1, "expires_at": 4102444800,
                          "status": "active"},
        "scope_allow": ["ok.lab"], "scope_deny": [], "allowed_ports": [443],
        "allowed_methods": ["GET"], "allow_connect": True,
        "allowed_families": ["ipv4"], "private_ip_exemptions": ["192.0.2.1"],
        "authorized_ips": ["192.0.2.1"], "explicit_ip_allowlist": [],
        "max_requests": CAP, "asset_max_requests": {}}}, "credentials": {}}


class SplitBudget(Budgets):
    """Pre-repair check/act window, forced at the real decide() call site."""
    def __init__(self):
        super().__init__(); self.barrier = threading.Barrier(N)

    def reserve(self, specs):
        stale = [(k, cap, self._n.get(k, 0)) for k, cap in specs]
        exceeded = next((k for k, cap, seen in stale
                         if cap is not None and seen >= cap), None)
        self.barrier.wait()
        if exceeded is not None:
            return exceeded
        with self._lock:
            for key, _ in specs:
                self._n[key] = self._n.get(key, 0) + 1
        return None


def decide_run(budget):
    pdp = PDP(policy, StaticResolver({"ok.lab": {"v4": ["192.0.2.1"]}}),
              os.path.join(tempfile.gettempdir(), "absent-dec5-kill"), budget)
    start = threading.Barrier(N); allowed = []; lock = threading.Lock()
    def worker():
        start.wait()
        d = pdp.decide(src_ip="127.0.0.1", authority="ok.lab", port=443,
                       method="CONNECT")
        if d.allow:
            with lock: allowed.append(1)
    ts = [threading.Thread(target=worker) for _ in range(N)]
    [t.start() for t in ts]; [t.join() for t in ts]
    return len(allowed), budget.peek("p")


class DenyPDP:
    def decide(self, **_):
        return Decision(False, "OUT_OF_SCOPE")


class NaiveRegistry(Registry):
    """Pre-R-8 admission shape: kill has no terminal state."""
    def add(self, c):
        with self._lock: self._conns.add(c)
        return True
    def terminate_all(self):
        with self._lock:
            victims = list(self._conns)
        torn = [c.conn_id for c in victims if c.close_all()]
        return torn, [c.conn_id for c in victims]


def send(port, row="DEC5", nonce="DEC5-NONCE"):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(("CONNECT denied.lab:443 HTTP/1.1\r\nHost: denied.lab:443\r\n"
               f"X-Strix-Row: {row}\r\nX-Strix-Nonce: {nonce}\r\n\r\n").encode())
    s.settimeout(2); data = b""
    try:
        while True:
            c = s.recv(4096)
            if not c: break
            data += c
            if b"\r\n\r\n" in data: break
    except (OSError, socket.timeout):
        pass
    s.close(); return data


def gateway_run(registry_cls):
    with tempfile.TemporaryDirectory() as td:
        audit = AuditLog(os.path.join(td, "audit.jsonl"), run_id="dec5")
        reg = registry_cls()
        Gateway.pdp, Gateway.ca, Gateway.audit, Gateway.registry = DenyPDP(), None, audit, reg
        srv = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
        th = threading.Thread(target=srv.serve_forever, daemon=True); th.start()
        # A completed pre-kill connection must never be claimed as terminated.
        send(srv.server_port, row="PRE", nonce="PRE")
        torn, snapshot = reg.terminate_all()
        post_kill_response = send(srv.server_port)
        srv.shutdown(); srv.server_close(); th.join(timeout=3)
        recs = [json.loads(x) for x in open(audit.path, encoding="utf-8") if x.strip()]
        return (recs, torn, snapshot, AuditLog.verify(audit.path)[0],
                post_kill_response)


def main():
    old_n, old_count = decide_run(SplitBudget())
    new_n, new_count = decide_run(Budgets())
    decide_control = old_n > CAP and old_count > CAP
    decide_fixed = new_n == CAP and new_count == CAP
    print(f"DECIDE negative control: allowed={old_n} count={old_count} live={decide_control}")
    print(f"DECIDE under test:       allowed={new_n} count={new_count} holds={decide_fixed}")

    good, torn, snap, chain, good_response = gateway_run(Registry)
    bad, _, _, bad_chain, _ = gateway_run(NaiveRegistry)
    good_kill = [r for r in good if r.get("reason") == "KILL_SWITCH_ACTIVE"]
    good_post_policy = [r for r in good
                        if r.get("test_nonce") == "DEC5-NONCE"]
    bad_out = [r for r in bad if r.get("reason") == "OUT_OF_SCOPE"]
    # Current quiescence protocol refuses the whole handler/audit-producer at
    # the admission edge after cancellation. The earlier implementation could
    # instead enter do_CONNECT and emit a correlated KILL_SWITCH_ACTIVE denial.
    # Either shape preserves the original P0 invariant, but the new stricter
    # shape must leave no post-kill policy record and no HTTP response bytes.
    correlated_denial = (len(good_kill) == 1 and
                         bool(good_kill[0].get("conn_id")) and
                         good_kill[0].get("row_id") == "DEC5" and
                         good_kill[0].get("test_nonce") == "DEC5-NONCE")
    producer_refusal = not good_response and not good_post_policy
    good_ok = ((correlated_denial or producer_refusal) and torn == [] and chain)
    control_ok = (not any(r.get("reason") == "KILL_SWITCH_ACTIVE" for r in bad)
                  and len(bad_out) >= 2 and bad_chain)
    print(f"do_CONNECT negative control: admitted after kill={control_ok}")
    print("do_CONNECT under test: "
          f"correlated_denial={correlated_denial} producer_refusal={producer_refusal} "
          f"holds={good_ok} torn={torn} snapshot={snap}")
    ok = decide_control and decide_fixed and control_ok and good_ok
    print(f"DEC-5 ENFORCEMENT-SURFACE PROOF: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

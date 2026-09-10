#!/usr/bin/env python3
"""Exact-base negative controls for Phase 1 F02/F03.

Exports baseline commit d341a300... into a temporary directory and drives that
code with socket doubles. Special convention: exit 0 means both defects were
reproduced; exit 1 means the negative control is void. The candidate worktree is
never reset or imported.
"""
from __future__ import annotations

import importlib
import os
import socket
import subprocess
import sys
import tarfile
import tempfile

BASE = "d341a3007ae80e5b7754154d14a7d9eb3c95f23e"
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeSocket:
    def __init__(self, observation):
        self.observation = observation
        self.responses = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", b""]
    def settimeout(self, _value): pass
    def connect(self, _target): self.observation["connect"] += 1
    def sendall(self, data):
        self.observation["send_calls"] += 1
        self.observation["bytes"] += len(data)
    def recv(self, _size): return self.responses.pop(0)
    def shutdown(self, _how): pass
    def close(self): pass


class FakeContext:
    def __init__(self, observation): self.observation = observation
    def wrap_socket(self, plain, **_kwargs): return plain


class FailingAudit:
    def __init__(self): self.records = []
    def add_secret(self, _secret): pass
    def write(self, _entry): raise OSError("ENOSPC injected after effect")


class ClientTLS:
    def sendall(self, _data): pass


def reproduce(gateway, addressing, pdp_module):
    # F02: exact base admits state, drains it socketless, then accepts and leaves
    # usable a socket acquired after cancellation; rearm also readmits.
    reg = gateway.Registry()
    state = gateway.ConnectionState(client_ip="10.0.0.9")
    admitted = reg.add(state)
    torn, snapshot = reg.terminate_all()
    local, peer = socket.socketpair()
    state.track(local)
    payload = b"POST /authorized HTTP/1.1\r\n\r\n"
    local.sendall(payload)
    usable = peer.recv(len(payload)) == payload
    reg.rearm()
    readmitted = reg.add(gateway.ConnectionState(client_ip="10.0.0.9"))
    local.close(); peer.close()
    f02 = (admitted and torn == [] and snapshot == [state.conn_id] and
           usable and readmitted)
    print(f"  F02 exact base: post-cancel socket usable={usable} "
          f"rearm readmitted={readmitted} -> {'REPRODUCED' if f02 else 'VOID'}")

    # F03: drive exact Gateway._inside. Its first audit write is the final ALLOW,
    # after connect and send. Inject ENOSPC there and prove target bytes already
    # crossed the socket double with no durable effect record.
    observation = {"connect": 0, "send_calls": 0, "bytes": 0}
    audit = FailingAudit()
    handler = object.__new__(gateway.Gateway)
    handler.audit = audit
    handler._read_head = lambda _tls: (
        "POST", "/x", {"host": "allowed.lab"}, b"abc")
    handler._deny_tls = lambda *_args: None
    handler.pdp = type("P", (), {"decide": lambda self, **kw: pdp_module.Decision(
        True, "ALLOW", pin=addressing.Pin("ipv4", "203.0.113.7", 443),
        secret="secret", program_id="prog_a",
        detail={"canonical_host": "allowed.lab"})})()
    state2 = gateway.ConnectionState(client_ip="10.0.0.8")
    state2.pin = addressing.Pin("ipv4", "203.0.113.7", 443)
    state2.canonical = "allowed.lab"
    state2.program_id = "prog_a"
    real_socket = gateway.socket.socket
    real_context = gateway.ssl.create_default_context
    gateway.socket.socket = lambda *_a, **_kw: FakeSocket(observation)
    gateway.ssl.create_default_context = lambda **_kw: FakeContext(observation)
    failed_after_effect = False
    try:
        handler._inside(state2, ClientTLS(), 443, "s", "a1", "cred", "allowed.lab")
    except OSError as exc:
        failed_after_effect = "ENOSPC" in str(exc)
    finally:
        gateway.socket.socket = real_socket
        gateway.ssl.create_default_context = real_context
    f03 = (observation["connect"] == 1 and observation["send_calls"] == 1 and
           observation["bytes"] > 0 and failed_after_effect and not audit.records)
    print(f"  F03 exact base: connect={observation['connect']} "
          f"bytes_sent={observation['bytes']} durable_records={len(audit.records)} "
          f"audit_failed_after_effect={failed_after_effect} -> "
          f"{'REPRODUCED' if f03 else 'VOID'}")
    return f02, f03


def main() -> int:
    head = subprocess.run(["git", "rev-parse", BASE], cwd=ROOT,
                          text=True, capture_output=True, check=True).stdout.strip()
    if head != BASE:
        print(f"  BASELINE IDENTITY VOID: expected={BASE} got={head}")
        return 1
    with tempfile.TemporaryDirectory(prefix="phase1_exact_base_") as temp:
        archive_path = os.path.join(temp, "base.tar")
        subprocess.run(["git", "archive", "--format=tar", "-o", archive_path, BASE],
                       cwd=ROOT, check=True)
        base_root = os.path.join(temp, "tree")
        os.mkdir(base_root)
        with tarfile.open(archive_path) as archive:
            archive.extractall(base_root)
        sys.path.insert(0, base_root)
        gateway = importlib.import_module("pep.gateway")
        addressing = importlib.import_module("pep.addressing")
        pdp_module = importlib.import_module("pep.pdp")
        f02, f03 = reproduce(gateway, addressing, pdp_module)
    print(f"  BASELINE_COMMIT={BASE}")
    print(f"  BASELINE F02={'REPRODUCED' if f02 else 'VOID'} "
          f"F03={'REPRODUCED' if f03 else 'VOID'}")
    return 0 if f02 and f03 else 1


if __name__ == "__main__":
    raise SystemExit(main())

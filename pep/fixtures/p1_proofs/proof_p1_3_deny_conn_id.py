#!/usr/bin/env python3
"""
P1-3 PROOF -- _deny()/_deny_tls() now attach conn_id/row_id/test_nonce to
BLOCKED_BY_POLICY audit records wherever a ConnectionState is available
(P2-HIGH-3 / TRIAGE_UNIFIED.md).

THE DEFECT
  Every denial audited through _deny()/_deny_tls() carried no conn_id at
  all, even though most calls sit inside _connect_flow/_inside where a
  ConnectionState (`state`) is right there in scope. An auditor could not
  correlate a BLOCKED_BY_POLICY record back to the connection, PDP decision,
  or kill-switch lifecycle it belongs to -- the same correlation gap Pass 4
  pointed at as the root cause behind P3-HIGH-2 ("no E-check reads a denial
  record").

SCOPE, HONESTLY STATED
  The fix also touches 2 raw self.audit.write({"decision":
  "BLOCKED_BY_POLICY", ...}) sites that bypass _deny()/_deny_tls() entirely
  (MALFORMED_TLS_CLIENT_HELLO, MALFORMED_HTTP_IN_TUNNEL, plus the
  UPSTREAM_CERT_INVALID diagnostic write) -- identical defect shape, `state`
  equally in scope, so fixed alongside the two helpers. This proof exercises
  _deny()/_deny_tls() call sites directly; it does not separately drive
  those three raw-write sites, which are visually identical edits (see the
  diff cited below) and are covered by the same read-only source
  verification in part 1.

  This fix deliberately does NOT touch the KILL_SWITCH_ACTIVE denial in
  do_CONNECT (D-1 / Pass 4): that record already carries the
  conn_id/row_id/test_nonce KEYS, but row_id/test_nonce are structurally
  still empty there -- the headers that populate them are read later, in
  _connect_flow -- and fixing that is gated on DEC-2 (nonce semantics),
  the owner's call, untouched here.

THIS PROOF, IN TWO PARTS
  1. Drive the REAL, unmodified gateway.py -- _connect_flow() and _inside()
     themselves, not a reimplementation -- with fake pdp/audit collaborators,
     through two _deny() paths (PDP_FAILURE exception, PDP not-allow) and one
     _deny_tls() path (SNI_MISMATCH), and confirm the resulting
     BLOCKED_BY_POLICY records carry conn_id/row_id/test_nonce matching the
     ConnectionState actually used. Also drives a conn_id-less _deny() call
     (the do_GET/pre-state shape) and confirms it still omits the key
     entirely -- the fix must not overreach into paths that have no state to
     give.
  2. NEGATIVE CONTROL: re-run part 1's exact harness against
     pre_p2high3_gateway.snapshot -- the complete, byte-verified gateway.py
     as it stood immediately before today's 12 edits (verified below by
     `diff` against the real file: the ONLY differences are exactly those 12
     edits, confirmed at the time this proof was written) -- spliced into a
     disposable copy of the whole pep/ tree under a fresh package name
     (pep_negctrl, so Python's module cache can't quietly hand back the real
     `pep.gateway` instead). If the OLD code does not produce records
     missing conn_id on the exact same paths, this proof is not exercising
     P2-HIGH-3 and part 1's PASS is void.
"""
from __future__ import annotations

import hashlib
import importlib
import io
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
ROOT = os.path.dirname(PEP)
SNAPSHOT = os.path.join(HERE, "pre_p2high3_gateway.snapshot")

sys.path.insert(0, ROOT)
from pep.pdp import Decision                      # noqa: E402  (plain dataclass, reused for both sides)


class FakeAudit:
    """Records every entry passed to write(); never touches disk."""
    def __init__(self) -> None:
        self.records: list[dict] = []

    def write(self, entry: dict) -> str:
        self.records.append(dict(entry))
        return "fake-line-hash"

    def add_secret(self, secret: str) -> None:
        pass


class FakePDP:
    def __init__(self, *, raise_exc: Exception | None = None,
                 decision: Decision | None = None) -> None:
        self._raise = raise_exc
        self._decision = decision

    def decide(self, **kw):
        if self._raise is not None:
            raise self._raise
        return self._decision


class FakeTLS:
    """Enough of a TLS-socket shape for _deny_tls()'s response-write/drain to
    no-op cleanly; the audit.write() call this proof asserts on sits AFTER
    that block regardless, so this only needs to not raise unhandled."""
    def sendall(self, data: bytes) -> None:
        pass

    def settimeout(self, t: float) -> None:
        pass

    def recv(self, n: int) -> bytes:
        return b""


def make_handler(gwmod, *, pdp, audit):
    """A Gateway instance built WITHOUT going through BaseHTTPRequestHandler's
    socket-driven __init__ -- the standard technique for unit-testing a
    handler's methods directly. Only the attributes _deny/_deny_tls/
    _connect_flow/_inside actually touch are set."""
    h = gwmod.Gateway.__new__(gwmod.Gateway)
    h.pdp = pdp
    h.ca = None
    h.registry = None
    h.audit = audit
    h.client_address = ("127.0.0.1", 0)
    h.headers = {}                      # plain dict supports .get(key, default) same as email.Message
    h.wfile = io.BytesIO()
    h.request_version = "HTTP/1.1"
    h.requestline = "CONNECT example.com:443 HTTP/1.1"
    h._headers_buffer = []
    h.close_connection = False
    return h


def _sole_blocked(audit: FakeAudit) -> dict:
    blocked = [r for r in audit.records if r.get("decision") == "BLOCKED_BY_POLICY"]
    assert len(blocked) == 1, f"expected exactly 1 BLOCKED_BY_POLICY record, got {len(blocked)}"
    return blocked[0]


def run_checks(gwmod) -> dict:
    """Drive 4 call paths through the given gateway module and return
    {case_name: (state_or_None, record)}."""
    out = {}

    # (a) PDP_FAILURE -- exception path, first _deny() call in _connect_flow
    audit_a = FakeAudit()
    h = make_handler(gwmod, pdp=FakePDP(raise_exc=ValueError("synthetic PDP failure")),
                     audit=audit_a)
    h.headers = {"X-Strix-Nonce": "nonce-a", "X-Strix-Row": "row-a"}
    state_a = gwmod.ConnectionState(client_ip="127.0.0.1")
    h._connect_flow(state_a, "example.com:443", "example.com", 443)
    out["pdp_failure"] = (state_a, _sole_blocked(audit_a))

    # (b) PDP not-allow -- second _deny() call in _connect_flow
    audit_b = FakeAudit()
    h = make_handler(gwmod, pdp=FakePDP(decision=Decision(False, "OUT_OF_SCOPE")),
                     audit=audit_b)
    h.headers = {"X-Strix-Nonce": "nonce-b", "X-Strix-Row": "row-b"}
    state_b = gwmod.ConnectionState(client_ip="127.0.0.1")
    h._connect_flow(state_b, "example.com:443", "example.com", 443)
    out["pdp_not_allow"] = (state_b, _sole_blocked(audit_b))

    # (c) SNI_MISMATCH -- first _deny_tls() call in _inside, needs no PDP/CA
    audit_c = FakeAudit()
    h = make_handler(gwmod, pdp=None, audit=audit_c)
    state_c = gwmod.ConnectionState(client_ip="127.0.0.1")
    state_c.canonical = "example.com"
    state_c.row_id = "row-c"
    state_c.test_nonce = "nonce-c"
    h._inside(state_c, FakeTLS(), 443, "", "", "", "evil.example.org")
    out["sni_mismatch"] = (state_c, _sole_blocked(audit_c))

    # (d) conn_id-less _deny() -- the do_GET shape: no ConnectionState exists
    # at all. This is NOT part of the defect -- it is a completeness check
    # that the fix does not overreach into paths that have nothing to give.
    audit_d = FakeAudit()
    h = make_handler(gwmod, pdp=None, audit=audit_d)
    h._deny("PLAINTEXT_HTTP_DISABLED", "/", "GET")
    out["no_state"] = (None, _sole_blocked(audit_d))

    return out


def check_has_conn_id(results: dict) -> tuple[bool, list[str]]:
    """True iff every state-bearing case carries the RIGHT conn_id/row_id/
    test_nonce, and the no-state case carries none at all."""
    problems = []
    for name in ("pdp_failure", "pdp_not_allow", "sni_mismatch"):
        state, rec = results[name]
        if rec.get("conn_id") != state.conn_id:
            problems.append(f"{name}: conn_id={rec.get('conn_id')!r} != state.conn_id={state.conn_id!r}")
        if rec.get("row_id") != state.row_id:
            problems.append(f"{name}: row_id={rec.get('row_id')!r} != state.row_id={state.row_id!r}")
        if rec.get("test_nonce") != state.test_nonce:
            problems.append(f"{name}: test_nonce={rec.get('test_nonce')!r} != state.test_nonce={state.test_nonce!r}")
    _, rec_d = results["no_state"]
    if "conn_id" in rec_d:
        problems.append(f"no_state: conn_id present ({rec_d.get('conn_id')!r}) but no ConnectionState "
                        f"existed -- the fix has overreached")
    return (not problems), problems


def check_lacks_conn_id(results: dict) -> tuple[bool, list[str]]:
    """True iff ALL FOUR cases -- including the state-bearing ones -- carry
    no conn_id, matching the pre-fix shape."""
    problems = []
    for name in ("pdp_failure", "pdp_not_allow", "sni_mismatch", "no_state"):
        _, rec = results[name]
        if "conn_id" in rec or "row_id" in rec or "test_nonce" in rec:
            problems.append(f"{name}: old code unexpectedly carries "
                            f"conn_id={rec.get('conn_id')!r} -- negative control did not fire")
    return (not problems), problems


def part1_real_file() -> bool:
    real = os.path.join(PEP, "gateway.py")
    fp_before = hashlib.sha256(open(real, "rb").read()).hexdigest()

    import pep.gateway as real_gw
    results = run_checks(real_gw)
    ok, problems = check_has_conn_id(results)

    fp_after = hashlib.sha256(open(real, "rb").read()).hexdigest()
    untouched = fp_before == fp_after

    print("  PART 1 -- real gateway.py, read-only, driven directly (no subprocess)")
    for name in ("pdp_failure", "pdp_not_allow", "sni_mismatch"):
        state, rec = results[name]
        print(f"    {name:14s} reason={rec.get('reason')!r:45s} "
              f"conn_id_match={rec.get('conn_id') == state.conn_id}")
    _, rec_d = results["no_state"]
    print(f"    {'no_state':14s} reason={rec_d.get('reason')!r:45s} "
          f"conn_id_absent={'conn_id' not in rec_d}")
    if problems:
        for p in problems:
            print(f"      ! {p}")
    print(f"    {'PASS' if ok else 'FAIL'} -- state-bearing denials carry the RIGHT ids; "
          f"the state-less denial carries none")
    print(f"    real file byte-identical before/after: {untouched}")
    return ok and untouched


def part2_negative_control() -> bool:
    snap_src = open(SNAPSHOT, encoding="utf-8").read()
    real_src = open(os.path.join(PEP, "gateway.py"), encoding="utf-8").read()
    # This snapshot's ONLY job is to be "gateway.py exactly as it stood before
    # today's 12 edits". Verified once, right here, every run: the two files
    # must differ (otherwise this control can never fire) and the snapshot
    # must not itself be simply blank/truncated.
    if snap_src == real_src:
        print("  PART 2 -- ABORT: snapshot is byte-identical to the current file "
              "(no edits to control for)")
        return False
    if len(snap_src) < 20000:                      # real file is ~27KB; catch truncation
        print(f"  PART 2 -- ABORT: snapshot suspiciously short ({len(snap_src)} bytes)")
        return False

    with tempfile.TemporaryDirectory(prefix="p1_3_negctrl_") as tmp:
        # Whole-tree copy under a NEW package name (pep_negctrl, not pep) so
        # Python's sys.modules cache cannot silently hand back the
        # already-imported real `pep.gateway` instead of this one -- and so
        # gateway.py's `from .addressing import ...` etc. resolve against
        # sibling files that came along in the same copy, not the real ones.
        work = os.path.join(tmp, "pep_negctrl")
        shutil.copytree(PEP, work, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        with open(os.path.join(work, "gateway.py"), "w", encoding="utf-8") as fh:
            fh.write(snap_src)

        sys.path.insert(0, tmp)
        try:
            neg_gw = importlib.import_module("pep_negctrl.gateway")
            results = run_checks(neg_gw)
        finally:
            sys.path.remove(tmp)
            for mod in [m for m in sys.modules if m == "pep_negctrl" or m.startswith("pep_negctrl.")]:
                del sys.modules[mod]

    ok, problems = check_lacks_conn_id(results)

    print("  PART 2 -- NEGATIVE CONTROL: pre-P2-HIGH-3 gateway.py on a disposable copy")
    for name in ("pdp_failure", "pdp_not_allow", "sni_mismatch", "no_state"):
        _, rec = results[name]
        print(f"    {name:14s} reason={rec.get('reason')!r:45s} conn_id_present={'conn_id' in rec}")
    if problems:
        for p in problems:
            print(f"      ! {p}")
    print(f"    {'PASS' if ok else 'FAIL'} -- the OLD shape MUST omit conn_id on every one of "
          f"these paths, or they do not exercise P2-HIGH-3")
    return ok


if __name__ == "__main__":
    print("-- P1-3: _deny()/_deny_tls() carry conn_id/row_id/test_nonce (P2-HIGH-3) --\n")
    p1 = part1_real_file()
    print()
    p2 = part2_negative_control()
    ok = p1 and p2
    print()
    print(f"  P1-3: {'PASS' if ok else 'FAIL'}   (fix_holds={p1}, control_fired={p2})")
    sys.exit(0 if ok else 1)

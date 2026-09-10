#!/usr/bin/env python3
"""
P0-2 PROOF -- the kill switch is a one-way door, and its evidence is honest.

R-8 was a check-then-act race between Registry.add() and terminate_all():
a connection could be admitted after the switch had already drained the
registry, leaving a live, unpoliced connection behind.

THREE CLAIMS, EACH WITH ITS OWN LIVE NEGATIVE CONTROL.

  A1  DECISIVE, DETERMINISTIC.
      After terminate_all() has returned, add() must refuse. No scheduling
      luck is involved: _killed is terminal, so if this ever succeeds the
      door is not one-way. A pass here is the actual proof.

  A2  SUPPLEMENTARY STRESS.
      300 concurrent late adds against a firing kill switch; the registry
      must be empty once everything has joined. This is timing-dependent, so
      a green A2 is NOT independent evidence -- it is a smoke check that A1's
      invariant survives contention. Its value is in the negative control:
      if the naive shape does not leak here, this file is not exercising R-8.

  B   EVIDENCE HONESTY.
      terminated_conn_ids must name only connections whose socket the kill
      switch actually tore down -- not connections that had already finished.
      The pre-repair code reported its pre-close snapshot, so a connection
      that closed itself in the window was still recorded as a kill-switch
      victim. Every row title built on that field says "the kill switch
      terminated THIS connection", so the old field was an over-claim in the
      direction that flatters the control. The control below recomputes the
      old snapshot behaviour and shows it names the wrong connection.

Run with --naive to see all three controls fire.
"""

import os
import socket
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(PEP))

from pep.gateway import ConnectionState, Registry                # noqa: E402

VICTIMS = 200
LATE = 300


def _mkconn(cid: str) -> ConnectionState:
    """A connection with two genuinely LIVE sockets, so close_all() has
    something real to tear down. A pair of closed or never-connected sockets
    would make close_all() return False for the wrong reason and would
    silently turn CLAIM B green."""
    c = ConnectionState(client_ip="127.0.0.1", conn_id=cid)
    a, b = socket.socketpair()
    c.track(a)
    c.track(b)
    return c


def _add(reg: Registry, c: ConnectionState, naive: bool) -> bool:
    if naive:                       # pre-repair: add() had no kill check
        with reg._lock:
            reg._conns.add(c)
        return True
    return reg.add(c)


# --------------------------------------------------------------------------
def claim_a1(naive: bool) -> tuple[bool, bool, int]:
    reg = Registry()
    reg.add(_mkconn("before"))
    reg.terminate_all()

    admitted = _add(reg, _mkconn("after"), naive)
    with reg._lock:
        residual = len(reg._conns)
    return admitted, (not admitted and residual == 0), residual


def claim_a2(naive: bool) -> tuple[int, int]:
    reg = Registry()
    for i in range(VICTIMS):
        reg.add(_mkconn(f"v{i}"))

    refused = []
    out = threading.Lock()
    start = threading.Barrier(LATE + 1)

    def late(i: int) -> None:
        c = _mkconn(f"late{i}")
        start.wait()
        if not _add(reg, c, naive):
            with out:
                refused.append(i)

    ts = [threading.Thread(target=late, args=(i,)) for i in range(LATE)]
    for t in ts:
        t.start()
    start.wait()
    reg.terminate_all()
    for t in ts:
        t.join()

    with reg._lock:
        residual = len(reg._conns)
    return residual, len(refused)


def claim_b() -> tuple[list[str], list[str]]:
    reg = Registry()
    reg.add(_mkconn("live"))
    finished = _mkconn("finished")
    reg.add(finished)
    finished.close_all()            # completed on its own, before the switch
    torn, snapshot = reg.terminate_all()
    return torn, snapshot


# --------------------------------------------------------------------------
if __name__ == "__main__":
    naive = "--naive" in sys.argv
    mode = "NEGATIVE CONTROL (pre-repair shape)" if naive else "UNDER TEST (repaired)"
    print(f"-- P0-2: kill switch -- {mode} --\n")

    admitted, a1_repaired_ok, residual = claim_a1(naive)
    print("  A1  DECISIVE: add() after terminate_all() has returned")
    print(f"        admitted after the kill        = {admitted}")
    print(f"        residual in registry           = {residual}")
    a1 = admitted if naive else a1_repaired_ok
    print(f"        {'PASS' if a1 else 'FAIL'} -- "
          + ("the control MUST be admitted, or R-8 is not being exercised"
             if naive else "nothing may be admitted after the kill"))

    print()
    res, ref = claim_a2(naive)
    print("  A2  STRESS (supplementary, timing-dependent -- not standalone evidence)")
    print(f"        victims before kill            = {VICTIMS}")
    print(f"        concurrent late add() attempts = {LATE}")
    print(f"        refused outright               = {ref}")
    print(f"        LIVE IN REGISTRY AFTER KILL    = {res}")
    a2 = res > 0 if naive else res == 0
    print(f"        {'PASS' if a2 else 'FAIL'} -- "
          + ("the control MUST leak survivors under contention"
             if naive else "the registry must be empty once the switch has fired"))

    print()
    torn, snap = claim_b()
    old_field = snap                # what the pre-repair code recorded
    print("  B   EVIDENCE: terminated_conn_ids must not over-claim")
    print(f"        registered at kill             = {len(snap)}")
    print(f"        PRE-REPAIR field (snapshot)    = {sorted(old_field)}")
    print(f"        REPAIRED field (actually torn) = {sorted(torn)}")
    control_over_claims = "finished" in old_field
    b = control_over_claims and ("live" in torn) and ("finished" not in torn)
    print(f"        control over-claims 'finished' = {control_over_claims}")
    print(f"        {'PASS' if b else 'FAIL'} -- the old field names a connection the "
          f"switch did not terminate; the new field names only what it tore down")

    ok = a1 and a2 and b
    print()
    print(f"  P0-2: {'PASS' if ok else 'FAIL'}   (A1={a1}  A2={a2}  B={b})")
    sys.exit(0 if ok else 1)

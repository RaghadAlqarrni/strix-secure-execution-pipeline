#!/usr/bin/env python3
"""
P0-1 PROOF -- the budget cap is enforced atomically (no check-then-act split).

WHY THE OBVIOUS VERSION OF THIS TEST IS WORTHLESS
  Firing N threads at a naive check-then-act counter and hoping for an
  overshoot is a *probabilistic* test. Under CPython's GIL the barrier
  releases threads roughly serially, so each one finishes check+act before
  the next is scheduled and the naive shape passes -- which would make a
  green result on the repaired shape meaningless. A test whose negative
  control does not fail is not evidence.

WHAT THIS TEST DOES INSTEAD
  It constructs the interleaving deterministically. Every worker is held at a
  barrier at the ONE point where the pre-repair code could be preempted --
  between reading the counter and incrementing it. This is a schedule the OS
  is permitted to produce; forcing it removes the luck.

  NAIVE shape:  read -> [BARRIER: all 64 threads now hold the stale read] -> write
                All 64 see 0 < 10. All 64 charge. Cap breached by 54.

  ATOMIC shape: reserve() checks every cap and charges every counter inside a
                single critical section. There is no point between the read
                and the write at which a barrier can be placed, because no
                such point exists. That absence IS the property under test,
                so the barrier is placed immediately before the call -- the
                worst position still available to an attacker.

PASS CONDITION
  naive  -> overshoot > 0   (control is live; the race is real)
  atomic -> overshoot == 0  (the repair holds under the same pressure)
  Both must hold. Either alone is not evidence.
"""

import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.dirname(PEP))

from pep.pdp import Budgets                                      # noqa: E402

CAP = 10
WORKERS = 64


def run_naive() -> int:
    """Pre-repair shape: the check and the charge are separate statements."""
    b = Budgets()
    allowed: list[int] = []
    out = threading.Lock()
    split = threading.Barrier(WORKERS)

    def w(i: int) -> None:
        # --- check ---
        seen = b._n.get("global", 0)
        under_cap = seen < CAP
        # --- the window the repair closes: every thread is now holding a
        #     stale read. This is a legal schedule, forced deterministically.
        split.wait()
        # --- act ---
        if under_cap:
            with b._lock:
                b._n["global"] = b._n.get("global", 0) + 1
            with out:
                allowed.append(i)

    ts = [threading.Thread(target=w, args=(i,)) for i in range(WORKERS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return len(allowed)


def run_atomic() -> int:
    """Post-repair shape: reserve() is one indivisible critical section."""
    b = Budgets()
    allowed: list[int] = []
    out = threading.Lock()
    split = threading.Barrier(WORKERS)

    def w(i: int) -> None:
        # There is no split point INSIDE reserve() to place a barrier at.
        # The worst an attacker can do is pile every request onto the call.
        split.wait()
        if b.reserve([("global", CAP)]) is None:
            with out:
                allowed.append(i)

    ts = [threading.Thread(target=w, args=(i,)) for i in range(WORKERS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return len(allowed)


def report(label: str, n: int, must_overshoot: bool) -> bool:
    over = max(0, n - CAP)
    ok = (over > 0) if must_overshoot else (over == 0)
    print(f"  {label}")
    print(f"    cap                 = {CAP}")
    print(f"    concurrent requests = {WORKERS}")
    print(f"    ALLOWED             = {n}")
    print(f"    overshoot           = {over}")
    if must_overshoot:
        print(f"    {'PASS' if ok else 'FAIL'} -- the control MUST breach the cap, "
              f"otherwise this test never exercised the race")
    else:
        print(f"    {'PASS' if ok else 'FAIL'} -- the cap must hold exactly")
    return ok


if __name__ == "__main__":
    print("-- P0-1: budget cap under a forced check-then-act interleaving --\n")
    a = report("NEGATIVE CONTROL: naive check-then-act", run_naive(), True)
    print()
    b = report("UNDER TEST: atomic Budgets.reserve()", run_atomic(), False)
    print()
    ok = a and b
    print(f"  P0-1: {'PASS' if ok else 'FAIL'}"
          f"   (control live={a}, repair holds={b})")
    sys.exit(0 if ok else 1)

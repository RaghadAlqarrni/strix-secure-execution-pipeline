#!/usr/bin/env python3
"""Behavioural falsification battery for E9; every single-link break must fail."""
from __future__ import annotations

import copy
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, PEP)
sys.path.insert(0, HERE)

import make_fixtures as F  # noqa: E402
from verify_b7_evidence import validate_fixture_summary  # noqa: E402


def main() -> int:
    base = F.honest_artifacts()
    cases = [("honest", lambda e, lb: None, True)]
    cases += [
        ("unrelated counter source",
         lambda e, lb: e["enforcement"].update(
             rule_identity=e["packet_attempt"]["rule_identity"]), False),
        ("receiver dies after C1", lambda e, lb: e["receiver"].update(c2_seen=False), False),
        ("packet never observed", lambda e, lb: e["packet_attempt"].update(observed=False), False),
        ("nonce mismatch", lambda e, lb: e["packet_attempt"].update(nonce="9" * 64), False),
        ("port mismatch", lambda e, lb: e["packet_attempt"].update(dst_port=49178), False),
        ("measurement delivered", lambda e, lb: e["receiver"].update(measurement_seen=True), False),
        ("drop counter unchanged", lambda e, lb: e["enforcement"].update(packets_after=10), False),
        ("drop counter jumps by two", lambda e, lb: e["enforcement"].update(packets_after=12), False),
        ("cross-run evidence", lambda e, lb: e.update(run_id="run-other"), False),
        ("B3 absent", lambda e, lb: lb.update(rows=[r for r in lb["rows"] if r["id"] != "B3"]), False),
        ("calibration absent", lambda e, lb: e["calibration"].update(seen=False), False),
        ("calibration code differs", lambda e, lb: e["calibration"].update(sender_sha256="0" * 64), False),
        ("stale reused control nonce", lambda e, lb: e["controls"].update(c1_nonce=e["probe"]["nonce"]), False),
        ("fixture not torn down", lambda e, lb: e.update(b7_teardown=False), False),
        ("self-labelled evidence", lambda e, lb: e.update(run_id_source="sandbox"), False),
    ]
    good = 0
    for name, mutate, expected in cases:
        e, lb = copy.deepcopy(base["b7"]), copy.deepcopy(base["layerb"])
        mutate(e, lb)
        got, failures = validate_fixture_summary(e, lb, F.RID)
        ok = got is expected
        good += int(ok)
        print(f"  {'PASS' if ok else 'FAIL'}  {name:34} expected={expected} got={got} "
              f"failures={failures[:2]}")
    print(f"\n  E9 FALSIFICATION: {good}/{len(cases)}")
    return 0 if good == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())

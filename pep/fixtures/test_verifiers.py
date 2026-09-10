#!/usr/bin/env python3
"""
VERIFIER SELF-TEST — drives verify_layerb_audit.evaluate() and verify_pp18.verify()
against synthetic audit records and asserts the exact verdict code each scenario
must produce.

Why this exists separately from the fixture battery: the battery checks the
AUDITOR, and reaches the verifiers only through E5, which merely *reads their
source*. Neither verifier is ever EXECUTED there. A logic defect inside a
verifier — as opposed to a weakened one — is therefore invisible to the battery.
This module executes them.

Exit 0 only if every scenario produces its required code.
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, PEP)

import verify_layerb_audit as V                                   # noqa: E402
import verify_pp18 as P                                           # noqa: E402

RID = "run-selftest000000000000000000000"
NON = "nonce-selftest-0001"
C_B3, C_B6 = "aaaa1111", "bbbb2222"
V6 = "fd00:9a17:e9:1::20"

RESULTS: list[tuple[str, str, str, bool]] = []


def base(**kw):
    d = {"run_id": RID, "ts": 1.0}
    d.update(kw)
    return d


def allow(**over):
    r = base(decision="ALLOW", row_id="B3", test_nonce=NON, conn_id=C_B3,
             pin_family="ipv6", pin_ip=V6, canonical_host="allowed6.lab",
             sni="allowed6.lab", request_hash="a" * 64, response_hash="b" * 64)
    r.update(over)
    return r


def term(**over):
    r = base(decision="CONNECTION_TERMINATED", row_id="B6", test_nonce=NON,
             conn_id=C_B6)
    r.update(over)
    return r


def kill(ids=(C_B6,), **over):
    r = base(decision="KILL_SWITCH", terminated_conn_ids=list(ids),
             connections_terminated=len(ids))
    r.update(over)
    return r


def write(tmp: str, recs: list[dict]) -> str:
    import json
    p = os.path.join(tmp, "a.jsonl")
    with open(p, "w") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")
    return p


def check(name: str, got: str, want: str) -> None:
    ok = got == want or (want.endswith("*") and got.startswith(want[:-1]))
    RESULTS.append((name, want, got, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name:52} want={want:34} got={got}",
          flush=True)


def main() -> int:
    import tempfile
    tmp = tempfile.mkdtemp()

    def lb(recs, run_id=RID, client=None):
        return V.evaluate(write(tmp, recs), run_id, client or {})

    # --- the honest baseline: both rows must PROVE ---------------------------
    b8, b9 = lb([allow(), term(), kill()])
    check("honest evidence -> B8", b8["status"], "PROVEN")
    check("honest evidence -> B9", b9["status"], "PROVEN")

    # --- a verifier that cannot fail is a rubber stamp; these must all bite ---
    b8, _ = lb([allow(run_id="run-OTHER"), term(), kill()])
    check("v6 ALLOW from a different execution", b8["status"], "NO_MATCHING_RECORD")

    b8, _ = lb([allow(pin_family="ipv4"), term(), kill()])
    check("pin_family not ipv6", b8["status"], "PIN_FAMILY_NOT_V6*")

    b8, _ = lb([allow(pin_ip="172.29.0.20"), term(), kill()])
    check("pin labelled ipv6 holding an IPv4 literal", b8["status"], "PIN_NOT_V6*")

    r = allow(); r.pop("request_hash"); r.pop("response_hash")
    b8, _ = lb([r, term(), kill()])
    check("ALLOW record missing both hashes", b8["status"], "MISSING*")

    r = allow(); r["test_nonce"] = ""
    b8, _ = lb([r, term(), kill()])
    check("ALLOW record carries no nonce", b8["status"], "NO_TEST_CORRELATION")

    _, b9 = lb([allow(), term(), kill(ids=("zzzz9999",))])
    check("kill switch terminated a different connection", b9["status"],
          "TERMINATED_A_DIFFERENT_CONNECTION")

    _, b9 = lb([allow(), term(), kill(ids=())])
    check("kill record lists no conn_ids", b9["status"],
          "KILL_RECORD_LISTS_NO_CONNECTIONS")

    _, b9 = lb([allow(), term()])
    check("no KILL_SWITCH record at all", b9["status"], "NO_KILL_RECORD")

    _, b9 = lb([allow(), kill()])
    check("no B6 connection record", b9["status"], "NO_MATCHING_CONNECTION")

    _, b9 = lb([allow(), term(test_nonce="DIFFERENT"), kill()])
    check("B8 and B9 nonces disagree", b9["status"], "NONCE_MISMATCH*")

    _, b9 = lb([allow(), term(), kill()], client={"partial_bytes": 0})
    check("client received no body before the kill", b9["status"],
          "NO_LIVE_STREAM_BEFORE_KILL")

    b8, b9 = lb([allow(), term(), kill()], run_id="")
    check("control plane issued no run_id", b8["status"], "NO_RUN_ID")

    b8, b9 = lb([allow(), term(), kill()], run_id="run-ABSENT")
    check("run_id absent from the audit", b8["status"], "NO_RECORDS_FOR_RUN")

    # truncated log
    p = write(tmp, [allow(), term(), kill()])
    with open(p, "a") as fh:
        fh.write('{"partial": tru\n')
    b8, _ = V.evaluate(p, RID, {})
    check("audit log contains a malformed line", b8["status"],
          "AUDIT_UNREADABLE_OR_TRUNCATED")

    # --- PP18 -----------------------------------------------------------------
    pp = [allow(), term(row_id="PP18", conn_id="cccc3333"),
          kill(ids=("cccc3333",))]
    check("PP18 honest chain", P.verify(write(tmp, pp), RID)["status"], "PROVEN")

    pp = [allow(), term(row_id="PP18", conn_id="cccc3333"), kill(ids=("other",))]
    check("PP18 kill hit a different connection",
          P.verify(write(tmp, pp), RID)["status"], "TERMINATED_A_DIFFERENT_CONNECTION")

    pp = [allow(), term(row_id="PP18", conn_id="cccc3333", test_nonce=""),
          kill(ids=("cccc3333",))]
    check("PP18 record carries no nonce",
          P.verify(write(tmp, pp), RID)["status"], "NO_TEST_CORRELATION")

    pp = [allow(), term(row_id="PP18", conn_id="cccc3333")]
    check("PP18 with no kill record",
          P.verify(write(tmp, pp), RID)["status"], "NO_KILL_RECORD")

    ok = sum(1 for *_, g in RESULTS if g)
    print(f"\n  VERIFIER SELF-TEST: {ok}/{len(RESULTS)}")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())

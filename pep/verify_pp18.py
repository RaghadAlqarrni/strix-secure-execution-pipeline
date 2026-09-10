#!/usr/bin/env python3
"""
PP18 — host-side IPv4 kill-switch evidence.

Previously this lived as an inline heredoc inside run_pep.sh, which meant it was
(a) invisible to the Evidence Auditor's verifier-integrity check and (b) absent
entirely from the dual-stack release gate, where E6 fell back to a partial-byte
count written by the SANDBOX about itself. Both are closed by making this a real,
inspectable module that the gate calls.

Authority model:
  * run_id      — issued by the control plane, stamped by the PEP on every audit
                  record, NEVER transmitted to the sandbox. This is the anchor.
  * row_id      — structured label saying which acceptance row a record belongs
                  to. Client-supplied, therefore narrowing only, never proof.
  * conn_id     — PEP-generated per connection.

Chain (no step may be skipped, no fallback exists):
  run_id -> record(row_id=PP18) -> conn_id -> KILL_SWITCH.terminated_conn_ids

Usage: verify_pp18.py <audit.jsonl> <run_id> [<out.json>]
Exit 0 only when the chain is complete.
"""
from __future__ import annotations

import json
import sys

ROW = "PP18"


def load_strict(path: str) -> tuple[list[dict], int]:
    """Return (records, malformed_line_count). Malformed lines are counted, not
    silently dropped — a truncated log must be visible, not invisible."""
    recs, bad = [], 0
    try:
        with open(path) as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    recs.append(json.loads(ln))
                except ValueError:
                    bad += 1
    except OSError:
        return [], -1
    return recs, bad


def verify(audit_path: str, run_id: str) -> dict:
    recs, bad = load_strict(audit_path)
    if bad != 0:
        return {"row": ROW, "status": "AUDIT_UNREADABLE_OR_TRUNCATED",
                "detail": f"malformed_lines={bad}"}
    if not run_id:
        return {"row": ROW, "status": "NO_RUN_ID", "detail": "control plane issued no run_id"}

    scoped = [e for e in recs if str(e.get("run_id", "")) == run_id]
    if not scoped:
        return {"row": ROW, "status": "NO_RECORDS_FOR_RUN",
                "detail": f"run_id={run_id} absent from audit"}

    owners = [e for e in scoped if str(e.get("row_id", "")) == ROW and e.get("conn_id")]
    if not owners:
        return {"row": ROW, "status": "NO_MATCHING_CONNECTION",
                "detail": f"no record with row_id={ROW} in run {run_id}"}

    # The mandated PP18 chain begins at the current-execution nonce. A record
    # without one cannot be tied to this execution's test, so it fails closed
    # rather than being accepted on run_id + row_id alone.
    nonces = {str(e.get("test_nonce", "")) for e in owners}
    if "" in nonces or not nonces:
        return {"row": ROW, "status": "NO_TEST_CORRELATION",
                "detail": f"row_id={ROW} record carries no test_nonce"}
    if len(nonces) > 1:
        return {"row": ROW, "status": "NO_TEST_CORRELATION",
                "detail": f"conflicting nonces for {ROW}: {sorted(nonces)}"}

    conn_ids = {str(e["conn_id"]) for e in owners}

    kills = [e for e in scoped if e.get("decision") == "KILL_SWITCH"]
    if not kills:
        return {"row": ROW, "status": "NO_KILL_RECORD", "detail": "no KILL_SWITCH in this run"}

    killed: set[str] = set()
    for k in kills:
        for c in (k.get("terminated_conn_ids") or []):
            killed.add(str(c))
    if not killed:
        return {"row": ROW, "status": "KILL_RECORD_LISTS_NO_CONNECTIONS",
                "detail": f"kill_records={len(kills)}"}

    hit = conn_ids & killed
    if not hit:
        return {"row": ROW, "status": "TERMINATED_A_DIFFERENT_CONNECTION",
                "detail": f"pp18_conns={sorted(conn_ids)} killed={sorted(killed)[:4]}"}

    return {"row": ROW, "status": "PROVEN",
            "detail": f"run_id={run_id} conn_id={sorted(hit)[0]} "
                      f"killed_set={len(killed)} nonce={owners[-1].get('test_nonce')}"}


def main() -> int:
    audit_path = sys.argv[1]
    run_id = sys.argv[2] if len(sys.argv) > 2 else ""
    out_path = sys.argv[3] if len(sys.argv) > 3 else None
    res = verify(audit_path, run_id)
    res["run_id"] = run_id
    ok = res["status"] == "PROVEN"
    print(f"  {'PASS' if ok else 'FAIL'}  PP18   kill switch terminated THE connection "
          f"that armed it   expect=PROVEN     got={res['status']}")
    print(f"         {res['detail']}")
    if out_path:
        with open(out_path, "w") as fh:
            json.dump(res, fh, indent=2)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

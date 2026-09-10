#!/usr/bin/env python3
"""
Host-side Layer B evidence check (rows B8, B9).

The sandbox cannot read the audit log — that is the point. So the claims that
matter most are verified HERE, against the PEP's own record.

AUTHORITY MODEL (revised after the architecture review):

  run_id      Control-plane-issued, stamped by the PEP on every audit record,
              NEVER transmitted to the sandbox. This is the execution anchor.
              A valid-looking record from a previous execution carries a
              different run_id and therefore cannot satisfy the current test.

  test_nonce  A single unguessable value per execution. Per the contract,
              B8_nonce MUST EQUAL B9_nonce — they belong to one execution.
              Client-supplied, so it NARROWS which record we mean; it is never
              the proof of execution identity (run_id is).

  row_id      Structured field naming the acceptance row. Replaces the old
              practice of embedding "-b3"/"-b6" suffixes in a URL and parsing
              them back out, which was both prose-parsing and vulnerable to
              prefix collisions ("abc-b3" matching "abc-b30").

  conn_id     PEP-generated per connection.

Chains, with no fallback anywhere. Missing correlation data is a FAILURE:

  B8: run_id -> ALLOW(row_id in {B3,B5}) -> pin_family=ipv6 + real v6 pin_ip
                + canonical_host + sni + request_hash + response_hash
  B9: run_id -> record(row_id=B6) -> conn_id -> KILL_SWITCH.terminated_conn_ids
      and B8.test_nonce == B9.test_nonce

Usage: verify_layerb_audit.py <audit.jsonl> <ipv6_layerb.json> <run_id> [b6_client.json]
"""
from __future__ import annotations

import ipaddress
import json
import sys

REQUIRED_ALLOW_FIELDS = ("pin_family", "pin_ip", "canonical_host", "sni",
                         "request_hash", "response_hash")
B8_ROWS = ("B3", "B5")
B9_ROW = "B6"


def load_strict(path: str) -> tuple[list[dict], int]:
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


def is_v6(addr) -> bool:
    try:
        return ipaddress.ip_address(str(addr)).version == 6
    except (ValueError, TypeError):
        return False


def evaluate(audit_path: str, run_id: str, client_info: dict) -> tuple[dict, dict]:
    recs, bad = load_strict(audit_path)
    if bad != 0:
        err = {"status": "AUDIT_UNREADABLE_OR_TRUNCATED", "detail": f"malformed_lines={bad}"}
        return dict(err), dict(err)
    if not run_id:
        err = {"status": "NO_RUN_ID", "detail": "control plane issued no run_id"}
        return dict(err), dict(err)

    scoped = [e for e in recs if str(e.get("run_id", "")) == run_id]
    if not scoped:
        err = {"status": "NO_RECORDS_FOR_RUN", "detail": f"run_id={run_id} absent"}
        return dict(err), dict(err)

    # ---------------------------------------------------------------- B8
    allows = [e for e in scoped
              if e.get("decision") == "ALLOW" and str(e.get("row_id", "")) in B8_ROWS]
    if not allows:
        b8 = {"status": "NO_MATCHING_RECORD",
              "detail": f"no ALLOW with row_id in {B8_ROWS} for run {run_id}"}
        b8_nonce = None
    else:
        rec = allows[-1]
        b8_nonce = str(rec.get("test_nonce", ""))
        missing = [f for f in REQUIRED_ALLOW_FIELDS if not rec.get(f)]
        if rec.get("pin_family") != "ipv6":
            st = f"PIN_FAMILY_NOT_V6:{rec.get('pin_family')}"
        elif missing:
            st = f"MISSING:{','.join(missing)}"
        elif not is_v6(rec.get("pin_ip")):
            st = f"PIN_NOT_V6:{rec.get('pin_ip')}"
        elif not b8_nonce:
            st = "NO_TEST_CORRELATION"
        else:
            st = "PROVEN"
        b8 = {"status": st,
              "detail": (f"run_id={run_id} row_id={rec.get('row_id')} "
                         f"conn_id={rec.get('conn_id')} pin={rec.get('pin_ip')} "
                         f"host={rec.get('canonical_host')} sni={rec.get('sni')}"),
              "conn_id": rec.get("conn_id"), "nonce": b8_nonce,
              "pin_ip": rec.get("pin_ip")}

    # ---------------------------------------------------------------- B9
    owners = [e for e in scoped
              if str(e.get("row_id", "")) == B9_ROW and e.get("conn_id")]
    kills = [e for e in scoped if e.get("decision") == "KILL_SWITCH"]
    killed: set[str] = set()
    for k in kills:
        for c in (k.get("terminated_conn_ids") or []):
            killed.add(str(c))

    partial = client_info.get("partial_bytes")
    if not owners:
        b9 = {"status": "NO_MATCHING_CONNECTION",
              "detail": f"no record with row_id={B9_ROW} in run {run_id}"}
    elif not kills:
        b9 = {"status": "NO_KILL_RECORD", "detail": "no KILL_SWITCH in this run"}
    elif not killed:
        b9 = {"status": "KILL_RECORD_LISTS_NO_CONNECTIONS",
              "detail": f"kill_records={len(kills)}"}
    else:
        conn_ids = {str(e["conn_id"]) for e in owners}
        b9_nonce = str(owners[-1].get("test_nonce", ""))
        hit = conn_ids & killed
        if not b9_nonce:
            st = "NO_TEST_CORRELATION"
        elif not hit:
            st = "TERMINATED_A_DIFFERENT_CONNECTION"
        elif b8_nonce is not None and b8_nonce != b9_nonce:
            # Contract: one execution, one nonce.
            st = f"NONCE_MISMATCH:{b8_nonce}!={b9_nonce}"
        elif partial is not None and partial <= 0:
            st = "NO_LIVE_STREAM_BEFORE_KILL"
        else:
            st = "PROVEN"
        b9 = {"status": st,
              "detail": (f"run_id={run_id} conn_id={sorted(hit)[0] if hit else None} "
                         f"killed_set={len(killed)} nonce={b9_nonce} "
                         f"client_partial_bytes={partial}"),
              "conn_id": sorted(hit)[0] if hit else None, "nonce": b9_nonce}
    return b8, b9


def main() -> int:
    audit_path, layerb_path = sys.argv[1], sys.argv[2]
    run_id = sys.argv[3] if len(sys.argv) > 3 else ""
    client_path = sys.argv[4] if len(sys.argv) > 4 else None

    client_info = {}
    if client_path:
        try:
            with open(client_path) as fh:
                client_info = json.load(fh)
        except Exception:
            client_info = {}

    b8, b9 = evaluate(audit_path, run_id, client_info)

    with open(layerb_path) as fh:
        data = json.load(fh)
    rows = [r for r in data.get("rows", []) if r.get("id") not in ("B8", "B9")]
    for tid, desc, res in (
        ("B8", "audit proves enforcement for the IPv6 flow (run_id-scoped)", b8),
        ("B9", "kill switch terminated THE connection that armed it (conn_id)", b9),
    ):
        st = res.get("status", "NO_RESULT")
        ok = st == "PROVEN"
        rows.append({"layer": "B", "id": tid, "desc": desc, "expect": "PROVEN",
                     "got": st, "status": st, "pass": ok,
                     "detail": res.get("detail", ""),
                     "conn_id": res.get("conn_id"), "nonce": res.get("nonce")})
        print(f"  {'PASS' if ok else 'FAIL'}  {tid:6} {desc:56} expect=PROVEN      got={st}",
              flush=True)
        print(f"           {res.get('detail','')}", flush=True)

    data["rows"] = rows
    # This rewrite happens HOST-side; the sandbox's copy of the file carries
    # run_id = null by construction (it is never told the control-plane id).
    # A populated value therefore means the sandbox labelled the file itself —
    # record it rather than overwriting silently, so E8 can reject the run.
    prior = data.get("run_id")
    prior_src = data.get("run_id_source")
    already_bound = (prior_src == "control-plane" and str(prior) == run_id)
    if prior not in (None, "") and not already_bound:
        # A populated run_id that is NOT this run's control-plane stamp means the
        # sandbox labelled the file itself. Record it so E8 rejects the run.
        # (The guard matters: stamp_artifacts.py legitimately runs on this file
        # first, and treating its own stamp as a conflict would make the gate
        # unpassable by construction.)
        data["run_id_conflict"] = str(prior)
    data["run_id"] = run_id
    data["run_id_source"] = "control-plane"
    data["passed"] = sum(1 for r in rows if r.get("status") == "PROVEN")
    data["total"] = len(rows)
    with open(layerb_path, "w") as fh:
        json.dump(data, fh, indent=2)
    return 0 if data["passed"] == data["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

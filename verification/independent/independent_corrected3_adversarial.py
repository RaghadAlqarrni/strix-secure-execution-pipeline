#!/usr/bin/env python3
"""Independent adversarial checks for corrected3 E10-v2 candidate 8e924860."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

REPO = str(Path(__file__).resolve().parents[2])
sys.path.insert(0, REPO)

from pep import verify_e10  # noqa: E402
from pep.e10_anchor import build_anchor  # noqa: E402

RUN = "run-independent-corrected3"
SOURCE = "8e924860bd9b6f27381c6964ec1f585edf4d5ac3"
KEY = b"independent-local-test-key-material-32-bytes-minimum"
KEY_ID = "independent-local-test-only"
RESPONSE = "b" * 64
GENESIS = "0" * 64


def auth():
    intent_text = "v2\nGET\nallowed.lab\n/x\nbody_len=0"
    return {
        "decision": "AUTH_COMMITTED", "lifecycle_version": "E10-v2",
        "attempt_id": "att-1", "conn_id": "conn-1", "epoch": 0,
        "program_id": "prog-1", "policy_generation": "policy-1",
        "budget_binding": "budget-1", "method": "GET",
        "canonical_host": "allowed.lab", "pin_family": "ipv4",
        "pin_ip": "127.0.0.1", "pin_port": 443,
        "credential_ref": "none",
        "request_intent_digest": "sha256:" + hashlib.sha256(intent_text.encode()).hexdigest(),
        "lifecycle_seq": 1,
    }


def quiescence():
    return {
        "cancellation_epoch": 1, "lifecycle_seq": 4,
        "local_drain_complete": True, "inflight_remaining": 0,
        "effect_permits_remaining": 0, "audit_producers_remaining": 0,
        "listener_state": "STOPPED", "external_enforcement": "NOT_RUN_PHASE1",
    }


def complete_records():
    a = auth()
    request_hash = a["request_intent_digest"].split(":", 1)[1]
    q = quiescence()
    return [
        a,
        {"decision": "PERMIT_GRANTED", "attempt_id": "att-1", "conn_id": "conn-1",
         "epoch": 0, "lifecycle_seq": 2, "policy_generation": "policy-1",
         "budget_binding": "budget-1"},
        {"decision": "EFFECT_ATTEMPTED", "attempt_id": "att-1", "conn_id": "conn-1",
         "epoch": 0, "permit_seq": 2, "pin_ip": "127.0.0.1", "pin_port": 443},
        {"decision": "EFFECT_COMPLETED", "attempt_id": "att-1", "conn_id": "conn-1",
         "epoch": 0, "permit_seq": 2, "upstream_status": 200,
         "response_hash": RESPONSE, "streamed_bytes": 0},
        {"decision": "ALLOW", "reason": "ALLOW", "url": "https://allowed.lab/x",
         "method": "GET", "src": "127.0.0.1", "program_id": "prog-1",
         "conn_id": "conn-1", "attempt_id": "att-1", "test_nonce": "", "row_id": "",
         "tls_intercepted": True, "canonical_host": "allowed.lab", "sni": None,
         "pin_family": "ipv4", "pin_ip": "127.0.0.1", "pin_port": 443,
         "upstream_status": 200, "redirect_followed": False,
         "credential_injected": False, "streamed_bytes": 0,
         "request_hash": request_hash, "request_hash_semantics": "sanitized-intent-v2",
         "response_hash": RESPONSE},
        {"decision": "PERMIT_RELEASED", "attempt_id": "att-1", "conn_id": "conn-1",
         "epoch": 0, "permit_seq": 2, "lifecycle_seq": 3},
        {"decision": "CANCELLATION_REQUESTED", "reason": "STOP_ALL_PRESENT",
         "cancellation_epoch": 1, "lifecycle_seq": 4},
        {"decision": "CANCELLATION_LINEARIZED", "cancelled_epoch": 0, "new_epoch": 1,
         "lifecycle_seq": 4, "inflight_at_linearization": 0},
        {"decision": "KILL_SWITCH", "reason": "STOP_ALL_TORE_DOWN_LIVE_CONNECTIONS",
         "connections_terminated": 0, "terminated_conn_ids": [], "registered_at_kill": [], **q},
        {"decision": "CANCELLATION_ACK", "ack_scope": "LOCAL_IN_PROCESS_DRAIN_ONLY", **q},
        {"decision": "RUN_CLOSED", "closure_schema": "E10-run-close-v1",
         "closure_sequence": 4, "closure_state": "CLOSED", "admission_state": "TERMINAL",
         "inflight_remaining": 0, "effect_permits_remaining": 0,
         "audit_producers_remaining": 0, "listener_state": "STOPPED",
         "seal_action": "FINAL_FSYNC_THEN_ATOMIC_SEAL",
         "cancellation_disposition": "CANCELLATION_ACK"},
    ]


def unknown_records():
    records = complete_records()
    records[3] = {
        "decision": "EFFECT_OUTCOME_UNKNOWN", "attempt_id": "att-1",
        "conn_id": "conn-1", "epoch": 0, "permit_seq": 2,
        "reason": "TimeoutError", "bytes_streamed": 7,
    }
    records.pop(4)
    records.insert(4, {
        "decision": "CONNECTION_TERMINATED", "reason": "TimeoutError",
        "url": "https://allowed.lab/x", "method": "GET", "bytes_streamed": 7,
        "conn_id": "conn-1", "attempt_id": "att-1", "test_nonce": "", "row_id": "",
        "pin": ["ipv4", "127.0.0.1", 443],
    })
    return records


def write_chain(path, records):
    prev = GENESIS
    with open(path, "wb") as fh:
        for i, source in enumerate(records, 1):
            record = dict(source)
            record.update(run_id=RUN, ts=float(i), prev=prev)
            raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
            fh.write(raw + b"\n")
            prev = hashlib.sha256(raw).hexdigest()


def verify_case(root, name, records):
    log = os.path.join(root, name + ".jsonl")
    key = os.path.join(root, name + ".key")
    anchor_path = os.path.join(root, name + ".anchor.json")
    write_chain(log, records)
    with open(key, "wb") as fh:
        fh.write(KEY)
    anchor = build_anchor(log, expected_run_id=RUN, source_commit=SOURCE,
                          key=KEY, key_id=KEY_ID)
    with open(anchor_path, "w", encoding="utf-8") as fh:
        json.dump(anchor, fh, sort_keys=True, separators=(",", ":"))
        fh.write("\n")
    return verify_e10.verify(log, RUN, anchor_path=anchor_path,
                             trusted_key_path=key, expected_source_commit=SOURCE,
                             expected_authority_key_id=KEY_ID)


def main():
    cases = []
    with tempfile.TemporaryDirectory(prefix="corrected3-independent-") as root:
        baseline = complete_records()
        cases.append(("baseline_without_startup", verify_case(root, "baseline", baseline)))

        spoofed_allow = copy.deepcopy(baseline)
        spoofed_allow[4]["url"] = "https://allowed.lab.evil.example/x"
        cases.append(("allow_prefix_spoof", verify_case(root, "allow-prefix", spoofed_allow)))

        userinfo_allow = copy.deepcopy(baseline)
        userinfo_allow[4]["url"] = "https://allowed.lab@evil.example/x"
        cases.append(("allow_userinfo_spoof", verify_case(root, "allow-userinfo", userinfo_allow)))

        path_allow = copy.deepcopy(baseline)
        path_allow[4]["url"] = "https://allowed.lab/not-the-authorized-path"
        cases.append(("allow_path_contradiction",
                      verify_case(root, "allow-path", path_allow)))

        port_allow = copy.deepcopy(baseline)
        port_allow[4]["url"] = "https://allowed.lab:9443/x"
        cases.append(("allow_port_contradiction",
                      verify_case(root, "allow-port", port_allow)))

        spoofed_termination = unknown_records()
        spoofed_termination[4]["url"] = "https://allowed.lab.evil.example/x"
        cases.append(("termination_prefix_spoof",
                      verify_case(root, "termination-prefix", spoofed_termination)))

    for name, result in cases:
        print(name, result["status"], result.get("detail", ""))
    bad = [name for name, result in cases if result["status"] == "PROVEN"]
    print("PROVEN_CASES=" + ",".join(bad))
    return 1 if len(bad) == len(cases) else 0


if __name__ == "__main__":
    raise SystemExit(main())

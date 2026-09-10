#!/usr/bin/env python3
"""Deterministic E10-v2 transition, closure, and anchor adversarial tests."""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(PEP))

from pep.audit import AuditLog                                      # noqa: E402
from pep import lifecycle as lc                                    # noqa: E402
from pep.e10_anchor import build_anchor, canonical_payload          # noqa: E402
from pep import verify_e10                                         # noqa: E402

RUN = "run-e10-v2"
SOURCE = "a" * 40
KEY = b"phase-1-fixture-key-not-an-external-authority!!"
RESPONSE_HASH = "b" * 64


class Cases:
    def __init__(self): self.total = 0; self.failed = 0
    def check(self, name, condition):
        self.total += 1
        ok = bool(condition)
        self.failed += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")


class Pin:
    family = "ipv4"
    ip = "127.0.0.1"
    port = 443


def auth(aid="att-1", cid="c1", seq=1):
    record = lc.sanitized_intent(
        run_id=RUN, conn_id=cid, attempt_id=aid, epoch=0,
        program_id="prog_a", policy_generation="policy-1", method="GET",
        canonical_host="allowed.lab", path="/x", pin=Pin(),
        credential_ref="none", budget_binding="budget-1")
    record["lifecycle_seq"] = seq
    return record


def permit(aid="att-1", cid="c1", seq=2):
    return {"decision": lc.PERMIT, "attempt_id": aid, "conn_id": cid,
            "epoch": 0, "lifecycle_seq": seq,
            "policy_generation": "policy-1", "budget_binding": "budget-1"}


def attempted(aid="att-1", cid="c1", seq=2):
    return {"decision": lc.ATTEMPTED, "attempt_id": aid, "conn_id": cid,
            "epoch": 0, "permit_seq": seq, "pin_ip": Pin.ip,
            "pin_port": Pin.port}


def terminal(decision=lc.COMPLETED, aid="att-1", cid="c1", seq=2,
             streamed=0):
    record = {"decision": decision, "attempt_id": aid, "conn_id": cid,
              "epoch": 0, "permit_seq": seq}
    if decision == lc.COMPLETED:
        record.update(upstream_status=200, response_hash=RESPONSE_HASH,
                      streamed_bytes=streamed)
    else:
        record["reason"] = "FIXTURE_TERMINAL"
        if decision == lc.UNKNOWN:
            record["bytes_streamed"] = streamed
    return record


def allow(aid="att-1", cid="c1", streamed=0):
    return {
        "decision": "ALLOW", "reason": "ALLOW",
        "url": "https://allowed.lab/x", "method": "GET",
        "src": "127.0.0.1", "program_id": "prog_a", "conn_id": cid,
        "attempt_id": aid, "test_nonce": "", "row_id": "",
        "tls_intercepted": True, "canonical_host": "allowed.lab",
        "sni": None, "pin_family": Pin.family, "pin_ip": Pin.ip,
        "pin_port": Pin.port, "upstream_status": 200,
        "redirect_followed": False, "credential_injected": False,
        "streamed_bytes": streamed,
        "request_hash": auth(aid, cid)["request_intent_digest"].split(":", 1)[1],
        "request_hash_semantics": "sanitized-intent-v2",
        "response_hash": RESPONSE_HASH,
    }


def released(aid="att-1", cid="c1", permit_seq=2, seq=3):
    return {"decision": lc.PERMIT_RELEASED, "attempt_id": aid,
            "conn_id": cid, "epoch": 0, "permit_seq": permit_seq,
            "lifecycle_seq": seq}


def quiescence(seq, *, remaining=0, effects=0, producers=0,
               listener="STOPPED", drained=True):
    return {
        "cancellation_epoch": 1, "lifecycle_seq": seq,
        "local_drain_complete": drained,
        "inflight_remaining": remaining,
        "effect_permits_remaining": effects,
        "audit_producers_remaining": producers,
        "listener_state": listener,
        "external_enforcement": "NOT_RUN_PHASE1",
    }


def kill(seq, **kwargs):
    return {
        "decision": "KILL_SWITCH", "reason": "FIXTURE_CLOSE",
        "connections_terminated": 0, "terminated_conn_ids": [],
        "registered_at_kill": [], **quiescence(seq, **kwargs),
    }


def ack(seq, **kwargs):
    return {"decision": lc.CANCEL_ACK,
            "ack_scope": "LOCAL_IN_PROCESS_DRAIN_ONLY",
            **quiescence(seq, **kwargs)}


def closed(seq):
    return {
        "decision": lc.RUN_CLOSED, "closure_schema": "E10-run-close-v1",
        "closure_sequence": seq, "closure_state": "CLOSED",
        "admission_state": "TERMINAL", "inflight_remaining": 0,
        "effect_permits_remaining": 0, "audit_producers_remaining": 0,
        "listener_state": "STOPPED",
        "seal_action": "FINAL_FSYNC_THEN_ATOMIC_SEAL",
        "cancellation_disposition": lc.CANCEL_ACK,
    }


def cancel_requested(seq):
    return {"decision": lc.CANCEL_REQUESTED, "reason": "FIXTURE_CLOSE",
            "cancellation_epoch": 1, "lifecycle_seq": seq}


def cancel_tail(seq=4, inflight=0):
    return [
        cancel_requested(seq),
        {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
         "new_epoch": 1, "lifecycle_seq": seq,
         "inflight_at_linearization": inflight},
        kill(seq), ack(seq), closed(seq),
    ]


def complete_records():
    return [auth(), permit(), attempted(), terminal(), allow(), released(),
            *cancel_tail()]


def write_log(path, records):
    audit = AuditLog(path, run_id=RUN)
    for record in records:
        audit.write(dict(record))
    return path


def history_status(root, name, records):
    path = write_log(os.path.join(root, name + ".jsonl"), records)
    loaded, error = verify_e10._load_and_verify(path)
    assert not error
    return verify_e10._validate_history(loaded, RUN)["status"]


def write_json(path, value):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(value, fh, sort_keys=True, separators=(",", ":"))
        fh.write("\n")


def main() -> int:
    c = Cases()
    root = tempfile.mkdtemp(prefix="e10_v2_")
    try:
        good_records = complete_records()
        good_log = write_log(os.path.join(root, "good.jsonl"), good_records)
        c.check("E10-v2 positive local history validates",
                history_status(root, "good-history", good_records) ==
                "LOCAL_HISTORY_VALID")

        key_path = os.path.join(root, "fixture.key")
        with open(key_path, "wb") as fh:
            fh.write(KEY)
        anchor = build_anchor(
            good_log, expected_run_id=RUN, source_commit=SOURCE, key=KEY,
            key_id="fixture-key-not-production")
        anchor_path = os.path.join(root, "good.anchor.json")
        write_json(anchor_path, anchor)
        result = verify_e10.verify(
            good_log, RUN, anchor_path=anchor_path,
            trusted_key_path=key_path, expected_source_commit=SOURCE,
            expected_authority_key_id="fixture-key-not-production",
            non_certifying_fixture=True)
        c.check("fixture anchor is explicitly non-certifying",
                result["status"] == "LOCAL_FIXTURE_PASS_NON_CERTIFYING")
        wrong_key_id = verify_e10.verify(
            good_log, RUN, anchor_path=anchor_path,
            trusted_key_path=key_path, expected_source_commit=SOURCE,
            expected_authority_key_id="wrong-controller-selection",
            non_certifying_fixture=True)
        c.check("caller-selected expected anchor key ID is mandatory",
                wrong_key_id["status"] == "ANCHOR_AUTHORITY_KEY_ID_MISMATCH")
        cli = subprocess.run([
            sys.executable, os.path.join(PEP, "verify_e10.py"), good_log,
            "--expected-run-id", RUN, "--anchor", anchor_path,
            "--trusted-anchor-key", key_path,
            "--expected-source-commit", SOURCE,
            "--expected-authority-key-id", "fixture-key-not-production",
            "--non-certifying-fixture"], text=True, capture_output=True)
        c.check("non-certifying fixture CLI cannot return certification success",
                cli.returncode == 3)

        # Every quiescence fact is mandatory and the sum equation is universal.
        decision_indexes = {
            "KILL_SWITCH": 8, lc.CANCEL_ACK: 9, lc.RUN_CLOSED: 10,
        }
        for decision, index in decision_indexes.items():
            required = (
                verify_e10.CANCEL_REQUIRED if decision != lc.RUN_CLOSED else
                {"inflight_remaining", "effect_permits_remaining",
                 "audit_producers_remaining", "listener_state", "seal_action"})
            for field in sorted(required):
                records = copy.deepcopy(good_records)
                records[index].pop(field)
                c.check(f"{decision} missing {field} is rejected",
                        history_status(root, f"missing-{decision}-{field}",
                                       records) == "MALFORMED_RECORD_SCHEMA")

        timeout_common = quiescence(
            2, remaining=1, producers=1, drained=False)
        timeout_records = [
            auth(seq=1),
            {"decision": lc.FAILED, "attempt_id": "att-1",
             "conn_id": "c1", "epoch": 0, "reason": "NO_EFFECT"},
            cancel_requested(2),
            {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
             "new_epoch": 1, "lifecycle_seq": 2,
             "inflight_at_linearization": 0},
            {"decision": "KILL_SWITCH", "reason": "FIXTURE_CLOSE",
             "connections_terminated": 0, "terminated_conn_ids": [],
             "registered_at_kill": [], **timeout_common},
            {"decision": lc.CANCEL_DRAIN_TIMEOUT,
             "ack_scope": "NO_ACK_DRAIN_INCOMPLETE",
             "closure_blockers": ["AUDIT_PRODUCERS_REMAIN"],
             **timeout_common},
        ]
        for field in sorted(verify_e10.CANCEL_REQUIRED):
            records = copy.deepcopy(timeout_records)
            records[-1].pop(field)
            c.check(f"TIMEOUT missing {field} is rejected",
                    history_status(root, f"timeout-missing-{field}", records) ==
                    "MALFORMED_RECORD_SCHEMA")
        for index in (8, 9):
            records = copy.deepcopy(good_records)
            records[index]["audit_producers_remaining"] = 1
            c.check("contradictory quiescence sum is rejected",
                    history_status(root, f"bad-sum-{index}", records) ==
                    "QUIESCENCE_COUNT_MISMATCH")
        timeout_bad_sum = copy.deepcopy(timeout_records)
        timeout_bad_sum[-1]["audit_producers_remaining"] = 2
        c.check("TIMEOUT contradictory quiescence sum is rejected",
                history_status(root, "timeout-bad-sum", timeout_bad_sum) ==
                "QUIESCENCE_COUNT_MISMATCH")
        close_bad = copy.deepcopy(good_records)
        close_bad[10]["admission_state"] = "OPEN"
        c.check("RUN_CLOSED contradictory terminal admission is rejected",
                history_status(root, "close-admission", close_bad) ==
                "INVALID_RUN_CLOSURE")

        # Release cardinality, order, binding, closure position, and sequences.
        mutations = []
        missing = copy.deepcopy(good_records); missing.pop(5)
        mutations.append(("missing release", missing, "MISSING_PERMIT_RELEASE"))
        duplicate = copy.deepcopy(good_records); duplicate.insert(6, released())
        mutations.append(("duplicate release", duplicate,
                          "DUPLICATE_PERMIT_RELEASE"))
        before_terminal = copy.deepcopy(good_records)
        item = before_terminal.pop(5); before_terminal.insert(3, item)
        mutations.append(("release before terminal", before_terminal,
                          "RELEASE_BEFORE_TERMINAL"))
        wrong_binding = copy.deepcopy(good_records)
        wrong_binding[5]["conn_id"] = "wrong"
        mutations.append(("wrong release binding", wrong_binding,
                          "RELEASE_BINDING_MISMATCH"))
        wrong_order = copy.deepcopy(good_records)
        wrong_order[5]["lifecycle_seq"] = 2
        mutations.append(("P >= R", wrong_order, "RELEASE_SEQUENCE_ORDER"))
        reused = copy.deepcopy(good_records)
        reused[5]["lifecycle_seq"] = 1
        mutations.append(("reused lifecycle sequence", reused,
                          "RELEASE_SEQUENCE_ORDER"))
        post_close = copy.deepcopy(good_records) + [released()]
        mutations.append(("post-close release", post_close,
                          "RECORD_AFTER_RUN_CLOSURE"))
        for name, records, expected in mutations:
            c.check(name + " is rejected",
                    history_status(root, name.replace(" ", "-"), records) ==
                    expected)

        # P < R < C and P < C < R are both valid. Terminal append position is
        # deliberately before cancellation in the in-flight schedule.
        released_before_cancel = complete_records()
        c.check("P < R < C computes zero in flight",
                history_status(root, "release-before-cancel",
                               released_before_cancel) ==
                "LOCAL_HISTORY_VALID")
        in_flight = [
            auth(), permit(), attempted(), terminal(),
            cancel_requested(3),
            {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
             "new_epoch": 1, "lifecycle_seq": 3,
             "inflight_at_linearization": 1},
            allow(), released(seq=4), kill(3), ack(3), closed(3),
        ]
        c.check("terminal-before-release with P < C < R validates",
                history_status(root, "terminal-before-release", in_flight) ==
                "LOCAL_HISTORY_VALID")
        delayed_permit_append = [
            auth(),
            cancel_requested(3),
            {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
             "new_epoch": 1, "lifecycle_seq": 3,
             "inflight_at_linearization": 1},
            permit(),
            terminal(lc.CANCELLED), released(seq=4),
            kill(3), ack(3), closed(3),
        ]
        c.check("permit append after cancellation uses global sequence order",
                history_status(root, "permit-append-after-cancel",
                               delayed_permit_append) ==
                "LOCAL_HISTORY_VALID")
        permit_between_cancel_records = [
            auth(),
            cancel_requested(3),
            permit(),
            {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
             "new_epoch": 1, "lifecycle_seq": 3,
             "inflight_at_linearization": 1},
            terminal(lc.CANCELLED), released(seq=4),
            kill(3), ack(3), closed(3),
        ]
        c.check("permit append may interleave cancellation evidence records",
                history_status(root, "permit-between-cancel-records",
                               permit_between_cancel_records) ==
                "LOCAL_HISTORY_VALID")
        p_ge_c = copy.deepcopy(in_flight)
        p_ge_c[1]["lifecycle_seq"] = 3
        p_ge_c[2]["permit_seq"] = 3
        p_ge_c[3]["permit_seq"] = 3
        p_ge_c[7]["permit_seq"] = 3
        c.check("P >= C is rejected",
                history_status(root, "p-ge-c", p_ge_c) in {
                    "REPLAYED_LIFECYCLE_SEQUENCE",
                    "PERMIT_SEQUENCE_NOT_BEFORE_CANCELLATION"})
        wrong_cancel_epoch = copy.deepcopy(good_records)
        wrong_cancel_epoch[7]["cancelled_epoch"] = 7
        wrong_cancel_epoch[7]["new_epoch"] = 8
        wrong_cancel_epoch[6]["cancellation_epoch"] = 8
        wrong_cancel_epoch[8]["cancellation_epoch"] = 8
        wrong_cancel_epoch[9]["cancellation_epoch"] = 8
        c.check("cancellation epoch must bind every authorization",
                history_status(root, "wrong-cancel-epoch",
                               wrong_cancel_epoch) == "BINDING_MISMATCH")

        late_auth = [
            cancel_requested(2),
            {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
             "new_epoch": 1, "lifecycle_seq": 2,
             "inflight_at_linearization": 0},
            auth(seq=1),
            {"decision": lc.CANCELLED, "attempt_id": "att-1",
             "conn_id": "c1", "epoch": 0, "reason": "LATE_AUTH_NO_EFFECT"},
            kill(2), ack(2), closed(2),
        ]
        c.check("durably late AUTH proves A < C and has no post-cancel effect",
                history_status(root, "late-auth", late_auth) ==
                "LOCAL_HISTORY_VALID")
        auth_between_cancel_records = [
            cancel_requested(2),
            auth(seq=1),
            {"decision": lc.CANCEL_LINEARIZED, "cancelled_epoch": 0,
             "new_epoch": 1, "lifecycle_seq": 2,
             "inflight_at_linearization": 0},
            {"decision": lc.CANCELLED, "attempt_id": "att-1",
             "conn_id": "c1", "epoch": 0, "reason": "NO_EFFECT"},
            kill(2), ack(2), closed(2),
        ]
        c.check("late AUTH may interleave cancellation evidence records",
                history_status(root, "auth-between-cancel-records",
                               auth_between_cancel_records) ==
                "LOCAL_HISTORY_VALID")
        late_effect = copy.deepcopy(late_auth)
        late_effect.insert(3, permit(seq=1))
        c.check("late AUTH cannot authorize a post-cancel effect",
                history_status(root, "late-auth-effect", late_effect) !=
                "LOCAL_HISTORY_VALID")

        # KILL_SWITCH must be sole, ordered, fully bound, and fact-consistent.
        for field, value in (("cancellation_epoch", 99),
                             ("lifecycle_seq", 99)):
            records = copy.deepcopy(good_records)
            records[6][field] = value
            c.check(f"cancellation request contradictory {field} rejected",
                    history_status(root, f"request-{field}", records) ==
                    "CANCELLATION_REQUEST_BINDING_MISMATCH")
        no_kill = copy.deepcopy(good_records); no_kill.pop(8)
        c.check("missing KILL_SWITCH is rejected",
                history_status(root, "no-kill", no_kill) !=
                "LOCAL_HISTORY_VALID")
        duplicate_kill = copy.deepcopy(good_records)
        duplicate_kill.insert(9, copy.deepcopy(duplicate_kill[8]))
        c.check("duplicate KILL_SWITCH is rejected",
                history_status(root, "duplicate-kill", duplicate_kill) ==
                "KILL_SWITCH_CARDINALITY_ORDER")
        for field, value in (
                ("cancellation_epoch", 99), ("lifecycle_seq", 99),
                ("local_drain_complete", False),
                ("external_enforcement", "FAILED"),
                ("listener_state", "NOT_STOPPED"),
                ("connections_terminated", 1),
                ("terminated_conn_ids", ["not-registered"])):
            records = copy.deepcopy(good_records)
            records[8][field] = value
            c.check(f"KILL_SWITCH contradictory {field} is rejected",
                    history_status(root, f"kill-{field}", records) !=
                    "LOCAL_HISTORY_VALID")

        # Explicit semantic validation for ALLOW and CONNECTION_TERMINATED.
        for field, value in (
                ("conn_id", "wrong"), ("program_id", "wrong"),
                ("method", "POST"), ("canonical_host", "wrong.lab"),
                ("pin_ip", "192.0.2.9"), ("pin_port", 444),
                ("upstream_status", 500), ("streamed_bytes", 1),
                ("response_hash", "c" * 64), ("credential_injected", True),
                ("request_hash", "c" * 64), ("reason", "DENY"),
                ("tls_intercepted", False), ("redirect_followed", True),
                ("url", "https://wrong.lab/x"), ("sni", "wrong.lab")):
            records = copy.deepcopy(good_records)
            records[4][field] = value
            c.check(f"ALLOW contradictory {field} is rejected",
                    history_status(root, f"allow-{field}", records) ==
                    "BINDING_MISMATCH")
        connection = {
            "decision": "CONNECTION_TERMINATED", "reason": "TimeoutError",
            "url": "https://allowed.lab/x", "method": "GET",
            "bytes_streamed": 7, "conn_id": "c1", "attempt_id": "att-1",
            "test_nonce": "", "row_id": "",
            "pin": ["ipv4", "127.0.0.1", 443],
        }
        unknown_history = [
            auth(), permit(), attempted(), terminal(lc.UNKNOWN, streamed=7),
            connection, released(), *cancel_tail(),
        ]
        c.check("bound CONNECTION_TERMINATED validates",
                history_status(root, "connection-bound", unknown_history) ==
                "LOCAL_HISTORY_VALID")
        duplicate_connection = copy.deepcopy(unknown_history)
        duplicate_connection.insert(5, copy.deepcopy(duplicate_connection[4]))
        c.check("duplicate CONNECTION_TERMINATED is rejected",
                history_status(root, "connection-duplicate",
                               duplicate_connection) ==
                "DUPLICATE_CONNECTION_TERMINATED")
        for field, value in (
                ("attempt_id", "orphan"), ("conn_id", "wrong"),
                ("method", "POST"), ("bytes_streamed", 8),
                ("pin", ["ipv4", "192.0.2.1", 443]),
                ("url", "https://wrong.lab/x")):
            records = copy.deepcopy(unknown_history)
            records[4][field] = value
            c.check(f"CONNECTION_TERMINATED contradictory {field} rejected",
                    history_status(root, f"connection-{field}", records) in {
                        "ORPHAN_CONNECTION_TERMINATED",
                        "CONNECTION_TERMINATED_BINDING_MISMATCH"})
        startup_after_effect = [auth(), {
            "decision": "STARTUP", "reason": "PEP_READY",
            "max_connections": 1, "port": 1, "listener": "local",
            "listen_family": "2", "listen_addr": "127.0.0.1:1"}]
        c.check("STARTUP after an active transition is rejected",
                history_status(root, "startup-position", startup_after_effect) ==
                "ILLEGAL_RUN_TRANSITION")
        startup = {"decision": "STARTUP", "reason": "PEP_READY",
                   "max_connections": 1, "port": 1, "listener": "local",
                   "listen_family": "2", "listen_addr": "127.0.0.1:1"}
        degraded = {"decision": "STARTUP_DEGRADED",
                    "reason": "IPV6_LISTENER_UNAVAILABLE",
                    "detail": "fixture", "port": 1}
        c.check("STARTUP_DEGRADED then STARTUP is a legal prefix",
                history_status(root, "startup-prefix",
                               [degraded, startup, *good_records]) ==
                "LOCAL_HISTORY_VALID")
        failed_start = {"decision": "STARTUP_FAILED",
                        "reason": "AUDIT_SINK_UNHEALTHY",
                        "detail": "fixture"}
        c.check("STARTUP_FAILED is terminal",
                history_status(root, "startup-failed",
                               [failed_start, auth()]) ==
                "ILLEGAL_RUN_TRANSITION")
        blocked = {"decision": "BLOCKED_BY_POLICY", "reason": "DENY",
                   "pin": ["invalid-family", "127.0.0.1", 443]}
        c.check("BLOCKED_BY_POLICY contextual contradiction is rejected",
                history_status(root, "blocked-context", [blocked]) ==
                "CONTEXT_BINDING_MISMATCH")
        c.check("unknown decision has no unchecked contextual fall-through",
                history_status(root, "unknown-decision", [
                    {"decision": "UNRECOGNIZED_CONTEXT"}]) ==
                "UNKNOWN_DECISION")

        # Authentication itself remains mandatory; no local EOF is authority.
        unsigned = copy.deepcopy(anchor)
        unsigned.pop("authentication_tag")
        unsigned_path = os.path.join(root, "unsigned.anchor.json")
        write_json(unsigned_path, unsigned)
        c.check("unsigned close sidecar is rejected",
                verify_e10.verify(
                    good_log, RUN, anchor_path=unsigned_path,
                    trusted_key_path=key_path, expected_source_commit=SOURCE,
                    expected_authority_key_id="fixture-key-not-production")
                ["status"] == "ANCHOR_SCHEMA_INVALID")
        tampered = copy.deepcopy(anchor)
        tampered["record_count"] += 1
        tampered["authentication_tag"] = hmac.new(
            KEY, canonical_payload(tampered), hashlib.sha256).hexdigest()
        tampered_path = os.path.join(root, "tampered.anchor.json")
        write_json(tampered_path, tampered)
        c.check("authenticated but contradictory close anchor is rejected",
                verify_e10.verify(
                    good_log, RUN, anchor_path=tampered_path,
                    trusted_key_path=key_path, expected_source_commit=SOURCE,
                    expected_authority_key_id="fixture-key-not-production")
                ["status"] == "ANCHOR_RECORD_COUNT_MISMATCH")

        print(f"\n  E10-v2 POSITIVE/ADVERSARIAL: {c.total-c.failed}/{c.total}")
        print("  FIXTURE SCOPE: TEST KEY / NON-CERTIFYING / NO EXTERNAL AUTHORITY")
        return 0 if c.failed == 0 else 1
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())

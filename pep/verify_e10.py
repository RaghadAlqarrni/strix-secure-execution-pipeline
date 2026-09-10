#!/usr/bin/env python3
"""Exhaustive E10 state-machine and authenticated closed-run verifier."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import re

try:
    from .e10_anchor import (ANCHOR_SCHEMA, AUTHORITY_ROLE, MAC_ALGORITHM,
                             RUN_CLOSE_SCHEMA, audit_facts, canonical_payload)
except ImportError:
    from e10_anchor import (ANCHOR_SCHEMA, AUTHORITY_ROLE, MAC_ALGORITHM,
                            RUN_CLOSE_SCHEMA, audit_facts, canonical_payload)

AUTH = "AUTH_COMMITTED"
PERMIT = "PERMIT_GRANTED"
PERMIT_RELEASED = "PERMIT_RELEASED"
ATTEMPTED = "EFFECT_ATTEMPTED"
COMPLETED = "EFFECT_COMPLETED"
FAILED = "EFFECT_FAILED"
UNKNOWN = "EFFECT_OUTCOME_UNKNOWN"
CANCELLED = "EFFECT_CANCELLED"
TERMINAL = {COMPLETED, FAILED, UNKNOWN, CANCELLED}
CANCEL_REQUESTED = "CANCELLATION_REQUESTED"
CANCEL_LINEARIZED = "CANCELLATION_LINEARIZED"
CANCEL_ACK = "CANCELLATION_ACK"
CANCEL_DRAIN_TIMEOUT = "CANCELLATION_DRAIN_TIMEOUT"
RUN_CLOSED = "RUN_CLOSED"
GENESIS = "0" * 64
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")

COMMON = {"decision", "run_id", "ts", "prev"}
AUTH_FIELDS = {
    "lifecycle_version", "attempt_id", "conn_id", "epoch", "program_id",
    "policy_generation", "budget_binding", "method", "canonical_host",
    "pin_family", "pin_ip", "pin_port", "credential_ref",
    "request_intent_digest", "lifecycle_seq",
}
ALLOW_FIELDS = {
    "reason", "url", "method", "src", "program_id", "conn_id", "attempt_id",
    "test_nonce", "row_id", "tls_intercepted", "canonical_host", "sni",
    "pin_family", "pin_ip", "pin_port", "upstream_status",
    "redirect_followed", "credential_injected", "streamed_bytes",
    "request_hash", "request_hash_semantics", "response_hash",
}
CANCEL_REQUIRED = {
    "cancellation_epoch", "lifecycle_seq", "local_drain_complete",
    "inflight_remaining", "effect_permits_remaining",
    "audit_producers_remaining", "listener_state", "external_enforcement",
}

# (required fields, allowed fields). Common chain fields are implicit.
SCHEMAS = {
    AUTH: (AUTH_FIELDS, AUTH_FIELDS),
    PERMIT: (
        {"attempt_id", "conn_id", "epoch", "lifecycle_seq",
         "policy_generation", "budget_binding"},
        {"attempt_id", "conn_id", "epoch", "lifecycle_seq",
         "policy_generation", "budget_binding"},
    ),
    PERMIT_RELEASED: (
        {"attempt_id", "conn_id", "epoch", "permit_seq", "lifecycle_seq"},
        {"attempt_id", "conn_id", "epoch", "permit_seq", "lifecycle_seq"},
    ),
    ATTEMPTED: (
        {"attempt_id", "conn_id", "epoch", "permit_seq", "pin_ip", "pin_port"},
        {"attempt_id", "conn_id", "epoch", "permit_seq", "pin_ip", "pin_port"},
    ),
    COMPLETED: (
        {"attempt_id", "conn_id", "epoch", "permit_seq", "upstream_status",
         "response_hash", "streamed_bytes"},
        {"attempt_id", "conn_id", "epoch", "permit_seq", "upstream_status",
         "response_hash", "streamed_bytes"},
    ),
    FAILED: (
        {"attempt_id", "conn_id", "epoch", "reason"},
        {"attempt_id", "conn_id", "epoch", "permit_seq", "reason"},
    ),
    UNKNOWN: (
        {"attempt_id", "conn_id", "epoch", "permit_seq", "reason"},
        {"attempt_id", "conn_id", "epoch", "permit_seq", "reason",
         "bytes_streamed"},
    ),
    CANCELLED: (
        {"attempt_id", "conn_id", "epoch", "reason"},
        {"attempt_id", "conn_id", "epoch", "permit_seq", "reason"},
    ),
    "ALLOW": (ALLOW_FIELDS, ALLOW_FIELDS),
    CANCEL_REQUESTED: (
        {"reason", "cancellation_epoch", "lifecycle_seq"},
        {"reason", "cancellation_epoch", "lifecycle_seq"}),
    CANCEL_LINEARIZED: (
        {"cancelled_epoch", "new_epoch", "lifecycle_seq",
         "inflight_at_linearization"},
        {"cancelled_epoch", "new_epoch", "lifecycle_seq",
         "inflight_at_linearization"},
    ),
    CANCEL_ACK: (CANCEL_REQUIRED | {"ack_scope"},
                 CANCEL_REQUIRED | {"ack_scope"}),
    CANCEL_DRAIN_TIMEOUT: (
        CANCEL_REQUIRED | {"ack_scope"},
        CANCEL_REQUIRED | {"ack_scope", "closure_blockers"},
    ),
    RUN_CLOSED: (
        {"closure_schema", "closure_sequence", "closure_state",
         "admission_state", "inflight_remaining", "cancellation_disposition",
         "effect_permits_remaining", "audit_producers_remaining",
         "listener_state", "seal_action"},
        {"closure_schema", "closure_sequence", "closure_state",
         "admission_state", "inflight_remaining", "cancellation_disposition",
         "effect_permits_remaining", "audit_producers_remaining",
         "listener_state", "seal_action"},
    ),
    "KILL_SWITCH": (
        {"reason", "connections_terminated", "terminated_conn_ids",
         "registered_at_kill"} | CANCEL_REQUIRED,
        {"reason", "connections_terminated", "terminated_conn_ids",
         "registered_at_kill"} | CANCEL_REQUIRED,
    ),
    "BLOCKED_BY_POLICY": (
        {"reason"},
        {"reason", "url", "method", "src", "conn_id", "row_id",
         "test_nonce", "tls", "detail", "pin"},
    ),
    "CONNECTION_TERMINATED": (
        {"reason", "url", "method", "bytes_streamed", "conn_id",
         "attempt_id", "test_nonce", "row_id", "pin"},
        {"reason", "url", "method", "bytes_streamed", "conn_id",
         "attempt_id", "test_nonce", "row_id", "pin"},
    ),
    "STARTUP": (
        {"reason", "max_connections", "port", "listener", "listen_family",
         "listen_addr"},
        {"reason", "max_connections", "port", "listener", "listen_family",
         "listen_addr"},
    ),
    "STARTUP_DEGRADED": (
        {"reason", "detail", "port"}, {"reason", "detail", "port"}),
    "STARTUP_FAILED": (
        {"reason", "detail"}, {"reason", "detail"}),
}

STRING_FIELDS = {
    "lifecycle_version", "attempt_id", "conn_id", "program_id",
    "policy_generation", "budget_binding", "method", "canonical_host",
    "pin_family", "pin_ip", "credential_ref", "request_intent_digest",
    "reason", "url", "src", "test_nonce", "row_id", "request_hash",
    "request_hash_semantics", "response_hash", "ack_scope",
    "external_enforcement", "closure_schema", "closure_state",
    "admission_state", "cancellation_disposition", "listener_state",
    "seal_action", "detail", "listener", "listen_family", "listen_addr",
}


def _result(status, detail, **extra):
    out = {"status": status, "detail": detail}
    out.update(extra)
    return out


def _load_and_verify(path):
    records = []
    prev = GENESIS
    try:
        with open(path, "rb") as fh:
            for line_no, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    return None, f"line {line_no}: blank records are forbidden"
                try:
                    record = json.loads(line)
                except ValueError:
                    return None, f"line {line_no}: malformed JSON"
                if not isinstance(record, dict):
                    return None, f"line {line_no}: record is not an object"
                if record.get("prev") != prev:
                    return None, f"line {line_no}: audit chain break"
                prev = hashlib.sha256(line).hexdigest()
                records.append(record)
    except OSError as exc:
        return None, f"cannot open: {type(exc).__name__}"
    return records, ""


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _schema_error(record: dict, line_no: int) -> str:
    decision = record.get("decision")
    if decision not in SCHEMAS:
        return f"UNKNOWN_DECISION: line {line_no} decision={decision!r}"
    required, allowed = SCHEMAS[decision]
    keys = set(record)
    missing = sorted(field for field in required if field not in record)
    extra = sorted(keys - COMMON - allowed)
    if missing or extra:
        return (f"MALFORMED_RECORD_SCHEMA: line {line_no} {decision} "
                f"missing={missing} extra={extra}")
    if (not isinstance(record.get("run_id"), str) or not record["run_id"] or
            not isinstance(record.get("ts"), (int, float)) or
            isinstance(record.get("ts"), bool) or
            not math.isfinite(record["ts"]) or
            not HEX64.fullmatch(str(record.get("prev", "")))):
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid chain metadata"
    for field in STRING_FIELDS & keys:
        if not isinstance(record[field], str):
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid {field}"
    if "sni" in keys and record["sni"] is not None and not isinstance(record["sni"], str):
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid sni"
    int_fields = {
        "epoch", "pin_port", "lifecycle_seq", "permit_seq", "cancelled_epoch",
        "new_epoch", "inflight_at_linearization", "cancellation_epoch",
        "inflight_remaining", "effect_permits_remaining",
        "audit_producers_remaining", "closure_sequence", "upstream_status",
        "streamed_bytes", "bytes_streamed", "connections_terminated", "port",
        "max_connections",
    }
    for field in int_fields & keys:
        if not _is_int(record[field]) or record[field] < 0:
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid {field}"
    bool_fields = {"local_drain_complete", "tls_intercepted",
                   "redirect_followed", "credential_injected", "tls"}
    for field in bool_fields & keys:
        if not isinstance(record[field], bool):
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid {field}"
    list_fields = {"terminated_conn_ids", "registered_at_kill", "closure_blockers"}
    for field in list_fields & keys:
        if (not isinstance(record[field], list) or
                any(not isinstance(item, str) for item in record[field])):
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid {field}"
    if "pin" in keys:
        pin = record["pin"]
        if (not isinstance(pin, (list, tuple)) or len(pin) != 3 or
                not isinstance(pin[0], str) or not isinstance(pin[1], str) or
                not _is_int(pin[2]) or not 1 <= pin[2] <= 65535):
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid pin"
    if decision == AUTH:
        if (record.get("lifecycle_version") != "E10-v2" or
                any(not str(record.get(field, "")) for field in
                    ("attempt_id", "conn_id", "program_id", "policy_generation",
                     "budget_binding", "method", "canonical_host", "pin_ip",
                     "credential_ref")) or
                record.get("pin_family") not in ("ipv4", "ipv6") or
                not 1 <= record["pin_port"] <= 65535 or
                not DIGEST.fullmatch(str(record.get("request_intent_digest", "")))):
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid E10 intent"
    if decision in {AUTH, PERMIT, PERMIT_RELEASED, CANCEL_REQUESTED,
                    CANCEL_LINEARIZED} and record["lifecycle_seq"] <= 0:
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} non-positive lifecycle_seq"
    if decision in {ATTEMPTED, COMPLETED, UNKNOWN} and record["permit_seq"] <= 0:
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} non-positive permit_seq"
    if decision in {FAILED, CANCELLED} and "permit_seq" in record and record["permit_seq"] <= 0:
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} non-positive permit_seq"
    if decision == COMPLETED and not HEX64.fullmatch(record["response_hash"]):
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid response_hash"
    if decision == "ALLOW":
        if (record.get("request_hash_semantics") != "sanitized-intent-v2" or
                not HEX64.fullmatch(str(record.get("request_hash", ""))) or
                not HEX64.fullmatch(str(record.get("response_hash", "")))):
            return f"MALFORMED_RECORD_SCHEMA: line {line_no} invalid ALLOW hashes"
    if decision in {FAILED, UNKNOWN, CANCELLED, CANCEL_REQUESTED,
                    "BLOCKED_BY_POLICY", "CONNECTION_TERMINATED",
                    "STARTUP", "STARTUP_DEGRADED", "STARTUP_FAILED",
                    "KILL_SWITCH"} and not str(record.get("reason", "")):
        return f"MALFORMED_RECORD_SCHEMA: line {line_no} empty reason"
    return ""


def _looks_secret(record) -> bool:
    forbidden = {"authorization", "secret", "credential_secret", "raw_request"}

    def walk(value):
        if isinstance(value, dict):
            if forbidden & {str(key).lower() for key in value}:
                return True
            return any(walk(item) for item in value.values())
        if isinstance(value, list):
            return any(walk(item) for item in value)
        return False

    credential = str(record.get("credential_ref", ""))
    return (walk(record) or credential.lower().startswith("bearer ") or
            any(char.isspace() for char in credential))


def _validate_history(records: list[dict], expected_run_id: str) -> dict:
    if not expected_run_id:
        return _result("EXPECTED_RUN_ID_REQUIRED", "an explicit expected Run ID is required")
    if not records:
        return _result("NO_LIFECYCLE_RECORDS", "audit contains no records")
    for line_no, record in enumerate(records, 1):
        if record.get("run_id") != expected_run_id:
            return _result("WRONG_RUN_ID", f"line {line_no} is outside expected Run ID")
        error = _schema_error(record, line_no)
        if error:
            status, _, detail = error.partition(": ")
            return _result(status, detail or error)

    attempts: dict[str, dict] = {}
    sequences: dict[int, str] = {}
    run_state = "RUNNING"
    startup_seen = False
    active_seen = False
    cancel = None
    cancel_request = None
    kill = None
    disposition = None
    closure = None

    def own_sequence(seq: int, owner: str):
        if seq in sequences:
            return _result(
                "REPLAYED_LIFECYCLE_SEQUENCE",
                f"sequence {seq} already owned by {sequences[seq]}")
        sequences[seq] = owner
        return None

    def count_error(record: dict):
        if (record["inflight_remaining"] !=
                record["effect_permits_remaining"] +
                record["audit_producers_remaining"]):
            return _result("QUIESCENCE_COUNT_MISMATCH",
                           "inflight count is not permit plus producer counts")
        return None

    def incomplete_attempts():
        return [key for key, value in attempts.items()
                if value["terminal"] is None]

    def missing_releases():
        return [key for key, value in attempts.items()
                if value["permit"] is not None and value["release"] is None]

    def missing_allows():
        return [key for key, value in attempts.items()
                if value["terminal"] is not None and
                value["terminal"]["decision"] == COMPLETED and
                value["allow"] is None]

    for index, record in enumerate(records, 1):
        decision = record["decision"]
        aid = str(record.get("attempt_id", ""))

        if run_state == "CLOSED":
            return _result("RECORD_AFTER_RUN_CLOSURE",
                           f"line {index} follows RUN_CLOSED")
        if run_state in {"ACKNOWLEDGED", "DRAIN_TIMEOUT", "STARTUP_FAILED"}:
            if not (run_state == "ACKNOWLEDGED" and decision == RUN_CLOSED):
                return _result(
                    "ILLEGAL_RUN_TRANSITION",
                    f"{decision} appended after terminal run disposition")

        if decision == "STARTUP_DEGRADED":
            if startup_seen or active_seen or run_state != "RUNNING":
                return _result("ILLEGAL_RUN_TRANSITION",
                               "STARTUP_DEGRADED is outside startup")
            continue

        if decision == "STARTUP_FAILED":
            if startup_seen or active_seen or run_state != "RUNNING":
                return _result("ILLEGAL_RUN_TRANSITION",
                               "STARTUP_FAILED is outside startup")
            run_state = "STARTUP_FAILED"
            continue

        if decision == "STARTUP":
            if startup_seen or active_seen or run_state != "RUNNING":
                return _result("ILLEGAL_RUN_TRANSITION",
                               "duplicate or out-of-position STARTUP")
            if record["max_connections"] <= 0:
                return _result("CONTEXT_BINDING_MISMATCH",
                               "STARTUP max_connections must be positive")
            startup_seen = True
            run_state = "RUNNING"
            continue

        active_seen = True

        if decision == AUTH:
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "AUTH_COMMITTED is outside the active/cancel drain")
            if aid in attempts:
                return _result("ILLEGAL_ATTEMPT_TRANSITION",
                               f"attempt replayed: {aid}")
            if _looks_secret(record):
                return _result("CREDENTIAL_LEAK",
                               f"AUTH_COMMITTED {aid} may carry a secret")
            seq = record["lifecycle_seq"]
            replay = own_sequence(seq, f"auth:{aid}")
            if replay:
                return replay
            late = run_state != "RUNNING"
            if late and cancel is not None and (
                    seq >= cancel["lifecycle_seq"] or
                    record["epoch"] != cancel["cancelled_epoch"]):
                return _result("AUTH_SEQUENCE_NOT_BEFORE_CANCELLATION",
                               "late AUTH does not prove pre-cancel allocation")
            attempts[aid] = {
                "state": "AUTHORIZED", "auth": record, "permit": None,
                "attempted": None, "terminal": None, "allow": None,
                "release": None, "late_auth": late,
            }
            continue

        if decision == PERMIT:
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "PERMIT_GRANTED is outside active/cancel drain")
            attempt = attempts.get(aid)
            if attempt is None:
                return _result("PERMIT_WITHOUT_INTENT",
                               f"permit {aid!r} has no intent")
            if attempt["state"] != "AUTHORIZED" or attempt["late_auth"]:
                return _result("ILLEGAL_ATTEMPT_TRANSITION",
                               f"PERMIT_GRANTED after {attempt['state']} for {aid}")
            auth = attempt["auth"]
            for field in ("conn_id", "epoch", "policy_generation",
                          "budget_binding"):
                if record[field] != auth[field]:
                    return _result("BINDING_MISMATCH",
                                   f"permit {aid} {field} != intent")
            seq = record["lifecycle_seq"]
            if auth["lifecycle_seq"] >= seq:
                return _result("LIFECYCLE_SEQUENCE_ORDER",
                               f"AUTH sequence is not below permit for {aid}")
            replay = own_sequence(seq, f"permit:{aid}")
            if replay:
                return replay
            if cancel is not None and (
                    seq >= cancel["lifecycle_seq"] or
                    record["epoch"] != cancel["cancelled_epoch"]):
                return _result("PERMIT_SEQUENCE_NOT_BEFORE_CANCELLATION",
                               "late permit does not prove pre-cancel allocation")
            attempt["state"] = "PERMITTED"
            attempt["permit"] = record
            continue

        if decision == ATTEMPTED:
            if run_state != "RUNNING":
                return _result("POST_CANCELLATION_EFFECT",
                               f"EFFECT_ATTEMPTED after cancellation for {aid}")
            attempt = attempts.get(aid)
            if attempt is None or attempt["state"] != "PERMITTED":
                prior = attempt["state"] if attempt else "NO_INTENT"
                return _result("ILLEGAL_ATTEMPT_TRANSITION",
                               f"EFFECT_ATTEMPTED after {prior} for {aid!r}")
            permit = attempt["permit"]
            auth = attempt["auth"]
            if (record["permit_seq"] != permit["lifecycle_seq"] or
                    record["conn_id"] != permit["conn_id"] or
                    record["epoch"] != permit["epoch"] or
                    record["pin_ip"] != auth["pin_ip"] or
                    record["pin_port"] != auth["pin_port"]):
                return _result("BINDING_MISMATCH",
                               f"attempt {aid} does not match permit/pin")
            attempt["state"] = "ATTEMPTED"
            attempt["attempted"] = record
            continue

        if decision in TERMINAL:
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               f"{decision} is outside active/cancel drain")
            attempt = attempts.get(aid)
            if attempt is None:
                return _result("EFFECT_WITHOUT_INTENT",
                               f"{decision} has no intent: {aid!r}")
            prior = attempt["state"]
            legal = (
                (prior == "AUTHORIZED" and decision in {FAILED, CANCELLED}) or
                (prior == "PERMITTED" and decision in {FAILED, CANCELLED}) or
                (prior == "ATTEMPTED" and decision in TERMINAL))
            if not legal:
                return _result("ILLEGAL_ATTEMPT_TRANSITION",
                               f"{decision} after absorbing/illegal {prior} for {aid}")
            auth = attempt["auth"]
            permit = attempt["permit"]
            if record["conn_id"] != auth["conn_id"] or record["epoch"] != auth["epoch"]:
                return _result("BINDING_MISMATCH",
                               f"terminal != intent for {aid}")
            if permit is not None and record.get("permit_seq") != permit["lifecycle_seq"]:
                return _result("BINDING_MISMATCH",
                               f"terminal permit mismatch for {aid}")
            if permit is None and "permit_seq" in record:
                return _result("BINDING_MISMATCH",
                               f"terminal invents permit for {aid}")
            attempt["state"] = decision
            attempt["terminal"] = record
            continue

        if decision == "ALLOW":
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "ALLOW is outside active/cancel drain")
            attempt = attempts.get(aid)
            if attempt is None or attempt["terminal"] is None or (
                    attempt["terminal"]["decision"] != COMPLETED):
                return _result("ALLOW_WITHOUT_COMPLETION",
                               f"ALLOW has no preceding completion: {aid!r}")
            if attempt["allow"] is not None:
                return _result("DUPLICATE_ALLOW",
                               f"multiple ALLOW records for {aid}")
            auth = attempt["auth"]
            terminal = attempt["terminal"]
            attempted = attempt["attempted"]
            expected_request = auth["request_intent_digest"].split(":", 1)[1]
            expected_pin = (auth["pin_family"], auth["pin_ip"], auth["pin_port"])
            actual_pin = (record["pin_family"], record["pin_ip"],
                          record["pin_port"])
            valid = (
                attempted is not None and
                record["conn_id"] == auth["conn_id"] and
                record["program_id"] == auth["program_id"] and
                record["method"] == auth["method"] and
                record["canonical_host"] == auth["canonical_host"] and
                actual_pin == expected_pin and
                record["request_hash"] == expected_request and
                record["response_hash"] == terminal["response_hash"] and
                record["upstream_status"] == terminal["upstream_status"] and
                record["streamed_bytes"] == terminal["streamed_bytes"] and
                record["reason"] == "ALLOW" and
                record["tls_intercepted"] is True and
                record["redirect_followed"] is False and
                record["credential_injected"] ==
                (auth["credential_ref"] != "none") and
                record["url"].startswith(
                    "https://" + auth["canonical_host"]) and
                record["sni"] in {None, auth["canonical_host"]})
            if not valid:
                return _result("BINDING_MISMATCH",
                               f"ALLOW facts contradict attempt {aid}")
            attempt["allow"] = record
            continue

        if decision == PERMIT_RELEASED:
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "PERMIT_RELEASED is outside active/cancel drain")
            attempt = attempts.get(aid)
            if attempt is None or attempt["permit"] is None:
                return _result("RELEASE_WITHOUT_PERMIT",
                               f"release {aid!r} has no durable permit")
            if attempt["terminal"] is None:
                return _result("RELEASE_BEFORE_TERMINAL",
                               f"release precedes terminal for {aid}")
            if (attempt["terminal"]["decision"] == COMPLETED and
                    attempt["allow"] is None):
                return _result("RELEASE_BEFORE_ALLOW",
                               f"completed attempt {aid} released before ALLOW")
            if attempt["release"] is not None:
                return _result("DUPLICATE_PERMIT_RELEASE",
                               f"multiple releases for {aid}")
            permit = attempt["permit"]
            if (record["conn_id"] != permit["conn_id"] or
                    record["epoch"] != permit["epoch"] or
                    record["permit_seq"] != permit["lifecycle_seq"]):
                return _result("RELEASE_BINDING_MISMATCH",
                               f"release does not bind permit {aid}")
            seq = record["lifecycle_seq"]
            if permit["lifecycle_seq"] >= seq:
                return _result("RELEASE_SEQUENCE_ORDER",
                               f"permit is not below release for {aid}")
            replay = own_sequence(seq, f"release:{aid}")
            if replay:
                return replay
            attempt["release"] = record
            continue

        if decision == CANCEL_REQUESTED:
            if run_state != "RUNNING":
                return _result("ILLEGAL_RUN_TRANSITION",
                               "duplicate/out-of-order cancellation request")
            cancel_request = record
            run_state = "CANCEL_REQUESTED"
            continue

        if decision == CANCEL_LINEARIZED:
            if run_state != "CANCEL_REQUESTED":
                return _result("ILLEGAL_RUN_TRANSITION",
                               "linearization lacks one request")
            seq = record["lifecycle_seq"]
            if record["new_epoch"] != record["cancelled_epoch"] + 1:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "invalid cancellation epoch transition")
            if (cancel_request["lifecycle_seq"] != record["lifecycle_seq"] or
                    cancel_request["cancellation_epoch"] !=
                    record["new_epoch"]):
                return _result("CANCELLATION_REQUEST_BINDING_MISMATCH",
                               "request does not bind the linearization")
            replay = own_sequence(seq, "cancellation")
            if replay:
                return replay
            for attempt_id, attempt in attempts.items():
                auth = attempt["auth"]
                permit = attempt["permit"]
                if auth["epoch"] != record["cancelled_epoch"]:
                    return _result("BINDING_MISMATCH",
                                   f"AUTH {attempt_id} epoch is not cancelled epoch")
                if auth["lifecycle_seq"] >= seq:
                    return _result("AUTH_SEQUENCE_NOT_BEFORE_CANCELLATION",
                                   f"AUTH {attempt_id} is not below cancellation")
                if permit is not None and permit["lifecycle_seq"] >= seq:
                    return _result("PERMIT_SEQUENCE_NOT_BEFORE_CANCELLATION",
                                   f"permit {attempt_id} is not below cancellation")
            cancel = record
            run_state = "CANCEL_LINEARIZED"
            continue

        if decision == "KILL_SWITCH":
            if run_state != "CANCEL_LINEARIZED" or kill is not None:
                return _result("KILL_SWITCH_CARDINALITY_ORDER",
                               "KILL_SWITCH must occur exactly once after linearization")
            if incomplete_attempts():
                return _result("INCOMPLETE_ATTEMPT",
                               "KILL_SWITCH precedes terminal attempts",
                               incomplete_attempt_ids=incomplete_attempts())
            if missing_allows():
                return _result("MISSING_REQUIRED_ALLOW",
                               "KILL_SWITCH precedes required ALLOW",
                               attempt_ids=missing_allows())
            if missing_releases():
                return _result("MISSING_PERMIT_RELEASE",
                               "KILL_SWITCH precedes durable releases",
                               attempt_ids=missing_releases())
            mismatch = count_error(record)
            if mismatch:
                return mismatch
            logical_inflight = sum(
                1 for attempt in attempts.values()
                if attempt["permit"] is not None and
                attempt["permit"]["lifecycle_seq"] < cancel["lifecycle_seq"] <
                attempt["release"]["lifecycle_seq"])
            if logical_inflight != cancel["inflight_at_linearization"]:
                return _result(
                    "INFLIGHT_LINEARIZATION_MISMATCH",
                    f"recorded={cancel['inflight_at_linearization']} "
                    f"computed={logical_inflight}")
            if (record["lifecycle_seq"] != cancel["lifecycle_seq"] or
                    record["cancellation_epoch"] != cancel["new_epoch"] or
                    record["effect_permits_remaining"] != 0 or
                    record["connections_terminated"] !=
                    len(record["terminated_conn_ids"]) or
                    len(set(record["terminated_conn_ids"])) !=
                    len(record["terminated_conn_ids"]) or
                    len(set(record["registered_at_kill"])) !=
                    len(record["registered_at_kill"]) or
                    not set(record["terminated_conn_ids"]).issubset(
                        set(record["registered_at_kill"])) or
                    record["external_enforcement"] != "NOT_RUN_PHASE1"):
                return _result("KILL_SWITCH_BINDING_MISMATCH",
                               "KILL_SWITCH facts contradict cancellation")
            quiescent = (
                record["inflight_remaining"] == 0 and
                record["listener_state"] == "STOPPED")
            if record["local_drain_complete"] is not quiescent:
                return _result("KILL_SWITCH_BINDING_MISMATCH",
                               "KILL_SWITCH drain fact contradicts counts/listener")
            kill = record
            continue

        if decision in {CANCEL_ACK, CANCEL_DRAIN_TIMEOUT}:
            if run_state != "CANCEL_LINEARIZED" or kill is None:
                return _result("ILLEGAL_RUN_TRANSITION",
                               f"{decision} lacks the sole bound KILL_SWITCH")
            mismatch = count_error(record)
            if mismatch:
                return mismatch
            binding_fields = (
                "cancellation_epoch", "lifecycle_seq",
                "local_drain_complete", "inflight_remaining",
                "effect_permits_remaining", "audit_producers_remaining",
                "listener_state", "external_enforcement")
            if any(record[field] != kill[field] for field in binding_fields):
                return _result("FALSE_CANCELLATION_DISPOSITION",
                               "disposition contradicts KILL_SWITCH")
            if decision == CANCEL_ACK:
                valid = (
                    record["local_drain_complete"] is True and
                    record["inflight_remaining"] == 0 and
                    record["effect_permits_remaining"] == 0 and
                    record["audit_producers_remaining"] == 0 and
                    record["listener_state"] == "STOPPED" and
                    record["external_enforcement"] == "NOT_RUN_PHASE1" and
                    record["ack_scope"] == "LOCAL_IN_PROCESS_DRAIN_ONLY")
                if not valid:
                    return _result("FALSE_CANCELLATION_DISPOSITION",
                                   "invalid ACK quiescence facts")
                run_state = "ACKNOWLEDGED"
            else:
                blockers = record["closure_blockers"]
                valid = (
                    record["local_drain_complete"] is False and
                    record["ack_scope"] == "NO_ACK_DRAIN_INCOMPLETE" and
                    bool(blockers) and
                    (record["inflight_remaining"] > 0 or
                     record["listener_state"] != "STOPPED"))
                if not valid:
                    return _result("FALSE_CANCELLATION_DISPOSITION",
                                   "invalid TIMEOUT quiescence facts")
                run_state = "DRAIN_TIMEOUT"
            disposition = decision
            continue

        if decision == RUN_CLOSED:
            if run_state != "ACKNOWLEDGED":
                return _result("ILLEGAL_RUN_TRANSITION",
                               "RUN_CLOSED requires ACK")
            if (record["closure_schema"] != RUN_CLOSE_SCHEMA or
                    record["closure_sequence"] != cancel["lifecycle_seq"] or
                    record["closure_state"] != "CLOSED" or
                    record["admission_state"] != "TERMINAL" or
                    record["inflight_remaining"] != 0 or
                    record["effect_permits_remaining"] != 0 or
                    record["audit_producers_remaining"] != 0 or
                    record["listener_state"] != "STOPPED" or
                    record["seal_action"] !=
                    "FINAL_FSYNC_THEN_ATOMIC_SEAL" or
                    record["cancellation_disposition"] != CANCEL_ACK):
                return _result("INVALID_RUN_CLOSURE",
                               "RUN_CLOSED fields are not exact")
            mismatch = count_error(record)
            if mismatch:
                return mismatch
            closure = record
            run_state = "CLOSED"
            continue

        if decision == "CONNECTION_TERMINATED":
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "CONNECTION_TERMINATED outside active/drain run")
            attempt = attempts.get(aid)
            if (attempt is None or attempt["attempted"] is None or
                    attempt["terminal"] is None or
                    attempt["terminal"]["decision"] != UNKNOWN):
                return _result("ORPHAN_CONNECTION_TERMINATED",
                               f"no attempted UNKNOWN effect for {aid!r}")
            auth = attempt["auth"]
            terminal = attempt["terminal"]
            if attempt.get("connection_terminated") is not None:
                return _result("DUPLICATE_CONNECTION_TERMINATED",
                               f"multiple termination records for {aid}")
            expected_pin = [auth["pin_family"], auth["pin_ip"],
                            auth["pin_port"]]
            if (record["conn_id"] != auth["conn_id"] or
                    record["method"] != auth["method"] or
                    list(record["pin"]) != expected_pin or
                    terminal.get("bytes_streamed") !=
                    record["bytes_streamed"] or
                    not record["url"].startswith(
                        "https://" + auth["canonical_host"])):
                return _result("CONNECTION_TERMINATED_BINDING_MISMATCH",
                               f"termination facts contradict {aid}")
            attempt["connection_terminated"] = record
            continue

        if decision == "BLOCKED_BY_POLICY":
            if run_state not in {
                    "RUNNING", "CANCEL_REQUESTED",
                    "CANCEL_LINEARIZED"} or kill:
                return _result("ILLEGAL_RUN_TRANSITION",
                               "BLOCKED_BY_POLICY outside active/drain run")
            if record.get("pin") is not None and record["pin"][0] not in {
                    "ipv4", "ipv6"}:
                return _result("CONTEXT_BINDING_MISMATCH",
                               "BLOCKED_BY_POLICY has invalid pin family")
            continue

        return _result("UNVALIDATED_CONTEXTUAL_RECORD",
                       f"no semantic branch for {decision}")

    if not attempts:
        return _result("NO_LIFECYCLE_RECORDS",
                       "no E10-v2 authorization intents")
    incomplete = incomplete_attempts()
    missing_allow = missing_allows()
    missing_release = missing_releases()
    counts = {
        "intents": len(attempts),
        "permits": sum(value["permit"] is not None for value in attempts.values()),
        "attempted": sum(value["attempted"] is not None
                         for value in attempts.values()),
        "completed": sum(value["terminal"] is not None and
                         value["terminal"]["decision"] == COMPLETED
                         for value in attempts.values()),
        "outcome_unknown": len(incomplete),
        "allow": sum(value["allow"] is not None for value in attempts.values()),
        "released": sum(value["release"] is not None for value in attempts.values()),
    }
    if incomplete:
        return _result("INCOMPLETE_ATTEMPT", "attempt lacks absorbing outcome",
                       counts=counts,
                       release_disposition="INDEPENDENT_REVIEW_REQUIRED_NO_AUTOMATIC_RETRY",
                       incomplete_attempt_ids=incomplete)
    if missing_allow:
        return _result("MISSING_REQUIRED_ALLOW", "completed gateway effects lack ALLOW",
                       counts=counts, attempt_ids=missing_allow)
    if missing_release:
        return _result("MISSING_PERMIT_RELEASE",
                       "durable permits lack durable release",
                       counts=counts, attempt_ids=missing_release)
    if kill is None and cancel is not None:
        return _result("MISSING_KILL_SWITCH",
                       "cancellation has no semantically bound KILL_SWITCH")
    if run_state == "RUNNING":
        return _result("RUN_NOT_CLOSED", "EOF is not completeness evidence", counts=counts)
    if run_state == "CANCEL_REQUESTED":
        return _result("MISSING_CANCELLATION_LINEARIZATION", "request has no linearization")
    if run_state == "CANCEL_LINEARIZED":
        return _result("MISSING_CANCELLATION_DISPOSITION",
                       "linearization has no disposition")
    if run_state == "DRAIN_TIMEOUT":
        return _result("RUN_NOT_CLOSED", "timeout cannot close a run", counts=counts)
    if run_state == "ACKNOWLEDGED":
        return _result("RUN_NOT_CLOSED", "ACK is not a close", counts=counts)
    return _result("LOCAL_HISTORY_VALID", "closed history satisfies E10 state machines",
                   counts=counts, closure=closure, disposition=disposition)


def verify(audit_path: str, run_id: str = "", *, anchor_path: str = "",
           trusted_key_path: str = "", expected_source_commit: str = "",
           expected_authority_key_id: str = "",
           non_certifying_fixture: bool = False) -> dict:
    records, error = _load_and_verify(audit_path)
    if records is None:
        return _result("AUDIT_UNREADABLE_OR_CORRUPT", error)
    history = _validate_history(records, run_id)
    if history["status"] != "LOCAL_HISTORY_VALID":
        return history
    if not expected_source_commit or not COMMIT.fullmatch(expected_source_commit):
        return _result("EXPECTED_SOURCE_COMMIT_REQUIRED", "exact source commit is required")
    if not expected_authority_key_id:
        return _result("EXPECTED_AUTHORITY_KEY_ID_REQUIRED",
                       "release controller must select the authority key ID")
    if not anchor_path:
        return _result("ANCHOR_REQUIRED", "EOF/local sidecar is not completeness evidence")
    if not trusted_key_path:
        return _result("TRUSTED_ANCHOR_KEY_REQUIRED", "separate authority key is required")
    try:
        with open(anchor_path, "rb") as fh:
            anchor = json.load(fh)
    except (OSError, ValueError) as exc:
        return _result("ANCHOR_UNREADABLE", f"cannot load anchor: {type(exc).__name__}")
    try:
        with open(trusted_key_path, "rb") as fh:
            key = fh.read()
    except OSError as exc:
        return _result("TRUSTED_ANCHOR_KEY_UNAVAILABLE", type(exc).__name__)
    if len(key) < 32:
        return _result("TRUSTED_ANCHOR_KEY_INVALID", "authority key is shorter than 32 bytes")
    mandatory = {"schema", "authority_role", "authority_key_id", "mac_algorithm",
                 "run_id", "source_commit", "record_count", "byte_length",
                 "final_chain_hash", "closure_sequence", "closure_state",
                 "issued_at", "authentication_tag"}
    if set(anchor) != mandatory:
        return _result("ANCHOR_SCHEMA_INVALID",
                       f"anchor fields mismatch missing={sorted(mandatory-set(anchor))} "
                       f"extra={sorted(set(anchor)-mandatory)}")
    if (anchor["schema"] != ANCHOR_SCHEMA or anchor["authority_role"] != AUTHORITY_ROLE or
            anchor["mac_algorithm"] != MAC_ALGORITHM):
        return _result("ANCHOR_SCHEMA_INVALID", "unsupported anchor schema/authority/algorithm")
    expected_tag = hmac.new(key, canonical_payload(anchor), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(str(anchor["authentication_tag"]), expected_tag):
        return _result("ANCHOR_AUTHENTICATION_FAILED", "anchor MAC does not verify")
    if anchor["authority_key_id"] != expected_authority_key_id:
        return _result("ANCHOR_AUTHORITY_KEY_ID_MISMATCH",
                       "authenticated anchor key ID was not selected by verifier")
    facts = audit_facts(audit_path)
    closure = history["closure"]
    comparisons = (
        ("run_id", run_id, "ANCHOR_RUN_ID_MISMATCH"),
        ("source_commit", expected_source_commit, "ANCHOR_SOURCE_COMMIT_MISMATCH"),
        ("record_count", facts["record_count"], "ANCHOR_RECORD_COUNT_MISMATCH"),
        ("byte_length", facts["byte_length"], "ANCHOR_BYTE_LENGTH_MISMATCH"),
        ("final_chain_hash", facts["final_chain_hash"], "ANCHOR_TAIL_HASH_MISMATCH"),
        ("closure_sequence", closure["closure_sequence"], "ANCHOR_CLOSURE_SEQUENCE_MISMATCH"),
        ("closure_state", closure["closure_state"], "ANCHOR_CLOSURE_STATE_MISMATCH"),
    )
    for field, expected, status in comparisons:
        if anchor[field] != expected:
            return _result(status, f"anchor {field} does not bind selected run")
    status = "LOCAL_FIXTURE_PASS_NON_CERTIFYING" if non_certifying_fixture else "PROVEN"
    disposition = ("TEST_KEY_MECHANICS_ONLY_NOT_CERTIFYING" if non_certifying_fixture
                   else "E10_ANCHORED_LOCAL_VERIFICATION_PASS")
    return _result(status, "state machines and authenticated closed range match",
                   counts=history.get("counts"), release_disposition=disposition)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify E10 closed-run evidence")
    parser.add_argument("audit")
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--anchor", required=True)
    parser.add_argument("--trusted-anchor-key", required=True)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-authority-key-id", required=True)
    parser.add_argument("--non-certifying-fixture", action="store_true")
    args = parser.parse_args()
    result = verify(
        args.audit, args.expected_run_id, anchor_path=args.anchor,
        trusted_key_path=args.trusted_anchor_key,
        expected_source_commit=args.expected_source_commit,
        expected_authority_key_id=args.expected_authority_key_id,
        non_certifying_fixture=args.non_certifying_fixture)
    proven = result["status"] == "PROVEN"
    fixture_ok = result["status"] == "LOCAL_FIXTURE_PASS_NON_CERTIFYING"
    print(f"  {'PASS' if proven else 'FAIL'}  E10 anchored lifecycle got={result['status']}")
    print(f"         {result.get('detail', '')}")
    if result.get("release_disposition"):
        print(f"         release_disposition={result['release_disposition']}")
    if fixture_ok:
        return 3
    return 0 if proven else 1


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Control-plane close-anchor contract for E10.

The gateway never imports this module and never receives the authentication
key. A control-plane process that has stopped/quiesced the gateway may bind an
exact closed audit byte range to a source commit. HMAC is the Phase 1
authentication mechanism; custody, provisioning, rotation, and an external
append-only/WORM publication service remain integration dependencies.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import time

ANCHOR_SCHEMA = "E10-close-anchor-v1"
RUN_CLOSE_SCHEMA = "E10-run-close-v1"
MAC_ALGORITHM = "HMAC-SHA256"
AUTHORITY_ROLE = "CONTROL_PLANE_CLOSE_AUTHORITY"
GENESIS = "0" * 64
COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def canonical_payload(anchor: dict) -> bytes:
    payload = {key: value for key, value in anchor.items()
               if key != "authentication_tag"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def audit_facts(audit_path: str) -> dict:
    count = 0
    tail = GENESIS
    last = None
    with open(audit_path, "rb") as fh:
        raw_file = fh.read()
    for line_no, raw in enumerate(raw_file.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"line {line_no}: malformed JSON") from exc
        if rec.get("prev") != tail:
            raise ValueError(f"line {line_no}: audit chain break")
        tail = hashlib.sha256(line).hexdigest()
        count += 1
        last = rec
    return {
        "record_count": count,
        "byte_length": len(raw_file),
        "final_chain_hash": tail,
        "last_record": last,
    }


def build_anchor(audit_path: str, *, expected_run_id: str,
                 source_commit: str, key: bytes, key_id: str,
                 issued_at: str | None = None) -> dict:
    """Build an authenticated anchor; caller is the control-plane authority."""
    if not expected_run_id:
        raise ValueError("expected_run_id is required")
    if not COMMIT.fullmatch(source_commit):
        raise ValueError("source_commit must be a lowercase 40/64-hex object id")
    if len(key) < 32:
        raise ValueError("control-plane anchor key must contain at least 32 bytes")
    if not key_id:
        raise ValueError("key_id is required")
    facts = audit_facts(audit_path)
    close = facts.pop("last_record")
    if not close or close.get("decision") != "RUN_CLOSED":
        raise ValueError("the final record is not RUN_CLOSED")
    if close.get("run_id") != expected_run_id:
        raise ValueError("RUN_CLOSED does not bind expected_run_id")
    if close.get("closure_schema") != RUN_CLOSE_SCHEMA:
        raise ValueError("unsupported run closure schema")
    anchor = {
        "schema": ANCHOR_SCHEMA,
        "authority_role": AUTHORITY_ROLE,
        "authority_key_id": key_id,
        "mac_algorithm": MAC_ALGORITHM,
        "run_id": expected_run_id,
        "source_commit": source_commit,
        "record_count": facts["record_count"],
        "byte_length": facts["byte_length"],
        "final_chain_hash": facts["final_chain_hash"],
        "closure_sequence": close.get("closure_sequence"),
        "closure_state": close.get("closure_state"),
        "issued_at": issued_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    anchor["authentication_tag"] = hmac.new(
        key, canonical_payload(anchor), hashlib.sha256).hexdigest()
    return anchor


def write_anchor(path: str, anchor: dict) -> None:
    """Durably create, never replace, an authority-owned anchor file."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    data = json.dumps(anchor, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("zero progress writing anchor")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue an E10 control-plane close anchor")
    parser.add_argument("--audit", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--authority-key-file", required=True)
    parser.add_argument("--authority-key-id", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    with open(args.authority_key_file, "rb") as fh:
        key = fh.read()
    anchor = build_anchor(
        args.audit, expected_run_id=args.expected_run_id,
        source_commit=args.source_commit, key=key,
        key_id=args.authority_key_id)
    write_anchor(args.output, anchor)
    print("ANCHOR_WRITTEN_CONTROL_PLANE_AUTHORITY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

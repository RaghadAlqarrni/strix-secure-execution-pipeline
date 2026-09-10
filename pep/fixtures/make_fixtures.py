#!/usr/bin/env python3
"""
Adversarial fixture generator for the Evidence Auditor.

Builds ONE honest, internally-consistent evidence set and forged
variants. The honest one must validate in fixture mode (exit 3); every forgery must be rejected
(exit 1). Fixtures 11-15 forge the VERIFIER SOURCE rather than the evidence, to
prove the auditor notices when the checker itself is weakened; 18-21 forge the
ARTIFACT BINDING.

Hash chains are really computed, exactly the way AuditLog.write does, so E7 is
exercised for real rather than passing trivially. f16 is then deliberately
corrupted from a valid chain and f17 deliberately truncated — that is the point
of those two.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
GENESIS = "0" * 64

RID = "run-honest0000000000000000000000"
NONCE = "n0nce0000111122223333444455556666"
C_B3 = "aaaa0000000000000000000000000001"
C_B6 = "bbbb0000000000000000000000000002"
C_PP18 = "cccc0000000000000000000000000003"
C_B4_SNI = "dddd0000000000000000000000000004"
C_B4_HOST = "eeee0000000000000000000000000005"
V6 = "fd00:9a17:e9:1::20"


def chain(records: list[dict]) -> bytes:
    """Serialize with a valid prev-hash chain, exactly as AuditLog.write does."""
    out, prev = [], GENESIS
    for r in records:
        rec = dict(r)
        rec["prev"] = prev
        line = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
        out.append(line)
        prev = hashlib.sha256(line).hexdigest()
    return b"\n".join(out) + b"\n"


def honest_records(run_id: str = RID, nonce: str = NONCE) -> list[dict]:
    base = {"run_id": run_id, "ts": 1000.0}
    return [
        {**base, "decision": "STARTUP", "reason": "PEP_READY"},
        {**base, "decision": "ALLOW", "reason": "ALLOW", "row_id": "B3",
         "test_nonce": nonce, "conn_id": C_B3, "pin_family": "ipv6", "pin_ip": V6,
         "pin_port": 443, "canonical_host": "allowed6.lab", "sni": "allowed6.lab",
         "request_hash": "a" * 64, "response_hash": "b" * 64,
         "url": "https://allowed6.lab:443/ok", "redirect_followed": False},
        {**base, "decision": "BLOCKED_BY_POLICY",
         "reason": "SNI_MISMATCH:evil6.lab!=allowed6.lab", "row_id": "B4",
         "test_nonce": nonce, "conn_id": C_B4_SNI, "tls": True},
        {**base, "decision": "BLOCKED_BY_POLICY",
         "reason": "HOST_HEADER_MISMATCH:evil6.lab!=allowed6.lab", "row_id": "B4",
         "test_nonce": nonce, "conn_id": C_B4_HOST, "tls": True},
        {**base, "decision": "CONNECTION_TERMINATED", "reason": "OSError",
         "row_id": "B6", "test_nonce": nonce, "conn_id": C_B6,
         "url": "https://slow6.lab:443/drip", "pin": ["ipv6", "fd00:9a17:e9:1::60", 443]},
        {**base, "decision": "CONNECTION_TERMINATED", "reason": "OSError",
         "row_id": "PP18", "test_nonce": nonce, "conn_id": C_PP18,
         "url": "https://slow.lab:443/drip", "pin": ["ipv4", "172.29.0.60", 443]},
        {**base, "decision": "KILL_SWITCH",
         "reason": "STOP_ALL_TORE_DOWN_LIVE_CONNECTIONS",
         "connections_terminated": 2, "terminated_conn_ids": [C_B6, C_PP18]},
    ]


def honest_artifacts() -> dict:
    a_rows = [{"layer": "A", "id": f"A{i}", "desc": f"row {i}", "expect": "DENY",
               "got": "DENY", "status": "PROVEN", "pass": True, "detail": ""}
              for i in range(1, 31)]
    b_rows = [{"layer": "B", "id": f"B{i}", "desc": f"row {i}", "expect": "PROVEN",
               "got": "PROVEN", "status": "PROVEN", "pass": True, "detail": ""}
              for i in range(1, 10)]
    # run_id_source marks a CONTROL-PLANE stamp. The sandbox is never told the
    # run_id, so only the host can legitimately produce these two fields (E8).
    cp = {"run_id": RID, "run_id_source": "control-plane"}
    acc = {**cp, "layer_a": a_rows, "layer_b": copy.deepcopy(b_rows),
           "layer_a_passed": 30, "layer_a_total": 30,
           "layer_b_passed": 9, "layer_b_total": 9, "gate_passed": True}
    lb = {**cp, "rows": b_rows, "passed": 9, "total": 9, "test_nonce": NONCE}
    v4 = {**cp, "passed": 17, "total": 17,
          "results": [{"id": f"PP{i}", "status": "PROVEN", "pass": True}
                      for i in range(1, 18)]}
    measured = "f" * 64
    b7 = {**cp, "schema_version": "strix-b7-e9-v1",
          "sender": {"container_id": "sbx-container-id", "host_veth": "vethB7",
                     "network_id": "net-internal-id", "src_ip": "fd00:9a17:e9:2::50"},
          "target": {"ip": "fd00:9a17:e9:1::80", "port": 49177,
                     "network_id": "net-egress-id",
                     "off_link": True},
          "probe": {"protocol": "udp", "nonce": measured},
          "packet_attempt": {"observed": True, "source": "tcpdump-host-veth",
                             "rule_identity": "capture-vethB7",
                             "src_ip": "fd00:9a17:e9:2::50",
                             "dst_ip": "fd00:9a17:e9:1::80", "dst_port": 49177,
                             "protocol": "udp", "nonce": measured,
                             "pcap_sha256": "6" * 64},
          "enforcement": {"action": "DROP", "preexisting": True,
                          "rule_identity": "DOCKER-ISOLATION:rule-7",
                          "src_ip": "fd00:9a17:e9:2::50",
                          "dst_ip": "fd00:9a17:e9:1::80", "dst_port": 49177,
                          "protocol": "udp", "packets_before": 10,
                          "packets_after": 11},
          "controls": {"c1_nonce": "1" * 64, "c2_nonce": "2" * 64},
          "receiver": {"ready": True, "c1_seen": True, "c2_seen": True,
                       "measurement_seen": False, "raw_log_sha256": "3" * 64},
          "sender_script_sha256": "4" * 64, "receiver_script_sha256": "5" * 64,
          "calibration": {"run_id": "run-calibration-distinct", "seen": True,
                          "nonce": "7" * 64,
                          "sender_sha256": "4" * 64, "receiver_sha256": "5" * 64},
          "b7_teardown": True}
    return {"acceptance": acc, "layerb": lb, "v4": v4, "b7": b7}


def write_fixture(name: str, records, arts: dict, verifier_src: str | None = None):
    d = os.path.join(HERE, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "audit.jsonl"), "wb") as fh:
        fh.write(records if isinstance(records, bytes) else chain(records))
    for k, v in arts.items():
        with open(os.path.join(d, f"{k}.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(v, fh, indent=2)
    if verifier_src is not None:
        with open(os.path.join(d, "verifier.py"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(verifier_src)
    return d


# --- weakened verifier variants (fixtures 11-15) ---------------------------
STRICT_CODES = ('NO_TEST_CORRELATION = "NO_TEST_CORRELATION"\n'
                'TERMINATED_A_DIFFERENT_CONNECTION = "TERMINATED_A_DIFFERENT_CONNECTION"\n')

MUT = {
    "f11_verifier_hostname_fallback": STRICT_CODES + '''
def find(entries, conn_id, host):
    if not conn_id:
        # fallback to hostname matching when the correlation key is absent
        return [e for e in entries if e.get("canonical_host") == host]
''',
    "f12_verifier_timestamp_fallback": STRICT_CODES + '''
def find(entries, conn_id):
    if not conn_id:
        return sorted(entries, key=lambda e: e["ts"])[-1]
''',
    "f13_verifier_latest_record": STRICT_CODES + '''
def find(entries):
    most_recent = max(entries, key=lambda e: e["ts"])
    return most_recent
''',
    "f14_verifier_any_kill_event": STRICT_CODES + '''
def killed(entries):
    kills = [e for e in entries if e.get("decision") == "KILL_SWITCH"]
    return bool(kills)          # any kill event counts
''',
    "f15_verifier_count_only": STRICT_CODES + '''
def killed(entries, conn_id):
    total = sum(int(e.get("connections_terminated") or 0) for e in entries)
    return total > 0            # count without exact conn_id
''',
}


def build_all() -> list[tuple[str, str]]:
    made = []

    # 0 — honest
    write_fixture("f00_honest", honest_records(), honest_artifacts())
    made.append(("f00_honest", "FIXTURE_VALIDATED"))

    # 1 — valid IPv6 ALLOW, but from a PREVIOUS execution
    recs = honest_records()
    recs[1] = {**recs[1], "run_id": "run-PREVIOUS0000000000000000000"}
    write_fixture("f01_stale_execution", recs, honest_artifacts())
    made.append(("f01_stale_execution", "FIXTURE_REJECTED"))

    # 2 — B8 nonce != B9 nonce
    recs = honest_records()
    i = next(i for i, r in enumerate(recs) if r.get("row_id") == "B6")
    recs[i] = {**recs[i], "test_nonce": "DIFFERENT-NONCE-999"}
    write_fixture("f02_nonce_mismatch", recs, honest_artifacts())
    made.append(("f02_nonce_mismatch", "FIXTURE_REJECTED"))

    # 3 — pin_family says ipv6 but pin_ip is IPv4
    recs = honest_records()
    recs[1] = {**recs[1], "pin_ip": "172.29.0.20"}
    write_fixture("f03_pin_not_v6", recs, honest_artifacts())
    made.append(("f03_pin_not_v6", "FIXTURE_REJECTED"))

    # 4 — kill switch terminated an unrelated connection
    recs = honest_records()
    i = next(i for i, r in enumerate(recs) if r.get("decision") == "KILL_SWITCH")
    recs[i] = {**recs[i], "terminated_conn_ids": ["dddd000000000000unrelated00000001"]}
    write_fixture("f04_killed_other_conn", recs, honest_artifacts())
    made.append(("f04_killed_other_conn", "FIXTURE_REJECTED"))

    # 5 / 6 — missing hashes
    for idx, field in ((5, "request_hash"), (6, "response_hash")):
        recs = honest_records()
        r = dict(recs[1]); r.pop(field)
        recs[1] = r
        nm = f"f0{idx}_missing_{field}"
        write_fixture(nm, recs, honest_artifacts())
        made.append((nm, "FIXTURE_REJECTED"))

    # 7 — missing nonce
    recs = honest_records()
    i1 = next(i for i, r in enumerate(recs) if r.get("row_id") == "B3")
    i2 = next(i for i, r in enumerate(recs) if r.get("row_id") == "B6")
    r1 = dict(recs[i1]); r1.pop("test_nonce")
    r2 = dict(recs[i2]); r2.pop("test_nonce")
    recs[i1], recs[i2] = r1, r2
    write_fixture("f07_missing_nonce", recs, honest_artifacts())
    made.append(("f07_missing_nonce", "FIXTURE_REJECTED"))

    # 8 — summary claims 9/9 while a raw row is non-PROVEN
    arts = honest_artifacts()
    arts["layerb"]["rows"][4] = {**arts["layerb"]["rows"][4],
                                 "status": "BLOCKED_ENV", "got": "BLOCKED_ENV",
                                 "pass": True}
    write_fixture("f08_hidden_non_proven", honest_records(), arts)
    made.append(("f08_hidden_non_proven", "FIXTURE_REJECTED"))

    # 9 — counts disagree with rows actually present
    arts = honest_artifacts()
    arts["layerb"]["rows"] = arts["layerb"]["rows"][:7]
    arts["layerb"]["passed"] = 9
    arts["layerb"]["total"] = 9
    write_fixture("f09_count_mismatch", honest_records(), arts)
    made.append(("f09_count_mismatch", "FIXTURE_REJECTED"))

    # 10 — PP18 claimed but no matching raw chain
    recs = honest_records()
    recs = [r for r in recs if r.get("row_id") != "PP18"]
    recs[-1] = {**recs[-1], "terminated_conn_ids": [C_B6]}
    write_fixture("f10_pp18_unbacked", recs, honest_artifacts())
    made.append(("f10_pp18_unbacked", "FIXTURE_REJECTED"))

    # 11-15 — weakened verifiers
    for nm, src in MUT.items():
        write_fixture(nm, honest_records(), honest_artifacts(), verifier_src=src)
        made.append((nm, "FIXTURE_REJECTED"))

    # 16 — broken hash chain (E7)
    lines = chain(honest_records()).split(b"\n")
    rec = json.loads(lines[2]); rec["reason"] = "TAMPERED"
    lines[2] = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
    write_fixture("f16_broken_chain", b"\n".join(lines), honest_artifacts())
    made.append(("f16_broken_chain", "FIXTURE_REJECTED"))

    # 17 — truncated/malformed line appended (E7)
    raw = chain(honest_records()) + b'{"partial": tru\n'
    write_fixture("f17_truncated_log", raw, honest_artifacts())
    made.append(("f17_truncated_log", "FIXTURE_REJECTED"))

    # 18 — artifact belongs to a DIFFERENT execution than the one audited (E8)
    arts = honest_artifacts()
    arts["v4"] = {**arts["v4"], "run_id": "run-SOMEOTHEREXECUTION00000000"}
    write_fixture("f18_artifact_run_id_mismatch", honest_records(), arts)
    made.append(("f18_artifact_run_id_mismatch", "FIXTURE_REJECTED"))

    # 19 — artifact SELF-LABELLED by the measured party: right run_id, but no
    #      control-plane stamp. A claim, not a binding.
    arts = honest_artifacts()
    v4 = dict(arts["v4"]); v4["run_id_source"] = "sandbox"
    arts["v4"] = v4
    write_fixture("f19_artifact_self_labelled", honest_records(), arts)
    made.append(("f19_artifact_self_labelled", "FIXTURE_REJECTED"))

    # 20 — stamper detected the artifact had authored its own run_id (E8)
    arts = honest_artifacts()
    arts["layerb"] = {**arts["layerb"], "run_id_conflict": "run-SANDBOXCHOSE0000000000000"}
    write_fixture("f20_artifact_run_id_conflict", honest_records(), arts)
    made.append(("f20_artifact_run_id_conflict", "FIXTURE_REJECTED"))

    # 21 — the sandbox learned the run_id and self-labelled with the CORRECT
    #      value. Built by running the REAL stamper, so this fixture tests
    #      stamp_artifacts.py itself, not a hand-written conflict flag.
    sys.path.insert(0, PEP)
    import stamp_artifacts                                    # noqa: E402
    arts = honest_artifacts()
    d = write_fixture("f21_selflabel_matching_runid", honest_records(), arts)
    tgt = os.path.join(d, "v4.json")
    with open(tgt) as fh:
        v4 = json.load(fh)
    v4.pop("run_id_source", None)
    v4["run_id"] = RID              # correct value, asserted by the wrong party
    with open(tgt, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(v4, fh, indent=2)
    stamp_artifacts.stamp(tgt, RID)
    made.append(("f21_selflabel_matching_runid", "FIXTURE_REJECTED"))

    # 22 — a required row's status and pass fields disagree (P3-CRIT-2 /
    #      TRIAGE_UNIFIED.md; Pass 4's D-3): status claims "PROVEN" while the
    #      row's OWN pass field says False. rec() in ipv6_acceptance.py /
    #      ipv6_transport.py always sets both from one `ok` at construction,
    #      so honest rows never disagree — but E1 previously read status
    #      only, so nothing stopped a row from a different/broken/hand-edited
    #      path from claiming PROVEN while contradicting itself. A10 is
    #      arbitrary; any required A- or B-row demonstrates the same hole.
    arts = honest_artifacts()
    arts["acceptance"]["layer_a"][9] = {**arts["acceptance"]["layer_a"][9],
                                        "pass": False}
    write_fixture("f22_contradictory_row", honest_records(), arts)
    made.append(("f22_contradictory_row", "FIXTURE_REJECTED"))

    # 23 — a valid chain for the current run explicitly records degraded
    #       startup.  This must hard-fail certification (DEC-4), even when all
    #       sandbox-authored result rows claim PROVEN.
    records = honest_records()
    records.insert(1, {"decision": "STARTUP_DEGRADED",
                       "reason": "IPV6_LISTENER_UNAVAILABLE",
                       "detail": "negative-control fixture",
                       "run_id": RID, "ts": 1000.0})
    write_fixture("f23_startup_degraded", records, honest_artifacts())
    made.append(("f23_startup_degraded", "FIXTURE_REJECTED"))

    # 24 — the sandbox claims B4 passed, but raw audit has only the SNI denial
    #       and no HOST_HEADER_MISMATCH decision.
    records = [r for r in honest_records()
               if not str(r.get("reason", "")).startswith("HOST_HEADER_MISMATCH:")]
    write_fixture("f24_missing_b4_host_denial", records, honest_artifacts())
    made.append(("f24_missing_b4_host_denial", "FIXTURE_REJECTED"))

    # 25-32 — E9 must reject every broken link in the B7 evidence chain.
    mutations = {
        "f25_b7_unrelated_counter": lambda b: b["enforcement"].update(
            rule_identity=b["packet_attempt"]["rule_identity"]),
        "f26_b7_receiver_dead": lambda b: b["receiver"].update(c2_seen=False),
        "f27_b7_no_packet_attempt": lambda b: b["packet_attempt"].update(observed=False),
        "f28_b7_wrong_port": lambda b: b["packet_attempt"].update(dst_port=49178),
        "f29_b7_measurement_seen": lambda b: b["receiver"].update(measurement_seen=True),
        "f30_b7_counter_unchanged": lambda b: b["enforcement"].update(packets_after=10),
        "f31_b7_cross_run": lambda b: b.update(run_id="run-OTHER"),
        "f32_b7_no_calibration": lambda b: b["calibration"].update(seen=False),
    }
    for name, mutate in mutations.items():
        arts = honest_artifacts()
        mutate(arts["b7"])
        write_fixture(name, honest_records(), arts)
        made.append((name, "FIXTURE_REJECTED"))

    return made


if __name__ == "__main__":
    made = build_all()
    print(f"built {len(made)} fixtures in {HERE}")
    for n, exp in made:
        print(f"  {n:34} expect: {exp}")

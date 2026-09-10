#!/usr/bin/env python3
"""Independent E9 re-derivation for DEC-7 B7 off-link IPv6 UDP evidence."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys

SCHEMA = "strix-b7-e9-v1"
HEX64 = r"[0-9a-f]{64}"
REQUIRED_RAW = ("attempt.pcap", "receiver.jsonl", "cal_receiver.jsonl",
                "rules.before", "rules.after", "sandbox.inspect.json",
                "receiver.inspect.json", "network-in.inspect.json",
                "network-eg.inspect.json", "host-links.json",
                "sandbox-ipv6-addr.json", "sandbox-ipv6-route-before.json")


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        obj = json.load(fh)
    if not isinstance(obj, dict):
        raise ValueError("evidence is not a JSON object")
    return obj


def is_v6(value: object) -> bool:
    try:
        return ipaddress.ip_address(str(value)).version == 6
    except ValueError:
        return False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _raw_checks(e: dict, raw_dir: str) -> list[str]:
    """Re-derive runtime claims from raw apparatus output, never the summary."""
    f: list[str] = []
    need = lambda ok, code: None if ok else f.append(code)
    p = lambda n: os.path.join(raw_dir, n)
    need(all(os.path.isfile(p(n)) and not os.path.islink(p(n))
             for n in REQUIRED_RAW), "RAW_ARTIFACTS_ABSENT_OR_UNSAFE")
    if f:
        return f
    sender, target, probe = e["sender"], e["target"], e["probe"]
    nonce = probe["nonce"]
    # Capture binding and payload attribution.
    need(sha256_file(p("attempt.pcap")) == e["packet_attempt"].get("pcap_sha256"),
         "PCAP_HASH_MISMATCH")
    raw_pcap = Path(p("attempt.pcap")).read_bytes()
    need(nonce.encode("ascii") in raw_pcap, "NONCE_ABSENT_FROM_PCAP")
    # Receiver and calibration are independently parsed from JSONL.
    def nonces(name: str) -> set[str]:
        out = set()
        for line in Path(p(name)).read_text(encoding="utf-8", errors="strict").splitlines():
            o = json.loads(line); n = o.get("nonce")
            if isinstance(n, str): out.add(n)
        return out
    rn, cn = nonces("receiver.jsonl"), nonces("cal_receiver.jsonl")
    c = e["controls"]; cal = e["calibration"]
    need(sha256_file(p("receiver.jsonl")) == e["receiver"].get("raw_log_sha256"),
         "RECEIVER_RAW_HASH_MISMATCH")
    need(c.get("c1_nonce") in rn and c.get("c2_nonce") in rn,
         "RAW_RECEIVER_CONTROL_FAILED")
    need(nonce not in rn, "RAW_MEASUREMENT_REACHED_RECEIVER")
    need(sha256_file(p("cal_receiver.jsonl")) == cal.get("raw_log_sha256"),
         "CAL_RAW_HASH_MISMATCH")
    need(cal.get("nonce") in cn, "RAW_CALIBRATION_NOT_DELIVERED")
    # Exact rule identity and counters are reconstructed from both snapshots.
    counter_pattern = r'^\[(\d+):(\d+)\]\s+(.*)$'
    def rules(name: str) -> dict[str, tuple[int, int]]:
        out = {}
        for line in Path(p(name)).read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(counter_pattern, line.strip())
            if m: out[m.group(3)] = (int(m.group(1)), int(m.group(2)))
        return out
    rb, ra = rules("rules.before"), rules("rules.after")
    rule = e["enforcement"].get("rule_identity", "")
    exact_tokens = ("-A PREROUTING", "",
                    f"-s {sender['src_ip']}/128", f"-d {target['ip']}/128",
                    "-p udp", f"--dport {target['port']}",
                    "-j DROP")
    # The ingress match is the program bridge (stored by the raw network inspect),
    # not the peer veth name: packets enter FORWARD through that bridge.
    nin = json.loads(Path(p("network-in.inspect.json")).read_text(encoding="utf-8"))[0]
    bridge = (nin.get("Options") or {}).get("com.docker.network.bridge.name") \
             or "br-" + nin["Id"][:12]
    exact_tokens = tuple(x for x in exact_tokens if x) + (f"-i {bridge}",)
    need(rule in rb and rule in ra, "EXACT_RULE_NOT_IN_RAW_SNAPSHOTS")
    need(all(t in rule for t in exact_tokens), "RAW_RULE_NOT_EXACT_FLOW")
    need(f"strix-b7:{e['run_id']}" in rule, "RAW_RULE_RUN_LABEL_MISSING")
    if rule in rb and rule in ra:
        need(ra[rule][0] == rb[rule][0] + 1, "RAW_EXACT_COUNTER_NOT_ONE")
    # Control-plane identity/topology reconstruction.
    sbx = json.loads(Path(p("sandbox.inspect.json")).read_text(encoding="utf-8"))[0]
    recv = json.loads(Path(p("receiver.inspect.json")).read_text(encoding="utf-8"))[0]
    neg = json.loads(Path(p("network-eg.inspect.json")).read_text(encoding="utf-8"))[0]
    need(sbx.get("Id") == sender.get("container_id") and
         (sbx.get("State") or {}).get("Pid") == sender.get("container_pid"),
         "RAW_SENDER_IDENTITY_MISMATCH")
    need(nin.get("Id") == sender.get("network_id") and
         neg.get("Id") == target.get("network_id"), "RAW_NETWORK_ID_MISMATCH")
    links = json.loads(Path(p("host-links.json")).read_text(encoding="utf-8"))
    need(any(x.get("ifname", "").split("@")[0] == sender.get("host_veth") for x in links),
         "RAW_HOST_VETH_ABSENT")
    nets = ((sbx.get("NetworkSettings") or {}).get("Networks") or {})
    inrec = nets.get(nin.get("Name"), {})
    need(str(inrec.get("GlobalIPv6Address")) == sender.get("src_ip"),
         "RAW_SENDER_IPV6_MISMATCH")
    need(target.get("network_id") != sender.get("network_id"),
         "RAW_TARGET_NOT_OFFLINK")
    rnets = ((recv.get("NetworkSettings") or {}).get("Networks") or {})
    erec = rnets.get(neg.get("Name"), {})
    need(str(erec.get("GlobalIPv6Address")) == target.get("ip"),
         "RAW_TARGET_IPV6_MISMATCH")
    routes = json.loads(Path(p("sandbox-ipv6-route-before.json")).read_text(encoding="utf-8"))
    need(not any(str(x.get("dst")) == f"{target.get('ip')}/128" for x in routes),
         "RAW_TARGET_ALREADY_ROUTED")
    return f


def validate_fixture_summary(e: dict, layerb: dict, run_id: str) -> tuple[bool, list[str]]:
    """Validate synthetic summary assertions only; never evidence of enforcement.

    Production callers must use derive(), which additionally requires raw input.
    This helper returns no certification/result marker and is used only by the
    explicitly non-certifying fixture CLI and summary falsification tests.
    """
    failures: list[str] = []
    need = lambda ok, code: None if ok else failures.append(code)
    need(e.get("schema_version") == SCHEMA, "SCHEMA_MISMATCH")
    need(e.get("run_id") == run_id, "RUN_ID_MISMATCH")
    need(e.get("run_id_source") == "control-plane", "NOT_CONTROL_PLANE_BOUND")

    sender, target, probe = (e.get("sender") or {}, e.get("target") or {},
                             e.get("probe") or {})
    need(bool(sender.get("container_id") and sender.get("host_veth")
              and sender.get("network_id")), "SENDER_IDENTITY_ABSENT")
    need(is_v6(sender.get("src_ip")), "SENDER_NOT_IPV6")
    need(is_v6(target.get("ip")) and target.get("off_link") is True,
         "TARGET_NOT_PROVEN_OFFLINK")
    port = target.get("port")
    need(isinstance(port, int) and 1024 <= port <= 65535, "TARGET_PORT_INVALID")
    nonce = str(probe.get("nonce", ""))
    need(probe.get("protocol") == "udp" and bool(re.fullmatch(HEX64, nonce)),
         "PROBE_TUPLE_INVALID")

    attempt = e.get("packet_attempt") or {}
    enforcement = e.get("enforcement") or {}
    expected = {"src_ip": sender.get("src_ip"), "dst_ip": target.get("ip"),
                "dst_port": port, "protocol": "udp", "nonce": nonce}
    need(attempt.get("observed") is True, "NO_HOST_PACKET_ATTEMPT")
    need(all(attempt.get(k) == v for k, v in expected.items()),
         "ATTEMPT_TUPLE_MISMATCH")
    need(attempt.get("source") in ("tcpdump-host-veth", "host-bridge-capture"),
         "ATTEMPT_SOURCE_NOT_INDEPENDENT")
    need(bool(re.fullmatch(HEX64, str(attempt.get("pcap_sha256", "")))),
         "ATTEMPT_CAPTURE_UNBOUND")
    need(enforcement.get("action") == "DROP" and enforcement.get("preexisting") is True,
         "ENFORCEMENT_NOT_PREEXISTING_DROP")
    need(all(enforcement.get(k) == v for k, v in expected.items() if k != "nonce"),
         "ENFORCEMENT_TUPLE_MISMATCH")
    need(bool(enforcement.get("rule_identity")), "ENFORCEMENT_RULE_ABSENT")
    need(enforcement.get("rule_identity") != attempt.get("rule_identity"),
         "ATTEMPT_AND_DROP_SAME_SOURCE")
    before, after = enforcement.get("packets_before"), enforcement.get("packets_after")
    need(isinstance(before, int) and isinstance(after, int) and after == before + 1,
         "EXACT_DROP_COUNTER_NOT_ONE")

    controls, receiver = e.get("controls") or {}, e.get("receiver") or {}
    c1, c2 = str(controls.get("c1_nonce", "")), str(controls.get("c2_nonce", ""))
    need(bool(re.fullmatch(HEX64, c1)) and bool(re.fullmatch(HEX64, c2))
         and len({c1, nonce, c2}) == 3, "CONTROL_NONCES_INVALID")
    need(receiver.get("ready") is True, "RECEIVER_NOT_READY")
    need(receiver.get("c1_seen") is True and receiver.get("c2_seen") is True,
         "RECEIVER_CONTROL_FAILED")
    need(receiver.get("measurement_seen") is False, "MEASUREMENT_REACHED_RECEIVER")
    need(bool(re.fullmatch(HEX64, str(receiver.get("raw_log_sha256", "")))),
         "RECEIVER_LOG_UNBOUND")

    cal = e.get("calibration") or {}
    need(cal.get("run_id") and cal.get("run_id") != run_id,
         "CALIBRATION_RUN_NOT_DISTINCT")
    need(cal.get("seen") is True, "CALIBRATION_NOT_DELIVERED")
    need(cal.get("sender_sha256") == e.get("sender_script_sha256")
         and cal.get("receiver_sha256") == e.get("receiver_script_sha256"),
         "CALIBRATION_CODE_MISMATCH")
    need(e.get("b7_teardown") is True, "B7_FIXTURE_NOT_TORN_DOWN")

    rows = {str(r.get("id")): r for r in (layerb.get("rows") or [])}
    b3 = rows.get("B3") or {}
    need(b3.get("status") == "PROVEN" and b3.get("pass") is True,
         "B3_LIVENESS_NOT_PROVEN")
    return not failures, failures


def derive(e: dict, layerb: dict, run_id: str, raw_dir: str | None = None) -> tuple[bool, list[str]]:
    """Production E9: absent raw acquisition is never a summary-only pass."""
    if not raw_dir or not os.path.isdir(raw_dir) or os.path.islink(raw_dir):
        return False, ["RAW_DIRECTORY_ABSENT_OR_UNSAFE"]
    try:
        _, failures = validate_fixture_summary(e, layerb, run_id)
        failures.extend(_raw_checks(e, raw_dir))
    except Exception as exc:
        return False, [f"RAW_REDERIVATION_FAILED:{type(exc).__name__}"]
    return not failures, failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--layerb", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--raw-dir")
    ap.add_argument("--json-out")
    a = ap.parse_args()
    try:
        evidence, layerb = load(a.evidence), load(a.layerb)
        ok, failures = derive(evidence, layerb, a.run_id, a.raw_dir)
    except Exception as exc:
        ok, failures = False, [f"UNREADABLE:{type(exc).__name__}"]
    result = {"check": "E9", "pass": ok,
              "status": "PROVEN" if ok else "NOT_PROVEN", "failures": failures}
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, sort_keys=True, indent=2)
    print(json.dumps(result, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

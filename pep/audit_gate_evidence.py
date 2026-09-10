#!/usr/bin/env python3
"""
EVIDENCE AUDITOR — the check on the checker.

A green "Layer B: 9/9" is a claim the harness makes ABOUT ITSELF. This tool
refuses it at face value and re-derives from the PEP's raw audit log the claims
that CAN be re-derived from it: E3, E4, E7, and the PP18 half of E6.

What is NOT re-derived, and must not be read as if it were:
  * Layer A rows A1..A30 — pure policy-logic evaluation, no network activity, so
    no audit records exist to check them against.
  * Layer B rows B1..B6 — measured INSIDE the sandbox and self-reported. B7 is
    re-derived by E9 from host evidence; B8/B9 from the PEP audit.
  * E6's "IPv4 regression complete" half — read from the sandbox-written
    pep_results.json.
E1/E2 check the summary against its own rows; they catch self-contradiction, not
a false row.

AUTHORITY HIERARCHY (strict):
    RAW AUDIT + CONNECTION REGISTRY  >  EVIDENCE AUDITOR  >  VERIFIER  >  SUMMARY

Nothing below may override contradictory evidence above it.

NINE CHECKS
  E1  strict WHITELIST: every required row has status == "PROVEN".
      Unknown != pass. A blacklist was the previous design and let any
      unrecognised status through.
  E2  required row IDs are exactly {A1..A30} and {B1..B9} — no duplicates, no
      extras, no substitutions — and the reported counts match reality.
  E3  nonce integrity from RAW AUDIT FIELDS ONLY (never from verifier prose):
      B8 and B9 carry the SAME test_nonce, in the CURRENT run_id.
  E4  conn_id integrity re-derived from raw records: the exact conn_id of the
      B6 connection appears in KILL_SWITCH.terminated_conn_ids of this run.
  E5  verifier source integrity across ALL verifier modules.
  E6  IPv4 regression complete AND PP18 re-derived from the raw audit — never
      from the sandbox-written kill.json.
  E7  audit chain integrity: hash chain recomputed independently here, zero
      malformed lines, run_id present and consistent.
  E8  artifact binding (R-7): all AUDITED artifacts (acceptance, layerb, v4,
      B7 host evidence) carry THIS run_id and a CONTROL-PLANE source. An
      artifact that labelled itself is a claim by the measured party, not a
      binding. pep_kill.json and b6_client.json are stamped but not checked
      here — both are advisory and neither feeds a verdict.
  E9  B7 host-side re-derivation: exact UDP attempt, pre-existing enforcement
      event, occupied receiver controls, calibration and B3 liveness.

Exit 0 = CERTIFIED. Anything else = NOT CERTIFIED.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import ipaddress
import json
import os
import re
import sys

GENESIS = "0" * 64
REQUIRED_A = {f"A{i}" for i in range(1, 31)}
REQUIRED_B = {f"B{i}" for i in range(1, 10)}
REQUIRED_ALLOW_FIELDS = ("pin_family", "pin_ip", "canonical_host", "sni",
                         "request_hash", "response_hash")
B8_ROWS = ("B3", "B5")
B9_ROW = "B6"

FALLBACK_PATTERNS = (
    r"\bfallback\b",
    r"if\s+not\s+\w*conn_id\w*\s*:",
    r"(sorted|max|min)\s*\([^)]*\bts\b",
    r"\b(most_recent|latest_record|newest)\b",
)
REQUIRED_STRICT_CODES = ("NO_TEST_CORRELATION", "TERMINATED_A_DIFFERENT_CONNECTION")
DYNAMIC_CALLS = {"eval", "exec", "compile", "__import__", "getattr"}

# Blacklisting weakened SHAPES is a losing game — f14 ("any kill event counts")
# and f15 ("termination count > 0") both evaded pattern matching while being
# exactly the weakening we care about. So E5 also asserts POSITIVE constructs a
# correct verifier must contain:
#   * it must reference terminated_conn_ids (the exact-membership evidence), and
#   * it must actually perform a membership test (an `in` comparison).
# A verifier that decides on a COUNT instead of membership fails both.
REQUIRED_CONSTRUCTS = ("terminated_conn_ids",)
COUNT_FIELD = "connections_terminated"

findings: list[tuple[str, str, bool, str]] = []


def chk(cid: str, desc: str, ok: bool, detail: str = "") -> None:
    findings.append((cid, desc, ok, detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {cid:4} {desc:56} {detail}", flush=True)


def load_json(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def load_audit(path: str) -> tuple[list[dict], list[bytes], int]:
    """Return (records, raw_lines, malformed_count). Malformed lines are COUNTED,
    never silently dropped — truncation must be visible."""
    recs, raws, bad = [], [], 0
    try:
        with open(path, "rb") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                    raws.append(line)
                except ValueError:
                    bad += 1
    except OSError:
        return [], [], -1
    return recs, raws, bad


def is_v6(addr) -> bool:
    try:
        return ipaddress.ip_address(str(addr)).version == 6
    except (ValueError, TypeError):
        return False


def strip_noncode(src: str) -> str:
    src = re.sub(r'"""(?:.|\n)*?"""', "", src)
    src = re.sub(r"'''(?:.|\n)*?'''", "", src)
    return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))


def ast_membership_and_count(src: str) -> tuple[bool, bool]:
    """Return (has_membership_test, decides_on_count).

    A correct kill-switch verifier proves membership of an exact conn_id in
    terminated_conn_ids — an ``in`` comparison. One that instead thresholds
    ``connections_terminated`` is deciding on a count, which is precisely the
    weakening fixtures 14/15 encode.
    """
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False, False
    has_in = False
    on_count = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            if any(isinstance(op, ast.In) for op in node.ops):
                has_in = True
            seg = ast.dump(node)
            if COUNT_FIELD in seg:
                on_count = True
        if isinstance(node, (ast.BoolOp, ast.Return)) and COUNT_FIELD in ast.dump(node):
            on_count = True
    return has_in, on_count


def ast_findings(src: str) -> list[str]:
    """AST pass: catch dynamic-execution shapes that regex cannot see."""
    out: list[str] = []
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return [f"unparseable:{exc.lineno}"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            name = getattr(fn, "id", None) or getattr(fn, "attr", None)
            if name in DYNAMIC_CALLS:
                out.append(f"dynamic_call:{name}")
        if isinstance(node, ast.Import):
            for al in node.names:
                if al.name in ("importlib", "imp"):
                    out.append(f"dynamic_import:{al.name}")
        if isinstance(node, ast.ImportFrom) and node.module in ("importlib", "imp"):
            out.append(f"dynamic_import:{node.module}")
    return sorted(set(out))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--acceptance", required=True)
    ap.add_argument("--layerb", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--v4")
    ap.add_argument("--b7-evidence")
    ap.add_argument("--verifier", action="append", default=None)
    ap.add_argument("--integrity-manifest")
    ap.add_argument("--fixture-mode", action="store_true",
                    help="Synthetic summary checks only; never certifies; success exits 3")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    integrity_manifest = a.integrity_manifest or os.path.join(here, "audit_manifest_required.json")
    manifest_obj = load_json(integrity_manifest) or {}
    expected_verifier_hashes = manifest_obj.get("verifier_sha256") or {}
    verifiers = a.verifier or [os.path.join(here, "verify_layerb_audit.py"),
                               os.path.join(here, "verify_pp18.py"),
                               os.path.join(here, "verify_b7_evidence.py")]

    acc = load_json(a.acceptance) or {}
    lb = load_json(a.layerb) or {}
    v4 = load_json(a.v4) if a.v4 else None
    b7_evidence = load_json(a.b7_evidence) if a.b7_evidence else None
    recs, raws, bad = load_audit(a.audit)
    run_id = a.run_id

    print("=" * 78)
    print("FIXTURE VALIDATION — synthetic assertions, not enforcement evidence"
          if a.fixture_mode else
          "EVIDENCE AUDIT — independent re-derivation from the raw audit log")
    print(f"  run_id = {run_id}")
    print("=" * 78)

    scoped = [e for e in recs if str(e.get("run_id", "")) == run_id]
    degraded = [e for e in scoped if e.get("decision") == "STARTUP_DEGRADED"]

    # ------------------------------------------------------------------ E7
    # (run first: if the log is not intact, nothing derived from it is usable)
    chain_ok, chain_detail = True, ""
    prev = GENESIS
    for i, (rec, raw) in enumerate(zip(recs, raws), 1):
        if rec.get("prev") != prev:
            chain_ok, chain_detail = False, f"chain break at record {i}"
            break
        prev = hashlib.sha256(raw).hexdigest()
    if chain_ok:
        chain_detail = f"{len(recs)} records, chain intact"
    # DEC-4: degraded startup is a certification failure in its own right,
    # rather than an indirect side effect of later Layer-B rows failing.
    e7_ok = chain_ok and bad == 0 and bool(scoped) and not degraded
    chk("E7", "audit chain intact, run_id present, startup not degraded", e7_ok,
        f"{chain_detail}, malformed={bad}, records_for_run={len(scoped)}, "
        f"startup_degraded={len(degraded)}")

    # ------------------------------------------------------------------ E1
    # P3-CRIT-2: status and pass are two views of the SAME fact, set together
    # by one `ok` at construction (rec() in ipv6_acceptance.py /
    # ipv6_transport.py: status = "PROVEN" if ok else str(got); pass = ok).
    # They can only be read separately here because this file reads a JSON
    # blob off disk — nothing guarantees that blob came from rec(). A row
    # with status == "PROVEN" but pass in {False, None, missing} is either
    # corrupted, hand-edited, or written by a code path that decoupled the
    # two, and certifying it on status alone is exactly the self-trust this
    # auditor exists to refuse. Absence of `pass` counts as failing it, same
    # as "unknown != pass" already applies to status.
    a_rows = acc.get("layer_a") or []
    b_rows = lb.get("rows") or []
    required_rows = [r for r in a_rows if r.get("id") in REQUIRED_A] + \
                    [r for r in b_rows if r.get("id") in REQUIRED_B]
    not_proven = [f"{r.get('id')}={r.get('status', r.get('got', 'MISSING'))}"
                  for r in required_rows if str(r.get("status")) != "PROVEN"]
    contradictory = [f"{r.get('id')}=status:PROVEN,pass:{r.get('pass')!r}"
                     for r in required_rows
                     if str(r.get("status")) == "PROVEN" and r.get("pass") is not True]
    have_a = {r.get("id") for r in a_rows}
    have_b = {r.get("id") for r in b_rows}
    absent = sorted((REQUIRED_A - have_a) | (REQUIRED_B - have_b))
    e1_ok = not not_proven and not absent and not contradictory
    chk("E1", "every required row has status == PROVEN (strict whitelist), "
              "pass == True (no self-contradiction)", e1_ok,
        "clean" if e1_ok else
        f"not_proven={not_proven[:5]} missing={absent[:5]} "
        f"contradictory={contradictory[:5]}")

    # ------------------------------------------------------------------ E2
    ids_a = [r.get("id") for r in a_rows]
    ids_b = [r.get("id") for r in b_rows]
    dupes = ([x for x in set(ids_a) if ids_a.count(x) > 1] +
             [x for x in set(ids_b) if ids_b.count(x) > 1])
    extras = sorted((have_a - REQUIRED_A) | (have_b - REQUIRED_B))
    counts_ok = (acc.get("layer_a_total") == len(a_rows)
                 and acc.get("layer_a_passed") == sum(
                     1 for r in a_rows if str(r.get("status")) == "PROVEN")
                 and lb.get("total") == len(b_rows)
                 and lb.get("passed") == sum(
                     1 for r in b_rows if r.get("id") in REQUIRED_B
                     and str(r.get("status")) == "PROVEN"))
    e2_ok = (set(ids_a) == REQUIRED_A and set(ids_b) == REQUIRED_B
             and not dupes and not extras and counts_ok)
    chk("E2", "row ID sets exactly {A1..A30}/{B1..B9}, counts match reality", e2_ok,
        f"A={len(ids_a)} B={len(ids_b)} dupes={dupes[:3]} extras={extras[:3]} "
        f"counts_ok={counts_ok}")

    # ------------------------------------------------------------------ E3
    # RAW AUDIT ONLY. Never the verifier's detail strings.
    b8_recs = [e for e in scoped
               if e.get("decision") == "ALLOW" and str(e.get("row_id", "")) in B8_ROWS]
    b9_recs = [e for e in scoped
               if str(e.get("row_id", "")) == B9_ROW and e.get("conn_id")]
    n8 = str(b8_recs[-1].get("test_nonce", "")) if b8_recs else ""
    n9 = str(b9_recs[-1].get("test_nonce", "")) if b9_recs else ""
    if not b8_recs or not b9_recs:
        e3_ok, e3_detail = False, f"b8_records={len(b8_recs)} b9_records={len(b9_recs)}"
    elif not n8 or not n9:
        e3_ok, e3_detail = False, "NO_TEST_CORRELATION (nonce absent from raw record)"
    elif n8 != n9:
        e3_ok, e3_detail = False, f"NONCE_MISMATCH {n8} != {n9}"
    else:
        e3_ok, e3_detail = True, f"nonce={n8} shared by B8/B9 within run {run_id}"
    chk("E3", "B8/B9 share one nonce, re-derived from raw audit fields", e3_ok, e3_detail)

    # P3-HIGH-2, scoped remediation: B4's two negative outcomes must exist in
    # the authoritative raw audit for this run.  The sandbox's own response
    # strings are not evidence that the PEP made either decision.
    b4_denials = [e for e in scoped
                  if e.get("decision") == "BLOCKED_BY_POLICY"
                  and str(e.get("row_id", "")) == "B4"
                  and e.get("conn_id")]
    b4_sni = [e for e in b4_denials
              if str(e.get("reason", "")).startswith("SNI_MISMATCH:")]
    b4_host = [e for e in b4_denials
               if str(e.get("reason", "")).startswith("HOST_HEADER_MISMATCH:")]
    b4_nonce_ok = bool(n8) and all(str(e.get("test_nonce", "")) == n8
                                   for e in b4_sni + b4_host)
    b4_denials_ok = bool(b4_sni) and bool(b4_host) and b4_nonce_ok

    # ------------------------------------------------------------------ E4
    killed: set[str] = set()
    for e in scoped:
        if e.get("decision") == "KILL_SWITCH":
            for c in (e.get("terminated_conn_ids") or []):
                killed.add(str(c))
    b9_conns = {str(e["conn_id"]) for e in b9_recs}
    hit = b9_conns & killed
    # the B8 ALLOW must also be a genuine v6 enforcement record
    b8_valid = False
    if b8_recs:
        r = b8_recs[-1]
        b8_valid = (r.get("pin_family") == "ipv6" and is_v6(r.get("pin_ip"))
                    and all(r.get(f) for f in REQUIRED_ALLOW_FIELDS))
    e4_ok = bool(hit) and b8_valid and b4_denials_ok
    chk("E4", "exact kill conn_id, genuine v6 pin, B4 denials in raw audit", e4_ok,
        f"b9_conns={sorted(b9_conns)[:2]} killed={len(killed)} matched={sorted(hit)[:1]} "
        f"b8_pin_valid={b8_valid} b4_sni={len(b4_sni)} "
        f"b4_host={len(b4_host)} b4_nonce_ok={b4_nonce_ok}")

    # ------------------------------------------------------------------ E5
    v_reports, e5_ok = [], True
    for vp in verifiers:
        try:
            src = open(vp).read()
        except OSError:
            v_reports.append(f"{os.path.basename(vp)}:UNREADABLE")
            e5_ok = False
            continue
        code = strip_noncode(src)
        hits = [p for p in FALLBACK_PATTERNS if re.search(p, code, re.I | re.M)]
        dyn = ast_findings(src)
        base = os.path.basename(vp)
        if base == "verify_b7_evidence.py":
            strict_codes = ("NO_HOST_PACKET_ATTEMPT", "EXACT_DROP_COUNTER_NOT_ONE",
                            "MEASUREMENT_REACHED_RECEIVER", "B3_LIVENESS_NOT_PROVEN")
            constructs = ("packet_attempt", "enforcement", "receiver", "calibration")
        else:
            strict_codes = REQUIRED_STRICT_CODES
            constructs = REQUIRED_CONSTRUCTS
        missing = [c for c in strict_codes if c not in src]
        absent_constructs = [c for c in constructs if c not in code]
        has_in, on_count = ast_membership_and_count(src)
        full_digest = hashlib.sha256(src.encode()).hexdigest()
        digest = full_digest[:12]
        weak = []
        if absent_constructs:
            weak.append(f"missing_construct={absent_constructs}")
        if base != "verify_b7_evidence.py":
            if not has_in:
                weak.append("no_membership_test")
            if on_count:
                weak.append("decides_on_termination_count")
        expected_digest = expected_verifier_hashes.get(base)
        if not expected_digest:
            weak.append("verifier_not_hash_pinned")
        elif full_digest != expected_digest:
            weak.append("verifier_hash_mismatch")
        good = not hits and not dyn and not missing and not weak
        e5_ok = e5_ok and good
        v_reports.append(f"{os.path.basename(vp)}[{digest}]"
                         + ("" if good else
                            f" hits={hits} ast={dyn} missing={missing} weak={weak}"))
    chk("E5", "all verifier modules: no fallback, no dynamic exec, strict codes",
        e5_ok, " | ".join(v_reports))

    # ------------------------------------------------------------------ E6
    # PP18 re-derived HERE from raw audit. kill.json is NOT consulted.
    pp18_owners = [e for e in scoped if str(e.get("row_id", "")) == "PP18" and e.get("conn_id")]
    pp18_conns = {str(e["conn_id"]) for e in pp18_owners}
    pp18_hit = pp18_conns & killed
    if v4 is None:
        e6_ok, e6_detail = False, "no --v4 results supplied"
    else:
        v4_rows = v4.get("results") or []
        v4_all_proven = (v4.get("passed") == v4.get("total") and v4.get("total", 0) > 0
                         and all(r.get("pass") for r in v4_rows))
        e6_ok = bool(v4_all_proven and pp18_hit)
        e6_detail = (f"v4={v4.get('passed')}/{v4.get('total')} "
                     f"pp18_conn={sorted(pp18_hit)[:1] or 'NONE'} "
                     f"(re-derived from raw audit, kill.json ignored)")
    chk("E6", "IPv4 regression complete and PP18 re-derived from raw audit",
        e6_ok, e6_detail)

    # ------------------------------------------------------------------ E8
    # R-7. Binding is a control-plane act. The sandbox is never given the
    # run_id, so an artifact that arrives already carrying one self-labelled —
    # and a stamp claimed by any source other than the control plane is not a
    # binding. Both fail here rather than being tolerated.
    e8_parts, e8_ok = [], True
    for label, obj, path in (("acceptance", acc, a.acceptance),
                             ("layerb", lb, a.layerb),
                             ("v4", v4, a.v4),
                             ("b7", b7_evidence, a.b7_evidence)):
        if obj is None:
            e8_parts.append(f"{label}=ABSENT")
            e8_ok = False
            continue
        got = obj.get("run_id")
        src = obj.get("run_id_source")
        conflict = obj.get("run_id_conflict")
        problems = []
        if str(got) != run_id:
            problems.append(f"run_id={got!r}")
        if src != "control-plane":
            problems.append(f"source={src!r}")
        if conflict:
            problems.append(f"self_labelled={conflict!r}")
        if problems:
            e8_ok = False
            e8_parts.append(f"{label}:" + ",".join(problems))
        else:
            e8_parts.append(f"{label}=bound")
    chk("E8", "audited artifacts bound to THIS run_id by the control plane", e8_ok,
        " ".join(e8_parts))

    # ------------------------------------------------------------------ E9
    # Independent semantic derivation. The sandbox's B7 status/advisory is not
    # an input to derive(); only host-owned evidence and same-run B3 liveness
    # are. This deliberately remains separate from E8: binding an artifact to a
    # run does not make its contents true.
    if b7_evidence is None:
        e9_ok, e9_failures = False, ["B7_EVIDENCE_ABSENT"]
    else:
        try:
            from verify_b7_evidence import derive as derive_b7, validate_fixture_summary
            if a.fixture_mode:
                e9_ok, e9_failures = validate_fixture_summary(b7_evidence, lb, run_id)
            else:
                raw_dir = os.path.join(os.path.dirname(a.b7_evidence), "b7_raw")
                e9_ok, e9_failures = derive_b7(b7_evidence, lb, run_id, raw_dir)
        except Exception as exc:
            e9_ok, e9_failures = False, [f"E9_FAILURE:{type(exc).__name__}"]
    chk("E9", "B7 synthetic summary consistency (fixture only)" if a.fixture_mode else
        "B7 off-link UDP containment independently host-derived", e9_ok,
        "clean" if e9_ok else ",".join(e9_failures[:6]))

    # ------------------------------------------------------------------ summary
    v6_allows = [e for e in scoped
                 if e.get("decision") == "ALLOW" and e.get("pin_family") == "ipv6"]
    # Name the cause rather than leaving it to be inferred. If the PEP could not
    # open an IPv6 listener, every Layer B row fails for that ONE reason, and
    # reading them as nine independent enforcement failures is wrong.
    startups = [e for e in scoped if e.get("decision") == "STARTUP"]
    listener = (startups[-1].get("listener", "<not recorded>") if startups
                else "<no STARTUP record>")
    print(f"\n  PEP listener this run:          {listener}")
    if degraded:
        print(f"  *** LISTENER DEGRADED: {degraded[-1].get('reason')} — "
              f"{degraded[-1].get('detail')}")
        print("      Layer B CANNOT pass in this state. The Layer B rows share")
        print("      ONE cause; do not read them as separate enforcement failures.")
    print(f"  IPv6 ALLOW records in this run: {len(v6_allows)}")
    print(f"  KILL_SWITCH records in this run: "
          f"{sum(1 for e in scoped if e.get('decision') == 'KILL_SWITCH')}")
    print(f"  records total / in-run:          {len(recs)} / {len(scoped)}")

    passed = sum(1 for _, _, ok, _ in findings if ok)
    total = len(findings)
    print("\n" + "-" * 78)
    print(f"  EVIDENCE AUDIT: {passed}/{total}")
    if a.fixture_mode:
        print("  RESULT: FIXTURE_VALIDATED" if passed == total else
              "  RESULT: FIXTURE_REJECTED")
        print("  Synthetic validation cannot certify a measured run; exit 3 is not release success.")
        print("-" * 78)
        return 3 if passed == total else 1
    if passed == total:
        print("  RESULT: CERTIFIED — the gate result is supported by the raw evidence")
    else:
        print("  RESULT: NOT CERTIFIED — the gate result is NOT supported by evidence")
        print("  Do not treat this run as an IPv6 pass, regardless of the summary.")
    print("-" * 78)
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())

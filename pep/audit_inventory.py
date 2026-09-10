#!/usr/bin/env python3
"""
RUNTIME TEST INVENTORY — source of truth for an audit coverage manifest.

Why this is not a grep. A static scan of the source found 25 Layer A rows; the
suite actually emits 30. The five it missed (A11-A15) are produced by

    for tid, host in (("A11", ...), ("A12", ...), ...):
        rec("A", tid, ...)

where the identifier is a VARIABLE. An auditor enumerating tests by reading the
code produces a manifest that is internally consistent and silently short by
five — and silence reads as clean. That is the exact defect a coverage manifest
exists to prevent, reproduced one level up.

So this reports THREE views and flags any disagreement between them:

  CONTRACT  the ID sets the Evidence Auditor enforces (E2 requires EXACTLY
            these, so they are authoritative by construction)
  RUNTIME   IDs actually present in produced artifacts
  STATIC    IDs a source scan can see — shown only to expose its blind spots

Any ID in CONTRACT or RUNTIME but absent from an audit's manifest is a gap.
Usage: audit_inventory.py [artifact_dir]   (default: ./collected)
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def contract_sets() -> dict[str, list[str]]:
    """Read required and study ID sets from the auditor's own source.

    This deliberately interprets only the tiny literal/set-comprehension forms
    used for these constants; it never executes the auditor being inventoried.
    """
    src = open(os.path.join(HERE, "audit_gate_evidence.py")).read()
    out: dict[str, list[str]] = {}
    tree = ast.parse(src)
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        name = getattr(node.targets[0], "id", "")
        if name not in ("REQUIRED_A", "REQUIRED_B", "STUDY_B"):
            continue
        vals: list[str] = []
        if isinstance(node.value, ast.Set):
            vals = [e.value for e in node.value.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        elif isinstance(node.value, ast.SetComp):
            gen = node.value.generators[0]
            if (isinstance(gen.iter, ast.Call)
                    and getattr(gen.iter.func, "id", "") == "range"):
                args = [ast.literal_eval(a) for a in gen.iter.args]
                seq = range(*args)
            else:
                seq = ast.literal_eval(gen.iter)
            pref = "A" if name == "REQUIRED_A" else "B"
            vals = [f"{pref}{i}" for i in seq]
        out[name] = sorted(vals, key=lambda x: (x[:1], int(x[1:])))
    e = [n.args[0].value for n in ast.walk(tree)
         if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "chk"
         and n.args and isinstance(n.args[0], ast.Constant)]
    out["EVIDENCE_CHECKS"] = sorted(set(e))
    return out


def runtime_ids(artifact_dir: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    def ids(path, key, field="layer_a"):
        try:
            d = json.load(open(path))
        except Exception:
            return
        rows = d.get(field) or d.get("rows") or d.get("results") or []
        got = [r.get("id") for r in rows if isinstance(r, dict) and r.get("id")]
        if got:
            out[key] = got
    ids(os.path.join(artifact_dir, "ipv6_acceptance.json"), "layer_a", "layer_a")
    ids(os.path.join(artifact_dir, "ipv6_acceptance.json"), "layer_b", "layer_b")
    ids(os.path.join(artifact_dir, "ipv6_layerb.json"), "layer_b_raw")
    ids(os.path.join(artifact_dir, "pep_results.json"), "ipv4")
    return out


def static_ids() -> dict[str, list[str]]:
    pats = {"ipv6_acceptance.py": r'rec\(\s*"A",\s*"(A\d+)"',
            "ipv6_transport.py": r'rec\(\s*"(B\d+)"',
            "pep_client.py": r'rec\(\s*"(PP\d+)"'}
    out = {}
    for f, p in pats.items():
        try:
            out[f] = sorted(set(re.findall(p, open(os.path.join(HERE, f)).read())))
        except OSError:
            pass
    return out


def main() -> int:
    art = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "collected")
    con, run, sta = contract_sets(), runtime_ids(art), static_ids()

    print("=" * 76)
    print("AUDIT COVERAGE INVENTORY — source of truth for the manifest")
    print("=" * 76)

    print("\n-- CONTRACT (enforced by the Evidence Auditor; authoritative) --")
    expected: set[str] = set()
    for k, v in con.items():
        expected |= set(v)
        print(f"  {k:18} {len(v):3}  {v[0]}..{v[-1]}" if len(v) > 3
              else f"  {k:18} {len(v):3}  {' '.join(v)}")

    print(f"\n-- RUNTIME (emitted into artifacts under {os.path.basename(art)}/) --")
    if not run:
        print("  NONE — no artifacts present. Runtime inventory NOT-VERIFIED.")
        print("  An audit cannot treat the contract set as observed coverage.")
    for k, v in run.items():
        expected |= set(v)
        print(f"  {k:18} {len(v):3}  {' '.join(v[:8])}{' …' if len(v) > 8 else ''}")

    print("\n-- STATIC (what a source scan sees — shown to expose its blind spots) --")
    gaps = []
    for f, v in sta.items():
        print(f"  {f:26} {len(v):3}")
    for k, v in list(con.items()) + list(run.items()):
        flat = {i for ids in sta.values() for i in ids}
        miss = [i for i in v if i not in flat and not i.startswith("E")]
        if miss:
            gaps.append((k, miss))
    if gaps:
        print("\n  *** IDs INVISIBLE TO A STATIC SCAN ***")
        for k, miss in gaps:
            print(f"    {k}: {miss}")
        print("    An auditor enumerating tests by reading source would omit these")
        print("    and its manifest would still look internally consistent.")

    print("\n" + "=" * 76)
    print(f"  AUTHORITATIVE SET: {len(expected)} IDs")
    print("  Every one MUST appear in an audit coverage manifest with a label of")
    print("  INSPECTED / EXECUTION-VERIFIED / CODE-VERIFIED /")
    print("  ENVIRONMENT-BLOCKED / NOT-VERIFIED. Silence is not acceptance.")
    print("=" * 76)
    verifier_names = ("verify_layerb_audit.py", "verify_pp18.py",
                      "verify_b7_evidence.py")
    verifier_sha256 = {}
    for name in verifier_names:
        path = os.path.join(HERE, name)
        verifier_sha256[name] = hashlib.sha256(open(path, "rb").read()).hexdigest()
    with open(os.path.join(HERE, "audit_manifest_required.json"), "w") as fh:
        json.dump({"required_ids": sorted(expected), "contract": con,
                   "verifier_sha256": verifier_sha256,
                   "runtime": run, "static_blind_spots": dict(gaps)}, fh, indent=2)
    print(f"  written -> audit_manifest_required.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

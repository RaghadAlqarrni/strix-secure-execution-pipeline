#!/usr/bin/env python3
"""
PIPELINE-ORDER INTEGRATION TEST.

The fixture battery hands the auditor artifacts that are already in their final
shape. The real gate does not: it runs

    collect_artifacts.py -> stamp_artifacts.py -> verify_layerb_audit.py -> auditor

and each of those rewrites the layerb artifact. An ordering defect between them
is invisible to the battery, because the battery never executes the middle two.

That is not hypothetical. An earlier revision made verify_layerb_audit.py treat
the control plane's OWN stamp as a sandbox self-label, which set run_id_conflict
on every run and would have made E8 fail the gate unconditionally — on a
dual-stack host, permanently, with a message blaming the sandbox. A fully green
battery did not notice.

Scenarios:
  1. honest sandbox artifact (run_id null)              -> FIXTURE_VALIDATED, exit 3
  2. sandbox self-labelled with the CORRECT run_id      -> FIXTURE_REJECTED, exit 1
  3. sandbox self-labelled with a DIFFERENT run_id      -> FIXTURE_REJECTED, exit 1
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
SRC = os.path.join(HERE, "f00_honest")
RID = "run-honest0000000000000000000000"

RESULTS: list[tuple[str, str, str, bool]] = []


def run(scenario: str, sandbox_run_id, want: str) -> None:
    tmp = tempfile.mkdtemp()
    out, col = os.path.join(tmp, "out"), os.path.join(tmp, "collected")
    os.makedirs(out)
    os.makedirs(col)

    # what the SANDBOX writes into the shared mount
    lb = json.load(open(os.path.join(SRC, "layerb.json")))
    lb.pop("run_id_source", None)
    lb["origin"] = "sandbox"
    lb["run_id"] = sandbox_run_id
    lb["rows"] = [r for r in lb["rows"] if r["id"] not in ("B8", "B9")]
    lb["passed"], lb["total"] = len(lb["rows"]), len(lb["rows"])
    with open(os.path.join(out, "ipv6_layerb.json"), "w") as fh:
        json.dump(lb, fh)
    with open(os.path.join(out, "b6_client.json"), "w") as fh:
        json.dump({"origin": "sandbox", "run_id": None, "partial_bytes": 512,
                   "content_length": 4096, "live": True, "terminated": True}, fh)

    audit = os.path.join(tmp, "audit.jsonl")
    shutil.copyfile(os.path.join(SRC, "audit.jsonl"), audit)

    # --- the REAL gate sequence, in the REAL order --------------------------
    def py(*a):
        return subprocess.run([sys.executable, *a], capture_output=True, text=True)

    py(os.path.join(PEP, "collect_artifacts.py"), col,
       os.path.join(out, "ipv6_layerb.json"), os.path.join(out, "b6_client.json"))
    py(os.path.join(PEP, "stamp_artifacts.py"), RID,
       os.path.join(col, "ipv6_layerb.json"), os.path.join(col, "b6_client.json"))
    py(os.path.join(PEP, "verify_layerb_audit.py"), audit,
       os.path.join(col, "ipv6_layerb.json"), RID, os.path.join(col, "b6_client.json"))

    acc = json.load(open(os.path.join(SRC, "acceptance.json")))
    accp = os.path.join(col, "acceptance.json")
    with open(accp, "w") as fh:
        json.dump(acc, fh)
    v4 = json.load(open(os.path.join(SRC, "v4.json")))
    v4p = os.path.join(col, "v4.json")
    with open(v4p, "w") as fh:
        json.dump(v4, fh)
    b7p = os.path.join(col, "b7.json")
    shutil.copyfile(os.path.join(SRC, "b7.json"), b7p)

    r = py(os.path.join(PEP, "audit_gate_evidence.py"), "--fixture-mode",
           "--acceptance", accp, "--layerb", os.path.join(col, "ipv6_layerb.json"),
           "--audit", audit, "--run-id", RID, "--v4", v4p,
           "--b7-evidence", b7p)
    got = ("FIXTURE_VALIDATED" if "RESULT: FIXTURE_VALIDATED" in r.stdout else
           "FIXTURE_REJECTED" if "RESULT: FIXTURE_REJECTED" in r.stdout else "NO_VERDICT")
    rc_ok = (r.returncode == 3) if want == "FIXTURE_VALIDATED" else (r.returncode == 1)
    ok = got == want and rc_ok
    RESULTS.append((scenario, want, f"{got} rc={r.returncode}", ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {scenario:48} want={want:14} "
          f"got={got} rc={r.returncode}", flush=True)
    if not ok:
        for ln in r.stdout.splitlines():
            if ln.strip().startswith(("FAIL", "RESULT")):
                print("        " + ln.strip())
    shutil.rmtree(tmp, ignore_errors=True)


def main() -> int:
    print("PIPELINE-ORDER INTEGRATION TEST "
          "(collect -> stamp -> verify_layerb -> audit)")
    run("sandbox writes run_id: null (contract)", None, "FIXTURE_VALIDATED")
    run("sandbox self-labels with the CORRECT run_id", RID, "FIXTURE_REJECTED")
    run("sandbox self-labels with a DIFFERENT run_id", "run-STOLEN", "FIXTURE_REJECTED")
    ok = sum(1 for *_, g in RESULTS if g)
    print(f"\n  PIPELINE ORDER: {ok}/{len(RESULTS)}")
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())

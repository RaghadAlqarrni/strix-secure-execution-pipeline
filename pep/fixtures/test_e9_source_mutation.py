#!/usr/bin/env python3
"""E5 must reject an E9 oracle mutation even when its required words remain."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
F = os.path.join(HERE, "f00_honest")
RID = "run-honest0000000000000000000000"


def main() -> int:
    td = tempfile.mkdtemp()
    mutated = os.path.join(td, "verify_b7_evidence.py")
    src = open(os.path.join(PEP, "verify_b7_evidence.py"), encoding="utf-8").read()
    old = "return not failures, failures"
    if old not in src:
        print("  FAIL  mutation anchor absent")
        return 1
    # Rubber-stamp mutation: all required codes/construct names remain, so only
    # the integrity binding (not keyword inspection) can detect it.
    open(mutated, "w", encoding="utf-8").write(src.replace(old, "return True, failures", 1))
    cmd = [sys.executable, os.path.join(PEP, "audit_gate_evidence.py"),
           "--fixture-mode",
           "--acceptance", os.path.join(F, "acceptance.json"),
           "--layerb", os.path.join(F, "layerb.json"),
           "--audit", os.path.join(F, "audit.jsonl"), "--run-id", RID,
           "--v4", os.path.join(F, "v4.json"), "--b7-evidence", os.path.join(F, "b7.json"),
           "--verifier", os.path.join(PEP, "verify_layerb_audit.py"),
           "--verifier", os.path.join(PEP, "verify_pp18.py"),
           "--verifier", mutated]
    r = subprocess.run(cmd, capture_output=True, text=True)
    ok = r.returncode != 0 and "verifier_hash_mismatch" in r.stdout
    print(f"  {'PASS' if ok else 'FAIL'}  E9 all→oracle mutation rejected by hash binding")
    shutil.rmtree(td, ignore_errors=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

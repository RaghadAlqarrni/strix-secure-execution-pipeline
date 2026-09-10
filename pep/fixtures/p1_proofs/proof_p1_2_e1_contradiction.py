#!/usr/bin/env python3
"""
P1-2 PROOF -- E1 now rejects a row whose status and pass fields disagree
(P3-CRIT-2 / TRIAGE_UNIFIED.md; independently re-confirmed by Pass 4 as D-3).

THE DEFECT
  status and pass are two views of the SAME fact -- rec() in
  ipv6_acceptance.py / ipv6_transport.py sets both from one `ok` at
  construction. But audit_gate_evidence.py reads a JSON blob off disk, which
  gives no guarantee that blob came from rec(): a hand-edited fixture, a
  future/alternate construction path, or corruption could produce
  status=="PROVEN" with pass=False. The old E1 read status only, so such a
  row was certified.

FIXTURE
  fixtures/f22_contradictory_row: honest evidence with exactly one change --
  required row A10's pass forced to False while its status stays "PROVEN".
  Isolation already confirmed by hand: of E1..E8, f22 fails ONLY E1 -- so any
  FIXTURE_REJECTED result on this fixture is attributable to E1's own logic, not
  a side effect of some other check.

THIS PROOF, IN TWO PARTS
  1. Confirm on the REAL file (read-only) that f22 is FIXTURE_REJECTED today,
     failing E1 specifically, and that f00_honest (unmodified) still
     CERTIFIES -- so the fix does not merely reject everything.
  2. NEGATIVE CONTROL: revert E1 to its pre-fix shape (status-only) on a
     DISPOSABLE COPY -- the real audit_gate_evidence.py is never touched --
     and show that shape WOULD have certified f22. If it does not, this
     fixture does not actually exercise the defect and part 1's PASS is
     void.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
FIXTURES = os.path.join(PEP, "fixtures")
RID = "run-honest0000000000000000000000"

# The exact pre-fix E1 body (from git history / PASS4_REPORT.md's own quote
# of it) -- reads status only, never pass.
OLD_E1 = '''    a_rows = acc.get("layer_a") or []
    b_rows = lb.get("rows") or []
    required_rows = [r for r in a_rows if r.get("id") in REQUIRED_A] + \\
                    [r for r in b_rows if r.get("id") in REQUIRED_B]
    not_proven = [f"{r.get('id')}={r.get('status', r.get('got', 'MISSING'))}"
                  for r in required_rows if str(r.get("status")) != "PROVEN"]
    have_a = {r.get("id") for r in a_rows}
    have_b = {r.get("id") for r in b_rows}
    absent = sorted((REQUIRED_A - have_a) | (REQUIRED_B - have_b))
    e1_ok = not not_proven and not absent
    chk("E1", "every required row has status == PROVEN (strict whitelist)", e1_ok,
        "clean" if e1_ok else f"not_proven={not_proven[:5]} missing={absent[:5]}")
'''


def _run(auditor_path: str, fixture_dir: str) -> tuple[int, str]:
    d = fixture_dir
    r = subprocess.run(
        [sys.executable, auditor_path, "--fixture-mode",
         "--acceptance", os.path.join(d, "acceptance.json"),
         "--layerb", os.path.join(d, "layerb.json"),
         "--audit", os.path.join(d, "audit.jsonl"),
         "--run-id", RID,
         "--v4", os.path.join(d, "v4.json"),
         "--b7-evidence", os.path.join(d, "b7.json")],
        capture_output=True, text=True, timeout=60,
    )
    return r.returncode, r.stdout + r.stderr


def part1_real_file() -> bool:
    real = os.path.join(PEP, "audit_gate_evidence.py")
    fp_before = hashlib.sha256(open(real, "rb").read()).hexdigest()

    rc22, out22 = _run(real, os.path.join(FIXTURES, "f22_contradictory_row"))
    e1_line = next((ln for ln in out22.splitlines() if " E1 " in ln), "<no E1 line>")
    f22_ok = rc22 == 1 and "FAIL  E1" in out22 and "A10=status:PROVEN" in out22

    rc00, out00 = _run(real, os.path.join(FIXTURES, "f00_honest"))
    f00_ok = rc00 == 3 and "RESULT: FIXTURE_VALIDATED" in out00

    fp_after = hashlib.sha256(open(real, "rb").read()).hexdigest()
    untouched = fp_before == fp_after

    print("  PART 1 -- real audit_gate_evidence.py, read-only")
    print(f"    f22_contradictory_row: exit={rc22}  {e1_line.strip()}")
    print(f"    {'PASS' if f22_ok else 'FAIL'} -- must be FIXTURE_REJECTED, failing E1, naming A10")
    print(f"    f00_honest:             exit={rc00}  "
          f"{'FIXTURE_VALIDATED' if f00_ok else 'FIXTURE_REJECTED'}")
    print(f"    {'PASS' if f00_ok else 'FAIL'} -- the fix must not certify-reject everything")
    print(f"    real file byte-identical before/after: {untouched}")
    return f22_ok and f00_ok and untouched


def part2_negative_control() -> bool:
    real = os.path.join(PEP, "audit_gate_evidence.py")
    src = open(real, encoding="utf-8").read()

    marker_start = '    # ------------------------------------------------------------------ E1\n'
    marker_end = '\n    # ------------------------------------------------------------------ E2\n'
    start = src.index(marker_start)
    end = src.index(marker_end, start)
    # Keep everything up to and including the comment header, splice in the
    # OLD body, keep everything from E2 onward untouched.
    header_end = src.index("\n", start) + 1
    while src[header_end:header_end + 5] == "    #":
        header_end = src.index("\n", header_end) + 1
    patched = src[:header_end] + OLD_E1 + src[end + 1:]

    if patched == src:
        print("  PART 2 -- ABORT: splice produced no change (anchor did not match)")
        return False

    with tempfile.TemporaryDirectory(prefix="p1_2_negctrl_") as tmp:
        # Copy the WHOLE pep/ tree, not just this one file: E5 resolves
        # verify_layerb_audit.py / verify_pp18.py relative to __file__'s own
        # directory, so a bare single-file copy makes E5 report those
        # sibling verifiers UNREADABLE -- a failure that comes from this
        # harness's file layout, not from the OLD E1 logic under test, and
        # would corrupt the very thing this control is trying to isolate.
        work = os.path.join(tmp, "pep")
        shutil.copytree(PEP, work, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        copy_path = os.path.join(work, "audit_gate_evidence.py")
        with open(copy_path, "w", encoding="utf-8") as fh:
            fh.write(patched)

        rc, out = _run(copy_path, os.path.join(work, "fixtures", "f22_contradictory_row"))
        e1_line = next((ln for ln in out.splitlines() if " E1 " in ln), "<no E1 line>")
        old_certified_it = rc == 3 and "RESULT: FIXTURE_VALIDATED" in out

    print("  PART 2 -- NEGATIVE CONTROL: pre-fix E1 (status-only) on a disposable copy")
    print(f"    f22_contradictory_row against OLD E1: exit={rc}  {e1_line.strip()}")
    print(f"    {'PASS' if old_certified_it else 'FAIL'} -- the OLD shape MUST wrongly "
          f"certify this fixture, or f22 does not exercise P3-CRIT-2")
    return old_certified_it


if __name__ == "__main__":
    print("-- P1-2: E1 status/pass self-contradiction (P3-CRIT-2 / D-3) --\n")
    p1 = part1_real_file()
    print()
    p2 = part2_negative_control()
    ok = p1 and p2
    print()
    print(f"  P1-2: {'PASS' if ok else 'FAIL'}   (fix_holds={p1}, control_fired={p2})")
    sys.exit(0 if ok else 1)

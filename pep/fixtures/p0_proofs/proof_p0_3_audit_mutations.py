#!/usr/bin/env python3
"""
P0-3 PROOF -- the audit-log suite actually detects regressions in audit.py.

WHY THIS EXISTS
  Pass 3 established that a passing test suite is not evidence a module is
  protected. Before fixtures/test_audit_log.py existed, audit.py was imported
  by no suite at all: five separate weakenings of the write path -- including
  deleting the hash chain outright -- left all four suites green. A suite that
  cannot fail on a broken module tells you nothing when it passes.

  Mutation testing is the only reliable way to answer "would this suite have
  caught it?", so it is run as a standing proof rather than a one-off.

READ-ONLY DISCIPLINE
  audit.py is NEVER modified. Each mutant is written into a disposable copy
  of the package under a temp dir, and the suite is executed against that
  copy in a subprocess. The real tree is verified byte-identical at the end;
  if it is not, this script reports FAIL regardless of the mutation results.
  Bounded default mode runs the current audit suite against every mutant; use
  --full-prior to repeat the historical pre-P0-3 battery for each mutant. The
  repository's current full battery remains a separate mandatory command.

PASS CONDITION
  Every mutant must be CAUGHT (the suite must exit non-zero).
  A SURVIVING mutant is a hole in the suite, reported as such.
  The unmutated copy must also still PASS -- otherwise "caught" would just
  mean the harness is broken and every mutant would look detected.
"""

import concurrent.futures
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(os.path.dirname(HERE))
ROOT = os.path.dirname(PEP)

# (id, description, exact source text to replace, replacement)
MUTANTS = [
    ("M13", "fsync removed (a crash can lose an already-reported record)",
     "                self._write_all(fd, line + b\"\\n\")\n                os.fsync(fd)",
     "                self._write_all(fd, line + b\"\\n\")\n                pass  # MUTANT: per-record fsync removed"),

    ("M14", "hash chain deleted (every record claims prev = GENESIS)",
     '            rec["prev"] = self._prev',
     '            rec["prev"] = self.GENESIS  # MUTANT: chain deleted'),

    ("M15", "write lock removed (concurrent writers can interleave the chain)",
     "        with self._lock:\n            if self._sealed:\n                raise RuntimeError(\"AUDIT_LOG_SEALED: final RUN_CLOSED already fsynced\")",
     "        if True:  # MUTANT: write lock removed\n            if self._sealed:\n                raise RuntimeError(\"AUDIT_LOG_SEALED: final RUN_CLOSED already fsynced\")"),

    ("M16", "redaction removed (secrets reach the log verbatim)",
     "                    out = out.replace(s, \"«REDACTED»\")",
     "                    pass  # MUTANT: redaction removed"),

    ("M17", "caller can override run_id (control-plane anchor becomes forgeable)",
     '            rec["run_id"] = self._run_id',
     '            rec.setdefault("run_id", self._run_id)  # MUTANT: caller wins'),
]


def _tree_fingerprint() -> str:
    import hashlib
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(PEP):
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        for fn in sorted(filenames):
            if fn.endswith(".pyc"):
                continue
            p = os.path.join(dirpath, fn)
            h.update(os.path.relpath(p, PEP).encode())
            with open(p, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


def run_suite(pkg_root: str) -> tuple[int, str]:
    """The new audit-log suite alone."""
    r = subprocess.run(
        [sys.executable, os.path.join(pkg_root, "pep", "fixtures", "test_audit_log.py")],
        capture_output=True, text=True, timeout=300,
    )
    return r.returncode, (r.stdout + r.stderr)


def run_prior_suites(pkg_root: str) -> tuple[int, str]:
    """The four suites that existed BEFORE test_audit_log.py.

    The audit-log stage is stubbed out on the disposable copy so the battery
    reproduces the pre-P0-3 coverage exactly. If these stay green on a mutant,
    that mutant was genuinely invisible before this work -- which is what makes
    the new suite's catch a real gain rather than a duplicated check.
    """
    stub = os.path.join(pkg_root, "pep", "fixtures", "test_audit_log.py")
    with open(stub, "w", encoding="utf-8") as fh:
        fh.write("import sys; sys.exit(0)  # stubbed: pre-P0-3 coverage\n")
    r = subprocess.run(
        ["bash", os.path.join(pkg_root, "pep", "fixtures", "run_fixtures.sh")],
        capture_output=True, text=True, timeout=900,
        cwd=os.path.join(pkg_root, "pep"),
    )
    return r.returncode, (r.stdout + r.stderr)


def main() -> int:
    full_prior = "--full-prior" in sys.argv[1:]
    before = _tree_fingerprint()
    results = []
    prior_results = []

    with tempfile.TemporaryDirectory(prefix="p0_3_mut_") as tmp:
        pristine = os.path.join(tmp, "pristine")
        shutil.copytree(PEP, os.path.join(pristine, "pep"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))

        print("-- baseline: the suite must PASS on an unmutated copy --")
        rc, _ = run_suite(pristine)
        baseline_ok = rc == 0
        print(f"   unmutated copy: {'PASS' if baseline_ok else 'FAIL'} (exit={rc})")
        if not baseline_ok:
            print("   ABORT -- with a broken baseline, every mutant would look 'caught'")
            return 1

        src_path = os.path.join(pristine, "pep", "audit.py")
        with open(src_path, encoding="utf-8") as fh:
            original = fh.read()

        print()
        print("-- mutation testing audit.py (real file untouched; copies only) --")

        def exercise_mutant(spec):
            mid, desc, old, new = spec
            occurrences = original.count(old)
            if occurrences != 1:
                return mid, desc, None, None, occurrences
            work = os.path.join(tmp, mid)
            shutil.copytree(os.path.join(pristine, "pep"), os.path.join(work, "pep"),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            with open(os.path.join(work, "pep", "audit.py"), "w", encoding="utf-8") as fh:
                fh.write(original.replace(old, new, 1))
            rc, _ = run_suite(work)
            caught = rc != 0
            prior = os.path.join(tmp, mid + "_prior")
            shutil.copytree(os.path.join(work, "pep"), os.path.join(prior, "pep"),
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            if full_prior:
                prc, _ = run_prior_suites(prior)
                missed_before = prc == 0
            else:
                missed_before = None
            return mid, desc, caught, missed_before, occurrences

        # The five disposable mutants are independent. Running them together
        # keeps this standing proof below bounded CI/agent command timeouts.
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(MUTANTS)) as pool:
            outcomes = list(pool.map(exercise_mutant, MUTANTS))
        for mid, desc, caught, missed_before, occurrences in outcomes:
            if caught is None:
                print(f"   {'ERROR':8} {mid} anchor matched {occurrences}x -- "
                      f"cannot apply this mutation unambiguously")
                results.append((mid, desc, None))
                continue
            results.append((mid, desc, caught))
            prior_results.append((mid, missed_before))
            print(f"   {'CAUGHT' if caught else 'SURVIVED':8} {mid}  {desc}")
            prior_label = ("NOT_RUN (use --full-prior; current full battery runs separately)"
                           if missed_before is None else
                           ("GREEN -- undetected" if missed_before else "RED -- already covered"))
            print(f"   {'':8} pre-P0-3 four-suite battery on this mutant: {prior_label}")

    after = _tree_fingerprint()
    intact = before == after

    print()
    caught_n = sum(1 for _, _, c in results if c is True)
    total = len(results)
    print(f"   caught {caught_n} of {total} mutants")
    print(f"   audit target byte-identical after the run: {intact}")
    if not intact:
        print("   FAIL -- the proof mutated the tree it was auditing")
        return 1

    measured_prior = [(mid, value) for mid, value in prior_results
                      if value is not None]
    if measured_prior:
        missed = sum(1 for _, value in measured_prior if value)
        print(f"   of those, invisible to the pre-P0-3 battery: "
              f"{missed} of {len(measured_prior)}")
    else:
        print("   pre-P0-3 repeated mutant battery: NOT_RUN in bounded mode")

    survivors = [(m, d) for m, d, c in results if c is False]
    errors = [(m, d) for m, d, c in results if c is None]
    for m, d in survivors:
        print(f"   HOLE: {m} survived -- the suite does not detect: {d}")
    for m, d in errors:
        print(f"   HOLE: {m} could not be applied -- coverage UNKNOWN for: {d}")

    ok = caught_n == total and intact
    print()
    print(f"  P0-3: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
CONTROL-PLANE ARTIFACT STAMPER (R-7).

Binding an artifact to an execution is a CONTROL-PLANE act. Before this module
existed, two of the artifacts (pep_results.json, ipv6_layerb.json) wrote their
own run_id from an environment variable the gate had handed to the SANDBOX —
so the "binding" was a value the measured party chose for itself, and the
docstrings claiming run_id was "never transmitted to the sandbox" were false.

Now:
  * the sandbox is not given PEP_RUN_ID at all and writes run_id = null,
  * this tool — running host-side, after collection — writes the real run_id
    together with run_id_source="control-plane",
  * the Evidence Auditor (E8) refuses any artifact whose run_id does not match
    the run_id it was itself invoked with, or that is not control-plane stamped.

An artifact that arrives already bearing a run_id was self-labelled by the
party under test. That is not binding; it is a claim. It fails E8.

Usage: stamp_artifacts.py <run_id> <artifact.json> [<artifact.json> ...]
Exit 0 only if every named artifact was stamped.
"""
from __future__ import annotations

import json
import sys


def stamp(path: str, run_id: str) -> str:
    with open(path) as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("artifact is not a JSON object")
    prior = data.get("run_id")
    if prior not in (None, ""):
        # ANY pre-existing run_id is a finding, including one that happens to
        # match: sandbox artifacts are contractually null here, so a populated
        # field means the measured party labelled itself. Accepting a matching
        # value would reward exactly the adversary who learned the run_id.
        data["run_id_conflict"] = str(prior)
    data["run_id"] = run_id
    data["run_id_source"] = "control-plane"
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)
    return "CONFLICT" if "run_id_conflict" in data else "ok"


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: stamp_artifacts.py <run_id> <artifact.json> ...", file=sys.stderr)
        return 2
    run_id, paths = sys.argv[1], sys.argv[2:]
    if not run_id:
        print("  FAIL  stamp: empty run_id", flush=True)
        return 1
    rc = 0
    for p in paths:
        try:
            st = stamp(p, run_id)
        except Exception as exc:
            print(f"  FAIL  stamp {p}: {type(exc).__name__}: {exc}", flush=True)
            rc = 1
            continue
        print(f"  {'WARN' if st == 'CONFLICT' else 'ok  '}  stamped {p} "
              f"run_id={run_id}" + ("  (artifact carried its own run_id!)"
                                    if st == "CONFLICT" else ""), flush=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

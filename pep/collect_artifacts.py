#!/usr/bin/env python3
"""
CONTROL-PLANE ARTIFACT COLLECTOR.

Copies sandbox-written artifacts OUT of the read-write bind mount the sandbox
shares with the host, into a directory the sandbox cannot reach, so that
stamping, verification and auditing all happen on material the measured party
can no longer touch.

Why this is not `cp`. `cp -f "$OUT/x.json" "$COL/"` runs as root on the host and
DEREFERENCES symlinks: a sandbox that replaces its own output file with a
symlink to an arbitrary host path makes the host read that path on its behalf.
This collector refuses anything that is not a regular, non-symlink file, and
refuses anything that does not parse as a JSON object — failing the run rather
than importing whatever it was handed.

Usage: collect_artifacts.py <dest_dir> <src.json> [<src.json> ...]
Exit 0 only if every named source was collected.
"""
from __future__ import annotations

import json
import os
import shutil
import sys


def collect(src: str, dest_dir: str) -> str:
    if os.path.islink(src):
        return "REFUSED: symlink"
    if not os.path.exists(src):
        return "MISSING"
    st = os.lstat(src)
    if not os.path.isfile(src) or st.st_nlink != 1:
        return f"REFUSED: not a regular single-linked file (nlink={st.st_nlink})"
    try:
        with open(src) as fh:
            if not isinstance(json.load(fh), dict):
                return "REFUSED: not a JSON object"
    except ValueError as exc:
        return f"REFUSED: unparseable JSON ({exc.__class__.__name__})"
    dst = os.path.join(dest_dir, os.path.basename(src))
    shutil.copyfile(src, dst, follow_symlinks=False)
    return "ok"


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: collect_artifacts.py <dest_dir> <src.json> ...", file=sys.stderr)
        return 2
    dest_dir, srcs = sys.argv[1], sys.argv[2:]
    os.makedirs(dest_dir, exist_ok=True)
    rc = 0
    for s in srcs:
        res = collect(s, dest_dir)
        if res != "ok":
            rc = 1
        print(f"  {'ok  ' if res == 'ok' else 'FAIL'}  collect {os.path.basename(s)}"
              + ("" if res == "ok" else f": {res}"), flush=True)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

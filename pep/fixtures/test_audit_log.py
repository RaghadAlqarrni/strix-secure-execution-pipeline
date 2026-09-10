#!/usr/bin/env python3
"""
AUDIT LOG SELF-TEST — the module at the root of the authority hierarchy had
zero coverage.

Why this exists. An independent audit applied five weakenings to the shipped
`audit.py` — deleting the hash chain, the write lock, the `fsync`, the secret
redaction, and the `run_id` stamping — and every one survived all four suites
green. No suite imported the module at all, and `make_fixtures.py` does not call
it: it re-implements `AuditLog.write`'s serialisation as an INDEPENDENT COPY.
So if `write()` changed its field order, separators or `prev` semantics
tomorrow, every fixture would keep passing against the old format and E7 would
keep certifying.

`RAW AUDIT` sits at the top of the authority hierarchy — above the auditor,
above the verifiers, above every summary. A root of trust that can be silently
gutted makes everything above it decorative.

This suite EXECUTES the real module. That property is not incidental: the audit
found that detection concentrated almost entirely in the one suite that executes
the code it checks.

Exit 0 only if every property holds.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(PEP))

from pep.audit import AuditLog                                    # noqa: E402

R: list[tuple[str, str, str, bool]] = []


def check(name: str, got, want) -> None:
    got, want = str(got), str(want)
    ok = got == want
    R.append((name, want, got, ok))
    print(f"  {'PASS' if ok else 'FAIL'}  {name:58} want={want:24} got={got}",
          flush=True)


def lines(p: str) -> list[dict]:
    return [json.loads(l) for l in open(p) if l.strip()]


def main() -> int:
    print("AUDIT LOG SELF-TEST — executing the real module\n")
    tmp = tempfile.mkdtemp()

    # ---- the hash chain must be REAL -------------------------------------
    print("-- hash chain --")
    p = os.path.join(tmp, "chain.jsonl")
    a = AuditLog(p, run_id="run-selftest")
    for i in range(5):
        a.write({"decision": "ALLOW", "i": i})
    check("a freshly written log verifies", AuditLog.verify(p)[0], True)

    recs = lines(p)
    check("first record anchors to GENESIS", recs[0]["prev"], AuditLog.GENESIS)
    # each prev must be the sha256 of the PRECEDING line, recomputed here
    raw = [l.strip() for l in open(p, "rb") if l.strip()]
    ok_links = all(
        json.loads(raw[i])["prev"] == hashlib.sha256(raw[i - 1]).hexdigest()
        for i in range(1, len(raw)))
    check("every prev is sha256 of the preceding line", ok_links, True)

    # tamper with a middle record -> must break
    p2 = os.path.join(tmp, "tampered.jsonl")
    with open(p2, "wb") as fh:
        for i, l in enumerate(raw):
            if i == 2:
                r = json.loads(l); r["decision"] = "TAMPERED"
                l = json.dumps(r, sort_keys=True, separators=(",", ":")).encode()
            fh.write(l + b"\n")
    check("an edited middle record breaks the chain", AuditLog.verify(p2)[0], False)

    # delete a record -> must break
    p3 = os.path.join(tmp, "deleted.jsonl")
    with open(p3, "wb") as fh:
        for i, l in enumerate(raw):
            if i != 2:
                fh.write(l + b"\n")
    check("a deleted record breaks the chain", AuditLog.verify(p3)[0], False)

    # ---- run_id is CONTROL-PLANE, not caller-supplied --------------------
    print("\n-- run_id anchoring --")
    check("run_id is stamped on every record",
          all(r.get("run_id") == "run-selftest" for r in recs), True)
    a.write({"decision": "ALLOW", "run_id": "run-FORGED-BY-CALLER"})
    check("a caller CANNOT override run_id", lines(p)[-1]["run_id"], "run-selftest")
    b = AuditLog(os.path.join(tmp, "norun.jsonl"))
    b.write({"decision": "X"})
    check("absent run_id is empty, never omitted",
          lines(os.path.join(tmp, "norun.jsonl"))[-1].get("run_id"), "")

    # ---- secrets never reach the log -------------------------------------
    print("\n-- redaction --")
    p4 = os.path.join(tmp, "secret.jsonl")
    c = AuditLog(p4, redact={"S3CRET-TOKEN"}, run_id="r")
    c.write({"decision": "ALLOW", "hdr": "Authorization: Bearer S3CRET-TOKEN"})
    c.add_secret("LATER-SECRET")
    c.write({"decision": "ALLOW", "nested": {"deep": ["x", "LATER-SECRET"]}})
    body = open(p4).read()
    check("a known secret never appears in the file", "S3CRET-TOKEN" in body, False)
    check("a secret added later is also scrubbed", "LATER-SECRET" in body, False)
    # Assert on the PARSED record, not raw bytes: json.dumps escapes non-ASCII,
    # so the marker is written as \u00abREDACTED\u00bb. Checking the raw text
    # for "«REDACTED»" fails even though redaction worked perfectly — a test
    # defect that would have looked like a redaction defect.
    nested = lines(p4)[-1]["nested"]["deep"]
    check("redaction reaches nested lists/dicts", "«REDACTED»" in nested, True)
    check("the scrubbed value replaced the secret, not the whole field",
          lines(p4)[0]["hdr"], "Authorization: Bearer «REDACTED»")

    # ---- durability ------------------------------------------------------
    print("\n-- durability --")
    import os as _os
    real_fsync, calls = _os.fsync, []
    _os.fsync = lambda fd: (calls.append(fd), real_fsync(fd))[1]
    try:
        d = AuditLog(os.path.join(tmp, "sync.jsonl"), run_id="r")
        startup_syncs = len(calls)
        d.write({"decision": "ALLOW"})
        d.write({"decision": "ALLOW"})
        record_syncs = len(calls) - startup_syncs
    finally:
        _os.fsync = real_fsync
    check("new log syncs file and parent directory", startup_syncs, 2)
    check("fsync is called once per record", record_syncs, 2)

    # ---- concurrency: the lock is load-bearing ---------------------------
    print("\n-- concurrent writers --")
    p5 = os.path.join(tmp, "conc.jsonl")
    e = AuditLog(p5, run_id="r")
    def hammer(n):
        for i in range(n):
            e.write({"decision": "ALLOW", "t": threading.get_ident(), "i": i})
    ts = [threading.Thread(target=hammer, args=(120,)) for _ in range(8)]
    for t in ts: t.start()
    for t in ts: t.join()
    intact, detail = AuditLog.verify(p5)
    check("960 records from 8 threads keep the chain intact", intact, True)
    check("no record was lost", len(lines(p5)), 960)

    # ---- torn write recovery --------------------------------------------
    print("\n-- torn-write recovery --")
    p6 = os.path.join(tmp, "torn.jsonl")
    f = AuditLog(p6, run_id="r")
    f.write({"decision": "ALLOW", "n": 1})
    with open(p6, "ab") as fh:
        fh.write(b'{"partial": tru')          # crash mid-write, no newline
    before_torn = open(p6, "rb").read()
    g = AuditLog(p6, run_id="r")               # restart
    refused = False
    try:
        g.write({"decision": "ALLOW", "n": 2})
    except RuntimeError:
        refused = True
    check("a torn tail is not rewritten", open(p6, "rb").read(), before_torn)
    check("verify() reports the torn line rather than hiding it",
          AuditLog.verify(p6)[0], False)
    check("restart latches a torn chain unhealthy", g.healthy(), False)
    check("restart refuses to append after a torn chain", refused, True)

    # ---- append-only -----------------------------------------------------
    print("\n-- append-only --")
    p7 = os.path.join(tmp, "append.jsonl")
    h = AuditLog(p7, run_id="r")
    h.write({"decision": "ALLOW", "n": 1})
    first = open(p7, "rb").read()
    h.write({"decision": "ALLOW", "n": 2})
    check("earlier bytes are never rewritten",
          open(p7, "rb").read().startswith(first), True)

    ok = sum(1 for *_, g_ in R if g_)
    print(f"\n  AUDIT LOG SELF-TEST: {ok}/{len(R)}")
    return 0 if ok == len(R) else 1


if __name__ == "__main__":
    raise SystemExit(main())

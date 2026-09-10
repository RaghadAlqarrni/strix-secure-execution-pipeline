# Security Audit — Pass 3 of 3: Evidence Model / Layer A / Test Architecture

**24 findings: 4 CRITICAL · 8 HIGH · 8 MEDIUM · 4 LOW.**
**36 mutations executed. 20 security-relevant weakenings survived ALL FOUR suites undetected.**

```
AUDIT_INTEGRITY = VERIFIED   e5ef9f8098c3717b… start = end, target never written.
LIVE_EXECUTION  = NONE       AF_INET6 EAFNOSUPPORT; dockerd unreachable.
```

---

## CRITICAL

### CRIT-1 — The evidence model has never certified a real run, and by construction cannot

Two independent structural blocks:

* `ipv6_transport.py:452-457` — **no branch assigns `PROVEN` to `b7`.** `B7 ∈ REQUIRED_B`, and E1 demands `status == "PROVEN"` for every required row. **E1 can never pass.**
* `phase2b/target_https.py:105` — targets bind `AF_INET` only, so **no `ALLOW` record with `pin_family == "ipv6"` can ever be written.** E3 fails (`b8_records=0`), E4 fails (`b8_valid=False`).

**Every `RESULT: CERTIFIED` that exists was produced against `fixtures/f00_honest/` — an evidence set fabricated by `make_fixtures.py`. The eight E-checks have zero observations from a real execution.**

E1 also has no category for "the harness declined to assert this row." B7's honest `NOT_PROVABLE_IN_TOPOLOGY` and a genuine enforcement failure surface identically. An operator cannot distinguish "the boundary leaked" from "the harness said it could not tell."

### CRIT-2 — E1 certifies a self-contradictory row

`ipv6_acceptance.py` writes four encodings of one fact: `expect`, `got`, `status`, `pass`. `audit_gate_evidence.py:230` reads **only `status`**, never asserting `status=="PROVEN" ⇒ (pass and expect==got)` — though all four sit in the row it is holding. Executed:

```
FAIL  A29  link-local stays denied even if listed as exempt   expect=DENY  got=ALLOW
layer_a_passed/total = 30 / 30      rows with pass=False: ['A29','A30']
PASS  E1 ...   PASS  E2 ...   RESULT: CERTIFIED
```

The artifact records the failure **and** is certified.

### CRIT-3 — Twenty weakenings survive all four suites

36 mutations, each followed by a full `run_fixtures.sh`. **15 detected, 21 survived (20 security-relevant).** Selected:

| Weakening | Detected |
|---|---|
| `rec()` emits `status:"PROVEN"` unconditionally — **Layer A can never fail** | **none** |
| Layer B reports `PROVEN` instead of `BLOCKED_ENV` when there is no IPv6 stack | **none** |
| missing Layer B file reports `PROVEN` instead of `NOT_RUN` | **none** |
| `denied_by()` returns DENY for any denial — attribution removed from A11-A24 | **none** |
| `classify()` stops recognising loopback / link-local | **none** |
| E1 whitelists on `pass` instead of `status` — the exact regression E1 exists to prevent | **none** |
| E4 conn_id membership → "any kill event counts" (= fixtures f14/f15) | **none** |
| **`audit.py` writes `prev = GENESIS` — hash chain deleted** | **none** |
| **`audit.py` write lock removed · fsync removed · redaction removed** | **none** |
| **`audit.py` lets the caller override `run_id` — the anchor becomes forgeable** | **none** |
| `collect_artifacts.py` symlink refusal removed | **none** |

The `BLOCKED_ENV → PROVEN` mutation prints, verbatim, on this IPv6-less host:

```
Layer B (transport):    9/9   [no /proc/net/if_inet6 (IPv6 stack not initialized)]
IPv6 GATE: PASSED
```

— the exact outcome the docstring says it exists to prevent, with all four suites green.

**Two structural root causes:**
1. **No suite executes `ipv6_acceptance.py`, `audit.py`, or `audit_inventory.py`.** `make_fixtures.py` *synthesises* thirty `{"id":"A…","status":"PROVEN"}` dicts instead of producing them.
2. **The battery asserts only the aggregate verdict** — it greps for `RESULT: CERTIFIED` and never asserts *which* check fired. Every fixture trips ≥2 checks, so one of each pair is freely removable.

### CRIT-4 — `audit.py` has zero coverage; the fixture generator forges the chain rather than calling it

No suite imports `audit.py`. `make_fixtures.py:37-46` re-implements serialisation "exactly the way `AuditLog.write` does" as an **independent copy** — if `AuditLog.write` changed format tomorrow, every fixture would keep passing against the old one and E7 would keep certifying.

---

## HIGH

**H1 — The audit chain is unkeyed: forged records append cleanly.** `prev` is a plain SHA-256 with no key, MAC or signature. Executed: appending a forged `KILL_SWITCH` gives `chain intact`. It detects in-place edits of a log you already hold; it provides **no provenance**. `make_fixtures.py` is a working forger. Mitigation is topological only (`$CTRL` unmounted) — a Pass-2 property, not a property of `audit.py`.

**H2 — E1-E8 never examine a single denial record.** *(answers P2-C3)* `_deny()` and `_deny_tls()` carry no `conn_id` — **and the omission is not structural**: `state.conn_id` is in scope at the call site. The decisions E1-E8 touch are `ALLOW`, `KILL_SWITCH`, `STARTUP`, `STARTUP_DEGRADED`, row-labelled `CONNECTION_TERMINATED`. `BLOCKED_BY_POLICY` appears nowhere in the auditor.

> **The "check on the checker" audits only the permissive path and the termination path. The entire blocking surface — every row whose title contains "blocked" or "denied" — is self-reported by the measured party with zero independent re-derivation.**

Reason-string matching is accepted *transitively*: E1 whitelists a `status` produced by `denied_by()`/`blocked_by()` prefix matching, without ever seeing the string.

**H3 — Kill-switch snapshot proves registry presence, not causation.** `terminate_all()` returns the *snapshot*, taken under lock; `close_all()` runs outside it. A connection that completed naturally in that window is still listed. The kill is registry-wide, so membership proves only **liveness at kill time**. And `row_id`/`test_nonce` are **chosen by the measured party** — the sandbox selects which live connection wears the `B6`/`PP18` label. `verify_layerb_audit.py:116` selects B9 owners with **no `decision` filter**. The row titles assert causation; the evidence establishes co-occurrence.

**H4 — E5 is defeated by a trailing comment.** `strip_noncode()` removes only *full-line* comments; `REQUIRED_STRICT_CODES` is tested against raw source, so a docstring mention suffices; `has_in` is satisfied by any `ast.In` anywhere. A verifier gutted to `killed.add("*")  # was: …membership` passes E5 and certifies a kill of a totally unrelated connection. **Only `test_verifiers.py` — which executes the verifier — catches it.**

**H5 — E8's control-plane check cannot fail for 2 of its 3 artifacts.** `ipv6_acceptance.py` emits `"run_id_source": "control-plane"` as a **literal**; `verify_layerb_audit.py` sets it as an **unconditional overwrite** — a sandbox-authored `"sandbox"` value is erased rather than reported. The check is live only for `pep_results.json`. E8 also never reads `gate_passed`, `layer_b`, or `ipv6_runtime` — an acceptance artifact reading `gate_passed: false` certifies without comment.

**H6 — Budget check→charge TOCTOU, with no row anywhere to detect it.** *(answers P2-C6)* No acceptance row of any kind exists for budget enforcement — not in A1-A30, B1-B9, E1-E8 or PP1-PP18. **There is nothing to weaken, because there is nothing there.**

**H7 — E2's Layer-B count reconciliation is tautological.** `verify_layerb_audit.py:204-205` computes those two numbers with **character-identical arithmetic** immediately before writing the file E2 reads. Not re-derivation — a self-consistency check no producer can fail.

**H8 — The fixture battery has no per-check assertion.** No fixture isolates one check; eight of the twenty survivors trace to this alone. No fixture exists for a self-contradictory row, an un-passable row, a `STARTUP_DEGRADED` record, or `gate_passed: false`.

---

## MEDIUM

**M1** `STARTUP_DEGRADED` is printed but never enters `passed`/`total` — no `chk()` call exists. **It should hard-fail.** *(answers P2-C4)*
**M2** `AuditLog.verify()` has **zero call sites** repo-wide. E7 re-implements the walk inline — a second uncovered copy that can drift. *(answers P2-C5)*
**M3** collect→stamp TOCTOU. `shutil.copyfile(..., follow_symlinks=False)` **recreates a symlink at the destination**, importing a sandbox-chosen link into the trusted directory; `stamp_artifacts.py` then follows it. **Could not win the race in 500 000 attempts**; the shipped scripts close it by retiring the sandbox before collection. **Latent, not currently reachable** — but both teardowns and both collect/stamp calls are `|| true` with unchecked returns.
**M4** Two `AuditLog` instances on one path corrupt the chain — no lockfile, no `O_EXCL`, no PID guard. Intra-process locking is correct.
**M5** The manifest misses PP18 in **all three views**, and its runtime block covers **17 of 64 IDs**. `STARTUP_DEGRADED` and budget exhaustion have **no ID at all** and are structurally unmanifestable. *(answers P2-C2)*
**M6** `test_preconditions.py:158-167` — the `want` value is computed from the same `out` being measured. **The check named "no arbitrary fallback" cannot fail on a host with eth0.**
**M7** `test_pipeline_order.py` covers only the layerb artifact; acceptance and v4 bypass collect+stamp.
**M8** E7 requires only *at least one* record for the run — a log full of foreign-run records passes.

---

## Carry-forward — all twelve answered

**F3** — `--internal` is true by construction but **runtime-verified nowhere**; no `docker network inspect {{.Internal}}` exists. And `--internal` is *itself* the reason `NO_ROUTE` occurs, so the classifier cannot separate "policy denied it" from "this network has no route out by construction." **Unresolved as evidence.**
**F4** — **Upheld as a defect.** An on-link injected route can never produce an egress attempt. **B2 is not containment evidence.**
**F1** — Extended, not merely reproduced: the model detects neither a weakened row, nor a weakened auditor check, nor a weakened log.
**F8** — E1 fails permanently; **E2 passes**, because it only reconciles counts and never requires `passed == total`.
**B8 inherits F3+F7 · B9 inherits F2** — both upheld, both additionally unreachable under P2-C1.
**P2-C1 · C2 · C3 · C4 · C5 · C6** — all confirmed independently (see above).

---

## What survived

**`test_verifiers.py` — the strongest component in the tree.** It *executes* both verifiers and caught four mutations E5 missed. **Detection concentrates almost entirely in the one suite that executes the code it audits.**

`verify_pp18.py` is the strictest verifier (nonce presence *and* uniqueness). Layer A's thirty rows are individually **sound as logic claims** — A19/A20's rebinding repair is genuine. `stamp_artifacts.py`'s conflict detection works.

---

```
EVIDENCE_MODEL_STATUS = NOT-ESTABLISHED
MUTATION_RESISTANCE   = 20 of 35 security-relevant weakenings survived undetected
```

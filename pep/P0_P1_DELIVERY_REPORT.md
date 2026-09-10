# P0 + P1 Hardening — Delivery Report

**Scope executed:** R-1, R-2, R-3 (P0) and R-4, R-5, R-6, R-7 (P1), per approval.
**Decisions applied:** D-1 = option (a), one unguessable `test_nonce` per execution
with `row_id` as a separate structural field. D-2 = Layer B frozen at 9 rows.
**P2 not started.** R-8 … R-13 remain open and unfixed.

**Strix baseline untouched:** `0478a69ab03abfec4e8b7f764f40fe4131fd85fb`,
`git status --porcelain` → 0 files. Strix was not run, not modified, not imported.

---

## 1. Code changes

All paths relative to `strix-pipeline/pep/`. SHA-256 prefixes are of the delivered files.

| File | Δ | What changed and why |
|---|---|---|
| `audit.py` `623f0a6b9551eaf8` | mod | `AuditLog(run_id=…)`. Every record is stamped with the control-plane execution id before `prev`, so evidence can be scoped to one execution without any value the sandbox can choose. **(R-3)** |
| `server.py` `c9f1d03641d28a2a` | mod | Reads `PEP_RUN_ID` from the environment the control plane gave the PEP container only. |
| `gateway.py` `681e6f0462689e55` | mod | `conn_id` widened to a full `uuid4().hex`. `ConnectionState` gained structured `test_nonce` and `row_id`, populated from `X-Strix-Nonce` / `X-Strix-Row` and emitted on `ALLOW` and `CONNECTION_TERMINATED`. Both are documented in-code as **client-supplied and non-authoritative**. **(R-6)** |
| `verify_pp18.py` `f0bcc31007671a3e` | **new** | PP18 extracted from a `run_pep.sh` heredoc into a real module. Chain: `run_id → record(row_id=PP18) → conn_id → KILL_SWITCH.terminated_conn_ids`. No fallback at any step; a record without a `test_nonce` fails as `NO_TEST_CORRELATION` rather than being accepted on `run_id + row_id`. **(R-1)** |
| `verify_layerb_audit.py` `35b76327be27b33e` | rewrite | B8 = `{B3,B5}`, B9 = `B6`, matched on structured fields only — no URL-suffix parsing, so `-b3` can no longer collide with `-b30`. Scoped by `run_id`; `B8.test_nonce != B9.test_nonce` → `NONCE_MISMATCH`. Marks its output `run_id_source: control-plane`. **(R-3, R-6)** |
| `audit_gate_evidence.py` `36e814a3df27f6e1` | rewrite | Eight checks E1–E8 (detailed in §3). **(R-2, R-4, R-5, R-6, R-7)** |
| `collect_artifacts.py` `5ceede9595116018` | **new** | Symlink-safe collection of sandbox artifacts out of the shared mount. Refuses symlinks, hard links, non-regular files and non-JSON payloads, so a sandbox cannot make the host `cp` read an arbitrary path on its behalf. |
| `stamp_artifacts.py` `0c3a2db4de272bf8` | **new** | Host-side control-plane binding of sandbox-written artifacts, performed on copies collected out of the shared mount. Flags **any** pre-existing `run_id` as `run_id_conflict`. **(R-7)** |
| `ipv6_acceptance.py` `47eab69fecd74d07` | mod | Emits an explicit per-row `status`; totals count `status == "PROVEN"` only; output stamped `run_id` + `run_id_source`. **(R-4)** |
| `ipv6_transport.py` `0532a227bd4154d8` | mod | Single per-execution `TEST_NONCE`; `tunnel6(..., row=…)` sends `X-Strix-Nonce`/`X-Strix-Row`; B3/B5/B6 use `row=` instead of URL suffixes; writes `run_id: null`. **(D-1)** |
| `pep_client.py` `ebb0d6e71f1b383a` | mod | Same nonce/row treatment; PP18 drip connection sends `X-Strix-Row: PP18`; `pep_kill.json` marked advisory-only; writes `run_id: null`. |
| `run_pep.sh` `3796b6fece2a08d3` | mod | Mints `RUN_ID`, exports `PEP_RUN_ID` to the PEP container only, retires the sandbox, collects artifacts into `collected/`, stamps them, then calls `verify_pp18.py`. |
| `run_dualstack_gate.sh` `dda1e081a152c40e` | mod | Mints `RUN_ID`; **invokes PP18 and requires `PP18: PROVEN` in the verdict**; collects every artifact out of the sandbox-writable `$OUT` into `collected/` before stamping, verifying or auditing; retires the sandbox before evidence work; auditor called with `--run-id`. **(R-1, R-7)** |
| `fixtures/make_fixtures.py` `ae4c8575ec7a365a` | **new** | 1 honest + 21 forged evidence sets, chains computed the way `AuditLog` computes them. `f21` is built by invoking the real stamper. |
| `fixtures/test_verifiers.py` `031e0252a9b8094e` | **new** | Verifier **self-test**: executes `verify_layerb_audit.evaluate()` and `verify_pp18.verify()` against synthetic records and asserts all 20 verdict codes. The battery only *reads* verifier source (E5), so a verifier that is **wrong** rather than **weakened** was previously untested. |
| `fixtures/test_pipeline_order.py` `9587edf6b256de04` | **new** | Integration test over the real sequence `collect → stamp → verify_layerb_audit → audit`. |
| `collect_artifacts.py`-driven runner | mod | `fixtures/run_fixtures.sh` now gates on all three suites. |
| `fixtures/run_fixtures.sh` `8c378aab44a019ce` | **new** | Battery runner; asserts verdict text **and** exit code. |

### A defect found and fixed during this work

The docstrings asserted that `run_id` is *"never transmitted to the sandbox"*.
That was **false as implemented**: `run_pep.sh` and `run_dualstack_gate.sh` were
passing `-e PEP_RUN_ID` into the sandbox `docker exec` calls, and
`pep_client.py` / `ipv6_transport.py` were writing that value into their own
artifacts. The "binding" was therefore a value the measured party had been
handed and could assert about itself.

Fixed rather than documented away:

* the three sandbox `docker exec` invocations no longer carry `PEP_RUN_ID`;
* sandbox-written artifacts emit `run_id: null` and `origin: "sandbox"`;
* `stamp_artifacts.py` performs the binding host-side after collection, writing
  `run_id_source: "control-plane"` and flagging any artifact that arrived with a
  `run_id` of its own as `run_id_conflict`;
* **E8** was added to enforce all of the above, and fixtures f18–f21 prove it bites.

### A third defect, found by the next review round — and the test gap behind it

Reordering the collection introduced a **worse** bug than the one it fixed.
`stamp_artifacts.py` writes the control-plane `run_id` onto `ipv6_layerb.json`;
`verify_layerb_audit.py` then rewrites the same file and, seeing a populated
`run_id`, recorded it as a **sandbox self-label**. On a dual-stack host that
would have set `run_id_conflict` on every run, failed E8 unconditionally, and
reported `IPv6 GATE: NOT PASSED` — while blaming the sandbox for it. The gate
would have been unpassable by construction.

Fixed by having `verify_layerb_audit.py` recognise this run's own control-plane
stamp (`run_id_source == "control-plane"` **and** `run_id == this run`) and treat
only anything else as a conflict.

**The fixture battery reported 22/22 PASS with this bug present.** That is the
important part. The battery hands the auditor artifacts already in final shape
and reaches the verifiers only through E5, which merely *reads their source* —
neither verifier is ever executed, and no stage ordering is exercised. Two whole
classes of defect were outside it:

* a verifier that is **wrong** rather than **weakened**, and
* a fault in the **ordering** of the stages the real gate runs.

Both are now covered, and `run_fixtures.sh` gates on all three suites:

| Suite | Covers |
|---|---|
| fixture battery (22) | the auditor's response to forged evidence and weakened verifier source |
| `test_verifiers.py` (20) | the verifiers **executed** against synthetic records, one assertion per verdict code |
| `test_pipeline_order.py` (3) | `collect → stamp → verify_layerb_audit → audit` in the real order |

Verified as a genuine regression test: with the bug reintroduced,
`test_pipeline_order.py` fails (exit 1, `E8 … layerb:self_labelled=…`) while the
fixture battery still reports **22/22 PASS**.

### A second defect, found by adversarial review of this report

An independent verification pass attacked the claim above and found it still
false in the gate script, by a different route. `$OUT` is bind-mounted
**read-write** into the sandbox — it has to be, since that is how the sandbox
reports its results. The stamper was writing the real `run_id` into
`$OUT/pep_results.json` **before** the Layer B phase executed in that same
sandbox. The measured party could therefore read this execution's `run_id` out
of the shared directory for the whole of Layer B. Worse, the same directory held
`ipv6_acceptance.json` and `ipv6_layerb.json`, so the sandbox had write access to
the evidence artifacts the auditor would later read.

Fixed:

* a control-plane-only directory `$COL` (`collected/`) was introduced. It is
  mounted into **no sandbox container** — it does sit under `pep/`, which is
  bind-mounted **read-only** into the PEP container, and the PEP legitimately
  holds `PEP_RUN_ID` already, so that is not a disclosure. Artifacts are
  **collected out of `$OUT` first**, then stamped, verified and audited there.
  No control-plane *value* is written into the sandbox-writable mount; the only
  host touch there is `rm -f "$OUT/ARM_KILL"`, deleting the sandbox's own
  kill-switch trigger between phases.
* the sandbox container is **retired** (`docker rm -f`) after its last
  `docker exec` returns and **before any** of its evidence is collected. An
  earlier revision collected the IPv4 artifacts between the two sandbox phases,
  while the container was still alive — that window is now closed by deferring
  *all* collection until after retirement.
* `stamp_artifacts.py` now flags **any** pre-existing `run_id` as
  `run_id_conflict`, including one that *matches* — accepting a matching value
  would have rewarded precisely the adversary who had learned it.
* `verify_layerb_audit.py` no longer overwrites a self-labelled `run_id`
  silently; it records the conflict so E8 can reject the run.
* fixture **f21** builds its artifact by invoking the **real stamper** on a
  correctly-self-labelled file, so the fix is tested through the shipping code
  path rather than a hand-written flag.

Verified empirically on a live IPv4 run: the execution `run_id` appears in
`collected/` and in **no** file under the sandbox-writable `out/`.

---

## 2. Evidence model

```
CONTROL PLANE                                    SANDBOX (measured party)
─────────────                                    ────────────────────────
run_id ── minted per execution                   never receives run_id
   │                                             chooses test_nonce (a label)
   ├─ PEP container env ──► every audit record
   │                                             writes results to $OUT with
   │                        ┌── copy ────────────  run_id: null, origin: sandbox
   │                        │                     ($OUT is bind-mounted RW —
   └─ stamp_artifacts.py ──► $COL (no sandbox      the only shared surface)
      verify_* · auditor      mount)
                                                 retired before evidence work
```

**Authority hierarchy (strict, one-directional):**

```
RAW AUDIT + CONNECTION REGISTRY  >  EVIDENCE AUDITOR  >  VERIFIER  >  SUMMARY
```

**The chain, with no fallback at any link:**

```
run_id                        control-plane; the sandbox cannot guess or assert it
  └─► audit records stamped with that run_id, and only those
        └─► record with structured row_id  ({B3,B5}=B8 · B6=B9 · PP18)
              └─► that record's test_nonce   ← narrows only; never proof
                    └─► that record's conn_id  (PEP-generated uuid4)
                          └─► KILL_SWITCH.terminated_conn_ids ∋ that exact conn_id
```

Each element's authority is explicit: `run_id` anchors, `row_id` and `test_nonce`
narrow, `conn_id` identifies, and membership in `terminated_conn_ids` proves.
Missing correlation data is a **failure** (`NO_TEST_CORRELATION`), never a
relaxation to hostname, timestamp, or count matching.

**Demonstrated on a live run** (IPv4 path, this host, current code):

```
run_id   = run-63804cad4f7e29ae8ee0e4018f9ab6ba
records  = 118   missing run_id: 0   distinct run_id: 1
IPv4     = 17/17
PP18     = PROVEN  conn_id=d254e0bbed994529a108d881608303a7
                   killed_set=1  nonce=8103cb812453393b6c7208e7a2fadc29
artifacts: collected/pep_results.json · collected/pep_kill.json
           run_id=run-63804cad…  run_id_source=control-plane  run_id_conflict=None

leak check (this run_id searched across both directories):
  out/        (sandbox-writable, bind-mounted)   files containing run_id: NONE
  collected/  (no sandbox mount)                    pep_results, pep_kill, pp18
```

**Negative controls on the anchor**, same audit log, same command:

| Input | Result | Exit |
|---|---|---|
| correct `run_id` | `PROVEN` | 0 |
| a `run_id` that never existed | `NO_RECORDS_FOR_RUN` | 1 |
| empty `run_id` | `NO_RUN_ID` | 1 |

The anchor is load-bearing, not decorative: remove it and PP18 stops proving anything.

---

## 3. Auditor integrity

`audit_gate_evidence.py` never reads a verifier's prose and ignores
`pep_kill.json` entirely. It re-derives from the raw audit log the claims that
*can* be re-derived from it — E3, E4, E7 and the PP18 half of E6.

**It does not re-derive everything, and the distinction matters:**

* **E1 and E2 check the summary against itself** — row IDs, statuses and counts
  are read from the acceptance and layerb artifacts. They catch a summary that
  contradicts its own rows; they do not independently confirm a row is true.
* **All 30 Layer A rows are accepted on the artifact's own say-so.** Layer A is
  pure policy-logic evaluation with no network activity, so it produces no audit
  records to re-derive from. Its integrity rests on E8 (the artifact belongs to
  this execution) and on the suite itself, not on the audit log.
* **Layer B rows B1–B7 are measured inside the sandbox and self-reported.**
  `ipv6_transport.py` runs in the sandbox and writes them; `verify_layerb_audit.py`
  replaces only B8 and B9 with host-derived results and passes B1–B7 through
  verbatim. This is the largest self-assertion surface in the gate, and it sits
  under the rows the IPv6 claim rests on. It is mitigated — not removed — by B8
  and B9 being re-derived from audit, and by the whole artifact being bound to
  the execution by E8.
* **E6's "IPv4 regression complete" half** reads `passed`/`total` from the
  sandbox-written `pep_results.json`. Only the **PP18** half of E6 is re-derived
  from raw audit.

In short: what the sandbox reports about **itself** (17 IPv4 rows, Layer B
B1–B7, `b6_client.partial_bytes`) is taken as reported. What matters most —
B8, B9, PP18, chain integrity, artifact binding — is not.

| Check | Requires |
|---|---|
| **E1** | strict **whitelist** — every required row has `status == "PROVEN"`. Unknown ≠ pass. (Previously a blacklist, which let any unrecognised status through.) **(R-4)** |
| **E2** | row IDs exactly `{A1..A30}` and `{B1..B9}`; no duplicates, extras or substitutions; reported counts recomputed from the rows actually present. **(R-5)** |
| **E3** | B8 and B9 share one `test_nonce`, read from **structured audit fields only**. **(R-6)** |
| **E4** | the exact B6 `conn_id` ∈ `KILL_SWITCH.terminated_conn_ids` of this run, **and** the B8 ALLOW is a genuine v6 record (`pin_family=ipv6`, a real v6 `pin_ip`, plus `canonical_host`, `sni`, `request_hash`, `response_hash`). **(R-6)** |
| **E5** | verifier source integrity across **all** verifier modules. |
| **E6** | IPv4 regression complete **and** PP18 re-derived here from raw audit. **(R-1)** |
| **E7** | SHA-256 chain recomputed independently in the auditor; zero malformed lines; records exist for this `run_id`. **(R-2)** |
| **E8** | the three audited artifacts — `acceptance`, `layerb`, `v4` — each carry **this** `run_id`, `run_id_source: control-plane`, and no `run_id_conflict`. **(R-7)** |

**What E8 does and does not establish.** It checks three artifacts, not all of
them (`pep_kill.json` and `b6_client.json` are stamped but unchecked — both are
advisory and neither feeds a verdict). Of the three, `v4` **and `layerb`** are
sandbox-origin and externally stamped; only `acceptance` is written host-side and
therefore *self-asserts* the control-plane label. That is consistent with the
authority model — the control plane is the authority, so its own assertion about
its own output is the ground truth — but it is an assertion, not an independent
attestation, and should not be read as one.

### E5 in detail — and why blacklisting alone failed

E5 began as regex + AST **blacklisting** of weakened shapes. Two mutants passed it:

* `f14` — "any kill event counts" (`return bool(kills)`)
* `f15` — "termination count > 0" (`return total > 0`)

Both are exactly the weakening that matters, and neither matched any pattern.
Blacklisting shapes is a losing game, so E5 now also asserts **positive
constructs** a correct kill-switch verifier must contain:

* it must reference `terminated_conn_ids`, and
* it must perform a real membership test — an `ast.In` comparison, and
* it must not decide on `connections_terminated` (a count proves *something*
  died, never *which*).

f14 and f15 now fail on `missing_construct=['terminated_conn_ids']` and
`no_membership_test`; f15 additionally on `decides_on_termination_count`.

### Stated limits of E5

E5 is **static inspection of source text**. It cannot defeat a
semantically-equivalent rewrite that keeps the required constructs while
changing their meaning, and it says nothing about the interpreter executing it
(Thompson, *Reflections on Trusting Trust*). It raises the cost of weakening a
verifier; it does not make it impossible.

---

## 4. Adversarial results

`fixtures/run_fixtures.sh` — 1 honest set + 21 forgeries. Chains are **really
computed**, the same way `AuditLog.write()` computes them, so E7 is exercised for
real rather than passing trivially; `f16` is then deliberately corrupted from a
valid chain and `f17` deliberately truncated, which is the point of those two.
Five forgeries attack the **verifier source** rather than the evidence, and four
attack the **artifact binding**.

| Fixture | Expected | Actual | Exit | Rejected by |
|---|---|---|---|---|
| `f00_honest` | CERTIFIED | CERTIFIED | **0** | — |
| `f01_stale_execution` | NOT CERTIFIED | NOT CERTIFIED | 1 | E3, E4 |
| `f02_nonce_mismatch` | NOT CERTIFIED | NOT CERTIFIED | 1 | E3 |
| `f03_pin_not_v6` | NOT CERTIFIED | NOT CERTIFIED | 1 | E4 |
| `f04_killed_other_conn` | NOT CERTIFIED | NOT CERTIFIED | 1 | E4, E6 |
| `f05_missing_request_hash` | NOT CERTIFIED | NOT CERTIFIED | 1 | E4 |
| `f06_missing_response_hash` | NOT CERTIFIED | NOT CERTIFIED | 1 | E4 |
| `f07_missing_nonce` | NOT CERTIFIED | NOT CERTIFIED | 1 | E3 |
| `f08_hidden_non_proven` | NOT CERTIFIED | NOT CERTIFIED | 1 | E1, E2 |
| `f09_count_mismatch` | NOT CERTIFIED | NOT CERTIFIED | 1 | E1, E2 |
| `f10_pp18_unbacked` | NOT CERTIFIED | NOT CERTIFIED | 1 | E6 |
| `f11_verifier_hostname_fallback` | NOT CERTIFIED | NOT CERTIFIED | 1 | E5 |
| `f12_verifier_timestamp_fallback` | NOT CERTIFIED | NOT CERTIFIED | 1 | E5 |
| `f13_verifier_latest_record` | NOT CERTIFIED | NOT CERTIFIED | 1 | E5 |
| `f14_verifier_any_kill_event` | NOT CERTIFIED | NOT CERTIFIED | 1 | E5 |
| `f15_verifier_count_only` | NOT CERTIFIED | NOT CERTIFIED | 1 | E5 |
| `f16_broken_chain` | NOT CERTIFIED | NOT CERTIFIED | 1 | E7 |
| `f17_truncated_log` | NOT CERTIFIED | NOT CERTIFIED | 1 | E7 |
| `f18_artifact_run_id_mismatch` | NOT CERTIFIED | NOT CERTIFIED | 1 | E8 |
| `f19_artifact_self_labelled` | NOT CERTIFIED | NOT CERTIFIED | 1 | E8 |
| `f20_artifact_run_id_conflict` | NOT CERTIFIED | NOT CERTIFIED | 1 | E8 |
| `f21_selflabel_matching_runid` | NOT CERTIFIED | NOT CERTIFIED | 1 | E8 |

```
fixtures behaving correctly: 22   incorrect: 0
VERIFIER SELF-TEST: 20/20
PIPELINE ORDER: 3/3
  fixtures: PASS   verifier self-test: PASS   pipeline order: PASS
BATTERY: PASS        (runner exit 0)
```

Every check E1–E8 is the sole or joint discriminator for at least one fixture,
so no check is dead weight. (E1 and E2 only ever fire jointly; each of E3–E8
fires alone for at least one fixture.) `CERTIFIED` / exit 0 occurs for exactly
one fixture: the honest one.

**What this does not establish.** The battery proves the auditor rejects *these*
21 constructed forgeries. It does not enumerate the forgery space, and the honest
fixture is synthetic. A green battery is a floor, not a coverage claim — and this
turn is direct evidence of that: an adversarial review of an earlier draft of
this report found a real `run_id` leak that all 21 then-passing fixtures had
missed, because no fixture modelled the filesystem the sandbox could see.

---

## 5. Current gate status

Reported independently of everything above.

| Item | Status |
|---|---|
| Layer A (policy logic, 30 rows) | **30/30** — re-run on current code this turn; zero non-`PROVEN` rows |
| Layer B (transport, 9 rows) | **0/9 — `BLOCKED_ENV`** |
| IPv4 regression (`run_pep.sh`) | **17/17** on current code, `run_id=run-63804cad4f7e29ae8ee0e4018f9ab6ba` |
| PP18 (host-side, IPv4 kill switch) | **PROVEN** on current code |
| Evidence tooling suites | **22/22 fixtures · 20/20 verifier self-test · 3/3 pipeline order**, runner exit 0 |
| `run_dualstack_gate.sh` | **exit 1** — `REFUSING TO RUN: kernel booted with ipv6.disable=1` |
| **IPv6 GATE** | **NOT PASSED** |
| **IPv6 STATUS** | **UNKNOWN / RELEASE BLOCKER** |
| **PEP** | **NOT ELIGIBLE FOR STRIX OBSERVATION** |
| Strix | not run, not modified — `0478a69`, clean tree |

The environment gate still refuses on this host after every P0/P1 change. That is
the correct outcome: this kernel booted with `ipv6.disable=1`, there is no
`/proc/sys/net/ipv6`, and it cannot be fixed at runtime. **Absence of testability
is not evidence of security.** Layer B is `BLOCKED_ENV`, which is not a pass and
must never be counted as one. A dual-stack host is still required
(see `DUALSTACK_ENV.md` §1).

### Deferred by decision (P2 — not started, still open)

* **R-8** kill-switch registry race — a connection registered *after* the
  snapshot survives the sweep. **Both an evidence defect and a real enforcement
  gap.** `terminate_all()` / `close_all()` semantics are deliberately unchanged.
* **R-9** ip6tables rule assertion · **R-10** full mutation framework ·
  **R-11** RFC 8215/6052 coverage · **R-12** additional Layer B rows (frozen at 9
  by decision D-2) · **R-13** external audit anchoring.

---

## 6. DO NOT CLAIM SECURITY

This work hardened the **evidence pipeline**. It did not make the PEP secure, and
nothing here should be read as a security claim.

What is actually supported:

* the evidence auditor rejects 21 constructed forgeries and certifies exactly one
  honest set, on this code, today;
* the IPv4 enforcement path behaves as specified in a local lab on this host;
* PP18's chain is anchored on a value the measured party never receives — a
  property that was **false in an earlier draft of this same work** and is now
  verified empirically per run, not assumed from the code's docstrings.

What is **not** supported, and must not be inferred:

* **no IPv6 transport property is proven.** Layer B did not run. `BLOCKED_ENV` is
  not a pass, and v6 behaviour cannot be inferred from v4 results.
* **no claim about real targets.** Everything ran against local lab containers.
  Strix has never been executed under this PEP.
* **no claim of completeness.** The auditor catches the forgeries it was built to
  catch. E5 is static text inspection with the limits stated in §3. Three rounds
  of adversarial review of *this document* each found a real defect that the
  then-green test suites had missed — a `run_id` transmitted to the sandbox, then
  a `run_id` leaked through the shared mount, then a gate made unpassable by a
  double-stamp. The rate is not obviously zero now.
* **a known enforcement gap remains open** (R-8). The kill switch can miss a
  connection that registers after the snapshot.
* **a passing gate would make the PEP *eligible* for an observation run, nothing
  more.** That run is an experiment, not a proof; boundary soundness is
  established before Strix starts and is never argued from Strix's behaviour.

The single most honest summary of the current state: **the checker is now harder
to fool, and the thing it checks is still unproven on IPv6.**

# Unified Triage — all three audit passes

**51 findings: 8 CRITICAL · 14 HIGH · 17 MEDIUM · 12 LOW.**
Nothing has been repaired. This is the frozen finding set before the first edit.

## The single most important sentence

**The evidence model has never certified a real execution, and by construction
cannot.** Every `RESULT: CERTIFIED` in this project's history was produced
against `fixtures/f00_honest` — an evidence set fabricated by
`make_fixtures.py`. Two independent blocks make a live pass impossible: B7 has
no branch that emits `PROVEN`, and the v6 targets bind `AF_INET` only.

Everything below is ordered by that reality.

---

## P0 — enforcement defects. Strix must not run until these close.

| ID | Defect | Why P0 |
|---|---|---|
| **P2-HIGH-2** | **Budget TOCTOU** — `would_exceed()` and `charge()` lock separately with ~100 lines between them. Measured: **64 requests served against a cap of 10.** | A real enforcement bypass. Strix is an *adaptive* adversary; concurrency interleavings are exactly what a scripted client never explores. |
| **R-8** | **Kill-switch snapshot race** (deferred since P2 planning). `terminate_all()` snapshots under lock, `close_all()` runs outside it. A connection registered after the snapshot survives. | The kill switch is the last line of defence. Deferring a known race in it while introducing an autonomous agent is unjustifiable. |
| **P3-CRIT-3** | **`audit.py` can be gutted undetected** — chain, write lock, `fsync`, redaction and `run_id` stamping each deletable with all four suites green. | The audit log is the root of the authority hierarchy. If it can be silently weakened, nothing above it means anything. |

## P1 — the evidence model cannot do its job

| ID | Defect |
|---|---|
| **P3-CRIT-1** | E1/E3/E4 are jointly unpassable on any live run. Requires: B7 spec decision **(yours)**, PEP IPv6 listener (done), **IPv6 target listeners (not done)**. |
| **P2-CRIT-1** | `target_https.py:105` binds `AF_INET` only — the same bug class fixed in the PEP listener and left in the target. |
| **P3-CRIT-2** | E1 certifies rows that contradict themselves (`status=PROVEN` while `pass=False`). |
| **P3-HIGH-2** | **No E-check reads a single denial record.** The entire blocking surface is self-reported. |
| **P2-HIGH-3** | `_deny()`/`_deny_tls()` carry no `conn_id` — though it is in scope at the call site. |
| **P3-CRIT-4** | `audit.py` has zero test coverage; `make_fixtures.py` forges the chain instead of calling it. |
| **P3-HIGH-4** | E5 bypassed by a trailing comment. |
| **P3-HIGH-5** | E8's control-plane check is inert for 2 of its 3 artifacts. |
| **P3-HIGH-7** | E2's Layer-B counts are tautological. |
| **P3-HIGH-8** | The battery asserts only the aggregate verdict — no per-check isolation. |
| **P1-F1 / P3-CRIT-3** | 20 of 35 weakenings survive all four suites. |

## P2 — tests that cannot prove their claim

| ID | Defect |
|---|---|
| **P1-F2** | B6 accepts **any exception** as proof the kill switch fired. |
| **P1-CRIT-2 / F4** | B2's on-link injected route can never produce an egress attempt. **Not containment evidence.** |
| **P1-F3** | `NO_ROUTE` as blocking contradicts the file's own treatment of `PERMISSION_DENIED`; premise runtime-unverified. |
| **P1-F5 / P3-M6** | The `scoped_ll` assertion is *still* a tautology. |
| **P1-F8** | B7 un-passable by construction — **needs a specification decision, not a code fix.** |
| **P3-M1** | `STARTUP_DEGRADED` never reaches a verdict. Should hard-fail. |
| **P3-M5** | The manifest misses PP18 and covers 17 of 64 IDs at runtime. |
| **P1-F6, F7 · P2-M1, M5 · P3-M2, M7, M8** | Over-inference and coverage gaps. |

## P3 — robustness, latent, documentation

`P3-M3` collect→stamp symlink TOCTOU (latent, unreachable as shipped) ·
`P3-M4` multi-writer chain corruption · `P2-M2` decision ordering ·
`P2-M4` double-charge · `P1-F9, F10, F11` · `P2-L1..L5` · `P3-L1..L4` ·
**and every comment that attributes a failure to a cause that is not the real
one** — `gen_certs.sh:35-49` is the worst: it documents a *resolved* cause while
the real blocker sits one layer below, unmentioned.

---

## What must NOT happen next

**Do not reuse any of these results as evidence about repaired code.** Every
finding here was produced against the pre-repair tree. Reusing them would mean
*"the evidence proving the code sound was produced before the code changed."*
Repair requires a completely fresh run and a fresh independent audit.

**Do not fix in this order because it is written down.** The P0 items are
enforcement defects; the P1 items are why we could not have detected them. A
defensible sequence repairs P0 first but does not *trust* the repair until P1
gives the evidence model the ability to notice a regression.

## Sequence

```
Triage (this document)  ->  frozen finding set
        v
P0 repair               ->  enforcement defects only
        v
P1 repair               ->  evidence model can detect a weakened row,
                            a weakened check, and a weakened log
        v
Fresh run               ->  IPv4 regression, then Layer B on a dual-stack host
        v
Pass 4 independent audit -> against the repaired tree, from scratch
        v
Only then               ->  Strix observation
```

## Two decisions that are yours, not mine

1. **B7.** `NOT_PROVABLE_IN_TOPOLOGY` means `Layer B = 9/9` is unreachable as
   specified. Proving it needs a real, occupied link-local peer that policy
   should deny — a topology change **and** a change to what the row asserts.
2. **Whether `STARTUP_DEGRADED` should hard-fail certification** rather than
   relying on Layer B failing indirectly.

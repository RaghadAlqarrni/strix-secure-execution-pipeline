# P0 REPAIR — STATUS

**Status: REPAIRED AND LOCALLY PROVEN. NOT VERIFIED. NOT CERTIFIED.**

Three P0 defects from `TRIAGE_UNIFIED.md` are repaired, and each repair has a
standing re-runnable proof with a **live negative control**.

    bash pep/fixtures/p0_proofs/run_p0_proofs.sh     -> P0 PROOFS: PASS (exit 0)
    bash pep/fixtures/run_fixtures.sh                -> BATTERY: PASS   (exit 0)
    (cd strix && git status --porcelain | wc -l)     -> 0

---

## What "locally proven" means, and what it does not

These proofs were written by the same agent that wrote the repairs. Under the
standing rule — *findings from a pre-repair run are not evidence about
post-repair code* — a repairer's own green test is **not** verification. The
symmetric error is just as real: a repairer's own green test is not evidence
that the repairer is right.

So each proof is built to be falsifiable rather than reassuring:

| Requirement | Why |
|---|---|
| Every proof ships a negative control | A test that cannot go red proves nothing when it is green |
| Controls are **deterministic**, not probabilistic | See P0-1 below — the obvious version of that test passed on the broken code |
| The audit target is never mutated | Mutation runs happen on disposable copies; the tree is fingerprinted before and after |
| The runner prints its own scope limits | So a `PASS` cannot be quoted as certification |

**Nothing here may be promoted to SOUND without a fresh full run and an
independent Pass 4 audit.**

---

## P0-1 — budget cap: check-then-act race

`pep/pdp.py`. The cap check and the counter charge were separate statements, so
N concurrent requests could all read the same under-cap value and all charge.

Repair: `Budgets.reserve(specs)` checks **every** cap and charges **every**
counter inside one critical section, or does nothing. The budget decision also
moved to the end of `decide()` (which fixed a second defect: wrong-control
attribution) and charges only when `pin is None`, so a connection is charged
once rather than per request.

**The first version of this test was worthless and was discarded.** Firing 64
threads at the naive counter and hoping for an overshoot is probabilistic;
under the GIL the barrier released threads nearly serially, so the *broken*
shape passed with overshoot 0. A green result on the repaired shape would have
meant nothing. The test now forces the interleaving deterministically — every
worker is held at a barrier at the exact point where the pre-repair code could
be preempted, which is a schedule the OS is permitted to produce.

    NEGATIVE CONTROL: naive check-then-act
        cap = 10   concurrent = 64   ALLOWED = 64   overshoot = 54    PASS
    UNDER TEST: atomic Budgets.reserve()
        cap = 10   concurrent = 64   ALLOWED = 10   overshoot =  0    PASS

## P0-2 — kill switch: R-8 admit-after-kill, and evidence honesty

`pep/gateway.py`. A connection could be admitted after `terminate_all()` had
drained the registry, leaving a live unpoliced connection. Separately,
`terminated_conn_ids` recorded the **pre-close snapshot**, so a connection that
finished on its own inside the window was still named as a kill-switch victim —
an over-claim in the direction that flatters the control.

Repair: `Registry` gained a terminal `_killed` state set inside the same
critical section as the drain, so nothing can slip between them; `add()` returns
`False` and the caller honours the refusal. `close_all()` returns `True` only if
a genuinely live socket was shut down, and that is what the field now records;
the snapshot is kept separately as `registered_at_kill` for diagnostics.

    A1  DECISIVE       add() after terminate_all() returned
                       repaired: refused, residual 0        control: ADMITTED
    A2  STRESS         300 concurrent late adds
                       repaired: residual 0                 control: 25 survivors
    B   EVIDENCE       pre-repair field  = ['finished','live']   <- over-claims
                       repaired field    = ['live']

A2 is labelled in the output as supplementary and timing-dependent: a green A2
is **not** independent evidence. A1 is the decisive claim, because `_killed` is
terminal and so admits no scheduling luck.

## P0-3 — `audit.py` had no test coverage at all

The audit log is the root of the authority hierarchy, and no suite imported it.
Five separate weakenings of its write path — including deleting the hash chain
outright — left all four suites green.

Repair: `pep/fixtures/test_audit_log.py`, 18 assertions executing the real
`AuditLog` (chain reality under edit and delete, `run_id` stamped and not
caller-overridable, nested redaction, fsync per record, 960 records from 8
threads chain-intact, torn-write recovery, append-only). Wired into
`run_fixtures.sh` as a fifth gating stage.

The proof runs each mutant twice — once against the new suite, once against a
copy of the **pre-P0-3** four-suite battery with the audit-log stage stubbed —
so the result distinguishes "this suite catches it" from "this suite is the
reason it is caught".

    CAUGHT  M13 fsync removed                     pre-P0-3 battery: GREEN — undetected
    CAUGHT  M14 hash chain deleted                pre-P0-3 battery: GREEN — undetected
    CAUGHT  M15 write lock removed                pre-P0-3 battery: GREEN — undetected
    CAUGHT  M16 redaction removed                 pre-P0-3 battery: GREEN — undetected
    CAUGHT  M17 caller can override run_id        pre-P0-3 battery: GREEN — undetected

    caught 5 of 5 · invisible to the pre-P0-3 battery: 5 of 5
    audit target byte-identical after the run: True

---

## Explicitly NOT done

* **P1 is untouched** — `phase2b/target_https.py:105` still binds `AF_INET`
  (CRITICAL-1); E1 self-contradictory rows; denial records carrying `conn_id`;
  E5 trailing-comment bypass; E8 inert for 2 of 3 artifacts; E2 tautological
  counts; per-check fixture isolation; B2's missing positive control.
* **B7 remains un-passable** pending your specification decision. Layer B
  cannot reach 9/9 before that is answered.
* **No Pass 4 has run.** Every claim above is unit-level.
* **`run_fixtures.sh` and the fixture tree were modified during this repair**,
  which makes them UNTRUSTED under your own rule until Pass 4 revalidates them
  independently.

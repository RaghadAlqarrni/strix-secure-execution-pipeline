# Phase 1 corrected3 requirement/test matrix

Disposition: `CORRECTED3_CANDIDATE_READY_FOR_INDEPENDENT_REVIEW`

| Requirement | Implementation | Deterministic evidence |
|---|---|---|
| AUTH has a shared positive unique sequence; delayed durable AUTH is conservative | `RunContext.authorize`, `EffectGate.commit_intent`, E10 AUTH branch | `test_f02_f03_repaired.py`: delayed AUTH barrier and no post-cancel permit; `test_e10_lifecycle.py`: valid/invalid late AUTH |
| Exactly one durable bound release per durable permit | `EffectPermit.release`, `PERMIT_RELEASED` schema/grammar | E10 missing/duplicate/order/binding/post-close mutations; gateway success and idempotent-release assertions |
| Sequence-only cancellation count | E10 computes exactly `P < C < R`; enforces `A < P < R`, `P < C`, global uniqueness | E10 `P<R<C`, `P<C<R`, `P>=C`, reused sequence, permit append before/after cancellation, terminal-before-release case |
| Cancellation request binding | Request carries the new cancellation epoch and `C`; linearization cross-checks both | E10 valid histories and request epoch/sequence contradiction mutations |
| Release failure frees memory but blocks closure | Release linearizes before append and raises `AuditUnhealthy`; `cancel_and_quiesce` checks audit health | Gateway `fail-release` fault: memory zero, no release, no ACK/RUN_CLOSED |
| Mandatory truthful quiescence | Closed schemas plus `count_error`; exact ACK/TIMEOUT/RUN_CLOSED semantics | Field deletion and contradictory-count mutations for KILL_SWITCH, ACK, TIMEOUT, RUN_CLOSED; producer/listener timeout fixtures |
| Sole semantically bound KILL_SWITCH | Dedicated cardinality/order/binding branch before disposition | Missing/duplicate/conflicting KILL_SWITCH and epoch/sequence/listener/drain/enforcement mutations |
| Every recognized record is semantically validated | Explicit branches; no contextual fall-through | ALLOW fact mutation loop; valid/orphan/mismatched/duplicate CONNECTION_TERMINATED; startup position; unknown decision schema rejection |
| No append or release after close seal | Existing `AuditLog.seal_with`; release held inside producer lifetime | Quiescent close/reopen byte/hash immutability and explicit post-seal `PERMIT_RELEASED` rejection |
| Expected anchor key ID and limited trust scope | Existing verifier expected-key comparison retained | Positive fixture remains non-certifying; wrong key ID, unsigned anchor, authenticated contradictory anchor rejected |

## Required command groups

| Group | Command |
|---|---|
| Supplied five cases | `E10_REPO=... python3 .../independent_corrected2_adversarial.py` |
| E10-v2 protocol | `python3 pep/fixtures/test_e10_lifecycle.py` |
| Runtime lifecycle | `python3 pep/fixtures/test_f02_f03_repaired.py` |
| Real gateway path | `python3 pep/fixtures/test_gateway_lifecycle.py` |
| Quiescence and sealing | `python3 pep/fixtures/test_quiescent_shutdown.py` |
| Exact historical negative control | `python3 pep/fixtures/phase1_baseline_repro.py` |
| E1-E9/F01/audit fixtures | `bash pep/fixtures/run_fixtures.sh` |
| P0 proofs | `bash pep/fixtures/p0_proofs/run_p0_proofs.sh` |
| P1 proofs | the three scripts under `pep/fixtures/p1_proofs/` |
| Static checks | `python3 -m compileall -q pep phase2a phase2b`; `git diff --check` |

All commands are local. No production/external target or external-network test
is part of this matrix.

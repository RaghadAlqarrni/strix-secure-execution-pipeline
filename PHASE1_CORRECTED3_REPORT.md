# Phase 1 corrected3 protocol correction report

Date: 2026-09-11

Disposition: `CORRECTED3_CANDIDATE_READY_FOR_INDEPENDENT_REVIEW`

## Identity and pre-change reproduction

Work began only after confirming branch
`recovery/f02-f03-v10-20260910`, HEAD
`7690f1b5a87c50a25e3ab863fd08d3b1005cfc77`, and a clean worktree. The
independent corrected2 adversarial program reproduced all five reported
findings before any edit:

```text
minimal_close_omits_quiescence_fields PROVEN
ack_explicitly_contradicts_quiescence PROVEN
kill_switch_contradicts_ack PROVEN
orphan_connection_terminated PROVEN
terminal_written_before_release_but_cancel_counts_permit INFLIGHT_LINEARIZATION_MISMATCH
```

The protocol was frozen first in `E10_V2_TRANSITION_SPEC.md`.

## Correction

- `RunContext` is the single lock and positive sequence authority for AUTH,
  permit, release, and cancellation. It prevents a second permit for one
  attempt.
- AUTH obtains its sequence before durable append. A delayed append remains
  admissible only with `A < C`, the cancelled epoch, and no post-cancel effect.
- Releasing a permit removes it from memory and assigns `R` atomically, then
  writes one bound `PERMIT_RELEASED`. Failed release evidence frees memory for
  safety, propagates `AuditUnhealthy`, and prevents ACK/closure.
- The verifier reconstructs cancellation in-flight state only from
  `P < C < R`; terminal append position has no concurrency meaning.
- CANCELLATION_REQUESTED binds the same cancellation epoch and sequence as the
  subsequent linearization record.
- KILL_SWITCH, ACK, TIMEOUT, and RUN_CLOSED have mandatory quiescence fields.
  Every applicable record enforces `inflight = permits + producers`.
- Exactly one KILL_SWITCH is required after attempt terminal/ALLOW/release
  records and before ACK xor TIMEOUT. Its cancellation and quiescence facts
  must match the disposition.
- Every accepted decision has an explicit semantic branch. ALLOW binds the
  available authorization, attempted-effect and terminal facts.
  CONNECTION_TERMINATED binds an existing attempted UNKNOWN outcome's attempt,
  connection, pin, method, URL authority, and byte count. Startup and policy
  contexts are position checked.
- RUN_CLOSED remains the sole atomic `AuditLog.seal_with` record. Listener and
  producer drain prevents a release writer from racing the seal; the absorbing
  writer lock also rejects explicit post-seal release attempts.

## Local verification scope

Deterministic local tests cover the supplied corrected2 cases, the full E10-v2
mutation matrix, release/cancellation append schedules, delayed AUTH and permit
append, gateway fault barriers, release-audit failure, shutdown timeout,
startup STOP_ALL, post-kill admission, audit seal/reopen/immutability, the exact
historical F02/F03 negative control, E1-E9/F01 fixtures, P0 proofs, and P1
proofs. The immutable export contains raw command logs and the requirement/test
matrix.

No Strix, Docker, autonomous agent, production/external target, or external
network test was run. The dual-stack P1 proof used loopback only.

## Trust boundary

The expected anchor key ID remains a caller-selected mandatory input. Fixture
HMAC keys demonstrate local mechanics only. External key custody/isolation,
trusted configuration, rotation/revocation, external enforcement, WORM or
externally append-only publication, target-filesystem compatibility, measured
host latency, production behavior, release eligibility, and independent review
remain unperformed or unproven.

Disposition: `CORRECTED3_CANDIDATE_READY_FOR_INDEPENDENT_REVIEW`

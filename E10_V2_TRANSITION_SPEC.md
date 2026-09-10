# E10-v2 frozen transition specification

Version: `E10-v2` (frozen before corrected3 implementation)

This specification defines the only audit histories that E10-v2 may prove.
It coordinates durable append order with one global lifecycle order.  The
global order is authoritative for concurrency; JSONL position is authoritative
only for the per-attempt and run-closure grammars stated below.

## Common and required fields

Every record has exactly `decision`, `run_id`, finite `ts`, and the hash-chain
`prev`, plus the fields allowed for its decision.  Identifiers are non-empty
strings.  Counts and epochs are non-negative integers.  Every lifecycle
sequence is a positive integer.

The shared `RunContext` lock allocates one globally unique `lifecycle_seq` for
each `AUTH_COMMITTED`, `PERMIT_GRANTED`, `PERMIT_RELEASED`, and the sole
`CANCELLATION_LINEARIZED`.  Let these sequences be `A`, `P`, `R`, and `C`.

Required transition fields are:

- `AUTH_COMMITTED`: `lifecycle_version=E10-v2`, `attempt_id`, `conn_id`,
  `epoch`, `lifecycle_seq=A`, `program_id`, `policy_generation`,
  `budget_binding`, method/canonical host/pin, `credential_ref`, and a
  sanitized `request_intent_digest`.
- `PERMIT_GRANTED`: attempt, connection, epoch, `lifecycle_seq=P`, policy
  generation, and budget binding, all equal to AUTH.
- `EFFECT_ATTEMPTED`: attempt, connection, epoch, `permit_seq=P`, and the
  authorized pin when network I/O is attempted.
- A terminal transition: exactly one of `EFFECT_COMPLETED`, `EFFECT_FAILED`,
  `EFFECT_OUTCOME_UNKNOWN`, or `EFFECT_CANCELLED`, bound to attempt,
  connection, epoch and (after a permit) `permit_seq=P`; outcome-specific
  status/hash/byte/reason facts are required by its schema.
- `ALLOW`: the complete authorization, pin, attempted-effect, terminal status,
  response, byte, and sanitized request facts; it is required exactly once
  after `EFFECT_COMPLETED` and must equal the bound AUTH/attempt/terminal facts.
- `PERMIT_RELEASED`: attempt, connection, epoch, `permit_seq=P`, and
  `lifecycle_seq=R`.
- `CANCELLATION_REQUESTED`: reason, `cancellation_epoch`, and the bound
  `lifecycle_seq=C` subsequently carried by CANCELLATION_LINEARIZED.
- `CANCELLATION_LINEARIZED`: `cancelled_epoch`, `new_epoch`,
  `lifecycle_seq=C`, and `inflight_at_linearization`.

KILL_SWITCH and each ACK/TIMEOUT record require `cancellation_epoch`,
`lifecycle_seq=C`, `local_drain_complete`, `inflight_remaining`,
`effect_permits_remaining`, `audit_producers_remaining`, `listener_state`, and
`external_enforcement`; they also require their existing reason/scope and
connection-termination fields.  At every such record:

`inflight_remaining = effect_permits_remaining + audit_producers_remaining`.

`RUN_CLOSED` requires its closure schema/sequence/state plus all three zero
counts, `listener_state=STOPPED`, `admission_state=TERMINAL`,
`seal_action=FINAL_FSYNC_THEN_ATOMIC_SEAL`, and
`cancellation_disposition=CANCELLATION_ACK`.

## Per-attempt durable grammar

The normal append order is:

`AUTH_COMMITTED -> PERMIT_GRANTED -> [EFFECT_ATTEMPTED] -> terminal ->
[ALLOW iff completed] -> PERMIT_RELEASED`.

AUTH without a permit may terminate conservatively without an effect.  An AUTH
whose append is durably late (after cancellation records) is allowed only when
`A < C`, it obtains no permit with `P >= C`, and its attempt ends without any
post-cancellation effect.  A permit-bearing attempt has exactly one durable
release before ACK or RUN_CLOSED.  Release is idempotent in memory but not in
the audit grammar: missing or duplicate release is invalid.

The release linearization point, under the shared `RunContext` lock, removes
the permit from memory and allocates `R`.  The handler remains an audit producer
until `PERMIT_RELEASED` is durably appended.  If that append fails, memory is
still released for safety, the audit sink remains latched unhealthy, and no
ACK or RUN_CLOSED may be written.

## Global sequence equations

All `A/P/R/C` values are unique.  For a permitted attempt:

- `A < P < R`.
- If cancellation exists, `P < C`; permits with `P >= C` are forbidden.
- The permit is in flight at cancellation exactly when `P < C < R`.
- It is already released at cancellation exactly when `P < R < C`.
- Therefore `inflight_at_linearization` equals the number of permits satisfying
  `P < C < R`.  Terminal append position is never a release proxy.

Durable append order may differ from lifecycle sequence order across attempts,
including AUTH or release records appended after cancellation.  The equations,
not timestamps or cross-attempt JSONL position, decide concurrency.

## Cancellation and closure grammar

For gateway-produced histories the run grammar is:

`[STARTUP_DEGRADED]* -> STARTUP -> active records -> CANCELLATION_REQUESTED ->
CANCELLATION_LINEARIZED -> remaining terminal/release records -> KILL_SWITCH ->
(CANCELLATION_ACK xor CANCELLATION_DRAIN_TIMEOUT) ->
[RUN_CLOSED iff ACK]`.

There is exactly one semantically bound KILL_SWITCH.  It follows all attempt
terminal and release records and precedes the sole disposition.  Its epoch,
sequence, enforcement, listener, local-drain, and count facts must agree with
the cancellation and disposition.  ACK requires all counts zero, local drain
true, listener STOPPED, and local external enforcement only; TIMEOUT requires a
real nonzero/not-stopped blocker and forbids RUN_CLOSED.  RUN_CLOSED is the
sole final record and atomically seals the writer.  The stopped listener,
zero producers, zero permits, audit health latch, and absorbing audit seal prove
that neither a normal record nor PERMIT_RELEASED can append after it.

## Contextual records

Every recognized decision has an explicit semantic branch; schema-only fall
through is forbidden.  STARTUP, when present, precedes every active record
(minimal verifier fixtures may omit it).  STARTUP_DEGRADED and STARTUP_FAILED
are legal only during startup before active effects; FAILED is terminal for
startup.  BLOCKED_BY_POLICY must not claim an effect attempt.
CONNECTION_TERMINATED must name an existing attempted effect whose sole terminal
outcome is UNKNOWN and must equal that attempt's connection, pin, and streamed
byte count.  No contextual record may appear after disposition or closure.

## Trust boundary and disposition

Verification requires the caller-selected expected anchor key ID and checks the
authenticated close anchor.  This proves only the local evidence mechanism.
External key custody/isolation, trusted configuration, rotation/revocation,
external enforcement, append-only/WORM publication, production behavior, and
release readiness remain outside this protocol and are not claimed.

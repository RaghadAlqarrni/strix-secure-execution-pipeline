# F03/F02/E10 lifecycle design — Phase 1 corrected3 candidate

Status: **CORRECTED3_CANDIDATE_READY_FOR_INDEPENDENT_REVIEW** on branch
`recovery/f02-f03-v10-20260910`. This document describes the code as implemented.
It is implementer-produced local evidence only and makes no deployment claim.

## Target-effect authorization protocol

The target-side effect boundary begins at upstream `connect`; DNS and other
control-plane lookups happen earlier and can have their own network effects.
For each request the gateway performs these ordered steps:

1. The PDP authorizes the method against the retained destination pin. Its
   decision carries the program, policy generation and conservative budget-scope
   binding. Historical policies without an explicit `policy_generation` use the
   authorization `verified_at` value as a compatibility fallback.
2. The gateway creates a unique attempt ID and fsyncs an `AUTH_COMMITTED` record.
   Under the shared `RunContext` lock, AUTH receives its own positive unique
   lifecycle sequence before append. The E10-v2 intent binds the control-issued
   run ID, connection/attempt IDs,
   cancellation epoch, program, policy generation, budget scope, method,
   canonical destination/pin, credential reference and a sanitized request
   intent digest.
3. The policy is read again using the retained pin, so this check performs no
   DNS lookup and does not charge budget a second time. Any changed decision,
   program, pin, policy generation or budget binding refuses the attempt.
4. The upstream socket is created and registered under the connection ownership
   lock before `connect`.
5. AUTH allocation, `RunContext.issue_permit()`, permit release, and
   `RunContext.cancel()` share one condition lock and sequence counter. Permit
   issuance either wins first and increments the in-flight count, or
   cancellation wins first and the permit is refused.
6. `PERMIT_GRANTED` and `EFFECT_ATTEMPTED` are fsynced before `connect` runs. If
   either audit write fails, the permit is released and no target effect runs.
7. The permit stays in-flight across connect, TLS, request send, and response
   streaming. A terminal/unknown outcome is written first. Release then removes
   the in-memory permit and allocates its sequence under the shared lock, and
   fsyncs one bound `PERMIT_RELEASED`. The handler remains an audit producer
   until that append completes. A release append failure still frees memory for
   safety, latches audit unhealthy, and forbids ACK/closure.

The old `request_hash` was a SHA-256 of `raw_req`, which included the injected
Authorization header. E10-v2 retains the corrected semantics: `request_hash` contains
the hex portion of `request_intent_digest` and `request_hash_semantics` is
`sanitized-intent-v2`. The digest covers version, method, canonical authority,
path and body length, never the credential-bearing wire request. Historical
E1-E9 verifiers still receive the required 64-hex field; E10 requires the new
semantics on current-profile ALLOW records.

## Monotonic cancellation and acknowledgement

A run moves once from RUNNING to CANCELLED. Removing `STOP_ALL` does not rearm
it; `Registry.rearm()` is retained as a compatibility no-op and a new process/run
epoch is required.

The watcher first invokes the shared cancellation linearization authority, which
atomically increments the epoch and assigns `CANCELLATION_LINEARIZED` a lifecycle
sequence. Permits granted before that sequence may already be in flight. No
permit can be granted after it. Immediately after linearization, the registry
closes connection and audit-producer admission, snapshots/removes its
connections, and marks **every** victim
terminal before initiating shutdown/close on the retained handles outside the
global lock. Listener shutdown is initiated before cancellation evidence is
written. Only after those enforcement steps have run may audit storage be
touched. The audit then durably records `CANCELLATION_REQUESTED` followed by
`CANCELLATION_LINEARIZED`; their record order expresses the logical request and
linearization order even though persistence is deliberately downstream of
enforcement. The request carries and is checked against the same cancellation
epoch and sequence as the linearization record.
Socket registration and TLS ownership transfer share each connection's terminal
lock: a handle is either retained before teardown or rejected and closed after
terminal state; there is no unowned usable late handle.

The server is created, initialized, and its `STARTUP` record fsynced before the
kill watcher starts. Every handler is counted for its whole audit-producing
lifetime, including handlers that never obtain an effect permit. Closure waits
for effect-permit drain, handler/audit-producer drain, and confirmed listener
shutdown. It writes `CANCELLATION_ACK` only when all three are complete with
zero remaining operations **and** the request, linearization, sole semantically
bound `KILL_SWITCH`, every terminal/ALLOW/release record, and all mandatory
quiescence facts are durable. `inflight_remaining` must always equal effect
permits plus audit producers. Otherwise it writes
`CANCELLATION_DRAIN_TIMEOUT`, which is explicitly not an acknowledgement.
After a durable ACK it writes an absorbing `RUN_CLOSED` record binding the
closure schema/sequence/state, terminal admission, zero in-flight count, and the
ACK disposition. `AuditLog.seal_with()` fsyncs that final record under the writer
lock and atomically makes the writer reject every later append; reopening a log
whose final valid record is `RUN_CLOSED` restores the seal. Timeout, remaining
producer/listener, or audit failure omits `RUN_CLOSED`. Audit failure never
prevents enforcement, but it leaves admission closed and the evidence
insufficient.
`KILL_SWITCH.terminated_conn_ids` continues to name only handles actually shut
down for historical E1-E9 compatibility. The Phase 1 acknowledgement scope is
`LOCAL_IN_PROCESS_DRAIN_ONLY`; `external_enforcement` is recorded as
`NOT_RUN_PHASE1`.

Cancellation does not recall bytes already handed to the kernel or target.
Connect/TLS/send/stream interruption after `EFFECT_ATTEMPTED` is conservatively
`EFFECT_OUTCOME_UNKNOWN`. There is no automatic retry or exactly-once claim.

## Audit writer and recovery

The production entrypoint requests exclusive writer ownership through an
advisory `flock` on a path-specific lock file. A second production writer fails
startup. A new audit file is created and fsynced, followed by parent-directory
fsync, before service. Existing logs are fully chain-verified before accepting
the tail. Corrupt or torn bytes are preserved, the health latch becomes false,
and further writes/permits are refused.

Writes use `O_APPEND`, loop until every byte is written, reject zero progress,
fsync every record, and latch unhealthy on short-write failure, ENOSPC, EIO or
sync failure. The same re-entrant lock protects the hash-chain tail, health and
redaction set, so adding a secret cannot race record scrubbing. Blocking socket
shutdown never occurs under the registry or lifecycle-global lock.

## E10 deterministic state machines and completeness protocol

`pep/verify_e10.py` consumes records using the frozen
`E10_V2_TRANSITION_SPEC.md`, explicit per-attempt and
per-run state machines and a closed, versioned schema/field allowlist for every
recognized decision. Unknown decisions, missing/extra fields, and invalid field
types are rejected. Legal attempt transitions are enumerated; completed,
failed, unknown, and cancelled states are absorbing. The run machine requires
exactly `CANCELLATION_REQUESTED -> CANCELLATION_LINEARIZED -> KILL_SWITCH ->
(ACK xor DRAIN_TIMEOUT)`, permits no close after timeout, and makes `RUN_CLOSED`
absorbing. It validates mandatory fields and bindings at the transition where
they occur. An attempted effect without a terminal record returns
`INCOMPLETE_ATTEMPT` with
`INDEPENDENT_REVIEW_REQUIRED_NO_AUTOMATIC_RETRY`; it cannot return `PROVEN`.
Historical logs without E10-v2 intents cannot
satisfy the current profile.

Lifecycle sequence, not cross-attempt append position, defines concurrency.
Every AUTH, permit, release, and cancellation sequence is a unique positive
integer. For permit `P`, cancellation `C`, and release `R`, the permit is
in-flight exactly when `P < C < R`; `P < R < C` means it was already released.
Terminal-record position is never used as a release proxy. Every permit
sequence must be lower than the cancellation sequence. A
permit record appended after cancellation evidence may be accepted only when
its lower sequence, cancelled epoch, authorization bindings, and legal absorbing
terminal and release state all agree before ACK/closure. Each gateway `EFFECT_COMPLETED`
requires exactly one later `ALLOW` bound to the same attempt, connection,
request digest, response digest, and upstream status; an ALLOW must follow its
completion and cannot be replayed.

EOF and the local SHA-256 chain do not prove completeness. Current-profile
`PROVEN` additionally requires an explicit expected Run ID and source commit, a
final valid `RUN_CLOSED`, and an `E10-close-anchor-v1` object binding schema, Run
ID, source commit, record count, byte length, final chain hash, closure sequence,
and closure state. The anchor must carry a valid HMAC-SHA256 tag under a
separately supplied control-plane authority key of at least 32 bytes.
The verifier also requires `expected_authority_key_id` as an independent input
and compares it to the identity inside the already authenticated anchor; the
evidence object cannot choose which authority identity the caller trusts.

`pep/e10_anchor.py` is the authority-side issuer. The gateway neither imports it
nor accepts an anchor key. A gateway-created unsigned sidecar cannot satisfy the
verifier. Local fixtures use an explicitly named test key and return
`LOCAL_FIXTURE_PASS_NON_CERTIFYING`, never a certifying verdict.

Every accepted contextual record has a semantic branch. In particular,
`CONNECTION_TERMINATED` must bind an attempted UNKNOWN outcome's attempt,
connection, pin, and byte count; ALLOW binds all available authorization,
attempt, terminal, pin, byte, status, and hash facts; startup records are
position checked; and KILL_SWITCH is cardinality/order/fact checked.

The local suites include exact-base F02/F03 negative controls, 100 concurrent
permit/cancel schedules, registration/connect/TLS/pre-send/stream cancellation,
normal gateway flow, audit failure before connect, short/zero writes,
ENOSPC/EIO, delayed fsync, second writer, corrupt/torn restart, redaction
concurrency, blocked/failing cancellation audit, explicit crash/incomplete
outcomes, both deterministic permit/cancellation append orders, exhaustive
known-record schema mutations, unknown decisions, completion/ALLOW pairing,
startup with STOP_ALL present, delayed non-permitted producers, post-kill
admission, closure timeouts, absorbing audit sealing, all post-terminal
transitions, contradictory dispositions, suffix and component deletion, and
every anchor binding mismatch. These tests use
socketpair/test doubles, temporary files, and fixture-only keys.

## Residual integration limits

- No Docker, Strix, production target, V9/V10 activation, host firewall change,
  or external network measurement ran in Phase 1.
- External egress revocation/termination acknowledgement and a numeric host
  latency bound remain integration gates. Local drain is not a host or packet
  drain claim.
- Control-plane key custody/provisioning/rotation, gateway/sandbox key isolation,
  independently observed process quiescence, and external append-only/WORM
  anchor publication were not available or executed. Phase 1 proves only the
  strict interface and local test-key mechanics; it does not prove external
  anchoring.
- The historical `verified_at` policy-generation fallback preserves E1-E9 lab
  policies but is weaker than a mandatory monotonic control-issued generation;
  the release policy must provide the explicit field.
- The budget binding rechecks the existing conservative per-connection scope.
  Durable budget reservations across restart and full F06/R09 semantics remain
  outside this bounded repair.
- A crash after `EFFECT_ATTEMPTED` leaves an unknown target outcome. Recovery
  requires review/reconciliation and does not retry automatically.
- Advisory writer locking and directory fsync were locally fault-tested; exact
  target-filesystem behavior remains a deployment compatibility fact.
- Track B and the V10/S0E evidence chain were not executed by this correction.
  No production-readiness conclusion follows from these local results.

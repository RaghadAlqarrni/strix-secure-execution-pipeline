# Release requirements matrix — Phase 1 corrected3 working baseline

State: PRE-PRODUCTION. C6 is preserved. F01 is an implemented candidate with local tests; independent validation remains pending. The owner has delegated engineering decisions; this matrix is a working requirements baseline, not evidence of satisfaction.

Each required row is a conjunction, never a score. Missing/unknown/contradictory evidence blocks its claim. Evidence must bind candidate, configuration, image, policy and Run ID as applicable. Technical owner is Codex acting under the current delegation; validation is a separately identified reviewer/run, never inferred from author labels.

| ID | Requirement / exact acceptance predicate | Implementation owner / surface | Required artifact and evidence | Current status | Release effect |
|---|---|---|---|---|---|
| R01 | Source/config/image identities equal the identities tested and reviewed | Build/release controller | Frozen manifest, source commit, image digest/platform, build provenance, independently checked hashes | C6 identity verified; future image/build not verified | Block |
| R02 | Production E9 cannot pass without every required raw artifact and all raw checks passing | Evidence verifier | Positive sealed baseline; each missing-artifact and contradiction test; nonzero absence result | F01 candidate implemented; local tests pass; independent/Linux validation pending | Block until validated |
| R03 | Fixture-only validation cannot emit production certification or success exit status | Evidence verifier | CLI separation tests for both auditor and E9 | F01 candidate implemented; fixture success exits 3; independent validation pending | Block until validated |
| R04 | New egress authorization requires a durable intent; unhealthy audit closes admission; a current-profile proof requires a closed run and authenticated external anchor | PEP/audit writer + control-plane anchor authority | ENOSPC/EIO/short-write/crash tests, deterministic lifecycle tests, exact byte-range anchor, separately provisioned authority key, external observation | State machine/interface LOCAL_TESTED; external authority/key isolation/WORM publication and independent review NOT_RUN | Block until independently validated and externally anchored |
| R05 | Cancellation is monotonic and prevents newly authorized effects after its linearization point; enforcement starts before audit storage; acknowledgement follows local drain and durable evidence | PEP/lifecycle supervisor | Barrier-driven socket/audit races; audit-fault enforcement; host-observed drain; numeric latency bound fixed before measurement | Local ordering and fail-closed behavior LOCAL_TESTED; external enforcement, host drain and latency NOT_RUN | Block until independently validated and integrated |
| R06 | Authorized requests retain supported HTTP semantics regardless of transport segmentation | PEP protocol engine | Body/header/protocol matrix, boundary split tests, authenticated component probes | F04 OPEN | Block |
| R07 | Admission/work/FD/byte limits and an end-to-end monotonic deadline cover every phase | PEP/runtime | Slow-client/DNS/TLS/subprocess/overload tests; measured limits; no global resolver timeout mutation | F05 OPEN; exact ceilings pending compatibility | Block |
| R08 | Authorization subject, finite validity, run/session/asset/destination/action bindings are complete and control-issued | PDP/identity service | Strict schema and negative identity/credential tests | F06 OPEN | Block |
| R09 | For each scope, spent + reserved <= limit across concurrency, reload and restart | Budget authority | Transaction/reservation evidence; omitted-label, reload, restart and duplicate-operation tests | F06 OPEN | Block |
| R10 | Selected Track A IPv4/IPv6 claims retain their frozen semantics under the new runtime | PEP/network backend | Fresh affected-property regression and host/raw evidence on candidate | Historical C6 only | Block |
| B-T1 | Selected occupied cross-execution IPv4/IPv6 L3 flows denied, including same-program peers | Track B backend | Two executions, occupied controls, exact attempted tuples and enforcement telemetry | Unimplemented | Block |
| B-T2 | Only frozen role/protocol/port/direction/lifetime peers reachable | Track B backend | Run role manifest, configuration + occupied endpoint tests | Unimplemented | Block |
| B-T3 | Versioned critical host/runtime inventory inaccessible and absent from launch configuration | Track B backend | Socket/API/mount/device/namespace/canary probes and raw effective state | Unimplemented | Block |
| B-T4 | Non-root, NoNewPrivs, exact effective/permitted/bounding/ambient/inheritable caps | Track B backend | Kernel state and privilege-operation tests, not inspect alone | Compatibility pending | Block |
| B-T5 | Read-only root; declared ephemeral writes work; selected state absent next run | Track B backend | Write matrix and fresh-run persistence probes | Compatibility pending | Block |
| B-T6 | Finite CPU/memory/PIDs/storage bytes+inodes/wall-time/request ceilings effective | Runtime controller | Frozen numeric profile; bounded exhaustion and peer/host liveness | Values pending compatibility | Block |
| B-T7 | Target credentials PEP-only; provider authority bounded by model/provider/lifetime/budget and revocable | PEP/provider broker | Launch/storage inventory, broker interface tests, leakage/revocation/budget tests | Unimplemented; provider facts unknown | Block |
| B-T8 | Named unnecessary syscall classes denied while required components function | Runtime profile | Architecture-specific frozen seccomp and kernel-attributed positive/negative tests | Compatibility pending | Block |
| B-T9 | One control-issued Run ID owns resources; normal/abnormal teardown leaves no enumerated residue | Lifecycle controller | State transitions, inventory, crash/restart/reconciler tests | Unimplemented | Block |
| B-T10 | Track B does not weaken affected Track A properties | Integration validator | Fresh R10 regression bound to exact final candidate | Not run | Block |
| R11 | S0E durable package follows all 15 reviewed V10 obligations and stated operational/crash envelope | Evidence acquisition | Exact contract/code hashes, FD/mount identity, fault matrix, actual-byte rereads, sync/close outcomes | Reviewed text only | Blocks compatibility evidence reliance |
| R12 | Transport preserves the sealed package; host verification uses a separately trusted hash | Transport/host verifier | Exact inventories; missing/extra/corrupt-file tests; independent Windows hashes | Not implemented | Blocks exported-evidence reliance |
| R13 | Real frozen Strix/browser/Caido components function under the exact proposed profile | Compatibility investigator | Passive inventory then bounded non-agent component manifest/raw observations | Image/source facts not established | Blocks Track B freeze |
| R14 | Builds, upgrades, rollback, CA rotation and critical dependency failures have bounded procedures | Operations/build controller | Pinned inputs, SBOM/provenance, clean build, operational drills | Not established | Block |
| R15 | Selected security claims use declared independent evidence or explicit shared-TCB exception | Evidence owner/reviewer | Claim-to-observer map, controls, falsification corpus and residual-risk record | Partial historical evidence | Block |
| R16 | End-to-end research output meets predeclared discovery/reproduction/false-positive/cost criteria | Product evaluator | Authorized seeded benchmark, repeated runs, independent reproduction and uncertainty | Not established; thresholds pending benchmark definition | Block |
| R17 | ReleaseEligible = identities_match AND all_required_claims_proven AND all_mandatory_checks_pass AND no_unresolved_blockers AND authorization_valid | Release controller | Machine-readable evaluation over exact final candidate | Not eligible | Final gate |

## Scope decisions and dependencies

1. R06 initially requires ordinary HTTP/1.1 request/response fidelity, including fixed-length/chunked bodies, cookies, content type, redirects and binary/multipart uploads. HTTP/2, WebSocket, streaming and intentionally malformed protocol research require explicit compatibility classification; there is no claim they already work. Final supported product scope remains a release-critical open requirement.
2. R08/R09 cannot trust optional X-Strix-Asset or X-Strix-Session as authority. The future control-issued identity and reservation token must bind these fields and policy generation. Pin is destination data, not authorization proof.
3. R05 does not promise recall of already transmitted bytes. The final measured kill acknowledgement bound is fixed against the actual host before validation, not selected retrospectively to make a test pass.
4. R11 → R12 → evidence-backed R13 → final Track B profile. Local F01 and PEP work can proceed before that chain completes because their current source and synthetic reproductions are available.
5. All unknown numerical ceilings, protocol coverage, benchmark thresholds and operational premises above are explicit blocking facts, not silent defaults. Each must be replaced by a versioned decision and test before its gate can pass.

## Current work queue

1. IMPLEMENTED CANDIDATE: R02/R03 F01 default-deny raw-evidence verification; local regression and historical evidence replay pass. Independent and target-Linux validation remain pending.
2. CORRECTED3 CANDIDATE: E10-v2 shared AUTH/permit/release/cancellation sequencing, sequence-only in-flight reconstruction, durable release evidence, mandatory quiescence facts, sole bound KILL_SWITCH, explicit contextual semantics, quiescent shutdown, absorbing final audit seal, and caller-selected expected anchor-authority identity. Local test-key mechanics and deterministic races pass; independent review, external anchor custody/publication, key isolation, host enforcement, filesystem compatibility, and latency measurement remain pending/not run.
3. READY FOR PREPARATION: V10 obligation-to-test mapping and passive local Strix baseline inventory.
4. WAITING ON FACTS: real component compatibility and final Track B profile.
5. LOCKED BY FAILED REQUIREMENTS: production eligibility and autonomous/target execution.


## Phase 1 current-profile note (2026-09-10)

E10 is required in addition to E1-E9 for a current lifecycle profile. Historical
profiles retain their historical scope and cannot satisfy E10 by record shape or
by replay. Local E10 fixture success is implementer evidence under a
non-production test key only. EOF is never completeness proof, and an unsigned
gateway sidecar is never sufficient. The verifier requires a separately supplied
expected authority key ID as well as the trusted key; anchor contents cannot
select their own trust identity. Release remains blocked by separate review,
control-plane anchor custody and append-only/WORM publication, key isolation,
explicit production policy generation, external egress
enforcement/acknowledgement, target filesystem facts, and a predeclared host
latency bound. Track B and production readiness remain unproven.
`request_hash` on E10-v2 ALLOW records has
`sanitized-intent-v2` semantics; it no longer hashes the credential-bearing wire
request.

`RUN_CLOSED` requires a stopped listener, zero effect permits, zero active
handler/audit producers, terminal admission, the exact seal action, and ACK
disposition. KILL_SWITCH and ACK/TIMEOUT require the full quiescence vector and
its sum equation. The writer fsyncs closure and changes to an absorbing sealed
state under the same append lock. Timeout, failed release/audit write, or any
remaining producer omits closure. Shared AUTH/permit/release/cancellation
sequence numbers determine logical concurrency; a permit is in flight exactly
for `P < C < R`, never by terminal append position. These are local runtime
and verifier properties only. No Docker/Strix/external target was run, and no
new claim is made for host enforcement, measured latency, target filesystems,
Track B, V10/S0E execution, external anchor operation, or deployment readiness.

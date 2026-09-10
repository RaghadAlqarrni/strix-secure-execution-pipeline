# DEC-7 — B7 IPv6 link-local / multicast design study

Status: **DECISION REQUIRED — release remains blocked**  
Evidence bundle: `dec7-b7-run-evidence.tar.gz`  
SHA-256: `065c35c67aec32ce835a945a818b527e84788089425b070f2b7350e0f13b32bd`

## Observed state

The fresh eligible-host run produced:

- Layer A: 30/30
- IPv4 regression: 17/17
- Layer B: 8/9
- Evidence audit: 7/8
- B7: `NOT_PROVABLE_IN_TOPOLOGY:ll=TIMEOUT,mc=NO_ROUTE`
- gate exit: 1

The run is valid evidence of an unresolved claim. It is not evidence of a leak,
and it is not evidence that link-local or multicast transport was blocked.

## Why the current row cannot become PROVEN

1. `fe80::1` is an unoccupied synthetic peer. A timeout is compatible with both
   netfilter DROP and ordinary neighbour-discovery failure.
2. Link-local traffic is scoped to the sandbox's own L2 link. A live peer placed
   there measures same-network peer isolation, not off-link egress containment.
3. TCP `connect()` to `ff02::1` is not a valid multicast service/control model.
   `NO_ROUTE` cannot establish that multicast packets were filtered.
4. Treating any of those local failures as PROVEN would restore the false-green
   route removed before Pass 5.

## Decision options

### Option A — Recommended: split the claims

Keep B7, but rewrite it into independently testable properties:

- **B7-L2:** same-program/same-link peer reachability is explicitly documented
  as outside the egress-boundary claim. If peer isolation is required, create a
  separate requirement and test it with an occupied link-local TCP peer.
- **B7-MC:** test multicast as multicast: controlled UDP sender plus an occupied
  receiver/counter on the same link. Require a positive apparatus control before
  applying the sandbox boundary, then require zero received probe datagrams.
- Do not use synthetic unoccupied addresses as proof.
- Do not allow either subtest to override B1/B3, which already prove direct
  off-link IPv6 egress blocked against the same live target reachable via PEP.

This option changes the specification and requires a remediation contract,
independent implementation, fresh Pass 6 audit, and DEC-6 re-freeze before any
new dual-stack release verdict.

### Option B — Require same-link peer isolation

Add an occupied link-local peer and require the sandbox not to reach it. This is
a stronger architecture requirement than egress containment and may require
per-container filtering or separate networks. It must not be introduced as a
mere test-fixture change.

### Option C — Leave B7 unchanged

The gate remains permanently blocked because the row intentionally has no honest
PROVEN branch in the present topology.

## Recommended decision

Adopt **Option A**. Preserve the release block until the rewritten claims have a
remediation contract and independent evidence. Do not retire B7, manufacture a
pass, alter the current result, or run Strix.

## Non-decisions

- This note does not approve a topology change.
- This note does not mark DEC-7 implemented.
- This note does not re-freeze DEC-6.
- This note does not authorize Strix observation.

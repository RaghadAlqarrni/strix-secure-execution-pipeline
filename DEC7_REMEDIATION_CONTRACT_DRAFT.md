# DEC-7 remediation contract / design memo — DRAFT FOR OWNER REVIEW

Status: **NOT APPROVED FOR IMPLEMENTATION**  
Scope: design only; no code, topology, gate, release, or Strix authorization  
Owner direction: Option A approved in principle, subject to this contract

## 1. Problem statement

Current B7 combines two different mechanisms and cannot honestly prove either:

- an unoccupied scoped link-local TCP address makes filtering indistinguishable
  from neighbour-discovery failure;
- TCP `connect()` is not a valid multicast test;
- both probes are sandbox-self-reported and lack authoritative receiver or
  enforcement-point evidence.

The valid VM run therefore remains `B7=NOT_PROVABLE_IN_TOPOLOGY`, Layer B 8/9,
evidence audit 7/8, gate exit 1.

## 2. Proposed claims

### B7-L2 claim

> A sandbox cannot exchange IPv6 unicast traffic with an occupied link-local
> peer that is on the same L2 segment but outside the sandbox's explicitly
> allowed peer set; the PEP peer remains reachable.

This is **same-link peer isolation**, not off-link egress containment. B1/B3
remain the authority for off-link IPv6 egress.

### B7-MC claim

> A sandbox cannot deliver an unauthorized IPv6 link-local multicast UDP probe
> to a live receiver on its L2 segment, while the same apparatus demonstrably
> delivers a control probe when enforcement is absent or from an authorized
> control source.

This is multicast delivery isolation, not a claim that all multicast protocols
or scopes are blocked.

## 3. Critical architecture finding

The current architecture documents that same-network peers can reach each other
and uses per-program networks. Consequently, B7-L2 as written above introduces
a **new, stronger security property**: per-sandbox peer isolation within a
program network. A test-only change would be invalid. Implementation would need
an enforcement mechanism below the sandbox namespace, such as host-controlled
bridge-family nftables/ebtables rules, while preserving sandbox-to-PEP traffic.

If per-sandbox peer isolation is not an intended product requirement, B7-L2 must
not be made a mandatory release row. That specification choice requires owner
resolution; it cannot be hidden inside remediation.

## 4. Candidate topology

One dedicated, disposable test bridge contains:

1. `gate_sbx`: measured sandbox; retains its adversarial capabilities.
2. `gate_gw`: explicitly allowed PEP peer.
3. `gate_l2_receiver`: host-controlled occupied peer with a known link-local
   address and TCP nonce receiver.
4. `gate_mc_receiver`: host-controlled UDP receiver joined to one fixed
   link-local multicast group on one fixed port.
5. `gate_control_sender`: trusted apparatus-control sender.

The host, not any measured container, owns enforcement rules, receiver logs,
rule counters, run ID, nonces, timestamps, and artifact collection. Receivers
must not share writable evidence paths with the sandbox.

### Enforcement boundary

Host bridge-family rules allow sandbox-to-PEP traffic and deny sandbox-to-other
same-link IPv6 unicast plus the selected multicast group/port. Rules must match
an identity the sandbox cannot change from inside its namespace. Source IP alone
is insufficient because the sandbox has `NET_ADMIN`; interface/bridge port and,
if needed, immutable host-side veth identity must anchor the rule.

## 5. Controls

### B7-L2 positive apparatus controls

1. Receiver readiness: host verifies the receiver is listening and records its
   occupied link-local address, interface index, and run ID.
2. Authorized control sender reaches the exact receiver and receives an echoed
   unpredictable nonce.
3. Sandbox reaches the PEP during the measured topology, proving the sandbox's
   IPv6 stack and required same-link path remain functional.

### B7-L2 negative/control-of-enforcement

In a separate calibration instance, identical except for the isolation rule,
the sandbox must reach the receiver and receive its nonce. This proves that the
measured denial is attributable to enforcement rather than topology. Calibration
and measurement use distinct run IDs and clean bridges; rule mutation mid-run is
forbidden.

### B7-MC positive apparatus controls

1. Receiver confirms group membership, interface, port, and readiness.
2. Authorized control sender transmits a unique UDP nonce to the exact group,
   scope/interface, and port; receiver records it.
3. A separate calibration instance proves a sandbox-originated nonce is
   receivable without the isolation rule.

### B7-MC measured negative

With enforcement active, the sandbox sends a fresh nonce. `PROVEN` requires all
of the following, not merely receiver silence:

- sender reports successful local send with exact group, scope, port, nonce;
- host enforcement counter for the exact sandbox veth/group/port increments;
- receiver does not record that nonce inside a bounded window;
- receiver records a post-measurement authorized control nonce, proving it did
  not die during the test.

## 6. Expected authoritative evidence

Every B7 artifact must be control-plane collected and bound to one run manifest:

- run ID and per-probe cryptographic nonce;
- container IDs, network ID, bridge name, host-side veth identities;
- link-local addresses and interface indexes;
- normalized host rule set plus before/after packet/byte counters;
- receiver readiness and timestamped nonce logs;
- calibration result from a distinct clean run;
- sandbox-to-PEP liveness result;
- teardown result showing no rules/networks leaked into later runs;
- hashes of scripts/images used.

Sandbox JSON is supporting evidence only. It cannot override host receiver logs,
enforcement counters, or contradictory raw observations.

## 7. Verdict and failure semantics

### B7-L2 may be `PROVEN` only when

- occupied receiver and successful calibration are established;
- PEP remains reachable in measurement;
- measured sandbox nonce is absent at receiver;
- exact host enforcement counter increments;
- post-control succeeds; and
- all identities/nonces bind to the same measurement manifest.

### B7-MC may be `PROVEN` only when

- group receiver and both pre/post controls succeed;
- separate sandbox calibration succeeds;
- measured UDP send is well-formed;
- exact host drop counter increments; and
- measured nonce is absent at receiver.

### `FAILED_OPEN`

The measured nonce reaches the unauthorized receiver, or the enforcement counter
does not reflect the expected disposition while receiver evidence shows delivery.

### `ENVIRONMENT_BLOCKED`

Required bridge netfilter/nft support, multicast membership, scoped addressing,
or immutable host-side identity is unavailable. This never becomes `PROVEN`.

### `APPARATUS_FAILURE`

Receiver readiness, calibration, pre/post control, evidence binding, counter
readability, or teardown fails. Silence, timeout, `NO_ROUTE`, `EINVAL`, and
`EHOSTUNREACH` alone are never proof.

### `CONTRADICTORY_EVIDENCE`

Receiver, counter, sender, and manifest disagree. This is a hard gate failure and
must not be resolved by precedence in favor of a green summary.

## 8. Required schema and checker changes if approved

1. Replace the single B7 result with IDs `B7-L2` and `B7-MC`; do not retain a
   synthetic aggregate that can hide one failure.
2. Change `REQUIRED_B` from nine rows to ten exact IDs:
   `B1..B6, B7-L2, B7-MC, B8, B9`.
3. E1 requires both new rows to have strict `status=PROVEN` and `pass=true`.
4. E2 compares the exact ID set; range/count-only generation is forbidden.
5. Add a host-side B7 re-derivation check (proposed `E9`) that ignores sandbox
   verdict fields and derives both outcomes from manifest, receiver logs,
   calibration, PEP liveness, and rule counters.
6. E9 failure makes evidence `NOT CERTIFIED`, even if both sandbox rows say pass.
7. The acceptance schema version must change; old and new artifacts must not be
   merged or compared as if structurally equivalent.

## 9. Falsification tests required before implementation acceptance

The checker must reject fixtures where:

1. receiver is unoccupied;
2. scope ID/interface is wrong;
3. multicast receiver never joined the group;
4. pre-control passes but receiver dies before measurement;
5. sandbox reports blocked but receiver records its nonce;
6. receiver is silent but the exact drop counter does not increment;
7. an unrelated rule counter increments;
8. sandbox changes its IPv6 address using `NET_ADMIN`;
9. calibration and measurement artifacts are cross-run mixed;
10. stale receiver logs contain a reused nonce;
11. PEP connectivity is accidentally blocked by the new L2 rules;
12. teardown leaves a rule that makes the next run falsely green.

## 10. Alternatives considered

### Keep synthetic probes

Rejected: cannot distinguish filtering from an absent peer or invalid route.

### Add only a live peer

Rejected: proves same-link reachability but not that a policy boundary exists;
without host enforcement evidence it merely changes the expected outcome.

### Use packet capture without enforcement counters

Insufficient alone: capture placement can miss locally bridged traffic and
absence remains ambiguous. Capture may be supplementary, not authoritative.

### Treat Layer A classifier denial as B7 transport proof

Rejected: duplicates A2/A29 and does not establish L2 transport containment.

### Drop B7 because B1/B3 prove off-link egress

Not selected under owner direction. It remains a legitimate specification
alternative if per-sandbox same-link isolation is explicitly out of scope.

## 11. Hidden assumptions / unresolved owner decisions

Implementation must not start until these are resolved:

1. **Requirement boundary:** Is same-program, same-link peer isolation mandatory
   for release, despite the current per-program-network architecture?
2. **Allowed peer set:** Is only the PEP allowed, or are DNS/bootstrap/telemetry
   peers also legitimate?
3. **Multicast scope:** Is the claim limited to one controlled `ff02::/16`
   group/UDP port, or must all unauthorized IPv6 multicast be denied?
4. **Enforcement primitive:** Is host bridge-family nftables an acceptable
   production dependency, including bridge netfilter availability checks?
5. **Adversary identity:** Must the design withstand MAC spoofing in addition to
   source-IP changes available through `NET_ADMIN`?

## 12. Contract gates

1. Owner resolves Section 11 and approves a final contract.
2. Independent remediation implements only that contract.
3. Independent full-tree audit runs on the remediated tree.
4. Pass 6 is a fresh audit, not reuse of this VM run.
5. DEC-6 re-freezes triage and tree identity after Pass 6.
6. Only then may a new dual-stack gate be considered.
7. Strix and release verdict remain forbidden until that chain completes.

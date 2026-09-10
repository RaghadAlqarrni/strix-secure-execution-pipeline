# DEC-7 semantic ownership review + remediation contract V2

Status: **DRAFT — OWNER APPROVAL REQUIRED BEFORE IMPLEMENTATION**  
No code/topology changes authorized. No gate, release verdict, or Strix run authorized.

## A. Independent finding

The original architecture supports **Option D**, not the earlier Option A:

- `ARCHITECTURE_REVIEW.md:58` defines the PEP as the **sole egress path**.
- `ARCHITECTURE_REVIEW.md:141` explicitly records that **same-network peers can
  reach each other**, with the mitigation being per-program networks.
- `ARCHITECTURE_REVIEW.md:158` scopes **per-program network isolation**, not
  per-sandbox peer isolation.
- `SECURITY_ARCHITECTURE_REVIEW.md:145` says Layer B tests egress, **never
  intra-network L2**, and treats NDP/RA/SLAAC peer attacks as a later edge-case
  expansion.
- `SECURITY_ARCHITECTURE_REVIEW.md:238-241` classifies new intra-network rows as
  an expansion requiring separate sign-off.

Therefore:

1. “PEP is the sole egress path” does **not** mean “PEP is the only reachable
   same-link peer.”
2. Per-sandbox L2 peer isolation is a **NEW REQUIREMENT**, not remediation of an
   established B7 requirement.
3. Host bridge nftables for peer isolation is not currently an approved
   production security boundary.
4. The prior proposal to change `REQUIRED_B` from 9 to 10 was premature and is
   withdrawn.

## B. What B7 appears to own semantically

The strongest specification-supported interpretation is:

> IPv6 containment must prevent non-PEP, off-link egress, including traffic that
> does not use the PEP's TCP/TLS path.

Why this fits the baseline:

- PEP is the sole **egress** path.
- IPv4 containment is documented as protocol-agnostic, including raw/UDP.
- IPv6 containment is the release blocker.
- B1/B3 establish the correct paired-control shape for an off-link live target,
  but their live application path is TCP/TLS through the PEP.
- The old B7's link-local/multicast probes seem to have attempted broader IPv6
  transport coverage, but selected mechanisms that cannot establish attribution.

This is an inference from the approved architecture, not an explicit sentence
defining B7. Owner confirmation is still required.

## C. Claim ownership table

| Claim | Security property | Source | Status | What B1/B3 prove | What they do not prove | Required topology | Positive control | Negative control | Enforcement boundary | Failure semantics | REQUIRED_B / E-check impact | Owner decision? |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **B7-OFFLINK-UDP (recommended meaning for existing B7 ID)** | Sandbox cannot deliver direct off-link IPv6 UDP outside the PEP path | Architecture sole-egress-path; protocol-agnostic IPv4 property; IPv6 release blocker | **Existing requirement, inferred semantic ownership** | Live off-link IPv6 target is reachable through PEP while direct TCP path is blocked | Protocol-independent/UDP containment; attribution of a UDP drop | Existing internal sandbox bridge plus egress bridge; occupied UDP receiver on egress side; host-controlled forwarding/enforcement observation | Trusted control sender delivers fresh UDP nonce to exact receiver; receiver readiness and post-control succeed | Sandbox sends fresh nonce toward exact occupied off-link receiver; receiver must not receive it and exact enforcement counter must increment | Existing Docker/internal-network IPv6 forwarding boundary; no new same-link peer ACL | Delivery=`FAILED_OPEN`; missing controls/counter=`APPARATUS_FAILURE`; unsupported runtime=`ENVIRONMENT_BLOCKED`; silence alone=`NOT_PROVEN` | Keep **9 B rows and ID B7**. Add host re-derivation capability; whether new E ID or extension is a secondary design choice | **Yes: confirm this is B7's intended property** |
| **Same-link link-local peer isolation** | Sandbox cannot reach unauthorized peer on its own L2 link | Contradicted as baseline by documented same-network reachability; later review labels intra-network L2 untested | **NEW REQUIREMENT** | Nothing; B1/B3 are off-link | Same-link unicast isolation | Occupied link-local peer on sandbox bridge plus new host L2 ACL | Authorized sender and receiver controls | Sandbox nonce denied with authoritative ACL evidence | New host bridge/nft boundary | As in V1, but cannot gate release absent new requirement approval | No current change. New row/gate revision only after separate architecture decision | **Separate future decision** |
| **Selected IPv6 multicast isolation** | Defined sender cannot deliver UDP to defined group/scope/port/direction | No precise current group/protocol/port claim found | **NEW REQUIREMENT until specified** | Nothing specific to multicast | Group membership, UDP delivery, scope and direction | Live joined UDP receiver and scoped sender on relevant link | Pre/post receiver controls and calibration | Exact nonce absent plus exact enforcement evidence | Depends on whether same-link or off-link multicast is claimed; currently undefined | Silence/NO_ROUTE/TCP failure never proves | No current change. Requires separate claim and gate revision | **Separate future decision** |
| **PEP-only same-link peer** | PEP is the only reachable peer | No support found; “sole egress path” is not “sole peer” | **NEW REQUIREMENT** | Nothing | Peer allowlist/isolation | New same-link enforcement architecture | Per-allowed-peer controls | Unauthorized occupied peer blocked | New production L2 boundary | Hard fail on bypass or missing enforcement | No current change | **Separate future decision** |
| **MAC-spoof resistance** | Sandbox cannot evade L2 policy by changing MAC | No current DEC-7 ownership found | **NEW REQUIREMENT** | Nothing | L2 identity integrity | Adversarial L2 fixture | Known legitimate identity succeeds | Spoof attempts fail authoritatively | Host/vSwitch identity boundary | Separate threat-model semantics | No current change | **Separate future decision** |

## D. Option D — recommended

Do not add peer isolation to the product through DEC-7.

1. Preserve the existing row count and B7 identifier for now.
2. Redefine B7 narrowly as **live, attributable, non-PEP off-link IPv6 UDP
   containment**, subject to owner confirmation that this matches the original
   security property.
3. Remove link-local and multicast from B7's release claim because the current
   specification does not define same-link peer isolation or a precise multicast
   policy.
4. Record link-local peer isolation, PEP-only peer reachability, multicast policy,
   and MAC spoofing as separate NEW REQUIREMENT candidates. They do not block the
   current release unless separately adopted into the threat model.
5. B1/B3 remain authoritative for the paired live TCP/TLS off-link path. B7 does
   not override, aggregate, or weaken them; it adds protocol-independent UDP
   coverage for the same sole-egress security boundary.

This is a semantic correction, not deletion or weakening: the invalid mechanisms
are removed from the release claim, while the underlying supported egress
property receives an attributable live test.

## E. Proposed B7 remediation contract (only if owner confirms Section D)

### Exact claim

> From the sandbox's internal IPv6 network, a UDP datagram sent directly toward
> one occupied off-link IPv6 receiver cannot cross the non-PEP egress boundary;
> the same receiver and path apparatus are proven live by independent controls,
> and the responsible host enforcement point records the measured disposition.

The claim is limited to:

- protocol: UDP;
- destination: one run-created occupied ULA receiver on the egress test network;
- port: one run-randomized high UDP port recorded in the manifest;
- direction: sandbox internal bridge → egress bridge;
- property: direct non-PEP off-link delivery is blocked.

It does not claim all multicast, all link-local, all L2 attacks, or MAC-spoof
resistance.

### Topology

- Keep the existing dual-network PEP topology.
- Add one host-controlled UDP receiver to the existing egress test network only.
- Receiver artifacts are not writable by the sandbox.
- Use the existing host/Docker IPv6 forwarding boundary; do not add same-link ACLs.
- Record bridge/network IDs, receiver address/port, host veth identities, rule
  snapshots, and run ID before measurement.

### Positive controls

1. Receiver announces readiness and exact address/port.
2. A trusted control sender on a path permitted to the receiver sends nonce C1;
   receiver records C1.
3. After the measured probe, the trusted sender sends nonce C2; receiver records
   C2, proving the receiver remained alive.
4. Existing B3 PEP-path positive control remains green in the same gate run.

### Negative/control-of-attribution

- A separate clean calibration topology, identical except for the internal
  boundary, proves the same sender code and receiver can exchange a sandbox-like
  UDP nonce. Calibration and measurement have distinct run IDs.
- During measurement the sandbox sends nonce M to the exact receiver.
- `PROVEN` requires receiver absence of M **and** an increment in the exact
  host-side rule/counter responsible for denying that sandbox-to-egress packet.
- An unrelated counter increment is rejected.

### Expected evidence

- control-plane run manifest and unpredictable C1/M/C2 nonces;
- receiver readiness plus timestamped nonce log;
- exact sender destination/group-free unicast address, UDP port, interface and
  send result;
- host enforcement rule identity and before/after counters;
- B3 same-run result;
- separate calibration manifest and result;
- artifact hashes and teardown proof.

### Failure semantics

- `PROVEN`: C1/C2 received, calibration received, M not received, exact denial
  counter increments, B3 remains proven, all bindings agree.
- `FAILED_OPEN`: receiver records M.
- `APPARATUS_FAILURE`: C1/C2/calibration/counter/binding/teardown fails.
- `ENVIRONMENT_BLOCKED`: required IPv6 forwarding/rule observability unavailable.
- `CONTRADICTORY_EVIDENCE`: sender/receiver/counter/manifest disagree.
- `TIMEOUT`, `NO_ROUTE`, local send success, or receiver silence alone never prove.

## F. REQUIRED_B and E-check decision

### REQUIRED_B

No row-count or ID-set change is proposed. `B7` remains one required row. The
semantic description and schema version must change if this contract is approved,
so old B7 artifacts cannot satisfy the revised row.

### Host re-derivation

A host-side re-derivation is necessary because existing E1/E2 only validate row
status/set consistency; they cannot prove receiver delivery, identify the exact
enforcement counter, or distinguish silence from a drop.

The semantic requirement is:

> independently derive B7 from manifest + receiver nonces + calibration + exact
> host counter + B3 liveness, ignoring the sandbox's B7 verdict field.

Whether this becomes a new `E9` or an explicit extension of an existing E-check
is not decided here. A new E9 is cleaner for audit visibility; extending an
existing check avoids count churn. This naming/contract choice requires owner
approval, but the independent derivation itself is required for honest evidence.

## G. Falsification requirements

The eventual checker must reject at least:

1. unoccupied receiver;
2. failed pre- or post-control;
3. receiver silence with no exact denial-counter increment;
4. unrelated counter increment;
5. M observed by receiver despite sandbox reporting blocked;
6. stale/reused nonce;
7. mixed calibration and measurement run IDs;
8. calibration that did not use equivalent sender/receiver code;
9. B3 failure in the measurement run;
10. teardown leakage that makes the next run falsely green.

## H. Final recommendation

**Adopt Option D and reject B7-L2 as DEC-7 remediation.** Confirm B7's semantic
ownership as attributable non-PEP off-link IPv6 UDP containment. Keep peer
isolation, multicast policy, PEP-only peer reachability, and MAC spoofing outside
this remediation as explicit NEW REQUIREMENT candidates.

## I. Owner decisions still required

1. Confirm or reject the proposed B7-OFFLINK-UDP semantic ownership.
2. Choose host re-derivation presentation: new visible `E9`, or extension of an
   existing E-check with an independently reported B7 sub-result.
3. Confirm that the four NEW REQUIREMENT candidates do not gate this release.

## J. What remains prohibited through Pass 6

- no implementation or topology changes before final contract approval;
- no reuse of the current 8/9 run as release evidence;
- no dual-stack release verdict;
- no Strix observation;
- after approval: remediation must be independent, then full-tree fresh Pass 6,
  then DEC-6 re-freeze; only afterward may a fresh dual-stack gate be considered.

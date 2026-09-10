# DEC-7 final remediation contract V3 — FOR OWNER SIGNATURE

Status: **NOT YET APPROVED; NO IMPLEMENTATION AUTHORIZED**

## 1. Semantic conclusion

### What the source proves

1. The approved architecture calls the PEP the **sole egress path**
   (`ARCHITECTURE_REVIEW.md:58`).
2. It treats network containment as protocol-agnostic for IPv4, explicitly
   covering raw/UDP (`:21`, `:139`), while IPv6 containment remains a release
   blocker (`:144`).
3. It explicitly accepts same-network peer reachability and mitigates it with
   per-program networks (`:141`, `:158`).
4. The later security review says Layer B tests egress, not intra-network L2,
   and classifies intra-network additions as a separately approved expansion
   (`SECURITY_ARCHITECTURE_REVIEW.md:145`, `:238-241`).

### What the source does not prove

The historical B7 claim is explicitly documented as link-local, later renamed
link-local/multicast (`PASS4_REPORT.md:281-285`; `PASS5_REPORT.md:371-383`). No
source states that B7 itself owns off-link UDP. Pass 4 also distinguishes a
“stronger transport property beyond B7's narrowed claim” as a possible new
independent test (`PASS4_PROMPT.md:232-235`).

### Conclusion

**Direct non-PEP off-link IPv6 UDP containment is a legitimate existing
architecture-level security requirement, but assigning it to the existing B7 ID
is not derivable from the historical B7 specification.** It is a specification
amendment requiring explicit owner signature.

This contract therefore does not pretend that UDP was always B7. It proposes:

> Amend B7 by owner decision so that its release-gating semantic becomes live,
> attributable direct non-PEP off-link IPv6 UDP containment.

This preserves the nine-row contract and fills a real IPv6 containment gap, but
it is a deliberate semantic amendment, not a test-only fix.

B1/B3 remain unchanged and authoritative for their existing live TCP/TLS paired
path proof.

## 2. Scope table

| Claim | Existing requirement or NEW REQUIREMENT? | Why | Evidence status | Release impact |
|---|---|---|---|---|
| IPv6 direct non-PEP off-link UDP containment | **Existing architecture requirement; NEW assignment to B7** | Sole-egress path + IPv6 containment + protocol-independent containment support it; B7 history does not name UDP | Not yet implemented or proven | Gates release only if owner signs the B7 semantic amendment |
| B7-L2 same-link peer isolation | **NEW REQUIREMENT** | Baseline explicitly allows same-network peer reachability and specifies per-program isolation | Not required/proven | Does not gate current release |
| IPv6 multicast isolation | **NEW REQUIREMENT until exact group/protocol/port/direction is specified** | Historical probe exists, but no precise enforceable multicast policy was found | Current TCP multicast probe proves nothing | Does not gate current release |
| PEP-only same-link peer isolation | **NEW REQUIREMENT** | “Sole egress path” does not mean “sole reachable peer” | No supporting baseline | Does not gate current release |
| MAC-spoof resistance | **NEW REQUIREMENT** | Threat-model ownership not established for DEC-7 | Not tested | Does not gate current release |

## 3. E-check engineering comparison

### Existing checks and their present meanings

- **E1:** required rows report strict `PROVEN` and are internally consistent.
  It checks a claim, not its truth.
- **E2:** exact row IDs/counts. It checks schema completeness, not truth.
- **E3:** B8/B9 nonce correlation from PEP audit.
- **E4:** B6 kill `conn_id`, B8 IPv6 pin fields, and B4 denial records.
- **E5:** verifier-source integrity constraints.
- **E6:** IPv4 suite completeness plus PP18 kill re-derivation.
- **E7:** audit-chain/startup/run integrity.
- **E8:** control-plane run binding of existing artifacts.

The auditor explicitly states that B1–B7 are sandbox-self-reported and not
host-re-derived (`audit_gate_evidence.py:9-17`). None of E1–E8 can establish a
UDP sender identity, occupied receiver, exact target/port/nonce, packet attempt,
host enforcement event, or receiver observation.

### Extending an existing check

- **E1/E2:** would corrupt their narrow schema/consistency semantics.
- **E3:** is specific to B8/B9 correlation; UDP delivery is unrelated.
- **E4:** already combines specific PEP-audit obligations. Adding host UDP
  receiver/counter evidence would broaden it into an opaque miscellaneous check.
- **E5:** can inspect a B7 verifier but cannot itself re-derive runtime truth.
- **E6:** is IPv4-specific.
- **E7:** integrity does not imply semantic truth.
- **E8:** can bind new B7 evidence artifacts to the run, but binding does not
  prove their contents. E8 should bind them, not decide B7.

### Independent E9

**Recommendation: add an independently reported E9**, only after owner approval.

Proof obligation:

> E9 must derive the B7 outcome without trusting the sandbox B7 verdict, using
> control-plane identity, sender-attempt evidence, exact enforcement event,
> receiver controls/observations, calibration, and same-run B3 liveness.

E9 is justified because this is a new evidence domain (host network boundary +
receiver), not because a ninth check makes the gate greener. E8 must separately
bind E9's input artifacts to the run; E5 must cover the actual E9 verifier module.

### Anti-oracle controls for E9

The mutation/fixture battery must make E9 fail when any one of these is changed:

1. sandbox verdict changed to `PROVEN` with no host evidence;
2. receiver marked silent while its raw log contains measured nonce;
3. exact drop counter replaced with an unrelated counter;
4. counter does not increment;
5. sender target/port/nonce differs from receiver manifest;
6. pre-control, post-control, or calibration removed;
7. run IDs or nonces cross-mixed;
8. sender-attempt artifact fabricated without the host-observed packet-attempt
   anchor required below;
9. B3 liveness removed;
10. verifier weakened from conjunction to `any()`/count/summary trust.

An honest fixture must pass; every weakening must fail E9 specifically. A
negative control that does not genuinely fire makes E9's proof `VOID`.

## 4. Evidence-chain design

| Link | Independent evidence source | Acquisition | Positive control | Negative control | Failure semantics | What cannot be inferred |
|---|---|---|---|---|---|---|
| **Sender identity** | Host-recorded container ID, network namespace/veth identity, run manifest | Control plane inspects the created sandbox before probe | Identity matches expected sandbox and B3 run | Fixture swaps container/veth identity | Missing/mismatch=`APPARATUS_FAILURE`; conflicting identity=`CONTRADICTORY_EVIDENCE` | Source IP alone cannot prove sender identity |
| **Intended off-link target** | Control-plane-created receiver address plus Docker network/bridge inspection | Manifest records receiver ULA, egress network and confirms it is not on sandbox link | Trusted sender reaches exact receiver | Fixture substitutes on-link or unoccupied target | Wrong topology=`APPARATUS_FAILURE` | A string labelled “off-link” is not topology proof |
| **Protocol/port/nonce** | Control-plane-generated UDP port and cryptographic nonces C1/M/C2 | Injected separately into senders/receiver; raw receiver log retained | C1 and C2 match exact tuple | Reused/mismatched nonce or port fixture | Mismatch/staleness=`CONTRADICTORY_EVIDENCE` | Sandbox-written JSON alone cannot bind the tuple |
| **Packet attempt** | Host-side observation at sandbox's host veth/bridge ingress, keyed to exact UDP 5-tuple + M | Narrow host capture or equivalent trusted packet counter records the attempted datagram before enforcement | Calibration records equivalent packet and delivery | Sender claims success but host observes no exact packet | No host attempt=`APPARATUS_FAILURE`, never blocked | Local `sendto()` success does not prove packet left namespace |
| **Enforcement event** | Exact host rule identity and before/after packet+byte counters, tied to sandbox veth and exact destination/port | Control plane snapshots normalized rule and atomic counters around M | Deliberate calibration/bypass instance proves delivery without measured enforcement | Unrelated/no counter increment fixture | Exact increment absent=`NOT_PROVEN`; disagreement=`CONTRADICTORY_EVIDENCE` | Receiver silence cannot identify the cause |
| **Receiver observation** | Host-controlled receiver readiness and append-only raw nonce log | Receiver binds exact ULA/UDP port; logs C1/M/C2 with timestamps | C1 before and C2 after M are received | Fixture kills receiver or inserts M | M present=`FAILED_OPEN`; controls missing=`APPARATUS_FAILURE` | Absence of M alone is never proof |
| **Attribution/correlation** | Control-plane manifest hashes all artifacts under one measurement run; separate calibration run linked by explicit role | Collector rejects sandbox labels, symlinks, stale paths and run conflicts | All measurement artifacts agree; calibration is clean and distinct | Cross-run/cross-nonce fixtures | Conflict=`CONTRADICTORY_EVIDENCE` | Timestamp proximity alone is not correlation |
| **Final verdict** | E9 independent conjunction; E1 consumes resulting B7 row only after E9 succeeds | E9 ignores sandbox verdict and recomputes | Honest full chain passes | Each single-link mutation fails | Only full conjunction=`PROVEN`; delivery=`FAILED_OPEN`; apparatus/env/conflict remain non-pass | No individual link can establish containment |

### Required chain

`host-bound sender identity → host-observed exact UDP attempt → intended occupied
off-link receiver → exact enforcement counter increment → receiver C1/M/C2
observation → control-plane correlation → E9 conjunction → B7 verdict`

The ordering is logical, not merely chronological. Each arrow requires matching
run ID, identity, tuple and nonce.

## 5. Final remediation contract

This section becomes executable only after owner signature.

### Claim

`B7`: A direct UDP datagram from the measured sandbox to one occupied off-link
IPv6 ULA receiver cannot cross the non-PEP egress boundary, and the denial is
attributable to the intended host enforcement event.

Scope is exactly UDP, one run-created unicast ULA, one randomized high port,
sandbox-internal → egress direction. No link-local, multicast, peer-isolation,
PEP-only-peer, or MAC-spoof claim is included.

### Topology

Keep the existing internal and egress networks and dual-homed PEP. Add only an
occupied host-controlled UDP receiver on the existing egress test network plus
trusted control sender/capture facilities. Do not add same-link ACLs or a new
production peer-isolation boundary.

### Controls and proof

1. Verify topology and identities host-side.
2. Receiver ready; trusted sender delivers C1.
3. B3 succeeds in the measurement run.
4. Host observes exact sandbox UDP attempt M before enforcement.
5. Exact enforcement counter increments for M.
6. Receiver does not log M.
7. Trusted sender delivers C2 afterward.
8. Separate clean calibration proves equivalent sender/receiver code can deliver.
9. Control plane binds and hashes all artifacts.
10. E9 independently requires every item; E8 binds E9 inputs; E5 covers E9 code.

### Verdicts

- `PROVEN`: all ten obligations hold.
- `FAILED_OPEN`: receiver records M.
- `APPARATUS_FAILURE`: readiness, capture, controls, calibration, counter access,
  collection or teardown fails.
- `ENVIRONMENT_BLOCKED`: required IPv6/rule/capture facility unavailable.
- `CONTRADICTORY_EVIDENCE`: identities, tuple, nonce, counter or receiver disagree.
- `NOT_PROVEN`: a required attribution fact is absent without evidence of delivery.

`TIMEOUT`, `NO_ROUTE`, sender success, counter alone, capture alone, or receiver
silence alone cannot yield `PROVEN`.

### Contract/schema effects

- `REQUIRED_B` remains exactly B1–B9.
- B7 description and acceptance schema version change; old B7 artifacts cannot
  satisfy the new contract.
- Add E9 with the proof obligation above; E-check count changes only after owner
  approval, while B-row count does not.
- Extend E8 solely to bind the new host artifacts; do not let it decide B7.
- Extend E5 solely to inspect/hash the actual E9 verifier module.

### Independent remediation and audit sequence

1. Freeze this signed contract and pre-remediation tree hash.
2. Independent remediation implements only this contract.
3. Independent reviewer runs falsification/mutation tests and full-tree audit.
4. Pass 6 is a fresh audit of the remediated tree.
5. DEC-6 re-freezes triage and tree identity.
6. Only then may a fresh dual-stack gate be considered.

## 6. Decisions requiring owner signature

1. **Semantic amendment:** approve assigning direct non-PEP off-link IPv6 UDP
   containment to existing B7 despite historical B7 being link-local/multicast.
2. **E9:** approve a separate E9 with the exact proof obligation and anti-oracle
   controls in Sections 3–4.
3. **Scope exclusions:** confirm B7-L2, multicast, PEP-only peer isolation and MAC
   spoof resistance are NEW REQUIREMENTS and do not gate this release.
4. **Topology limit:** approve adding only an egress-side live UDP receiver and
   host observation apparatus; no same-link peer ACL or production-boundary
   expansion.

## 7. Locked boundaries until signature and Pass 6

No code, topology, `REQUIRED_B`, E-check, gate, release-verdict or Strix changes
are authorized before signature. After signature, release/Strix remain prohibited
through independent remediation, fresh full-tree Pass 6 and DEC-6 re-freeze.

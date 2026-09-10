# Unified Triage — DEC-6 Re-freeze (post DEC-5)

**Re-frozen:** 2026-09-01. This replaces the pre-repair triage as the current
state ledger. `TRIAGE_UNIFIED_PRE_REPAIR_FROZEN.md` preserves the historical
51-finding baseline byte-for-byte.

## Evidence status of this tree

**REPAIRED + LOCALLY/COMPONENT PROVEN. NOT LIVE-GATE VERIFIED. NOT RELEASE-READY.**
No finding below is promoted by a repairer's own test. A live dual-stack run and
fresh independent post-run audit remain mandatory.

## Closed in implementation, with re-runnable negative controls

| Item | Current evidence |
|---|---|
| P2-HIGH-2 budget TOCTOU | CODE-VERIFIED; P0-1 unit control live; DEC-5 P0-4 drives 64 concurrent real `PDP.decide()` calls: old split shape 64/10, repaired shape 10/10. |
| R-8 kill-switch admission race | CODE-VERIFIED; P0-2 controls live; DEC-5 P0-4 drives real `Gateway.do_CONNECT()`: old registry admits after kill, repaired registry emits correlated `KILL_SWITCH_ACTIVE`. |
| P3-CRIT-3/4 audit-log coverage | 5/5 audit mutants caught; 18/18 audit self-tests. |
| P2-CRIT-1 IPv6 target listener | CODE + local EXECUTION verified over IPv4/IPv6 loopback; live Docker topology still NOT-VERIFIED. |
| P3-CRIT-2 contradictory row | f22 rejects `status=PROVEN,pass=False`; negative control certifies the old shape. |
| P2-HIGH-3 denial correlation | State-bearing denial paths carry `conn_id`; `INTERNAL_FAILURE` gap closed. |
| D-1 kill-active labels | DEC-2: row/nonce are untrusted correlation labels captured before admission; control-plane `run_id` remains authority. |
| P3-M1 degraded startup | DEC-4: any in-run `STARTUP_DEGRADED` directly fails E7; f23 proves rejection. |
| P3-HIGH-2, scoped B4 portion | B4 SNI and Host-header denials must both be re-derived from raw, run-scoped audit with nonce + conn_id; f24 proves a missing denial fails. |
| DEC-5 enforcement-surface depth | Shipped `proof_p0_4_enforcement_surfaces.py` covers `decide()` and `do_CONNECT()` with deterministic negative controls. |

## Open release blockers / NOT-VERIFIED

1. **Live dual-stack gate:** not run on the Ubuntu VM. All inter-container IPv6,
   Docker ip6tables, listener, and live E-check claims remain NOT-VERIFIED.
2. **B7:** owner ruling remains `REWRITE CLAIM`: keep the row, narrow the claim,
   do not retire it, do not change topology, never promote beyond evidence.
   Current synthetic topology reports `NOT_PROVABLE_IN_TOPOLOGY`; it cannot yield
   a release pass and must not be relabelled.
3. **Upstream Strix checkout:** long-lived checkout and pinned commit cleanliness
   remain NOT-VERIFIED. Do not clone a fresh tree and call that proof.
4. **Chain of custody:** no Git repository or signed provenance chain. Hash
   manifests establish transfer integrity, not authorship/custody.
5. **35-mutant baseline:** historical 20/35 survival has not been re-measured;
   the complete mutant corpus is absent. Only named, runnable mutants may be cited.
6. **Audit multi-process safety:** thread-safe; two-process append behavior remains
   NOT-VERIFIED and has no process lock.
7. **Remaining denial surface:** B4 is raw-audit re-derived; this is not a claim
   that every negative Layer A/B property has a corresponding raw denial proof.
8. **Verifier independence:** source heuristics and fixtures test known weakening
   shapes; arbitrary semantic equivalence is externally anchored only by the
   frozen full-tree hash manifest, not a signed independent verifier release.

## Release sequence (frozen)

```
DEC-6 tree freeze
  -> transfer-integrity verification in VM
  -> preflight
  -> explicitly-authorized interpretable dual-stack observation
  -> collect raw output/artifacts
  -> fresh independent post-run evidence audit
  -> deterministic release triage
  -> only if every required gate passes: consider Strix observation
```

## Prohibitions

- No check modification to make a run pass.
- `BLOCKED_ENV`, `NOT_RUN`, `SKIP`, `NOT_PROVABLE`, or nonzero exit are not passes.
- No Strix and no real target before deterministic release triage.
- Pre-repair evidence is never evidence about this re-frozen tree.

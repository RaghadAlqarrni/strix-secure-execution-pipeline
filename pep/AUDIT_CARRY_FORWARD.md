# Carry-Forward Ledger

Splitting the audit into three passes created a new blind spot: the **seams**.
A finding raised in one pass can be silently dropped by the next, and silence
reads as clean. Every later pass MUST explicitly **resolve** or **restate** each
item below. Dropping one without comment is an audit gap.

## Issued by Pass 1 (transport) — owed by Pass 2

| ID | Finding | What Pass 2 owes |
|---|---|---|
| **F3** | `NO_ROUTE` treated as blocking rests on an **unverified topology premise**. Nothing checks the sandbox is on an `--internal` network, or that the missing route is *policy* rather than v6 never being configured on the egress side. | **Runtime-verify** the premise in `run_dualstack_gate.sh`: is `gate_prog_a` genuinely `--internal`? Is `TGT6` genuinely absent from the internal link? Is the absence of an egress route a configured denial or an accident? If unverifiable, `NO_ROUTE` is an assumption, not evidence. |
| **F4** | B2 injects `ip -6 route add … dev eth0` with no `via` — an **on-link** route. The kernel does ND for `TGT6` on the internal link; `TGT6` lives on the egress network, so **nobody can ever answer**. Failure is by topology, not policy. | Confirm from the gate's network construction whether an injected route could *ever* produce an egress attempt. If not, B2 cannot prove NET_ADMIN containment as written. |

## Issued by Pass 1 — owed by Pass 3

| ID | Finding | What Pass 3 owes |
|---|---|---|
| **B8 inherits F3 + F7** | `B8_ROWS = ("B3","B5")`. B3 is OVERSTATED (F3); B5 never inspects the peer certificate (F7). | B8 may not be declared sound while its sources are defective. State the inheritance explicitly. |
| **B9 inherits F2** | `B9_ROW = "B6"`. B6 accepts **any exception** as proof the kill switch fired. | Same. B9's evidence chain starts at a row that cannot distinguish a kill from a client timeout. |
| **F1** | The anti-regression suite survives **ten** weakenings at 42/42; `main()` has zero coverage. | Assess whether the evidence model can detect a weakened *row*, not only a weakened verifier. |
| **F8** | `b7` can never equal `PROVEN`, so `main()` always returns 1 — **Layer B is permanently red by construction**. | Assess what E1/E2 do with a row that is un-passable by design. |

## Standing rules earned by Pass 1

1. **"Consistent with blocking" is insufficient.** An observation must
   *materially exclude* the principal non-enforcement explanations.
2. **`CODE-VERIFIED` alone cannot establish runtime security behaviour.**
   Distinguish **logic claims** ("can this function return PROVEN for input X?"
   — settleable by local execution) from **behaviour claims** ("does the
   boundary actually drop this packet?" — `ENVIRONMENT-BLOCKED` without a live
   topology). B4 was labelled `SOUND` in Pass 1 on a row that has never
   executed; under this rule its ceiling is `ENVIRONMENT-BLOCKED`.
3. **A green suite is not regression detection.** Prove it by mutation.
4. **Silence is not acceptance.** Every in-scope item gets one label AND one
   verdict; "not mentioned" is never an implicit pass.

---

## Issued by Pass 2 — owed by Pass 3

| ID | Finding | What Pass 3 owes |
|---|---|---|
| **P2-C1** | `target_https.py:105` binds `AF_INET` only — the v6 targets have nothing listening on IPv6. B1/B2/B3's positive control is **unsatisfiable by construction**. | Assess what E1/E2 do with a Layer B row whose positive control cannot be satisfied. Same shape as F8's un-passable B7. |
| **P2-C2** | The manifest omits **PP18**, a gating row, because it is runtime-derived from *sandbox* output while PP18 is produced *host-side*. | Is any other host-derived row invisible to the manifest for the same reason? |
| **P2-C3** | `_deny()` / `_deny_tls()` carry **no `conn_id`, `row_id` or `test_nonce`** — the anchor is absent from every negative PEP decision. | How much of E1–E8 rests on binding denials to connections? Does any E-check silently accept reason-string matching as a substitute? |
| **P2-C4** | `STARTUP_DEGRADED` is printed but never enters `passed`/`total` (`audit_gate_evidence.py:379-397`). | Should a degraded listener hard-fail certification instead of relying on Layer B failing indirectly? |
| **P2-C5** | `AuditLog.verify()` exists (`audit.py:92`) and is never called on the PP18 path. | Does ANY E-check call it? If not, tamper-evidence is built but unused. |
| **P2-C6** | Budget TOCTOU (64 served against a cap of 10) and double-charge are undetected because both harnesses set `max_requests: 100000`. | Relevant to F1 — here there is no row at all, so the evidence model has nothing to detect. |

## Three-layer verdict (adopted after Pass 2)

A single label cannot express what was found. Every finding now carries three:

```
IMPLEMENTATION   does the code achieve the property?
EXECUTION        did the experiment actually traverse the required path?
EVIDENCE         does the record prove that what happened is the state claimed?
```

Worked examples from prior passes:

| Finding | IMPLEMENTATION | EXECUTION | EVIDENCE |
|---|---|---|---|
| HIGH-2 budget TOCTOU | **FAIL** | PROVEN | PROVEN |
| B4 (labelled SOUND in Pass 1) | plausible | **NOT EXECUTED** | **NONE** |
| CRITICAL-1 target listener | **FAIL** | PROVEN (bind family) | PROVEN |

This prevents `SOUND` from carrying more than it can bear.

## Process rule — earned by Pass 2

**Findings from a pre-repair run are not evidence about post-repair code.** After
any remediation, a completely fresh run is required. Reusing these results would
mean "the evidence proving the code sound was produced before the code changed."

---

## Measured on a real dual-stack host — 2026-08-23

Ubuntu VM, `Linux 7.0.0-30-generic`, working IPv6, Docker 29.1.3. Three findings
that every audit pass had to leave as `ENVIRONMENT-BLOCKED` were executed.

### Q1 — F3's open half: PARTIALLY resolved, and it points at the B2 repair

```
Internal=true  EnableIPv6=true
ip6tables rules: before=18 after=21 delta=3
rules with both DOCKER and DROP: 3
```

**What this establishes:** creating `--internal --ipv6` **does install v6
netfilter DROP rules**. The isolation is *configured*, not an accident of v6
never being set up. That is a real upgrade over the audit's worst case.

**What it does NOT establish — and the distinction is the whole point.** The
audit's concern was whether the `NO_ROUTE` that B1/B2/B3 observe is attributable
to *policy*. `NO_ROUTE` is `ENETUNREACH` — a **local FIB failure in which no
packet is emitted**. If the packet never leaves, those DROP rules never fire.
So we now know two mechanisms exist; we have **not** shown which one produced
the observation.

Applying this project's own rule to this very measurement: rules existing is
*consistent with* enforcement. It does not *materially exclude* "the routing
table had no entry anyway."

**But it shows how to repair B2.** The correct injection is a route **`via` the
PEP's internal address** — the one node on both networks. Then the packet
genuinely leaves the sandbox, reaches the bridge, and meets the DROP rules —
and the observation becomes attributable. The shipped `dev eth0` on-link form
(CRITICAL-2) can never get that far.

**Status: F3 upgraded from NOT-VERIFIED to PARTIALLY-RESOLVED. The attribution
half remains open and now has a concrete experiment.**

### Q2a — CRITICAL-1 confirmed at runtime

```
v4-only listener (exact copy of target_https.py:105) reached over IPv6
  -> ConnectionRefusedError
```

`IMPLEMENTATION FAIL · EXECUTION PROVEN · EVIDENCE PROVEN`. No longer a code
reading — measured on a live dual-stack host.

### Q2b — the P1 fix is viable

```
dual-stack (::, IPV6_V6ONLY=0) listener -> DUALSTACK_OK
```

A dual-stack bind works on this kernel. The repair for `target_https.py` is
viable **by measurement, not assumption**.

### Note on the diagnostic itself

`bound family:` printed empty — the grep pattern in the script did not match the
container's output format. Cosmetic; the substantive Q2a result (the connection
attempt) is unaffected. Recorded so it is not mistaken for a missing measurement.

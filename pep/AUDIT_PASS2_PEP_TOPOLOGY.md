# Security Audit — Pass 2 of 3: PEP / Policy / Topology

Independent adversarial audit. Read-only on target; all execution on a
disposable copy. The auditor did not read prior reports except the
carry-forward ledger.

**16 findings: 2 CRITICAL · 3 HIGH · 6 MEDIUM · 5 LOW.**

```
AUDIT_INTEGRITY = VERIFIED
  d530d97ab017947f… at start and end, unchanged. Zero writes to pep/ or phase2b/.
  gen_certs.sh run only against /tmp/audit2. run_fixtures.sh and the gate NEVER run.
```

---

## CRITICAL-1 — The IPv6 targets have nothing listening on IPv6

`phase2b/target_https.py:105` · EXECUTION-VERIFIED · **DEFECT**

```python
srv = ThreadingHTTPServer(("0.0.0.0", PORT), H)
```

Independently confirmed:

```
target_https.py bind family = AF_INET (2)
grep -rn "AF_INET6" phase2b/   ->  no matches anywhere
```

The gate assigns every target a v6 address (`run_dualstack_gate.sh:81 --ip6`)
and resolves `allowed6.lab` / `slow6.lab` / `evil6.lab` to them (`:138-140`).
The PEP selects the family from the pin and connects to
`[fd00:9a17:e9:1::20]:443`. **Nothing is listening there.** The connect fails and
the row receives `UPSTREAM_ERROR:ConnectionRefusedError`.

Chain: `via_ok = False` → **B1, B2, B3 all collapse to `NO_POSITIVE_CONTROL`**;
B5 fails; B8 inherits.

**This is the identical bug class the PEP listener was fixed for.**
`gateway.py:414-424` documents it verbatim — "ThreadingHTTPServer inherits
address_family = AF_INET, so the PEP was IPv4-ONLY". Fixed in the listener,
left in the target.

**Compounding, and worse:** `gen_certs.sh:35-49` carries two paragraphs
attributing exactly this collapse to missing v6 SANs. The auditor verified by
openssl that **the SANs are now present and correct**. So that comment documents
a *resolved* cause while the real blocker sits one layer below it, unaddressed
and unmentioned. A reader would conclude Layer B is unblocked. It is not.

---

## CRITICAL-2 — Carry-forward F4 resolved: B2's injected route can never produce an egress attempt

`ipv6_transport.py:365-367` vs the gate's network construction · CODE-VERIFIED ·
**DEFECT — B2 OVERSTATED**

Both injected routes are **on-link** — neither names a `via`:

```python
["busybox","ip","-6","route","add","default","dev","eth0"]
["busybox","ip","-6","route","add", f"{TGT6}/128","dev","eth0"]
```

TGT6 ∈ `V6_EG` (`fd00:9a17:e9:1::/64`); the sandbox's only link is `V6_IN`
(`fd00:9a17:e9:2::/64`). Disjoint /64s on different bridges. An on-link route
makes the kernel resolve TGT6 by **Neighbor Solicitation on the internal
bridge**. No node there owns that address, so no advertisement can ever return.
`connect()` fails at neighbour resolution — **no packet ever leaves the bridge.**

The sharpest detail: `gate_gw` sits on **both** networks and is the one node
that could reach TGT6. The injected routes bypass it *precisely because they
name no `via`*. The only construction that could have produced a genuine egress
attempt — `route add <TGT6> via fd00:9a17:e9:2::10` — is the one B2 does not
perform.

**B2 tests "IPv6 Neighbor Discovery fails for an address not on the local L2
segment." It cannot demonstrate NET_ADMIN containment.**

---

## HIGH-1 — Carry-forward F3: the "configured denial" half remains NOT PROVEN

`run_dualstack_gate.sh:44-46` · CODE-VERIFIED / NOT-VERIFIED

| F3 sub-question | Answer |
|---|---|
| Is `gate_prog_a` genuinely `--internal`? | **Yes** (`:79`), CODE-VERIFIED |
| Is TGT6 absent from the internal link? | **Yes**, by subnet arithmetic |
| Is the missing egress route a **configured denial** or an **accident**? | **NOT PROVEN either way** |

The environment gate checks three host-kernel facts and never verifies that
dockerd runs with `--ipv6`, that `--ip6tables=true` is in effect — **which its
own failure text at `:61` names as required** — that containers received v6
addresses, or that `--internal` produced a v6 DROP rule.

Without `--ip6tables`, `--internal` v6 isolation reduces to "no route was
installed" — an absence, not a policy.

Second gap: **the env gate measures the HOST; the PEP binds inside a
CONTAINER.** A host with working v6 and a dockerd without `--ipv6` passes the
gate and yields an IPv4-only PEP.

## HIGH-2 — Budget enforcement is TOCTOU-racy: 64 requests served against a cap of 10

`pdp.py:157` (check) vs `:257` (charge) · EXECUTION-VERIFIED · **DEFECT**

`would_exceed()` and `charge()` each take the lock, but **not together**.
Between them sit DNS resolution, classification, family selection and credential
validation.

```
64 concurrent decide(), max_requests=10  ->  ALLOWED = 64
counters {'prog_a': 64, 'prog_a/a1': 64}     OVERSHOOT = 54
```

The `Budgets` docstring says "Exhaustion halts that scope." Under concurrency it
does not. **This is an enforcement defect, not an evidence one** — and no row
detects it, because both harnesses set `max_requests: 100000`.

## HIGH-3 — Every denial audit record omits the connection anchor

`gateway.py:137-138, 167-169, 228-231, 246-247, 368-369` · CODE-VERIFIED ·
**DEFECT**

`_deny()` and `_deny_tls()` write `{decision, reason, url, method, src|tls}` —
**no `conn_id`, no `row_id`, no `test_nonce`.** Only `ALLOW` and
`CONNECTION_TERMINATED` carry the anchor.

`ConnectionState`'s own docstring says `conn_id` is "what lets an auditor tie a
specific client request to a specific PEP decision … instead of matching on
timestamps or hostnames, which a stale-but-valid record from an earlier run
would also satisfy."

**That anchor is absent from every negative decision the PEP makes** — i.e. from
exactly the records carrying the enforcement claims. Host-side corroboration of
any negative row falls back to `run_id` + reason-string matching: precisely the
weaker mode the docstring rejects.

---

## MEDIUM

**M1 — PP2 and PP8 assert the same reason.** `UPSTREAM_CERT_INVALID` is emitted
for **any** `SSLCertVerificationError`; untrusted issuer and hostname mismatch
are indistinguishable at row level. The distinguishing evidence (`detail`) is
written but never consumed. *PKI itself verified clean: badcert.lab is still
rogue-signed; every v6 hostname is in its container's SAN.*

**M2 — Decision ordering lets budget/authorization preempt scope, port, method.**
Executed with `max_requests=0`: an out-of-scope host returns
`BUDGET_EXHAUSTED_PROGRAM`. Fails safe (`blocked_by` turns a wrong-control
denial into a row FAILURE), but a latent attribution hazard.

**M3 — The STARTUP record asserts `v6only=0` rather than measuring it.**
`families` is a hardcoded literal; no `getsockopt` readback. Placement of
`setsockopt` before `bind` is **correct**; the fallback is genuinely **loud**
(both records written, executed and confirmed). The AF_INET6 bind path itself is
ENVIRONMENT-BLOCKED.

**M4 — `decide()` is called twice per request; both charge the budget.**
`max_requests=4` serves only 2 full requests. Stricter, not a bypass — but the
number means half what it says.

**M5 — PP17 cannot distinguish a kill from a PEP idle timeout.** `IDLE_TIMEOUT`
30s vs `SLOW_SECONDS` 25s — a **5-second margin**. "Consistent with blocking",
which the standing rule rejects. **PP18 does materially exclude it** (requires
`conn_id ∈ terminated_conn_ids`, which only `kill_watcher` writes).

**M6 — The coverage manifest omits PP18, a gating row.** `required_ids` holds 64
entries: A1-A30, B1-B9, E1-E8, **PP1-PP17**. PP18 appears nowhere — yet
`PP18_RC == 0` is a required conjunct of `IPv6 GATE: PASSED`. The cause is
structural: the manifest is runtime-derived from the **sandbox's** output, and
PP18 is produced **host-side**. *A manifest built from the sandbox's own output
is architecturally blind to precisely the row that exists because the sandbox
cannot be trusted.*

---

## LOW

**L1** PP16's positive control runs *before* saturation — proves "served one
request before load", not "serves under load"; a limiter set to 1 passes. `hits`
read without the lock while 80 threads are in flight.
**L2** PP10's IP-specificity is conditional on `REBIND_SECOND_IP`; both
harnesses set it, so strictness is environmental not intrinsic.
**L3** `*.allowed.lab` matches multi-label subdomains — deliberate, and **no
suffix-confusion bypass** (`xallowed.lab`, `allowed.lab.evil.com` all denied).
**L4** The audit hash chain is never verified on the PP18 path — `AuditLog.verify()`
exists and is uncalled. Mitigated: `$CTRL` is not mounted into the sandbox.
**L5** The gate has no `set -e` and no container health check; `run_pep.sh` is
stricter (`set -euo pipefail`).

---

## Assessed SOUND

**`_program_for_source` — no bypass**, EXECUTION-VERIFIED:

```
plain v4 172.31.0.50            -> prog_a      6to4  2002:ac1f:32::1  -> None
ipv4_mapped ::ffff:172.31.0.50  -> prog_a      teredo                 -> None
native v6 in CIDR               -> prog_a      nat64 64:ff9b::ac1f:32 -> None
```

Both crafted forms *do* embed an in-CIDR v4 and both fail closed.

**But the stated rationale is a category error** — the comment asserts a
property of the *value* ("produced by the LOCAL KERNEL … not content the peer
chose") while the signature guarantees only `src_ip: str`. The function cannot
distinguish a kernel-derived mapped address from an attacker-supplied one. It is
safe **by convention, not by construction**: the only caller passes
`accept(2)`'s peer address. A future caller passing `X-Forwarded-For` silently
converts this into program impersonation while the comment still reads as
self-protecting. The correct form is an enforced caller contract.

**`blocked_by()` does real work** — all 47 emittable reasons tested against every
asserted prefix: **no collisions, not too strict**. And no prerequisite-failure
mode yields BLOCK for any row (PEP unreachable, TLS failure, 503, target absent,
DNS missing, budget exhausted, authorization expired, kill switch armed — all
fail the row).

**Topology parity is complete** in both harnesses — every host, credential,
port, method, asset, path and env var `pep_client.py` touches is present.

Also SOUND: `ca.py` (correct `IP:`/`DNS:` SAN selection, 0600 keys) ·
`resolver.py` · `addressing.py` (no suffix confusion, octal/hex rejected) ·
`audit.py` · `server.py` · `verify_pp18.py` · PP3, PP4, PP5, PP6, PP9, PP10, PP13.

---

## Carry-forward to Pass 3

| ID | Item |
|---|---|
| **F3** | PARTIAL — "configured denial" still NOT PROVEN. Do not record as resolved. |
| **F4** | RESOLVED AS DEFECT — Pass 3 must not accept B2 as containment evidence. |
| **P2-C1** | Assess what E1/E2 do with Layer B rows whose positive control is **unsatisfiable by construction** (same shape as F8's un-passable B7). |
| **P2-C2** | Any other host-derived row invisible to the manifest for the same reason as PP18? |
| **P2-C3** | How much of E1–E8 rests on binding denials to connections, given denials carry no `conn_id`? Does any E-check accept reason-string matching as a substitute? |
| **P2-C4** | `STARTUP_DEGRADED` never enters `passed`/`total`. Should a degraded listener hard-fail certification? |
| **P2-C5** | Does any E-check call `AuditLog.verify()`? If not, tamper-evidence is built but unused. |
| **P2-C6** | Budget TOCTOU and double-charge are undetected because no row exercises them. |

```
LIVE_EXECUTION_STATUS      = PARTIAL — local execution on a copy only. Docker daemon
                             DOWN; AF_INET6 UNAVAILABLE. No live topology exercised.
AUDIT_INTEGRITY            = VERIFIED
CODE_AUDIT_STATUS          = COMPLETE for Pass 2 scope
PEP_POLICY_EVIDENCE_STATUS = NOT ESTABLISHED. Negative rows are sound in LOGIC;
                             no row has executed against a live PEP. Layer B evidence
                             is void by construction: CRITICAL-1 removes its positive
                             control, CRITICAL-2 removes B2's claim. F3 PARTIALLY
                             UNPROVEN; F4 RESOLVED AS DEFECT.
```

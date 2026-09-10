# Security Audit — Pass 1 of 3: Transport Layer

Independent adversarial audit. Read-only on the target; all execution in a
disposable copy. The auditor did **not** read `REMEDIATION_DIAGNOSTIC.md`,
`VERIFICATION_STATUS.md` or any other report in the tree.

**11 findings: 2 CRITICAL · 3 HIGH · 3 MEDIUM · 3 LOW.**

---

## 0. Environment — measured, not assumed

```
socket.has_ipv6                        -> True     <-- COMPILE-TIME flag, not a capability
socket.socket(AF_INET6, SOCK_STREAM)   -> OSError [Errno 97] EAFNOSUPPORT
/proc/net/if_inet6                     -> No such file or directory
/proc/sys/net/ipv6/conf/all/disable_ipv6 -> No such file or directory
ip(8)                                  -> command not found
```

**Live IPv6 execution: ENVIRONMENT-BLOCKED.** Trap noted: `socket.has_ipv6` is
`True` here and would mislead any check relying on it. Real `tcp6()` returns
`NO_IPV6_STACK` for every address — correctly inconclusive. The module fails
closed in this environment.

---

## CRITICAL

### F1 — The anti-regression suite survives ten independent weakenings at 42/42

`fixtures/test_preconditions.py` · EXECUTION-VERIFIED · **DEFECT**

Coverage traced against `ipv6_transport`:

```
COVERED      enforcement_verdict()  scoped_ll()  tcp6()
NOT COVERED  main()   <-- ALL of B1..B7 row logic
NOT COVERED  rec()    tunnel6()    v()
```

Ten weakenings applied to a disposable copy. **All ten left the suite green:**

| mutation | suite |
|---|---|
| `BLOCKING_OBSERVATIONS += ("PERMISSION_DENIED",)` | 42/42 |
| `BLOCKING_OBSERVATIONS += ("LINK_DOWN",)` | 42/42 |
| `enforcement_verdict`: `OTHER:*` → `PROVEN` | 42/42 |
| `scoped_ll` forced to `%lo` | 42/42 |
| `scoped_ll` → `if_nameindex()[-1]` (arbitrary iface) | 42/42 |
| B2 `injected = True` unconditionally | 42/42 |
| B6 `terminated = True` unconditionally | 42/42 |
| B7 `b7 = "PROVEN"` unconditionally | 42/42 |
| **B3 `direct in BLOCKING_OBSERVATIONS` → `direct != "REACHABLE"`** | 42/42 |
| B5 `intercepted = True` | 42/42 |

The membership assert at `:68-69` only checks the **union** of the two tuples,
so moving an observation between them satisfies it. The B3 mutation reverts the
row to "anything not REACHABLE proves enforcement" — the exact pre-remediation
semantics — and the suite stays green.

**The suite tests three helpers and never tests the code that consumes them.**

### F2 — B6: any exception counts as proof the kill switch fired

`ipv6_transport.py:518-524` · EXECUTION-VERIFIED · **DEFECT**

```python
truncated  = live and holder["clen"] and holder["partial"] < holder["clen"]
terminated = bool(holder["err"]) or truncated
"PROVEN" if (live and terminated) else ...
```

`holder["err"]` is set by a bare `except Exception` catching **anything**:

```
partial=10 clen=100 err='timeout'  -> PROVEN   | live, NOT killed, 40s client timeout
partial=10 clen=100 err='SSLError' -> PROVEN   | live, NOT killed, TLS error
partial=10 clen=  0 err='timeout'  -> PROVEN   | no Content-Length, NOT killed
partial=10 clen=100 err=''         -> PROVEN   | merely still slow at the deadline
```

A literal instance of the governing rule violated: a transport-stack failure
treated as evidence the PEP enforced a denial. **No attribution to the kill
switch is attempted anywhere in the row.** The only non-`err` route depends on
an unasserted 10s margin between `t.join(timeout=35)` and `SLOW_SECONDS=25`.
Raise `SLOW_SECONDS` past 35 and an unkilled stream reports `PROVEN`.

---

## HIGH

### F3 — `NO_ROUTE` as blocking rests on an unverified premise and contradicts the file's own reasoning

`ipv6_transport.py:132`, `:173-174` · EXECUTION-VERIFIED · **OVERSTATED**

Driving the shipping `main()` with `direct = NO_ROUTE`:

```
B1  PROVEN | B2  PROVEN | B3  PROVEN
```

For ENETUNREACH the kernel's FIB lookup failed and **no packet was emitted at
all**. The module concedes this at `:90-91` ("no — refused locally"), then
answers "opportunity to decide: yes" by appeal to topology.

* **The topology premise is never verified at runtime** — nothing checks the
  sandbox is on an `--internal` network, or that the missing route is *policy*
  rather than v6 simply never being configured on the egress side.
* **It contradicts the file's own standard.** EACCES/EPERM are excluded because
  "the packet never left the sandbox". ENETUNREACH is *also* a local refusal
  where the packet never left. Treated oppositely, asserted not demonstrated.
* **ENETUNREACH and EHOSTUNREACH are conflated** — the latter can be a returned
  ICMPv6 unreachable, i.e. genuinely remote. Collapsing them destroys the only
  distinction that could separate local refusal from something answering.
* **`stack_ok` does not close the gap** — it proves v6 works toward the PEP on
  the internal link, nothing about egress-side path capability.

Honest scope of B1/B3: *"no path existed outside the PEP while the PEP path
worked."* Real and useful. **Not** a demonstration that an enforcement point
received a packet and dropped it.

Credit, EXECUTION-VERIFIED: the rows do fail closed on the named confounds —
`CONNECTION_REFUSED` → inconclusive, `REACHABLE` → `FAILED_OPEN`, no control →
`NO_POSITIVE_CONTROL`.

### F4 — B2's injected route fails by topology, not policy

`ipv6_transport.py:365-387` · EXECUTION-VERIFIED · **DEFECT**

`rc=0` from `ip -6 route add` means the kernel accepted a FIB entry — not that
the routing decision changed. Two paths to `PROVEN` with no enforcement:

* **Source-address selection** — with no global v6 address on `eth0`,
  `connect()` still returns ENETUNREACH after a successful add.
* **Off-link on-link route** — both commands use `dev eth0` with no `via`, so
  the kernel does neighbour discovery for `TGT6` *on the internal link*. `TGT6`
  is on the egress network. **Nobody will ever answer.**

This is the identical confound B7 explicitly refuses to claim proof on. B2 has
it and reports `PROVEN`:

```
B2  PROVEN | after_injection=NO_ROUTE injected=True rc=0 rc=1
```

No `ip -6 route show` capture, no proof any packet was emitted. Step (3) fails.

### F5 — The `scoped_ll` assertion is *still* a tautology

`fixtures/test_preconditions.py:162-167` · EXECUTION-VERIFIED · **DEFECT**

```python
out = T.scoped_ll("fe80::1")
scoped_here = "%" in out
check(..., str(out if not scoped_here else "SCOPED_TO_" + out.split("%")[1]),
      "fe80::1" if not any(...) else "SCOPED_TO_" + out.split("%")[1])
```

**The expected value is computed from the function's own return.** Whenever the
result is scoped, `want` and `got` are the same expression:

```
scoped_ll->fe80::1%eth0   got=SCOPED_TO_eth0   want=SCOPED_TO_eth0   PASS (tautology)
scoped_ll->fe80::1%lo     got=SCOPED_TO_lo     want=SCOPED_TO_lo     PASS (tautology)
scoped_ll->fe80::1%veth9  got=SCOPED_TO_veth9  want=SCOPED_TO_veth9  PASS (tautology)
scoped_ll->fe80::1        got=fe80::1          want=IndexError -> SUITE CRASHES
```

The comment above it says the previous assertion was replaced *because* it was
one `scoped_ll` could not fail. **The replacement has the same property**, and
passes for `%lo` and for a veth — the arbitrary-interface outcome the docstring
says "would read as PROVEN". The one non-tautological path raises `IndexError`
and aborts the suite instead of reporting FAIL.

---

## MEDIUM

**F6** — The direct probe carries no nonce (`tcp6()` sends a bare SYN); the
nonce appears only on the *sanctioned* path. The negative half of B1/B3 is
structurally unfalsifiable from outside the sandbox — the only witness is the
process making the claim. CODE-VERIFIED · OVERSTATED

**F7** — B5 never calls `tls.getpeercert()`. It proves "allowed and decrypted",
not "intercepted". CODE-VERIFIED · OVERSTATED

**F8** — B7's `NOT_PROVABLE_IN_TOPOLOGY` is **the correct call** (argued both
ways: `fe80::1` is fabricated; TCP-connect to `ff02::1` fails by protocol
invariant; link-local scoping is structural). But `b7` can never equal `PROVEN`
while `rec()` is called with `expect="PROVEN"`, so **`main()` always returns 1 —
Layer B is permanently red by construction.** EXECUTION-VERIFIED · SOUND
(honesty) / DEFECT (consequence)

---

## LOW

**F9** — The `ETIMEDOUT` errno branch is **dead code**: Python maps it to
`TimeoutError`, which `except socket.timeout` catches first. The suite case
claiming to test it exercises a different path. EXECUTION-VERIFIED

**F10** — `tunnel6`: unprotected `sendall` (kills `main()`, artifact never
written) and a socket leak on header-read failure. CODE-VERIFIED

**F11** — B4 uses loose substring matching on the reason header. CODE-VERIFIED

---

## Assessed SOUND

`tcp6` except-clause ordering · `getaddrinfo` masks no errno, scope ids resolve
correctly · the `finally` block · `INCONCLUSIVE_OBSERVATIONS` membership (all
five correct with correct reasoning) · `enforcement_verdict` ordering and
fall-through (**cannot return PROVEN outside `BLOCKING_OBSERVATIONS`**;
`control_ok` dominates) · `scoped_ll` **implementation** (its test is the
defect) · **B4 — the sole row satisfying all five enforcement-point steps** ·
`v()` · `rec()`

**Direct answer on B4/B5/B6 passing on an absent prerequisite: no.** All three
gate correctly. B5 and B6 pass the gate and then draw a conclusion their
evidence does not support — over-inference, a different defect class.

---

## Coverage manifest

| ID / item | label | verdict |
|---|---|---|
| B1 | EXECUTION-VERIFIED | **OVERSTATED** (F3) |
| B2 | EXECUTION-VERIFIED | **DEFECT** (F4) |
| B3 | EXECUTION-VERIFIED | **OVERSTATED** (F3) |
| B4 | CODE-VERIFIED | **SOUND** |
| B5 | CODE-VERIFIED | **OVERSTATED** (F7) |
| B6 | EXECUTION-VERIFIED | **DEFECT** (F2) |
| B7 | EXECUTION-VERIFIED | SOUND (honesty) / DEFECT (F8) |
| B8 | **NOT-VERIFIED** | out of scope — **derives from B3+B5, inherits F3 and F7** |
| B9 | **NOT-VERIFIED** | out of scope — **derives from B6, inherits F2** |
| `tcp6()` | EXECUTION-VERIFIED | DEFECT (F3) / ordering, getaddrinfo, finally SOUND |
| `enforcement_verdict()` | EXECUTION-VERIFIED | **SOUND** |
| `scoped_ll()` | EXECUTION-VERIFIED | **SOUND** (impl) |
| `BLOCKING_OBSERVATIONS` | EXECUTION-VERIFIED | **DEFECT** |
| `INCONCLUSIVE_OBSERVATIONS` | EXECUTION-VERIFIED | **SOUND** |
| `tunnel6()` | CODE-VERIFIED | DEFECT (F10) |
| `v()` / `rec()` | CODE-VERIFIED | SOUND |
| `main()` | EXECUTION-VERIFIED | **DEFECT** — untested by any suite |
| `test_preconditions.py` | EXECUTION-VERIFIED | **DEFECT** (F1 + F5) |

`gateway.py`, `pdp.py`, `pep_client.py`, the gate script, certificates, A1–A30,
E1–E8, PP1–PP17 were **not examined** — NOT-VERIFIED. **Absence from this report
is not acceptance.**

---

## Status

```
LIVE_EXECUTION_STATUS = ENVIRONMENT-BLOCKED
    AF_INET6 -> EAFNOSUPPORT. No Layer B row was executed against a real IPv6
    topology. All execution above was of DECISION LOGIC under simulated
    transport primitives, in /tmp/audit-ws, never on the target.

AUDIT_INTEGRITY = VERIFIED
    pre : bcbc636cd01b2d2491c243ce9e84926262046704ee47e71315174dbeff4c13f3
    post: bcbc636cd01b2d2491c243ce9e84926262046704ee47e71315174dbeff4c13f3
    Target byte-for-byte unchanged. run_fixtures.sh was NOT run on the target.

CODE_AUDIT_STATUS = COMPLETE for Pass-1 scope
    ipv6_transport.py (544 lines) and test_preconditions.py (226 lines) read in
    full. Out-of-scope files not examined.

TRANSPORT_EVIDENCE_STATUS = INSUFFICIENT — NOT PROVEN
    No Layer B transport row establishes both step (2) and step (3):
      B1, B3  step (3) unproven — NO_ROUTE/TIMEOUT do not show the boundary
              received the probe; no correlatable trace outside the sandbox
      B2      step (3) unproven — failure explained by topology alone
      B6      steps (3) and (4) unproven — any exception accepted as proof
      B7      self-declared NOT_PROVABLE (correctly)
      B4      the sole row satisfying all five steps
      B5      prerequisite sound; interception inference unsupported
    Compounding: the suite meant to prevent exactly this class survives ten
    weakenings at 42/42, including reverting B3 to pre-remediation semantics.
    B8 and B9 inherit these gaps.
```

No release recommendation offered — that gate is the operator's to apply.

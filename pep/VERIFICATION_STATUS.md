# Verification Status — §10 NO UNVERIFIED CLAIMS

Applied retroactively to the remediation diagnostic. My previous report said
"FIXED" ten times without distinguishing what was executed from what was only
read. That is the false confidence §10 exists to prevent, so every claim is
relabelled here.

**Labels**

| | Meaning |
|---|---|
| `CODE-VERIFIED` | implementation inspected; conclusion follows from the source |
| `EXECUTION-VERIFIED` | the test/command was actually run and the result observed |
| `ENVIRONMENT-BLOCKED` | inspectable, but live behaviour could not be exercised here |
| `NOT-VERIFIED` | required source, runtime evidence or artifact was unavailable |

`ENVIRONMENT-BLOCKED` and `NOT-VERIFIED` are never upgraded to SOUND.

---

## What blocks verification in this container

```
AF_INET6 socket : REFUSED — OSError [Errno 97] Address family not supported
/proc/net/if_inet6 : ABSENT
```

**Consequence, stated plainly: the dual-stack listener has never executed.**
The last live run recorded:

```
STARTUP_DEGRADED | IPV6_LISTENER_UNAVAILABLE | OSError: [Errno 97] ...
STARTUP          | PEP_READY | IPv4-ONLY(fallback: OSError: [Errno 97] ...)
```

Only the **fallback branch** has ever run. `DualStackHTTPServer`'s `AF_INET6`
bind with `IPV6_V6ONLY=0` has **zero successful executions** anywhere. Layer B
rows B1–B7 have **zero executions**. Everything I claimed about IPv6 behaviour
rests on reading code, not on watching it work.

---

## The independent audit did not complete

The adversarial review pass I commissioned was **terminated mid-run by a session
limit** and returned no usable findings.

> `Agent terminated early due to an API error: You've hit your session limit`

**Status: `NOT-VERIFIED`.** This is not "the audit found nothing" — it is "the
audit did not finish". The previous audit round (which did complete) found ten
defects, seven outside the original scope; there is no basis to assume this
round would have found zero. **The suite has not passed an independent review in
its current state.**

---

## Claim-by-claim

### Fixes with observed execution

| Claim | Label | Evidence |
|---|---|---|
| IPv4 enforcement path holds with attribution now required on PP2/3/4/5/6/8/10/13 | `EXECUTION-VERIFIED` | live run 17/17 + PP18 `PROVEN`; every required reason observed in raw audit (`SNI_MISMATCH`, `HOST_HEADER_MISMATCH`, `METHOD_DENIED`, `OUT_OF_SCOPE`, `IP_NOT_AUTHORIZED:172.29.0.30`, `CREDENTIAL_WRONG_PROGRAM`, `UPSTREAM_CERT_INVALID`) |
| D5 (A20) + D6 (Layer A attribution) | `EXECUTION-VERIFIED` | `Layer A (policy logic): 30/30` after `denied_by()` applied to all six DENY groups |
| D10 (PP16 positive control) | `EXECUTION-VERIFIED` | `PP16 PROVEN limit=64 ok=0 pool_serves=True control=ALLOW` |
| D7 (tcp6 coverage) is a real regression test | `EXECUTION-VERIFIED` | reintroducing `except Exception: return "BLOCKED"` fails **12** assertions; the pre-remediation suite stayed green with the same defect |
| D8, D9 (scope fallback, observation partition) | `EXECUTION-VERIFIED` | 13 errno assertions drive the real `tcp6()`; 42/42 |
| Evidence model unregressed | `EXECUTION-VERIFIED` | 22 fixtures · 20 verifier self-tests · 3 pipeline-order · 42 preconditions, `BATTERY: PASS` exit 0 |
| Fallback branch is loud and audited | `EXECUTION-VERIFIED` | `STARTUP_DEGRADED` record observed above |

### Fixes verified only by reading

| Claim | Label | Why not more |
|---|---|---|
| **Dual-stack listener accepts IPv6 clients** | `ENVIRONMENT-BLOCKED` | the `AF_INET6` bind cannot execute here. `IPV6_V6ONLY=0` placement before `super().server_bind()` is `CODE-VERIFIED`; that it *works* is not verified at all |
| **D1 — v6 hostnames now certifiable** | split | cert artifacts `EXECUTION-VERIFIED` (`up/allowed.lab` → `DNS:allowed.lab,DNS:allowed6.lab`; `up/slow.lab` → `DNS:slow.lab,DNS:slow6.lab`, openssl output observed). That this makes Layer B's positive control succeed: `ENVIRONMENT-BLOCKED` |
| **D4 — B2 route injection** | `CODE-VERIFIED` | B2 has never executed. Whether removing `addr add` makes it meaningful is untested |
| **D3 — B7 `NOT_PROVABLE_IN_TOPOLOGY`** | `CODE-VERIFIED` | the reasoning is a code/topology argument. Never executed |
| **D2 — PP2/PP8 require `UPSTREAM_CERT_INVALID`** | `EXECUTION-VERIFIED` on IPv4 | both pass live and the reason appears in raw audit. The v6 equivalents: `ENVIRONMENT-BLOCKED` |
| **v4-mapped source canonicalization** | split | the unwrap logic is `EXECUTION-VERIFIED` (5 assertions against the real `_program_for_source`). That it is *needed and sufficient* for a live dual-stack listener: `ENVIRONMENT-BLOCKED` |
| **D8 topology parity** | `CODE-VERIFIED` | diffed `scope_allow`/`authorized_ips`/`private_ip_exemptions`/`dns_zone`/credentials against `run_pep.sh`, no gaps. The gate itself has not run since |

### Not verified at all

| Claim | Label |
|---|---|
| Independent adversarial review of the current state | `NOT-VERIFIED` — terminated by session limit |
| Any Layer B row (B1–B9) | `NOT-VERIFIED` — zero executions, ever |
| That the ten fixes introduced no *new* defect of the same class | `NOT-VERIFIED` — that was the terminated audit's job |

---

## Where this leaves the project

Unchanged, and now for a documented reason rather than an inferred one:

```
Layer A          30/30 PROVEN         (EXECUTION-VERIFIED)
Layer B          0/9 BLOCKED_ENV      (NOT-VERIFIED — never executed)
IPv4 regression  17/17 + PP18 PROVEN  (EXECUTION-VERIFIED)
Evidence suites  22 / 20 / 3 / 42     (EXECUTION-VERIFIED)
Independent review                    (NOT-VERIFIED — did not complete)
IPv6             UNKNOWN
RELEASE          BLOCKED
STRIX            MUST NOT RUN
Strix            0478a69, 0 dirty
```

**Two things must happen before the full gate is meaningful, and neither has:**

1. **The B7 specification decision is yours.** `NOT_PROVABLE_IN_TOPOLOGY` means
   `Layer B = 9/9` is unreachable as specified. I did not take that decision.
2. **The independent review must actually complete.** Re-run it in a fresh
   session; the last completed round found seven defects nobody had scoped.

The most honest one-line summary: **the IPv4 half is tested and the IPv6 half is
argued.** Reading code is not running it, and I should have drawn that line in
the previous report rather than writing "FIXED" ten times.

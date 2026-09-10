# Production PEP v1 — Build Report

**Status: BUILT, NOT PRODUCTION-READY.** The IPv6 acceptance gate is **NOT PASSED**, so by your own rule the PEP does not get a "secure" stamp.

| Item | State |
|---|---|
| PEP with IPv6 in the decision path from the start | **BUILT** |
| IPv6 acceptance — Layer A (policy logic) | **24/24 PROVEN** |
| IPv6 acceptance — Layer B (transport) | **0/7 — BLOCKED_ENV** |
| **IPv6 gate** | 🔴 **NOT PASSED** (suite exits non-zero) |
| **IPv6 status** | 🔴 **UNKNOWN / RELEASE BLOCKER** |
| Production hardening | implemented (§4) |
| PEP verification (IPv4 path) | **17/17** |
| Strix | untouched, `0478a69`, tree clean |

---

## 1. Why IPv6 could not be closed here — and it is not close-able here

```
/proc/cmdline: … nomodule random.trust_cpu=1  ipv6.disable=1  swiotlb=noforce …
```

The kernel has `CONFIG_IPV6=y`, but it was booted with **`ipv6.disable=1`**, so the stack was never initialized: no `/proc/net/if_inet6`, and **no `/proc/sys/net/ipv6` tree at all** (`ls /proc/sys/net` → `bridge core ipv4 mptcp netfilter unix`). Docker confirms it independently:

```
Cannot read IPv6 setup for bridge br-…: open /proc/sys/net/ipv6/conf/…/disable_ipv6:
no such file or directory
```

This is not a permissions or configuration problem I can work around — `modprobe` cannot help because IPv6 is built in, not a module, and a boot parameter cannot be revoked at runtime. **Closing IPv6 requires a different host/VM booted without `ipv6.disable=1`.** That is the entire remaining requirement.

---

## 2. The gate refuses to pass, by construction

`pep/ipv6_acceptance.py` splits the required matrix into two layers and **hard-fails** rather than skipping:

```
  Layer A (policy logic): 24/24
  Layer B (transport):    0/7   [no /proc/net/if_inet6 (IPv6 stack not initialized)]
  IPv6 GATE: NOT PASSED
  IPv6 STATUS: UNKNOWN / RELEASE BLOCKER
```
Exit code **1**. Transport rows report `BLOCKED_ENV`, not `SKIP`, precisely because a skipped row reads like a passed row months later. No pipeline can mistake IPv4 success for an IPv6 result.

### Layer A — 24/24 PROVEN (deciding *about* IPv6 needs no IPv6 stack)

| Row | Requirement | Result |
|---|---|---|
| A1 | `::1` loopback | DENY |
| A2 | `fe80::/10` link-local | DENY |
| A3 | `fc00::/7` ULA | DENY |
| A4 | `::ffff:169.254.169.254` judged by **embedded** v4 | DENY `link_local_denied_via_ipv4_mapped` |
| A5 | 6to4 `2002:7f00:1::1` wrapping 127.0.0.1 | DENY `loopback_denied_via_6to4` |
| A6, A9, A10 | public IPv6 allowed; pin carries `family=ipv6` | ALLOW |
| A7 | `[2001:DB8::1]` → `2001:db8::1` | canonicalized |
| A8 | ambiguous octal `0177.0.0.1` | rejected |
| A11–A15 | names resolving to blocked v6 classes | DENY |
| **A16** | **valid A + blocked AAAA → DENY (no v6→v4 fallback)** | DENY |
| **A17** | valid AAAA + blocked A → DENY (validate **all** families) | DENY |
| **A18** | no AAAA at all → v4 is normal (**absence ≠ denial**) | ALLOW |
| A19–A20 | IPv6 rebinding: 1st allowed, 2nd flip denied | correct |
| A21 | pinned connection does not re-resolve | ALLOW |
| A22 | AAAA present but family disabled → DENY, no fallback | DENY |
| A23 | policy source failure → fail closed | DENY |
| A24 | resolver failure → fail closed | DENY |

A16/A18 together encode the distinction you asked for: **denial of a family is not the same as absence of a family.** A missing AAAA legitimately uses A; a *refused* AAAA denies the whole request rather than quietly downgrading.

A4/A5 are the subtle ones. `::ffff:169.254.169.254` and `2002:7f00:1::1` are IPv6 addresses that carry a blocked IPv4 inside them. `addressing.unwrap_embedded_v4()` unwraps ipv4-mapped, 6to4, Teredo and NAT64 and judges the **embedded** address, so a blocked v4 cannot be smuggled past by re-encoding it as v6.

### Layer B — 0/7, blocked by environment

`direct IPv6 egress bypass` · `IPv6 route injection via NET_ADMIN` · `public IPv6 reachable through the PEP` · `Host/SNI over IPv6 destination` · `TLS interception over IPv6` · `kill switch on live IPv6 connections` · `IPv6 link-local egress at transport`.

All report `BLOCKED_ENV`. These are the rows that make IPv6 real, and none of them ran.

---

## 3. Architecture — one decision path, two families

`pep/pdp.py` has exactly one `decide()`. IPv4 and IPv6 differ only as **data** (which family a `Pin` carries), never as control flow, so an address-family bypass cannot hide in an unvisited branch.

```
kill switch → program identity → authorization record → budgets
→ canonicalize (both families) → IP-literal policy → scope → port
→ CONNECT/method → resolve A **and** AAAA
→ validate EVERY answer in BOTH families (one bad answer poisons the name)
→ family selection (absence ≠ denial; no automatic v6→v4 fallback)
→ Pin(family, ip, port) → credential binding
```

`Pin` is `(address_family, ip, port)` and is established **once** per connection. Passing it back into `decide()` suppresses resolution entirely, so a connection resolves once and stays bound — the fix that came out of Phase 2b's D-3.

TLS SNI and HTTP `Host` are both compared against the **canonical hostname**, and `CONNECT` remains an independent default-deny switch (`allow_connect`), never an entry in `allowed_methods`.

---

## 4. Production hardening — status

| Item | Implemented | Evidence |
|---|---|---|
| Streaming instead of full buffering | ✅ | 2 MB response relayed in 64 KB chunks, hashed incrementally (PP14/PP15) |
| Concurrency limits | ✅ | bounded pool; excess → audited `503 CONCURRENCY_LIMIT_REACHED` (PP16) |
| Connection lifecycle management | ✅ | `ConnectionState` + registry, idle/total timeouts, registry-driven teardown |
| HTTP/1.1 first | ✅ | HTTP/2 deliberately out of scope |
| Per-connection pin state | ✅ | pin carried in `ConnectionState`, reused via `decide(pin=…)` |
| Dynamic CA minting | ✅ | 4 leaves minted on demand; never-seen host got `DNS:neverseen.allowed.lab` |
| Secure key storage | ✅ | `ca.key` **600**, leaf keys **600**; sandbox mount contains only `ca.crt` |
| Append-only audit | ✅ | `O_APPEND` + `fsync`, SHA-256 **hash chain**; 81 records verified intact |
| Tamper evidence | ✅ | editing one record → `line 42: chain break` |
| Crash/restart semantics | ✅ | torn partial line appended, PEP restarted, re-anchored and served normally |
| Fail-closed on PDP/DNS/cert failure | ✅ | corrupt policy → `403 POLICY_UNAVAILABLE:JSONDecodeError`; A23/A24 cover resolver and policy failure |

## 5. IPv4-path verification — 17/17

Core enforcement survives the rewrite: dynamic minting, out-of-scope denial, SNI mismatch, `Host` mismatch inside the tunnel, method policy inside the tunnel, 3xx not auto-followed, untrusted upstream cert failing closed, rebinding flip denied, credential injection with correct/incorrect tuples, streaming, concurrency limit, and kill switch on live connections.

---

## 6. Defects found while building

**D-6 — `ConnectionState` was unhashable.** A plain `@dataclass` generates `__eq__`, which sets `__hash__ = None`; `registry.add()` then raised `TypeError: unhashable type`. Fixed with `@dataclass(eq=False)` — identity semantics are what a registry of live connections actually wants.

**D-7 — semaphore leak causing a self-inflicted DoS (the important one).** `registry.acquire()` sat **outside** the `try/finally`, so D-6's crash leaked a slot on every connection. Within 16 requests the pool hit zero and the PEP answered `CONCURRENCY_LIMIT_REACHED` to everything, permanently. It failed *closed*, which is the right direction — but a gateway that denies itself to death after N errors is an availability bug an attacker could trigger deliberately. Fixed by moving acquisition inside the guarded region.

Worth noting the pattern: both bugs were invisible to unit-level reasoning and only appeared under the full harness, and the audit log (`78 × CONCURRENCY_LIMIT_REACHED`, zero successes) is what localized them.

**Test-design error (mine, not the PEP's):** PP2 originally expected ALLOW for a never-seen host, but the upstream only holds a cert for `allowed.lab`, so the PEP minted the leaf and then correctly failed closed on the upstream name mismatch. Reframed to assert the correct behaviour, with minting verified host-side from the leaf directory.

---

## 7. What is NOT proven

- **IPv6 at transport — UNKNOWN, release blocker.** Nothing here softens it.
- **Anything about Strix.** Not run, not modified.
- **A hostile authoritative nameserver.** The lab zone is deterministic with a `sequence` primitive; the production `Resolver` uses `getaddrinfo` (A+AAAA) but has not been exercised against real DNS.
- **HTTP/2, connection reuse, load behaviour beyond the concurrency test.**
- **Certificate revocation / CRL / OCSP**, and CA key custody beyond filesystem permissions (no HSM, no KMS).

---

## 8. Next gate

The only thing standing between this and a valid PEP is a host booted **without `ipv6.disable=1`**. On such a host:

1. Run `pep/ipv6_acceptance.py` — Layer A should stay 24/24 and Layer B rows must be wired to the live topology and turned green.
2. Re-run `pep/run_pep.sh` with dual-stack targets so PP1–PP17 execute over both families.
3. Only then does the PEP become eligible for the Strix observation run — which, per constraint 8, is still an observation experiment and not a security proof.

I have not marked anything here as secure. The gate says NOT PASSED and exits 1, and that is the honest state.

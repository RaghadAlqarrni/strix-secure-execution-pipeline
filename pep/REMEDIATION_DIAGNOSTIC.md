# Remediation Diagnostic — §10

**The release gate was NOT run.** Per §2 this is the diagnostic phase only.
Status is unchanged: `IPv6 = UNKNOWN` · `RELEASE = BLOCKED` · `STRIX = MUST NOT RUN`.

Strix untouched: `0478a69`, 0 dirty files.

---

## A. IPv6 listener

**What changed.** `gateway.py` gained `DualStackHTTPServer(address_family = AF_INET6)`
and `serve()` now binds `::`.

**Address family.** Was `AF_INET` — `ThreadingHTTPServer` inherits it from
`socketserver.TCPServer`, so `("0.0.0.0", 3128)` produced an IPv4-only socket and
every IPv6 client got `ECONNREFUSED`. Now `AF_INET6` bound to `::`.

**`IPV6_V6ONLY`.** Set **explicitly** to `0` in `server_bind()`, before
`super().server_bind()`, rather than relying on the platform default (which
differs across kernels and distributions).

**Does IPv4 still work.** Yes — 17/17 live on this host. But not for free:
a v4 peer on a `::` socket is reported as `::ffff:a.b.c.d`, which matched no v4
CIDR, so `_program_for_source` returned `NO_PROGRAM_FOR_SOURCE` and **every**
IPv4 request would have failed closed. `pdp.py` now canonicalizes that form.

**Address-family validation was not weakened.** Only `ipv4_mapped` is unwrapped
for source attribution. `6to4`, `Teredo` and `NAT64` are deliberately **not**:
those are address *content*, and the sandbox holds `NET_ADMIN`/`NET_RAW`, so
unwrapping them would let a peer choose an address whose embedded IPv4 lands
inside another program's CIDR. `addressing.unwrap_embedded_v4()` unwraps all
four — correct for *destinations* ("what will this reach"), wrong for *sources*
("who is this"). Regression coverage added (5 assertions).

**Honest limit on that argument.** The safety rests on the kernel refusing to
deliver a native-v6 packet bearing a v4-mapped source. `_program_for_source`
receives a string and cannot verify that itself. No bypass in this topology
(both CIDRs map to the same program); the exposure would be a multi-program
deployment sharing one v6 segment.

**Fallback.** A host without IPv6 falls back to IPv4-only, but **loudly**: a
`STARTUP_DEGRADED` audit record, `listener`/`listen_family`/`listen_addr` on the
`STARTUP` record, and a stderr warning. The auditor now prints the degradation
and states that Layer B cannot pass in that state. Verified live on this
IPv6-less host: `IPV6_LISTENER_UNAVAILABLE — OSError: [Errno 97]`.

---

## B. B7

**Previous false-positive mechanism — two of them.**
1. No positive control: with IPv6 entirely dead both probes failed and B7
   reported `PROVEN`. It would have passed on a host with link-local egress open.
2. No scope id: `fe80::` is not routable without `%iface`, so bare `fe80::1`
   fails with `EINVAL` — a malformed probe, also read as "blocked".

**What was added.** A positive control (`via_ok and stack_ok`), scope-id
attachment via `scoped_ll()` + `getaddrinfo`, and distinguishable observations.

**What happens when the positive control fails.** `NO_POSITIVE_CONTROL`.

**B7 still cannot prove its claim, and now says so.** A third route is not
closable by implementation. `fe80::1` is fabricated — nothing holds it, so
"nobody answered neighbour discovery" yields `TIMEOUT`/`EHOSTUNREACH`,
byte-identical to a netfilter DROP. The confound is structural: link-local is
scoped *to the link*; the sandbox and PEP share one link (reachable by design),
the egress targets are on another (unreachable regardless of enforcement).
Neither outcome is attributable to the boundary.

B7 therefore reports **`NOT_PROVABLE_IN_TOPOLOGY`** and the gate stays blocked.
Proving it needs a real, occupied link-local peer that policy should deny — a
topology change *and* a change to what the row asserts. **That is a
specification decision and is referred to you, not taken here.**

---

## C. PP10

**What made the previous BLOCK meaningless.** It accepted any `BLOCK`.
`rebind.lab` was never provisioned in the gate, so the denial was `OUT_OF_SCOPE`
— rebinding protection was never reached.

**How the new test isolates rebinding.** The full chain must hold: PP9 (in
scope, resolves to IP A, A authorized, ALLOWED) is PP10's positive control; then
the denial must be `IP_NOT_AUTHORIZED:` **and** name the exact flipped-to IP
(`REBIND_SECOND_IP`). Any other denial reports
`BLOCKED_FOR_OTHER_REASON:<code>`. Live: `IP_NOT_AUTHORIZED:172.29.0.30
expect_ip=172.29.0.30`.

---

## D. PP9 / topology drift

**What was missing from the gate:** `rebind.lab`, `badcert.lab`,
`neverseen.allowed.lab`, `evil.lab` in `dns_zone`, and the `cred_beta`
credential.

**How it was reproduced.** `gate_rebind` at `172.29.0.50` (flipping to
`172.29.0.30`, exempt so it survives classification but absent from
`authorized_ips`), `gate_badcert` at `172.29.0.70` serving a **rogue-signed**
leaf, both v6 siblings, plus the missing zone entries and credentials. Verified
by diffing `scope_allow` / `authorized_ips` / `private_ip_exemptions` /
`dns_zone` / credentials against `run_pep.sh` — no remaining gaps.

**PP9 also self-verifies now:** a denial from `OUT_OF_SCOPE` or `DNS_NO_*`
reports `NO_TARGET_PROVISIONED`, naming topology drift instead of scoring it as
an enforcement failure.

---

## E. Additional audit (§7) — other tests that could pass on an absent prerequisite

An independent adversarial review was run over every negative test. **Ten
defects, seven of them not in the original scope.**

| # | Defect | Status |
|---|---|---|
| D1 | **No upstream certificate existed for `allowed6.lab` / `slow6.lab`.** The PEP verifies upstream with `check_hostname=True`, so Layer B's positive control could never succeed — **Layer B could not have passed even with the listener fixed** | FIXED — multi-SAN upstream leaves |
| D2 | PP2/PP8 accepted `UPSTREAM_ERROR`, the gateway's catch-all around `socket()`/`connect()`/`wrap_socket()`. A dead container would have passed both | FIXED — `UPSTREAM_CERT_INVALID` only |
| D3 | B7 (above) | REPORTED — `NOT_PROVABLE`, spec decision |
| D4 | B2 injected `ip -6 addr add TGT6/128`, making the target **local**; the probe was delivered to the sandbox itself. Its `injected` guard was satisfied by exactly the command that meant no route was injected | FIXED — routes only, guard corrected |
| D5 | **A20** flipped to `::1`, which `classify()` rejects as loopback before the authorization check — Layer A's own PP10 | FIXED — flips to a routable unauthorized address |
| D6 | **Every** Layer A DENY row asserted only `not r.allow`. One mis-provisioned zone key silently converts a class-enforcement proof into a DNS failure that still reads green | FIXED — `denied_by()`; still 30/30 |
| D7 | `test_preconditions.py` had one tautological assertion, and **`tcp6()` — the actual fix for the original defect — had zero coverage** | FIXED — 13 errno assertions; negative control below |
| D8 | `scoped_ll()`'s documented fallback picked an *arbitrary* interface (`if_nameindex()[-1]`, possibly `lo`); a probe on the wrong link reads as `PROVEN` | FIXED — no fallback; unscoped → inconclusive |
| D9 | `PERMISSION_DENIED` counted as blocking. EACCES/EPERM is a **local** refusal — the packet never left the sandbox, so the boundary never decided. `ENETDOWN` (interface down) was classed as `NO_ROUTE` | FIXED — both inconclusive / `LINK_DOWN` |
| D10 | **PP16 recorded `limit=64 ok=0`** — it proved the limiter rejects while never showing the pool serves anything. A limiter that rejected *everything* passed identically | FIXED — explicit positive control |

**Open, reported not fixed:** B7 (spec decision, above); `CONNECTION_REFUSED →
INCONCLUSIVE` means a boundary using `-j REJECT --reject-with tcp-reset` would
make B1/B2/B7 permanently non-provable (does not bite on this
absence-of-route topology, but it is a design constraint worth stating); the
degraded-listener signal is printed by the auditor but is not itself a scored
check; PP17 cannot distinguish a kill from an idle timeout on its own and
defers to PP18, which the gate gates on independently.

---

## F. Evidence auditor — regression check

No regression. New status strings (`NO_POSITIVE_CONTROL`, `INCONCLUSIVE_*`,
`FAILED_OPEN`, `NOT_PROVABLE_IN_TOPOLOGY`, `BLOCKED_FOR_OTHER_REASON:*`,
`DENIED_FOR_OTHER_REASON:*`) are all non-`PROVEN`, so E1's strict whitelist
rejects them by construction.

```
fixtures behaving correctly: 22   incorrect: 0
VERIFIER SELF-TEST:          20/20
PIPELINE ORDER:              3/3
PRECONDITION FIXTURES:       42/42
BATTERY: PASS                (exit 0)
```

**The adversarial fixtures still fail correctly** — all 21 forgeries rejected,
`CERTIFIED`/exit 0 for the honest set only.

**Negative control on the new coverage.** Reintroducing the original defect
(`except Exception: return "BLOCKED"`) makes **12 precondition assertions fail**.
Before this suite existed, the same defect left every test green.

**Live IPv4 regression on all changed code: 17/17 + PP18 `PROVEN`** — with
attribution now required on PP2, PP3, PP4, PP5, PP6, PP8, PP10, PP13 and all six
Layer A DENY groups. Every required reason was observed in the raw audit
(`SNI_MISMATCH`, `HOST_HEADER_MISMATCH`, `METHOD_DENIED`, `OUT_OF_SCOPE`,
`IP_NOT_AUTHORIZED`, `CREDENTIAL_WRONG_PROGRAM`, `UPSTREAM_CERT_INVALID`), so
the assertions are not over-strict.

---

## Under the standing rule: these tests are still UNTRUSTED

Every modified component is untrusted until its live results survive review.
Nothing here has run on a dual-stack host. Specifically:

* **Layer B has still never executed.** B1–B6 will run for the first time. Rows
  that pass will be claims that have never been tested, and get the same
  scrutiny as B7 and PP10 — not a presumption of correctness.
* **A rising Layer B count is not progress information.** It is a new set of
  claims requiring the same audit.
* **B7 cannot reach `PROVEN` as currently specified**, so `Layer B = 9/9` is
  unreachable without a decision from you.

**Do not run the full gate until you have decided the B7 question.**

# Phase 2a — Security Boundary Proof

**Thesis tested:** *a client in the sandbox position, actively trying to escape, cannot reach any destination except through the PDP, and the PDP denies by default.*

**Result: 34/34 matrix rows behaved as required**, plus 6 supplementary control checks. **Two defects were found and fixed by the suite**, and **one architectural gap was discovered** that changes the design (§5).

**Adversary:** a deliberately hostile Python client, **not Strix** — per standing constraint 8. A hostile client is strictly stronger than a model: it attempts every bypass unconditionally rather than only what an LLM happens to try. Nothing here is a claim about Strix's behaviour.

**Constraint compliance:** Strix not modified (tree clean at `0478a69`), no substitute Strix image used, no real targets, no real credentials, no provider APIs. All containers local and disposable.

---

## 1. Topology under test

```
   p2a_egress 172.29.0.0/24  (normal bridge)
     ├── p2a_allowed 172.29.0.20   (in-scope target)
     ├── p2a_evil    172.29.0.30   (out-of-scope target, serves the 302)
     ├── p2a_other   172.29.0.40   (in-scope host, NOT a credential destination)
     └── p2a_gw      172.29.0.10   ── PDP / Execution Gateway (tri-homed)
                                        │            │
                    172.31.0.10 ────────┘            └──────── 172.32.0.10
                          │                                        │
        p2a_prog_a 172.31.0.0/24 (internal)      p2a_prog_b 172.32.0.0/24 (internal)
          └── p2a_sbx_a 172.31.0.50                └── p2a_sbx_b 172.32.0.50
              cap_add NET_ADMIN, NET_RAW              (authorization EXPIRED)
              + host.docker.internal host-gateway
```

The sandbox was deliberately given **the worst-case posture Strix ships today** — `NET_ADMIN`, `NET_RAW`, and the `host.docker.internal` mapping — so the proof holds even before the least-privilege backend exists.

---

## 2. Results — network layer (direct escape attempts, no proxy)

| # | Attempt | Expected | Got |
|---|---|---|---|
| N1 | direct TCP to the in-scope target (bypass the proxy entirely) | BLOCKED | **BLOCKED** |
| N2 | direct TCP to public internet `1.1.1.1:443` | BLOCKED | **BLOCKED** |
| N3 | direct TCP to the docker bridge gateway | BLOCKED | **BLOCKED** |
| N4 | direct TCP to link-local metadata `169.254.169.254` | BLOCKED | **BLOCKED** |
| N5 | external DNS resolution | BLOCKED | **BLOCKED** |
| N6 | reach the gateway (intended control channel) | REACHABLE | **REACHABLE** |
| N7 | reach the **other program's** sandbox | BLOCKED | **BLOCKED** |
| N8 | egress after `ip route add default` + `ip addr add` spoof | BLOCKED | **BLOCKED** |
| N9 | in-scope target after route injection | BLOCKED | **BLOCKED** |

N7 is the empirical justification for **one internal network per program** (standing constraint 7): with a shared network this is reachable; with per-program networks it is not.

## 3. Results — PDP layer (through the gateway)

| # | Case | Expected | Got | Denial reason |
|---|---|---|---|---|
| P1 | in-scope host | ALLOW | **ALLOW** | — |
| P2 | unknown host (default deny) | BLOCK | **BLOCK** | `OUT_OF_SCOPE` |
| P3 | denylisted subdomain (deny beats allow) | BLOCK | **BLOCK** | `OUT_OF_SCOPE` |
| P4 | bare IP literal | BLOCK | **BLOCK** | `IP_LITERAL_DENIED` |
| P5 | `Host:` header ≠ request-line authority | BLOCK | **BLOCK** | `HOST_HEADER_MISMATCH` |
| P6 | host resolving to link-local | BLOCK | **BLOCK** | `DNS_ANSWER_REJECTED:link_local_denied` |
| P7 | host resolving to RFC1918 | BLOCK | **BLOCK** | `DNS_ANSWER_REJECTED:rfc1918_denied` |
| P8 | answer set with one good + one bad IP | BLOCK | **BLOCK** | `DNS_ANSWER_REJECTED` |
| P9 | rebinding — 1st lookup authorized | ALLOW | **ALLOW** | — |
| P10 | rebinding — 2nd lookup flips to hostile IP | BLOCK | **BLOCK** | `IP_NOT_AUTHORIZED:172.29.0.30` |
| P11 | 3xx returned, **not followed** by gateway | REDIRECT | **REDIRECT** | — |
| P12 | client follows the redirect → re-enters PDP | BLOCK | **BLOCK** | `OUT_OF_SCOPE` |
| P13 | canonicalization (`ALLOWED.LAB.` uppercase + trailing dot) | ALLOW | **ALLOW** | — |
| P14 | method not in policy (`DELETE`) | BLOCK | **BLOCK** | `METHOD_DENIED` |
| P15 | port not in policy | BLOCK | **BLOCK** | `PORT_DENIED` |
| P16 | correct credential tuple → injected upstream | ALLOW | **ALLOW** | — |
| P17 | upstream actually received the credential | YES | **YES** | — |
| P18 | credential belonging to **another program** | BLOCK | **BLOCK** | `CREDENTIAL_WRONG_PROGRAM` |
| P19 | credential used on the wrong asset | BLOCK | **BLOCK** | `CREDENTIAL_WRONG_ASSET` |
| P20 | credential used on the wrong destination | BLOCK | **BLOCK** | `CREDENTIAL_WRONG_DESTINATION` |
| P21 | per-asset budget exhaustion (3rd request) | BLOCK | **BLOCK** | `BUDGET_EXHAUSTED_ASSET` |
| P22 | `CONNECT` to a disallowed port | BLOCK | **BLOCK** | `PORT_DENIED` |
| P23 | `CONNECT` to an out-of-scope host | BLOCK | **BLOCK** | `OUT_OF_SCOPE` |
| P24 | `CONNECT` to in-scope host/port | ALLOW | **ALLOW** | — |
| P25 | malformed `CONNECT` target | BLOCK | **BLOCK** | `MALFORMED_CONNECT_TARGET` |

## 4. Supplementary control-plane checks

| Check | Result |
|---|---|
| Expired authorization (program B, in-scope request) | **BLOCKED** — `AUTHORIZATION_EXPIRED` |
| Credential plaintext anywhere in sandbox-visible data | **NOT PRESENT** — secret exists only in gateway-side policy |
| Credential precision | exactly **1** upstream request carried `auth_present: true`; 5 did not |
| Kill switch — file-based, control plane, out-of-process | previously-ALLOWED request → **`KILL_SWITCH_ACTIVE`**; restored after clearing |
| Kill switch — `docker kill --filter label=strix-run-id` | labeled container **TERMINATED** (fully outside the agent process) |
| Audit completeness | 29 decisions logged (9 ALLOW / 20 BLOCK), **16 distinct denial reasons**, every ALLOW carries `pinned_ip`, `resolved`, `request_hash`, `response_hash`, `redirect_followed:false` |

The single ALLOW without request/response hashes is the `CONNECT` tunnel — which is itself the finding in §5.

---

## 5. Defects found by the suite (this is the point of running it)

**D-1 — unimplemented verbs bypassed the PDP entirely.** `DELETE` was rejected by `BaseHTTPRequestHandler` with `501 Not Implemented` *before* the PDP ran. It failed closed, so there was no external effect — but the denial was **accidental and unaudited**. Relying on "the verb isn't implemented" is not enforcement. **Fixed:** every method now dispatches into the PDP via a catch-all, producing an explicit `METHOD_DENIED` with an audit record.

**D-2 — malformed `CONNECT` target raised an unhandled exception.** `CONNECT http://host/path` crashed the parse, killing the connection with no response and no audit entry. Again fails closed, again accidental. **Fixed:** malformed targets return `MALFORMED_CONNECT_TARGET` and are audited.

Both are **harness-class defects, not externally-effective bypasses** — per your release criterion they are flagged, not blockers. But both would have been invisible without an adversarial suite, and both would have become real gaps once the gateway grew.

**A-1 (architectural, important) — `CONNECT` blinds the L7 PDP.** Once a TLS tunnel is established the gateway sees only ciphertext. Host consistency, redirect re-entry, method policy, and request/response hashing are **structurally impossible inside the tunnel**; enforcement collapses to connect-time host+port+pinned-IP only. This is visible in the audit log as the one ALLOW lacking hashes.

Consequences for the architecture:
- `CONNECT` must be a **separate, default-deny switch** (`allow_connect`), not an entry in `allowed_methods`. Implemented.
- For real L7 enforcement over HTTPS the gateway needs **TLS interception** (its own CA, as Caido already does in-sandbox), otherwise HTTPS traffic is L3-contained but L7-unenforced.
- V1 decision required from you: either (a) gateway-side TLS interception, or (b) accept connect-time-only enforcement for HTTPS and document it as a known limitation.

---

## 6. What this does and does not prove

**PROVEN (executed, adversarial, this session):** network containment under `NET_ADMIN` route injection and IP spoofing; per-program network isolation; default-deny scope with formal wildcard + denylist precedence; host canonicalization (case, trailing dot); IP-literal denial; Host/authority mismatch detection; DNS validate-**all**-answers; IP authorization; per-request re-resolution catching an answer flip; redirect non-following with PDP re-entry; method and port policy; the full credential tuple (program/asset/destination) with the secret never entering the sandbox; per-asset budget exhaustion; authorization expiry; both kill switches; audit completeness with request/response hashing.

**Structural, not race-tested:** DNS pinning eliminates classic TOCTOU **by construction** — the gateway resolves, validates every answer, pins one IP, and connects to that literal IP with no second resolution. Verified by code inspection plus the flip test; not tested under concurrency.

**Simulated, not real:** the DNS zone is a deterministic in-gateway zone (with a `sequence` primitive to model a TTL flip), not a hostile authoritative nameserver. This makes rebinding reproducible; it is not a substitute for a real resolver test.

**NOT PROVEN:**
- **IPv6 — remains the hard release blocker.** This host has no IPv6 stack; nothing here changes that.
- **TLS/SNI enforcement inside `CONNECT` tunnels** (see A-1).
- **Anything about Strix** — its traffic, tools, browser behaviour, or whether it functions on an `internal` network. Still deferred by constraint 4.
- **Production readiness.** This gateway is a ~380-line stdlib proof harness. It buffers whole responses, re-reads policy per request, has no streaming, no HTTP/2, no connection pooling, no concurrency limits, and no IPv6 path.

---

## 7. Files

| Path | Role |
|---|---|
| `phase2a/policy_gw.py` | PDP / Execution Gateway (proof harness) |
| `phase2a/adversary.py` | hostile client running the matrix from the sandbox position |
| `phase2a/target_srv.py` | in-scope / out-of-scope / redirect targets |
| `phase2a/run_phase2a.sh` | builds topology + policy, runs the matrix |
| `phase2a/control/policy.json` | generated default-deny policy |
| `phase2a/control/audit.jsonl` | append-only decision log |
| `phase2a/out/results.json` | machine-readable matrix results |

Re-run with `./run_phase2a.sh` (idempotent; tears down the previous run first).

---

## 8. Recommendation

The boundary thesis holds for IPv4 at both L3 and L7, under an adversary explicitly trying to break it. I'd treat Phase 2a as **passed with two fixed defects and one open design decision (A-1)**.

Before Phase 2 proper, one decision is needed from you: **TLS interception at the gateway, or documented connect-time-only enforcement for HTTPS.** I recommend interception, since without it every HTTPS finding loses request/response provenance — which Phase 4's evidence engine depends on.

IPv6 and the real Strix runtime remain exactly where they were: blocked and deferred, unchanged by this proof.

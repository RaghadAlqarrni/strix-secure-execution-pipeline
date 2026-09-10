# Phase 2b — TLS Interception Boundary Proof

**Decision implemented:** A-1 resolved — TLS interception at the Execution Gateway, as controlled MITM **inside the PEP only**, never inside Strix.

**Result: 24/24 obligations proven**, plus **34/34 Phase 2a regression** after the shared PDP change. **Three defects were found and fixed by the suite**, one of them a genuine security-semantics violation (§4).

**Constraint compliance:** Strix not modified and not run. No substitute Strix image. No real targets, credentials, or provider APIs. All containers local and disposable. IPv6 **not** softened (§6).

---

## 1. Topology

```
   p2b_egress 172.29.0.0/24
     ├── allowed.lab 172.29.0.20   (upstream cert ← upca)
     ├── evil.lab    172.29.0.30   (out of scope; serves the 302 destination)
     ├── other.lab   172.29.0.40   (in scope, NOT a credential destination)
     ├── rebind.lab  172.29.0.50   (rebinding sequence target)
     ├── slow.lab    172.29.0.60   (stalls mid-transfer → live-connection kill test)
     ├── badcert.lab 172.29.0.70   (cert ← ROGUE ca, untrusted by the gateway)
     └── p2b_gw      172.29.0.10   PEP + TLS interception
                                    control plane bound to 172.29.0.10:9000 ONLY
                    172.31.0.10 ─┘        └─ 172.32.0.10
                          │
        p2b_prog_a 172.31.0.0/24 (internal)     p2b_prog_b 172.32.0.0/24 (internal)
          └── p2b_sbx_a 172.31.0.50
              cap_add NET_ADMIN, NET_RAW   (worst case, as Strix ships)
              mounts: /ca → gwca.crt ONLY  (never the CA key)
```

**Three independent trust roots**, so each obligation is isolated:
`gwca` (gateway MITM CA — private key gateway-side only) · `upca` (upstream CA, trusted by the gateway) · `rogue` (untrusted, proves cert validation fails closed).

---

## 2. Results — all 14 required obligations

| # | Requirement | Test(s) | Result |
|---|---|---|---|
| 1 | CA private key never enters the sandbox | T1, T2 | **PROVEN** — sandbox mounts only `certs/sandbox → /ca` containing `gwca.crt`; `ls /ca` returns `gwca.crt` alone; gateway holds `gwca.key` |
| 2 | Sandbox cannot reach the gateway control plane except via the PEP | T3, T4, T5 | **PROVEN** — control plane on egress IP **BLOCKED**, control port on internal IP **BLOCKED**, PEP port **REACHABLE** |
| 3 | HTTPS cannot bypass the PDP via `CONNECT` | T6, T8, T11 | **PROVEN** — tunnel request is a PDP decision, and the inner request is re-evaluated after decryption |
| 4 | SNI mismatch → `BLOCKED_BY_POLICY` | T9 | **PROVEN** — `SNI_MISMATCH:evil.lab!=allowed.lab` |
| 5 | HTTP `Host` mismatch → `BLOCKED_BY_POLICY` | T10 | **PROVEN** — `HOST_HEADER_MISMATCH:evil.lab!=allowed.lab`, detected *inside* the tunnel |
| 6 | Redirects never auto-followed; each destination re-enters the PDP | T12, T13 | **PROVEN** — 302 returned verbatim, `redirect_followed:false`; following it → `OUT_OF_SCOPE` |
| 7 | DNS validate-all + pin before connecting | T15, T16 | **PROVEN** — flip on 2nd resolution → `IP_NOT_AUTHORIZED:172.29.0.30` |
| 8 | Certificate validation failure → fail closed | T14 | **PROVEN** — `UPSTREAM_CERT_INVALID` for the rogue-signed upstream |
| 9 | Credential injection only after authorization | T17, T19, T20 | **PROVEN** — injected on the authorized tuple; `CREDENTIAL_WRONG_PROGRAM` / `CREDENTIAL_WRONG_DESTINATION` otherwise |
| 10 | Plaintext credentials never in sandbox or audit | grep | **PROVEN** — **0** occurrences of either secret in `audit.jsonl` or any sandbox-visible file |
| 11 | request/response hashes exist for HTTPS too | audit | **PROVEN** — **6/6** intercepted HTTPS ALLOWs carry `request_hash` + `response_hash` + `pinned_ip` + `sni` |
| 12 | Malformed TLS / CONNECT / protocol → explicit audited denial, not crash | T21, T22, T23 | **PROVEN** — `MALFORMED_TLS_CLIENT_HELLO`, `PLAINTEXT_HTTP_DISABLED_IN_PHASE2B`, gateway still serving afterwards |
| 13 | Kill switch tears down **live** connections | T24 | **PROVEN** — in-flight transfer **TERMINATED**; audit records `connections_terminated: 5` |
| 14 | IPv6 remains a release blocker | — | **UNCHANGED — still UNKNOWN** (§6) |

Sample intercepted-HTTPS audit record:
```json
{ "url": "https://allowed.lab:443/ok", "method": "GET", "canonical_host": "allowed.lab",
  "sni": "allowed.lab", "pinned_ip": "172.29.0.20", "upstream_status": 200,
  "redirect_followed": false, "credential_injected": false,
  "request_hash": "ca3c7115…", "response_hash": "e8d38ed2…" }
```
This is the artifact Phase 4's evidence engine needs, and it did not exist before interception.

---

## 3. Regression

Phase 2a re-run after the shared `pdp()` change: **34/34**, no regressions.

---

## 4. Defects found and fixed

**D-3 — one connection was resolving DNS twice (security semantics violation).**
The gateway called the PDP once for `CONNECT` and again for the decrypted request, and *each call re-resolved*. So a tunnel authorized against address X could have its inner request bound to address Y. In the test this failed closed, but it violated the architecture's own rule: *pin one validated IP for the life of the connection*. An attacker controlling DNS could split the authorization decision from the actual destination.
**Fixed:** `pdp()` now accepts `pinned_ip`; supplying it suppresses re-resolution entirely. One connection → one resolution → one address. This is the most important finding in Phase 2b.

**D-4 — denial responses were being lost to TCP RST.**
When the gateway wrote a 403 and closed while the client still had unsent data pending, the kernel emitted RST instead of FIN, **discarding the send buffer**. The sandbox saw a bare connection error rather than an explicit `BLOCKED_BY_POLICY`. Still contained, but obligation 12 requires an *explicit* denial, not an ambiguous socket error.
**Fixed:** the gateway drains pending input before closing, so the denial is actually delivered.

**D-5 (harness) — the adversarial client stopped reading after a failed send**, so it missed denials the gateway had already written. Fixed; the client now reads regardless of send outcome. Worth recording because it initially produced a *false* failure (T9) for a control that was working correctly — the audit log is what disambiguated it.

---

## 5. What changed in the architecture

- `CONNECT` is a **separate, default-deny switch** (`allow_connect`), not an entry in `allowed_methods`.
- Inside an intercepted tunnel the PDP is re-evaluated on the **real** method and path, with the **pin carried through** rather than re-derived.
- The control plane binds to the egress interface only; no program network can route to it.
- Upstream verification uses `check_hostname=True` against the canonical host while connecting to the **pinned IP** — name validated, address pinned, no re-resolution.

---

## 6. What this does NOT prove

- **IPv6 — still UNKNOWN, still a hard release blocker.** This host has no IPv6 stack. Nothing in Phase 2b touches it, and IPv4 success does not soften it.
- **Anything about Strix.** Not run, not modified, tree clean at `0478a69`. The first real run remains an observation experiment under constraint 8.
- **Real-world PKI behaviour.** Interception certificates are pre-minted for the fixed test hostnames; a production gateway mints per-host on demand from the CA. The enforcement logic proven here is unchanged by that, but the minting path itself is untested.
- **A hostile authoritative nameserver.** The zone is a deterministic in-gateway simulation with a `sequence` primitive; it makes rebinding reproducible but is not a live resolver.
- **Production readiness.** Stdlib proof harness: buffered (non-streaming) responses, policy re-read per request, no HTTP/2, no connection reuse, no concurrency limits, no IPv6 path.

---

## 7. Files

| Path | Role |
|---|---|
| `phase2b/policy_gw_tls.py` | TLS-intercepting PEP |
| `phase2b/gen_certs.sh` | three-root PKI (gwca / upca / rogue) |
| `phase2b/target_https.py` | HTTPS targets incl. redirect, slow, bad-cert |
| `phase2b/adversary_tls.py` | hostile client, 24-row matrix |
| `phase2b/run_phase2b.sh` | builds topology + policy, runs the matrix |
| `phase2b/evidence/` | audit log, policy, machine-readable results |
| `phase2a/policy_gw.py` | shared PDP (now pin-aware) |

---

## 8. Status

| Item | State |
|---|---|
| A-1 TLS interception | **RESOLVED — implemented and proven** |
| Phase 2a | PASS (34/34, regression clean) |
| Phase 2b | PASS (24/24), D-3/D-4/D-5 fixed |
| IPv6 | 🔴 **OPEN — hard release blocker** |
| Strix runtime | ⏸ DEFERRED (constraint 4 + 8) |
| Production gateway | not started — this is a proof harness |

Recommended next gate: decide whether to (a) close IPv6 on a v6-capable host, or (b) begin the production PEP with IPv6 designed in from the start rather than retrofitted. I lean toward (b) with (a) as its first acceptance test, since retrofitting address-family handling into an enforcement path is where this class of bug hides.

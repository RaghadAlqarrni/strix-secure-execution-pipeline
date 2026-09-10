# Architectural Review v1.0 — Policy-Enforced AI Bug Bounty Research Pipeline

**Status:** 🟢 **ARCHITECTURE APPROVED** / 🟡 **IMPLEMENTATION NOT APPROVED**
**Baseline:** Strix `0478a69ab03abfec4e8b7f764f40fe4131fd85fb`, unmodified.
**Supersedes:** the architecture sections of the Phase 0 report, as corrected by Phase 0.5 (empirical) and Phase 1 (lab).
**Purpose:** this is the single reference document Phase 2a tests against. If Phase 2a contradicts anything here, this document is wrong and gets amended — not the test.

---

## 1. Correction log

Corrections carried forward. Each one changed a claim that was previously stated too loosely.

| # | Correction | Origin |
|---|---|---|
| **C-1** | **"Host → lab is reachable" is NOT port publishing.** The lab binds nothing on any host interface (`PortBindings=map[]`). The host reaches it because the host has a **route to the Docker bridge subnet** as a directly-connected network. `-p 8080:8080` would create a listening socket on host interfaces, exposing it to anything that can reach the host; a bridge route does not. These must never be described interchangeably in a security claim. | Your review |
| **C-2** | **`cap_drop` does not override `cap_add`.** Passing both leaves the capability present (`CapEff` unchanged, `ping` and `ip route add` both worked). Strix hardcodes `cap_add=[NET_ADMIN,NET_RAW]`, so dropping them is a **code-level** requirement, not a config flag. | Phase 0.5 (PROVEN) |
| **C-3** | **`STRIX_DOCKER_SANDBOX_NETWORK` alone is insufficient.** Verified in code: `_apply_sandbox_network` sets only `network` and pops `ports`. Strix sets no `dns`, no `sysctls`, no `cap_drop` anywhere. A custom backend via `register_backend()` is mandatory. | Phase 0.5 (PROVEN) |
| **C-4** | **Caido is observability, not a boundary.** Proxy wiring is env-var only and the agent's own shell can discard it. | Phase 0 → accepted 🔴 by you |
| **C-5** | **In-container `NET_ADMIN` does not breach an `internal` network** — but this is *not* a reason to keep it. It still permits intra-network sniffing/ARP-spoofing against peers. Least privilege stands. | Phase 0.5 (PROVEN) |
| **C-6** | **Network containment covers WebRTC/UDP at IPv4 L3** because the netfilter rules carry no protocol match. This does **not** deliver browser *action* mediation, which is a separate, deferred concern. | Phase 0.5 (PROVEN) |

---

## 2. Standing constraints (binding on all later phases)

Recorded verbatim in intent; these govern every subsequent phase.

1. Do not modify Strix yet.
2. Do not substitute the Strix image to obtain a runtime baseline.
3. Keep `strixlab_net` as the disposable Phase-1 target network.
4. When Strix becomes runnable, use a fresh environment with the **real** Strix image + a **real test** LLM credential.
5. Treat `/api/vulns` as harness-only before measuring agent discovery accuracy.
6. IPv6 remains a **hard release blocker**.
7. **One internal network per program** is a mandatory topology requirement.
8. The first real Strix run is an **observation experiment**, not proof that Option B works.

---

## 3. Architecture (corrected, V1)

```
  CONTROL PLANE  (non-LLM, deterministic, outside the sandbox)
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Authorization Gate      Policy/Scope Engine (PDP)     Budget Engine  │
  │  program_id              canonical host matching        program/asset │
  │  verified_by             DNS resolve → validate → pin   session/agent │
  │  verified_at             redirect re-entry              vuln-class    │
  │  expires_at              DEFAULT DENY                   finding       │
  │  status                                                               │
  │                                                                       │
  │  External Kill Switch (out-of-process)     Audit Log (append-only)    │
  │  docker kill --filter label=strix-run-id   evidence_id, target_ip,    │
  │                                            request_hash, resp_hash    │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │ decisions
  ┌───────────────────────────────▼──────────────────────────────────────┐
  │  EXECUTION GATEWAY  (PEP)  — dual-homed, SOLE egress path            │
  │  • enforces PDP verdicts        • injects credentials (cred never    │
  │  • pinned-IP connect              enters the sandbox)                │
  │  • rate limit / idempotency     • hashes req/resp for provenance     │
  └───────────────────────────────┬──────────────────────────────────────┘
                                  │  only reachable route
  ┌───────────────────────────────▼──────────────────────────────────────┐
  │  net-<program>   (docker bridge, internal=true, one PER PROGRAM)     │
  │                                                                      │
  │   RESEARCH PLANE — Strix sandbox (LLM)                               │
  │   caps: NET_ADMIN/NET_RAW DROPPED    no extra_hosts                  │
  │   Caido in-container: observability only, upstream = gateway         │
  └──────────────────────────────────────────────────────────────────────┘
        ✗ no internet   ✗ no host   ✗ no other program's network
```

**Enforcement principle.** Every control lives where the agent has **no capability**: the host netns and the isolated network. The research plane may *request* and *read*; it may never *widen* authorization, scope, DNS policy, tool permission, or budget.

---

## 4. Component specifications

### 4.1 Sandbox runtime (custom backend — mandatory per C-2/C-3)
Registered through `register_backend()`; must **not** inherit `StrixDockerSandboxClient._create_container`, whose cap injection cannot be neutralized.

| Setting | Value | Why |
|---|---|---|
| network | `net-<program_id>`, `internal=true` | sole containment boundary (PROVEN) |
| caps | `NET_ADMIN`, `NET_RAW` **dropped** | least privilege; V1 needs no raw packets (C-5) |
| `extra_hosts` | **not set** | Strix injects `host.docker.internal` unconditionally; leaks host gateway IP |
| dns | gateway resolver only | DNS becomes a policy decision |
| IPv6 | `EnableIPv6=false` + daemon `--ip6tables=true` + sysctl disable | release blocker until proven |
| labels | `strix-run-id`, `strix-run-type` | external kill switch handle |

### 4.2 Policy Decision Point — the network decision chain
A redirect is **a new network decision**, not a continuation. The chain is single-entry and re-entrant:

```
requested URL
  → canonicalize host   (lowercase, IDN→punycode, strip trailing dot, default port,
                         IPv4/IPv6 normalization, formal wildcard semantics)
  → resolve via gateway resolver
  → validate EVERY returned address   (reject loopback/link-local/RFC1918 unless explicitly authorized)
  → PIN one validated IP             (no re-resolution for the life of the connection)
  → connect to the pinned IP
  → TLS SNI  MUST equal canonical host
  → HTTP Host MUST equal canonical host
  → response
  → 3xx Location present?  → DO NOT FOLLOW → re-enter this chain from the top
```
Any ambiguity, mismatch, malformed value, or unverifiable state ⇒ `BLOCKED_BY_POLICY`.

### 4.3 Authorization record (deterministic gate)
`{program_id, verified_by, verified_at, expires_at, status}`. Checked **before** sandbox bring-up and again per request. Missing/expired/non-active ⇒ deny. No prompt text can substitute for it.

### 4.4 Credential binding (full tuple, not `cred_id`)
```
PDP(program_id, session_id, asset_id, action, destination{host, pinned_ip, port, proto},
    credential_id, authorization_record) → ALLOW | BLOCKED_BY_POLICY
```
The secret is injected **at the gateway** and never enters the sandbox. Cross-program or cross-destination reuse is denied.

### 4.5 Budgets (hierarchical)
Extend Strix's real `ReportUsageHooks` (cost + turns, already hard-stops) with gateway-side counters: per program / asset / session / agent / vuln-class / finding, plus **max requests** and **wall-clock**. Exhaustion halts that scope.

### 4.6 Browser (V1 scope — deliberately narrow)
Network containment + Chromium hardening (disable non-proxied UDP / WebRTC IP handling) + audit of `agent-browser` invocations via the existing host-side `_wrap_exec_command` seam. **No browser action-mediation gateway in V1.**

### 4.7 Caido
Retained inside the sandbox for request crafting and observability. Upstream is the gateway. It holds **no** enforcement role.

---

## 5. Evidence ledger

| Property | Status |
|---|---|
| IPv4 egress blocked from `internal` network | **PROVEN** |
| Escape via `NET_ADMIN` route injection / IP spoofing | **PROVEN BLOCKED** |
| Escape via forwarding-enabled gateway container | **PROVEN BLOCKED** |
| Host / `host.docker.internal` / docker gateway / link-local unreachable | **PROVEN BLOCKED** |
| Containment is protocol-agnostic (covers raw/UDP/WebRTC at IPv4 L3) | **PROVEN** |
| Host→internal-container reachable (Caido bootstrap survives) | **PROVEN** (mechanism: bridge route, per C-1) |
| Same-network peers can reach each other | **PROVEN** → mandates per-program networks |
| `cap_drop` cannot neutralize `cap_add` | **PROVEN** |
| Disposable lab + deterministic reset | **PROVEN** |
| **IPv6 containment** | **UNKNOWN — RELEASE BLOCKER** |
| L7 PDP (redirect/SNI/Host/DNS-pin) | **UNPROVEN** → Phase 2a |
| Credential binding, authorization expiry, budgets, kill switch | **UNPROVEN** → Phase 2a |
| Strix behaviour on an `internal` network | **UNKNOWN** — deferred by constraint 4 |
| Strix tool/traffic/browser/runtime baseline | **DEFERRED** |

---

## 6. Phase 2a specification — Security Boundary Proof

**Thesis under test:** *a client in the sandbox position, actively trying to escape, cannot reach any destination except through the PDP, and the PDP denies by default.*

**Method.** The adversary is a deliberately hostile test client, **not Strix** — consistent with constraint 8, which forbids treating a Strix run as boundary proof. A hostile client is also strictly stronger: it attempts every bypass unconditionally rather than only what a model happens to try.

**In scope:** network escapes, DNS resolution/validation/pinning/rebinding, redirect re-entry, Host/scope canonicalization, credential binding, authorization expiry, budget exhaustion, kill switch, per-program network isolation, audit completeness.

**Explicitly NOT proven by Phase 2a:**
- IPv6 (no IPv6 stack on this host) — remains the release blocker.
- Any statement about Strix's real behaviour, traffic, or tool usage.
- Production hardening of the gateway (this is a proof harness, not the shipping PEP).

**Exit criterion.** Every BLOCK-expected row fails closed under a client explicitly instructed to bypass every control. Any externally-effective bypass is a release blocker; harness-only failures are flagged for review.

---

*Phase 2a execution follows in `phase2a/`. Results are reported separately and do not amend this document unless they contradict it.*

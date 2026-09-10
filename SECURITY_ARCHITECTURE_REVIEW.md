# Security Architecture Peer Review — PEP Validation Pipeline

**Scope:** read-only architectural review. No code modified, no gate executed.
**Reviewer posture:** red team against our own evidence pipeline.
**Codebase reviewed:** `strix-pipeline/pep/*` at current working state; Strix untouched (`0478a69`).

---

## 1. Architectural validation & rating

### 1.1 What the design gets right

The three-layer model (Harness → Verifier → Evidence Auditor) with a declared authority hierarchy is sound, and stronger than what most egress-control test suites do. Three properties are genuinely well-founded:

- **Positive controls before negative results.** B1/B3 as a pair is the correct shape.
- **Client-side socket behaviour demoted to non-authoritative.** We proved this empirically in both directions (503 → false TERMINATED; clean EOF → false SURVIVED).
- **Environment inability ≠ security.** The gate refuses and exits 1 rather than skipping.

### 1.2 Rating

| Dimension | Rating | Note |
|---|---|---|
| Conceptual model | **Strong** | authority hierarchy and fail-closed intent are right |
| Layer A (policy logic) | **Strong** | 30 rows, real decision path, unwrapping covered |
| Layer B design | **Adequate** | correct shape, but transport rows never executed |
| Verifier (B8/B9) | **Moderate** | correlated, but correlates on attacker-influenced data |
| **Evidence Auditor** | **WEAK — not currently trustworthy as a release gate** | three independent false-green paths, below |
| Audit log trust boundary | **WEAK** | tamper-evidence implemented but never checked |

**Bottom line:** the *architecture* is defensible; the *auditor implementation* is not yet strong enough to be the final gate. I would not accept a CERTIFIED verdict from it today. Critically, the weaknesses are not hypothetical — **C-1 is a live false-green path in the current dual-stack gate.**

---

## 2. Findings

Severity: **C** = critical (false-green possible today) · **H** = high · **M** = medium · **L** = low/forward-looking.

### C-1 — The release gate never runs PP18; E6 substitutes a client-written file

`run_dualstack_gate.sh` contains **zero** references to PP18 (verified by grep). The host-side PP18 re-derivation exists **only** in `run_pep.sh`. In the release gate, E6's kill evidence reduces to:

```python
pp18 = kill is not None and (kill.get("partial_bytes") or 0) > 0
```

`pep_kill.json` is written **by the sandbox client**. So in the gate path, the entire IPv4 kill-switch claim rests on a number the adversary writes about itself. This directly violates §6 of the mandate ("Do NOT trust kill.json.partial_bytes") and is exploitable today by a client that simply writes `{"partial_bytes": 4096}` without ever being killed.
**Impact:** a CERTIFIED verdict with no host-side kill evidence whatsoever.

### C-2 — The audit hash chain is built but never verified

`AuditLog.verify()` exists and works. Grep across the entire tree returns **zero callers**. The auditor re-parses the JSONL with `load_jsonl()`, which *silently discards unparseable lines*.

Consequences:
- Line deletion, truncation, or wholesale rewrite is invisible to the gate.
- `_recover_tail()` re-anchors from the last *parseable* line, so appending a malformed line and truncating is self-healing by design — good for crash recovery, bad if never independently verified.
- The chain has **no external anchor**: it is written by the same process it protects, so an attacker with file write access recomputes it from genesis. It detects *edits*, not *replacement*.

**Impact:** the "tamper-evident audit" property is decorative in the gate.

### C-3 — The correlation nonce is attacker-controlled

The nonce travels in the **request path**, chosen by the sandbox, and lands in the audit `url` field. The sandbox is our declared adversary. Therefore a hostile client can issue a legitimate in-scope request with path `/ok?tid=<any-nonce-it-likes>` and **manufacture a well-formed ALLOW record bearing an arbitrary nonce** — including another execution's nonce.

Note the audit writer uses `json.dumps`, so *structural* log injection is prevented (good). The exposure is **semantic**: nonce forgery, not JSON breakage.

**Impact:** B8's "matched by nonce" is not a proof of execution identity. Correlation must be anchored in something the client cannot choose.

### H-1 — Kill-switch registry race produces false `terminated_conn_ids`

```python
with self._lock:
    victims = list(self._conns)     # snapshot under lock
for c in victims:                   # closed OUTSIDE the lock
    c.close_all()
return [c.conn_id for c in victims]
```

Two distinct defects:

1. **Evidence defect.** A connection that completes naturally between snapshot and close is still reported in `terminated_conn_ids`. Combined with `close_all()` swallowing *all* exceptions, a socket that failed to close is also reported as terminated. So the list means "was live at snapshot time", not "was killed".
2. **Enforcement defect (worse).** A connection admitted by the PDP microseconds before `STOP_ALL` appears, but registered *after* the snapshot, is never terminated. `armed` latches, so `terminate_all()` does not run again. That connection survives the kill switch. This is a real kill-switch gap, not merely a test artifact.

Also a TOCTOU: `os.path.exists(KILL_FILE)` is checked per decision; the file can appear between check and connect.

### H-2 — E1 is a blacklist; the mandate requires a whitelist

`BAD_OUTCOMES` enumerates known-bad strings. Any *unrecognised* status (`PARTIAL`, `ASSUMED`, `WAIVED`, a typo, or a future code) passes E1. The mandate requires `got == "PROVEN"` for every required row. **Unknown must not equal pass.**

### H-3 — E3/E4 parse human-readable prose

```python
d8 = str((by_id.get("B8") or {}).get("detail", ""))
nonces = re.findall(r"tid=([A-Za-z0-9]+-b\d)", d8 + " " + d9)
claimed = re.findall(r"conn_id=([0-9A-Za-z]{3,})", d9)
```

Both nonce and `conn_id` are extracted from the verifier's *display strings*. The mandate forbids exactly this (§5 E3/E4). A verifier that prints a plausible detail line satisfies the auditor without the underlying raw evidence existing. Re-derivation must come from the raw audit, keyed by machine-readable fields.

### H-4 — E5 inspects one file; the PP18 verifier is un-inspectable

E5 reads a single path (`--verifier`, default `verify_layerb_audit.py`). It does **not** inspect:
- the PP18 verifier, which is an **inline heredoc inside `run_pep.sh`** — not a file, so not inspectable at all;
- `ipv6_transport.py`, `ipv6_acceptance.py`, or the auditor itself.

Worse, there is **no integrity binding between the file E5 reads and the code actually executed**. Pointing `--verifier` at a pristine copy while running a weakened one passes E5.

### H-5 — No execution binding between artifacts

`acc.json`, `ipv6_layerb.json`, `pep_results.json`, `pep_kill.json`, and `audit.jsonl` carry no shared run identifier, no timestamps that are compared, and no freshness check. Artifacts from different runs — or a fresh audit paired with stale results — certify happily. Re-running the auditor against yesterday's outputs produces the same verdict.

### H-6 — E2 does not verify the required row set

E2 checks that counts match the rows *present*. It does not check that the rows present are exactly `{B1..B9}` and `{A1..A30}`. Nine rows named `B1,B1,B1,…` satisfy E2.

### M-1 — Substring nonce matching

`tid in str(e.get("url",""))` matches prefixes and substrings: nonce `abc-b3` matches `xabc-b3` and `abc-b30`. Should parse the query parameter and compare exactly.

### M-2 — Spec/implementation contradiction on nonce identity

The mandate states **B8_nonce MUST equal B9_nonce**. Our E3 currently requires them to be **different** (`len(set(nonces)) >= 2`). Our design uses one `TEST_ID` with per-row suffixes (`-b3`, `-b5`, `-b6`), i.e. same execution, different sub-tag. This is a genuine design decision that needs your ruling (see §4, item R-3) — as written, implementation and mandate contradict.

### M-3 — Preflight validates configuration, not enforcement

The environment gate checks for `ipv6.disable=1`, the sysctl tree, and recommends `--ip6tables=true`. It never verifies that **ip6tables/nftables rules actually exist** for the internal v6 bridge. This violates our own rule ("config is not evidence") inside the gate that enforces it. If `ip6tables` is off, Docker may create a `--internal` v6 network with **no filtering**, and B1/B2/B7 would be the only thing standing between us and a silent false green.

### M-4 — RFC 6052 NAT64 coverage is incomplete

`addressing.py` unwraps only the well-known `64:ff9b::/96`. RFC 6052 defines IPv4-embedded addresses at prefix lengths **/32, /40, /48, /56, /64 and /96**, and RFC 8215 adds `64:ff9b:1::/48` for local-use NAT64. Network-specific prefixes are operator-chosen and cannot be enumerated statically, but the local-use prefix and the non-/96 well-known layouts are missable today.

### M-5 — Parallel/concurrent run cross-contamination

Two gate runs sharing an audit file interleave nonces and `conn_id`s. With substring matching and no run binding, cross-matching is possible. The mandate raises this explicitly.

### L-1 — `conn_id` is `uuid4().hex[:16]` (64 bits)

Not a practical collision risk at our volumes, but truncation weakens a correlation key we now depend on. Full 128-bit is free.

### L-2 — Forward-looking protocol gaps not covered by Layer A/B

- **TLS Encrypted Client Hello (ECH).** If a client offers ECH, the outer SNI is a cover value; our SNI-vs-authority check (B4) inspects what we can see. Since the PEP terminates TLS this is currently containable, but an ECH-aware client changes the meaning of "SNI matches".
- **DoH/DoT tunnelling.** If any in-scope host is a DoH resolver, the sandbox obtains arbitrary name resolution *through* an allowed channel, bypassing our resolver policy entirely. No layer tests this.
- **`IPV6_V6ONLY=0` mapped sockets.** An AF_INET6 socket may reach an IPv4 destination via `::ffff:`. Our pin carries a family label; we do not assert the *socket* honoured it.
- **Happy Eyeballs (RFC 8305).** Our PDP deterministically prefers v6; real clients race. A behavioural divergence worth documenting, not a bypass.
- **NDP / RA / SLAAC.** A sandbox with `NET_ADMIN`+`NET_RAW` on a shared internal network can send Router Advertisements or spoof NDP to attack *peers on the same network*. Layer B tests egress, never intra-network L2. (Mitigated in production by one-network-per-program, but untested.)
- **IPv6 extension headers / fragmentation.** Certain nftables configurations mis-handle fragmented or extension-header-laden v6 packets. Untested.

### L-3 — E5's static analysis is regex-based and evadable

Even after the docstring/comment fix, the check is textual. Evasion is trivial for a motivated author: `getattr(mod, "sor"+"ted")`, `eval`/`exec`, `importlib.import_module`, module-level `__getattr__`, decorator wrapping, monkeypatching at import, or reading the matching strategy from a data file. This is the Thompson "Trusting Trust" problem in miniature: a checker that inspects source cannot bound behaviour.

---

## 3. Research & benchmark findings

Standards and practice that should inform the fixes:

| Source | Relevance |
|---|---|
| **RFC 5952** | Canonical IPv6 text representation. Our canonicalization should cite it explicitly; we currently normalize via `ipaddress` which is compatible, but the contract is undocumented. |
| **RFC 6890** | Special-Purpose Address Registry — the authoritative basis for "which ranges are non-routable", better than our hand-rolled class list for both families. |
| **RFC 6052 / RFC 8215** | IPv4-embedded IPv6 addressing and local-use NAT64 prefix — see M-4. |
| **RFC 4193 / 4291** | ULA and IPv6 addressing architecture — supports our ULA↔RFC1918 symmetry decision. |
| **RFC 3056 / 4380** | 6to4 / Teredo — already unwrapped; worth citing in code. |
| **RFC 8305** | Happy Eyeballs v2 — dual-stack selection behaviour. |
| **RFC 9110** | HTTP semantics: authority vs `Host` handling — underpins our mismatch checks. |
| **RFC 6125** | Service identity verification — underpins upstream cert validation. |
| **RFC 9162 (Certificate Transparency v2)** | Merkle-tree logs with signed tree heads and inclusion proofs — the mature answer to C-2. A hash chain without an external anchor is not tamper-evident against an attacker who can rewrite the file. |
| **RFC 5848 / NIST SP 800-92** | Signed syslog and log management — external anchoring, key separation, off-box shipping. |
| **CWE-807 / CWE-349 / CWE-117 / CWE-367** | Reliance on untrusted inputs in a security decision (C-1, C-3); trusting unverified data; log injection; TOCTOU (H-1). |
| **Thompson, "Reflections on Trusting Trust"** | Bounds what E5 can ever achieve by inspection alone; argues for behavioural (mutation) testing over static inspection. |

Practice note from egress-proxy design generally: enforcement decisions should be keyed on **server-observed** connection identity (a 5-tuple plus a server-generated identifier), never on client-supplied correlation tokens. That is exactly the C-3 fix.

---

## 4. Proposed enhancements & action plan

Prioritised. Each states the risk solved, the files affected, and the effect on rigour.

### Priority 0 — close the live false-green paths

**R-1 · Run PP18 inside the release gate and re-derive it from raw audit**
*Solves:* C-1 (certification with no host-side kill evidence).
*Files:* `pep/run_dualstack_gate.sh`, `pep/audit_gate_evidence.py`, and extract the PP18 heredoc from `pep/run_pep.sh` into a real module (`pep/verify_pp18.py`) so it is both reusable and inspectable.
*Effect:* the IPv4 kill claim becomes host-derived; also removes H-4's un-inspectable heredoc.

**R-2 · Verify the audit hash chain inside the auditor, and reject unparseable lines**
*Solves:* C-2.
*Files:* `pep/audit_gate_evidence.py` (call `AuditLog.verify`, add a new check **E7**), `pep/audit.py` (surface malformed-line counts rather than silently dropping).
*Effect:* truncation/edit/rewrite become detectable at the gate. **Note the residual limit:** without an external anchor this still does not defend against a full rewrite by an attacker with file-write access. R-8 addresses that.

**R-3 · Re-anchor correlation on a server-generated identifier**
*Solves:* C-3 (attacker-chosen nonce) and M-2 (spec contradiction).
*Design:* the PEP mints a per-connection `conn_id` (already does) and should additionally record a **server-side execution/run id** it receives from the control plane, not the client. The client nonce is retained only as a *convenience label*, explicitly non-authoritative. Correlation becomes: control-plane `run_id` (written into the audit at `STARTUP`) → `conn_id` → `terminated_conn_ids`.
*Files:* `pep/gateway.py`, `pep/server.py`, `pep/verify_layerb_audit.py`, `pep/audit_gate_evidence.py`, `pep/ipv6_transport.py`, `pep/pep_client.py`.
*Decision needed from you:* the mandate says B8_nonce **must equal** B9_nonce. Our current design uses one `TEST_ID` with `-b3/-b5/-b6` suffixes. I recommend **one nonce per execution, with the row identity carried in a separate machine-readable field** — which satisfies the mandate literally and removes the suffix parsing. Please confirm.

### Priority 1 — auditor rigour

**R-4 · E1 → strict whitelist**
`got == "PROVEN"` required for every row in a required-ID set; unknown/missing/unrecognised all fail.
*Files:* `pep/audit_gate_evidence.py`. *Solves:* H-2.

**R-5 · E2 → required-ID set validation**
Assert the row IDs are exactly `{A1..A30}` and `{B1..B9}`, no duplicates, no extras.
*Files:* same. *Solves:* H-6.

**R-6 · E3/E4 → machine-readable re-derivation only**
Stop parsing `detail`. Read `conn_id`, `pin_family`, `pin_ip`, `sni`, hashes and the run identifier from the raw audit records; exact query-parameter parsing rather than substring.
*Files:* `pep/audit_gate_evidence.py`, `pep/verify_layerb_audit.py`. *Solves:* H-3, M-1.

**R-7 · Execution binding + artifact freshness**
Stamp every artifact with the control-plane `run_id`; the auditor requires all artifacts to agree and to match the audit's `STARTUP` record.
*Files:* all runners + auditor. *Solves:* H-5, M-5.

### Priority 2 — enforcement correctness (not just evidence)

**R-8 · Fix the kill-switch race and make the termination list truthful**
Hold the lock across close, or mark each `ConnectionState` with a `killed_by_switch` flag set under lock; record close failures rather than swallowing them; re-arm the sweep so connections registered after the first sweep are also terminated (or refuse admission once armed).
*Files:* `pep/gateway.py`. *Solves:* H-1 — including the genuine enforcement gap.
*Note:* this is the only Priority-0/1/2 item that changes PEP behaviour rather than test behaviour. It should be re-validated against the full IPv4 suite.

**R-9 · Verify enforcement rules exist, not just daemon config**
Preflight should assert actual ip6tables/nftables rules for the internal v6 bridge before Layer B is allowed to count.
*Files:* `pep/run_dualstack_gate.sh`, `pep/ipv6_acceptance.py`. *Solves:* M-3.

### Priority 3 — verifier integrity and coverage

**R-10 · E5 → AST + integrity binding + mutation testing**
AST analysis (detect `eval`/`exec`/`getattr`-built calls/dynamic import), hash-pin the modules actually executed, and — most importantly — **behavioural mutation testing**: run the auditor against a battery of deliberately weakened verifiers and require every one to yield NOT CERTIFIED. Static inspection alone cannot bound behaviour (Thompson).
*Files:* `pep/audit_gate_evidence.py`, new `pep/mutations/`. *Solves:* H-4, L-3.

**R-11 · Extend RFC coverage in Layer A**
RFC 8215 `64:ff9b:1::/48`, RFC 6052 non-/96 layouts, `IPV6_V6ONLY` assertion, scoped-literal (`%zone`) handling.
*Files:* `pep/addressing.py`, `pep/ipv6_acceptance.py`. *Solves:* M-4, part of L-2.

**R-12 · New Layer B rows for intra-network and protocol edge cases**
NDP/RA/SLAAC peer attack, IPv6 fragmentation/extension headers, DoH/DoT tunnelling through an allowed host.
*Files:* `pep/ipv6_transport.py`, `pep/DUALSTACK_ENV.md`. *Solves:* remainder of L-2.
*Note:* this expands Layer B beyond 9 rows — a documentation and contract change requiring your sign-off.

### Priority 4 — hardening

**R-13 · External audit anchoring** — sign the chain head with a key the PEP process cannot read, or ship heads off-box (RFC 9162 / 5848 pattern). Closes C-2's residual rewrite risk.
**R-14 · Full-length `conn_id`** — trivial. Solves L-1.
**R-15 · Align `DUALSTACK_ENV.md`** — reflect the final row contract once R-3/R-12 are decided. Mandate §8.

---

## 5. What this review does *not* change

Current gate status is unchanged and remains correct:

| | |
|---|---|
| Layer A | 30/30 PROVEN |
| Layer B | 0/9 **BLOCKED_ENV** |
| IPv4 regression | 17/17 (harness-level) |
| IPv6 | 🔴 **UNKNOWN / RELEASE BLOCKER** |
| Evidence Auditor | **NOT CERTIFIED** |
| PEP | BUILT, NOT PRODUCTION-READY |
| Strix | not run, not modified (`0478a69`, clean) |

None of the findings above make IPv6 any more known. They make the *auditor* less trustworthy than its output currently suggests — which argues for fixing it before it is ever used to certify anything, not after.

---

## 6. Approval gate

**Summary of what I propose to do, in order:**

1. **P0 (C-1, C-2, C-3):** run PP18 in the release gate and re-derive it from raw audit; verify the hash chain inside the auditor (new E7); re-anchor correlation on a server-generated `run_id` instead of the client-chosen nonce.
2. **P1 (H-2, H-3, H-5, H-6, M-1):** E1 strict whitelist; E2 required-ID set; E3/E4 machine-readable re-derivation with exact matching; artifact execution binding.
3. **P2 (H-1, M-3):** fix the kill-switch race and truthful termination list — *this modifies PEP behaviour and needs IPv4 re-validation*; assert real ip6tables rules in preflight.
4. **P3 (H-4, L-3, M-4, L-2):** E5 via AST + module hash-pinning + mutation battery; RFC 8215/6052 coverage; new Layer B rows for NDP/RA, fragmentation, DoH tunnelling.
5. **P4:** external audit anchoring, full-length `conn_id`, spec alignment.

**Two decisions I need from you before touching anything:**

- **D-1 — nonce semantics.** Mandate says `B8_nonce == B9_nonce`; our design uses one `TEST_ID` with per-row suffixes. Do you want (a) literal single shared nonce with row identity in a separate field *(my recommendation)*, or (b) keep suffixes and relax E3 to check common-root-plus-same-execution?
- **D-2 — Layer B row count.** R-12 would take Layer B beyond 9 rows, changing the published contract. Expand now, or freeze at 9 and schedule the additions as a separate gate revision?

**I have made no code changes and executed no gate scripts. May I proceed — and if so, with which priorities and which answers to D-1 and D-2?**

I'd recommend approving **P0 and P1 only** in the first pass, re-running the adversarial fixtures against the hardened auditor, and holding P2 (which changes PEP behaviour) for a separate review — so that a behaviour change and an evidence change never land in the same unvalidated step.

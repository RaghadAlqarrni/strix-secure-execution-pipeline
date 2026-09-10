# Dual-Stack Validation Environment — provisioning spec

The only thing standing between the production PEP and a valid release gate is a
host that can actually carry IPv6. This is the complete requirement.

---

## 1. Host requirements

| Requirement | Why | Check |
|---|---|---|
| Kernel **without** `ipv6.disable=1` | With it, the stack is never initialized: no `/proc/net/if_inet6`, no `/proc/sys/net/ipv6`. Not fixable at runtime — IPv6 is built in (`CONFIG_IPV6=y`), so `modprobe` cannot help, and a boot parameter cannot be revoked. | `grep -c ipv6.disable=1 /proc/cmdline` → must be `0` |
| IPv6 sysctl tree present | Docker reads `/proc/sys/net/ipv6/conf/<bridge>/disable_ipv6` when creating v6 bridges. | `ls -d /proc/sys/net/ipv6` |
| `net.ipv6.conf.all.disable_ipv6=0` | A running-but-disabled stack fails the same way. | `sysctl net.ipv6.conf.all.disable_ipv6` → `0` |
| Docker ≥ 26 with IPv6 + ip6tables | Needed for `--ipv6` networks and for v6 forwarding rules to be enforced. | `dockerd --ipv6 --ip6tables=true` |
| Root / `CAP_NET_ADMIN` on the host | Creating bridges and reading nftables. | `id -u` → `0` |

**No global IPv6 connectivity is required.** The gate runs entirely on local ULA
(`fd00::/8`) networks; nothing needs to reach the public v6 internet.

### One-shot preflight
```bash
grep -q 'ipv6.disable=1' /proc/cmdline && echo "FAIL: ipv6 disabled at boot"
test -d /proc/sys/net/ipv6 || echo "FAIL: no ipv6 sysctl tree"
test -f /proc/net/if_inet6 || echo "FAIL: no if_inet6"
python3 -c "import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.close();print('AF_INET6 ok')"
docker network create --ipv6 --subnet fd00:test::/64 _v6probe && docker network rm _v6probe
```

### Docker daemon
```json
// /etc/docker/daemon.json
{ "ipv6": true, "ip6tables": true, "experimental": false,
  "fixed-cidr-v6": "fd00:d0ck::/64" }
```
Restart the daemon, then confirm `docker network create --ipv6 …` succeeds.

---

## 2. Running the gate

```bash
cd strix-pipeline/pep
./run_dualstack_gate.sh
```

It builds dual-stack networks and targets, starts the PEP, runs Layer A, Layer B,
the IPv4 regression and the host-side PP18 / B8 / B9 evidence checks, then the
evidence audit, tearing the topology down afterwards. It **refuses to run** — exit 1,
`NOT PASSED` — if the preflight fails, because absence of IPv6 is evidence the
gate cannot be tested, not evidence that it is safe.

### The execution anchor: `run_id`

The gate mints one unguessable `run_id` per execution and passes it to the PEP
only (`-e PEP_RUN_ID`). The PEP stamps it on **every** audit record. It is
**never** given to the sandbox: no `docker exec` into the sandbox carries it,
and sandbox-written artifacts leave `run_id` as `null`.

Binding a sandbox artifact to the execution is therefore a control-plane act,
performed host-side by `stamp_artifacts.py` after collection, which also writes
`run_id_source: "control-plane"`. An artifact that arrives already bearing a
`run_id` labelled itself; the stamper records that as `run_id_conflict` and the
auditor rejects it (**E8**) — including when the value *matches*, since a
matching self-label means the sandbox learned a value it should never have had.

### Why `collected/` exists

`$OUT` is bind-mounted **read-write** into the sandbox; that is how the sandbox
reports results, and it cannot be avoided. It follows that:

* anything the control plane writes into `$OUT` is **readable** by the sandbox, and
* any evidence artifact left in `$OUT` is **writable** by the sandbox.

So the gate collects artifacts **out of `$OUT` into `collected/`** — a directory
mounted into no *sandbox* container — and only then stamps, verifies and audits
them. (`collected/` sits under `pep/`, which is bind-mounted **read-only** into
the PEP container. The PEP legitimately holds `PEP_RUN_ID` already, so that is
not a disclosure; the sandbox has no mount reaching it.) The sandbox is removed (`docker rm -f`) as soon as its last `docker exec`
returns, *before* collection, so there is no window in which it can rewrite
`$OUT` behind the collector.

Collection is done by `collect_artifacts.py`, not `cp`. A host-side `cp` runs as
root and dereferences symlinks, so a sandbox that replaced its own output file
with a symlink could make the host read an arbitrary path on its behalf. The
collector refuses symlinks, hard links, non-regular files and payloads that do
not parse as a JSON object.

This is not hypothetical tidiness. Stamping in place published the run_id into
the shared directory before the Layer B phase ran in that same sandbox, which
defeated the anchor entirely. Verify it per run:

```bash
grep -rl "$RUN_ID" out/        # must print nothing
grep -rl "$RUN_ID" collected/  # must print the stamped artifacts
```

Consequences that matter:

* a valid-looking record from a **previous** execution carries a different
  `run_id` and can never satisfy the current gate;
* the party under measurement cannot choose, guess, or assert the value that
  scopes its own evidence;
* `test_nonce` is a **single** value per execution, sent by the sandbox as a
  header and echoed into structured audit fields. It is client-supplied, so it
  only *narrows* which record is meant — it is never proof of execution
  identity. `row_id` (also a structured field) says which acceptance row a
  record belongs to, replacing the old practice of embedding `-b3` / `-b6`
  suffixes in a URL and parsing them back out.

### Required output for release

```
  Layer A:          30/30
  Layer B:          9/9
  IPv4 regression:  17/17
  IPv6 regression:  PASS
  PP18 (host):      PROVEN
  Evidence audit:   CERTIFIED
  ========================
  IPv6 GATE: PASSED
  PEP: ELIGIBLE FOR STRIX OBSERVATION
```

Exit code `0`. **Any** other result means back to the PEP, and Strix does not run.
The verdict is a conjunction of five distinct conditions — Layer A complete,
Layer B complete (which is what the "IPv6 regression" line restates), IPv4
regression complete and non-empty, `PP18: PROVEN`, `Evidence audit: CERTIFIED` —
so a single `NOT PROVEN` or `NOT CERTIFIED` blocks the gate.

### The evidence audit (E1–E8)

A green `Layer B: 9/9` is a claim the harness makes *about itself*.
`audit_gate_evidence.py` re-derives from the PEP's raw audit log the facts that
*can* be re-derived from it — E3, E4, E7 and the PP18 half of E6 — and refuses to
certify a pass those facts do not support. It does **not** re-derive everything:
Layer A rows A1–A30 produce no network activity and therefore no audit records;
Layer B rows B1–B7 are measured inside the sandbox and self-reported; E6's "IPv4
regression complete" half reads the sandbox-written `pep_results.json`. E1 and E2
check the summary against its own rows — they catch self-contradiction, not a
false row. The authority hierarchy is strict and one-directional:

```
RAW AUDIT + CONNECTION REGISTRY  >  EVIDENCE AUDITOR  >  VERIFIER  >  SUMMARY
```

| Check | Requires |
|---|---|
| E1 | **strict whitelist**: every required row has `status == "PROVEN"`. Unknown is not pass. (The previous blacklist let any unrecognised status through.) |
| E2 | row IDs are exactly `{A1..A30}` and `{B1..B9}` — no duplicates, extras or substitutions — and reported counts match the rows actually present |
| E3 | B8 and B9 carry the **same** `test_nonce`, read from **structured audit fields only** — never parsed out of a verifier's prose or a URL |
| E4 | the exact `conn_id` of the B6 connection appears in `KILL_SWITCH.terminated_conn_ids` of this run, and the B8 ALLOW is a genuine v6 record (`pin_family=ipv6`, a real v6 `pin_ip`, plus `canonical_host`, `sni`, `request_hash`, `response_hash`) |
| E5 | every verifier module passes source integrity: no fallback/loose-match patterns, no dynamic execution (AST), strict failure codes present, **and** the positive constructs a correct verifier must contain — it must reference `terminated_conn_ids` and perform an actual membership (`in`) test, and must not decide on `connections_terminated` |
| E6 | IPv4 regression complete **and** PP18 re-derived here from the raw audit — the sandbox-written `pep_kill.json` is ignored entirely |
| E7 | the SHA-256 audit chain, recomputed independently in the auditor, is intact; zero malformed/truncated lines; records exist for this `run_id` |
| E8 | the three **audited** artifacts (`acceptance`, `layerb`, `v4`) each carry **this** `run_id` and `run_id_source == "control-plane"`, with no `run_id_conflict`. `pep_kill.json` and `b6_client.json` are stamped but not checked — both are advisory and neither feeds a verdict |

E5 exists because blacklisting weakened *shapes* is a losing game: two mutants
("any kill event counts", "termination count > 0") initially evaded pattern
matching while being exactly the weakening that matters. Positive-construct
assertions catch both.

Its limits are real and stated: E5 is **static inspection of source text**. It
cannot defeat a semantically-equivalent rewrite that keeps the required
constructs while changing meaning, and it says nothing about the interpreter
running it (Thompson, *Reflections on Trusting Trust*).

### Auditing the auditor: the fixture battery

```bash
cd strix-pipeline/pep/fixtures
./run_fixtures.sh          # exit 0 only if every fixture behaves as required
```

`run_fixtures.sh` runs three suites and passes only if all three pass:

1. **Fixture battery** — `make_fixtures.py` builds one honest,
   internally-consistent evidence set and twenty-one forgeries. Chains are really
   computed, the way `AuditLog.write()` computes them, so E7 is exercised rather
   than passing trivially. Five forgeries attack the **verifier source** rather
   than the evidence; four attack the artifact binding.
2. **Verifier self-test** (`test_verifiers.py`) — executes the verifiers against
   synthetic records and asserts each verdict code.
3. **Pipeline-order integration** (`test_pipeline_order.py`) — drives the real
   sequence `collect → stamp → verify_layerb_audit → audit` and asserts the
   honest path certifies while a sandbox self-label does not.

Suite 3 exists because of a defect that a fully green battery did not catch: a
revision of `verify_layerb_audit.py` treated the control plane's **own** stamp as
a sandbox self-label, which would have set `run_id_conflict` on every run and
failed E8 unconditionally on a dual-stack host — while blaming the sandbox for
it. The battery never executes the middle two stages, so it could not see it.

The battery is a release condition on the auditor, not on the PEP: it asserts
`CERTIFIED` / exit 0 for the honest set and `NOT CERTIFIED` / exit 1 for every
forgery. It proves the auditor rejects **these** forgeries. It does not prove
the forgery space is covered — a `run_id` leak through the shared bind mount
survived a fully green battery, because no fixture modelled the filesystem the
sandbox could see.

### Known-deferred (P2, not fixed)

These were identified in the security architecture review and are deliberately
**not** addressed here. They remain open:

* **R-8** kill-switch registry race — a connection registered *after* the
  snapshot survives the sweep. This is both an evidence defect and a genuine
  enforcement gap.
* **R-9** ip6tables rule assertion; **R-10** full mutation framework;
  **R-11** RFC 8215/6052 coverage; **R-12** additional Layer B rows (frozen at
  9 by decision); **R-13** external audit anchoring.

---

## 3. What each layer covers

**Layer A — 30 rows, policy logic.** Runs anywhere. Address classification for
both families, IPv4-mapped / 6to4 / Teredo / NAT64 unwrapping, canonicalization,
validate-all-across-families, absence-vs-denial, rebinding, pin reuse,
family-disabled-no-fallback, fail-closed on policy/resolver failure, and
address-family symmetry (ULA exemptible exactly like RFC1918, while
loopback / link-local / mapped-loopback stay denied even when explicitly listed
as exemptions).

**Layer B — 9 rows, transport.** Requires the live stack. B1–B7 run from inside
the sandbox; **B8–B9 are verified host-side against the PEP's own audit**, which
the sandbox can neither read nor forge.

Be precise about what that means: **B1–B7 are self-reported by the measured
party.** `verify_layerb_audit.py` replaces only B8 and B9 with host-derived
results and passes B1–B7 through verbatim. Their credibility rests on the
positive-control discipline below and on E8 binding the artifact to the
execution — not on independent re-derivation, which for those rows does not
exist.

| Row | Proves | Where |
|---|---|---|
| B1 | direct IPv6 egress bypass blocked, **against a live positive control** | sandbox |
| B2 | IPv6 route injection under `NET_ADMIN` blocked | sandbox |
| B3 | **path proof**: direct BLOCKED *and* via-PEP ALLOWED, same target, same run | sandbox |
| B4 | Host **and** SNI bound to canonical host over a v6 destination | sandbox |
| B5 | TLS interception works over IPv6 | sandbox |
| B6 | kill switch tears down a **live stream** — partial body received first | sandbox |
| B7 | link-local / multicast egress blocked at transport | sandbox |
| B8 | audit record for the v6 flow carries `pin_family=ipv6`, a genuine v6 `pin_ip`, `canonical_host`, `sni`, `request_hash`, `response_hash` | **host** |
| B9 | kill switch evidenced by **exact `conn_id` membership** in `KILL_SWITCH.terminated_conn_ids` — not a client socket error, and explicitly **not** a `connections_terminated > 0` count (a count proves *something* died, never *which*) | **host** |

### Four methodological rules these rows enforce

1. **Config is not evidence.** `fixed-cidr-v6` or the presence of a v6 route says
   nothing about whether the netfilter boundary holds. B1/B2/B7 are live socket
   attempts from inside the sandbox, never inferences from daemon settings.

2. **Negative results need positive controls.** A `BLOCKED` direct connection is
   meaningless if the v6 target was never listening. B1 and B3 are therefore
   evaluated as a **pair**: the run first proves the target is reachable *through
   the PEP*, and only then does a direct-path failure prove enforcement rather
   than absence. If the positive control fails, the row reports
   `NO_POSITIVE_CONTROL` — not `PROVEN`.

3. **Reachability is not enforcement.** B3 passing on its own would only show
   connectivity. B8 closes that by requiring the PEP's audit to carry the pin,
   the canonical host, the SNI, and both hashes. A pin *labelled* `ipv6` while
   holding an IPv4 literal is rejected as `PIN_NOT_V6`.

4. **Correlation, not coincidence.** Every host-side match is chained from the
   control-plane `run_id` — never from hostname, timestamp, or a value the
   sandbox chose:

   ```
   run_id                          (control plane; sandbox never sees it)
      -> audit records stamped with that run_id, and only those
      -> record with structured row_id in {B3,B5} (B8) or == B6 (B9)
      -> that record's test_nonce   (narrowing label, not proof)
      -> that record's conn_id      (PEP-generated)
      -> KILL_SWITCH.terminated_conn_ids contains that exact conn_id
   ```

   The earlier design anchored on the nonce alone. That was wrong in kind: the
   nonce is supplied by the party being measured. Anchoring now begins at a
   value only the control plane holds, and the nonce merely narrows within it.

   Without this, a valid-but-**stale** IPv6 ALLOW from an earlier run would
   satisfy B8, and B9 would accept the termination of some *other* connection
   that happened to die in the same window. Missing correlation data is a
   FAILURE (`NO_TEST_CORRELATION`), never a fallback to loose matching, and
   `B8.test_nonce != B9.test_nonce` is `NONCE_MISMATCH`, not a near-miss.

### Verifier self-test

`fixtures/test_verifiers.py` **executes** `verify_layerb_audit.evaluate()` and
`verify_pp18.verify()` against synthetic audit records and asserts the exact
verdict code each scenario must produce (20 scenarios). This is separate from
the fixture battery on purpose: the battery only ever *reads* verifier source,
through E5, so a verifier that is **wrong** rather than **weakened** is invisible
to it. It is run as part of `run_fixtures.sh`. The asserted verdicts:

| Scenario | Verdict |
|---|---|
| everything correct | `PROVEN` / `PROVEN` |
| **valid v6 ALLOW, but from an earlier execution** (different `run_id`) | B8 `NO_MATCHING_RECORD` |
| B8 and B9 nonces disagree | B9 `NONCE_MISMATCH:<n8>!=<n9>` |
| audit log truncated or containing a malformed line | `AUDIT_UNREADABLE_OR_TRUNCATED` |
| no `run_id` issued by the control plane | `NO_RUN_ID` |
| **kill switch terminated a different connection** | B9 `TERMINATED_A_DIFFERENT_CONNECTION` |
| kill record lists no conn_ids | B9 `KILL_RECORD_LISTS_NO_CONNECTIONS` |
| pin labelled `ipv6` holding an IPv4 literal | B8 `PIN_NOT_V6` |
| ALLOW record missing hashes | B8 `MISSING:request_hash,response_hash` |
| client never received body before the kill | B9 `NO_LIVE_STREAM_BEFORE_KILL` |
| no nonce emitted at all | `NO_TEST_CORRELATION` (both) |

**IPv4 regression — 17 rows**, plus a host-side **PP18** that holds the IPv4
kill switch to the same `conn_id` standard as B9. The v6 work cannot silently
regress v4.

PP18 now lives in its own module (`verify_pp18.py`) rather than inside a
`run_pep.sh` heredoc. That relocation is not cosmetic: as a heredoc it was
invisible to E5's verifier-integrity check and absent from the release gate
altogether, which left E6 trusting a partial-byte count the **sandbox** had
written about itself. `run_dualstack_gate.sh` now invokes it and requires
`PP18: PROVEN` in the verdict, and E6 re-derives the same chain independently.

> **Why client-side socket behaviour is never the evidence.** A torn-down
> connection reaches the client as a *clean EOF*, not an exception — and a
> connection rejected by the concurrency limit also produces "no response".
> Testing `bool(socket_error)` therefore fails in **both** directions: it
> reported TERMINATED for a connection that was never established (503), and
> SURVIVED for one the PEP had genuinely killed. The honest client-side signal
> is **truncation** (bytes received < `Content-Length`); the authoritative
> signal is the PEP's own audit, correlated by `conn_id`.

---

## 4. Topology the gate builds

```
gate_egress   172.29.0.0/24 + fd00:9a17:e9:1::/64   (dual-stack bridge)
  ├── allowed  172.29.0.20 / fd00:9a17:e9:1::20     authorized target
  ├── evil     172.29.0.30 / fd00:9a17:e9:1::30     out-of-scope
  ├── slow     172.29.0.60 / fd00:9a17:e9:1::60     stalls -> live-kill test
  └── PEP      172.29.0.10 / fd00:9a17:e9:1::10
                        │
gate_prog_a   172.31.0.0/24 + fd00:9a17:e9:2::/64   (INTERNAL, no egress)
  ├── PEP      172.31.0.10 / fd00:9a17:e9:2::10
  └── sandbox  172.31.0.50 / fd00:9a17:e9:2::50     NET_ADMIN + NET_RAW
```

Lab v6 targets sit on ULA and are therefore listed in `private_ip_exemptions` —
the same explicit-authorization step RFC1918 lab targets require. Removing an
address from that list must make it fail; that is the symmetry Layer A A25–A27
locks in.

---

## 5. If Layer B fails

Fix the PEP, not the test. Specifically do **not**:

- relax the environment gate so the suite "passes" without IPv6;
- mark a row `SKIP`, which reads like a pass months later;
- infer v6 behaviour from v4 results.

The suite reports `BLOCKED_ENV` / `NOT_RUN` rather than skipping, and returns
non-zero, precisely so none of the above can happen by accident in CI.

---

## 6. After the gate passes

The PEP becomes *eligible* for the Strix observation run — and that run remains
an **observation experiment**, not a security proof. The boundary is proven
before Strix starts; Strix behaviour is then measured inside it, never used to
argue the boundary is sound.

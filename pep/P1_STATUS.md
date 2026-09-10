# P1 REPAIR (PARTIAL) — STATUS

**Status: REPAIRED AND LOCALLY PROVEN. NOT VERIFIED. NOT CERTIFIED.**

Three DEC-2-independent P1 items from `TRIAGE_UNIFIED.md` / Pass 4's report are
repaired, plus the pending half of an already-settled decision (DEC-3's B7
title rewrite). Each code repair has a standing re-runnable proof with a
**live negative control**, same discipline as `P0_STATUS.md`.

    bash pep/fixtures/p1_proofs/run_p1_proofs.sh     -> P1 PROOFS: PASS (exit 0)
    bash pep/fixtures/run_fixtures.sh                -> BATTERY: PASS   (exit 0)
    (cd strix && git status --porcelain | wc -l)     -> 0

---

## Scope of this pass, and why it stops here

`POST_PASS4_DECISIONS.md` gates D-1's fix (the `KILL_SWITCH_ACTIVE` denial's
structurally-empty `row_id`/`test_nonce`) behind **DEC-2** (nonce semantics) —
explicitly the owner's call, explicitly not delegable the way DEC-1 was. This
pass deliberately did **not** touch that code path. Everything below was
chosen specifically because it does **not** depend on DEC-2:

- P1-1 — `phase2b/target_https.py` dual-stack bind (P2-CRIT-1)
- P1-2 — `audit_gate_evidence.py` E1 status/pass self-contradiction (P3-CRIT-2 / D-3)
- P1-3 — `gateway.py` `_deny()`/`_deny_tls()` carrying `conn_id` (P2-HIGH-3)
- DEC-3 — B7's title, the pending *execution* of an already-settled decision

The rest of `TRIAGE_UNIFIED.md`'s P1 list — P3-HIGH-2 (no E-check reads a
denial record), P3-HIGH-4 (E5 trailing-comment bypass), P3-HIGH-5 (E8 inert
for 2 of 3 artifacts), P3-HIGH-7 (E2 tautological counts), P3-HIGH-8 (no
per-check fixture isolation) — is **untouched**, by choice, to keep this a
reviewable increment rather than one large unreviewable batch.

## What "locally proven" means, and what it does not

Same rule as P0: a repairer's own green test is not evidence the repair
holds, and it is not evidence the repairer is wrong either. So every proof
here ships a negative control that must independently fail on the pre-fix
shape, or the corresponding pass is reported void. Two of the three P1 proofs
splice or run the **actual pre-fix source** — not a hand-written imitation of
it — on a disposable copy, so the control is exercising the real defect, not
a description of it.

**Nothing here may be promoted to SOUND without a fresh full run and an
independent Pass-4-style audit of this P1 tree.** Findings from the pre-P1
tree (including Pass 4's own report) are not evidence about this code.

---

## P1-1 — `phase2b/target_https.py`: dual-stack bind (P2-CRIT-1)

Was `ThreadingHTTPServer(("0.0.0.0", PORT), H)` — `AF_INET`-only by
inheritance, so every IPv6 connection the PEP forwarded here hit
`ECONNREFUSED` before reaching application code. TRIAGE_UNIFIED.md named this
as making Layer B's IPv6 rows "jointly unpassable on any live run", regardless
of how correct `pdp.py`'s decision logic was.

Repair: `DualStackHTTPServer(ThreadingHTTPServer)` — `address_family =
socket.AF_INET6`, `IPV6_V6ONLY` cleared explicitly in an overridden
`server_bind()` — mirrors `gateway.py`'s own listener exactly. Startup tries
`("::", PORT)` first with a **loud** (never silent) fallback to IPv4-only on
`OSError`.

This container has **no IPv6 kernel support at all** (`AF_INET6` socket
creation fails with `EAFNOSUPPORT` on both the client and server side
identically). The proof checks that capability explicitly, first, rather than
letting a "PASS" mean nothing:

    PRECONDITION: can this host create an AF_INET6 socket at all?
      OSError: [Errno 97] Address family not supported by protocol
    STATIC (CODE-VERIFIED): DualStackHTTPServer.address_family == socket.AF_INET6 -> True
    P1-1: ENVIRONMENT-BLOCKED (static shape check: PASS)

**This is not a PASS.** The transport-level claim (a real socket accepting
both families) is `ENVIRONMENT-BLOCKED` here and needs a real dual-stack host
— re-run `pep/fixtures/p1_proofs/proof_p1_1_target_dualstack.py` there (e.g.
via `run_dualstack_gate.sh`) to get an `EXECUTION-VERIFIED` result. Only the
static class-shape check ran on this container.

## P1-2 — `audit_gate_evidence.py`: E1 status/pass self-contradiction (P3-CRIT-2 / D-3)

`status` and `pass` are two views of one `ok` boolean, set together at
construction by `rec()` in `ipv6_acceptance.py`/`ipv6_transport.py`. But the
auditor reads a JSON blob off disk — no guarantee it came from `rec()` — and
the old E1 read `status` only. A hand-edited or corrupted row with
`status=="PROVEN"` and `pass=False` was certified.

Repair: E1 now also rejects `status=="PROVEN"` paired with `pass is not
True`, on every required row. New fixture `f22_contradictory_row` (required
row A10's `pass` forced `False`, `status` left `"PROVEN"`) confirmed by hand
to fail **only** E1 among E1–E8.

    PART 1 (real file, read-only)
      f22_contradictory_row: exit=1  FAIL  E1  contradictory=['A10=status:PROVEN,pass:False']
      f00_honest:             exit=0  CERTIFIED          <- fix does not certify-reject everything
    PART 2 (negative control: pre-fix E1, status-only, disposable copy)
      f22_contradictory_row against OLD E1: exit=0  CERTIFIED   <- old shape wrongly certifies it
    P1-2: PASS

## P1-3 — `gateway.py`: `_deny()`/`_deny_tls()` now carry `conn_id` (P2-HIGH-3)

Every denial audited through `_deny()`/`_deny_tls()` carried no `conn_id` at
all, even where a `ConnectionState` (`state`) was right there in scope — an
auditor could not correlate a `BLOCKED_BY_POLICY` record back to the
connection, PDP decision, or kill-switch lifecycle it belongs to. This is the
same correlation gap behind P3-HIGH-2 ("no E-check reads a denial record"),
which is why P3-HIGH-2 is the natural next item but was left for a future
pass rather than folded in here.

Repair: `conn_id`/`row_id`/`test_nonce` threaded through all 4 in-scope
`_deny()` call sites in `_connect_flow`, all 7 `_deny_tls()` call sites in
`_inside` (whose signature now makes them **required**, not optional — every
call site has `state` by construction), and the 2 raw
`audit.write({"decision": "BLOCKED_BY_POLICY", ...})` sites that bypass both
helpers (`MALFORMED_TLS_CLIENT_HELLO`, `MALFORMED_HTTP_IN_TUNNEL`) plus the
`UPSTREAM_CERT_INVALID` diagnostic write — identical defect shape, `state`
equally in scope.

**Deliberately unchanged:** the `KILL_SWITCH_ACTIVE` denial in `do_CONNECT`
(D-1). It already carries the `conn_id`/`row_id`/`test_nonce` *keys*, but
`row_id`/`test_nonce` are structurally still empty there — the headers that
populate them are read later, in `_connect_flow` — and fixing that is DEC-2's
call, not this pass's.

The negative control here runs the **actual pre-fix `gateway.py`** — not a
rewritten imitation — on a disposable copy under a fresh package name
(`pep_negctrl`, so Python's module cache can't hand back the real module by
accident). `pre_p2high3_gateway.snapshot` is verified byte-for-byte against
the real file at the moment this pass started: `diff` shows its only
differences are exactly today's 12 edits, nothing else.

    PART 1 (real file, driven directly — no subprocess)
      pdp_failure    conn_id_match=True   pdp_not_allow  conn_id_match=True
      sni_mismatch   conn_id_match=True   no_state       conn_id_absent=True  <- fix doesn't overreach
    PART 2 (negative control: pre-fix gateway.py, disposable copy, fresh package name)
      pdp_failure    conn_id_present=False   pdp_not_allow  conn_id_present=False
      sni_mismatch   conn_id_present=False   no_state       conn_id_present=False
    P1-3: PASS

## DEC-3 — B7 title rewrite (executed; wording chosen by the owner)

`ipv6_transport.py:458`'s title read *"IPv6 link-local egress blocked at
transport"* with `expect="PROVEN"` — an outcome claim the code's own 25-line
comment explains it can never produce against a fabricated, unoccupied peer
(the same confound Pass 4 confirmed as D-5). Rewritten, per the owner's
choice, to describe the property under test rather than assert a result, the
same way `B4`/`B5`'s `desc` strings already do:

    "IPv6 link-local/multicast egress boundary (synthetic unoccupied peer)"

**String-only change.** `expect` is still `"PROVEN"`; `got`/the `rec()`
equality check (`ok = expect == got`) is byte-for-byte unchanged; every
downstream E-check reads the same `status`/`pass` values as before. The row's
behaviour — it cannot report `PROVEN` against this topology, and the gate
stays blocked until a real occupied link-local peer exists — is identical to
before this rewrite. `ipv6_transport.py` is a live-network Layer B script,
not exercised by `run_fixtures.sh`; there is no hermetic regression battery
for this file in this container, only the syntax check and the confirmation
that `run_fixtures.sh`'s own import of `ipv6_transport` (`fixtures/
test_preconditions.py:40`) still passes at 42/42.

---

## Explicitly NOT done

* **D-1's fix** (`KILL_SWITCH_ACTIVE`'s empty `row_id`/`test_nonce`) — gated
  on DEC-2 (nonce semantics), the owner's call, deliberately untouched.
* **The rest of P1**: P3-HIGH-2 (no E-check reads a denial record — the
  natural next item now that P1-3 gives denials a `conn_id` to correlate on),
  P3-HIGH-4 (E5 trailing-comment bypass), P3-HIGH-5 (E8 inert for 2 of 3
  artifacts), P3-HIGH-7 (E2 tautological counts), P3-HIGH-8 (no per-check
  fixture isolation).
* **P1-1's transport claim is `ENVIRONMENT-BLOCKED`, not proven** — this
  container has no IPv6 stack. Needs a real dual-stack host.
* **No fresh Pass 4 has run on this P1 tree.** Everything above is
  unit/component-level, written by the same agent that wrote the repairs.
  Pass 4's own report (and this document) are about the **pre-P1** tree and
  are not evidence about this one.
* **`run_fixtures.sh`, `fixtures/make_fixtures.py`, and the fixture tree were
  modified during this and the prior (P0) pass** — UNTRUSTED under the
  project's own rule until independently revalidated.
* **DEC-4, DEC-5, DEC-6** (from `POST_PASS4_DECISIONS.md`) remain open and
  untouched by this pass.

"""
Production Execution Gateway (PEP).

Differences from the Phase 2a/2b proof harness, all deliberate:

  * STREAMING, not buffering. Bodies are relayed in chunks and hashed
    incrementally, so provenance survives without holding a response in memory.
  * CONCURRENCY LIMIT. A bounded worker pool; exhaustion is an audited denial,
    not an unbounded queue.
  * PER-CONNECTION PIN STATE. The (family, ip, port) bound is established once
    and carried in ConnectionState for the connection's whole life.
  * ADDRESS-FAMILY AWARE SOCKETS. AF_INET6 vs AF_INET is chosen from the pin,
    never guessed and never retried across families.
  * DYNAMIC CA MINTING per destination.
  * FAIL CLOSED on any PDP, DNS, or certificate-machinery failure.
  * LIFECYCLE: idle/total timeouts, registry-driven teardown for the kill switch.
"""

from __future__ import annotations

import hashlib
import os
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .addressing import Pin, canonical_host
from .audit import AuditLog
from .ca import CAError, InterceptionCA
from .lifecycle import (ConnectionLifecycle, EffectGate, RunContext,
                        AuditUnhealthy, Cancelled, new_attempt_id,
                        sanitized_intent)
from . import lifecycle as _lc
from .pdp import PDP

MAX_CONNECTIONS = int(os.environ.get("PEP_MAX_CONNECTIONS", "64"))
CANCEL_DRAIN_TIMEOUT = float(os.environ.get("PEP_CANCEL_DRAIN_TIMEOUT", "5"))
IDLE_TIMEOUT = float(os.environ.get("PEP_IDLE_TIMEOUT", "30"))
TOTAL_TIMEOUT = float(os.environ.get("PEP_TOTAL_TIMEOUT", "300"))
CHUNK = 65536


@dataclass(eq=False)   # identity semantics: a live connection is not "equal" to
                       # another with the same field values, and it must stay
                       # hashable so the registry can hold it in a set.
class ConnectionState:
    """Everything bound to ONE client connection, including its pin.

    ``conn_id`` is what lets an auditor tie a specific client request to a
    specific PEP decision and, later, to a specific termination — instead of
    matching on timestamps or hostnames, which a stale-but-valid record from an
    earlier run would also satisfy.

    Phase 1 (F02): socket ownership and the per-connection TERMINAL flag live in
    ``lifecycle`` (a ConnectionLifecycle). ``track()`` now REGISTERS a socket
    under the ownership lock and returns False (closing the socket) if the
    connection is already terminal — so a socket created after a kill can never
    be used. ``close_all()`` delegates to the same terminal teardown.
    """
    client_ip: str
    conn_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    test_nonce: str = ""     # client-supplied LABEL, explicitly non-authoritative
    row_id: str = ""         # which acceptance row this connection belongs to
    started: float = field(default_factory=time.time)
    pin: Pin | None = None
    canonical: str | None = None
    program_id: str | None = None
    policy_generation: str = ""
    budget_binding: str = ""
    lifecycle: ConnectionLifecycle | None = None

    def __post_init__(self) -> None:
        if self.lifecycle is None:
            self.lifecycle = ConnectionLifecycle(self.conn_id)

    @property
    def sockets(self) -> list:
        return self.lifecycle._sockets

    def track(self, s) -> bool:
        """Register a socket BEFORE connect. Returns False (and closes ``s``) if
        the connection is already terminal; the caller MUST NOT proceed."""
        return self.lifecycle.track_or_reject(s)

    def track_or_reject(self, s) -> bool:
        return self.lifecycle.track_or_reject(s)

    def transfer(self, old, new) -> bool:
        """Hand ownership to a TLS-wrapped socket without a cancellation gap."""
        return self.lifecycle.transfer(old, new)

    def is_terminal(self) -> bool:
        return self.lifecycle.is_terminal()

    def close_all(self) -> bool:
        """Set terminal and tear down every owned socket. Returns True iff at
        least one socket was still LIVE and was actually shut down (the kill
        evidence — see terminated_conn_ids)."""
        return self.lifecycle.terminate()

    def begin_termination(self) -> list:
        return self.lifecycle.begin_termination()

    def shutdown_retained(self, sockets: list) -> bool:
        return self.lifecycle.shutdown_retained(sockets)


class Registry:
    """Live-connection registry with a TERMINAL, MONOTONIC kill state.

    R-8 (closed earlier): terminate_all() sets `_killed` and drains the set in
    ONE lock acquisition, so nothing can be admitted without seeing the flag.

    Phase 1 F02 (closed here): terminate_all() also makes every victim's
    ConnectionState TERMINAL (via close_all()), including a connection that was
    admitted but has not yet created its upstream socket. That connection's
    later track()/permit sees the terminal flag and refuses — closing the
    "admitted, socket created after kill" race the add()-only fix left open.
    Cancellation is MONOTONIC: there is no in-process rearm; a withdrawn kill
    file cannot return the run to RUNNING (a new run epoch/process is required).
    """

    def __init__(self) -> None:
        self._conns: set[ConnectionState] = set()
        self._lock = threading.Lock()
        self._producer_cv = threading.Condition(self._lock)
        self._sem = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._killed = False
        self._producer_admission = True
        self._active_producers = 0
        self.run = RunContext()     # cancellation epoch shared with EffectGate
        self.last_cancellation: dict | None = None

    def acquire(self) -> bool:
        return self._sem.acquire(blocking=False)

    def release(self) -> None:
        try:
            self._sem.release()
        except ValueError:
            pass

    def add(self, c: ConnectionState) -> bool:
        """Register a live connection. Returns False if the kill switch has
        already fired — the caller MUST NOT proceed with the connection."""
        with self._lock:
            if self._killed:
                return False
            self._conns.add(c)
            return True

    def begin_producer(self) -> bool:
        """Track a complete handler/audit-producer lifetime, permit or not."""
        with self._producer_cv:
            if self._killed or not self._producer_admission:
                return False
            self._active_producers += 1
            return True

    def end_producer(self) -> None:
        with self._producer_cv:
            if self._active_producers <= 0:
                raise RuntimeError("PRODUCER_ACCOUNTING_UNDERFLOW")
            self._active_producers -= 1
            if self._active_producers == 0:
                self._producer_cv.notify_all()

    def producer_count(self) -> int:
        with self._producer_cv:
            return self._active_producers

    def wait_for_producer_drain(self, timeout: float | None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._producer_cv:
            while self._active_producers:
                if deadline is None:
                    self._producer_cv.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._producer_cv.wait(remaining)
            return True

    def remove(self, c: ConnectionState) -> None:
        with self._lock:
            self._conns.discard(c)

    def is_killed(self) -> bool:
        with self._lock:
            return self._killed

    def rearm(self) -> None:
        """DELIBERATE NO-OP (Phase 1 / F02). Cancellation is terminal: a
        withdrawn kill file does NOT return a cancelled run to RUNNING. Retained
        only so no caller can accidentally re-open egress by clearing state."""
        return

    def terminate_all(self, *, on_linearized=None, stop_listener=None,
                      drain_timeout: float = 0.0) -> tuple[list[str], list[str]]:
        """Cancel, make all victims terminal, start shutdown, then audit/drain.

        The RunContext transition is the permit/cancel linearization point.
        Every connection is marked terminal and all retained-handle shutdowns
        are initiated before on_linearized may perform audit I/O. Thus blocked
        storage cannot delay admission closure or retained-handle enforcement.
        The historical two-list return is retained for E1-E9 callers; drain
        and evidence facts are exposed through last_cancellation.
        """
        transition = self.run.cancel()
        with self._lock:
            self._killed = True
            self._producer_admission = False
            victims = list(self._conns)
            self._conns.clear()
        # Mark every victim before any potentially blocking socket operation.
        retained = [(c, c.begin_termination()) for c in victims]
        torn = [c.conn_id for c, sockets in retained
                if c.shutdown_retained(sockets)]
        listener_stop_started = stop_listener is None
        if stop_listener is not None:
            try:
                stop_listener()
                listener_stop_started = True
            except Exception:
                listener_stop_started = False
        evidence_durable = on_linearized is None
        if on_linearized is not None:
            try:
                on_linearized(transition)
                evidence_durable = True
            except Exception:
                # Enforcement already happened. Evidence failure must fail
                # certification/admission closed, never undo cancellation.
                evidence_durable = False
        drained = self.run.wait_for_drain(drain_timeout)
        self.last_cancellation = {
            "transition": transition,
            "local_drain_complete": drained,
            "inflight_remaining": self.run.inflight_count(),
            "linearization_evidence_durable": evidence_durable,
            "listener_stop_started": listener_stop_started,
        }
        return torn, [c.conn_id for c in victims]

    def count(self) -> int:
        with self._lock:
            return len(self._conns)


class Gateway(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "StrixPEP/1.0"

    pdp: PDP = None          # injected by serve()
    ca: InterceptionCA = None
    audit: AuditLog = None
    registry: Registry = None

    def log_message(self, *a) -> None:
        pass

    def handle(self) -> None:
        """Account for every handler that could append audit evidence.

        A socket accepted just before listener shutdown but dispatched after
        cancellation is refused here without producing post-close audit bytes.
        """
        if not self.registry.begin_producer():
            self.close_connection = True
            return
        try:
            super().handle()
        finally:
            self.registry.end_producer()

    # ------------------------------------------------------------------ helpers
    def _deny(self, reason: str, url: str, method: str, code: int = 403,
             conn_id: str = "", row_id: str = "", test_nonce: str = "") -> None:
        """P2-HIGH-3 (TRIAGE_UNIFIED.md): conn_id (and, once headers are read,
        row_id/test_nonce) is attached whenever a caller has a ConnectionState
        to give — previously every denial through this method was audited
        with no conn_id at all, though the 4 calls inside _connect_flow have
        `state` right there in scope and are fixed here. Four calls genuinely
        have none, because they fire before any ConnectionState exists:
        do_GET's PLAINTEXT_HTTP_DISABLED and __getattr__'s
        UNSUPPORTED_PROTOCOL_OR_METHOD handle plain HTTP methods that never go
        through a CONNECT tunnel at all, and do_CONNECT's
        MALFORMED_CONNECT_TARGET / CONCURRENCY_LIMIT_REACHED both fire before
        `state = ConnectionState(...)` runs. All four leaving conn_id empty is
        correct, not a gap. This is deliberately NOT the KILL_SWITCH_ACTIVE
        denial in do_CONNECT (D-1 / Pass 4): that path DOES have a `state` by
        the time it fires and already carries the conn_id/row_id/test_nonce
        keys, but row_id/test_nonce are structurally still empty there — the
        headers that populate them are read later, in _connect_flow — and
        fixing that is gated on DEC-2 (nonce semantics), untouched here.
        """
        body = f'{{"error":"BLOCKED_BY_POLICY","reason":"{reason}"}}'.encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-PDP-Decision", "BLOCKED_BY_POLICY")
            self.send_header("X-PDP-Reason", reason)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass
        rec = {"decision": "BLOCKED_BY_POLICY", "reason": reason,
              "url": url, "method": method, "src": self.client_address[0]}
        if conn_id:
            rec["conn_id"] = conn_id
            rec["row_id"] = row_id
            rec["test_nonce"] = test_nonce
        self.audit.write(rec)

    def __getattr__(self, name: str):
        if name.startswith("do_"):
            return lambda: self._deny("UNSUPPORTED_PROTOCOL_OR_METHOD", self.path, name[3:])
        raise AttributeError(name)

    def do_GET(self) -> None:  # noqa: N802
        self._deny("PLAINTEXT_HTTP_DISABLED", self.path, "GET")

    # ------------------------------------------------------------------ CONNECT
    def do_CONNECT(self) -> None:  # noqa: N802
        target = self.path
        host_raw, sep, p = target.rpartition(":")
        if not sep or not p.isdigit():
            return self._deny("MALFORMED_CONNECT_TARGET", f"CONNECT {target}", "CONNECT")
        port = int(p)

        if not self.registry.acquire():
            return self._deny("CONCURRENCY_LIMIT_REACHED", f"CONNECT {target}",
                              "CONNECT", code=503)

        # Everything after acquire() must sit inside the try, or a failure in
        # between leaks the slot permanently and the PEP denies itself to death.
        state = ConnectionState(client_ip=self.client_address[0])
        # DEC-2: row_id/test_nonce are untrusted client labels, not execution
        # authority.  Capture them before Registry.add() so an admission refused
        # by an already-active kill switch is still correlatable.  run_id remains
        # the control-plane execution anchor stamped by AuditLog.
        state.test_nonce = self.headers.get("X-Strix-Nonce", "")
        state.row_id = self.headers.get("X-Strix-Row", "")
        try:
            if not self.registry.add(state):
                # The kill switch fired while this connection was being set up.
                # Refuse it rather than running it — otherwise "stop everything"
                # would have a hole exactly the width of the setup path.
                self.audit.write({"decision": "BLOCKED_BY_POLICY",
                                  "reason": "KILL_SWITCH_ACTIVE",
                                  "url": f"CONNECT {target}", "method": "CONNECT",
                                  "conn_id": state.conn_id,
                                  "row_id": state.row_id,
                                  "test_nonce": state.test_nonce,
                                  "src": state.client_ip})
                return
            self._connect_flow(state, target, host_raw, port)
        except Exception as exc:                      # fail closed on anything
            self.audit.write({"decision": "BLOCKED_BY_POLICY",
                              "reason": f"INTERNAL_FAILURE:{type(exc).__name__}",
                              "url": f"CONNECT {target}", "method": "CONNECT",
                              "conn_id": state.conn_id, "row_id": state.row_id,
                              "test_nonce": state.test_nonce,
                              "src": state.client_ip})
        finally:
            state.close_all()
            self.registry.remove(state)
            self.registry.release()
            self.close_connection = True

    def _connect_flow(self, state, target, host_raw, port) -> None:
        session = self.headers.get("X-Strix-Session", "")
        asset = self.headers.get("X-Strix-Asset", "")
        cred = self.headers.get("X-Strix-Cred", "")
        # Structured labels so the auditor never has to parse a URL or prose.
        # These are client-chosen and therefore NOT the execution anchor —
        # run_id (control-plane) is. They only say which row a record belongs to.

        try:
            d = self.pdp.decide(src_ip=state.client_ip, authority=host_raw, port=port,
                                method="CONNECT", session=session, asset=asset, cred_id=cred)
        except Exception as exc:
            return self._deny(f"PDP_FAILURE:{type(exc).__name__}", f"CONNECT {target}",
                              "CONNECT", conn_id=state.conn_id, row_id=state.row_id,
                              test_nonce=state.test_nonce)
        if not d.allow:
            return self._deny(d.reason, f"CONNECT {target}", "CONNECT",
                              conn_id=state.conn_id, row_id=state.row_id,
                              test_nonce=state.test_nonce)

        # Pin is established ONCE, here, and reused for this connection's life.
        state.pin = d.pin
        state.canonical = canonical_host(host_raw)
        state.program_id = d.program_id
        state.policy_generation = str((d.detail or {}).get("policy_generation", ""))
        state.budget_binding = str((d.detail or {}).get("budget_binding", ""))

        try:
            crt, key = self.ca.leaf_for(state.canonical)
        except CAError as exc:
            return self._deny(f"CERT_MINT_FAILED:{exc}", f"CONNECT {target}", "CONNECT",
                              conn_id=state.conn_id, row_id=state.row_id,
                              test_nonce=state.test_nonce)

        self.send_response(200, "Connection Established")
        self.end_headers()

        seen: list[str | None] = [None]

        def sni_cb(sock, name, ctx):  # noqa: ANN001
            seen[0] = name

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(crt, key)
        except Exception as exc:
            return self._deny(f"CERT_LOAD_FAILED:{type(exc).__name__}",
                              f"CONNECT {target}", "CONNECT", conn_id=state.conn_id,
                              row_id=state.row_id, test_nonce=state.test_nonce)
        ctx.sni_callback = sni_cb

        raw = self.connection
        state.track(raw)
        raw.settimeout(IDLE_TIMEOUT)
        try:
            tls = ctx.wrap_socket(raw, server_side=True)
        except (ssl.SSLError, OSError) as exc:
            self.audit.write({"decision": "BLOCKED_BY_POLICY",
                              "reason": "MALFORMED_TLS_CLIENT_HELLO",
                              "detail": type(exc).__name__,
                              "url": f"CONNECT {target}", "method": "CONNECT",
                              "conn_id": state.conn_id, "row_id": state.row_id,
                              "test_nonce": state.test_nonce})
            return
        if not state.transfer(raw, tls):
            return
        self._inside(state, tls, port, session, asset, cred, seen[0])

    # --------------------------------------------------------- inside the tunnel
    def _inside(self, state, tls, port, session, asset, cred, sni) -> None:
        canon = state.canonical
        label = f"https://{canon}:{port}"

        if sni is not None and canonical_host(sni) != canon:
            return self._deny_tls(tls, f"SNI_MISMATCH:{sni}!={canon}", label, "CONNECT",
                                  state.conn_id, state.row_id, state.test_nonce)

        head = self._read_head(tls)
        if head is None:
            self.audit.write({"decision": "BLOCKED_BY_POLICY",
                              "reason": "MALFORMED_HTTP_IN_TUNNEL", "url": label,
                              "conn_id": state.conn_id, "row_id": state.row_id,
                              "test_nonce": state.test_nonce})
            return
        method, path, headers, pre_body = head

        hdr_host = canonical_host((headers.get("host") or "").split(":")[0]
                                  if not (headers.get("host") or "").startswith("[")
                                  else (headers.get("host") or "").split("]")[0] + "]")
        if hdr_host != canon:
            return self._deny_tls(tls, f"HOST_HEADER_MISMATCH:{hdr_host}!={canon}",
                                  label + path, method, state.conn_id, state.row_id,
                                  state.test_nonce)

        # Re-decide on the real method, carrying the pin so nothing re-resolves.
        try:
            d = self.pdp.decide(src_ip=state.client_ip, authority=canon, port=port,
                                method=method, session=session, asset=asset,
                                cred_id=cred, pin=state.pin)
        except Exception as exc:
            return self._deny_tls(tls, f"PDP_FAILURE:{type(exc).__name__}",
                                  label + path, method, state.conn_id, state.row_id,
                                  state.test_nonce)
        if not d.allow:
            return self._deny_tls(tls, d.reason, label + path, method, state.conn_id,
                                  state.row_id, state.test_nonce)

        if d.secret:
            self.audit.add_secret(d.secret)

        # F03: durably bind the control decision before the first target effect.
        # DNS/control-plane work above is outside this target-effect boundary and
        # can itself have network effects when a non-static resolver is used.
        gate = EffectGate(self.audit, self.registry.run)
        epoch = self.registry.run.epoch()
        attempt_id = new_attempt_id()
        policy_generation = str((d.detail or {}).get("policy_generation", ""))
        budget_binding = str((d.detail or {}).get("budget_binding", ""))
        if (policy_generation != state.policy_generation or
                budget_binding != state.budget_binding):
            return self._deny_tls(tls, "AUTHORIZATION_BINDING_CHANGED",
                                  label + path, method, state.conn_id,
                                  state.row_id, state.test_nonce)
        intent = sanitized_intent(
            run_id=getattr(self.audit, "run_id", ""), conn_id=state.conn_id,
            attempt_id=attempt_id, epoch=epoch,
            program_id=state.program_id or "",
            policy_generation=policy_generation,
            method=method, canonical_host=canon, path=path, pin=state.pin,
            credential_ref=cred or "none", budget_binding=budget_binding,
            body_len=len(pre_body))
        try:
            gate.commit_intent(intent)
        except (AuditUnhealthy, Cancelled) as exc:
            return self._deny_tls(tls, f"AUDIT_UNHEALTHY:{type(exc).__name__}",
                                  label + path, method, state.conn_id, state.row_id,
                                  state.test_nonce)

        # Re-read policy with the already-pinned destination. This is network-free
        # and does not reserve budget again, but detects generation/scope/credential
        # changes between durable intent and permit acquisition.
        try:
            current = self.pdp.decide(
                src_ip=state.client_ip, authority=canon, port=port,
                method=method, session=session, asset=asset, cred_id=cred,
                pin=state.pin)
        except Exception as exc:
            gate.settle(attempt_id, state.conn_id, _lc.FAILED,
                        {"reason": f"PDP_RECHECK:{type(exc).__name__}"})
            return self._deny_tls(tls, f"PDP_FAILURE:{type(exc).__name__}",
                                  label + path, method, state.conn_id,
                                  state.row_id, state.test_nonce)
        current_generation = str((current.detail or {}).get("policy_generation", ""))
        current_budget = str((current.detail or {}).get("budget_binding", ""))
        if (not current.allow or current.program_id != state.program_id or
                current.pin != state.pin or
                current_generation != policy_generation or
                current_budget != budget_binding):
            gate.settle(attempt_id, state.conn_id, _lc.FAILED,
                        {"reason": "AUTHORIZATION_RECHECK_FAILED"})
            return self._deny_tls(tls, "AUTHORIZATION_RECHECK_FAILED",
                                  label + path, method, state.conn_id,
                                  state.row_id, state.test_nonce)

        fam = socket.AF_INET6 if state.pin.family == "ipv6" else socket.AF_INET
        up_ctx = ssl.create_default_context(
            cafile=os.environ.get("PEP_UPSTREAM_CA") or None)
        up_ctx.check_hostname = True
        up_ctx.verify_mode = ssl.CERT_REQUIRED

        permit = None
        try:
            try:
                plain = socket.socket(fam, socket.SOCK_STREAM)
                plain.settimeout(IDLE_TIMEOUT)
            except Exception as exc:
                gate.settle(attempt_id, state.conn_id, _lc.FAILED,
                            {"reason": f"SOCKET_CREATE:{type(exc).__name__}"})
                return self._deny_tls(tls, f"UPSTREAM_ERROR:{type(exc).__name__}",
                                      label + path, method, state.conn_id,
                                      state.row_id, state.test_nonce)
            if not state.track(plain):
                gate.settle(attempt_id, state.conn_id, _lc.CANCELLED,
                            {"reason": "TERMINAL_BEFORE_CONNECT"})
                return self._deny_tls(tls, "KILL_SWITCH_ACTIVE", label + path,
                                      method, state.conn_id, state.row_id,
                                      state.test_nonce)
            try:
                permit = gate.acquire_permit(
                    attempt_id, epoch, state.lifecycle,
                    policy_generation=current_generation,
                    budget_binding=current_budget)
            except AuditUnhealthy as exc:
                return self._deny_tls(
                    tls, f"AUDIT_UNHEALTHY:{type(exc).__name__}", label + path,
                    method, state.conn_id, state.row_id, state.test_nonce)
            if permit is None:
                gate.settle(attempt_id, state.conn_id, _lc.CANCELLED,
                            {"reason": "EPOCH_TERMINAL_OR_BINDING_AT_PERMIT"})
                return self._deny_tls(tls, "CANCELLED_AT_PERMIT", label + path,
                                      method, state.conn_id, state.row_id,
                                      state.test_nonce)
            if state.is_terminal():
                gate.settle(permit, state.conn_id, _lc.CANCELLED,
                            {"reason": "TERMINAL_BEFORE_ATTEMPT"})
                return self._deny_tls(tls, "CANCELLED_BEFORE_ATTEMPT",
                                      label + path, method, state.conn_id,
                                      state.row_id, state.test_nonce)
            try:
                gate.mark_attempted(
                    permit, state.conn_id,
                    {"pin_ip": state.pin.ip, "pin_port": state.pin.port})
            except AuditUnhealthy as exc:
                return self._deny_tls(
                    tls, f"AUDIT_UNHEALTHY:{type(exc).__name__}", label + path,
                    method, state.conn_id, state.row_id, state.test_nonce)

            try:
                plain.connect((state.pin.ip, state.pin.port))
                up = up_ctx.wrap_socket(plain, server_hostname=canon)
                if not state.transfer(plain, up):
                    gate.settle(permit, state.conn_id, _lc.UNKNOWN,
                                {"reason": "TERMINAL_DURING_TLS"})
                    return self._deny_tls(tls, "CANCELLED_DURING_TLS",
                                          label + path, method, state.conn_id,
                                          state.row_id, state.test_nonce)
            except ssl.SSLCertVerificationError as exc:
                gate.settle(permit, state.conn_id, _lc.UNKNOWN,
                            {"reason": "UPSTREAM_CERT_INVALID"})
                self.audit.write({"decision": "BLOCKED_BY_POLICY",
                                  "reason": "UPSTREAM_CERT_INVALID",
                                  "detail": str(exc)[:160], "url": label + path,
                                  "pin": state.pin.as_tuple(),
                                  "conn_id": state.conn_id,
                                  "row_id": state.row_id,
                                  "test_nonce": state.test_nonce})
                return self._deny_tls(tls, "UPSTREAM_CERT_INVALID",
                                      label + path, method, state.conn_id,
                                      state.row_id, state.test_nonce)
            except TimeoutError:
                gate.settle(permit, state.conn_id, _lc.UNKNOWN,
                            {"reason": "CONNECT_TIMEOUT"})
                return self._deny_tls(tls, "UPSTREAM_ERROR:TimeoutError",
                                      label + path, method, state.conn_id,
                                      state.row_id, state.test_nonce)
            except Exception as exc:
                gate.settle(permit, state.conn_id, _lc.UNKNOWN,
                            {"reason": f"UPSTREAM_ERROR:{type(exc).__name__}"})
                return self._deny_tls(tls, f"UPSTREAM_ERROR:{type(exc).__name__}",
                                      label + path, method, state.conn_id,
                                      state.row_id, state.test_nonce)

            out = [f"{method} {path} HTTP/1.1", f"Host: {canon}",
                   "Connection: close", "Accept: */*"]
            if d.secret:
                out.append(f"Authorization: Bearer {d.secret}")
            if pre_body:
                out.append(f"Content-Length: {len(pre_body)}")
            raw_req = ("\r\n".join(out) + "\r\n\r\n").encode() + pre_body
            # v2 semantics: request_hash is the sanitized intent commitment. It
            # never digests the credential-bearing raw_req.
            req_hash = intent["request_intent_digest"].split(":", 1)[1]

            try:
                up.sendall(raw_req)
            except Exception as exc:
                gate.settle(permit, state.conn_id, _lc.UNKNOWN,
                            {"reason": f"UPSTREAM_WRITE:{type(exc).__name__}"})
                return self._deny_tls(tls, f"UPSTREAM_WRITE:{type(exc).__name__}",
                                      label + path, method, state.conn_id,
                                      state.row_id, state.test_nonce)

            h = hashlib.sha256()
            total = 0
            status = 0
            first = True
            deadline = time.time() + TOTAL_TIMEOUT
            try:
                while True:
                    if time.time() > deadline:
                        raise TimeoutError("total_timeout")
                    chunk = up.recv(CHUNK)
                    if not chunk:
                        break
                    if first:
                        try:
                            status = int(chunk.split(b" ", 2)[1])
                        except Exception:
                            status = 0
                        first = False
                    h.update(chunk)
                    total += len(chunk)
                    tls.sendall(chunk)
            except Exception as exc:
                gate.settle(permit, state.conn_id, _lc.UNKNOWN,
                            {"reason": type(exc).__name__,
                             "bytes_streamed": total})
                self.audit.write({
                    "decision": "CONNECTION_TERMINATED",
                    "reason": type(exc).__name__, "url": label + path,
                    "method": method, "bytes_streamed": total,
                    "conn_id": state.conn_id, "attempt_id": attempt_id,
                    "test_nonce": state.test_nonce, "row_id": state.row_id,
                    "pin": state.pin.as_tuple()})
                return

            gate.settle(permit, state.conn_id, _lc.COMPLETED,
                        {"upstream_status": status,
                         "response_hash": h.hexdigest(),
                         "streamed_bytes": total})
            self.audit.write({
                "decision": "ALLOW", "reason": "ALLOW", "url": label + path,
                "method": method, "src": state.client_ip,
                "program_id": state.program_id,
                "conn_id": state.conn_id, "attempt_id": attempt_id,
                "test_nonce": state.test_nonce, "row_id": state.row_id,
                "tls_intercepted": True, "canonical_host": canon, "sni": sni,
                "pin_family": state.pin.family, "pin_ip": state.pin.ip,
                "pin_port": state.pin.port, "upstream_status": status,
                "redirect_followed": False,
                "credential_injected": bool(d.secret),
                "streamed_bytes": total, "request_hash": req_hash,
                "request_hash_semantics": "sanitized-intent-v2",
                "response_hash": h.hexdigest(),
            })
        finally:
            if permit is not None:
                permit.release()

    def _deny_tls(self, tls, reason, url, method, conn_id: str, row_id: str,
                  test_nonce: str) -> None:
        """P2-HIGH-3: conn_id/row_id/test_nonce are required here (not
        optional, as in _deny()) because every call site inside _inside()
        always has `state` in scope by construction — there is no code path
        that reaches _deny_tls() before a ConnectionState exists, unlike
        do_CONNECT where two denials fire before allocation. A required
        parameter makes that guarantee checkable at every call site instead of
        silently defaulting to empty, which is what this replaces.
        """
        body = f'{{"error":"BLOCKED_BY_POLICY","reason":"{reason}"}}'.encode()
        resp = (b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n"
                b"X-PDP-Decision: BLOCKED_BY_POLICY\r\n"
                + f"X-PDP-Reason: {reason}\r\nContent-Length: {len(body)}\r\n\r\n".encode()
                + body)
        try:
            tls.sendall(resp)
            # drain so the close is FIN, not RST — otherwise the kernel discards
            # our denial and the caller sees a bare socket error instead.
            tls.settimeout(1.0)
            try:
                while tls.recv(CHUNK):
                    pass
            except Exception:
                pass
        except Exception:
            pass
        self.audit.write({"decision": "BLOCKED_BY_POLICY", "reason": reason,
                          "url": url, "method": method, "tls": True,
                          "conn_id": conn_id, "row_id": row_id,
                          "test_nonce": test_nonce})

    @staticmethod
    def _read_head(sock):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(CHUNK)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 262144:
                return None
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, path, _ = lines[0].split(" ", 2)
        except ValueError:
            return None
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return method, path, headers, rest


def cancel_and_quiesce(registry: Registry, audit: AuditLog, *, server=None,
                       listener_closed: threading.Event | None = None,
                       timeout: float = CANCEL_DRAIN_TIMEOUT) -> dict:
    """Enforce cancellation, stop accepts, drain every producer, then seal.

    The caller may set ``listener_closed`` before entry when the listener was
    initialized but never served (STOP_ALL already present at startup).
    """
    if listener_closed is None:
        listener_closed = threading.Event()
        if server is None:
            listener_closed.set()

    def record_linearization(transition) -> None:
        # These fsyncs occur after registry/connection enforcement and after
        # listener shutdown was initiated.
        audit.write({"decision": _lc.CANCEL_REQUESTED,
                     "reason": "STOP_ALL_PRESENT",
                     "cancellation_epoch": transition.new_epoch,
                     "lifecycle_seq": transition.lifecycle_seq})
        audit.write({
            "decision": _lc.CANCEL_LINEARIZED,
            "cancelled_epoch": transition.cancelled_epoch,
            "new_epoch": transition.new_epoch,
            "lifecycle_seq": transition.lifecycle_seq,
            "inflight_at_linearization": transition.inflight_at_linearization,
        })

    stop_listener = server.shutdown if server is not None else None
    torn, snapshot = registry.terminate_all(
        on_linearized=record_linearization, stop_listener=stop_listener,
        drain_timeout=timeout)
    result = registry.last_cancellation or {}
    transition = result.get("transition")
    listener_stopped = listener_closed.wait(max(0.0, timeout))
    registry.wait_for_producer_drain(timeout)
    effect_remaining = registry.run.inflight_count()
    producer_remaining = registry.producer_count()
    remaining = effect_remaining + producer_remaining
    evidence_durable = bool(result.get("linearization_evidence_durable"))
    stop_started = bool(result.get("listener_stop_started"))
    blockers = []
    if effect_remaining:
        blockers.append("EFFECT_PERMITS_REMAIN")
    if producer_remaining:
        blockers.append("AUDIT_PRODUCERS_REMAIN")
    if not listener_stopped or not stop_started:
        blockers.append("LISTENER_NOT_STOPPED")
    quiescent = not blockers
    common = {
        "cancellation_epoch": registry.run.epoch(),
        "lifecycle_seq": getattr(transition, "lifecycle_seq", None),
        "local_drain_complete": quiescent,
        "inflight_remaining": remaining,
        "effect_permits_remaining": effect_remaining,
        "audit_producers_remaining": producer_remaining,
        "listener_state": "STOPPED" if listener_stopped and stop_started else "NOT_STOPPED",
        "external_enforcement": "NOT_RUN_PHASE1",
    }
    outcome = {**common, "evidence_durable": evidence_durable,
               "closure_blockers": blockers, "sealed": False}
    try:
        if not evidence_durable:
            raise RuntimeError("CANCELLATION_EVIDENCE_NOT_DURABLE")
        if hasattr(audit, "healthy") and not audit.healthy():
            raise RuntimeError("AUDIT_SINK_UNHEALTHY_BEFORE_KILL_EVIDENCE")
        audit.write({
            "decision": "KILL_SWITCH",
            "reason": "STOP_ALL_TORE_DOWN_LIVE_CONNECTIONS",
            "connections_terminated": len(torn),
            "terminated_conn_ids": torn,
            "registered_at_kill": snapshot,
            **common,
        })
        if not quiescent:
            audit.write({
                "decision": _lc.CANCEL_DRAIN_TIMEOUT,
                "ack_scope": "NO_ACK_DRAIN_INCOMPLETE",
                "closure_blockers": blockers,
                **common,
            })
            return outcome
        audit.write({
            "decision": _lc.CANCEL_ACK,
            "ack_scope": "LOCAL_IN_PROCESS_DRAIN_ONLY",
            **common,
        })
        audit.seal_with({
            "decision": _lc.RUN_CLOSED,
            "closure_schema": "E10-run-close-v1",
            "closure_sequence": transition.lifecycle_seq,
            "closure_state": "CLOSED",
            "admission_state": "TERMINAL",
            "inflight_remaining": 0,
            "effect_permits_remaining": 0,
            "audit_producers_remaining": 0,
            "listener_state": "STOPPED",
            "seal_action": "FINAL_FSYNC_THEN_ATOMIC_SEAL",
            "cancellation_disposition": _lc.CANCEL_ACK,
        })
        outcome["sealed"] = True
        return outcome
    except Exception as exc:
        outcome["audit_failure"] = type(exc).__name__
        return outcome


def kill_watcher(kill_file: str, registry: Registry, audit: AuditLog, *,
                 server=None, listener_closed: threading.Event | None = None) -> None:
    while not os.path.exists(kill_file):
        time.sleep(0.25)
    cancel_and_quiesce(registry, audit, server=server,
                       listener_closed=listener_closed,
                       timeout=CANCEL_DRAIN_TIMEOUT)


class ManagedThreadingHTTPServer(ThreadingHTTPServer):
    """Threaded listener whose handler lifetimes are tracked by Registry."""

    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.serving_ready = threading.Event()
        super().__init__(*args, **kwargs)

    def service_actions(self) -> None:
        # Set only from inside serve_forever's loop; shutdown() is then safe.
        self.serving_ready.set()


class DualStackHTTPServer(ManagedThreadingHTTPServer):
    """Listener that accepts BOTH address families on one socket.

    The previous listener was ThreadingHTTPServer(("0.0.0.0", port), ...).
    ThreadingHTTPServer inherits address_family = AF_INET, so the PEP was
    IPv4-ONLY and every IPv6 client received ECONNREFUSED. On an IPv4-only host
    this was undetectable — the IPv4 suite passed 17/17 while the entire IPv6
    enforcement path did not exist. It only surfaced on a real dual-stack host,
    as via-PEP=NOGW.

    IPV6_V6ONLY is set EXPLICITLY rather than relying on the platform default,
    which differs between kernels and distributions. IPv4 peers then arrive as
    ::ffff:a.b.c.d, which PDP._program_for_source canonicalizes (and only that
    form — see the comment there for why the other embeddings must not be).
    """

    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def serve(*, pdp: PDP, ca: InterceptionCA, audit: AuditLog, kill_file: str,
          host: str | None = None, port: int = 3128) -> None:
    registry = Registry()
    Gateway.pdp, Gateway.ca, Gateway.audit, Gateway.registry = pdp, ca, audit, registry

    # F03: the audit chain must be intact and its parent directory durable BEFORE
    # any request can earn a permit. A torn chain or a directory that cannot be
    # synced (e.g. vboxsf) latches the sink unhealthy; serving would then refuse
    # every effect, so fail loudly here instead.
    if hasattr(audit, "startup_verify"):
        ok, detail = audit.startup_verify()
        if not ok:
            audit.write({"decision": "STARTUP_FAILED",
                         "reason": "AUDIT_SINK_UNHEALTHY", "detail": detail}) \
                if audit.healthy() else None
            print(f"[pep] REFUSING TO SERVE: audit sink unhealthy: {detail}", flush=True)
            raise RuntimeError(f"AUDIT_SINK_UNHEALTHY: {detail}")

    # Dual-stack is the intended configuration. A host with no IPv6 must still
    # be able to run the IPv4 suite, so there is a fallback — but it is LOUD and
    # AUDITED, never silent. A silent fallback is exactly how a listener ends up
    # not supporting IPv6 while every dashboard says it does.
    families = "dual-stack(::, v6only=0)"
    try:
        srv = DualStackHTTPServer((host or "::", port), Gateway)
    except OSError as exc:
        families = f"IPv4-ONLY(fallback: {type(exc).__name__}: {exc})"
        srv = ManagedThreadingHTTPServer((host or "0.0.0.0", port), Gateway)
        audit.write({"decision": "STARTUP_DEGRADED",
                     "reason": "IPV6_LISTENER_UNAVAILABLE",
                     "detail": f"{type(exc).__name__}: {exc}", "port": port})
        print(f"[pep] WARNING: IPv6 listener unavailable ({exc}). "
              f"Listening IPv4-ONLY. Layer B CANNOT pass in this state.",
              flush=True)

    bound = srv.socket.getsockname()[:2]
    audit.write({"decision": "STARTUP", "reason": "PEP_READY",
                 "max_connections": MAX_CONNECTIONS, "port": port,
                 "listener": families,
                 "listen_family": str(srv.socket.family),
                 "listen_addr": f"{bound[0]}:{bound[1]}"})
    print(f"[pep] listening {bound[0]}:{bound[1]} [{families}] "
          f"max_conn={MAX_CONNECTIONS} ca={ca.ca_cert_path}", flush=True)

    listener_closed = threading.Event()
    # A pre-existing STOP_ALL must never race a later STARTUP append. The
    # listener has been initialized and STARTUP fsynced, but it is closed before
    # accepting any handler; cancellation then writes and seals the final range.
    if os.path.exists(kill_file):
        srv.server_close()
        listener_closed.set()
        cancel_and_quiesce(registry, audit, listener_closed=listener_closed,
                           timeout=CANCEL_DRAIN_TIMEOUT)
        return

    serving = threading.Thread(target=srv.serve_forever,
                               kwargs={"poll_interval": 0.05})
    serving.start()
    if not srv.serving_ready.wait(2.0):
        srv.shutdown()
        serving.join()
        srv.server_close()
        raise RuntimeError("LISTENER_DID_NOT_ENTER_SERVE_LOOP")
    watcher = threading.Thread(
        target=kill_watcher, args=(kill_file, registry, audit),
        kwargs={"server": srv, "listener_closed": listener_closed},
        daemon=True)
    watcher.start()
    serving.join()
    srv.server_close()
    listener_closed.set()
    if registry.is_killed():
        watcher.join()

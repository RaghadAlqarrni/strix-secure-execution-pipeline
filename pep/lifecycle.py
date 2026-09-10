"""
F02/F03 authorization and cancellation lifecycle (Phase 1).

Authorization, permit, release, and cancellation linearization points share
RunContext's condition and one positive sequence authority.  A permit admitted
first is counted in-flight until release removes it under that lock.  The
release record is then made durable before its handler stops being an audit
producer.  Cancellation admitted first invalidates all future permits.

AUTH_COMMITTED is fsynced before a permit is issued.  PERMIT_GRANTED and
EFFECT_ATTEMPTED are also durable before the target-side connect/send begins.
Timeout or crash after an attempt is never treated as proof that the target did
nothing.  No credential-bearing wire request is hashed: request_intent_digest
covers only the sanitized method, authority, path and body length.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import socket as _socket
import threading
import time
import uuid


class LifecycleError(Exception):
    """Base for lifecycle refusals."""


class Cancelled(LifecycleError):
    """The run/connection was cancelled at or before this transition."""


class AuditUnhealthy(LifecycleError):
    """The audit sink cannot durably record a required transition."""


@dataclass(frozen=True)
class CancellationTransition:
    cancelled_epoch: int
    new_epoch: int
    lifecycle_seq: int
    inflight_at_linearization: int
    monotonic_time: float
    newly_cancelled: bool


@dataclass(frozen=True)
class ReleaseTransition:
    attempt_id: str
    epoch: int
    permit_seq: int
    lifecycle_seq: int


class EffectPermit:
    """One admitted target effect, counted until release()."""

    def __init__(self, run: "RunContext", attempt_id: str, epoch: int,
                 lifecycle_seq: int, policy_generation: str,
                 budget_binding: str) -> None:
        self.attempt_id = attempt_id
        self.epoch = epoch
        self.lifecycle_seq = lifecycle_seq
        self.policy_generation = policy_generation
        self.budget_binding = budget_binding
        self._run = run
        self._lock = threading.Lock()
        self._released = False
        self._release_transition: ReleaseTransition | None = None
        self._release_error: AuditUnhealthy | None = None
        self._audit = None
        self._conn_id = ""

    def bind_durable_release(self, audit, conn_id: str) -> None:
        """Enable the one durable release record after PERMIT_GRANTED fsync."""
        with self._lock:
            if self._released or self._audit is not None:
                raise LifecycleError("permit release binding is not mutable")
            self._audit = audit
            self._conn_id = conn_id

    def release(self) -> ReleaseTransition | None:
        with self._lock:
            if self._released:
                if self._release_error is not None:
                    raise self._release_error
                return self._release_transition
            self._released = True
            transition = self._run._release(self.attempt_id)
            self._release_transition = transition
            if transition is None or self._audit is None:
                return transition
            try:
                self._audit.write({
                    "decision": PERMIT_RELEASED,
                    "attempt_id": self.attempt_id,
                    "conn_id": self._conn_id,
                    "epoch": self.epoch,
                    "permit_seq": self.lifecycle_seq,
                    "lifecycle_seq": transition.lifecycle_seq,
                })
            except Exception as exc:
                # Memory is already released for safety. AuditLog latches its
                # health; the exception keeps the producer alive through the
                # failed durable append and prevents normal closure.
                error = AuditUnhealthy(
                    f"release record failed: {type(exc).__name__}")
                self._release_error = error
                raise error from exc
            return transition

    def abandon_undurable(self) -> None:
        """Safety release when PERMIT_GRANTED itself did not become durable."""
        with self._lock:
            if self._released:
                return
            self._released = True
            self._release_transition = self._run._release(self.attempt_id)

    def __enter__(self) -> "EffectPermit":
        return self

    def __exit__(self, _typ, _value, _traceback) -> None:
        self.release()


class RunContext:
    """Atomic permit/cancel authority and in-flight drain tracker.

    issue_permit() and cancel() take the same condition lock.  Their order is
    therefore total: a permit either increments _inflight before cancellation,
    or it is refused after cancellation.  wait_for_drain() acknowledges only a
    local count of zero; it makes no packet-recall or host-firewall claim.
    """

    def __init__(self, run_id: str = "") -> None:
        self.run_id = run_id
        self._cv = threading.Condition(threading.Lock())
        self._epoch = 0
        self._cancelled = False
        self._sequence = 0
        self._inflight: dict[str, EffectPermit] = {}
        self._authorizations: dict[str, tuple[int, int]] = {}
        self._permitted_attempts: set[str] = set()
        self._cancellation: CancellationTransition | None = None

    def epoch(self) -> int:
        with self._cv:
            return self._epoch

    def live(self, epoch: int) -> bool:
        with self._cv:
            return (not self._cancelled) and epoch == self._epoch

    def authorize(self, attempt_id: str, epoch: int) -> int | None:
        """Allocate AUTH's global sequence before its durable append."""
        with self._cv:
            if (self._cancelled or epoch != self._epoch or
                    attempt_id in self._authorizations):
                return None
            self._sequence += 1
            self._authorizations[attempt_id] = (epoch, self._sequence)
            return self._sequence

    def issue_permit(self, attempt_id: str, epoch: int,
                     conn: "ConnectionLifecycle", *,
                     policy_generation: str,
                     budget_binding: str) -> EffectPermit | None:
        with self._cv:
            if self._cancelled or epoch != self._epoch:
                return None
            # Lock ordering is RunContext -> ConnectionLifecycle. terminate()
            # never calls back into RunContext while holding the connection lock.
            if conn.is_terminal():
                return None
            authorization = self._authorizations.get(attempt_id)
            if (authorization is None or authorization[0] != epoch or
                    attempt_id in self._permitted_attempts):
                return None
            self._sequence += 1
            permit = EffectPermit(self, attempt_id, epoch, self._sequence,
                                  policy_generation, budget_binding)
            self._permitted_attempts.add(attempt_id)
            self._inflight[attempt_id] = permit
            return permit

    def _release(self, attempt_id: str) -> ReleaseTransition | None:
        with self._cv:
            permit = self._inflight.pop(attempt_id, None)
            if permit is None:
                return None
            self._sequence += 1
            transition = ReleaseTransition(
                attempt_id=attempt_id, epoch=permit.epoch,
                permit_seq=permit.lifecycle_seq,
                lifecycle_seq=self._sequence)
            if not self._inflight:
                self._cv.notify_all()
            return transition

    def cancel(self) -> CancellationTransition:
        with self._cv:
            if self._cancellation is not None:
                prior = self._cancellation
                return CancellationTransition(
                    prior.cancelled_epoch, prior.new_epoch, prior.lifecycle_seq,
                    prior.inflight_at_linearization,
                    prior.monotonic_time, False)
            cancelled_epoch = self._epoch
            self._cancelled = True
            self._epoch += 1
            self._sequence += 1
            transition = CancellationTransition(
                cancelled_epoch=cancelled_epoch,
                new_epoch=self._epoch,
                lifecycle_seq=self._sequence,
                inflight_at_linearization=len(self._inflight),
                monotonic_time=time.monotonic(),
                newly_cancelled=True,
            )
            self._cancellation = transition
            if not self._inflight:
                self._cv.notify_all()
            return transition

    def wait_for_drain(self, timeout: float | None) -> bool:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        with self._cv:
            while self._inflight:
                if deadline is None:
                    self._cv.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cv.wait(remaining)
            return True

    def inflight_count(self) -> int:
        with self._cv:
            return len(self._inflight)

    def cancellation(self) -> CancellationTransition | None:
        with self._cv:
            return self._cancellation


# -------------------------------------------------------------- per-connection
def _shutdown_close(sock) -> bool:
    torn = False
    try:
        sock.shutdown(_socket.SHUT_RDWR)
        torn = True
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass
    return torn


class ConnectionLifecycle:
    """Per-connection terminal state and atomic socket ownership."""

    def __init__(self, conn_id: str) -> None:
        self.conn_id = conn_id
        self._lock = threading.Lock()
        self._terminal = False
        self._sockets: list = []

    def is_terminal(self) -> bool:
        with self._lock:
            return self._terminal

    def track_or_reject(self, sock) -> bool:
        with self._lock:
            if not self._terminal:
                self._sockets.append(sock)
                return True
        _shutdown_close(sock)
        return False

    def transfer(self, old, new) -> bool:
        """Take ownership of a wrapper while retaining the underlying handle.

        The old handle remains registered.  If cancellation won before this
        transfer, new is closed here; if transfer won, terminate() sees new.
        """
        with self._lock:
            if not self._terminal:
                if old not in self._sockets:
                    self._sockets.append(old)
                self._sockets.append(new)
                return True
        _shutdown_close(new)
        return False

    def begin_termination(self) -> list:
        """Make this connection terminal and return its retained handles.

        This step performs no socket I/O, so a caller can mark every victim
        terminal before one slow shutdown blocks progress.
        """
        with self._lock:
            self._terminal = True
            return list(self._sockets)

    @staticmethod
    def shutdown_retained(socks: list) -> bool:
        torn_any = False
        for sock in socks:
            if _shutdown_close(sock):
                torn_any = True
        return torn_any

    def terminate(self) -> bool:
        return self.shutdown_retained(self.begin_termination())


# ------------------------------------------------------------- sanitized intent
def request_intent_digest(method: str, authority: str, path: str,
                          body_len: int = 0) -> str:
    """Commit to non-credential request fields only.

    This deliberately replaces the old digest of raw_req, which included the
    injected Authorization header.  It is a versioned sanitized-intent digest,
    not a digest of the credential-bearing wire request.
    """
    canon = f"v2\n{method.upper()}\n{authority}\n{path}\nbody_len={body_len}"
    return "sha256:" + hashlib.sha256(canon.encode()).hexdigest()


def sanitized_intent(*, run_id: str, conn_id: str, attempt_id: str, epoch: int,
                     program_id: str, policy_generation: str, method: str,
                     canonical_host: str, path: str, pin, credential_ref: str,
                     budget_binding: str, body_len: int = 0) -> dict:
    return {
        "decision": AUTH,
        "lifecycle_version": "E10-v2",
        "run_id": run_id,
        "attempt_id": attempt_id,
        "conn_id": conn_id,
        "epoch": epoch,
        "program_id": program_id,
        "policy_generation": policy_generation,
        "budget_binding": budget_binding,
        "method": method.upper(),
        "canonical_host": canonical_host,
        "pin_family": getattr(pin, "family", None),
        "pin_ip": getattr(pin, "ip", None),
        "pin_port": getattr(pin, "port", None),
        "credential_ref": credential_ref or "none",
        "request_intent_digest": request_intent_digest(
            method, canonical_host, path, body_len),
    }


class EffectGate:
    """Durable intent, binding recheck, atomic permit, and durable attempt."""

    def __init__(self, audit, run: RunContext) -> None:
        self._audit = audit
        self._run = run
        self._intents: dict[str, dict] = {}

    def commit_intent(self, intent: dict) -> str:
        if hasattr(self._audit, "healthy") and not self._audit.healthy():
            raise AuditUnhealthy("audit sink latched unhealthy before intent")
        sequence = self._run.authorize(intent["attempt_id"], intent["epoch"])
        if sequence is None:
            raise Cancelled("authorization refused by terminal epoch")
        intent["lifecycle_seq"] = sequence
        try:
            self._audit.write(dict(intent))
        except Exception as exc:
            raise AuditUnhealthy(
                f"intent commit failed: {type(exc).__name__}") from exc
        self._intents[intent["attempt_id"]] = dict(intent)
        return intent["attempt_id"]

    def acquire_permit(self, attempt_id: str, epoch: int,
                       conn: ConnectionLifecycle, *,
                       policy_generation: str,
                       budget_binding: str) -> EffectPermit | None:
        intent = self._intents.get(attempt_id)
        if intent is None:
            return None
        if (not policy_generation or not budget_binding or
                intent.get("policy_generation") != policy_generation or
                intent.get("budget_binding") != budget_binding or
                intent.get("epoch") != epoch or
                intent.get("conn_id") != conn.conn_id):
            return None
        permit = self._run.issue_permit(
            attempt_id, epoch, conn,
            policy_generation=policy_generation,
            budget_binding=budget_binding)
        if permit is None:
            return None
        try:
            self._audit.write({
                "decision": PERMIT,
                "attempt_id": attempt_id,
                "conn_id": conn.conn_id,
                "epoch": epoch,
                "lifecycle_seq": permit.lifecycle_seq,
                "policy_generation": policy_generation,
                "budget_binding": budget_binding,
            })
        except Exception as exc:
            permit.abandon_undurable()
            raise AuditUnhealthy(
                f"permit record failed: {type(exc).__name__}") from exc
        permit.bind_durable_release(self._audit, conn.conn_id)
        return permit

    def mark_attempted(self, permit: EffectPermit, conn_id: str,
                       extra: dict | None = None) -> None:
        rec = {
            "decision": ATTEMPTED,
            "attempt_id": permit.attempt_id,
            "conn_id": conn_id,
            "epoch": permit.epoch,
            "permit_seq": permit.lifecycle_seq,
        }
        if extra:
            rec.update(extra)
        try:
            self._audit.write(rec)
        except Exception as exc:
            raise AuditUnhealthy(
                f"attempt record failed: {type(exc).__name__}") from exc

    def settle(self, attempt, conn_id: str, outcome: str,
               extra: dict | None = None) -> None:
        permit = attempt if isinstance(attempt, EffectPermit) else None
        attempt_id = permit.attempt_id if permit else str(attempt)
        rec = {"decision": outcome, "attempt_id": attempt_id,
               "conn_id": conn_id}
        if permit:
            rec["permit_seq"] = permit.lifecycle_seq
            rec["epoch"] = permit.epoch
        else:
            intent = self._intents.get(attempt_id)
            if intent is not None:
                rec["epoch"] = intent.get("epoch")
        if extra:
            rec.update(extra)
        try:
            self._audit.write(rec)
        except Exception:
            # Settlement failure cannot undo an effect. AuditLog's health latch
            # blocks every later permit; the caller still releases in-flight.
            pass


def new_attempt_id() -> str:
    return "att-" + uuid.uuid4().hex


AUTH = "AUTH_COMMITTED"
PERMIT = "PERMIT_GRANTED"
PERMIT_RELEASED = "PERMIT_RELEASED"
ATTEMPTED = "EFFECT_ATTEMPTED"
COMPLETED = "EFFECT_COMPLETED"
FAILED = "EFFECT_FAILED"
UNKNOWN = "EFFECT_OUTCOME_UNKNOWN"
CANCELLED = "EFFECT_CANCELLED"
CANCEL_REQUESTED = "CANCELLATION_REQUESTED"
CANCEL_LINEARIZED = "CANCELLATION_LINEARIZED"
CANCEL_ACK = "CANCELLATION_ACK"
CANCEL_DRAIN_TIMEOUT = "CANCELLATION_DRAIN_TIMEOUT"
RUN_CLOSED = "RUN_CLOSED"
EFFECT_DECISIONS = (ATTEMPTED, COMPLETED, FAILED, UNKNOWN, CANCELLED)

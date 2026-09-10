#!/usr/bin/env python3
"""Executed local positive, cancellation-race, and audit-fault tests for F02/F03.

Uses the shipping AuditLog, Registry, ConnectionState, RunContext and EffectGate.
All networking is socketpair or test doubles; no external target is contacted.
Exit 0 only when every explicit assertion holds.
"""
from __future__ import annotations

import errno
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(PEP))

from pep.audit import AuditLog                                      # noqa: E402
from pep.gateway import ConnectionState, Registry                  # noqa: E402
from pep import lifecycle as lc                                    # noqa: E402
from pep.lifecycle import EffectGate, AuditUnhealthy, new_attempt_id, sanitized_intent  # noqa: E402


class Cases:
    def __init__(self):
        self.total = 0
        self.failed = 0

    def check(self, name, condition):
        self.total += 1
        ok = bool(condition)
        self.failed += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
        return ok


def pair():
    return socket.socketpair()


def pin():
    class P:
        family = "ipv4"
        ip = "127.0.0.1"
        port = 9

        def as_tuple(self):
            return self.family, self.ip, self.port
    return P()


def intent(conn_id, attempt_id, epoch, *, policy="policy-1", budget="budget-1"):
    return sanitized_intent(
        run_id="run-test", conn_id=conn_id, attempt_id=attempt_id,
        epoch=epoch, program_id="prog_a", policy_generation=policy,
        method="POST", canonical_host="allowed.lab", path="/x", pin=pin(),
        credential_ref="cred-ref-1", budget_binding=budget, body_len=3)


def records(path):
    return [json.loads(line) for line in open(path) if line.strip()]


def authorized(tmp, name="flow"):
    audit = AuditLog(os.path.join(tmp, name + ".jsonl"), run_id="run-test")
    reg = Registry()
    state = ConnectionState(client_ip="10.0.0.5")
    assert reg.add(state)
    gate = EffectGate(audit, reg.run)
    epoch = reg.run.epoch()
    aid = new_attempt_id()
    auth = intent(state.conn_id, aid, epoch)
    gate.commit_intent(auth)
    permit = gate.acquire_permit(
        aid, epoch, state.lifecycle,
        policy_generation="policy-1", budget_binding="budget-1")
    assert permit is not None
    return audit, reg, state, gate, aid, permit


def run() -> int:
    c = Cases()
    tmp = tempfile.mkdtemp(prefix="phase1_repaired_")
    try:
        # Cancellation before socket creation is terminal and cannot rearm.
        reg = Registry()
        state = ConnectionState(client_ip="10.0.0.1")
        c.check("F02 precondition: state admitted", reg.add(state))
        reg.terminate_all()
        local, peer = pair()
        accepted = state.track(local)
        try:
            local.sendall(b"x")
            usable = True
        except OSError:
            usable = False
        c.check("F02 cancel-before-create: late socket refused", accepted is False)
        c.check("F02 cancel-before-create: late socket closed", usable is False)
        peer.close()
        local.close()
        reg.rearm()
        c.check("F02 cancellation remains terminal after rearm()", reg.is_killed())
        c.check("F02 post-cancel connection admission refused",
                reg.add(ConnectionState(client_ip="10.0.0.2")) is False)

        # Register-before-connect and both TLS ownership-transfer outcomes.
        reg2 = Registry()
        state2 = ConnectionState(client_ip="10.0.0.2")
        reg2.add(state2)
        live, live_peer = pair()
        c.check("F02 register-before-connect owns handle", state2.track(live))
        reg2.terminate_all()
        try:
            live.sendall(b"effect")
            alive = True
        except OSError:
            alive = False
        c.check("F02 cancel during connect closes registered handle", not alive)
        live_peer.close()
        live.close()

        reg3 = Registry()
        state3 = ConnectionState(client_ip="10.0.0.3")
        reg3.add(state3)
        old, old_peer = pair()
        wrapped, wrapped_peer = pair()
        state3.track(old)
        c.check("F02 live TLS ownership transfer accepted",
                state3.transfer(old, wrapped))
        reg3.terminate_all()
        try:
            wrapped.sendall(b"x")
            wrapped_alive = True
        except OSError:
            wrapped_alive = False
        c.check("F02 cancellation closes transferred TLS handle", not wrapped_alive)
        for item in (old, old_peer, wrapped, wrapped_peer):
            item.close()

        rejected, rejected_peer = pair()
        c.check("F02 transfer after terminal is rejected",
                state3.transfer(old, rejected) is False)
        try:
            rejected.sendall(b"x")
            rejected_alive = True
        except OSError:
            rejected_alive = False
        c.check("F02 rejected late TLS handle is closed", not rejected_alive)
        rejected.close()
        rejected_peer.close()

        # A pre-cancel permit is in-flight; later permits lose atomically.
        _audit4, reg4, state4, gate4, aid4, permit4 = authorized(tmp, "drain")
        _, snap4 = reg4.terminate_all(drain_timeout=0.01)
        cancel4 = reg4.last_cancellation
        c.check("F02 cancellation snapshot includes permitted connection",
                state4.conn_id in snap4)
        c.check("F02 in-flight count captured at linearization",
                cancel4["transition"].inflight_at_linearization == 1)
        c.check("F02 no premature local-drain acknowledgement",
                cancel4["local_drain_complete"] is False and
                cancel4["inflight_remaining"] == 1)
        late_state = ConnectionState(client_ip="10.0.0.4")
        late_aid = new_attempt_id()
        try:
            gate4.commit_intent(intent(late_state.conn_id, late_aid, 0))
            late_authorized = True
        except lc.Cancelled:
            late_authorized = False
        c.check("F02 no authorization after cancellation linearization",
                late_authorized is False)
        permit4.release()
        permit4.release()
        c.check("F02 local drain completes only after permit release",
                reg4.run.wait_for_drain(0.1))
        c.check("F02 durable permit release is exactly once",
                [record["decision"] for record in records(_audit4.path)].count(
                    lc.PERMIT_RELEASED) == 1)
        c.check("F02 released attempt cannot acquire a second permit",
                gate4.acquire_permit(
                    aid4, 0, state4.lifecycle,
                    policy_generation="policy-1",
                    budget_binding="budget-1") is None)

        # AUTH owns its sequence before fsync. If cancellation linearizes while
        # that fsync is delayed, the late durable AUTH remains provably A < C,
        # but it cannot obtain a permit or cause a post-cancel effect.
        late_real = AuditLog(os.path.join(tmp, "auth-append-after-cancel.jsonl"),
                             run_id="run-test")
        late_run = lc.RunContext("run-test")
        late_state = ConnectionState(client_ip="10.0.0.31")
        auth_entered = threading.Event()
        auth_release = threading.Event()

        class DelayedAuthAudit:
            def healthy(self): return late_real.healthy()
            def write(self, entry):
                if entry.get("decision") == lc.AUTH:
                    auth_entered.set()
                    auth_release.wait(2)
                return late_real.write(entry)

        late_gate = EffectGate(DelayedAuthAudit(), late_run)
        late_aid = new_attempt_id()
        late_intent = intent(late_state.conn_id, late_aid, 0)
        late_committed = {}

        def late_auth_worker():
            late_gate.commit_intent(late_intent)
            late_committed["done"] = True

        late_thread = threading.Thread(target=late_auth_worker)
        late_thread.start()
        c.check("F02 delayed AUTH owns sequence before append",
                auth_entered.wait(1))
        late_cancel = late_run.cancel()
        auth_release.set()
        late_thread.join(2)
        late_permit = late_gate.acquire_permit(
            late_aid, 0, late_state.lifecycle,
            policy_generation="policy-1", budget_binding="budget-1")
        c.check("F02 late durable AUTH proves A below cancellation",
                late_committed.get("done") is True and
                late_intent["lifecycle_seq"] < late_cancel.lifecycle_seq)
        c.check("F02 late durable AUTH cannot gain post-cancel permit",
                late_permit is None)

        # Race permit and cancellation repeatedly. Every winning permit must have
        # a smaller lifecycle sequence than cancellation; no later sequence wins.
        race_ok = True
        for index in range(100):
            race_audit = AuditLog(os.path.join(tmp, f"race-{index}.jsonl"),
                                  run_id="run-test")
            race_run = lc.RunContext("run-test")
            race_gate = EffectGate(race_audit, race_run)
            race_state = ConnectionState(client_ip="10.0.0.9")
            race_aid = new_attempt_id()
            race_gate.commit_intent(intent(race_state.conn_id, race_aid, 0))
            barrier = threading.Barrier(2)
            outcome = {}

            def issue():
                barrier.wait()
                outcome["permit"] = race_gate.acquire_permit(
                    race_aid, 0, race_state.lifecycle,
                    policy_generation="policy-1", budget_binding="budget-1")

            def cancel():
                barrier.wait()
                outcome["cancel"] = race_run.cancel()

            one = threading.Thread(target=issue)
            two = threading.Thread(target=cancel)
            one.start(); two.start()
            one.join(2); two.join(2)
            permit = outcome.get("permit")
            transition = outcome.get("cancel")
            if one.is_alive() or two.is_alive() or transition is None:
                race_ok = False
                break
            if permit is not None:
                race_ok = race_ok and permit.lifecycle_seq < transition.lifecycle_seq
                permit.release()
            race_ok = race_ok and race_run.wait_for_drain(0.1)
        c.check("F02 100 concurrent permit/cancel schedules linearize", race_ok)

        # Deterministically force both durable append orders around the shared
        # permit/cancel linearization. AUTH owns sequence 1 and a permit can own
        # sequence 2 while its audit append is blocked; cancellation sequence 3
        # may then append first.
        delayed_real = AuditLog(os.path.join(tmp, "permit-append-after-cancel.jsonl"),
                                run_id="run-test")
        delayed_reg = Registry()
        delayed_state = ConnectionState(client_ip="10.0.0.21")
        delayed_reg.add(delayed_state)
        permit_write_entered = threading.Event()
        permit_write_release = threading.Event()

        class DelayedPermitAudit:
            def healthy(self): return delayed_real.healthy()
            def write(self, entry):
                if entry.get("decision") == lc.PERMIT:
                    permit_write_entered.set()
                    permit_write_release.wait(2)
                return delayed_real.write(entry)

        delayed_gate = EffectGate(DelayedPermitAudit(), delayed_reg.run)
        delayed_aid = new_attempt_id()
        delayed_gate.commit_intent(intent(delayed_state.conn_id, delayed_aid, 0))
        delayed_outcome = {}

        def delayed_permit_worker():
            delayed_outcome["permit"] = delayed_gate.acquire_permit(
                delayed_aid, 0, delayed_state.lifecycle,
                policy_generation="policy-1", budget_binding="budget-1")

        def record_cancel(audit, transition):
            audit.write({"decision": lc.CANCEL_REQUESTED, "reason": "BARRIER",
                         "cancellation_epoch": transition.new_epoch,
                         "lifecycle_seq": transition.lifecycle_seq})
            audit.write({"decision": lc.CANCEL_LINEARIZED,
                         "cancelled_epoch": transition.cancelled_epoch,
                         "new_epoch": transition.new_epoch,
                         "lifecycle_seq": transition.lifecycle_seq,
                         "inflight_at_linearization":
                             transition.inflight_at_linearization})

        permit_thread = threading.Thread(target=delayed_permit_worker)
        permit_thread.start()
        c.check("F02 delayed permit owns sequence before its audit append",
                permit_write_entered.wait(1))
        cancel_thread = threading.Thread(target=lambda: delayed_reg.terminate_all(
            on_linearized=lambda transition: record_cancel(delayed_real, transition),
            drain_timeout=1.0))
        cancel_thread.start()
        deadline = time.monotonic() + 1
        while (lc.CANCEL_LINEARIZED not in [r["decision"] for r in records(delayed_real.path)]
               and time.monotonic() < deadline):
            time.sleep(0.001)
        permit_write_release.set()
        permit_thread.join(2)
        delayed_permit = delayed_outcome.get("permit")
        if delayed_permit is not None:
            delayed_gate.settle(delayed_permit, delayed_state.conn_id, lc.CANCELLED,
                                {"reason": "TERMINAL_BEFORE_ATTEMPT"})
            delayed_permit.release()
        cancel_thread.join(2)
        delayed_decisions = [r["decision"] for r in records(delayed_real.path)]
        c.check("F02 cancellation audit can append before lower permit audit",
                delayed_decisions.index(lc.CANCEL_LINEARIZED) <
                delayed_decisions.index(lc.PERMIT) and
                delayed_permit is not None and
                delayed_permit.lifecycle_seq <
                delayed_reg.last_cancellation["transition"].lifecycle_seq)

        first_real = AuditLog(os.path.join(tmp, "permit-append-before-cancel.jsonl"),
                              run_id="run-test")
        first_reg = Registry()
        first_state = ConnectionState(client_ip="10.0.0.22")
        first_reg.add(first_state)
        first_gate = EffectGate(first_real, first_reg.run)
        first_aid = new_attempt_id()
        first_gate.commit_intent(intent(first_state.conn_id, first_aid, 0))
        first_permit = first_gate.acquire_permit(
            first_aid, 0, first_state.lifecycle,
            policy_generation="policy-1", budget_binding="budget-1")
        assert first_permit is not None
        first_cancel = threading.Thread(target=lambda: first_reg.terminate_all(
            on_linearized=lambda transition: record_cancel(first_real, transition),
            drain_timeout=1.0))
        first_cancel.start()
        deadline = time.monotonic() + 1
        while (lc.CANCEL_LINEARIZED not in [r["decision"] for r in records(first_real.path)]
               and time.monotonic() < deadline):
            time.sleep(0.001)
        first_gate.settle(first_permit, first_state.conn_id, lc.CANCELLED,
                          {"reason": "TERMINAL_BEFORE_ATTEMPT"})
        first_permit.release()
        first_cancel.join(2)
        first_decisions = [r["decision"] for r in records(first_real.path)]
        c.check("F02 permit audit can append before cancellation audit",
                first_decisions.index(lc.PERMIT) <
                first_decisions.index(lc.CANCEL_LINEARIZED) and
                first_permit.lifecycle_seq <
                first_reg.last_cancellation["transition"].lifecycle_seq)

        # Blocking shutdown occurs outside Registry's lock.
        entered = threading.Event()
        release_shutdown = threading.Event()

        class SlowSocket:
            def shutdown(self, _how):
                entered.set()
                release_shutdown.wait(1)
            def close(self):
                pass

        reg_lock = Registry()
        slow_state = ConnectionState(client_ip="10.0.0.8")
        reg_lock.add(slow_state)
        slow_state.track(SlowSocket())
        terminator = threading.Thread(target=reg_lock.terminate_all)
        terminator.start()
        c.check("F02 teardown fault reached blocking shutdown", entered.wait(1))
        started = time.monotonic()
        refused = reg_lock.add(ConnectionState(client_ip="10.0.0.10")) is False
        elapsed = time.monotonic() - started
        c.check("F02 global registry lock not held during blocking I/O",
                refused and elapsed < 0.2)
        release_shutdown.set()
        terminator.join(2)

        # Successful durable flow: intent -> permit -> attempt -> completion.
        audit5, reg5, state5, gate5, aid5, permit5 = authorized(tmp, "success")
        upstream, upstream_peer = pair()
        state5.track(upstream)
        gate5.mark_attempted(permit5, state5.conn_id)
        upstream.sendall(b"GET")
        c.check("F03 authorized local effect executes", upstream_peer.recv(3) == b"GET")
        gate5.settle(permit5, state5.conn_id, lc.COMPLETED,
                     {"upstream_status": 200, "response_hash": "h"})
        permit5.release()
        decisions = [r["decision"] for r in records(audit5.path)]
        c.check("F03 durable transition order",
                decisions.index(lc.AUTH) < decisions.index(lc.PERMIT) <
                decisions.index(lc.ATTEMPTED) < decisions.index(lc.COMPLETED))
        c.check("F03 completed flow drains in-flight", reg5.run.inflight_count() == 0)
        upstream.close(); upstream_peer.close()

        # Binding mismatch is rejected before permit/effect.
        audit_bind = AuditLog(os.path.join(tmp, "binding.jsonl"), run_id="run-test")
        run_bind = lc.RunContext("run-test")
        gate_bind = EffectGate(audit_bind, run_bind)
        state_bind = ConnectionState(client_ip="10.0.0.11")
        aid_bind = new_attempt_id()
        gate_bind.commit_intent(intent(state_bind.conn_id, aid_bind, 0))
        c.check("F03 policy generation mismatch blocks permit",
                gate_bind.acquire_permit(
                    aid_bind, 0, state_bind.lifecycle,
                    policy_generation="policy-2", budget_binding="budget-1") is None)
        c.check("F03 budget binding mismatch blocks permit",
                gate_bind.acquire_permit(
                    aid_bind, 0, state_bind.lifecycle,
                    policy_generation="policy-1", budget_binding="budget-2") is None)

        # Audit failure before target effect.
        class FailingAudit:
            def __init__(self): self.ok = True
            def healthy(self): return self.ok
            def write(self, _entry):
                self.ok = False
                raise OSError(errno.ENOSPC, "injected")

        failed_gate = EffectGate(FailingAudit(), lc.RunContext())
        effect_ran = False
        try:
            failed_gate.commit_intent(intent("c-fail", new_attempt_id(), 0))
            effect_ran = True
        except AuditUnhealthy:
            pass
        c.check("F03 audit failure before connect blocks effect", not effect_ran)

        # Partial writes complete; zero progress and ENOSPC/EIO latch unhealthy.
        partial_path = os.path.join(tmp, "partial.jsonl")
        partial = AuditLog(partial_path, run_id="run-test")
        real_write = os.write
        first = {"value": True}

        def short_write(fd, data):
            if first["value"]:
                first["value"] = False
                return real_write(fd, data[:max(1, len(data) // 2)])
            return real_write(fd, data)

        os.write = short_write
        try:
            partial.write({"decision": "SHORT_WRITE_RECOVERED"})
        finally:
            os.write = real_write
        c.check("F03 short write is completed rather than truncated",
                AuditLog.verify(partial_path)[0] and partial.healthy())

        for label, injected_errno in (("zero-progress", None),
                                      ("ENOSPC", errno.ENOSPC),
                                      ("EIO", errno.EIO)):
            fault = AuditLog(os.path.join(tmp, label + ".jsonl"), run_id="run-test")
            def bad_write(_fd, _data, code=injected_errno):
                if code is None:
                    return 0
                raise OSError(code, label)
            os.write = bad_write
            raised = False
            try:
                fault.write({"decision": "FAULT"})
            except OSError:
                raised = True
            finally:
                os.write = real_write
            c.check(f"F03 {label} write fails and latches sink",
                    raised and not fault.healthy())
            refused = False
            try:
                fault.write({"decision": "LATER"})
            except RuntimeError:
                refused = True
            c.check(f"F03 {label} unhealthy sink refuses later records", refused)

        # Delayed fsync proves commit_intent does not return early.
        delayed = AuditLog(os.path.join(tmp, "delayed.jsonl"), run_id="run-test")
        delayed_gate = EffectGate(delayed, lc.RunContext())
        fsync_entered = threading.Event()
        fsync_release = threading.Event()
        commit_done = threading.Event()
        real_fsync = os.fsync

        def slow_fsync(fd):
            fsync_entered.set()
            fsync_release.wait(2)
            return real_fsync(fd)

        os.fsync = slow_fsync
        def commit_worker():
            try:
                delayed_gate.commit_intent(intent("c-delay", new_attempt_id(), 0))
            finally:
                commit_done.set()
        worker = threading.Thread(target=commit_worker)
        worker.start()
        c.check("F03 delayed fsync reached durable boundary", fsync_entered.wait(1))
        c.check("F03 intent commit waits for fsync", not commit_done.wait(0.05))
        fsync_release.set()
        worker.join(2)
        os.fsync = real_fsync
        c.check("F03 intent commit completes after fsync", commit_done.is_set())

        # Exclusive writer ownership.
        exclusive_path = os.path.join(tmp, "exclusive.jsonl")
        owner = AuditLog(exclusive_path, run_id="run-test", exclusive=True)
        second_refused = False
        try:
            AuditLog(exclusive_path, run_id="run-test", exclusive=True)
        except RuntimeError as exc:
            second_refused = "AUDIT_WRITER_NOT_EXCLUSIVE" in str(exc)
        c.check("F03 second exclusive audit writer refused", second_refused)
        owner.close()

        # Full-chain recovery: corruption/torn tails are preserved and block writes.
        for label, payload in (("corrupt", b'{"not":"a chain"}\n'),
                               ("torn", b'{"partial": tru')):
            damaged_path = os.path.join(tmp, label + "-chain.jsonl")
            healthy = AuditLog(damaged_path, run_id="run-test")
            healthy.write({"decision": "FIRST"})
            before = open(damaged_path, "rb").read() + payload
            with open(damaged_path, "wb") as fh:
                fh.write(before)
            recovered = AuditLog(damaged_path, run_id="run-test")
            startup_ok, _detail = recovered.startup_verify()
            write_refused = False
            try:
                recovered.write({"decision": "MUST_NOT_APPEND"})
            except RuntimeError:
                write_refused = True
            c.check(f"F03 {label} chain latches unhealthy on restart",
                    not startup_ok and not recovered.healthy())
            c.check(f"F03 {label} bytes preserved and append refused",
                    open(damaged_path, "rb").read() == before and write_refused)

        restart_path = os.path.join(tmp, "restart.jsonl")
        original = AuditLog(restart_path, run_id="run-test")
        original.write({"decision": "ONE"})
        restarted = AuditLog(restart_path, run_id="run-test")
        ok_start, _ = restarted.startup_verify()
        restarted.write({"decision": "TWO"})
        c.check("F03 intact restart resumes verified chain",
                ok_start and AuditLog.verify(restart_path)[0] and
                len(records(restart_path)) == 2)

        # Redaction mutation and writes share a lock.
        redact = AuditLog(os.path.join(tmp, "redact.jsonl"), run_id="run-test")
        redaction_errors = []
        def redact_writer():
            try:
                for idx in range(80):
                    redact.add_secret(f"secret-{idx}")
                    redact.write({"decision": "R", "value": f"secret-{idx}"})
            except Exception as exc:
                redaction_errors.append(exc)
        threads = [threading.Thread(target=redact_writer) for _ in range(4)]
        for thread in threads: thread.start()
        for thread in threads: thread.join(5)
        body = open(redact.path).read()
        c.check("F03 concurrent redaction/write has no mutation race",
                not redaction_errors and all(not t.is_alive() for t in threads))
        c.check("F03 concurrently registered secrets are redacted",
                all(f'secret-{idx}' not in body for idx in range(80)))

    finally:
        shutil.rmtree(tmp)

    print(f"\n  F02/F03 REPAIRED: {c.total - c.failed}/{c.total} checks passed")
    return 0 if c.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(run())

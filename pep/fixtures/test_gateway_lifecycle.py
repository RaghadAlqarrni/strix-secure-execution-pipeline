#!/usr/bin/env python3
"""Fault-driven tests of Gateway._inside's real Phase 1 lifecycle path.

Socket/context doubles prohibit external networking and expose deterministic
barriers at connect, TLS ownership transfer, pre-send, and response streaming.
"""
from __future__ import annotations

import json
import os
import shutil
import ssl
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(PEP))

from pep.addressing import Pin                                      # noqa: E402
from pep.audit import AuditLog                                     # noqa: E402
from pep.gateway import (ConnectionState, Gateway, Registry,
                         cancel_and_quiesce)                       # noqa: E402
from pep.pdp import Decision                                       # noqa: E402
from pep import gateway as gateway_module                          # noqa: E402
from pep import lifecycle as lc                                    # noqa: E402
from pep import verify_e10                                         # noqa: E402

POLICY = "policy-generation-7"
BUDGET = "program:prog_a|asset:a1|reservation:connect"
SECRET = "target-secret-must-not-reach-audit"


class Cases:
    def __init__(self): self.total = 0; self.failed = 0
    def check(self, name, condition):
        self.total += 1
        ok = bool(condition)
        self.failed += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")


class FakePDP:
    def decide(self, **_kwargs):
        return Decision(
            True, "ALLOW", pin=Pin("ipv4", "203.0.113.7", 443),
            secret=SECRET, program_id="prog_a",
            detail={"canonical_host": "allowed.lab",
                    "policy_generation": POLICY,
                    "budget_binding": BUDGET})


class FakeSocket:
    def __init__(self, harness):
        self.harness = harness
        self.closed = False
        self.responses = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK", b""]

    def settimeout(self, _value): pass

    def connect(self, _target):
        self.harness.connect_calls += 1
        self.harness.events.append("connect")
        self.harness.decisions_at_connect = self.harness.audit_decisions()
        if self.harness.mode == "cancel-connect":
            self.harness.registry.terminate_all()
        if self.harness.mode == "connect-timeout":
            raise TimeoutError("injected connect timeout")

    def sendall(self, data):
        if self.closed:
            raise OSError("closed before send")
        self.harness.events.append("send")
        self.harness.sent.append(bytes(data))

    def recv(self, _size):
        if self.harness.mode == "cancel-stream" and not self.harness.stream_cancelled:
            self.harness.stream_cancelled = True
            self.harness.registry.terminate_all()
            raise OSError("cancelled during stream")
        if self.closed:
            raise OSError("closed")
        return self.responses.pop(0)

    def shutdown(self, _how):
        if self.closed:
            raise OSError("already closed")
        self.closed = True

    def close(self): self.closed = True


class FakeWrapped(FakeSocket):
    def __init__(self, harness, plain):
        super().__init__(harness)
        self.plain = plain


class FakeContext:
    def __init__(self, harness): self.harness = harness
    def wrap_socket(self, plain, **_kwargs):
        wrapped = FakeWrapped(self.harness, plain)
        self.harness.wrapped = wrapped
        if self.harness.mode == "cancel-tls-transfer":
            self.harness.registry.terminate_all()
        return wrapped


class FakeClientTLS:
    def __init__(self): self.sent = []
    def sendall(self, data): self.sent.append(bytes(data))


class AuditProxy:
    def __init__(self, real, harness, mode):
        self.real = real
        self.harness = harness
        self.mode = mode
        self.ok = True

    @property
    def run_id(self): return self.real.run_id
    def healthy(self): return self.ok and self.real.healthy()
    def add_secret(self, secret): return self.real.add_secret(secret)

    def write(self, entry):
        decision = entry.get("decision")
        if self.mode == "fail-intent" and decision == lc.AUTH:
            self.ok = False
            raise OSError("ENOSPC before intent")
        if self.mode == "fail-attempt" and decision == lc.ATTEMPTED:
            self.ok = False
            raise OSError("EIO before target effect")
        if self.mode == "fail-release" and decision == lc.PERMIT_RELEASED:
            self.ok = False
            raise OSError("EIO during permit release evidence")
        result = self.real.write(entry)
        if self.mode == "cancel-before-send" and decision == lc.ATTEMPTED:
            self.harness.registry.terminate_all()
        return result

    def seal_with(self, entry):
        return self.real.seal_with(entry)


class Harness:
    def __init__(self, root, mode):
        self.mode = mode
        self.path = os.path.join(root, mode + ".jsonl")
        self.real_audit = AuditLog(self.path, run_id="run-gateway")
        self.registry = Registry()
        self.state = ConnectionState(client_ip="10.0.0.8")
        self.state.pin = Pin("ipv4", "203.0.113.7", 443)
        self.state.canonical = "allowed.lab"
        self.state.program_id = "prog_a"
        self.state.policy_generation = POLICY
        self.state.budget_binding = BUDGET
        assert self.registry.add(self.state)
        self.audit = AuditProxy(self.real_audit, self, mode)
        self.events = []
        self.sent = []
        self.connect_calls = 0
        self.decisions_at_connect = []
        self.stream_cancelled = False
        self.wrapped = None
        self.denials = []

    def audit_decisions(self):
        return [json.loads(line)["decision"] for line in open(self.path)
                if line.strip()]

    def run(self):
        handler = object.__new__(Gateway)
        handler.audit = self.audit
        handler.registry = self.registry
        handler.pdp = FakePDP()
        handler._read_head = lambda _tls: (
            "POST", "/x", {"host": "allowed.lab"}, b"abc")
        handler._deny_tls = lambda _tls, reason, *_args: self.denials.append(reason)
        client = FakeClientTLS()
        real_socket = gateway_module.socket.socket
        real_context = gateway_module.ssl.create_default_context
        gateway_module.socket.socket = lambda *_a, **_kw: FakeSocket(self)
        gateway_module.ssl.create_default_context = lambda **_kw: FakeContext(self)
        try:
            handler._inside(self.state, client, 443, "session-1", "a1",
                            "cred-alpha", "allowed.lab")
        finally:
            gateway_module.socket.socket = real_socket
            gateway_module.ssl.create_default_context = real_context
        return client


def main() -> int:
    c = Cases()
    root = tempfile.mkdtemp(prefix="gateway_lifecycle_")
    try:
        success = Harness(root, "success")
        client = success.run()
        prefix = success.decisions_at_connect
        c.check("gateway fsyncs intent, permit, attempt before connect",
                prefix == [lc.AUTH, lc.PERMIT, lc.ATTEMPTED])
        c.check("gateway authorized request reaches socket double",
                success.connect_calls == 1 and len(success.sent) == 1)
        c.check("gateway streams response to client", bool(client.sent))
        final = [json.loads(line) for line in open(success.path) if line.strip()]
        allow = next(record for record in final if record["decision"] == "ALLOW")
        auth = next(record for record in final if record["decision"] == lc.AUTH)
        c.check("gateway request hash uses sanitized-intent-v2",
                allow["request_hash_semantics"] == "sanitized-intent-v2" and
                allow["request_hash"] == auth["request_intent_digest"].split(":", 1)[1])
        c.check("gateway audit contains no injected credential secret",
                SECRET not in open(success.path).read())
        c.check("live gateway EOF is not misreported as a closed E10 run",
                verify_e10.verify(success.path, "run-gateway")["status"] ==
                "RUN_NOT_CLOSED")
        c.check("gateway success releases in-flight permit",
                success.registry.run.inflight_count() == 0)
        c.check("gateway success emits one durable release",
                success.audit_decisions().count(lc.PERMIT_RELEASED) == 1)

        fail_release = Harness(root, "fail-release")
        release_failed = False
        try:
            fail_release.run()
        except lc.AuditUnhealthy:
            release_failed = True
        c.check("release-memory succeeds when release audit fails",
                release_failed and
                fail_release.registry.run.inflight_count() == 0 and
                lc.PERMIT_RELEASED not in fail_release.audit_decisions())
        fail_release_close = cancel_and_quiesce(
            fail_release.registry, fail_release.audit, timeout=0.01)
        c.check("release audit failure forbids ACK and RUN_CLOSED",
                fail_release_close.get("sealed") is False and
                lc.CANCEL_ACK not in fail_release.audit_decisions() and
                lc.RUN_CLOSED not in fail_release.audit_decisions())

        fail_intent = Harness(root, "fail-intent")
        fail_intent.run()
        c.check("gateway audit failure before intent prevents socket creation/connect",
                fail_intent.connect_calls == 0 and not fail_intent.sent)

        fail_attempt = Harness(root, "fail-attempt")
        fail_attempt.run()
        c.check("gateway attempt-record failure prevents connect",
                fail_attempt.connect_calls == 0 and not fail_attempt.sent)
        c.check("gateway failed attempt-record releases in-flight permit",
                fail_attempt.registry.run.inflight_count() == 0)

        cancel_connect = Harness(root, "cancel-connect")
        cancel_connect.run()
        c.check("gateway cancellation during connect leaves no send",
                cancel_connect.connect_calls == 1 and not cancel_connect.sent)
        c.check("gateway connect cancellation settles unknown, not completed",
                lc.UNKNOWN in cancel_connect.audit_decisions() and
                lc.COMPLETED not in cancel_connect.audit_decisions())

        cancel_tls = Harness(root, "cancel-tls-transfer")
        cancel_tls.run()
        c.check("gateway cancellation at TLS transfer rejects late wrapper",
                cancel_tls.wrapped is not None and cancel_tls.wrapped.closed and
                not cancel_tls.sent)

        before_send = Harness(root, "cancel-before-send")
        before_send.run()
        c.check("gateway cancellation after attempted record but before send emits no bytes",
                before_send.connect_calls == 1 and not before_send.sent)
        c.check("gateway pre-send cancellation is outcome-unknown",
                lc.UNKNOWN in before_send.audit_decisions())

        during_stream = Harness(root, "cancel-stream")
        during_stream.run()
        c.check("gateway streaming cancellation occurs after one request send",
                during_stream.stream_cancelled and len(during_stream.sent) == 1)
        c.check("gateway streaming cancellation records unknown outcome",
                lc.UNKNOWN in during_stream.audit_decisions() and
                lc.COMPLETED not in during_stream.audit_decisions())
        c.check("gateway streaming cancellation drains local permit",
                during_stream.registry.run.wait_for_drain(0.1))

        timeout = Harness(root, "connect-timeout")
        timeout.run()
        c.check("gateway connect timeout records unknown outcome",
                lc.UNKNOWN in timeout.audit_decisions() and
                lc.COMPLETED not in timeout.audit_decisions())

        # Drive the actual watcher once by replacing its loop sleep with a
        # bounded stop exception. It may acknowledge only a zero local count.
        class StopWatcher(Exception): pass
        old_sleep = gateway_module.time.sleep
        old_drain = gateway_module.CANCEL_DRAIN_TIMEOUT
        gateway_module.time.sleep = lambda _seconds: (_ for _ in ()).throw(StopWatcher())
        gateway_module.CANCEL_DRAIN_TIMEOUT = 0.01
        try:
            watcher_path = os.path.join(root, "STOP_ACK")
            open(watcher_path, "wb").close()
            watcher_audit = AuditLog(os.path.join(root, "watcher-ack.jsonl"),
                                     run_id="run-watcher")
            watcher_reg = Registry()
            try:
                gateway_module.kill_watcher(watcher_path, watcher_reg, watcher_audit)
            except StopWatcher:
                pass
            watcher_decisions = [json.loads(line) for line in open(watcher_audit.path)]
            c.check("kill watcher distinguishes request, linearization, and ack",
                    [record["decision"] for record in watcher_decisions] ==
                    [lc.CANCEL_REQUESTED, lc.CANCEL_LINEARIZED,
                     "KILL_SWITCH", lc.CANCEL_ACK, lc.RUN_CLOSED])
            ack = watcher_decisions[-2]
            c.check("kill watcher ack truthfully reports zero local in-flight",
                    ack["local_drain_complete"] is True and
                    ack["inflight_remaining"] == 0 and
                    ack["ack_scope"] == "LOCAL_IN_PROCESS_DRAIN_ONLY")
            closure = watcher_decisions[-1]
            c.check("kill watcher closes only after durable ACK",
                    closure["closure_state"] == "CLOSED" and
                    closure["cancellation_disposition"] == lc.CANCEL_ACK and
                    closure["inflight_remaining"] == 0)

            timeout_path = os.path.join(root, "STOP_TIMEOUT")
            open(timeout_path, "wb").close()
            timeout_audit = AuditLog(os.path.join(root, "watcher-timeout.jsonl"),
                                     run_id="run-watcher")
            timeout_reg = Registry()
            timeout_state = ConnectionState(client_ip="10.0.0.12")
            timeout_reg.add(timeout_state)
            assert timeout_reg.run.authorize("att-held", 0) is not None
            held = timeout_reg.run.issue_permit(
                "att-held", 0, timeout_state.lifecycle,
                policy_generation="policy", budget_binding="budget")
            assert held is not None
            try:
                gateway_module.kill_watcher(timeout_path, timeout_reg, timeout_audit)
            except StopWatcher:
                pass
            timeout_records = [json.loads(line) for line in open(timeout_audit.path)]
            disposition = timeout_records[-1]
            c.check("kill watcher emits timeout instead of false drain ack",
                    disposition["decision"] == lc.CANCEL_DRAIN_TIMEOUT and
                    disposition["local_drain_complete"] is False and
                    disposition["inflight_remaining"] == 1 and
                    disposition["ack_scope"] == "NO_ACK_DRAIN_INCOMPLETE")
            held.release()
        finally:
            gateway_module.time.sleep = old_sleep
            gateway_module.CANCEL_DRAIN_TIMEOUT = old_drain

        # A cancellation evidence fsync may block indefinitely, but by the time
        # it starts every victim and registry admission must already be terminal
        # and retained socket shutdown must already have been initiated.
        blocked_registry = Registry()
        blocked_state = ConnectionState(client_ip="10.0.0.44")
        assert blocked_registry.add(blocked_state)
        shutdown_seen = threading.Event()
        audit_entered = threading.Event()
        audit_release = threading.Event()

        class ShutdownProbe:
            def shutdown(self, _how): shutdown_seen.set()
            def close(self): pass

        blocked_state.track(ShutdownProbe())

        def blocked_audit(_transition):
            audit_entered.set()
            audit_release.wait(2)

        worker = threading.Thread(target=lambda: blocked_registry.terminate_all(
            on_linearized=blocked_audit, drain_timeout=0.1))
        worker.start()
        c.check("blocked cancellation audit begins only after socket shutdown",
                audit_entered.wait(1) and shutdown_seen.is_set())
        c.check("blocked cancellation audit cannot delay terminal marking",
                blocked_state.is_terminal() and blocked_registry.is_killed())
        c.check("blocked cancellation audit cannot reopen registry admission",
                blocked_registry.add(ConnectionState(client_ip="10.0.0.45")) is False)
        late = blocked_registry.run.issue_permit(
            "att-after-cancel", 0, ConnectionState("10.0.0.46").lifecycle,
            policy_generation="policy", budget_binding="budget")
        c.check("no permit is issued while cancellation audit is blocked", late is None)
        audit_release.set()
        worker.join(2)
        c.check("blocked cancellation audit test completes", not worker.is_alive())

        failed_registry = Registry()
        failed_state = ConnectionState(client_ip="10.0.0.47")
        failed_registry.add(failed_state)
        failed_shutdown = threading.Event()

        class FailedAuditSocket:
            def shutdown(self, _how): failed_shutdown.set()
            def close(self): pass

        failed_state.track(FailedAuditSocket())

        def failed_audit(_transition):
            raise OSError("injected cancellation audit EIO")

        failed_registry.terminate_all(on_linearized=failed_audit)
        failed_result = failed_registry.last_cancellation
        c.check("cancellation audit failure cannot prevent enforcement",
                failed_shutdown.is_set() and failed_state.is_terminal() and
                failed_registry.is_killed())
        c.check("cancellation audit failure is retained as non-durable evidence",
                failed_result["linearization_evidence_durable"] is False)
        c.check("cancellation audit failure leaves admission closed",
                failed_registry.add(ConnectionState(client_ip="10.0.0.48")) is False)

        print(f"\n  GATEWAY LIFECYCLE: {c.total - c.failed}/{c.total}")
        return 0 if c.failed == 0 else 1
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())

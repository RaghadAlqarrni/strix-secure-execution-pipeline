#!/usr/bin/env python3
"""Deterministic Phase 1 quiescence, listener-stop, and audit-seal tests."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PEP = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(PEP))

from pep.audit import AuditLog                                      # noqa: E402
from pep.e10_anchor import audit_facts                              # noqa: E402
from pep.gateway import Registry, cancel_and_quiesce, serve         # noqa: E402
from pep import lifecycle as lc                                    # noqa: E402
from pep.lifecycle import ConnectionLifecycle                     # noqa: E402


class Cases:
    def __init__(self): self.total = 0; self.failed = 0
    def check(self, name, condition):
        self.total += 1
        ok = bool(condition)
        self.failed += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")


def decisions(path):
    return [json.loads(line)["decision"] for line in open(path) if line.strip()]


class FakeServer:
    def __init__(self, listener_closed, release=None):
        self.listener_closed = listener_closed
        self.release = release
        self.shutdown_started = threading.Event()

    def shutdown(self):
        self.shutdown_started.set()
        if self.release is not None:
            self.release.wait(2)
        self.listener_closed.set()


def main() -> int:
    c = Cases()
    root = tempfile.mkdtemp(prefix="phase1_quiescence_")
    try:
        # A handler that never acquired an effect permit remains an audit
        # producer and prevents close until its entire handler lifetime ends.
        path = os.path.join(root, "delayed-producer.jsonl")
        audit = AuditLog(path, run_id="run-quiescence")
        registry = Registry()
        assert registry.begin_producer()
        listener_closed = threading.Event()
        server = FakeServer(listener_closed)
        outcome = {}

        def cancel_worker():
            outcome.update(cancel_and_quiesce(
                registry, audit, server=server, listener_closed=listener_closed,
                timeout=1.0))

        worker = threading.Thread(target=cancel_worker)
        worker.start()
        c.check("listener shutdown begins during cancellation",
                server.shutdown_started.wait(1))
        c.check("non-permitted handler delayed across cancellation blocks close",
                lc.RUN_CLOSED not in decisions(path) and registry.producer_count() == 1)
        c.check("post-kill handler/client admission is refused during shutdown",
                registry.begin_producer() is False)
        registry.end_producer()
        worker.join(2)
        c.check("close waits for complete producer drain",
                not worker.is_alive() and outcome.get("sealed") is True and
                registry.producer_count() == 0)
        c.check("RUN_CLOSED is final only after listener and producer drain",
                decisions(path)[-2:] == [lc.CANCEL_ACK, lc.RUN_CLOSED] and
                audit.sealed())

        before = audit_facts(path)
        refused = False
        try:
            audit.write({"decision": "BLOCKED_BY_POLICY", "reason": "LATE"})
        except RuntimeError as exc:
            refused = "AUDIT_LOG_SEALED" in str(exc)
        after = audit_facts(path)
        c.check("post-close audit write is rejected",
                refused)
        c.check("post-close write leaves byte length and tail hash unchanged",
                before["byte_length"] == after["byte_length"] and
                before["final_chain_hash"] == after["final_chain_hash"])
        reopened = AuditLog(path, run_id="run-quiescence")
        reopened_refused = False
        try:
            reopened.write({"decision": "BLOCKED_BY_POLICY", "reason": "REOPENED"})
        except RuntimeError as exc:
            reopened_refused = "AUDIT_LOG_SEALED" in str(exc)
        c.check("reopened AuditLog preserves absorbing seal",
                reopened.sealed() and reopened_refused and
                audit_facts(path)["byte_length"] == before["byte_length"])

        # The same absorbing writer boundary also rejects a release transition.
        late_run = lc.RunContext("run-quiescence")
        late_conn = ConnectionLifecycle("late-conn")
        assert late_run.authorize("late-attempt", 0) == 1
        late_permit = late_run.issue_permit(
            "late-attempt", 0, late_conn,
            policy_generation="policy", budget_binding="budget")
        assert late_permit is not None
        late_permit.bind_durable_release(audit, late_conn.conn_id)
        release_refused = False
        try:
            late_permit.release()
        except lc.AuditUnhealthy:
            release_refused = True
        c.check("PERMIT_RELEASED cannot append after absorbing seal",
                release_refused and late_run.inflight_count() == 0 and
                audit_facts(path)["byte_length"] == before["byte_length"] and
                audit_facts(path)["final_chain_hash"] ==
                before["final_chain_hash"])

        # A remaining non-permitted producer exhausts the finite wait. Timeout
        # is recorded, but RUN_CLOSED is omitted and the writer stays unsealed.
        timeout_path = os.path.join(root, "producer-timeout.jsonl")
        timeout_audit = AuditLog(timeout_path, run_id="run-timeout")
        timeout_registry = Registry()
        assert timeout_registry.begin_producer()
        timeout_listener = threading.Event()
        timeout_server = FakeServer(timeout_listener)
        timeout_result = cancel_and_quiesce(
            timeout_registry, timeout_audit, server=timeout_server,
            listener_closed=timeout_listener, timeout=0.01)
        c.check("producer timeout emits no RUN_CLOSED",
                lc.CANCEL_DRAIN_TIMEOUT in decisions(timeout_path) and
                lc.RUN_CLOSED not in decisions(timeout_path))
        c.check("producer timeout leaves audit unsealed and names blocker",
                not timeout_audit.sealed() and
                "AUDIT_PRODUCERS_REMAIN" in timeout_result["closure_blockers"])
        timeout_registry.end_producer()

        # Listener failure/timeout is independently sufficient to prevent close.
        listener_path = os.path.join(root, "listener-timeout.jsonl")
        listener_audit = AuditLog(listener_path, run_id="run-listener-timeout")
        listener_registry = Registry()
        listener_event = threading.Event()

        class ListenerNeverCloses:
            def shutdown(self): pass

        listener_result = cancel_and_quiesce(
            listener_registry, listener_audit, server=ListenerNeverCloses(),
            listener_closed=listener_event, timeout=0.01)
        c.check("listener timeout emits no RUN_CLOSED",
                lc.RUN_CLOSED not in decisions(listener_path) and
                "LISTENER_NOT_STOPPED" in listener_result["closure_blockers"])

        # Failure after durable cancellation evidence but before ACK/seal must
        # omit closure even though enforcement and listener shutdown occurred.
        failure_path = os.path.join(root, "audit-failure.jsonl")
        real_failure_audit = AuditLog(failure_path, run_id="run-audit-failure")

        class FailKillAudit:
            def __init__(self, real): self.real = real
            def write(self, entry):
                if entry.get("decision") == "KILL_SWITCH":
                    raise OSError("injected audit failure")
                return self.real.write(entry)
            def seal_with(self, entry): return self.real.seal_with(entry)

        failure_registry = Registry()
        failure_listener = threading.Event()
        failure_result = cancel_and_quiesce(
            failure_registry, FailKillAudit(real_failure_audit),
            server=FakeServer(failure_listener),
            listener_closed=failure_listener, timeout=0.1)
        c.check("audit failure after enforcement emits no RUN_CLOSED",
                lc.RUN_CLOSED not in decisions(failure_path) and
                failure_result.get("audit_failure") == "OSError")
        c.check("audit failure keeps registry admission terminal",
                failure_registry.is_killed() and
                failure_registry.begin_producer() is False)

        # STOP_ALL present before serve(): listener is constructed and STARTUP
        # is fsynced first, but no serving thread/watcher can append ahead of it.
        startup_root = os.path.join(root, "startup-stop")
        os.mkdir(startup_root)
        startup_stop = os.path.join(startup_root, "STOP_ALL")
        open(startup_stop, "wb").close()
        startup_path = os.path.join(startup_root, "audit.jsonl")
        startup_audit = AuditLog(startup_path, run_id="run-startup-stop")

        class FakeCA:
            ca_cert_path = "fixture-ca"

        serve(pdp=None, ca=FakeCA(), audit=startup_audit,
              kill_file=startup_stop, host="127.0.0.1", port=0)
        startup_decisions = decisions(startup_path)
        c.check("STOP_ALL at startup records STARTUP before cancellation",
                "STARTUP" in startup_decisions and
                startup_decisions.index("STARTUP") <
                startup_decisions.index(lc.CANCEL_REQUESTED))
        c.check("STOP_ALL at startup closes and seals without late records",
                startup_decisions[-1] == lc.RUN_CLOSED and startup_audit.sealed())
        startup_size = os.path.getsize(startup_path)
        time.sleep(0.05)
        c.check("STOP_ALL startup close remains physically final",
                os.path.getsize(startup_path) == startup_size)

        print(f"\n  QUIESCENT SHUTDOWN: {c.total - c.failed}/{c.total}")
        return 0 if c.failed == 0 else 1
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    raise SystemExit(main())

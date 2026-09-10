"""
Append-only, tamper-evident audit log.

Properties:
  * O_APPEND only — entries are never rewritten in place.
  * Each record carries ``prev`` = the SHA-256 of the previous record, forming a
    hash chain. Editing an anchored byte range breaks verification. The chain
    alone cannot detect suffix deletion; E10 therefore requires a separately
    authenticated control-plane close anchor over count, bytes, and final hash.
  * fsync per record: a crash loses at most the record in flight, and crash
    recovery re-anchors from the last verifiable line (crash/restart semantics).
  * Secrets are never accepted: values are scrubbed against a redaction set
    before writing, so a credential cannot reach the log by accident.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
import time


class AuditLog:
    GENESIS = "0" * 64

    def __init__(self, path: str, redact: set[str] | None = None,
                 run_id: str | None = None, exclusive: bool = False):
        self.path = path
        # One lock protects the hash-chain tail, health latch, and redaction
        # set. add_secret() may race request writers, so redaction cannot be a
        # separately-mutated set.
        self._lock = threading.RLock()
        self._redact = set(redact or ())
        # Control-plane-issued execution id. Stamped on EVERY record so the
        # auditor can scope evidence to one execution without relying on any
        # value the sandbox can choose. The sandbox never learns this value.
        self._run_id = run_id or ""
        # Phase 1 hardening (F03): a latched health flag. Any failed/short/
        # unsynced write flips it False and it never returns True in-process, so
        # an unhealthy sink blocks every future permit (see EffectGate).
        self._healthy = True
        # A successful seal_with(RUN_CLOSED) is absorbing. It is protected by
        # the same lock as append/hash-tail state, so no writer can interleave
        # between the final fsync and the sealed flag becoming visible.
        self._sealed = False
        # Exclusive single-writer ownership (opt-in; the gateway uses it). A
        # second exclusive writer on the same path fails to acquire the lock —
        # two writers interleaving the chain is exactly how a break appears.
        self._exclusive = exclusive
        self._lockfd = None
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        if exclusive:
            lock_name = "." + os.path.basename(path) + ".writer.lock"
            self._lockfd = os.open(os.path.join(parent, lock_name),
                                   os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(self._lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                os.close(self._lockfd)
                self._lockfd = None
                raise RuntimeError("AUDIT_WRITER_NOT_EXCLUSIVE") from exc
        # F03: establish the file and its directory entry before any effect can
        # rely on the log. A new empty log is fsynced, then its parent directory
        # is fsynced. Existing logs are fully verified before their tail is
        # accepted; corrupt/torn bytes remain untouched and latch the sink bad.
        self._parent = parent
        self._dir_durable = None
        self._recovery_detail = "not checked"
        self._prev = self.GENESIS
        self._initialize_storage()

    def _initialize_storage(self) -> None:
        if os.path.exists(self.path):
            intact, detail = self.verify(self.path)
            self._recovery_detail = detail
            if not intact:
                self._healthy = False
                return
            self._prev = self._recover_tail()
        else:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._recovery_detail = "new empty log created durably"
            except FileExistsError:
                # Another initializer won creation. Exclusive production
                # writers cannot reach this path; verify before accepting it.
                intact, detail = self.verify(self.path)
                self._recovery_detail = detail
                if not intact:
                    self._healthy = False
                    return
                self._prev = self._recover_tail()
            except OSError:
                self._healthy = False
                self._recovery_detail = "could not create and sync audit log"
                return
        self.ensure_parent_durable()

    @staticmethod
    def _fsync_dir(parent: str) -> bool:
        try:
            dfd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            return True
        except OSError:
            return False

    def healthy(self) -> bool:
        with self._lock:
            return self._healthy

    def sealed(self) -> bool:
        with self._lock:
            return self._sealed

    @property
    def run_id(self) -> str:
        return self._run_id

    def close(self) -> None:
        if self._lockfd is not None:
            try:
                fcntl.flock(self._lockfd, fcntl.LOCK_UN)
                os.close(self._lockfd)
            except OSError:
                pass
            self._lockfd = None

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        """Write every byte or raise. A short/zero-progress write is a durable-
        record failure, not a success — the base ignored os.write's return."""
        mv = memoryview(data)
        while mv:
            n = os.write(fd, mv)
            if n <= 0:
                raise OSError("SHORT_WRITE: zero progress writing audit record")
            mv = mv[n:]

    def ensure_parent_durable(self) -> bool:
        """F03: sync the log's parent directory so the log's own existence is
        durable. A filesystem that cannot sync a directory (e.g. vboxsf ->
        EINVAL) latches the sink unhealthy rather than silently proceeding."""
        with self._lock:
            self._dir_durable = self._fsync_dir(self._parent)
            if not self._dir_durable:
                self._healthy = False
            return self._dir_durable

    def startup_verify(self) -> tuple[bool, str]:
        """Verify the whole existing chain before serving, then establish parent
        durability. A torn/broken chain latches the sink unhealthy (blocking
        admission) WITHOUT rewriting or discarding the damaged segment; recovery
        requires a new linked segment."""
        with self._lock:
            if not self._healthy:
                return False, self._recovery_detail
            intact, detail = self.verify(self.path)
            if not intact:
                self._healthy = False
                self._recovery_detail = detail
                return False, detail
            self.ensure_parent_durable()
            if not self._healthy:
                return False, "parent directory not durable"
            self._recovery_detail = detail
            return True, detail

    # ------------------------------------------------------------------ recovery
    def _recover_tail(self) -> str:
        """Re-anchor the chain from the last intact line after a restart."""
        if not os.path.exists(self.path):
            return self.GENESIS
        last = None
        last_record = None
        with open(self.path, "rb") as fh:
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue          # torn final write — ignore, do not rewrite
                last = line
                last_record = record
        if last_record is not None and last_record.get("decision") == "RUN_CLOSED":
            self._sealed = True
        return hashlib.sha256(last).hexdigest() if last else self.GENESIS

    # -------------------------------------------------------------------- write
    def _scrub(self, obj):
        if isinstance(obj, str):
            out = obj
            for s in self._redact:
                if s and s in out:
                    out = out.replace(s, "«REDACTED»")
            return out
        if isinstance(obj, dict):
            return {k: self._scrub(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._scrub(v) for v in obj]
        return obj

    def add_secret(self, secret: str) -> None:
        if secret:
            with self._lock:
                self._redact.add(secret)

    def write(self, entry: dict) -> str:
        with self._lock:
            if self._sealed:
                raise RuntimeError("AUDIT_LOG_SEALED: final RUN_CLOSED already fsynced")
            if not self._healthy:
                raise RuntimeError("AUDIT_SINK_UNHEALTHY: refusing to write after a latched failure")
            rec = self._scrub(dict(entry))
            rec["ts"] = time.time()
            rec["run_id"] = self._run_id
            rec["prev"] = self._prev
            line = json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                self._write_all(fd, line + b"\n")
                os.fsync(fd)
            except Exception:
                self._healthy = False        # latch: block every future permit
                raise
            finally:
                os.close(fd)
            self._prev = hashlib.sha256(line).hexdigest()
            return self._prev

    def seal_with(self, final_entry: dict) -> str:
        """Append/fsync the sole final record and atomically reject all later writes."""
        with self._lock:
            if final_entry.get("decision") != "RUN_CLOSED":
                raise ValueError("AUDIT_SEAL_REQUIRES_RUN_CLOSED")
            if self._sealed:
                raise RuntimeError("AUDIT_LOG_ALREADY_SEALED")
            tail = self.write(final_entry)
            self._sealed = True
            return tail

    # ------------------------------------------------------------------- verify
    @classmethod
    def verify(cls, path: str) -> tuple[bool, str]:
        """Walk the chain. Returns (intact, detail)."""
        prev = cls.GENESIS
        n = 0
        with open(path, "rb") as fh:
            for i, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    return False, f"line {i}: unparseable"
                if rec.get("prev") != prev:
                    return False, f"line {i}: chain break (expected prev={prev[:12]}…)"
                prev = hashlib.sha256(line).hexdigest()
                n += 1
        return True, f"{n} records, chain intact"

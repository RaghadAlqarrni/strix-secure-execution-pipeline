#!/usr/bin/env python3
"""Host-controlled UDP/IPv6 nonce receiver for DEC-7 B7 evidence."""
from __future__ import annotations

import argparse
import json
import os
import socket
import time


def emit(path: str, record: dict) -> None:
    record = {"ts_ns": time.time_ns(), **record}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--log", required=True)
    ap.add_argument("--ready", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--timeout", type=float, default=45.0)
    a = ap.parse_args()

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port))
    s.settimeout(0.5)
    emit(a.log, {"event": "READY", "run_id": a.run_id,
                 "bind": a.bind, "port": a.port, "protocol": "udp"})
    with open(a.ready, "w", encoding="ascii") as fh:
        fh.write(f"{a.run_id} {a.bind} {a.port}\n")
        fh.flush()
        os.fsync(fh.fileno())

    deadline = time.monotonic() + a.timeout
    while time.monotonic() < deadline:
        try:
            data, peer = s.recvfrom(4096)
        except socket.timeout:
            continue
        nonce = data.decode("ascii", "replace")
        emit(a.log, {"event": "DATAGRAM", "run_id": a.run_id,
                     "nonce": nonce, "src_ip": peer[0], "src_port": peer[1],
                     "dst_ip": a.bind, "dst_port": a.port,
                     "bytes": len(data), "protocol": "udp"})
    s.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

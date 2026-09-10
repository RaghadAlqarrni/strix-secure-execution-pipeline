#!/usr/bin/env python3
"""Minimal UDP/IPv6 sender shared by calibration, controls and measurement."""
from __future__ import annotations

import argparse
import json
import socket
import time


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--port", required=True, type=int)
    ap.add_argument("--nonce", required=True)
    ap.add_argument("--role", required=True)
    ap.add_argument("--output", required=True)
    a = ap.parse_args()
    out = {"ts_ns": time.time_ns(), "role": a.role, "protocol": "udp",
           "dst_ip": a.target, "dst_port": a.port, "nonce": a.nonce,
           "attempted": False, "bytes": 0, "error": ""}
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        n = s.sendto(a.nonce.encode("ascii"), (a.target, a.port))
        out.update({"attempted": True, "bytes": n,
                    "src_ip": s.getsockname()[0], "src_port": s.getsockname()[1]})
        s.close()
    except Exception as exc:
        out["error"] = type(exc).__name__
    with open(a.output, "w", encoding="utf-8") as fh:
        json.dump(out, fh, sort_keys=True, indent=2)
    print(json.dumps(out, sort_keys=True), flush=True)
    return 0 if out["attempted"] and out["bytes"] == len(a.nonce) else 1


if __name__ == "__main__":
    raise SystemExit(main())

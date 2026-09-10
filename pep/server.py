#!/usr/bin/env python3
"""Production PEP entrypoint.

Fail-closed startup: if policy, CA, or audit cannot be initialized, the process
exits rather than serving with a degraded decision path.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pep.audit import AuditLog          # noqa: E402
from pep.ca import InterceptionCA       # noqa: E402
from pep.gateway import serve           # noqa: E402
from pep.pdp import PDP, Budgets        # noqa: E402
from pep.resolver import Resolver, StaticResolver  # noqa: E402

CONTROL = os.environ.get("PEP_CONTROL", "/control")
POLICY = os.path.join(CONTROL, "policy.json")
KILL = os.path.join(CONTROL, "STOP_ALL")
AUDIT = os.path.join(CONTROL, "audit.jsonl")
CA_DIR = os.environ.get("PEP_CA_DIR", "/capki")
LEAF_DIR = os.environ.get("PEP_LEAF_DIR", "/capki/leaf")


def policy_provider() -> dict:
    """Re-read per decision so policy edits take effect without a restart.
    A malformed or missing file raises, and the PDP turns that into a denial."""
    with open(POLICY) as fh:
        return json.load(fh)


def main() -> int:
    try:
        policy = policy_provider()
    except Exception as exc:
        print(f"[pep] FATAL: policy unreadable at startup: {exc}", file=sys.stderr)
        return 2
    try:
        ca = InterceptionCA(CA_DIR, LEAF_DIR)
    except Exception as exc:
        print(f"[pep] FATAL: CA init failed: {exc}", file=sys.stderr)
        return 3
    try:
        # Issued by the control plane (run_dualstack_gate.sh / run_pep.sh) and
        # never transmitted to the sandbox.
        audit = AuditLog(AUDIT, run_id=os.environ.get("PEP_RUN_ID", ""),
                         exclusive=True)
        if not audit.healthy():
            raise RuntimeError("AUDIT_SINK_UNHEALTHY")
    except Exception as exc:
        print(f"[pep] FATAL: audit init failed: {exc}", file=sys.stderr)
        return 4

    zone = policy.get("dns_zone")
    resolver = StaticResolver(zone) if zone else Resolver()
    if zone:
        print("[pep] using STATIC zone from policy (test/lab mode)", flush=True)

    pdp = PDP(policy_provider, resolver, KILL, Budgets())
    try:
        serve(pdp=pdp, ca=ca, audit=audit, kill_file=KILL,
              port=int(os.environ.get("PEP_PORT", "3128")))
    except RuntimeError as exc:
        print(f"[pep] FATAL: runtime startup failed: {exc}", file=sys.stderr)
        return 5
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

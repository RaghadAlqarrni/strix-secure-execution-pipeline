"""Verify the public, sanitized incident-response tabletop record."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EVENT = ROOT / "simulated_incident_event.json"
RESULT = ROOT / "IR_TABLETOP_2026-09-11.json"
REQUIRED_STAGES = {
    "detect",
    "stop",
    "contain",
    "assess_authorization",
    "preserve_evidence",
    "notify",
    "eradicate",
    "recover",
    "review",
}


def main() -> int:
    event_bytes = EVENT.read_bytes()
    event = json.loads(event_bytes)
    result = json.loads(RESULT.read_text(encoding="utf-8"))

    observed_hash = hashlib.sha256(event_bytes).hexdigest()
    observed_stages = {step["stage"] for step in result["steps"] if step["status"] == "PASS"}

    checks = {
        "simulation_only": event["simulation"] is True,
        "no_real_credentials": event["contains_real_credentials"] is False,
        "no_third_party_data": event["contains_third_party_data"] is False,
        "no_external_effect": event["external_effect_occurred"] is False,
        "evidence_hash_matches": observed_hash == result["source_event_sha256"],
        "all_response_stages_passed": REQUIRED_STAGES <= observed_stages,
        "record_declares_no_live_actions": result["live_actions_executed"] is False,
    }

    for name, passed in checks.items():
        print(f"{'PASS' if passed else 'FAIL'} {name}")
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

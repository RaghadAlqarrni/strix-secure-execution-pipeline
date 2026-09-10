#!/usr/bin/env bash
# Owner-authorized remediation validation entrypoint. This is intentionally a
# separate command from the release gate and can never print a release verdict.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export TRACK_A_VALIDATION_ONLY=1
exec bash "$HERE/run_dualstack_gate.sh"

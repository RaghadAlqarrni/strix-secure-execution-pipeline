#!/usr/bin/env bash
# P1 REPAIR PROOFS -- standing, re-runnable evidence for this pass's P1 fixes.
#
# Same discipline as fixtures/p0_proofs/run_p0_proofs.sh: every proof here
# carries a NEGATIVE CONTROL (or, for P1-1, an explicit ENVIRONMENT-BLOCKED
# downgrade instead of a misleading PASS/FAIL when the host cannot test the
# property at all). A green result from a check that cannot go red is not
# evidence.
#
# SCOPE OF THIS FILE -- read before quoting results from it:
#   Covers the 3 DEC-2-independent P1 items done in this pass:
#     P1-1  phase2b/target_https.py dual-stack bind      (P2-CRIT-1)
#     P1-2  audit_gate_evidence.py E1 status/pass check   (P3-CRIT-2 / D-3)
#     P1-3  gateway.py _deny()/_deny_tls() conn_id        (P2-HIGH-3)
#   It does NOT cover the rest of TRIAGE_UNIFIED.md's P1 list (P3-HIGH-2,
#   P3-HIGH-4, P3-HIGH-5, P3-HIGH-7, P3-HIGH-8), and D-1's fix (empty
#   row_id/test_nonce on KILL_SWITCH_ACTIVE) is deliberately NOT included --
#   gated on DEC-2 (nonce semantics), the owner's call, untouched this pass.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=0

hdr() { echo; echo "============================================================================"; echo "$1"; echo "============================================================================"; }

hdr "P1-1  phase2b/target_https.py -- dual-stack bind (P2-CRIT-1)"
OUT1="$(python3 "$HERE/proof_p1_1_target_dualstack.py" 2>&1)"; P1=$?
echo "$OUT1"
BLOCKED1=0
echo "$OUT1" | grep -q "ENVIRONMENT-BLOCKED" && BLOCKED1=1
[ "$P1" = 0 ] || FAIL=1

hdr "P1-2  audit_gate_evidence.py -- E1 status/pass self-contradiction (P3-CRIT-2 / D-3)"
python3 "$HERE/proof_p1_2_e1_contradiction.py"; P2=$?
[ "$P2" = 0 ] || FAIL=1

hdr "P1-3  gateway.py -- _deny()/_deny_tls() carry conn_id (P2-HIGH-3)"
python3 "$HERE/proof_p1_3_deny_conn_id.py"; P3=$?
[ "$P3" = 0 ] || FAIL=1

echo
echo "============================================================================"
if [ "$BLOCKED1" = 1 ] && [ "$P1" = 0 ]; then
  P1_LABEL="ENVIRONMENT-BLOCKED (static shape only -- re-run on a dual-stack host)"
else
  P1_LABEL="$([ "$P1" = 0 ] && echo PASS || echo FAIL)"
fi
printf "  P1-1 target dual-stack: %s\n" "$P1_LABEL"
printf "  P1-2 E1 contradiction:  %s\n" "$([ "$P2" = 0 ] && echo PASS || echo FAIL)"
printf "  P1-3 deny conn_id:      %s\n" "$([ "$P3" = 0 ] && echo PASS || echo FAIL)"
if [ "$FAIL" = 0 ]; then
  echo "  P1 PROOFS: PASS"
  echo
  echo "  SCOPE OF THIS RESULT -- read before quoting it:"
  echo "    Unit/component-level evidence for 3 specific P1 items on THIS"
  echo "    container. P1-1 could only run its static/code-shape check here --"
  echo "    this host has no IPv6 stack at all, so the transport-level claim"
  echo "    needs a real dual-stack host (e.g. run_dualstack_gate.sh on the"
  echo "    Ubuntu VM) before it is EXECUTION-VERIFIED. None of this is a"
  echo "    release recommendation, and pre-repair findings are not evidence"
  echo "    about this repaired code -- a fresh, independent Pass-4-style audit"
  echo "    is still required before this tree is anything but REPAIRED,"
  echo "    PENDING RE-AUDIT."
  exit 0
else
  echo "  P1 PROOFS: FAIL"; exit 1
fi

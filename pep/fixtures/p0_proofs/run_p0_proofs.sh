#!/usr/bin/env bash
# P0 REPAIR PROOFS -- standing, re-runnable evidence for the three P0 fixes.
#
# DELIBERATELY NOT A STAGE INSIDE run_fixtures.sh.
# proof_p0_3 INVOKES run_fixtures.sh (to reproduce pre-P0-3 coverage on each
# mutant). Wiring these proofs into that runner would make it call itself.
#
# Every proof here carries a NEGATIVE CONTROL. A proof whose control does not
# fail is reported as VOID, not as a pass -- a green result from a test that
# cannot go red is not evidence.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FAIL=0

hdr() { echo; echo "============================================================================"; echo "$1"; echo "============================================================================"; }

hdr "P0-1  budget cap -- check-then-act race (atomic reserve)"
python3 "$HERE/proof_p0_1_budget_toctou.py"; P1=$?
[ "$P1" = 0 ] || FAIL=1

hdr "P0-2  kill switch -- R-8 admit-after-kill race + evidence honesty"
echo "--- UNDER TEST (repaired) ---"
python3 "$HERE/proof_p0_2_killswitch.py"; P2A=$?
echo
echo "--- NEGATIVE CONTROL (pre-repair shape must reproduce R-8) ---"
python3 "$HERE/proof_p0_2_killswitch.py" --naive; P2B=$?
P2=0; { [ "$P2A" = 0 ] && [ "$P2B" = 0 ]; } || P2=1
[ "$P2" = 0 ] || FAIL=1

hdr "P0-3  audit.py -- mutation coverage (real file never modified)"
python3 "$HERE/proof_p0_3_audit_mutations.py"; P3=$?
[ "$P3" = 0 ] || FAIL=1

hdr "P0-4 / DEC-5  enforcement surfaces -- PDP.decide + Gateway.do_CONNECT"
python3 "$HERE/proof_p0_4_enforcement_surfaces.py"; P4=$?
[ "$P4" = 0 ] || FAIL=1

echo
echo "============================================================================"
printf "  P0-1 budget: %s    P0-2 kill switch: %s    P0-3 audit coverage: %s\n" \
  "$([ "$P1" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$P2" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$P3" = 0 ] && echo PASS || echo FAIL)"
printf "  P0-4 DEC-5 enforcement surfaces: %s\n" \
  "$([ "$P4" = 0 ] && echo PASS || echo FAIL)"
if [ "$FAIL" = 0 ]; then
  echo "  P0 PROOFS: PASS"
  echo
  echo "  SCOPE OF THIS RESULT -- read before quoting it:"
  echo "    P0-1..P0-3 are unit/component evidence. P0-4 additionally drives the"
  echo "    real PDP.decide() and Gateway.do_CONNECT() enforcement surfaces. Every"
  echo "    proof has a live negative control. This is NOT a statement about the"
  echo "    system under the real dual-stack gate, and it does not certify"
  echo "    anything. Pre-repair findings are not evidence about post-repair code,"
  echo "    and neither is a repairer's own test. Status stays REPAIRED, PENDING"
  echo "    PASS 4 until a fresh run and an independent audit say otherwise."
  exit 0
else
  echo "  P0 PROOFS: FAIL"; exit 1
fi

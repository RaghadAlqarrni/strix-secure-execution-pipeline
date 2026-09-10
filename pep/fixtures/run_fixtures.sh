#!/usr/bin/env bash
# Adversarial fixture battery for the Evidence Auditor.
# Honest fixture MUST validate (exit 3); every forgery MUST be rejected (exit 1).
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PEP="$(cd "$HERE/.." && pwd)"
RID="run-honest0000000000000000000000"

if ! python3 "$HERE/make_fixtures.py" >/dev/null; then
  echo "FIXTURE GENERATION FAILED"; exit 1
fi
echo "============================================================================"
echo "ADVERSARIAL FIXTURE BATTERY"
echo "============================================================================"
printf "  %-34s %-16s %-16s %s\n" FIXTURE EXPECTED ACTUAL RC
printf "  %-34s %-16s %-16s %s\n" "----------------------------------" "----------------" "----------------" "--"

PASS=0; FAIL=0
for d in "$HERE"/f*/; do
  name="$(basename "$d")"
  [ "$name" = "f00_honest" ] && expect="FIXTURE_VALIDATED" || expect="FIXTURE_REJECTED"

  vargs=(--verifier "$PEP/verify_layerb_audit.py" --verifier "$PEP/verify_pp18.py" \
         --verifier "$PEP/verify_b7_evidence.py")
  [ -f "$d/verifier.py" ] && vargs=(--verifier "$d/verifier.py" \
         --verifier "$PEP/verify_pp18.py" --verifier "$PEP/verify_b7_evidence.py")

  out=$(python3 "$PEP/audit_gate_evidence.py" \
        --fixture-mode --acceptance "$d/acceptance.json" --layerb "$d/layerb.json" \
        --audit "$d/audit.jsonl" --run-id "$RID" --v4 "$d/v4.json" \
        --b7-evidence "$d/b7.json" \
        "${vargs[@]}" 2>&1)
  rc=$?
  if echo "$out" | grep -q "RESULT: FIXTURE_VALIDATED"; then
    actual="FIXTURE_VALIDATED"
  elif echo "$out" | grep -q "RESULT: FIXTURE_REJECTED"; then
    actual="FIXTURE_REJECTED"
  else
    actual="NO_VERDICT"
  fi

  if [ "$expect" = "$actual" ] && \
     { { [ "$expect" = "FIXTURE_VALIDATED" ] && [ "$rc" = "3" ]; } || \
       { [ "$expect" = "FIXTURE_REJECTED" ] && [ "$rc" = "1" ]; }; }; then
    mark="OK"; PASS=$((PASS+1))
  else
    mark="** WRONG **"; FAIL=$((FAIL+1))
  fi
  printf "  %-34s %-16s %-16s %-3s %s\n" "$name" "$expect" "$actual" "$rc" "$mark"
  if [ "$mark" != "OK" ]; then echo "$out" | sed 's/^/        /' | grep -E 'FAIL|RESULT'; fi
done

echo
echo "  fixtures behaving correctly: $PASS   incorrect: $FAIL"

# The fixture battery only ever READS the verifiers (through E5) and hands the
# auditor artifacts already in final shape. Two whole classes of defect are
# therefore outside it: a verifier that is wrong rather than weakened, and an
# ordering fault between the stages the real gate runs. Both are covered here.
echo
echo "============================================================================"
echo "VERIFIER SELF-TEST (the verifiers are EXECUTED, not just read)"
echo "============================================================================"
python3 "$HERE/test_verifiers.py"; SELFTEST=$?

echo
echo "============================================================================"
echo "E9 BEHAVIOURAL FALSIFICATION"
echo "============================================================================"
python3 "$HERE/test_b7_e9.py"; E9TEST=$?
python3 "$HERE/test_e9_raw_mutations.py"; E9RAW=$?
python3 "$HERE/test_e9_source_mutation.py"; E9MUT=$?
python3 "$HERE/test_f01_raw_required.py"; F01=$?
echo "F01 production raw-evidence regression exit: $F01"

echo
echo "============================================================================"
echo "PIPELINE-ORDER INTEGRATION"
echo "============================================================================"
python3 "$HERE/test_pipeline_order.py"; ORDER=$?

echo
echo "============================================================================"
echo "AUDIT LOG SELF-TEST (the root of the authority hierarchy, EXECUTED)"
echo "============================================================================"
python3 "$HERE/test_audit_log.py"; AUDITLOG=$?

echo
echo "============================================================================"
echo "PRECONDITION FIXTURES (a test must not pass when it never ran)"
echo "============================================================================"
python3 "$HERE/test_preconditions.py"; PRECOND=$?

echo
echo "============================================================================"
printf "  fixtures: %s   verifier: %s   E9: %s   E9-mutation: %s   order: %s   preconditions: %s   audit-log: %s\n" \
  "$([ "$FAIL" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$SELFTEST" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$E9TEST" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$E9MUT" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$ORDER" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$PRECOND" = 0 ] && echo PASS || echo FAIL)" \
  "$([ "$AUDITLOG" = 0 ] && echo PASS || echo FAIL)"
if [ "$FAIL" = "0" ] && [ "$SELFTEST" = "0" ] && [ "$E9TEST" = "0" ] && [ "$E9RAW" = "0" ] && [ "$E9MUT" = "0" ] && [ "$F01" = "0" ] && [ "$ORDER" = "0" ] \
   && [ "$PRECOND" = "0" ] && [ "$AUDITLOG" = "0" ]; then
  echo "  BATTERY: PASS"; exit 0
else
  echo "  BATTERY: FAIL"; exit 1
fi

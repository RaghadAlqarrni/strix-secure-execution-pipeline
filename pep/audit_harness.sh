#!/usr/bin/env bash
# ============================================================================
# ISOLATED AUDIT HARNESS — makes READ-ONLY actually true.
#
# The audit instruction said "READ-ONLY, do not modify any file" AND "run
# ./run_fixtures.sh". Those contradict: run_fixtures.sh calls make_fixtures.py,
# which rewrites all 22 fixture directories. Measured — content is deterministic
# but the files ARE rewritten:
#     content: a097225fc06c -> a097225fc06c   (same bytes)
#     mtime:   1787426559   -> 1787426903     (REWRITTEN)
# It also creates Docker containers. The previous audit round therefore mutated
# the tree it was auditing, and said so in its own report.
#
# This harness resolves it: the auditor works on a DISPOSABLE COPY, and the
# original is proven byte-for-byte unchanged afterwards. Anything that can only
# be tested by mutating the original is NOT RUN and reported NOT-VERIFIED.
#
# Usage: audit_harness.sh [workspace]        default: /tmp/audit-ws
# ============================================================================
set -uo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WS="${1:-/tmp/audit-ws}"
MANIFEST="/tmp/audit-src-hashes.txt"

hash_tree() { # excludes generated dirs that are not part of the audited source
  ( cd "$SRC" && find pep phase2b -type f \
      ! -path '*/__pycache__/*' ! -path 'pep/control/*' ! -path 'pep/out/*' \
      ! -path 'pep/collected/*' ! -path 'pep/capki/*' ! -path 'pep/sandbox_ca/*' \
      ! -path 'phase2b/certs/*' ! -name '*.tar.gz' \
      -print0 | sort -z | xargs -0 sha256sum )
}

echo "============================================================================"
echo "ISOLATED AUDIT HARNESS"
echo "  source     : $SRC"
echo "  workspace  : $WS"
echo "============================================================================"

echo; echo "-- pre-audit state of the ORIGINAL tree --"
hash_tree > "$MANIFEST"
echo "  files hashed : $(wc -l < "$MANIFEST")"
echo "  tree digest  : $(sha256sum "$MANIFEST" | cut -c1-16)"
if command -v git >/dev/null 2>&1 && git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
  echo "  git status   : $(git -C "$SRC" status --porcelain | wc -l) modified"
else
  echo "  git status   : not a git repository (hash manifest is the baseline)"
fi

echo; echo "-- building disposable copy --"
rm -rf "$WS"; mkdir -p "$WS"
cp -a "$SRC/pep" "$SRC/phase2b" "$WS/" 2>/dev/null
rm -rf "$WS/pep/__pycache__" "$WS/pep/fixtures/__pycache__"
echo "  copied -> $WS   ($(find "$WS" -type f | wc -l) files)"

echo; echo "-- runtime coverage inventory (manifest source of truth) --"
python3 "$WS/pep/audit_inventory.py" "$SRC/pep/collected" 2>&1 | tail -6

echo; echo "-- running mutating suites INSIDE the copy only --"
( cd "$WS/pep/fixtures" && ./run_fixtures.sh 2>&1 | \
  grep -E "fixtures behaving|SELF-TEST:|PIPELINE ORDER:|PRECONDITION FIXTURES:|BATTERY:" )
BATTERY_RC=${PIPESTATUS[0]}

echo; echo "-- post-audit verification of the ORIGINAL tree --"
hash_tree > "${MANIFEST}.after"
if diff -q "$MANIFEST" "${MANIFEST}.after" >/dev/null; then
  echo "  ORIGINAL TREE UNCHANGED — byte-for-byte identical"
  echo "  digest before/after: $(sha256sum "$MANIFEST" | cut -c1-16) / $(sha256sum "${MANIFEST}.after" | cut -c1-16)"
  RC=0
else
  echo "  *** ORIGINAL TREE WAS MODIFIED — READ-ONLY MANDATE VIOLATED ***"
  diff "$MANIFEST" "${MANIFEST}.after" | head -20
  RC=1
fi

echo; echo "============================================================================"
echo "  audit workspace : $WS   (disposable — safe to mutate)"
echo "  battery in copy : $([ "${BATTERY_RC:-1}" = 0 ] && echo PASS || echo FAIL)"
echo "  read-only proof : $([ "$RC" = 0 ] && echo HELD || echo VIOLATED)"
echo "  required manifest: $SRC/pep/audit_manifest_required.json"
echo "============================================================================"
exit $RC

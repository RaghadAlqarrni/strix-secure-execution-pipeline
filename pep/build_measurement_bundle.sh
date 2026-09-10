#!/usr/bin/env bash
# Seal host-owned Track-A measurement output outside the protected candidate tree.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${PRE_TREE_HASH:?set PRE_TREE_HASH}"
: "${CANDIDATE_TREE_HASH:?set CANDIDATE_TREE_HASH}"
: "${CONTRACT_SHA256:?set CONTRACT_SHA256}"
: "${VALIDATION_OUTPUT:?set VALIDATION_OUTPUT to the tee log}"
DEST="${MEASUREMENT_BUNDLE_DEST:-$HOME}"
COL="$HERE/collected"; CTRL="$HERE/control"
[ -d "$COL" ] && [ -s "$CTRL/audit.jsonl" ] && [ -s "$VALIDATION_OUTPUT" ]
RUN_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["run_id"])' "$COL/b7_evidence.json")"
STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/track-a-measurement-$RUN_ID"; mkdir -p "$ROOT"
cp -a "$COL" "$ROOT/collected"
mkdir -p "$ROOT/control"; cp "$CTRL/audit.jsonl" "$ROOT/control/audit.jsonl"
cp "$VALIDATION_OUTPUT" "$ROOT/track-a-validation-output.txt"
cat >"$ROOT/governance.txt" <<EOF
contract_sha256=$CONTRACT_SHA256
pre_remediation_tree_hash=$PRE_TREE_HASH
candidate_tree_hash=$CANDIDATE_TREE_HASH
run_id=$RUN_ID
bundle_stage=measurement
release_verdict=PROHIBITED
strix=PROHIBITED
EOF
(cd "$ROOT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
mkdir -p "$DEST"
ARCHIVE="$DEST/track-a-measurement-$RUN_ID.tar.gz"
tar -C "$STAGE" -czf "$ARCHIVE" "$(basename "$ROOT")"
sha256sum "$ARCHIVE" >"$ARCHIVE.sha256"
printf '%s\n' "$ARCHIVE"

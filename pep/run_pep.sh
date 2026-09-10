#!/usr/bin/env bash
# Production PEP verification run. Local containers only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
P2B="$ROOT/phase2b"
CTRL="$HERE/control"; OUT="$HERE/out"; CAPKI="$HERE/capki"; SBXCA="$HERE/sandbox_ca"
# $OUT is bind-mounted read-write into the sandbox. Evidence is copied out of
# it into $COL before being stamped or verified, so the control plane never
# publishes this execution's run_id into a directory the sandbox can read.
COL="$HERE/collected"
NET_EG=pep_egress; NET_A=pep_prog_a
# Control-plane-issued execution id. Never transmitted to the sandbox.
RUN_ID="run-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export PEP_RUN_ID="$RUN_ID"
echo "== run_id: $RUN_ID =="

echo "== teardown =="
docker rm -f pep_gw pep_allowed pep_evil pep_rebind pep_slow pep_badcert pep_sbx >/dev/null 2>&1 || true
docker network rm $NET_EG $NET_A >/dev/null 2>&1 || true
rm -rf "$CTRL" "$OUT" "$CAPKI" "$SBXCA" "$COL"
mkdir -p "$CTRL" "$OUT" "$CAPKI/leaf" "$SBXCA" "$COL"

echo "== upstream PKI =="
"$P2B/gen_certs.sh" >/dev/null
C="$P2B/certs"

echo "== networks =="
docker network create --subnet 172.29.0.0/24 $NET_EG >/dev/null
docker network create --internal --subnet 172.31.0.0/24 $NET_A >/dev/null

t() { docker run -d --name "pep_$1" --network $NET_EG --ip "$2" \
  -e TARGET_NAME="$1" -e TARGET_PORT=443 -e SLOW_SECONDS=25 -e BIG_BYTES=2097152 \
  -e TARGET_CERT="/certs/$4/$3.crt" -e TARGET_KEY="/certs/$4/$3.key" \
  -e REDIRECT_TO="https://evil.lab/pwned" \
  -v "$P2B/target_https.py:/srv.py:ro" -v "$C:/certs:ro" \
  strixlab/vulnlab:1.0 python3 /srv.py >/dev/null; }
echo "== targets =="
t allowed 172.29.0.20 allowed.lab up
t evil    172.29.0.30 evil.lab    up
t rebind  172.29.0.50 rebind.lab  up
t slow    172.29.0.60 slow.lab    up
t badcert 172.29.0.70 badcert.lab up

NOW=$(date +%s)
cat > "$CTRL/policy.json" <<JSON
{
  "networks": { "172.31.0.0/24": "prog_a" },
  "programs": {
    "prog_a": {
      "authorization": { "program_id": "prog_a", "verified_by": "pep-verification",
        "verified_at": $((NOW-60)), "expires_at": $((NOW+86400)), "status": "active" },
      "scope_allow": ["allowed.lab","*.allowed.lab","rebind.lab","slow.lab","badcert.lab"],
      "scope_deny": [],
      "allowed_ports": [443],
      "allowed_methods": ["GET","POST"],
      "allow_connect": true,
      "allowed_families": ["ipv4","ipv6"],
      "private_ip_exemptions": ["172.29.0.20","172.29.0.30","172.29.0.50",
                                "172.29.0.60","172.29.0.70"],
      "authorized_ips": ["172.29.0.20","172.29.0.50","172.29.0.60","172.29.0.70"],
      "explicit_ip_allowlist": [],
      "max_requests": 100000,
      "asset_max_requests": {}
    }
  },
  "credentials": {
    "cred_alpha": { "program_id": "prog_a", "asset_id": "a1",
                    "destinations": ["allowed.lab","neverseen.allowed.lab"],
                    "secret": "S3CRET-PROD-7d41" },
    "cred_beta":  { "program_id": "other_prog", "asset_id": "a1",
                    "destinations": ["allowed.lab"], "secret": "S3CRET-OTHER-22bb" }
  },
  "dns_zone": {
    "allowed.lab":           { "v4": ["172.29.0.20"] },
    "neverseen.allowed.lab": { "v4": ["172.29.0.20"] },
    "evil.lab":              { "v4": ["172.29.0.30"] },
    "slow.lab":              { "v4": ["172.29.0.60"] },
    "badcert.lab":           { "v4": ["172.29.0.70"] },
    "rebind.lab":  { "sequence": [ { "v4": ["172.29.0.50"] }, { "v4": ["172.29.0.30"] } ] }
  }
}
JSON

echo "== PEP (mints its own interception CA on first start) =="
docker run -d --name pep_gw --network $NET_EG --ip 172.29.0.10 \
  -e PEP_CONTROL=/control -e PEP_CA_DIR=/capki -e PEP_LEAF_DIR=/capki/leaf \
  -e PEP_UPSTREAM_CA=/certs/upca.crt -e PEP_MAX_CONNECTIONS=16 \
  -e PEP_RUN_ID="$RUN_ID" \
  -v "$ROOT/pep:/app/pep:ro" -v "$CTRL:/control" -v "$CAPKI:/capki" -v "$C:/certs:ro" \
  strixlab/vulnlab:1.0 python3 /app/pep/server.py >/dev/null
docker network connect --ip 172.31.0.10 $NET_A pep_gw
sleep 4
docker logs pep_gw 2>&1 | head -4 | sed 's/^/  /'

echo "== hand the sandbox ONLY the public CA cert =="
cp "$CAPKI/ca.crt" "$SBXCA/ca.crt"
ls -la "$SBXCA" | tail -2 | sed 's/^/  /'

docker run -d --name pep_sbx --network $NET_A --ip 172.31.0.50 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$HERE/pep_client.py:/client.py:ro" -v "$SBXCA:/ca:ro" -v "$OUT:/out" \
  strixlab/adversary:1.0 sleep 3600 >/dev/null
sleep 1

( while [ ! -f "$OUT/ARM_KILL" ]; do sleep 0.3; done; touch "$CTRL/STOP_ALL"; \
  echo "[control-plane] STOP_ALL armed" ) &
W=$!

echo
echo "================= PRODUCTION PEP VERIFICATION ================="
# Parity with the dual-stack gate: PP10 asserts the denial names the IP the
# binding flipped TO. Without this the row falls back to a weaker "any
# IP_NOT_AUTHORIZED" match, and the two harnesses stop testing the same thing.
docker exec -e GW_IP=172.31.0.10 -e REBIND_SECOND_IP=172.29.0.30 \
  pep_sbx python3 /client.py || true
kill $W 2>/dev/null || true

# R-7: the sandbox never learns the run_id, so it cannot bind its own output to
# this execution. The CONTROL PLANE does the binding, here, after collection.
docker rm -f pep_sbx >/dev/null 2>&1     # sandbox retired before evidence work
python3 "$HERE/collect_artifacts.py" "$COL" \
        "$OUT/pep_results.json" "$OUT/pep_kill.json" || true
python3 "$HERE/stamp_artifacts.py" "$RUN_ID" \
        "$COL/pep_results.json" "$COL/pep_kill.json" 2>/dev/null || true

echo
echo "-------- host-side kill-switch evidence (PP18) --------"
# Same standard as Layer B's B9: the client's socket error is NOT proof. The
# PEP's own audit must show a KILL_SWITCH whose terminated_conn_ids contains the
# conn_id of the connection identified by this run's nonce.
python3 "$HERE/verify_pp18.py" "$CTRL/audit.jsonl" "$RUN_ID" "$COL/pp18.json"
rm -f "$CTRL/STOP_ALL"

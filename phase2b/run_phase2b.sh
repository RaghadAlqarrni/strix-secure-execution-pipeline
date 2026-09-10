#!/usr/bin/env bash
# Phase 2b — TLS-interception boundary proof. Local containers only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
P2A="$(cd "$HERE/../phase2a" && pwd)"
CTRL="$HERE/control"; OUT="$HERE/out"; C="$HERE/certs"
NET_EG=p2b_egress; NET_A=p2b_prog_a; NET_B=p2b_prog_b

echo "== teardown =="
docker rm -f p2b_gw p2b_allowed p2b_evil p2b_other p2b_rebind p2b_slow p2b_badcert \
  p2b_sbx_a >/dev/null 2>&1 || true
docker network rm $NET_EG $NET_A $NET_B >/dev/null 2>&1 || true
rm -rf "$CTRL" "$OUT"; mkdir -p "$CTRL" "$OUT"

echo "== PKI =="
"$HERE/gen_certs.sh"

echo "== networks =="
docker network create --subnet 172.29.0.0/24 $NET_EG >/dev/null
docker network create --internal --subnet 172.31.0.0/24 $NET_A >/dev/null
docker network create --internal --subnet 172.32.0.0/24 $NET_B >/dev/null

start_target() { # name ip certhost certdir
  docker run -d --name "p2b_$1" --network $NET_EG --ip "$2" \
    -e TARGET_NAME="$1" -e TARGET_PORT=443 -e SLOW_SECONDS=25 \
    -e TARGET_CERT="/certs/$4/$3.crt" -e TARGET_KEY="/certs/$4/$3.key" \
    -e REDIRECT_TO="https://evil.lab/pwned" \
    -v "$HERE/target_https.py:/srv.py:ro" -v "$C:/certs:ro" \
    strixlab/vulnlab:1.0 python3 /srv.py >/dev/null
}
echo "== HTTPS targets =="
start_target allowed 172.29.0.20 allowed.lab up
start_target evil    172.29.0.30 evil.lab    up
start_target other   172.29.0.40 other.lab   up
start_target rebind  172.29.0.50 rebind.lab  up
start_target slow    172.29.0.60 slow.lab    up
start_target badcert 172.29.0.70 badcert.lab up   # cert signed by the ROGUE ca

NOW=$(date +%s)
cat > "$CTRL/policy.json" <<JSON
{
  "networks": { "172.31.0.0/24": "prog_a", "172.32.0.0/24": "prog_b" },
  "programs": {
    "prog_a": {
      "authorization": { "program_id": "prog_a", "verified_by": "phase2b-harness",
        "verified_at": $((NOW-60)), "expires_at": $((NOW+86400)), "status": "active" },
      "scope_allow": ["allowed.lab","other.lab","rebind.lab","slow.lab","badcert.lab"],
      "scope_deny": [],
      "allowed_ports": [443],
      "allowed_methods": ["GET","POST"],
      "allow_connect": true,
      "private_ip_exemptions": ["172.29.0.20","172.29.0.30","172.29.0.40",
                                "172.29.0.50","172.29.0.60","172.29.0.70"],
      "authorized_ips": ["172.29.0.20","172.29.0.40","172.29.0.50",
                         "172.29.0.60","172.29.0.70"],
      "explicit_ip_allowlist": [],
      "max_requests": 500,
      "asset_max_requests": {}
    },
    "prog_b": {
      "authorization": { "program_id": "prog_b", "verified_by": "phase2b-harness",
        "verified_at": $((NOW-60)), "expires_at": $((NOW+86400)), "status": "active" },
      "scope_allow": ["allowed.lab"], "allowed_ports": [443],
      "allowed_methods": ["GET"], "allow_connect": true,
      "private_ip_exemptions": ["172.29.0.20"], "authorized_ips": ["172.29.0.20"],
      "max_requests": 50
    }
  },
  "credentials": {
    "cred_alpha": { "program_id": "prog_a", "asset_id": "a1",
                    "destinations": ["allowed.lab"], "secret": "S3CRET-ALPHA-9f2c" },
    "cred_beta":  { "program_id": "prog_b", "asset_id": "a1",
                    "destinations": ["allowed.lab"], "secret": "S3CRET-BETA-11ab" }
  },
  "dns_zone": {
    "allowed.lab": ["172.29.0.20"],
    "evil.lab":    ["172.29.0.30"],
    "other.lab":   ["172.29.0.40"],
    "slow.lab":    ["172.29.0.60"],
    "badcert.lab": ["172.29.0.70"],
    "rebind.lab":  { "sequence": [["172.29.0.50"], ["172.29.0.30"]] }
  }
}
JSON

echo "== gateway (full PKI incl. CA private key) =="
docker run -d --name p2b_gw --network $NET_EG --ip 172.29.0.10 \
  -e PDP_CERTS=/certs -e PDP_CONTROL_IP=172.29.0.10 -e PDP_CONTROL_PORT=9000 \
  -v "$P2A/policy_gw.py:/gw/policy_gw.py:ro" \
  -v "$HERE/policy_gw_tls.py:/gw/policy_gw_tls.py:ro" \
  -v "$C:/certs:ro" -v "$CTRL:/control" \
  strixlab/vulnlab:1.0 python3 /gw/policy_gw_tls.py >/dev/null
docker network connect --ip 172.31.0.10 $NET_A p2b_gw
docker network connect --ip 172.32.0.10 $NET_B p2b_gw
sleep 3

echo "== sandbox (gets ONLY the public CA cert — never the CA key) =="
docker run -d --name p2b_sbx_a --network $NET_A --ip 172.31.0.50 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$HERE/adversary_tls.py:/adversary_tls.py:ro" \
  -v "$C/sandbox:/ca:ro" -v "$OUT:/out" \
  strixlab/adversary:1.0 sleep 3600 >/dev/null
sleep 1

# host-side arming of the kill switch (control plane, outside the sandbox)
( while [ ! -f "$OUT/ARM_KILL" ]; do sleep 0.3; done; touch "$CTRL/STOP_ALL"; \
  echo "[control-plane] STOP_ALL armed" ) &
WATCHER=$!

echo
echo "================= PHASE 2B ADVERSARIAL MATRIX ================="
docker exec -e GW_IP=172.31.0.10 -e GW_EGRESS_IP=172.29.0.10 -e ALLOWED_IP=172.29.0.20 \
  p2b_sbx_a python3 /adversary_tls.py || true
kill $WATCHER 2>/dev/null || true
rm -f "$CTRL/STOP_ALL"

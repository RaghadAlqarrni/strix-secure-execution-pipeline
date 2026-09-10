#!/usr/bin/env bash
# Phase 2a — Security Boundary Proof harness.
# Builds the topology from ARCHITECTURE_REVIEW.md §3 and runs the adversarial matrix.
# Local containers only. No real targets, no real credentials, no provider APIs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTRL="$HERE/control"
OUT="$HERE/out"

NET_EG=p2a_egress          # normal bridge: gateway's external leg + targets
NET_A=p2a_prog_a           # internal: program A sandbox
NET_B=p2a_prog_b           # internal: program B sandbox (expired authorization)

echo "== teardown any previous run =="
docker rm -f p2a_gw p2a_allowed p2a_evil p2a_other p2a_sbx_a p2a_sbx_b >/dev/null 2>&1 || true
docker network rm $NET_EG $NET_A $NET_B >/dev/null 2>&1 || true
rm -rf "$CTRL" "$OUT"; mkdir -p "$CTRL" "$OUT"

echo "== build adversary image (local base, no registry) =="
cp -f /bin/busybox "$HERE/busybox"
cat > "$HERE/Dockerfile.adv" <<'DOCKER'
FROM strixlab/vulnlab:1.0
COPY busybox /bin/busybox
DOCKER
docker build -q -f "$HERE/Dockerfile.adv" -t strixlab/adversary:1.0 "$HERE" >/dev/null
rm -f "$HERE/busybox" "$HERE/Dockerfile.adv"

echo "== networks =="
docker network create --subnet 172.29.0.0/24 $NET_EG >/dev/null
docker network create --internal --subnet 172.31.0.0/24 $NET_A >/dev/null
docker network create --internal --subnet 172.32.0.0/24 $NET_B >/dev/null

echo "== targets (on egress net; sandboxes must NOT reach these directly) =="
docker run -d --name p2a_allowed --network $NET_EG --ip 172.29.0.20 \
  -e TARGET_NAME=allowed -e TARGET_PORT=80 -e REDIRECT_TO=http://evil.lab/pwned \
  -v "$HERE/target_srv.py:/srv.py:ro" strixlab/vulnlab:1.0 python3 /srv.py >/dev/null
docker run -d --name p2a_evil --network $NET_EG --ip 172.29.0.30 \
  -e TARGET_NAME=evil -e TARGET_PORT=80 \
  -v "$HERE/target_srv.py:/srv.py:ro" strixlab/vulnlab:1.0 python3 /srv.py >/dev/null
docker run -d --name p2a_other --network $NET_EG --ip 172.29.0.40 \
  -e TARGET_NAME=other -e TARGET_PORT=80 \
  -v "$HERE/target_srv.py:/srv.py:ro" strixlab/vulnlab:1.0 python3 /srv.py >/dev/null

ALLOWED_IP=172.29.0.20; EVIL_IP=172.29.0.30; OTHER_IP=172.29.0.40

echo "== policy (default-deny) =="
NOW=$(date +%s)
cat > "$CTRL/policy.json" <<JSON
{
  "networks": { "172.31.0.0/24": "prog_a", "172.32.0.0/24": "prog_b" },
  "programs": {
    "prog_a": {
      "authorization": { "program_id": "prog_a", "verified_by": "phase2a-harness",
        "verified_at": $((NOW-60)), "expires_at": $((NOW+86400)), "status": "active" },
      "scope_allow": ["allowed.lab", "*.allowed.lab", "rebind.lab", "other.lab",
                      "linklocal.lab", "internalonly.lab", "poisoned.lab"],
      "scope_deny":  ["blocked.allowed.lab"],
      "allowed_ports": [80],
      "allowed_methods": ["GET", "POST"],
      "allow_connect": true,
      "private_ip_exemptions": ["$ALLOWED_IP", "$EVIL_IP", "$OTHER_IP"],
      "authorized_ips": ["$ALLOWED_IP", "$OTHER_IP"],
      "explicit_ip_allowlist": [],
      "max_requests": 200,
      "asset_max_requests": { "a_budget": 2 }
    },
    "prog_b": {
      "authorization": { "program_id": "prog_b", "verified_by": "phase2a-harness",
        "verified_at": $((NOW-7200)), "expires_at": $((NOW-3600)), "status": "active" },
      "scope_allow": ["allowed.lab"],
      "allowed_ports": [80], "allowed_methods": ["GET"],
      "private_ip_exemptions": ["$ALLOWED_IP"], "authorized_ips": ["$ALLOWED_IP"],
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
    "allowed.lab": ["$ALLOWED_IP"],
    "blocked.allowed.lab": ["$ALLOWED_IP"],
    "other.lab": ["$OTHER_IP"],
    "evil.lab": ["$EVIL_IP"],
    "linklocal.lab": ["169.254.169.254"],
    "internalonly.lab": ["10.0.0.5"],
    "poisoned.lab": ["$ALLOWED_IP", "169.254.169.254"],
    "rebind.lab": { "sequence": [["$ALLOWED_IP"], ["$EVIL_IP"]] }
  }
}
JSON

echo "== gateway (dual-homed: egress + both program nets) =="
docker run -d --name p2a_gw --network $NET_EG --ip 172.29.0.10 \
  -v "$HERE/policy_gw.py:/gw.py:ro" -v "$CTRL:/control" \
  strixlab/vulnlab:1.0 python3 /gw.py >/dev/null
docker network connect --ip 172.31.0.10 $NET_A p2a_gw
docker network connect --ip 172.32.0.10 $NET_B p2a_gw
sleep 2

echo "== sandboxes (worst case: NET_ADMIN + NET_RAW, as Strix ships today) =="
docker run -d --name p2a_sbx_a --network $NET_A --ip 172.31.0.50 \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  --add-host host.docker.internal:host-gateway \
  -v "$HERE/adversary.py:/adversary.py:ro" -v "$OUT:/out" \
  strixlab/adversary:1.0 sleep 3600 >/dev/null
docker run -d --name p2a_sbx_b --network $NET_B --ip 172.32.0.50 \
  -v "$HERE/adversary.py:/adversary.py:ro" -v "$OUT:/out" \
  strixlab/adversary:1.0 sleep 3600 >/dev/null
sleep 1

echo "== gateway reachability check =="
docker exec p2a_gw python3 -c "
import socket
for ip in ['$ALLOWED_IP','$EVIL_IP']:
    s=socket.create_connection((ip,80),3); s.close(); print('  gw ->',ip,'OK')"

echo
echo "================= ADVERSARIAL MATRIX (program A sandbox) ================="
docker exec -e GW_IP=172.31.0.10 -e ALLOWED_IP=$ALLOWED_IP -e EVIL_IP=$EVIL_IP \
  -e PEER_IP=172.32.0.50 p2a_sbx_a python3 /adversary.py all

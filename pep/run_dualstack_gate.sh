#!/usr/bin/env bash
# ============================================================================
# DUAL-STACK RELEASE GATE for the production PEP.
#
# Runs the complete gate and emits ONE verdict:
#     Layer A / Layer B / IPv4 regression / IPv6 regression
#     -> IPv6 GATE: PASSED|NOT PASSED
# This script never authorizes Strix. In validation mode it cannot issue a
# release verdict either.
#
# REFUSES TO RUN on a host without IPv6. Absence of IPv6 is evidence that the
# gate cannot be tested — never evidence that it is safe.
# Local containers only. Does not touch Strix.
# ============================================================================
set -uo pipefail
VALIDATION_ONLY="${TRACK_A_VALIDATION_ONLY:-0}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
P2B="$ROOT/phase2b"
CTRL="$HERE/control"; OUT="$HERE/out"; CAPKI="$HERE/capki"; SBXCA="$HERE/sandbox_ca"
B7DIR="$HERE/b7_runtime"
# Evidence is processed HERE, never in $OUT. $OUT is bind-mounted read-write into
# the sandbox (it has to be — that is how the sandbox reports), so any artifact
# left sitting there is writable by the measured party, and anything the control
# plane writes there is READABLE by it. Artifacts are copied out of $OUT into
# $COL before they are stamped, verified, or audited.
COL="$HERE/collected"
NET_EG=gate_egress; NET_A=gate_prog_a
# Control-plane-issued execution id. Never transmitted to the sandbox; the PEP
# stamps it on every audit record so evidence can be scoped to THIS execution.
RUN_ID="run-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
export PEP_RUN_ID="$RUN_ID"
V6_EG="fd00:9a17:e9:1::/64"      # ULA — must be listed in private_ip_exemptions
V6_IN="fd00:9a17:e9:2::/64"
GW6_EG="fd00:9a17:e9:1::10";  GW6_IN="fd00:9a17:e9:2::10"
T6_ALLOWED="fd00:9a17:e9:1::20"; T6_EVIL="fd00:9a17:e9:1::30"
T6_SLOW="fd00:9a17:e9:1::60"
T6_REBIND="fd00:9a17:e9:1::50"; T6_BADCERT="fd00:9a17:e9:1::70"
REBIND_SECOND_IP="172.29.0.30"   # asserted by PP10: the flipped-to, unauthorized IP
SBX6="fd00:9a17:e9:2::50"

red()  { printf "\033[31m%s\033[0m\n" "$*"; }
grn()  { printf "\033[32m%s\033[0m\n" "$*"; }

echo "== environment gate =="
if [ "$VALIDATION_ONLY" = "1" ]; then
  echo "  MODE: TRACK-A REMEDIATION VALIDATION ONLY"
  echo "  This run cannot issue a release verdict or authorize Strix."
fi
FAIL=""
[ -f /proc/net/if_inet6 ] || FAIL="no /proc/net/if_inet6 (IPv6 stack not initialized)"
[ -d /proc/sys/net/ipv6 ] || FAIL="${FAIL:-no /proc/sys/net/ipv6 sysctl tree}"
grep -q 'ipv6.disable=1' /proc/cmdline 2>/dev/null && FAIL="kernel booted with ipv6.disable=1"
if [ -n "$FAIL" ]; then
  echo
  red "  REFUSING TO RUN: $FAIL"
  echo
  echo "  Layer A:          not run"
  echo "  Layer B:          BLOCKED_ENV"
  echo "  IPv4 regression:  not run"
  echo "  IPv6 regression:  BLOCKED_ENV"
  echo "  ========================"
  red "  IPv6 GATE: NOT PASSED"
  red "  IPv6 STATUS: UNKNOWN / RELEASE BLOCKER"
  red "  PEP: NOT ELIGIBLE FOR STRIX OBSERVATION"
  echo
  echo "  Required: a host booted WITHOUT ipv6.disable=1, with dockerd started"
  echo "  as: dockerd --ipv6 --ip6tables=true  (see DUALSTACK_ENV.md)"
  exit 1
fi
grn "  IPv6 runtime present"
echo "  run_id: $RUN_ID"

echo "== teardown =="
docker rm -f gate_gw gate_allowed gate_evil gate_slow gate_badcert gate_rebind gate_sbx >/dev/null 2>&1
docker network rm $NET_EG $NET_A >/dev/null 2>&1
rm -rf "$CTRL" "$OUT" "$CAPKI" "$SBXCA" "$COL" "$B7DIR"
mkdir -p "$CTRL" "$OUT" "$CAPKI/leaf" "$SBXCA" "$COL" "$B7DIR"
{
  echo "run_id=$RUN_ID"
  echo "captured_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  uname -a
  docker version 2>&1
  docker info 2>&1
} >"$COL/environment.txt"

echo "== upstream PKI =="
C="$P2B/certs"
if ! bash "$P2B/gen_certs.sh" >/dev/null 2>&1; then
  red "  REFUSING TO RUN: upstream PKI generation failed"
  exit 1
fi
for required in upca.crt up/allowed.lab.crt up/allowed.lab.key \
                up/slow.lab.crt up/slow.lab.key; do
  if [ ! -s "$C/$required" ]; then
    red "  REFUSING TO RUN: missing/empty PKI artifact: $C/$required"
    exit 1
  fi
done

echo "== dual-stack networks =="
docker network create --subnet 172.29.0.0/24 --ipv6 --subnet "$V6_EG" $NET_EG >/dev/null || exit 1
docker network create --internal --subnet 172.31.0.0/24 --ipv6 --subnet "$V6_IN" $NET_A >/dev/null || exit 1

t() { docker run -d --name "gate_$1" --network $NET_EG --ip "$2" --ip6 "$3" \
  -e TARGET_NAME="$1" -e TARGET_PORT=443 -e SLOW_SECONDS=25 -e BIG_BYTES=2097152 \
  -e TARGET_CERT="/certs/up/$4.crt" -e TARGET_KEY="/certs/up/$4.key" \
  -e REDIRECT_TO="https://evil.lab/pwned" \
  -v "$P2B/target_https.py:/srv.py:ro" -v "$C:/certs:ro" \
  strixlab/vulnlab:1.0 python3 /srv.py >/dev/null; }
echo "== dual-stack targets =="
# TOPOLOGY PARITY WITH run_pep.sh.
# The gate reuses pep_client.py verbatim but used to provision only three of the
# targets that suite depends on. rebind.lab and badcert.lab were missing, so PP9
# failed and PP10 "passed" on an OUT_OF_SCOPE denial that had nothing to do with
# rebinding protection. A test must never pass because its target was absent.
t allowed 172.29.0.20 "$T6_ALLOWED" allowed.lab
t evil    172.29.0.30 "$T6_EVIL"    evil.lab
t slow    172.29.0.60 "$T6_SLOW"    slow.lab
t rebind  172.29.0.50 "$T6_REBIND"  rebind.lab
t badcert 172.29.0.70 "$T6_BADCERT" badcert.lab

NOW=$(date +%s)
cat > "$CTRL/policy.json" <<JSON
{
  "networks": { "172.31.0.0/24": "prog_a", "$V6_IN": "prog_a" },
  "programs": {
    "prog_a": {
      "authorization": { "program_id": "prog_a", "verified_by": "dualstack-gate",
        "verified_at": $((NOW-60)), "expires_at": $((NOW+86400)), "status": "active" },
      "scope_allow": ["allowed.lab","*.allowed.lab","slow.lab","rebind.lab",
                      "badcert.lab","allowed6.lab","slow6.lab"],
      "scope_deny": [], "allowed_ports": [443],
      "allowed_methods": ["GET","POST"], "allow_connect": true,
      "allowed_families": ["ipv4","ipv6"],
      "private_ip_exemptions": ["172.29.0.20","172.29.0.30","172.29.0.50",
                                "172.29.0.60","172.29.0.70",
                                "$T6_ALLOWED","$T6_EVIL","$T6_SLOW",
                                "$T6_REBIND","$T6_BADCERT"],
      "authorized_ips": ["172.29.0.20","172.29.0.50","172.29.0.60","172.29.0.70",
                         "$T6_ALLOWED","$T6_SLOW"],
      "explicit_ip_allowlist": [], "max_requests": 100000, "asset_max_requests": {}
    }
  },
  "credentials": {
    "cred_alpha": { "program_id": "prog_a", "asset_id": "a1",
                    "destinations": ["allowed.lab","neverseen.allowed.lab",
                                     "allowed6.lab"],
                    "secret": "S3CRET-GATE-01" },
    "cred_beta":  { "program_id": "other_prog", "asset_id": "a1",
                    "destinations": ["allowed.lab"],
                    "secret": "S3CRET-OTHER-22bb" }
  },
  "dns_zone": {
    "allowed.lab":           { "v4": ["172.29.0.20"] },
    "neverseen.allowed.lab": { "v4": ["172.29.0.20"] },
    "evil.lab":              { "v4": ["172.29.0.30"] },
    "slow.lab":     { "v4": ["172.29.0.60"] },
    "badcert.lab":  { "v4": ["172.29.0.70"] },
    "rebind.lab":   { "sequence": [ { "v4": ["172.29.0.50"] },
                                    { "v4": ["$REBIND_SECOND_IP"] } ] },
    "allowed6.lab": { "v6": ["$T6_ALLOWED"] },
    "slow6.lab":    { "v6": ["$T6_SLOW"] },
    "evil6.lab":    { "v6": ["$T6_EVIL"] }
  }
}
JSON

echo "== PEP =="
docker run -d --name gate_gw --network $NET_EG --ip 172.29.0.10 --ip6 "$GW6_EG" \
  -e PEP_CONTROL=/control -e PEP_CA_DIR=/capki -e PEP_LEAF_DIR=/capki/leaf \
  -e PEP_UPSTREAM_CA=/certs/upca.crt -e PEP_MAX_CONNECTIONS=32 \
  -e PEP_RUN_ID="$RUN_ID" \
  -v "$ROOT/pep:/app/pep:ro" -v "$CTRL:/control" -v "$CAPKI:/capki" -v "$C:/certs:ro" \
  strixlab/vulnlab:1.0 python3 /app/pep/server.py >/dev/null
docker network connect --ip 172.31.0.10 --ip6 "$GW6_IN" $NET_A gate_gw
sleep 4
cp "$CAPKI/ca.crt" "$SBXCA/ca.crt"

docker run -d --name gate_sbx --network $NET_A --ip 172.31.0.50 --ip6 "$SBX6" \
  --cap-add NET_ADMIN --cap-add NET_RAW \
  -v "$HERE/pep_client.py:/client.py:ro" -v "$HERE/ipv6_transport.py:/v6.py:ro" \
  -v "$HERE/b7_udp_sender.py:/sender.py:ro" -v "$B7DIR:/b7:ro" \
  -v "$SBXCA:/ca:ro" -v "$OUT:/out" \
  strixlab/adversary:1.0 sleep 3600 >/dev/null
sleep 1

( while [ ! -f "$OUT/ARM_KILL" ]; do sleep 0.3; done; touch "$CTRL/STOP_ALL"; ) &
W=$!

echo; echo "===================== IPv4 REGRESSION ====================="
docker exec -e GW_IP=172.31.0.10 -e REBIND_SECOND_IP="$REBIND_SECOND_IP" \
  gate_sbx python3 /client.py
rm -f "$CTRL/STOP_ALL" "$OUT/ARM_KILL"; kill $W 2>/dev/null

echo; echo "================== B7 HOST UDP EVIDENCE ==================="
RUN_ID="$RUN_ID" NET_EG="$NET_EG" NET_A="$NET_A" SBX=gate_sbx \
  SBX6="$SBX6" B7_DIR="$B7DIR" B7_TARGET6="fd00:9a17:e9:1::80" \
  B7_CONTROL6="fd00:9a17:e9:1::81" \
  bash "$HERE/run_b7_host_harness.sh"
B7_HARNESS_RC=$?
if [ "$B7_HARNESS_RC" != 0 ] && [ ! -s "$B7DIR/b7_advisory.json" ]; then
  printf '{"status":"APPARATUS_FAILURE","ready_for_e9":false,"measurement_seen":false,"evidence_sha256":""}\n' \
    >"$B7DIR/b7_advisory.json"
fi

( while [ ! -f "$OUT/ARM_KILL" ]; do sleep 0.3; done; touch "$CTRL/STOP_ALL"; ) &
W=$!
echo; echo "================== IPv6 TRANSPORT (LAYER B) ================"
docker exec -e GW6="$GW6_IN" -e TGT6="$T6_ALLOWED" gate_sbx python3 /v6.py
rm -f "$CTRL/STOP_ALL"; kill $W 2>/dev/null

# ---------------------------------------------------------------- collection
# The sandbox has no further role, so it is retired BEFORE ANY of its evidence
# is collected. Collecting the IPv4 artifacts earlier — while the container was
# still alive for the Layer B phase — would have left a window in which it could
# rewrite $OUT behind the collector. Nothing is read out of $OUT until here.
echo; echo "-------- retire sandbox, collect and bind evidence --------"
docker rm -f gate_sbx >/dev/null 2>&1
# R-7: collect first, THEN bind. Stamping inside $OUT would have published this
# execution's run_id into a directory the sandbox can read, handing the measured
# party the very value that scopes its own evidence.
python3 "$HERE/collect_artifacts.py" "$COL" \
        "$OUT/pep_results.json" "$OUT/pep_kill.json" \
        "$OUT/ipv6_layerb.json" "$OUT/b6_client.json" || true
python3 "$HERE/stamp_artifacts.py" "$RUN_ID" \
        "$COL/pep_results.json" "$COL/pep_kill.json" \
        "$COL/ipv6_layerb.json" "$COL/b6_client.json" 2>/dev/null || true
if [ -s "$B7DIR/b7_evidence.json" ]; then
  cp "$B7DIR/b7_evidence.json" "$COL/b7_evidence.json"
fi
# Preserve the raw, host-owned apparatus output before runtime teardown.  E9
# consumes only the normalized evidence above; auditors receive both sources.
mkdir -p "$COL/b7_raw"
cp -a "$B7DIR/." "$COL/b7_raw/"
V4_PASS=$(python3 -c "import json;d=json.load(open('$COL/pep_results.json'));print(d['passed'])" 2>/dev/null || echo 0)
V4_TOT=$(python3 -c "import json;d=json.load(open('$COL/pep_results.json'));print(d['total'])" 2>/dev/null || echo 0)

echo; echo "-------- host-side Layer B evidence (B8/B9) --------"
# Verified against the PEP's own audit, which the sandbox cannot read or forge.
python3 "$HERE/verify_layerb_audit.py" "$CTRL/audit.jsonl" \
        "$COL/ipv6_layerb.json" "$RUN_ID" "$COL/b6_client.json"

echo; echo "-------- host-side IPv4 kill evidence (PP18) --------"
# R-1: PP18 was previously absent from this gate entirely, leaving E6 to trust a
# partial-byte count the SANDBOX wrote about itself. Re-derived from raw audit.
python3 "$HERE/verify_pp18.py" "$CTRL/audit.jsonl" "$RUN_ID" "$COL/pp18.json"
PP18_RC=$?

echo; echo "===================== LAYER A + VERDICT ==================="
ACC_OUT="$COL/ipv6_acceptance.json" LAYERB_RESULTS="$COL/ipv6_layerb.json" \
  PEP_RUN_ID="$RUN_ID" python3 "$HERE/ipv6_acceptance.py" >"$COL/acc.txt" 2>&1
sed -n '/Layer A (policy/,$p' "$COL/acc.txt"

A_P=$(python3 -c "import json;d=json.load(open('$COL/ipv6_acceptance.json'));print(d['layer_a_passed'])")
A_T=$(python3 -c "import json;d=json.load(open('$COL/ipv6_acceptance.json'));print(d['layer_a_total'])")
B_P=$(python3 -c "import json;d=json.load(open('$COL/ipv6_acceptance.json'));print(d['layer_b_passed'])")
B_T=$(python3 -c "import json;d=json.load(open('$COL/ipv6_acceptance.json'));print(d['layer_b_total'])")

echo; echo "-------- evidence audit (the check on the checker) --------"
# A green summary is a claim the harness makes about itself. This re-derives the
# facts from the PEP's raw audit log and refuses to certify a pass that is not
# actually supported by evidence.
python3 "$HERE/audit_gate_evidence.py" \
  --acceptance "$COL/ipv6_acceptance.json" --layerb "$COL/ipv6_layerb.json" \
  --audit "$CTRL/audit.jsonl" --run-id "$RUN_ID" --v4 "$COL/pep_results.json" \
  --b7-evidence "$COL/b7_evidence.json"
EVIDENCE_RC=$?

echo
echo "  Layer A:          $A_P/$A_T"
echo "  Layer B:          $B_P/$B_T"
echo "  IPv4 regression:  $V4_PASS/$V4_TOT"
if [ "$B_P" = "$B_T" ]; then echo "  IPv6 regression:  PASS"; else echo "  IPv6 regression:  FAIL"; fi
if [ "${PP18_RC:-1}" = "0" ]; then echo "  PP18 (host):      PROVEN"; \
else echo "  PP18 (host):      NOT PROVEN"; fi
if [ "${EVIDENCE_RC:-1}" = "0" ]; then echo "  Evidence audit:   CERTIFIED"; \
else echo "  Evidence audit:   NOT CERTIFIED"; fi
echo "  ========================"
if [ "$A_P" = "$A_T" ] && [ "$B_P" = "$B_T" ] && [ "$V4_PASS" = "$V4_TOT" ] \
   && [ "$V4_TOT" != "0" ] && [ "${EVIDENCE_RC:-1}" = "0" ] \
   && [ "${PP18_RC:-1}" = "0" ]; then
  if [ "$VALIDATION_ONLY" = "1" ]; then
    grn "  TRACK-A VALIDATION: PASSED (not a release verdict)"
  else
    grn "  IPv6 GATE: PASSED"
    grn "  TRACK A GATE: PASSED (Strix remains prohibited pending Track B + owner order)"
  fi
  RC=0
else
  if [ "$VALIDATION_ONLY" = "1" ]; then
    red "  TRACK-A VALIDATION: NOT PASSED"
  else
    red "  IPv6 GATE: NOT PASSED"
  fi
  red "  IPv6 STATUS: UNKNOWN / RELEASE BLOCKER"
  red "  TRACK A GATE: NOT PASSED — Strix prohibited"
  RC=1
fi
echo
docker rm -f gate_gw gate_allowed gate_evil gate_slow gate_rebind gate_badcert gate_sbx >/dev/null 2>&1
docker network rm $NET_EG $NET_A >/dev/null 2>&1
python3 - "$COL/teardown.json" "$RUN_ID" "$NET_EG" "$NET_A" <<'PY'
import json, subprocess, sys, time
out, run_id, *nets = sys.argv[1:]
containers = ["gate_gw", "gate_allowed", "gate_evil", "gate_slow",
              "gate_rebind", "gate_badcert", "gate_sbx"]
def absent(kind, name):
    cmd = ["docker", kind, "inspect", name]
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0
doc = {"schema":"strix-track-a-teardown-v1", "run_id":run_id,
       "captured_unix_ns":time.time_ns(),
       "containers":{n:absent("container", n) for n in containers},
       "networks":{n:absent("network", n) for n in nets}}
doc["complete"] = all(doc["containers"].values()) and all(doc["networks"].values())
with open(out, "w", encoding="utf-8") as f:
    json.dump(doc, f, sort_keys=True, indent=2); f.write("\n")
PY
rm -rf "$B7DIR"
exit $RC

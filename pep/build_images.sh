#!/usr/bin/env bash
# ============================================================================
# Build the two lab images the gate needs, on a host with registry access.
#
# WHY THIS EXISTS: in the container this project was developed in, all registries
# were blocked, so strixlab/vulnlab:1.0 and strixlab/adversary:1.0 were built
# ad-hoc with debootstrap. Those images do not exist anywhere else. Without them
# run_dualstack_gate.sh cannot run on any other host at all.
#
# HONESTY NOTE: this script could NOT be executed in the development container
# (no registry access), so it is untested there. That is exactly why it ends with
# a hard verification pass: every binary and module the gate actually needs is
# checked INSIDE each built image, and the script exits non-zero if any is
# missing. It will tell you it is wrong rather than fail mysteriously later.
#
# Usage:  sudo ./build_images.sh
# ============================================================================
set -uo pipefail
BASE="${BASE_IMAGE:-python:3-slim}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
RC=0

echo "=== base image: $BASE ==="
docker pull "$BASE" || { echo "FAIL: cannot pull $BASE — check registry access"; exit 1; }

# ---------------------------------------------------------------- vulnlab
# Runs pep/server.py and phase2b/target_https.py.
# Needs python3 (stdlib only) AND the openssl BINARY: pep/ca.py shells out to
# `openssl req` / `openssl x509` to mint the interception CA and leaf certs.
cat > "$TMP/Dockerfile.vulnlab" <<EOF
FROM $BASE
RUN apt-get update \\
 && apt-get install -y --no-install-recommends openssl ca-certificates \\
 && rm -rf /var/lib/apt/lists/*
EOF

# -------------------------------------------------------------- adversary
# Runs pep/pep_client.py and pep/ipv6_transport.py from the sandbox position.
# Needs python3 (stdlib only) AND busybox: B2 injects IPv6 routes via
# `busybox ip -6 route add ...` under NET_ADMIN. iproute2 is included too so the
# same probes work if busybox is ever swapped out.
cat > "$TMP/Dockerfile.adversary" <<EOF
FROM $BASE
RUN apt-get update \\
 && apt-get install -y --no-install-recommends busybox iproute2 iputils-ping \\
 && rm -rf /var/lib/apt/lists/*
EOF

echo "=== building strixlab/vulnlab:1.0 ==="
docker build -f "$TMP/Dockerfile.vulnlab" -t strixlab/vulnlab:1.0 "$TMP" || RC=1
echo "=== building strixlab/adversary:1.0 ==="
docker build -f "$TMP/Dockerfile.adversary" -t strixlab/adversary:1.0 "$TMP" || RC=1
[ "$RC" = 0 ] || { echo; echo "BUILD FAILED"; exit 1; }

# ============================================================================
# VERIFICATION — an image that builds is not an image that works.
# ============================================================================
echo
echo "=== verification (inside the built images) ==="

chk() { # chk <image> <label> <shell test>
  if docker run --rm "$1" sh -c "$3" >/dev/null 2>&1; then
    printf "  PASS  %-24s %s\n" "$1" "$2"
  else
    printf "  FAIL  %-24s %s\n" "$1" "$2"; RC=1
  fi
}

V=strixlab/vulnlab:1.0
A=strixlab/adversary:1.0

chk "$V" "python3 present"        "python3 -c 'print(1)'"
chk "$V" "stdlib ssl/socket/http" "python3 -c 'import ssl,socket,hashlib,json,ipaddress,secrets,uuid,subprocess,threading; from http.server import ThreadingHTTPServer'"
chk "$V" "openssl binary (ca.py)" "command -v openssl"
chk "$V" "openssl can mint a key" "openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=t -keyout /tmp/k -out /tmp/c"

chk "$A" "python3 present"        "python3 -c 'print(1)'"
chk "$A" "stdlib ssl/socket"      "python3 -c 'import ssl,socket,secrets,subprocess,threading,json,os'"
chk "$A" "busybox ip (B2 needs)"  "busybox ip -6 route show"
chk "$A" "sleep (container idle)" "command -v sleep"

echo
if [ "$RC" = 0 ]; then
  echo "  IMAGES READY — strixlab/vulnlab:1.0 and strixlab/adversary:1.0"
  echo "  Next: sudo ./preflight_dualstack.sh   then   sudo ./run_dualstack_gate.sh"
else
  echo "  VERIFICATION FAILED — do NOT run the gate with these images."
  echo "  A missing binary here surfaces later as a Layer B row that fails for"
  echo "  the wrong reason, which is worse than not running at all."
fi
exit $RC

#!/usr/bin/env bash
# ============================================================================
# HOST DIAGNOSTIC — convert ENVIRONMENT-BLOCKED findings into measured facts.
#
# This does NOT run the gate and does NOT repair anything. The three audit
# passes were performed in a container with no IPv6 and no Docker daemon, so
# several findings could only be reasoned about. Your machine can settle them.
#
# Nothing here modifies the repository. It creates and removes two containers
# and one network, all prefixed diag-.
# ============================================================================
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NET=diag-v6net; T=diag-target; C=diag-client
V6=fd00:9a17:d1a6::/64; T6=fd00:9a17:d1a6::20
cleanup(){ docker rm -f $T $C >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT

ok(){ printf "  \033[32mCONFIRMED\033[0m  %s\n" "$*"; }
no(){ printf "  \033[31mREFUTED  \033[0m  %s\n" "$*"; }
inf(){ printf "             %s\n" "$*"; }

echo "============================================================================"
echo "HOST DIAGNOSTIC — settling what the audit could not execute"
echo "  host: $(uname -sr)   date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================================"

echo; echo "-- A. STATIC: the two CRITICAL findings, checkable in seconds --"

# CRIT: phase2b/target_https.py binds AF_INET only
if grep -q 'ThreadingHTTPServer(("0.0.0.0"' "$HERE/../phase2b/target_https.py" 2>/dev/null; then
  ok "P2-CRIT-1: target_https.py binds 0.0.0.0 -> AF_INET only"
  inf "$(grep -n 'ThreadingHTTPServer((' "$HERE/../phase2b/target_https.py")"
  inf "the v6 targets have NOTHING listening on IPv6"
else
  no "P2-CRIT-1 not found as described — report this, the tree differs"
fi
if grep -rq "AF_INET6" "$HERE/../phase2b/" 2>/dev/null; then
  no "AF_INET6 does appear in phase2b/ — report this"
else
  ok "AF_INET6 appears NOWHERE in phase2b/"
fi

# CRIT: b7 has no PROVEN branch
if grep -A 12 'll_addr, mc_addr' "$HERE/ipv6_transport.py" 2>/dev/null | grep -q 'b7 = "PROVEN"'; then
  no "P1-F8 refuted: b7 CAN be PROVEN — report this"
else
  ok "P1-F8: no branch assigns PROVEN to b7 -> B7 un-passable -> E1 unpassable"
fi

# CRIT: denials carry no conn_id
if grep -n 'def _deny' -A 8 "$HERE/gateway.py" 2>/dev/null | grep -q 'conn_id'; then
  no "P3-HIGH-2 refuted: _deny carries conn_id — report this"
else
  ok "P3-HIGH-2: _deny()/_deny_tls() carry NO conn_id"
  inf "every negative PEP decision is unanchored to its connection"
fi

echo; echo "-- B. LIVE: what only your machine can measure --"
if ! docker info >/dev/null 2>&1; then
  echo "  docker daemon unreachable — section B NOT RUN (this is not a pass)"
  exit 1
fi
cleanup
docker network create --internal --ipv6 --subnet 172.30.77.0/24 --subnet "$V6" $NET >/dev/null 2>&1 \
  || { echo "  could not create the test network — section B NOT RUN"; exit 1; }

# B1 — does --internal actually produce IPv6 isolation, or is it just "no route"?
INTERNAL=$(docker network inspect $NET --format '{{.Internal}}' 2>/dev/null)
[ "$INTERNAL" = "true" ] && ok "network reports Internal=true" || no "Internal=$INTERNAL"
V6RULES=$(ip6tables -S 2>/dev/null | grep -ci 'DOCKER\|DROP' || echo 0)
inf "ip6tables rules mentioning DOCKER/DROP: $V6RULES"
if [ "${V6RULES:-0}" -gt 0 ]; then
  ok "F3 (open half): v6 netfilter rules EXIST — isolation is configured, not incidental"
else
  no "F3 (open half): NO v6 netfilter rules — '--internal' here is absence-of-route only"
  inf "this is exactly the ambiguity the audit flagged: NO_ROUTE cannot then"
  inf "distinguish 'policy denied it' from 'this network never had a route'"
fi

# B2 — does a python AF_INET6 listener actually accept, proving the fix is viable?
docker run -d --name $T --network $NET --ip6 "$T6" python:3-slim python3 -c "
import socket
s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::',8443)); s.listen(1)
while True:
    c,_=s.accept(); c.sendall(b'DUALSTACK_LISTENER_OK'); c.close()
" >/dev/null 2>&1
sleep 4
RUNNING=$(docker inspect -f '{{.State.Running}}' $T 2>/dev/null || echo false)
if [ "$RUNNING" != "true" ]; then
  no "the dual-stack listener container did not start — NOT RUN, not a failure"
  docker logs $T 2>&1 | tail -3 | sed 's/^/             /'
else
  GOT=$(docker run --rm --network $NET python:3-slim python3 -c "
import socket,sys
try:
    s=socket.create_connection(('$T6',8443),6); sys.stdout.write(s.recv(64).decode())
except Exception as e: sys.stdout.write(type(e).__name__+':'+str(e))
" 2>/dev/null | tr -d '\r\n')
  if [ "$GOT" = "DUALSTACK_LISTENER_OK" ]; then
    ok "a dual-stack (::, V6ONLY=0) listener WORKS on this host"
    inf "so the P1 fix for target_https.py is viable here — measured, not assumed"
  else
    no "dual-stack listener unreachable: got='${GOT:-<nothing>}'"
  fi
fi

echo; echo "============================================================================"
echo "  Send the FULL output back. Do NOT run run_dualstack_gate.sh."
echo "  Nothing was repaired; nothing in the repository was modified."
echo "============================================================================"

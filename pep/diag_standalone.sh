#!/usr/bin/env bash
# ============================================================================
# STANDALONE HOST DIAGNOSTIC — needs NO project files. Docker + a python image.
#
# Answers two questions the three audit passes could not, because they ran in a
# container with no IPv6 and no Docker daemon:
#
#   Q1  Does `--internal --ipv6` produce REAL netfilter isolation, or is it
#       merely "no route was installed"?  (audit finding F3, open half)
#       This decides whether NO_ROUTE is EVIDENCE or an ASSUMPTION — three
#       Layer B rows rest on it.
#
#   Q2  Does an AF_INET-only listener really become unreachable over IPv6,
#       and does a dual-stack (::, V6ONLY=0) listener really work?
#       (audit finding CRITICAL-1, and whether its fix is viable)
#
# Repairs nothing. Modifies no file. Creates and removes three containers and
# one network, all prefixed diag-.
# ============================================================================
set -uo pipefail
NET=diag-net; T4=diag-v4only; T6=diag-dual; C=diag-client
V6NET=fd00:9a17:d1a6::/64; A4=fd00:9a17:d1a6::14; A6=fd00:9a17:d1a6::16
IMG="${DIAG_IMAGE:-python:3-slim}"

ok(){ printf "  \033[32mMEASURED\033[0m  %s\n" "$*"; }
no(){ printf "  \033[31mMEASURED\033[0m  %s\n" "$*"; }
inf(){ printf "            %s\n" "$*"; }
cleanup(){ docker rm -f $T4 $T6 $C >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; }
trap cleanup EXIT

echo "============================================================================"
echo "STANDALONE DIAGNOSTIC — settling what the audit could not execute"
echo "  host: $(uname -sr)   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================================"

docker info >/dev/null 2>&1 || { echo "  docker unreachable — NOT RUN (this is not a pass)"; exit 1; }
docker image inspect "$IMG" >/dev/null 2>&1 || docker pull "$IMG" >/dev/null 2>&1
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "  no $IMG — NOT RUN. Try DIAG_IMAGE=<local python image>"; exit 1; }

echo; echo "-- Q1: is --internal real netfilter isolation, or just no route? --"
BEFORE=$(ip6tables -S 2>/dev/null | wc -l)
cleanup
docker network create --internal --ipv6 --subnet 172.30.77.0/24 --subnet "$V6NET" $NET >/dev/null 2>&1 \
  || { echo "  could not create --internal --ipv6 network — NOT RUN"; exit 1; }
AFTER=$(ip6tables -S 2>/dev/null | wc -l)
INTERNAL=$(docker network inspect $NET --format '{{.Internal}}' 2>/dev/null)
EN6=$(docker network inspect $NET --format '{{.EnableIPv6}}' 2>/dev/null)
inf "Internal=$INTERNAL  EnableIPv6=$EN6"
inf "ip6tables rule count: before=$BEFORE  after=$AFTER  (delta=$((AFTER-BEFORE)))"
DROPS=$(ip6tables -S 2>/dev/null | grep -ci 'DOCKER.*DROP\|DROP.*DOCKER' || true)
inf "rules mentioning both DOCKER and DROP: ${DROPS:-0}"
if [ "$((AFTER-BEFORE))" -gt 0 ] || [ "${DROPS:-0}" -gt 0 ]; then
  ok "Q1: --internal INSTALLED v6 netfilter rules -> isolation is CONFIGURED"
  inf "NO_ROUTE can then be read as enforcement. F3's open half: RESOLVED."
else
  no "Q1: NO v6 netfilter rules appeared -> '--internal' here is absence-of-route"
  inf "NO_ROUTE then cannot distinguish 'policy denied it' from 'this network"
  inf "never had a route out'. F3's open half: CONFIRMED AS A REAL GAP."
fi

echo; echo "-- Q2a: does an AF_INET-only listener really vanish over IPv6? --"
docker run -d --name $T4 --network $NET --ip6 "$A4" "$IMG" python3 -c "
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import socket
class H(BaseHTTPRequestHandler):
    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'V4ONLY')
    def log_message(s,*a): pass
srv = ThreadingHTTPServer(('0.0.0.0', 8443), H)   # exactly target_https.py:105
print('family', srv.socket.family, flush=True)
srv.serve_forever()
" >/dev/null 2>&1
sleep 4
FAM=$(docker logs $T4 2>&1 | grep -o 'AddressFamily[^ ]*' | head -1)
RUN4=$(docker inspect -f '{{.State.Running}}' $T4 2>/dev/null || echo false)
if [ "$RUN4" != "true" ]; then
  inf "the v4-only listener did not start — Q2a NOT RUN"
  docker logs $T4 2>&1 | tail -2 | sed 's/^/            /'
else
  inf "listener bound with family: ${FAM:-<unknown>}"
  R=$(docker run --rm --network $NET "$IMG" python3 -c "
import socket,sys
try:
    s=socket.create_connection(('$A4',8443),5); sys.stdout.write('REACHED')
except Exception as e: sys.stdout.write(type(e).__name__)
" 2>/dev/null | tr -d '\r\n')
  if [ "$R" = "REACHED" ]; then
    no "Q2a: the v4-only listener WAS reachable over IPv6 — report this, unexpected"
  else
    ok "Q2a: v4-only listener unreachable over IPv6 -> $R"
    inf "CRITICAL-1 confirmed AT RUNTIME: targets bound this way have nothing on v6."
  fi
fi

echo; echo "-- Q2b: is the dual-stack fix actually viable on this kernel? --"
docker run -d --name $T6 --network $NET --ip6 "$A6" "$IMG" python3 -c "
import socket
s=socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::',8443)); s.listen(5)
while True:
    c,_=s.accept(); c.sendall(b'DUALSTACK_OK'); c.close()
" >/dev/null 2>&1
sleep 4
RUN6=$(docker inspect -f '{{.State.Running}}' $T6 2>/dev/null || echo false)
if [ "$RUN6" != "true" ]; then
  no "Q2b: the dual-stack listener did NOT start — the fix is not viable as written"
  docker logs $T6 2>&1 | tail -3 | sed 's/^/            /'
else
  G=$(docker run --rm --network $NET "$IMG" python3 -c "
import socket,sys
try:
    s=socket.create_connection(('$A6',8443),6); sys.stdout.write(s.recv(32).decode())
except Exception as e: sys.stdout.write(type(e).__name__+':'+str(e))
" 2>/dev/null | tr -d '\r\n')
  if [ "$G" = "DUALSTACK_OK" ]; then
    ok "Q2b: a dual-stack (::, V6ONLY=0) listener WORKS here"
    inf "the P1 fix for target_https.py is viable — measured, not assumed."
  else
    no "Q2b: dual-stack listener unreachable: got='${G:-<nothing>}'"
  fi
fi

echo; echo "============================================================================"
echo "  Send the FULL output back. Nothing was repaired or modified."
echo "  Do NOT run run_dualstack_gate.sh."
echo "============================================================================"

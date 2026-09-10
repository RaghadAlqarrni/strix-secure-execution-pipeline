#!/usr/bin/env bash
# DEC-7 B7 host evidence harness. Assumes gate_sbx and both gate networks exist.
# Produces host-owned b7_evidence.json + a read-only advisory for Layer B.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${RUN_ID:?}" "${NET_EG:?}" "${NET_A:?}" "${SBX:=gate_sbx}"
: "${B7_DIR:?}" "${B7_TARGET6:=fd00:9a17:e9:1::80}"
: "${B7_CONTROL6:=fd00:9a17:e9:1::81}" "${B7_IMAGE:=strixlab/adversary:1.0}"

mkdir -p "$B7_DIR"
chmod 700 "$B7_DIR"
# `od` emits decimal with leading padding. Strip it before Bash arithmetic;
# base#value rejects that padding on some Bash releases.
PORT_RAW="$(od -An -N2 -tu2 /dev/urandom | tr -d '[:space:]')"
case "$PORT_RAW" in (*[!0-9]*|'') echo "invalid random port seed" >&2; exit 10;; esac
PORT=$((49152 + PORT_RAW % 12000))
C1=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
M=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
C2=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
CAL=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
CAL_RUN="cal-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
CAL_NET="b7_cal_${RUN_ID#run-}"; CAL_NET="${CAL_NET:0:55}"

cleanup() {
  [ -n "${EXACT_RULE_ADDED:-}" ] && ip6tables -t raw -D PREROUTING -i "$BR_IN" \
    -s "$SBX6/128" -d "$B7_TARGET6/128" -p udp --dport "$PORT" \
    -m comment --comment "strix-b7:$RUN_ID" -j DROP >/dev/null 2>&1 || true
  docker rm -f gate_b7_recv gate_b7_ctl gate_b7_cal_recv gate_b7_cal_send >/dev/null 2>&1 || true
  docker network rm "$CAL_NET" >/dev/null 2>&1 || true
  [ -n "${CAP_PID:-}" ] && kill "$CAP_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

SENDER_SHA=$(sha256sum "$HERE/b7_udp_sender.py" | awk '{print $1}')
RECEIVER_SHA=$(sha256sum "$HERE/b7_udp_receiver.py" | awk '{print $1}')

# ------------------------------ separate clean calibration topology
docker network create --internal --ipv6 --subnet fd00:9a17:e9:3::/64 "$CAL_NET" >/dev/null || exit 20
docker run -d --name gate_b7_cal_recv --network "$CAL_NET" --ip6 fd00:9a17:e9:3::80 \
  -v "$HERE/b7_udp_receiver.py:/receiver.py:ro" -v "$B7_DIR:/evidence" \
  "$B7_IMAGE" python3 /receiver.py --bind fd00:9a17:e9:3::80 --port "$PORT" \
  --log /evidence/cal_receiver.jsonl --ready /evidence/cal.ready \
  --run-id "$CAL_RUN" --timeout 15 >/dev/null || exit 21
for _ in $(seq 1 30); do [ -s "$B7_DIR/cal.ready" ] && break; sleep .2; done
[ -s "$B7_DIR/cal.ready" ] || exit 22
docker run --rm --name gate_b7_cal_send --network "$CAL_NET" --ip6 fd00:9a17:e9:3::81 \
  -v "$HERE/b7_udp_sender.py:/sender.py:ro" -v "$B7_DIR:/evidence" \
  "$B7_IMAGE" python3 /sender.py --target fd00:9a17:e9:3::80 --port "$PORT" \
  --nonce "$CAL" --role calibration --output /evidence/cal_sender.json >/dev/null || exit 23
sleep .5
grep -q "\"nonce\":\"$CAL\"" "$B7_DIR/cal_receiver.jsonl" || exit 24
docker rm -f gate_b7_cal_recv >/dev/null 2>&1
docker network rm "$CAL_NET" >/dev/null 2>&1 || exit 25

# ------------------------------ occupied measurement receiver + controls
docker run -d --name gate_b7_recv --network "$NET_EG" --ip6 "$B7_TARGET6" \
  -v "$HERE/b7_udp_receiver.py:/receiver.py:ro" -v "$B7_DIR:/evidence" \
  "$B7_IMAGE" python3 /receiver.py --bind "$B7_TARGET6" --port "$PORT" \
  --log /evidence/receiver.jsonl --ready /evidence/receiver.ready \
  --run-id "$RUN_ID" --timeout 30 >/dev/null || exit 30
docker run -d --name gate_b7_ctl --network "$NET_EG" --ip6 "$B7_CONTROL6" \
  -v "$HERE/b7_udp_sender.py:/sender.py:ro" -v "$B7_DIR:/evidence" \
  "$B7_IMAGE" sleep 40 >/dev/null || exit 31
for _ in $(seq 1 30); do [ -s "$B7_DIR/receiver.ready" ] && break; sleep .2; done
[ -s "$B7_DIR/receiver.ready" ] || exit 32
docker exec gate_b7_ctl python3 /sender.py --target "$B7_TARGET6" --port "$PORT" \
  --nonce "$C1" --role c1 --output /evidence/c1_sender.json >/dev/null || exit 33
sleep .5
grep -q "\"nonce\":\"$C1\"" "$B7_DIR/receiver.jsonl" || exit 34

# Host identity and exact pre-enforcement observation point.
NET_IN_ID=$(docker network inspect -f '{{.Id}}' "$NET_A")
NET_EG_ID=$(docker network inspect -f '{{.Id}}' "$NET_EG")
BR_IN=$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$NET_A")
[ -n "$BR_IN" ] || BR_IN="br-${NET_IN_ID:0:12}"
GW_IN=$(docker network inspect -f '{{(index .IPAM.Config 1).Gateway}}' "$NET_A")
[ -n "$GW_IN" ] || GW_IN="fd00:9a17:e9:2::1"
SBX_ID=$(docker inspect -f '{{.Id}}' "$SBX")
SBX_PID=$(docker inspect -f '{{.State.Pid}}' "$SBX")
IFLINK=$(docker exec "$SBX" cat /sys/class/net/eth0/iflink)
HOST_VETH=$(ip -o link | awk -F': ' -v n="$IFLINK" '$1==n {sub(/@.*/,"",$2);print $2}')
[ -n "$HOST_VETH" ] || exit 35

# Preserve the control-plane sources from which identity and topology must be
# re-derived. The normalized b7_evidence.json is never authoritative for these.
docker inspect "$SBX" >"$B7_DIR/sandbox.inspect.json" || exit 43
docker inspect gate_b7_recv >"$B7_DIR/receiver.inspect.json" || exit 49
docker network inspect "$NET_A" >"$B7_DIR/network-in.inspect.json" || exit 44
docker network inspect "$NET_EG" >"$B7_DIR/network-eg.inspect.json" || exit 45
ip -j link show >"$B7_DIR/host-links.json" || exit 46
docker exec "$SBX" ip -j -6 addr >"$B7_DIR/sandbox-ipv6-addr.json" || exit 47
docker exec "$SBX" ip -j -6 route >"$B7_DIR/sandbox-ipv6-route-before.json" || exit 50

command -v tcpdump >/dev/null 2>&1 || exit 36
tcpdump -i "$BR_IN" -nn -s 0 -U -c 1 -w "$B7_DIR/attempt.pcap" \
  "ip6 and udp and src $SBX6 and dst $B7_TARGET6 and dst port $PORT" \
  >"$B7_DIR/tcpdump.stdout" 2>"$B7_DIR/tcpdump.stderr" & CAP_PID=$!
sleep .3
# Install one exact, run-labelled rule before the measured packet. It is exact
# to ingress bridge, sender, destination, UDP and destination port; broad Docker
# isolation rules are not accepted as B7 attribution.
# Docker's own off-link isolation DROP is in raw/PREROUTING.  The exact
# attribution rule must precede it; a later DOCKER-USER rule is unreachable.
ip6tables -t raw -I PREROUTING 1 -i "$BR_IN" -s "$SBX6/128" \
  -d "$B7_TARGET6/128" -p udp --dport "$PORT" \
  -m comment --comment "strix-b7:$RUN_ID" -j DROP || exit 48
EXACT_RULE_ADDED=1
ip6tables-save -c >"$B7_DIR/rules.before"
docker exec "$SBX" busybox ip -6 route replace "$B7_TARGET6/128" via "$GW_IN" dev eth0 || exit 37
docker exec "$SBX" python3 /sender.py --target "$B7_TARGET6" --port "$PORT" \
  --nonce "$M" --role measurement --output /out/b7_measurement_sender.json >/dev/null || exit 38
for _ in $(seq 1 20); do kill -0 "$CAP_PID" 2>/dev/null || break; sleep .1; done
kill "$CAP_PID" >/dev/null 2>&1 || true; wait "$CAP_PID" 2>/dev/null || true; CAP_PID=""
ip6tables-save -c >"$B7_DIR/rules.after"
tcpdump -nn -XX -r "$B7_DIR/attempt.pcap" >"$B7_DIR/attempt.txt" 2>/dev/null || true
grep -q "$B7_TARGET6\.$PORT" "$B7_DIR/attempt.txt" || exit 39
# The host capture must contain the measured payload, not merely a packet with
# the same 5-tuple. Decode the pcap independently and bind the nonce bytes.
python3 - "$B7_DIR/attempt.pcap" "$M" <<'PY'
import struct,sys
raw=open(sys.argv[1],'rb').read(); nonce=sys.argv[2].encode('ascii')
sys.exit(0 if nonce in raw else 1)
PY
[ "$?" = 0 ] || exit 42
sleep .5

docker exec gate_b7_ctl python3 /sender.py --target "$B7_TARGET6" --port "$PORT" \
  --nonce "$C2" --role c2 --output /evidence/c2_sender.json >/dev/null || exit 40
sleep .5
grep -q "\"nonce\":\"$C2\"" "$B7_DIR/receiver.jsonl" || exit 41
if grep -q "\"nonce\":\"$M\"" "$B7_DIR/receiver.jsonl"; then MEAS_SEEN=true; else MEAS_SEEN=false; fi

# Find exactly one PRE-EXISTING DROP rule whose packet counter rose by one.
python3 - "$B7_DIR/rules.before" "$B7_DIR/rules.after" "$B7_DIR/drop.json" <<'PY'
import json,re,sys
pat=re.compile(r'^\[(\d+):(\d+)\]\s+(.*(?:-j|jump)\s+(?:DROP|drop)\b.*)$')
def read(p):
 d={}
 for line in open(p,errors='replace'):
  m=pat.match(line.strip())
  if m:d[m.group(3)]=(int(m.group(1)),int(m.group(2)))
 return d
b,a=read(sys.argv[1]),read(sys.argv[2]); hits=[]
for rule,(bp,bb) in b.items():
 ap,ab=a.get(rule,(bp,bb))
 if ap-bp==1:hits.append((rule,bp,ap,bb,ab))
out={'candidate_count':len(hits),'hits':[{'rule':x[0],'packets_before':x[1],
     'packets_after':x[2],'bytes_before':x[3],'bytes_after':x[4]} for x in hits]}
json.dump(out,open(sys.argv[3],'w'),indent=2,sort_keys=True)
sys.exit(0 if len(hits)==1 else 1)
PY
DROP_RC=$?

ip6tables -t raw -D PREROUTING -i "$BR_IN" -s "$SBX6/128" \
  -d "$B7_TARGET6/128" -p udp --dport "$PORT" \
  -m comment --comment "strix-b7:$RUN_ID" -j DROP >/dev/null 2>&1 || true
EXACT_RULE_ADDED=""

# Retire every B7-specific measured process before sealing its evidence.
docker rm -f gate_b7_recv gate_b7_ctl >/dev/null 2>&1
docker exec "$SBX" busybox ip -6 route del "$B7_TARGET6/128" >/dev/null 2>&1 || true
TEARDOWN=true
docker ps -a --format '{{.Names}}' | grep -q '^gate_b7_' && TEARDOWN=false
docker network ls --format '{{.Name}}' | grep -q "^$CAL_NET$" && TEARDOWN=false
docker exec "$SBX" busybox ip -6 route show "$B7_TARGET6/128" | grep -q . && TEARDOWN=false

export RUN_ID CAL_RUN PORT C1 M C2 CAL B7_TARGET6 SBX6 SBX_ID SBX_PID HOST_VETH \
       NET_IN_ID NET_EG_ID BR_IN SENDER_SHA RECEIVER_SHA MEAS_SEEN TEARDOWN B7_DIR DROP_RC
python3 - <<'PY'
import hashlib,json,os
d=os.environ['B7_DIR']
def j(n): return json.load(open(os.path.join(d,n)))
def sha(n): return hashlib.sha256(open(os.path.join(d,n),'rb').read()).hexdigest()
drop=j('drop.json'); hit=(drop.get('hits') or [{}])[0]
e={'schema_version':'strix-b7-e9-v1','run_id':os.environ['RUN_ID'],
   'run_id_source':'control-plane',
   'sender':{'container_id':os.environ['SBX_ID'],'container_pid':int(os.environ['SBX_PID']),
             'host_veth':os.environ['HOST_VETH'],'network_id':os.environ['NET_IN_ID'],
             'src_ip':os.environ['SBX6']},
   'target':{'ip':os.environ['B7_TARGET6'],'port':int(os.environ['PORT']),
             'network_id':os.environ['NET_EG_ID'],'off_link':True},
   'probe':{'protocol':'udp','nonce':os.environ['M']},
   'packet_attempt':{'observed':os.path.getsize(os.path.join(d,'attempt.pcap'))>24,
      'source':'tcpdump-host-veth','rule_identity':'capture:'+os.environ['BR_IN'],
      'src_ip':os.environ['SBX6'],'dst_ip':os.environ['B7_TARGET6'],
      'dst_port':int(os.environ['PORT']),'protocol':'udp','nonce':os.environ['M'],
      'pcap_sha256':sha('attempt.pcap')},
   'enforcement':{'action':'DROP','preexisting':True,
      'rule_identity':hit.get('rule',''),'src_ip':os.environ['SBX6'],
      'dst_ip':os.environ['B7_TARGET6'],'dst_port':int(os.environ['PORT']),
      'protocol':'udp','packets_before':hit.get('packets_before'),
      'packets_after':hit.get('packets_after'),
      'rules_before_sha256':sha('rules.before'),'rules_after_sha256':sha('rules.after')},
   'controls':{'c1_nonce':os.environ['C1'],'c2_nonce':os.environ['C2']},
   'receiver':{'ready':os.path.exists(os.path.join(d,'receiver.ready')),
      'c1_seen':os.environ['C1'] in open(os.path.join(d,'receiver.jsonl')).read(),
      'c2_seen':os.environ['C2'] in open(os.path.join(d,'receiver.jsonl')).read(),
      'measurement_seen':os.environ['MEAS_SEEN']=='true',
      'raw_log_sha256':sha('receiver.jsonl')},
   'sender_script_sha256':os.environ['SENDER_SHA'],
   'receiver_script_sha256':os.environ['RECEIVER_SHA'],
   'calibration':{'run_id':os.environ['CAL_RUN'],
      'nonce':os.environ['CAL'],
      'seen':os.environ['CAL'] in open(os.path.join(d,'cal_receiver.jsonl')).read(),
      'sender_sha256':os.environ['SENDER_SHA'],'receiver_sha256':os.environ['RECEIVER_SHA'],
      'raw_log_sha256':sha('cal_receiver.jsonl')},
   'b7_teardown':os.environ['TEARDOWN']=='true'}
json.dump(e,open(os.path.join(d,'b7_evidence.json'),'w'),indent=2,sort_keys=True)
eh=sha('b7_evidence.json')
ready=(os.environ['DROP_RC']=='0' and not e['receiver']['measurement_seen']
       and e['packet_attempt']['observed'] and e['b7_teardown'])
adv={'status':'PROVEN' if ready else ('FAILED_OPEN' if e['receiver']['measurement_seen']
     else 'APPARATUS_FAILURE'),'ready_for_e9':ready,
     'measurement_seen':e['receiver']['measurement_seen'],'evidence_sha256':eh}
json.dump(adv,open(os.path.join(d,'b7_advisory.json'),'w'),indent=2,sort_keys=True)
PY
[ "$DROP_RC" = 0 ] && [ "$MEAS_SEEN" = false ] && [ "$TEARDOWN" = true ]

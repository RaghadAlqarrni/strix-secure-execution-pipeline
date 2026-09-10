#!/usr/bin/env bash
# ============================================================================
# DUAL-STACK HOST PREFLIGHT — is THIS host eligible to run the IPv6 gate?
#
# Standalone and self-contained: copy this one file to any candidate host and
# run it. It needs nothing from the rest of the repo.
#
# It answers ONE question with an exit code:
#     0 = this host can run the local Track-A validation harness; this is never
#         permission to run Strix or the release gate.
#     1 = it cannot, and every reason is printed
#
# DESIGN RULE, inherited from the gate itself: CONFIG IS NOT EVIDENCE.
# Reading daemon.json or seeing a v6 route proves nothing about whether the
# boundary holds. So the Docker checks here are LIVE: this actually creates a
# dual-stack network, actually starts two containers on it, and actually opens
# an IPv6 TCP connection between them. If that connection does not carry real
# bytes, the host is reported NOT ELIGIBLE — no inference, no partial credit.
#
# It creates and then removes: one network (pf-v6net), two containers
# (pf-srv, pf-cli). It touches nothing else and modifies no configuration.
# ============================================================================
set -uo pipefail

PASS=0; FAIL=0
# Docker container names must match [a-zA-Z0-9][a-zA-Z0-9_.-] — a LEADING
# UNDERSCORE is rejected. These were _pf_srv / _pf_cli, so `docker run` refused
# to start the server, the client then got "No route to host", and the script
# reported "no IPv6 traffic crossed" — blaming IPv6 for a container that was
# never created. Network names are more permissive, so _pf_v6net created fine
# and hid the problem.
NET=pf-v6net; SRV=pf-srv; CLI=pf-cli
# NOTE: every hextet must be HEX. An earlier default here was fd00:9a17:pf01::/64,
# which contains 'p' and is not a valid IPv6 address at all — so `docker network
# create` rejected it and the script blamed the daemon. The CIDRs are now
# validated at runtime (below) so a typo can never again be reported as a host
# defect.
V6NET="${PF_V6NET:-fd00:9a17:f001::/64}"
V4NET="${PF_V4NET:-172.28.244.0/24}"
SRV6="${V6NET%%/*}20"
IMG="${PREFLIGHT_IMAGE:-alpine:3}"
REASONS=()

ok()   { printf "  \033[32mPASS\033[0m  %-52s %s\n" "$1" "${2:-}"; PASS=$((PASS+1)); }
bad()  { printf "  \033[31mFAIL\033[0m  %-52s %s\n" "$1" "${2:-}"; FAIL=$((FAIL+1)); REASONS+=("$3"); }
note() { printf "        %s\n" "$*"; }

cleanup() {
  docker rm -f $SRV $CLI >/dev/null 2>&1
  docker network rm $NET  >/dev/null 2>&1
}
trap cleanup EXIT

echo "============================================================================"
echo "DUAL-STACK HOST PREFLIGHT"
echo "  host:   $(uname -sr)  $(uname -m)"
echo "  date:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================================"
# Validate the probe CIDRs BEFORE anything uses them, so a bad value is reported
# as a bad value — not as a broken host.
if command -v python3 >/dev/null 2>&1; then
  if ! python3 -c "
import ipaddress, sys
for c in ('$V4NET', '$V6NET'):
    ipaddress.ip_network(c)
" 2>/dev/null; then
  echo
  printf "  \033[31mABORT\033[0m  probe subnet is not a valid CIDR: V4NET=%s V6NET=%s\n" "$V4NET" "$V6NET"
  echo "         Fix the value (every IPv6 hextet must be hex: 0-9 a-f) and re-run."
  echo "         This is a script/argument error, NOT a finding about this host."
  exit 2
  fi
fi

echo
echo "-- 1. kernel ---------------------------------------------------------------"

if grep -q 'ipv6.disable=1' /proc/cmdline 2>/dev/null; then
  bad "kernel not booted with ipv6.disable=1" "found in /proc/cmdline" \
      "Kernel booted with ipv6.disable=1. NOT fixable at runtime: IPv6 is built in
   (CONFIG_IPV6=y), so modprobe cannot help and a boot parameter cannot be
   revoked. Remove ipv6.disable=1 from the bootloader and REBOOT."
else
  ok "kernel not booted with ipv6.disable=1"
fi

if [ -d /proc/sys/net/ipv6 ]; then
  ok "/proc/sys/net/ipv6 sysctl tree present"
else
  bad "/proc/sys/net/ipv6 sysctl tree present" "absent" \
      "No IPv6 sysctl tree. Docker reads
   /proc/sys/net/ipv6/conf/<bridge>/disable_ipv6 when creating v6 bridges."
fi

if [ -f /proc/net/if_inet6 ]; then
  ok "/proc/net/if_inet6 present" "$(wc -l < /proc/net/if_inet6) v6 addresses"
else
  bad "/proc/net/if_inet6 present" "absent" "IPv6 stack never initialized."
fi

D6=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "?")
if [ "$D6" = "0" ]; then
  ok "net.ipv6.conf.all.disable_ipv6 == 0"
elif [ "$D6" = "?" ]; then
  bad "net.ipv6.conf.all.disable_ipv6 == 0" "unreadable" "IPv6 sysctls unreadable."
else
  bad "net.ipv6.conf.all.disable_ipv6 == 0" "is $D6" \
      "Run: sysctl -w net.ipv6.conf.all.disable_ipv6=0  (and make it persistent)"
fi

# python3 is a genuine HOST prerequisite: run_dualstack_gate.sh, the verifiers and
# the evidence auditor all run on the host. Check it separately — if python3 were
# merely absent, the AF_INET6 probe below would fail and get reported as "the
# kernel refuses AF_INET6 sockets", which is a FALSE ATTRIBUTION: blaming the
# kernel for a missing interpreter. Distinguish the two.
if command -v python3 >/dev/null 2>&1; then
  ok "python3 present" "$(python3 -V 2>&1)"
  if python3 -c "import socket;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.close()" 2>/dev/null; then
    ok "AF_INET6 socket can be created"
  else
    bad "AF_INET6 socket can be created" "refused by kernel" \
        "The kernel refuses AF_INET6 sockets."
  fi
else
  bad "python3 present" "not on PATH" \
      "Install python3 (the gate, the verifiers and the evidence auditor all run
   on it). e.g. apt-get install -y python3"
  note "AF_INET6 probe NOT RUN — cannot test without python3. This is not a pass."
fi

echo
echo "-- 2. privileges and docker ------------------------------------------------"

if [ "$(id -u)" = "0" ]; then
  ok "running as root" "required to create bridges / read netfilter"
else
  bad "running as root" "uid=$(id -u)" "Re-run as root (or via sudo)."
fi

# DEC-7/E9 host evidence prerequisites. Packet-attempt observation and the
# enforcement counter are deliberately independent evidence sources.
if command -v tcpdump >/dev/null 2>&1; then
  ok "tcpdump present for host-veth packet observation" "$(tcpdump --version 2>&1 | head -1)"
else
  bad "tcpdump present for host-veth packet observation" "not on PATH" \
      "Install tcpdump. E9 refuses to infer a packet attempt from the DROP counter."
fi
if command -v ip6tables-save >/dev/null 2>&1; then
  ok "ip6tables-save present for before/after counters"
else
  bad "ip6tables-save present for before/after counters" "not on PATH" \
      "Install iptables tooling. E9 requires pre-existing rule identity and counters."
fi

if ! command -v docker >/dev/null 2>&1; then
  bad "docker CLI present" "not on PATH" "Install Docker Engine >= 26."
elif ! docker info >/dev/null 2>&1; then
  bad "docker daemon reachable" "cannot connect to socket" \
      "The Docker daemon is not running, or this user cannot reach its socket."
else
  SV=$(docker info --format '{{.ServerVersion}}' 2>/dev/null)
  MAJ=${SV%%.*}
  if [ "${MAJ:-0}" -ge 26 ] 2>/dev/null; then
    ok "docker server >= 26" "$SV"
  else
    bad "docker server >= 26" "$SV" "Upgrade Docker Engine to >= 26."
  fi
fi

FWD=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "?")
if [ "$FWD" = "1" ]; then
  ok "net.ipv6.conf.all.forwarding == 1"
else
  bad "net.ipv6.conf.all.forwarding == 1" "is $FWD" \
      "IPv6 forwarding is off, so traffic cannot cross between docker bridges.
   Run: sysctl -w net.ipv6.conf.all.forwarding=1
   (persist it in /etc/sysctl.d/ so it survives a reboot)"
fi

echo
echo "-- 3. LIVE dual-stack proof (config is not evidence) -----------------------"
# What the daemon itself reports, printed for diagnosis only — NOT scored.
# Config is not evidence; the live connection below is.
DINFO=$(docker info --format '{{json .}}' 2>/dev/null | tr ',' '\n' | grep -i 'ipv6\|ip6tables' | head -4)
[ -n "$DINFO" ] && note "daemon reports (diagnostic only): $(echo "$DINFO" | tr '\n' ' ')"

if [ "$FAIL" -gt 0 ]; then
  note "skipped: a prerequisite above already failed"
  note "(this is NOT a pass — it was not run)"
else
  cleanup
  # Capture the daemon's ACTUAL error. Reporting "failed" without the reason
  # sends the operator guessing, and guessing is how a host gets "fixed" by
  # disabling the thing that was protecting it.
  NETERR="$(docker network create --ipv6 --subnet "$V4NET" --subnet "$V6NET" $NET 2>&1 >/dev/null)"
  if [ -z "$NETERR" ]; then
    ok "dual-stack docker network creates"
  else
    bad "dual-stack docker network creates" "see error below" \
        "docker network create failed. The daemon said:

     $NETERR

   If it mentions IPv6 being disabled, enable it in /etc/docker/daemon.json:
     { \"ipv6\": true, \"ip6tables\": true, \"fixed-cidr-v6\": \"fd00:d0ck::/64\" }
   then: systemctl restart docker
   If it mentions a POOL OVERLAP, an existing network already uses one of these
   subnets — remove it, or re-run with a different range:
     PF_V4NET=172.28.245.0/24 PF_V6NET=fd00:9a17:f002::/64 $0"
    note "daemon error: $NETERR"
  fi

  if docker network inspect $NET --format '{{.EnableIPv6}}' 2>/dev/null | grep -q true; then
    ok "network reports EnableIPv6=true"
  else
    bad "network reports EnableIPv6=true" "false or unreadable" \
        "Docker created the network without IPv6."
  fi

  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    docker pull "$IMG" >/dev/null 2>&1 || true
  fi
  if ! docker image inspect "$IMG" >/dev/null 2>&1; then
    bad "probe image available" "$IMG missing and pull failed" \
        "Provide a small image with a shell, e.g.:
   PREFLIGHT_IMAGE=<local-image> $0"
  else
    ok "probe image available" "$IMG"

    # The probe runs on python3, NOT nc. An earlier version shelled out to `nc`,
    # which the lab images do not provide (busybox is installed but Debian does
    # not symlink `nc`). The probe therefore failed and the script reported "no
    # IPv6 traffic crossed" — blaming the network for a MISSING TEST TOOL. A
    # test that cannot run must say so; it must never be scored as a failure of
    # the thing it was meant to measure.
    if ! docker run --rm "$IMG" python3 -c "import socket" >/dev/null 2>&1; then
      note "LIVE IPv6 TCP probe: NOT RUN — $IMG has no usable python3"
      note "(this is NOT a pass and NOT a failure of the host — the probe could"
      note " not execute. Use an image with python3: PREFLIGHT_IMAGE=<img> $0)"
      FAIL=$((FAIL+1))
      REASONS+=("The live IPv6 probe could not run: the probe image '$IMG' has no
   working python3, so nothing was measured. Re-run with an image that does:
     PREFLIGHT_IMAGE=python:3-slim $0
   NOT RUN is not a pass. The host's IPv6 status is UNKNOWN until this executes.")
    else
      SRVERR="$(docker run -d --name $SRV --network $NET --ip6 "$SRV6" "$IMG" python3 -c "
import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('::', 9999)); s.listen(1)
while True:
    c, _ = s.accept(); c.sendall(b'PREFLIGHT_V6_OK'); c.close()
" 2>&1 >/dev/null)"
      sleep 3

      # THE APPARATUS MUST BE VERIFIED BEFORE ITS RESULT IS INTERPRETED.
      # If the listener never came up, the client's failure says nothing about
      # IPv6 — it says the test did not happen. Scoring that as an IPv6 failure
      # is a false attribution, and this script has now made that mistake three
      # separate ways (missing python3, missing nc, illegal container name).
      RUNNING=$(docker inspect -f '{{.State.Running}}' $SRV 2>/dev/null || echo false)
      if [ "$RUNNING" != "true" ]; then
        note "LIVE IPv6 TCP probe: NOT RUN — the listener container never started"
        note "(NOT a pass and NOT a host failure — the test apparatus failed)"
        FAIL=$((FAIL+1))
        REASONS+=("The live IPv6 probe did not run: the listener container failed
   to start, so nothing was measured. Docker said:

     ${SRVERR:-<no error captured>}
     $(docker logs $SRV 2>&1 | tail -2 | tr '\n' ' ')

   NOT RUN is not a pass. IPv6 status stays UNKNOWN until this executes.")
        SKIP_CLIENT=1
      fi

      if [ "${SKIP_CLIENT:-0}" = "1" ]; then
        :
      else
      GOT=$(docker run --rm --name $CLI --network $NET "$IMG" python3 -c "
import socket, sys
try:
    s = socket.create_connection(('$SRV6', 9999), 6)
    sys.stdout.write(s.recv(64).decode())
except Exception as e:
    sys.stderr.write(type(e).__name__ + ': ' + str(e))
" 2>/tmp/_pf_cli_err | tr -d '\r\n')
      CLIERR=$(cat /tmp/_pf_cli_err 2>/dev/null); rm -f /tmp/_pf_cli_err
      if [ "$GOT" = "PREFLIGHT_V6_OK" ]; then
        ok "LIVE IPv6 TCP between containers carried real bytes" "[$SRV6]:9999"
      else
        bad "LIVE IPv6 TCP between containers carried real bytes" \
            "got='${GOT:-<nothing>}'" \
            "A dual-stack network was created but no IPv6 traffic crossed it.
   Client error: ${CLIERR:-<none>}
   Server log:   $(docker logs $SRV 2>&1 | tail -2 | tr '\n' ' ')
   This is exactly the case where reading config would have lied. Check that the
   daemon has ip6tables enabled and that the host forwards IPv6."
        note "client error: ${CLIERR:-<none>}"
      fi
      fi
    fi

    if command -v ip6tables >/dev/null 2>&1 && ip6tables -L -n >/dev/null 2>&1; then
      RULES=$(ip6tables -S 2>/dev/null | wc -l)
      ok "ip6tables readable" "$RULES rules — gate asserts on these"
    else
      bad "ip6tables readable" "absent or unreadable" \
          "The gate inspects host netfilter for IPv6. Install ip6tables and ensure
   the daemon was started with --ip6tables=true."
    fi
  fi
fi

echo
echo "============================================================================"
printf "  checks passed: %s   failed: %s\n" "$PASS" "$FAIL"
if [ "$FAIL" = "0" ]; then
  printf "  \033[32mHOST: ELIGIBLE — Track-A validation harness can run here\033[0m\n"
  echo "  Release gate and Strix remain owner-locked."
  echo "============================================================================"
  exit 0
fi
printf "  \033[31mHOST: NOT ELIGIBLE\033[0m\n"
echo "----------------------------------------------------------------------------"
echo "  What must change:"
i=1
for r in "${REASONS[@]}"; do
  printf "\n  %s. %s\n" "$i" "$r"
  i=$((i+1))
done
echo
echo "  Reminder: a host that cannot run the gate is not a host that passed it."
echo "  Layer B stays BLOCKED_ENV, and IPv6 stays UNKNOWN / RELEASE BLOCKER."
echo "============================================================================"
exit 1

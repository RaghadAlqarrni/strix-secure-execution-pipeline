#!/usr/bin/env bash
# Phase 2b PKI. Three independent trust roots so each proof obligation is isolated:
#   gwca  — the gateway's MITM CA. Its PRIVATE KEY must never reach the sandbox.
#   upca  — upstream server CA, trusted BY THE GATEWAY only.
#   rogue — untrusted CA, used to prove upstream cert validation fails closed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
C="$HERE/certs"
rm -rf "$C"; mkdir -p "$C/leaf" "$C/up" "$C/sandbox"

mkca() { # name CN
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$C/$1.key" -out "$C/$1.crt" -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

leaf() { # dir host ca [extra_san ...]
  local dir="$1" host="$2" ca="$3"; shift 3
  local san="DNS:$host"
  for extra in "$@"; do san="$san,DNS:$extra"; done
  openssl req -newkey rsa:2048 -nodes -keyout "$C/$dir/$host.key" \
    -out "$C/$dir/$host.csr" -subj "/CN=$host" 2>/dev/null
  openssl x509 -req -in "$C/$dir/$host.csr" -CA "$C/$ca.crt" -CAkey "$C/$ca.key" \
    -CAcreateserial -days 825 -out "$C/$dir/$host.crt" \
    -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=serverAuth\n" "$san") 2>/dev/null
  rm -f "$C/$dir/$host.csr"
  cat "$C/$dir/$host.crt" "$C/$dir/$host.key" > "$C/$dir/$host.pem"
}

mkca gwca  "Strix PDP Interception CA"
mkca upca  "Lab Upstream CA"
mkca rogue "Rogue CA (untrusted)"

# The v6 names are NOT cosmetic aliases. The PEP verifies the upstream with
# check_hostname=True against the CANONICAL host, so a target reached as
# allowed6.lab must present a leaf whose SAN carries allowed6.lab. Without these
# the upstream handshake fails with UPSTREAM_CERT_INVALID, via_ok is False, and
# EVERY Layer B row collapses to NO_POSITIVE_CONTROL — i.e. Layer B could not
# have passed even with the IPv6 listener fixed. The v6 rows were added to the
# gate without ever adding their certificates.
# In the dual-stack gate ONE container serves both a v4 and a v6 name
# (gate_allowed is reached as allowed.lab over v4 and allowed6.lab over v6). The
# PEP verifies upstream with check_hostname=True against the CANONICAL host, so
# that container's leaf must carry BOTH names. Without allowed6.lab in the SAN
# the upstream handshake fails with UPSTREAM_CERT_INVALID, via_ok is False, and
# every Layer B row collapses to NO_POSITIVE_CONTROL — Layer B could not have
# passed even with the IPv6 listener fixed. The v6 rows were added to the gate
# without anyone adding their certificates.
for h in allowed.lab other.lab rebind.lab slow.lab badcert.lab evil.lab; do
  leaf leaf "$h" gwca      # what the gateway presents to the sandbox
done
leaf up allowed.lab upca allowed6.lab
leaf up slow.lab    upca slow6.lab
leaf up evil.lab    upca evil6.lab
for h in other.lab rebind.lab; do
  leaf up "$h" upca        # what the real upstream presents to the gateway
done
leaf up badcert.lab rogue  # untrusted upstream -> gateway must fail closed

# The sandbox receives ONLY the gateway CA *certificate* (public). Never the key.
cp "$C/gwca.crt" "$C/sandbox/gwca.crt"

echo "PKI built:"
echo "  gateway CA key (must stay gateway-side): $C/gwca.key"
echo "  sandbox trust bundle (public only):      $C/sandbox/gwca.crt"
echo "  upstream CA trusted by gateway:          $C/upca.crt"
echo "  rogue CA (untrusted, for badcert.lab):   $C/rogue.crt"

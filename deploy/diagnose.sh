#!/usr/bin/env bash
# prox diagnostic — collects everything needed to reconcile the proxy
# journal against the wire state. Run as root:
#
#   sudo deploy/diagnose.sh                 # ~10s
#   SECS=20 sudo deploy/diagnose.sh         # longer capture window
#
# Suggested sudoers entry (then plain `sudo deploy/diagnose.sh` works):
#   $USER ALL=(root) NOPASSWD: <repo>/deploy/diagnose.sh
#
# Environment overrides (defaults match /etc/prox/config.yaml):
#   CLIENT=192.0.2.177 CLOUD=198.51.100.72 ON_PORT=31280 TABLE=100 SECS=8
#
# Sections (each answers one question):
#   service    — is the unit up, what flags did it start with
#   journal    — recent structured events (the proxy's own view)
#   iptables   — live mangle rules WITH counters (which TPROXY rule matched what)
#   routing    — ip rule / routing table TPROXY delivery depends on
#   config     — the config the service actually loaded
#   sockets    — kernel tuple of the short-lived TPROXY conns (what the
#                kernel says vs what the journal says: local/remote must be
#                client-src <-> cloud-dst for TPROXY to have delivered)
#   tcpdump    — both legs on the wire: client->cloud (original tuple) and
#                proxy->cloud (the upstream leg prox dials itself)
#   conntrack  — NAT/redir records, if any exist (should be none for TPROXY)
set -u

CLIENT="${CLIENT:-192.0.2.177}"
CLOUD="${CLOUD:-198.51.100.72}"
CONFIG="${CONFIG:-/etc/prox/config.yaml}"

# Best-effort: prefer the live config over the defaults.
ON_PORT=31280
TABLE=100
CAPTURE_PORTS="port 80 or port 443 or port 14431"
if [[ -r $CONFIG ]]; then
  if p=$(sed -n 's/^listen:[[:space:]]*"\{0,1\}[^"]*:\([0-9]\+\)"\{0,1\}$/\1/p' "$CONFIG" | head -1); [[ -n ${p:-} ]]; then
    ON_PORT=$p
  fi
  if t=$(sed -n 's/^[[:space:]]*routing_table:[[:space:]]*\([0-9]\+\).*/\1/p' "$CONFIG" | head -1); [[ -n ${t:-} ]]; then
    TABLE=$t
  fi
  if line=$(sed -n 's/^ports:[[:space:]]*\[\(.*\)\].*/\1/p' "$CONFIG" | head -1); [[ -n ${line:-} ]]; then
    CAPTURE_PORTS=$(printf '%s\n' "$line" | tr ',' '\n' | grep -o '[0-9]\+' | sed 's/^/port /' | awk 'NR>1{printf " or "} {printf "%s", $0}')
  fi
fi
SECS="${SECS:-8}"

section() { printf '\n===== %s =====\n' "$*"; }

section "params"
echo "client=$CLIENT cloud=$CLOUD on_port=$ON_PORT table=$TABLE secs=$SECS"
echo "capture_ports=[$CAPTURE_PORTS]"
echo "kernel=$(uname -r)  host=$(hostname -I 2>/dev/null || hostname -i 2>/dev/null || hostname)"

section "service"
systemctl cat prox --no-pager 2>&1 || true
systemctl status prox --no-pager -l 2>&1 || true

section "journal (last 60 lines)"
journalctl -u prox -o cat --no-pager -n 60 2>&1 || true

section "iptables mangle (with counters)"
iptables -t mangle -S -v 2>&1 || true
section "iptables filter"
iptables -t filter -S 2>&1 || true

section "routing"
ip rule 2>&1 || true
echo "--- table $TABLE ---"
ip route show table "$TABLE" 2>&1 || true

section "config ($CONFIG)"
cat "$CONFIG" 2>&1 || true

section "listeners"
ss -tlnp 2>&1 || true

section "sockets (watching ${SECS}s for client/cloud conns)"
# TPROXY conns live ~20ms; loop and print each unique tuple once as it
# appears. The tuple is the ground truth for delivery: local should be
# $CLIENT:<ephemeral>, remote $CLOUD:<port> — anything else (e.g. remote
# == local == client source) means the packet did not arrive as a true
# TPROXY tuple.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
for ((t = 0; t < SECS * 5; t++)); do
  ss -tnpH state established "( src $CLIENT or dst $CLOUD )" 2>/dev/null \
    | sort -u | while read -r line; do
      grep -qxF "$line" "$tmp" || { echo "$line"; echo "$line" >>"$tmp"; }
    done
  sleep 0.2
done

section "tcpdump (${SECS}s)"
if command -v tcpdump >/dev/null 2>&1; then
  timeout "$SECS" tcpdump -i any -nn -tt -c 300 \
    "host $CLIENT or (host $CLOUD and ($CAPTURE_PORTS))" 2>&1 || true
else
  echo "tcpdump not installed"
fi

section "conntrack"
if command -v conntrack >/dev/null 2>&1; then
  conntrack -L --src "$CLIENT" 2>&1 || true
  conntrack -L --dst "$CLOUD" 2>&1 || true
else
  echo "conntrack tool not installed (kernel ct still visible via nft if needed)"
fi

section "done"

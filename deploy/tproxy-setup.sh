#!/usr/bin/env bash
#
# deploy/tproxy-setup.sh — idempotent setup for transparent TPROXY TLS capture
#
# Captures TCP connections (ports 80/443) passing through this host and
# redirects them to a local transparent proxy listening on ON_PORT (default
# 31280, matching the prox service's Listen default). Run as root:
#
#     sudo ./deploy/tproxy-setup.sh          # install / refresh
#     sudo ./deploy/tproxy-setup.sh --remove  # tear everything back down
#     sudo ./deploy/tproxy-setup.sh --dry-run # show what would change
#
# It is safe to run repeatedly: existing rules are detected and left alone,
# and marking/routing is only created when absent.
#
# How the pieces fit (canonical Linux TPROXY capture pattern):
#   * `-m socket -j MARK --set-xmark` PREROUTING rule: marks packets whose
#     tuple already has a socket (the established phase of a TPROXY'd
#     connection) so the local route below delivers them to the transparent
#     socket instead of forwarding them on.
#   * `ip rule fwmark N lookup T` + `ip route local 0.0.0.0/0 dev lo table T`:
#     the return-path correction referenced above.
#   * `--dport 80|443 -j TPROXY --tproxy-mark ... --on-port ON_PORT`: captures
#     ALL TCP traffic to those ports — including forwarded LAN-client traffic
#     (e.g. 192.0.2.177 -> its cloud server) — and hands it to the listener.
#     --on-ip is intentionally omitted so the original destination is preserved;
#     the proxy recovers it from the preserved socket tuple (getsockname).
#
set -euo pipefail

# ---- Configuration ---------------------------------------------------------
FW_MARK=1                 # iptables mark used for capture / return routing
ROUTING_TABLE=100         # ip route table for marked (return) traffic
ON_PORT=31280             # local transparent-proxy listen port
CAPTURE_PORTS=(80 443 14431) # TCP ports to capture

# ---- Options ---------------------------------------------------------------
REMOVE=0
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: tproxy-setup.sh [--remove] [--dry-run] [-h|--help]

  (no flags)   install / refresh the capture ruleset (idempotent)
  --remove     tear the ruleset back down (idempotent)
  --dry-run    print the commands that would run without applying them
  -h, --help   show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --remove)  REMOVE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage; exit 2 ;;
  esac
done

# ---- Prerequisites ---------------------------------------------------------
command -v iptables >/dev/null 2>&1 || { echo "error: iptables not found" >&2; exit 1; }
command -v ip       >/dev/null 2>&1 || { echo "error: ip (iproute2) not found" >&2; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  echo "error: this script must be run as root" >&2
  exit 1
fi

# iptables is a single binary whose subcommands are table/chain/rule specs.
IPT="iptables"
# `ip` is a single binary invoked as: ip <subcommand> <args...>

log()  { printf '%s\n' "$*"; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then printf '  + %s\n' "$*"; else "$@"; fi; }

# iptables rule exists? In dry-run assume absent so the adds are shown without
# touching the kernel (which otherwise needs real CAP_NET_ADMIN).
ipt_has() {
  [ "$DRY_RUN" -eq 1 ] && return 1
  "$IPT" -t mangle -C "$@" 2>/dev/null
}

# ---- Install ---------------------------------------------------------------
install() {
  log "installing TPROXY capture ruleset (fwmark=$FW_MARK table=$ROUTING_TABLE on_port=$ON_PORT ports=${CAPTURE_PORTS[*]})"

  # 1. IP forwarding (this host routes traffic, e.g. for 192.0.2.177).
  if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" != "1" ]; then
    log "enabling net.ipv4.ip_forward=1"
    run sysctl -w net.ipv4.ip_forward=1
    if [ "$DRY_RUN" -eq 0 ] && [ -w /etc/sysctl.d ]; then
      printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-prox-tproxy.conf
      log "persisted net.ipv4.ip_forward=1 in /etc/sysctl.d/99-prox-tproxy.conf"
    fi
  fi

  # 2. Established-phase fast path: mark packets that already have a socket
  #    so the "ip rule fwmark N lookup T" local route delivers them to the
  #    transparent socket instead of forwarding them on.
  local mark="0x${FW_MARK}/0xffffffff"
  if ! ipt_has PREROUTING -p tcp -m socket -j MARK --set-xmark "$mark"; then
    log "adding PREROUTING -m socket -j MARK --set-xmark $mark"
    run "$IPT" -t mangle -A PREROUTING -p tcp -m socket -j MARK --set-xmark "$mark"
  fi
  if ! ipt_has PREROUTING -p tcp -m mark --mark "0x${FW_MARK}" -j ACCEPT; then
    log "adding PREROUTING -m mark --mark 0x${FW_MARK} -j ACCEPT"
    run "$IPT" -t mangle -A PREROUTING -p tcp -m mark --mark "0x${FW_MARK}" -j ACCEPT
  fi

  # 3. TPROXY capture rules (idempotent per port).
  for port in "${CAPTURE_PORTS[@]}"; do
    if ! ipt_has PREROUTING -p tcp --dport "$port" -j TPROXY --tproxy-mark "$mark" --on-port "$ON_PORT"; then
      log "adding PREROUTING --dport $port -j TPROXY --on-port $ON_PORT"
      run "$IPT" -t mangle -A PREROUTING -p tcp --dport "$port" -j TPROXY --tproxy-mark "$mark" --on-port "$ON_PORT"
    fi
  done

  # 4. Return-path routing: fwmark -> table, and the table's local route.
  if [ "$DRY_RUN" -eq 1 ] || ! ip rule show 2>/dev/null | grep -qE "fwmark 0x${FW_MARK} +lookup +${ROUTING_TABLE}"; then
    log "adding ip rule: fwmark $FW_MARK lookup $ROUTING_TABLE"
    run ip rule add fwmark "$FW_MARK" lookup "$ROUTING_TABLE"
  fi
  if [ "$DRY_RUN" -eq 1 ] || ! ip route show table "$ROUTING_TABLE" 2>/dev/null | grep -q "local 0.0.0.0/0 dev lo"; then
    log "adding ip route: local 0.0.0.0/0 dev lo table $ROUTING_TABLE"
    run ip route add local 0.0.0.0/0 dev lo table "$ROUTING_TABLE"
  fi

  log "done."
}

# presence check for removal: in dry-run assume present (show the delete);
# otherwise run the real iptables -C existence check.
remove_has() { [ "$DRY_RUN" -eq 1 ] && return 0 || "$@"; }

# presence checks for the ip rule / route created above. In dry-run assume
# present so the deletes are shown; otherwise query the kernel.
ip_rule_present() {
  [ "$DRY_RUN" -eq 1 ] && return 0
  ip rule show 2>/dev/null | grep -qE "fwmark 0x${FW_MARK} +lookup +${ROUTING_TABLE}"
}
ip_route_present() {
  [ "$DRY_RUN" -eq 1 ] && return 0
  ip route show table "$ROUTING_TABLE" 2>/dev/null | grep -q "local 0.0.0.0/0 dev lo"
}

remove() {
  log "removing TPROXY capture ruleset"
  local mark="0x${FW_MARK}/0xffffffff"

  for port in "${CAPTURE_PORTS[@]}"; do
    remove_has ipt_has PREROUTING -p tcp --dport "$port" -j TPROXY --tproxy-mark "$mark" --on-port "$ON_PORT" &&
      run "$IPT" -t mangle -D PREROUTING -p tcp --dport "$port" -j TPROXY --tproxy-mark "$mark" --on-port "$ON_PORT"
  done
  remove_has ipt_has PREROUTING -p tcp -m mark --mark "0x${FW_MARK}" -j ACCEPT &&
    run "$IPT" -t mangle -D PREROUTING -p tcp -m mark --mark "0x${FW_MARK}" -j ACCEPT
  remove_has ipt_has PREROUTING -p tcp -m socket -j MARK --set-xmark "$mark" &&
    run "$IPT" -t mangle -D PREROUTING -p tcp -m socket -j MARK --set-xmark "$mark"
  ip_rule_present && run ip rule del fwmark "$FW_MARK" lookup "$ROUTING_TABLE"
  ip_route_present && run ip route del local 0.0.0.0/0 dev lo table "$ROUTING_TABLE"
  log "done."
}

# ---- Show ------------------------------------------------------------------
show_state() {
  log "current ruleset:"
  "$IPT" -t mangle -S
  ip rule show
  ip route show table "$ROUTING_TABLE" 2>/dev/null || log "  (table $ROUTING_TABLE has no routes)"
  log "net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"
}

# ---- Dispatch --------------------------------------------------------------
if [ "$REMOVE" -eq 1 ]; then
  remove
else
  install
fi

if [ "$DRY_RUN" -eq 0 ]; then
  echo
  show_state
fi

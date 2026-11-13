#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Make this host the IPv4 gateway/router for the client device.
#
# The device is configured with a static gateway of $GW_ADDR, this
# host's wired address (eth0). The uplink is whatever interface carries the
# preferred default route; here that is the same wired interface, so forwarded
# traffic is a single-interface hairpin. Other LAN segments are untouched.
#
# What this does
#   1. net.ipv4.ip_forward=1 (persistent)
#   2. masquerade on the uplink zone, so replies come back through this host.
#      Without NAT the upstream router would answer the device directly and
#      later interception would only ever see one direction.
#   3. send_redirects=0, so the kernel never tells the device to bypass us.
#      Essential here: ingress and egress are the same interface, which is
#      exactly when Linux emits an ICMP redirect by default.
#   4. deterministic ARP: both interfaces share $CLIENT_NET, so pin ARP to
#      the owning interface and use loose rp_filter.
#
# Idempotent; safe to re-run. Requires root.
# ---------------------------------------------------------------------------
set -euo pipefail

GW_ADDR=${GW_ADDR:-LAN_IP}
CLIENT_NET=${CLIENT_NET:-LAN_NET}
SYSCTL_FILE=/etc/sysctl.d/90-client-gateway.conf

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ ${EUID} -eq 0 ]] || die "run as root: sudo $0"

# --- topology --------------------------------------------------------------
lan_if=${LAN_IF:-$(ip -o -4 addr show | awk -v ip="$GW_ADDR" \
    '{split($4, a, "/"); if (a[1] == ip) {print $2; exit}}')}
[[ -n ${lan_if:-} ]] || die "no interface owns $GW_ADDR (override with LAN_IF=)"

wan_if=${WAN_IF:-$(ip -4 route show default | awk '$1 == "default" {
    for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}')}
[[ -n ${wan_if:-} ]] || die "no default route (override with WAN_IF=)"

zone_of() {
    local z
    z=$(firewall-cmd --get-zone-of-interface="$1" 2>/dev/null || true)
    if [[ -z $z || $z == "no zone" ]]; then
        firewall-cmd --get-default-zone
    else
        printf '%s\n' "$z"
    fi
}

lan_zone=$(zone_of "$lan_if")
wan_zone=$(zone_of "$wan_if")

printf 'client gateway : %s on %s [zone %s]\n' "$GW_ADDR" "$lan_if" "$lan_zone"
printf 'uplink           : %s [zone %s]\n' "$wan_if" "$wan_zone"
if [[ $lan_if == "$wan_if" ]]; then
    echo "note: ingress and uplink are the same interface (single-NIC hairpin)"
fi

ups_con=$(nmcli -g GENERAL.CONNECTION dev show "$lan_if" 2>/dev/null || true)
if [[ -n ${ups_con:-} ]] &&
        [[ $(nmcli -g ipv4.method con show "$ups_con" 2>/dev/null) == auto ]]; then
    printf 'warning: %s is DHCP-assigned on %s; the device loses its gateway\n' \
        "$GW_ADDR" "$lan_if"
    printf '         if the lease moves. Reserve it on the DHCP server, or\n'
    printf '         make it static in NetworkManager.\n'
fi
echo

# --- 1. kernel -------------------------------------------------------------
{
    cat <<EOF
# Managed by setup-gateway.sh -- route the device through this host.
net.ipv4.ip_forward = 1

# Both interfaces share the same subnet; keep source validation loose.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Never hand the device an ICMP redirect pointing away from this host.
# Mandatory when ingress and uplink are the same interface (hairpin).
net.ipv4.conf.all.send_redirects = 0
EOF
    for iface in $(printf '%s\n' "$lan_if" "$wan_if" | sort -u); do
        cat <<EOF
net.ipv4.conf.${iface}.send_redirects = 0
# Answer ARP only on the interface that owns the address.
net.ipv4.conf.${iface}.arp_ignore = 1
net.ipv4.conf.${iface}.arp_announce = 2
EOF
    done
} > "$SYSCTL_FILE"
sysctl -q -p "$SYSCTL_FILE"
echo "kernel  : ip_forward=1, redirects off, ARP pinned"

# --- 2. firewall -----------------------------------------------------------
fw=firewall-cmd

# Forwarding from the LAN zone to itself needs the zone's <forward/> flag.
# FedoraWorkstation ships it; enable it if the interface landed elsewhere.
if ! "$fw" --permanent --zone="$lan_zone" --query-forward >/dev/null 2>&1; then
    "$fw" --permanent --zone="$lan_zone" --add-forward >/dev/null
    echo "firewall: intra-zone forwarding enabled in $lan_zone"
fi

if [[ $lan_zone == "$wan_zone" ]]; then
    # One zone: masquerade on the zone covers both the uplink and LAN egress.
    if ! "$fw" --permanent --zone="$wan_zone" --query-masquerade >/dev/null 2>&1; then
        "$fw" --permanent --zone="$wan_zone" --add-masquerade >/dev/null
        echo "firewall: masquerade enabled in $wan_zone"
    fi
else
    # Separate zones: explicit policy LAN -> uplink, plus NAT for its traffic.
    if ! "$fw" --permanent --get-policies 2>/dev/null | grep -qx client-gateway; then
        "$fw" --permanent --new-policy=client-gateway >/dev/null
    fi
    if ! "$fw" --permanent --policy=client-gateway --list-ingress-zones 2>/dev/null |
            grep -qx "$lan_zone"; then
        "$fw" --permanent --policy=client-gateway --add-ingress-zone="$lan_zone" >/dev/null
    fi
    if ! "$fw" --permanent --policy=client-gateway --list-egress-zones 2>/dev/null |
            grep -qx "$wan_zone"; then
        "$fw" --permanent --policy=client-gateway --add-egress-zone="$wan_zone" >/dev/null
    fi
    "$fw" --permanent --policy=client-gateway --set-target=ACCEPT >/dev/null
    if ! "$fw" --permanent --policy=client-gateway --query-masquerade >/dev/null 2>&1; then
        "$fw" --permanent --policy=client-gateway --add-masquerade >/dev/null
    fi
    echo "firewall: policy client-gateway ($lan_zone -> $wan_zone, accept + masquerade)"
fi

"$fw" --reload >/dev/null
echo "firewall: reloaded"
echo

# --- 3. verify -------------------------------------------------------------
failed=0
check() {
    local out
    if out=$(eval "$2" 2>&1); then
        printf '  PASS  %s\n' "$1"
    else
        printf '  FAIL  %s\n' "$1"
        printf '%s\n' "$out" | sed -n '1,3p' | sed 's/^/        /'
        failed=1
    fi
}

echo "verify:"
check "net.ipv4.ip_forward = 1" \
    '[[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]'
check "send_redirects = 0 on $lan_if" \
    '[[ $(sysctl -n net.ipv4.conf.$lan_if.send_redirects) == 0 ]]'
if [[ $lan_zone == "$wan_zone" ]]; then
    check "masquerade active on $wan_zone" \
        '[[ $("$fw" --zone="$wan_zone" --query-masquerade) == yes ]]'
    # grep -c, not -q: with pipefail, grep -q exits early, nft dies of
    # SIGPIPE and the pipeline reports failure even when the rule is present.
    check "forward accept rule for $lan_if" \
        "[[ \$(nft list ruleset | grep -Ec 'oifname \"$lan_if\".*accept') -gt 0 ]]"
else
    check "masquerade active on policy client-gateway" \
        '[[ $("$fw" --policy=client-gateway --query-masquerade) == yes ]]'
fi
check "NAT masquerade rule in ruleset" \
    '[[ $(nft list ruleset | grep -c masquerade) -gt 0 ]]'
check "ARP for $GW_ADDR answered only by $lan_if" \
    '[[ $(sysctl -n net.ipv4.conf.$lan_if.arp_ignore) == 1 ]]'

if ((failed)); then
    echo
    echo "diagnostics:"
    nft list tables 2>&1 | sed 's/^/  /' || true
    printf '  masquerade rules in ruleset: %s\n' \
        "$(nft list ruleset 2>/dev/null | grep -c masquerade)"
    echo "  nat_POSTROUTING:"
    { nft list chain inet firewalld nat_POSTROUTING 2>&1 || true; } |
        sed -n '1,12p' | sed 's/^/    /' || true
    echo "  zone:"
    { "$fw" --info-zone="$lan_zone" 2>&1 || true; } |
        grep -E 'interfaces|masquerade|forward' | sed 's/^/    /' || true
    echo "  hint: if the rule is missing, run 'sudo systemctl restart firewalld'"
    echo "        and re-run this script."
fi

cat <<EOF

Now power-cycle the device, or re-apply its static config, so it re-ARPs
for $GW_ADDR. Then watch it work:

  sudo tcpdump -ni $lan_if -e 'ip and not host $GW_ADDR'
  sudo nft list ruleset | grep -B2 -A2 masquerade
  cat /proc/net/nf_conntrack | grep "src=${CLIENT_NET%%/*}."   # NATed flows

Undo:
  sudo rm -f $SYSCTL_FILE
EOF
if [[ $lan_zone == "$wan_zone" ]]; then
    printf '  sudo %s --permanent --zone=%s --remove-masquerade\n' "$fw" "$wan_zone"
else
    printf '  sudo %s --permanent --delete-policy=client-gateway\n' "$fw"
fi
cat <<EOF
  sudo $fw --reload
  sudo sysctl -q -w net.ipv4.ip_forward=0
EOF

exit $failed

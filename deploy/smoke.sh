#!/usr/bin/env bash
#
# deploy/smoke.sh — client-side smoke test for a deployed prox.
#
# Run on a machine whose traffic to the upstream is transparently
# intercepted by the proxy (routed through the proxy host, TPROXY rules
# installed). Needs only curl and openssl — no root, no extra clients.
#
#   ./smoke.sh -c /path/to/intermediate.pem [-u upstream-host] [-p port]
#              [-h http-upstream-host]
#   PROXY_SSH=user@proxy-host ./smoke.sh -c ...   # also grep the proxy log
#
# Checks:
#   1. plain-http      transparent plain HTTP relay works
#   2. mitm-forged     TLS via the proxy presents a leaf signed by the
#                      compromised intermediate (which the client trusts)
#   3. mitm-rejected   a client without the intermediate rejects the forged
#                      chain — proves MITM is active on the pair
#   4. patched-tunnel  after the rejection the pair is patched; the next
#                      connection tunnels to the real upstream (its real
#                      cert now verifies with the system store)
#   5. keepalive       two plain HTTP requests share one connection
#
# Re-running on an already-patched pair makes check 3 pass-as-patched; use a
# different -u/-p pair to exercise the full sequence again (the patched
# recheck interval unmarks pairs on the proxy side).
set -u

UP=example.com
PORT=443
HTTP_UP=example.com
CA=""
SSH="${PROXY_SSH:-}"

usage() {
    echo "usage: $0 -c intermediate.pem [-u upstream-host] [-p port] [-h http-upstream-host]" >&2
    exit 2
}
while getopts ":u:p:h:c:" o; do
    case $o in
        u) UP=$OPTARG ;;
        p) PORT=$OPTARG ;;
        h) HTTP_UP=$OPTARG ;;
        c) CA=$OPTARG ;;
        *) usage ;;
    esac
done
[ -n "$CA" ] || usage
[ -r "$CA" ] || { echo "cannot read CA file: $CA" >&2; exit 2; }

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0
report() { # $1=name $2=ok(0/1) $3=detail
    if [ "$2" -eq 0 ]; then
        echo "PASS  $1  $3"
        pass=$((pass + 1))
    else
        echo "FAIL  $1  $3"
        fail=$((fail + 1))
    fi
}

sclient() { # $1=extra openssl s_client args
    openssl s_client -connect "$UP:$PORT" -servername "$UP" "$1" </dev/null 2>"$TMP/sc.err"
}
verify_code() { # prints the "Verify return code: N (...)" number
    grep 'Verify return code:' "$TMP/sc.err" 2>/dev/null | sed 's/.*Verify return code: \([0-9]*\).*/\1/'
}

echo "smoke: upstream=$UP:$PORT http=$HTTP_UP ca=$CA"

# 1. Plain HTTP relay: any 2xx/3xx means the request traversed the proxy.
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "http://$HTTP_UP/" 2>"$TMP/curl.err")
ok=1
case $code in 2* | 3*) ok=0 ;; esac
[ $ok -ne 0 ] && report plain-http 1 "$(cat "$TMP/curl.err" 2>/dev/null) code=$code" \
    || report plain-http 0 "http://$HTTP_UP/ -> $code"

# 2. TLS with the compromised intermediate trusted: the forged leaf must
# verify, and its issuer must be exactly the intermediate we deployed.
out=$(sclient -CAfile "$CA")
vcode=$(verify_code)
printf '%s\n' "$out" | openssl x509 -noout -issuer 2>/dev/null > "$TMP/issuer.got"
openssl x509 -in "$CA" -noout -issuer > "$TMP/issuer.want"
ok=1
[ "$vcode" = "0" ] && grep -qF "$(cat "$TMP/issuer.want")" "$TMP/issuer.got" && ok=0
report mitm-forged $ok "verify=$vcode issuer=$(cat "$TMP/issuer.got")"

# 3. Same pair, system store (no intermediate): the forged chain must be
# rejected — proof that MITM, not the real upstream, is in the path.
sclient "" >/dev/null
vcode=$(verify_code)
ok=1
[ -n "$vcode" ] && [ "$vcode" != "0" ] && ok=0
report mitm-rejected $ok "verify=$vcode (expected non-zero)"

# 4. The rejection marks the pair patched: the next connection tunnels to
# the real upstream, whose real cert verifies with the system store.
sclient "" >/dev/null
vcode=$(verify_code)
ok=1
[ "$vcode" = "0" ] && ok=0
report patched-tunnel $ok "verify=$vcode (expected 0: real upstream cert)"

# 5. Keep-alive: two requests on one plain HTTP connection.
codes=$(curl -sS -o /dev/null -w '%{http_code}\n' --max-time 15 \
    "http://$HTTP_UP/" "http://$HTTP_UP/index.html" 2>"$TMP/curl.err")
n=0
for c in $codes; do
    case $c in 2* | 3*) n=$((n + 1)) ;; esac
done
ok=1
[ "$n" = "2" ] && ok=0
report keepalive $ok "codes: $(echo $codes | tr '\n' ' ')"

# Optional: grep the proxy's own log for the corresponding events.
if [ -n "$SSH" ]; then
    log=$(ssh -o BatchMode=yes -o ConnectTimeout=10 "$SSH" \
        "journalctl -u prox --since '15 min ago' -o cat 2>/dev/null || true")
    for pat in 'relay' 'mitm' 'tunnel'; do
        if printf '%s' "$log" | grep -q "\"msg\":\"$pat\""; then
            report "log-$pat" 0 "found in proxy log"
        else
            report "log-$pat" 1 "\"msg\":\"$pat\" not found on $SSH (journalctl -u prox)"
        fi
    done
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ]

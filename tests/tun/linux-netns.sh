#!/usr/bin/env bash
# End-to-end test of the TUN inbound on Linux, inside network namespaces.
#
#   root ns:   Xray (VLESS server)        10.200.0.1:20001
#              targets                    10.99.0.1, 10.99.0.2 (:8080 HTTP, :9000 UDP echo)
#   client ns: sybau with a TUN inbound   10.200.0.2, default route via 10.200.0.1
#
# The targets answer with the address they see, so a proxied request
# (Xray connects from the root ns) is told apart from a direct one
# (10.200.0.2). Needs root, ip, nft, curl, python3 and Xray (XRAY_BIN,
# default: the one tests/interop/build-refs.sh builds).
#
#   sudo tests/tun/linux-netns.sh [path/to/sybau]
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
sybau="$(realpath "${1:-$here/../../target/debug/sybau}")"
cd "$here"
xray="${XRAY_BIN:-$here/../interop/.bin/xray}"
work="$(mktemp -d)"
ns=sybtun
uuid=6d5a1c4e-3b7e-4a2f-9a8c-0e1f2a3b4c5d
pids=()
failed=0
passed=0

cleanup() {
    for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
    pkill -f "$work/sybau.json" 2>/dev/null
    ip netns exec "$ns" "$sybau" tun-cleanup >/dev/null 2>&1
    ip netns del "$ns" 2>/dev/null
    ip link del syb-h 2>/dev/null
    rm -rf "$work" "/etc/netns/$ns"
}
trap cleanup EXIT

check() { # name expected actual
    if [ "$2" = "$3" ]; then
        echo "  ok    $1"
        passed=$((passed + 1))
    else
        echo "  FAIL  $1: expected '$2', got '$3'"
        failed=$((failed + 1))
    fi
}

in_ns() { ip netns exec "$ns" "$@"; }
http_body() { in_ns curl -s --max-time 5 "$1" 2>/dev/null || echo "unreachable"; }

# ---- topology ---------------------------------------------------------
ip netns add "$ns"
ip link add syb-h type veth peer name syb-c
ip link set syb-c netns "$ns"
ip addr add 10.200.0.1/24 dev syb-h
ip link set syb-h up
# Target addresses live on the host side of the veth; the client reaches
# them through its default route, not as on-link neighbours.
ip addr add 10.99.0.1/32 dev syb-h
ip addr add 10.99.0.2/32 dev syb-h
in_ns ip link set lo up
in_ns ip addr add 10.200.0.2/24 dev syb-c
in_ns ip link set syb-c up
in_ns ip route add default via 10.200.0.1
# Loose reverse-path filtering, as on most distributions.
in_ns sysctl -qw net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.default.rp_filter=2

python3 "$here/helpers.py" http-server 10.99.0.1 10.99.0.2 & pids+=($!)
python3 "$here/helpers.py" udp-echo 10.99.0.1 & pids+=($!)
# Applications in the client ns ask a server that does not exist; only
# DNS hijacking can answer them.
mkdir -p "/etc/netns/$ns"
echo "nameserver 192.0.2.53" > "/etc/netns/$ns/resolv.conf"
# Xray resolves the domain that fake-ip hands back to it.
cat > "$work/xray.json" <<EOF
{"log": {"loglevel": "warning"},
 "dns": {"hosts": {"domain:fake.test": "10.99.0.1"}},
 "inbounds": [{"listen": "10.200.0.1", "port": 20001, "protocol": "vless",
               "settings": {"clients": [{"id": "$uuid"}], "decryption": "none"}}],
 "outbounds": [{"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}}]}
EOF
"$xray" run -c "$work/xray.json" >"$work/xray.log" 2>&1 & pids+=($!)
sleep 1

echo "direct, before the core starts:"
check "target sees the client address" "10.200.0.2" "$(http_body http://10.99.0.1:8080/)"

write_config() { # kill_switch
    cat > "$work/sybau.json" <<EOF
{"log": {"level": "debug"},
 "control": {"enabled": true, "path": "$work/ctl.sock"},
 "inbounds": [{"type": "tun", "tag": "tun", "interface_name": "sybtun0",
               "strict_route": true, "kill_switch": $1,
               "route_exclude_address": ["10.99.0.2/32"]}],
 "outbounds": [{"type": "vless", "tag": "proxy", "server": "10.200.0.1", "port": 20001, "uuid": "$uuid"},
               {"type": "direct", "tag": "direct"}],
 "dns": {"servers": [{"tag": "upstream", "address": "udp://10.200.0.1"},
                     {"tag": "fake", "address": "fakeip"}],
         "rules": [{"domain_suffix": ["fake.test"], "server": "fake"}],
         "hosts": {"hijack.test": ["10.99.0.1"]}},
 "route": {"final": "proxy"}}
EOF
}

start_core() {
    # The log is appended to: wait for a line written by this run.
    local before
    before=$(wc -l < "$work/sybau.log" 2>/dev/null || echo 0)
    # Not through `in_ns`: `$!` must be the core itself, not a subshell.
    ip netns exec "$ns" "$sybau" run -c "$work/sybau.json" >>"$work/sybau.log" 2>&1 &
    core=$!
    pids+=($core)
    for _ in $(seq 100); do
        if tail -n +"$((before + 1))" "$work/sybau.log" | grep -q 'TUN `sybtun0` up'; then
            return
        fi
        if ! kill -0 "$core" 2>/dev/null; then
            echo "core exited:"; tail -n +"$((before + 1))" "$work/sybau.log"; exit 1
        fi
        sleep 0.1
    done
    echo "core did not start:"; tail -n +"$((before + 1))" "$work/sybau.log"; exit 1
}

write_config true
start_core

echo "through the TUN:"
body="$(http_body http://10.99.0.1:8080/)"
check "TCP is proxied through Xray" "proxied" "$([ "$body" != 10.200.0.2 ] && [ "$body" != unreachable ] && echo proxied || echo "$body")"
check "route_exclude_address goes direct" "10.200.0.2" "$(http_body http://10.99.0.2:8080/)"
udp="$(in_ns python3 "$here/helpers.py" udp-ask 10.99.0.1 9000 2>&1)"
check "UDP is proxied through Xray" "proxied" "$(case "$udp" in *" ping") [ "${udp%% *}" != 10.200.0.2 ] && echo proxied ;; *) echo "$udp" ;; esac)"
check "DNS over UDP to any server is hijacked" "rcode=0 10.99.0.1" "$(in_ns python3 "$here/helpers.py" dns-ask 192.0.2.53 hijack.test 2>&1)"
check "DNS over TCP to any server is hijacked" "rcode=0 10.99.0.1" "$(in_ns python3 "$here/helpers.py" dns-ask 192.0.2.53 hijack.test tcp 2>&1)"
fake="$(in_ns python3 "$here/helpers.py" dns-ask 192.0.2.53 www.fake.test 2>&1)"
check "fake-ip answers from 198.18.0.0/15" "fake" "$(case "$fake" in "rcode=0 198.1"[89].*) echo fake ;; *) echo "$fake" ;; esac)"
body="$(in_ns curl -s --max-time 5 http://www.fake.test:8080/ 2>&1)"
check "fake-ip address is mapped back to the domain" "proxied" "$([ -n "$body" ] && [ "$body" != 10.200.0.2 ] && echo proxied || echo "$body")"
check "the proxy got the domain, not the fake address" "1" "$(grep -c -- '-> www.fake.test:8080' "$work/sybau.log")"
check "8 MiB download is intact" "8388608 ok" "$(in_ns python3 "$here/helpers.py" fetch http://10.99.0.1:8080/blob 2>&1)"
speed="$(in_ns curl -s -o /dev/null -w '%{speed_download}' --max-time 20 http://10.99.0.1:8080/blob)"
echo "        (download speed through TUN + VLESS: $(python3 -c "print(f'{$speed/1048576:.1f} MiB/s')"))"
check "connections show up in the control API" "yes" "$(in_ns "$sybau" ctl --endpoint "$work/ctl.sock" connections.list 2>/dev/null | grep -q '"inbound": "tun"' && echo yes || echo no)"

echo "reload keeps the TUN working:"
in_ns "$sybau" ctl --endpoint "$work/ctl.sock" core.reload >/dev/null
sleep 0.5
body="$(http_body http://10.99.0.1:8080/)"
check "kill switch stays across the reload" "1" "$(in_ns nft list tables | grep -c sybau)"
check "TCP after reload" "proxied" "$([ "$body" != 10.200.0.2 ] && [ "$body" != unreachable ] && echo proxied || echo "$body")"

echo "kill switch after a crash (SIGKILL):"
kill -9 "$core"; wait "$core" 2>/dev/null
sleep 0.3
check "traffic is blocked" "unreachable" "$(http_body http://10.99.0.1:8080/)"
# curl exits with 7 when the connection is refused (the kill switch
# rejects); Xray itself would accept and then close (52).
check "strict mode blocks the on-link gateway too" "7" "$(in_ns curl -s --max-time 3 http://10.200.0.1:20001/ >/dev/null 2>&1; echo $?)"
in_ns "$sybau" tun-cleanup >/dev/null
check "tun-cleanup lifts it" "10.200.0.2" "$(http_body http://10.99.0.1:8080/)"

echo "clean exit:"
start_core
body="$(http_body http://10.99.0.1:8080/)"
check "TCP is proxied again" "proxied" "$([ "$body" != 10.200.0.2 ] && [ "$body" != unreachable ] && echo proxied || echo "$body")"
kill -TERM "$core"; wait "$core" 2>/dev/null
check "routes and kill switch are gone" "10.200.0.2" "$(http_body http://10.99.0.1:8080/)"
check "no rules left" "0" "$(in_ns ip rule show | grep -c 'lookup 2022')"
check "no nft table left" "0" "$(in_ns nft list tables | grep -c sybau)"

echo "without strict_route the LAN stays direct:"
sed -i 's/"strict_route": true, "kill_switch": true/"strict_route": false, "kill_switch": false/' "$work/sybau.json"
start_core
in_ns curl -s --max-time 3 http://10.200.0.1:20001/ >/dev/null 2>&1
check "on-link host is reached directly, not through the TUN" "0" "$(grep -c -- '-> 10.200.0.1:20001' "$work/sybau.log")"
body="$(http_body http://10.99.0.1:8080/)"
check "default route still goes through the TUN" "proxied" "$([ "$body" != 10.200.0.2 ] && [ "$body" != unreachable ] && echo proxied || echo "$body")"
kill -TERM "$core"; wait "$core" 2>/dev/null

echo "per-user and per-program exclusions:"
python3 - "$work/sybau.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["inbounds"][0].update({"exclude_uid": [65534], "exclude_process": ["curl"]})
json.dump(cfg, open(sys.argv[1], "w"))
PY
start_core
check "excluded user goes direct (kernel rule)" "10.200.0.2" "$(in_ns setpriv --reuid=65534 --regid=65534 --clear-groups curl -s --max-time 5 http://10.99.0.1:8080/ 2>&1)"
check "excluded program goes direct (process lookup)" "10.200.0.2" "$(http_body http://10.99.0.1:8080/)"
body="$(in_ns python3 -c 'import urllib.request; print(urllib.request.urlopen("http://10.99.0.1:8080/", timeout=5).read().decode())' 2>&1)"
check "other programs are still proxied" "proxied" "$([ -n "$body" ] && [ "$body" != 10.200.0.2 ] && echo proxied || echo "$body")"
kill -TERM "$core"; wait "$core" 2>/dev/null

echo "descriptor handed over by the platform (Android VpnService style):"
ip netns exec "$ns" python3 "$here/helpers.py" tun-fd-launch sybfd0 "$work/sybau.json" "$sybau" >>"$work/sybau.log" 2>&1 &
core=$!
pids+=($core)
for _ in $(seq 50); do grep -q "TUN .sybfd0. up" "$work/sybau.log" && break; sleep 0.1; done
body="$(http_body http://10.99.0.1:8080/)"
check "TCP through the platform's TUN is proxied" "proxied" "$([ "$body" != 10.200.0.2 ] && [ "$body" != unreachable ] && echo proxied || echo "$body")"
check "the core installed no routes of its own" "0" "$(in_ns ip rule show | grep -c 'lookup 2022')"
in_ns "$sybau" ctl --endpoint "$work/ctl.sock" core.reload >/dev/null
sleep 0.5
body="$(http_body http://10.99.0.1:8080/)"
check "reload keeps the platform's descriptor usable" "proxied" "$([ "$body" != 10.200.0.2 ] && [ "$body" != unreachable ] && echo proxied || echo "$body")"
kill -TERM "$core"; wait "$core" 2>/dev/null

echo
echo "$passed passed, $failed failed"
if [ "$failed" -ne 0 ]; then
    echo "--- sybau log (tail) ---"; tail -40 "$work/sybau.log"
    exit 1
fi

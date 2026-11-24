#!/usr/bin/env bash
# =============================================================================
# NIDPS gateway pre-flight check. Run on the gateway right before a demo:
#
#   sudo ./check_gateway.sh <wan_if> <lan_if> [lan_cidr] [victim_ip]
#   e.g. sudo ./check_gateway.sh wlan0 eth1 192.168.50.0/24 192.168.50.10
#
# Checks everything on the gateway side, prints PASS/FAIL with a fix for each,
# then prints the exact commands for the attacker machine using the gateway's
# CURRENT outside address (hotspot addresses change between connections).
# Changes nothing. Exit code = number of failed checks.
# =============================================================================
set -uo pipefail

WAN="${1:?Usage: $0 <wan_if> <lan_if> [lan_cidr] [victim_ip]}"
LAN="${2:?Usage: $0 <wan_if> <lan_if> [lan_cidr] [victim_ip]}"
LAN_CIDR="${3:-192.168.50.0/24}"
VICTIM="${4:-${LAN_CIDR%.*}.10}"
LAN_GW="${LAN_CIDR%.*}.1"
PORT="${PORT:-5000}"

if [[ $(id -u) -ne 0 ]]; then echo "Run as root (sudo) so iptables can be read." >&2; exit 1; fi

passed=0; failed=0
check() { # check <ok:0|1> <what> <how to fix>
  if [[ $1 == 0 ]]; then echo "  PASS  $2"; passed=$((passed + 1))
  else echo "  FAIL  $2"; echo "        fix: $3"; failed=$((failed + 1)); fi
}
addr_of() { ip -4 -o addr show dev "$1" 2>/dev/null | awk '{print $4}' | head -1; }
ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
overlaps() { # overlaps <ip/prefix> <ip/prefix>
  local p1=${1#*/} p2=${2#*/} p
  p=$(( p1 < p2 ? p1 : p2 ))
  local mask=$(( p == 0 ? 0 : (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF ))
  (( ($(ip2int "${1%/*}") & mask) == ($(ip2int "${2%/*}") & mask) ))
}

echo "NIDPS gateway pre-flight: outside=$WAN inside=$LAN network=$LAN_CIDR victim=$VICTIM"

WAN_ADDR=$(addr_of "$WAN"); WAN_IP=${WAN_ADDR%/*}
[[ -n $WAN_ADDR ]]; check $? "$WAN has an IPv4 address (${WAN_ADDR:-none})" \
  "connect $WAN to the hotspot/outside network; check names with: ip -br addr"

LAN_ADDR=$(addr_of "$LAN")
[[ $LAN_ADDR == "$LAN_GW/${LAN_CIDR#*/}" ]]; check $? "$LAN has $LAN_GW/${LAN_CIDR#*/} (found: ${LAN_ADDR:-none})" \
  "re-run: sudo ./setup_gateway.sh $WAN $LAN $LAN_CIDR  (it also saves the address permanently)"

if [[ -n $WAN_ADDR ]]; then
  ! overlaps "$WAN_ADDR" "$LAN_CIDR"; check $? "$LAN_CIDR does not overlap the outside network ($WAN_ADDR)" \
    "choose another inside range, e.g. 192.168.77.0/24, and re-run setup_gateway.sh with it"
else
  check 1 "$LAN_CIDR does not overlap the outside network" "fix the outside address first"
fi

[[ $(sysctl -n net.ipv4.ip_forward 2>/dev/null) == 1 ]]; check $? "IPv4 forwarding is on" \
  "sudo sysctl -w net.ipv4.ip_forward=1   (setup_gateway.sh makes it permanent)"

[[ $(iptables -S FORWARD 2>/dev/null | grep -v '^-P' | head -1) == "-A FORWARD -j NIDPS" ]]; check $? "NIDPS is rule 1 in FORWARD" \
  "start NIDPS with NIDPS_MODE=gateway (it inserts the jump), or re-run setup_gateway.sh"

iptables -t nat -C POSTROUTING -s "$LAN_CIDR" -o "$WAN" -j MASQUERADE 2>/dev/null; check $? "NAT (MASQUERADE) from $LAN_CIDR out of $WAN" \
  "re-run: sudo ./setup_gateway.sh $WAN $LAN $LAN_CIDR"

pgrep -a snort 2>/dev/null | grep -qE -- "-i[[:space:]]+$LAN([[:space:]]|$)"; check $? "Snort is running on $LAN" \
  "sudo ./start_snort.sh $LAN   (Snort must watch the INSIDE port)"

{ curl -s -m 3 "http://127.0.0.1:$PORT/api/health" || curl -sk -m 3 "https://127.0.0.1:$PORT/api/health"; } 2>/dev/null | grep -q NIDPS
check $? "NIDPS is answering on port $PORT" "cd backend && npm start   (check backend/.env: NIDPS_MODE=gateway, ENABLE_REAL_IPTABLES=true)"

ping -c 1 -W 2 "$VICTIM" >/dev/null 2>&1; check $? "victim $VICTIM answers ping from the gateway" \
  "victim needs IP $VICTIM/${LAN_CIDR#*/}, gateway $LAN_GW, and its firewall must allow ping (or use a Linux victim)"

echo
if (( failed == 0 )); then echo "All $passed checks passed."; else echo "$failed check(s) failed, $passed passed. Fix them before the demo."; fi

cat <<EOF

On the ATTACKER (connected to the same hotspot/outside network as $WAN):
  Windows (administrator PowerShell):  route add ${LAN_CIDR%/*} mask $(
    p=${LAN_CIDR#*/}; m=$(( (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF ))
    echo "$(( m >> 24 & 255 )).$(( m >> 16 & 255 )).$(( m >> 8 & 255 )).$(( m & 255 ))") ${WAN_IP:-<gateway outside IP>}
  Linux:                               sudo ip route add $LAN_CIDR via ${WAN_IP:-<gateway outside IP>}
Then from the attacker:
  ping $WAN_IP          -> must reply (if not: the hotspot isolates clients; use a router/switch)
  ping $VICTIM     -> must reply before the attack
  nmap -sS $VICTIM  -> NIDPS should block the attacker within about a second
EOF

exit "$failed"

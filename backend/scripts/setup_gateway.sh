#!/usr/bin/env bash
# =============================================================================
# NIDPS gateway mode: turn this Linux machine into the router for a small
# protected network, so NIDPS can block attacks travelling THROUGH it.
#
#   sudo ./setup_gateway.sh <wan_if> <lan_if> [lan_cidr]
#   e.g. sudo ./setup_gateway.sh wlan0 eth1 192.168.50.0/24
#
#   wan_if  - interface towards the campus network / internet
#   lan_if  - interface towards the protected demo network (switch or victim PC)
#
# It is idempotent (safe to run twice) and only ADDS rules; it never flushes
# existing ones. Then set NIDPS_MODE=gateway in backend/.env.
# =============================================================================
set -euo pipefail

WAN="${1:?Usage: $0 <wan_if> <lan_if> [lan_cidr]}"
LAN="${2:?Usage: $0 <wan_if> <lan_if> [lan_cidr]}"
LAN_CIDR="${3:-192.168.50.0/24}"
LAN_ADDR="${LAN_CIDR%.*}.1/${LAN_CIDR#*/}"

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)." >&2; exit 1; fi
for i in "$WAN" "$LAN"; do ip link show "$i" >/dev/null 2>&1 || { echo "Interface $i not found. See: ip -br link" >&2; exit 1; }; done

add_rule() { # add_rule <table> <chain> <rule...>  - only if not already present
  local table=$1 chain=$2; shift 2
  iptables -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -t "$table" -A "$chain" "$@"
}

echo "[*] LAN interface $LAN -> $LAN_ADDR"
ip link set "$LAN" up
ip addr show dev "$LAN" | grep -q "inet ${LAN_ADDR%/*}/" || ip addr add "$LAN_ADDR" dev "$LAN"

echo "[*] Enabling IPv4 forwarding (persistent)"
sysctl -qw net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/90-nidps-gateway.conf

echo "[*] NAT: $LAN_CIDR leaves via $WAN"
add_rule nat POSTROUTING -s "$LAN_CIDR" -o "$WAN" -j MASQUERADE

echo "[*] NIDPS chain first in FORWARD, then normal forwarding rules"
iptables -N NIDPS 2>/dev/null || true
iptables -C FORWARD -j NIDPS 2>/dev/null || iptables -I FORWARD 1 -j NIDPS
add_rule filter FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
add_rule filter FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
add_rule filter FORWARD -i "$WAN" -o "$LAN" -d "$LAN_CIDR" -j ACCEPT

cat <<EOF
[+] Gateway ready.
    Protected network : $LAN_CIDR  (gateway address ${LAN_ADDR%/*})
    Victim PC         : give it e.g. ${LAN_CIDR%.*}.10/24, gateway ${LAN_ADDR%/*}, DNS 1.1.1.1
    Snort             : sudo ./start_snort.sh $LAN
    backend/.env      : NIDPS_MODE=gateway  ENABLE_REAL_IPTABLES=true  SNORT_INTERFACE=$LAN
                        NIDPS_ALLOWLIST=${LAN_ADDR%/*}
    Check             : sudo iptables -L FORWARD -n --line-numbers ; sudo iptables -L NIDPS -n -v
Note: iptables rules added here are not saved across reboots. Re-run this script,
or install iptables-persistent. NIDPS re-creates its own NIDPS rules on start-up.
EOF

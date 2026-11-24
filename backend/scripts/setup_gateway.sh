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

ip2int() { local IFS=.; read -r a b c d <<<"$1"; echo $(( (a << 24) | (b << 16) | (c << 8) | d )); }
WAN_ADDR=$(ip -4 -o addr show dev "$WAN" | awk '{print $4}' | head -1)
if [[ -n $WAN_ADDR ]]; then
  p1=${WAN_ADDR#*/}; p2=${LAN_CIDR#*/}; p=$(( p1 < p2 ? p1 : p2 ))
  mask=$(( (0xFFFFFFFF << (32 - p)) & 0xFFFFFFFF ))
  if (( ($(ip2int "${WAN_ADDR%/*}") & mask) == ($(ip2int "${LAN_CIDR%/*}") & mask) )); then
    echo "Inside range $LAN_CIDR overlaps the outside network $WAN_ADDR. Pick another, e.g.: $0 $WAN $LAN 192.168.77.0/24" >&2
    exit 1
  fi
fi

echo "[*] LAN interface $LAN -> $LAN_ADDR"
if command -v nmcli >/dev/null 2>&1 && nmcli -t -f DEVICE device status 2>/dev/null | grep -qx "$LAN"; then
  # NetworkManager manages this port: save the address as a permanent connection,
  # otherwise NM may look for DHCP on it and remove the address mid-demo.
  nmcli con delete nidps-lan >/dev/null 2>&1 || true
  nmcli con add type ethernet ifname "$LAN" con-name nidps-lan ipv4.method manual \
    ipv4.addresses "$LAN_ADDR" ipv6.method disabled connection.autoconnect yes >/dev/null
  nmcli con up nidps-lan >/dev/null
  echo "    saved as NetworkManager connection 'nidps-lan' (survives reconnects and reboots)"
else
  ip link set "$LAN" up
  ip addr show dev "$LAN" | grep -q "inet ${LAN_ADDR%/*}/" || ip addr add "$LAN_ADDR" dev "$LAN"
fi

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
    Pre-flight check  : sudo ./check_gateway.sh $WAN $LAN $LAN_CIDR   (run right before the demo)
Note: iptables rules added here are not saved across reboots. Re-run this script,
or install iptables-persistent. NIDPS re-creates its own NIDPS rules on start-up.
EOF

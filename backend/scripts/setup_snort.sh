#!/usr/bin/env bash
# =============================================================================
# NIDPS - Snort 2.9 sensor setup (Ubuntu 24.04, native Linux or WSL2). Run as root.
#
#   sudo ./setup_snort.sh <interface> <home_net_cidr> [backend_user]
#   e.g. sudo ./setup_snort.sh eth0 192.168.50.0/24 student
#
# - installs Snort if missing
# - writes the NIDPS demo rules to /etc/snort/rules/local.rules
# - sets HOME_NET to the network you protect (instead of "any")
# - enables fast-alert output
# - makes /var/log/snort accessible to group "nidps" only (not world-writable),
#   and adds the backend user to that group (the alert file is group-writable so
#   the dashboard's demo simulator can append to it)
# - installs the restricted iptables wrapper NIDPS uses through sudo
# =============================================================================
set -euo pipefail

IFACE="${1:?Usage: $0 <interface> <home_net_cidr> [backend_user]}"
HOME_NET="${2:?Usage: $0 <interface> <home_net_cidr> [backend_user]}"
BACKEND_USER="${3:-${SUDO_USER:-}}"
CONF=/etc/snort/snort.conf
LOG_DIR=/var/log/snort

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)." >&2; exit 1; fi
if ! ip link show "$IFACE" >/dev/null 2>&1; then echo "Interface $IFACE not found. See: ip -br link" >&2; exit 1; fi

if ! command -v snort >/dev/null; then
  echo "[*] Installing Snort..."
  DEBIAN_FRONTEND=noninteractive apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq snort
fi

echo "[*] Log directory: $LOG_DIR (root:nidps, 750; alert file 660)"
getent group nidps >/dev/null || groupadd --system nidps
mkdir -p "$LOG_DIR"
touch "$LOG_DIR/snort.alert.fast"
chown -R root:nidps "$LOG_DIR"
chmod 750 "$LOG_DIR"
chmod 660 "$LOG_DIR/snort.alert.fast"
if [[ -n "$BACKEND_USER" ]]; then
  usermod -aG nidps "$BACKEND_USER"
  echo "    added $BACKEND_USER to group nidps (log out and in again for it to apply)"
fi

echo "[*] Installing restricted iptables wrapper: /usr/local/sbin/nidps-iptables"
install -o root -g root -m 0755 "$(dirname "$0")/nidps-iptables" /usr/local/sbin/nidps-iptables
if [[ -n "$BACKEND_USER" ]]; then
  echo "$BACKEND_USER ALL=(root) NOPASSWD: /usr/local/sbin/nidps-iptables" > /etc/sudoers.d/nidps
  chmod 0440 /etc/sudoers.d/nidps
  visudo -cf /etc/sudoers.d/nidps >/dev/null && echo "    sudo rule written: /etc/sudoers.d/nidps"
fi

echo "[*] Writing NIDPS demo rules to /etc/snort/rules/local.rules"
cat > /etc/snort/rules/local.rules <<'EOF'
# ----------------------------------------------------------------------------
# NIDPS demo signatures. Priority 1 = automatic block; Priority 2 = escalates
# after repeats; Priority 3 = logged only. SIDs 1000001+ are reserved for local use.
# ----------------------------------------------------------------------------
# Ping sweep / probe (log only - pings are normal on a LAN)
alert icmp any any -> $HOME_NET any (msg:"NIDPS - ICMP Echo Request (ping)"; itype:8; classtype:misc-activity; priority:3; sid:1000001; rev:2;)
# SSH connection attempts: medium; repeated attempts escalate to a block
alert tcp any any -> $HOME_NET 22 (msg:"NIDPS - Inbound SSH Connection Attempt"; flags:S; classtype:attempted-admin; priority:2; sid:1000002; rev:2;)
# Port scan signatures (Nmap SYN scan with typical window size 1024)
alert tcp any any -> $HOME_NET any (msg:"NIDPS - Possible Nmap SYN Scan"; flags:S; window:1024; classtype:attempted-recon; priority:1; sid:1000003; rev:2;)
# Web attacks against port 80/8080
alert tcp any any -> $HOME_NET [80,8080] (msg:"NIDPS - SQL Injection UNION SELECT"; flow:to_server,established; content:"union"; nocase; content:"select"; nocase; distance:0; classtype:web-application-attack; priority:1; sid:1000004; rev:2;)
alert tcp any any -> $HOME_NET [80,8080] (msg:"NIDPS - Log4j JNDI Lookup Attempt"; flow:to_server,established; content:"|24 7B|jndi|3A|"; nocase; classtype:attempted-admin; priority:1; sid:1000005; rev:2;)
EOF

echo "[*] Configuring $CONF (HOME_NET=$HOME_NET, fast-alert output)"
sed -i "s#^ipvar HOME_NET .*#ipvar HOME_NET $HOME_NET#" "$CONF"
sed -i 's#^ipvar EXTERNAL_NET .*#ipvar EXTERNAL_NET any#' "$CONF"
grep -q '^include \$RULE_PATH/local.rules' "$CONF" || echo 'include $RULE_PATH/local.rules' >> "$CONF"
grep -q '^output alert_fast: snort.alert.fast' "$CONF" || echo 'output alert_fast: snort.alert.fast' >> "$CONF"

echo "[*] Testing the configuration..."
snort -T -q -c "$CONF" -i "$IFACE" >/dev/null && echo "[+] Snort configuration OK. Start it with: sudo ./start_snort.sh $IFACE"

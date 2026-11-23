#!/usr/bin/env bash
# ==============================================================================
# NIDPS Snort IDS Setup Script for Ubuntu 24.04 (WSL2 / Linux)
# ==============================================================================
set -e

echo "[*] Ensuring log directory exists..."
mkdir -p /var/log/snort
chmod -R 777 /var/log/snort
touch /var/log/snort/snort.alert.fast
chmod 666 /var/log/snort/snort.alert.fast

echo "[*] Configuring /etc/snort/rules/local.rules..."
cat << 'EOF' > /etc/snort/rules/local.rules
# ----------------------------------------------------
# NIDPS Custom Attack Signatures (Priority 1 for Auto-Mitigation)
# ----------------------------------------------------
# 1. ICMP Ping Detection (Echo Request Type 8 Code 0)
alert icmp any any -> $HOME_NET any (msg:"NIDPS TEST - ICMP Ping Probe Detected"; itype:8; icode:0; classtype:attempted-recon; priority:1; sid:1000001; rev:1;)

# 2. Inbound SSH TCP Connection Attempt (Port 22 SYN flag)
alert tcp any any -> $HOME_NET 22 (msg:"NIDPS TEST - Inbound SSH Connection Attempt"; flags:S; classtype:attempted-admin; priority:1; sid:1000002; rev:1;)

# 3. HTTP GET Infiltration / Web Recon
alert tcp any any -> $HOME_NET 80 (msg:"NIDPS TEST - Web Infiltration Attack Probe"; content:"GET"; classtype:web-application-attack; priority:1; sid:1000003; rev:1;)

# 4. Port 8080 Alternate Web Service Probe
alert tcp any any -> $HOME_NET 8080 (msg:"NIDPS TEST - Alternate Web Service Probe"; flags:S; classtype:attempted-recon; priority:1; sid:1000004; rev:1;)
EOF

echo "[*] Configuring /etc/snort/snort.conf..."
# Ensure HOME_NET and EXTERNAL_NET are set to 'any' for local WSL/subnet testing
sed -i 's/^ipvar HOME_NET .*/ipvar HOME_NET any/' /etc/snort/snort.conf
sed -i 's/^ipvar EXTERNAL_NET .*/ipvar EXTERNAL_NET any/' /etc/snort/snort.conf

# Check if alert_fast is already present
if ! grep -q "output alert_fast: snort.alert.fast" /etc/snort/snort.conf; then
  echo "output alert_fast: snort.alert.fast" >> /etc/snort/snort.conf
fi

echo "[*] Testing Snort configuration syntax..."
snort -T -c /etc/snort/snort.conf -i eth0

echo "[*] Setup completed successfully!"

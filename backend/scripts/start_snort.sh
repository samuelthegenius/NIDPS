#!/usr/bin/env bash
# Start the Snort sensor in fast-alert mode (Linux / WSL2). Run as root.
#   sudo ./start_snort.sh [interface]     (default: $SNORT_INTERFACE or eth0)
# In gateway mode, use the LAN-side interface (the one facing the protected network).
set -euo pipefail
IFACE="${1:-${SNORT_INTERFACE:-eth0}}"
LOG_DIR=/var/log/snort

if [[ $EUID -ne 0 ]]; then echo "Run as root (sudo)." >&2; exit 1; fi
echo "NIDPS Snort sensor | interface: $IFACE | alerts: $LOG_DIR/snort.alert.fast | Ctrl+C to stop"
mkdir -p "$LOG_DIR"
# No "-A fast" here: on the command line it would override the config and write to
# $LOG_DIR/alert instead of snort.alert.fast (the file NIDPS watches).
exec snort -q -c /etc/snort/snort.conf -i "$IFACE" -l "$LOG_DIR"

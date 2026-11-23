#!/usr/bin/env bash
# Start Snort in active Intrusion Detection mode on interface eth0
echo "========================================================"
echo " Starting Snort IDS Sensor (WSL2 / Linux)"
echo " Monitoring interface: eth0"
echo " Alert output: /var/log/snort/snort.alert.fast"
echo " Press Ctrl+C to stop the sensor."
echo "========================================================"

mkdir -p /var/log/snort
chmod -R 777 /var/log/snort

exec snort -A fast -q -c /etc/snort/snort.conf -i eth0 -l /var/log/snort

#!/usr/bin/env bash
# Checks scripts/nidps-iptables accepts only NIDPS rule shapes.
# Run: bash backend/test/nidps-iptables.cases.sh   (uses dry-run mode; runs nothing as root)
W="$(dirname "$0")/../scripts/nidps-iptables"
fail=0
ok()  { if NIDPS_WRAPPER_DRY=1 bash "$W" "$@" >/dev/null 2>&1; then echo "  ok   accept: $*"; else echo "  FAIL should accept: $*"; fail=1; fi; }
bad() { if NIDPS_WRAPPER_DRY=1 bash "$W" "$@" >/dev/null 2>&1; then echo "  FAIL should reject: $*"; fail=1; else echo "  ok   reject: $*"; fi; }

ok  iptables -N NIDPS
ok  iptables -F NIDPS
ok  ip6tables -F NIDPS
ok  iptables -C INPUT -j NIDPS
ok  iptables -I FORWARD 1 -j NIDPS
ok  iptables -I NIDPS 1 -s 203.0.113.5 -j DROP
ok  iptables -C NIDPS -s 203.0.113.5 -j DROP
ok  iptables -D NIDPS -s 203.0.113.5 -j DROP
ok  ip6tables -I NIDPS 1 -s 2001:db8::5 -j DROP
bad iptables --modprobe=/tmp/evil -L
bad iptables -F INPUT
bad iptables -F
bad iptables -I INPUT 1 -j ACCEPT
bad iptables -I NIDPS 1 -s 203.0.113.5 -j ACCEPT
bad iptables -I NIDPS 1 -s 0.0.0.0/0 -j DROP
bad iptables -I NIDPS 1 -s '1.2.3.4;id' -j DROP
bad iptables -I NIDPS 1 -s 203.0.113.5 -j DROP --modprobe=/tmp/x
bad sh -c id
bad
exit $fail

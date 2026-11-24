#!/usr/bin/env bash
# Tests for scripts/check_gateway.sh using fake system commands on PATH.
# Run: bash backend/test/check_gateway.cases.sh     (no root, changes nothing)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$HERE/../scripts/check_gateway.sh"
STUBS="$(mktemp -d)"
fail=0

# ---- fake commands, driven by FAKE_* environment variables --------------------
stub() { printf '#!/usr/bin/env bash\n%s\n' "$2" > "$STUBS/$1"; chmod +x "$STUBS/$1"; }
stub id        'echo 0'
stub ip        'dev="${@: -1}"; v="FAKE_IP_$dev"; [[ -n "${!v:-}" ]] && echo "3: $dev    inet ${!v} brd x scope global $dev"; exit 0'
stub sysctl    'echo "${FAKE_FORWARD:-1}"'
stub iptables  'if [[ "$*" == "-S FORWARD" ]]; then printf "%s\n" "-P FORWARD ACCEPT" "${FAKE_FORWARD_RULE1:--A FORWARD -j NIDPS}" "-A FORWARD -i eth1 -o wlan0 -j ACCEPT"; exit 0; fi
               if [[ "$1" == "-t" && "$3" == "-C" ]]; then [[ "${FAKE_NAT:-1}" == 1 ]]; exit; fi; exit 0'
stub pgrep     'echo "${FAKE_SNORT-1234 snort -q -c /etc/snort/snort.conf -i eth1 -l /var/log/snort}"; [[ -n "${FAKE_SNORT-x}" ]]'
stub curl      '[[ "${FAKE_NIDPS:-1}" == 1 ]] && echo "{\"status\":\"online\",\"system\":\"NIDPS\"}"'
stub ping      '[[ "${FAKE_VICTIM:-1}" == 1 ]]'

run() { # run <description> <expected-exit: 0|nonzero> <must-contain> [VAR=value ...]
  local desc=$1 want=$2 needle=$3; shift 3
  local out code
  out=$(env PATH="$STUBS:$PATH" FAKE_IP_wlan0=10.42.0.15/24 FAKE_IP_eth1=192.168.50.1/24 "$@" bash "$SCRIPT" wlan0 eth1 192.168.50.0/24 192.168.50.10 2>&1)
  code=$?
  if { [[ $want == 0 && $code == 0 ]] || [[ $want != 0 && $code != 0 ]]; } && grep -qF -- "$needle" <<<"$out"; then
    echo "  ok   $desc"
  else
    echo "  FAIL $desc (exit $code)"; echo "$out" | sed 's/^/       | /'; fail=1
  fi
}

run "all checks pass"                      0       "All 9 checks passed"
run "prints Windows route with WAN IP"     0       "route add 192.168.50.0 mask 255.255.255.0 10.42.0.15"
run "prints Linux route with WAN IP"       0       "ip route add 192.168.50.0/24 via 10.42.0.15"
run "no hotspot address"                   nonzero "FAIL  wlan0 has an IPv4 address"           FAKE_IP_wlan0=
run "inside address missing"               nonzero "FAIL  eth1 has 192.168.50.1/24"            FAKE_IP_eth1=
run "inside range overlaps the hotspot"    nonzero "FAIL  192.168.50.0/24 does not overlap"    FAKE_IP_wlan0=192.168.50.77/24
run "forwarding off"                       nonzero "FAIL  IPv4 forwarding is on"               FAKE_FORWARD=0
run "NIDPS jump not first in FORWARD"      nonzero "FAIL  NIDPS is rule 1 in FORWARD"          "FAKE_FORWARD_RULE1=-A FORWARD -j ACCEPT"
run "NAT missing"                          nonzero "FAIL  NAT (MASQUERADE)"                    FAKE_NAT=0
run "Snort on the wrong interface"         nonzero "FAIL  Snort is running on eth1"            "FAKE_SNORT=99 snort -i wlan0"
run "Snort not running"                    nonzero "FAIL  Snort is running on eth1"            FAKE_SNORT=
run "NIDPS not running"                    nonzero "FAIL  NIDPS is answering"                  FAKE_NIDPS=0
run "victim unreachable"                   nonzero "FAIL  victim 192.168.50.10 answers ping"   FAKE_VICTIM=0

rm -rf "$STUBS"
exit $fail

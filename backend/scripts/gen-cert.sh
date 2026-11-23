#!/usr/bin/env bash
# Create a self-signed HTTPS certificate for the NIDPS dashboard, valid for
# localhost and this machine's LAN addresses. Output: <repo>/certs/nidps.{crt,key}
#   ./gen-cert.sh                     (Linux, WSL, macOS or Git Bash on Windows)
#   ./gen-cert.sh 192.168.1.10        (add extra IP addresses to the certificate)
# Then in backend/.env:  TLS_CERT=../certs/nidps.crt  TLS_KEY=../certs/nidps.key
# Browsers will warn that the certificate is self-signed; that is expected.
set -euo pipefail
export MSYS_NO_PATHCONV=1   # stop Git Bash rewriting "/CN=..." into a Windows path
OUT="$(cd "$(dirname "$0")/../.." && pwd)/certs"
mkdir -p "$OUT"
command -v cygpath >/dev/null 2>&1 && OUT="$(cygpath -m "$OUT")"   # Git Bash: C:/... for openssl.exe

SAN="DNS:localhost,IP:127.0.0.1"
IPS="$*"
if [[ -z $IPS ]]; then
  if hostname -I >/dev/null 2>&1; then
    IPS="$(hostname -I)"
  elif command -v ipconfig.exe >/dev/null 2>&1 || command -v ipconfig >/dev/null 2>&1; then
    IPS="$(ipconfig 2>/dev/null | tr -d '\r' | sed -n 's/.*IPv4[^:]*: *\([0-9.]*\).*/\1/p')"
  fi
fi
for ip in $IPS; do [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && SAN="$SAN,IP:$ip"; done

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -subj "/CN=NIDPS Console" -addext "subjectAltName=$SAN" \
  -keyout "$OUT/nidps.key" -out "$OUT/nidps.crt"
chmod 600 "$OUT/nidps.key"
echo "Created $OUT/nidps.crt and nidps.key (SAN: $SAN)"

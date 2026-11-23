#!/usr/bin/env bash
# Create a self-signed HTTPS certificate for the NIDPS dashboard, valid for
# localhost and this machine's LAN addresses. Output: <repo>/certs/nidps.{crt,key}
#   ./gen-cert.sh            (Linux, WSL, macOS or Git Bash on Windows)
# Then in backend/.env:  TLS_CERT=../certs/nidps.crt  TLS_KEY=../certs/nidps.key
# Browsers will warn that the certificate is self-signed; that is expected.
set -euo pipefail
OUT="$(cd "$(dirname "$0")/../.." && pwd)/certs"
mkdir -p "$OUT"

SAN="DNS:localhost,IP:127.0.0.1"
if command -v hostname >/dev/null && hostname -I >/dev/null 2>&1; then
  for ip in $(hostname -I); do [[ $ip == *.* ]] && SAN="$SAN,IP:$ip"; done
fi

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 365 \
  -subj "/CN=NIDPS Console" -addext "subjectAltName=$SAN" \
  -keyout "$OUT/nidps.key" -out "$OUT/nidps.crt" 2>/dev/null
chmod 600 "$OUT/nidps.key"
echo "Created $OUT/nidps.crt and nidps.key (SAN: $SAN)"

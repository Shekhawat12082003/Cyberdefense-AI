#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-192.168.31.37}"
API="http://${TARGET}:5000"
FRONTEND="http://${TARGET}:5173"
WORKDIR="${TMPDIR:-/tmp}/cyberdefense-network-test"
mkdir -p "$WORKDIR"

command -v curl >/dev/null || { echo "curl is required"; exit 1; }
command -v nmap >/dev/null || { echo "nmap is required"; exit 1; }
command -v jq >/dev/null || { echo "jq is required"; exit 1; }

echo "[1/5] Checking backend health: $API"
curl --fail --silent --show-error --max-time 5 "$API/api/health" | jq .

echo "[2/5] Checking frontend: $FRONTEND"
curl --fail --silent --show-error --head --max-time 5 "$FRONTEND" >/dev/null
echo "Frontend is reachable."

echo "[3/5] Authenticating to read network alerts"
read -r -p "Application username [admin]: " USERNAME
USERNAME="${USERNAME:-admin}"
read -r -s -p "Application password: " PASSWORD
echo

TOKEN="$(
  curl --fail --silent --show-error --max-time 5 \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg u "$USERNAME" --arg p "$PASSWORD" \
      '{username: $u, password: $p}')" \
    "$API/api/login" | jq -er '.token'
)"

AUTH=(-H "Authorization: Bearer ${TOKEN}")

echo "[4/5] Network monitor state before scan"
curl --fail --silent --show-error "${AUTH[@]}" \
  "$API/api/network/stats" | tee "$WORKDIR/stats-before.json" | jq .

echo "[5/5] Running bounded authorized scan against $TARGET"
echo "Application ports:"
nmap -Pn -sT -sV -T2 --max-rate 20 -p 5000,5173 "$TARGET" |
  tee "$WORKDIR/application-ports.txt"

echo "Limited 1-1000 TCP scan:"
nmap -Pn -sT -T2 --max-rate 50 -p 1-1000 "$TARGET" |
  tee "$WORKDIR/portscan.txt"

sleep 3

echo
echo "Network monitor state after scan:"
curl --fail --silent --show-error "${AUTH[@]}" \
  "$API/api/network/stats" | tee "$WORKDIR/stats-after.json" | jq .

echo
echo "Alerts mentioning this test source or a port scan:"
SOURCE_IP="$(hostname -I 2>/dev/null | cut -d' ' -f1 || true)"
curl --fail --silent --show-error "${AUTH[@]}" \
  "$API/api/network/alerts" |
  tee "$WORKDIR/alerts.json" |
  jq --arg source "$SOURCE_IP" '
    if type == "array" then
      [.[] | select(
        ((tostring | ascii_upcase | contains("PORT_SCAN")) or
         (tostring | ascii_upcase | contains("SCAN")) or
         ($source != "" and tostring | contains($source)))
      )]
    else .
    end
  '

echo
echo "Artifacts saved in: $WORKDIR"

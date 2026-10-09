#!/usr/bin/env bash
#
# End-to-end test: the OFFICIAL opentunnel client against OUR relay build.
#
# What it proves (beyond `cargo test`): the real client binary from
# anomalyco/opentunnel can provision a tunnel through our relay's HTTP API,
# attach its bridge WebSocket, and serve traffic through SNI-routed TLS that
# the client itself terminates.
#
# Requirements (env):
#   CI_DOMAIN     public domain for this run, e.g. ci-relay.example.com
#                 (DNS hosted on Cloudflare; no A record needed)
#   CI_CF_TOKEN   Cloudflare API token with DNS-edit on the zone (ACME DNS-01)
#   CI_CF_ZONE_ID Cloudflare zone ID of CI_DOMAIN
#   RELAY_BIN     path to our opentunnel-relay binary
#   CLIENT_BIN    path to the official `opentunnel` binary
#
# Trust notes: the official client only trusts the bundled Mozilla roots, so
# the relay must serve a publicly-trusted certificate -> real Let's Encrypt
# issuance happens here (2 certificates per run: API domain + tunnel).
set -euo pipefail

DOMAIN="${CI_DOMAIN:?CI_DOMAIN not set}"
RELAY_BIN="${RELAY_BIN:?RELAY_BIN not set}"
CLIENT_BIN="${CLIENT_BIN:?CLIENT_BIN not set}"
PROFILE="ci"
ROUTE_NAME="itest"
BACKEND_PORT=8080
MARKER="opentunnel-ci-ok-$(date +%s)"

echo "==> point ${DOMAIN} at this machine"
echo "127.0.0.1 ${DOMAIN}" | sudo tee -a /etc/hosts > /dev/null

echo "==> start backend on 127.0.0.1:${BACKEND_PORT}"
mkdir -p /tmp/ci-backend
echo "$MARKER" > /tmp/ci-backend/marker.txt
python3 -m http.server "$BACKEND_PORT" --bind 127.0.0.1 \
  --directory /tmp/ci-backend > /tmp/ci-backend.log 2>&1 &
BACKEND_PID=$!

echo "==> start relay (real ACME via DNS-01)"
sudo "$RELAY_BIN" \
  --domain "$DOMAIN" \
  --cf-token "$CI_CF_TOKEN" \
  --cf-zone-id "$CI_CF_ZONE_ID" \
  --data-dir /tmp/ci-relay-data > /tmp/ci-relay.log 2>&1 &
RELAY_PID=$!

cleanup() {
  echo "==> cleanup"
  "$CLIENT_BIN" down --profile "$PROFILE" > /dev/null 2>&1 || true
  sudo kill "$RELAY_PID" 2> /dev/null || true
  kill "$BACKEND_PID" 2> /dev/null || true
}
dump_logs() {
  echo "----- relay log -----"
  tail -50 /tmp/ci-relay.log || true
}
trap 'dump_logs; cleanup' EXIT

echo "==> wait for relay API (includes first ACME issuance, up to ~10 min)"
for _ in $(seq 1 60); do
  if curl -fsS "https://${DOMAIN}/health" > /dev/null 2>&1; then
    echo "relay API is up"
    break
  fi
  sleep 10
done
curl -fsS "https://${DOMAIN}/health" > /dev/null
echo "relay health check passed (publicly-trusted TLS)"

echo "==> provision tunnel + route with the OFFICIAL client"
export OPENTUNNEL_API="https://${DOMAIN}"
URL=$("$CLIENT_BIN" route add "127.0.0.1:${BACKEND_PORT}" \
  --name "$ROUTE_NAME" --profile "$PROFILE" \
  | grep -o 'https://[^[:space:]]*$' | tail -1)
[ -n "$URL" ] || { echo "could not parse public URL from client output"; exit 1; }
echo "public URL: $URL"
HOST="${URL#https://}"
HOST="${HOST%%/*}"

echo "==> fetch through the tunnel"
BODY=$(curl -fsS --resolve "${HOST}:443:127.0.0.1" "${URL}/marker.txt")
if [ "$BODY" != "$MARKER" ]; then
  echo "MISMATCH: expected [$MARKER] got [$BODY]"
  exit 1
fi
echo "E2E OK: official client served [$BODY] through our relay"

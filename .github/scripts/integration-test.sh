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
#   CI_DOMAIN     base domain for CI, e.g. ci-relay.example.com
#                 (DNS hosted on Cloudflare; no A record needed)
#   CI_CF_TOKEN   Cloudflare API token with DNS-edit on the zone (ACME DNS-01)
#   CI_CF_ZONE_ID Cloudflare zone ID of CI_DOMAIN
#   RELAY_BIN     path to our opentunnel-relay binary
#   CLIENT_BIN    path to the official `opentunnel` binary
#
# Each run serves its own hostname, run-<run id>-<attempt>.<CI_DOMAIN>. Let's
# Encrypt allows only 5 certificates per identical name set per week, so a
# fixed hostname would hit that limit after a few reruns. TXT records left
# behind by an interrupted run are removed at the start of the next one.
#
# Trust notes: the official client only trusts bundled Mozilla roots, so the
# relay must serve a publicly-trusted certificate -> real Let's Encrypt
# issuance happens here (2 certificates per run: API domain + tunnel).
set -euo pipefail

BASE_DOMAIN="${CI_DOMAIN:?CI_DOMAIN not set}"
RELAY_BIN="${RELAY_BIN:?RELAY_BIN not set}"
CLIENT_BIN="${CLIENT_BIN:?CLIENT_BIN not set}"
RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
DOMAIN="run-${RUN_ID}-${GITHUB_RUN_ATTEMPT:-1}.${BASE_DOMAIN}"
PROFILE="ci"
ROUTE_NAME="itest"
BACKEND_PORT=8080
MARKER="opentunnel-ci-ok-$(date +%s)"
BACKEND_PID=""
RELAY_PID=""

dump_logs() {
  echo "----- relay log -----"
  tail -50 /tmp/ci-relay.log || true
}

# Deletes TXT records whose names start with $2 and end with $1 (the zone
# filter is applied by Cloudflare). Failures are reported, never fatal.
delete_txt_records() {
  local suffix="$1" prefix="$2"
  if [ -z "${CI_CF_TOKEN:-}" ] || [ -z "${CI_CF_ZONE_ID:-}" ]; then
    return 0
  fi
  local api="https://api.cloudflare.com/client/v4/zones/${CI_CF_ZONE_ID}/dns_records"
  local ids id
  if ! ids=$(curl -fsS -H "Authorization: Bearer ${CI_CF_TOKEN}" \
      "${api}?type=TXT&per_page=100&name.endswith=${suffix}" \
      | jq -r --arg prefix "$prefix" \
        '.result[] | select(.name | startswith($prefix)) | .id'); then
    echo "could not list TXT records ending in ${suffix}"
    return 0
  fi
  for id in $ids; do
    if curl -fsS -X DELETE -H "Authorization: Bearer ${CI_CF_TOKEN}" \
        "${api}/${id}" > /dev/null; then
      echo "deleted TXT record ${id}"
    else
      echo "could not delete TXT record ${id}"
    fi
  done
}

remove_hosts_entry() {
  sudo sed -i "/^127\\.0\\.0\\.1 ${DOMAIN//./\\.}\$/d" /etc/hosts 2> /dev/null || true
}

cleanup() {
  echo "==> cleanup"
  "$CLIENT_BIN" down --profile "$PROFILE" > /dev/null 2>&1 || true
  if [ -n "$RELAY_PID" ]; then sudo kill "$RELAY_PID" 2> /dev/null || true; fi
  if [ -n "$BACKEND_PID" ]; then kill "$BACKEND_PID" 2> /dev/null || true; fi
  delete_txt_records "$DOMAIN" "_acme-challenge." || true
  remove_hosts_entry
}
trap 'dump_logs; cleanup' EXIT

echo "==> remove challenge records left by interrupted runs"
delete_txt_records "$BASE_DOMAIN" "_acme-challenge.run-" || true

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

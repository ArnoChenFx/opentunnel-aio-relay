#!/usr/bin/env bash
#
# End-to-end test: authenticated provisioning + the OFFICIAL opentunnel client
# against OUR relay build.
#
# What it proves (beyond `cargo test`): the real client binary from
# anomalyco/opentunnel can attach to a tunnel provisioned through the
# authenticated API, serve traffic through SNI-routed TLS that the client
# itself terminates, and interoperate with this relay's bridge protocol.
#
# Requirements (env):
#   CI_DOMAIN     public domain for this run, e.g. ci-relay.example.com
#                 (DNS hosted on Cloudflare; no A record needed)
#   CI_CF_TOKEN   Cloudflare API token with DNS-edit on the zone (ACME DNS-01)
#   CI_CF_ZONE_ID Cloudflare zone ID of CI_DOMAIN
#   RELAY_BIN     path to our opentunnel-relay binary
#   CLIENT_BIN    path to the official `opentunnel` binary
#
# The upstream client currently creates tunnels without an admin header. This
# test provisions and issues the certificate with the authenticated HTTP API,
# then places that identity in the official client's normal profile store so
# the official binary still exercises attach, bridge, TLS and SNI routing.
# Trust notes: the official client only trusts bundled Mozilla roots, so the
# relay must serve a publicly-trusted certificate -> real Let's Encrypt
# issuance happens here (2 certificates per run: API domain + tunnel).
set -euo pipefail

BASE_DOMAIN="${CI_DOMAIN:?CI_DOMAIN not set}"
DOMAIN="run-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}.${BASE_DOMAIN}"
RELAY_BIN="${RELAY_BIN:?RELAY_BIN not set}"
CLIENT_BIN="${CLIENT_BIN:?CLIENT_BIN not set}"
PROFILE="ci"
ROUTE_NAME="itest"
BACKEND_PORT=8080
MARKER="opentunnel-ci-ok-$(date +%s)"
ADMIN_TOKEN="$(openssl rand -hex 32)"
TOKEN_CURL_CONFIG="/tmp/ci-admin-token.curlrc"
CERT_JSON="/tmp/ci-certificate.json"

export XDG_DATA_HOME=/tmp/ci-client-data
export XDG_CONFIG_HOME=/tmp/ci-client-config
export XDG_STATE_HOME=/tmp/ci-client-state
export XDG_RUNTIME_DIR=/tmp/ci-client-runtime
mkdir -p "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
chmod 700 "$XDG_RUNTIME_DIR"
printf 'header = "Authorization: Bearer %s"\n' "$ADMIN_TOKEN" > "$TOKEN_CURL_CONFIG"
chmod 600 "$TOKEN_CURL_CONFIG"

CLIENT_PROFILE_DIR="$XDG_DATA_HOME/opentunnel/$PROFILE"
BACKEND_PID=""
RELAY_PID=""

cleanup() {
  echo "==> cleanup"
  "$CLIENT_BIN" down --profile "$PROFILE" > /dev/null 2>&1 || true
  if [ -n "$RELAY_PID" ]; then sudo kill "$RELAY_PID" 2> /dev/null || true; fi
  if [ -n "$BACKEND_PID" ]; then kill "$BACKEND_PID" 2> /dev/null || true; fi
  sudo rm -rf /tmp/ci-relay-data 2> /dev/null || true
  rm -f "$TOKEN_CURL_CONFIG" "$CERT_JSON" /tmp/ci-bind-response.json /tmp/ci-tunnel.csr
  rm -rf "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"
}
dump_logs() {
  echo "----- relay log -----"
  tail -50 /tmp/ci-relay.log || true
}
trap 'dump_logs; cleanup' EXIT


echo "==> point ${DOMAIN} at this machine"
echo "127.0.0.1 ${DOMAIN}" | sudo tee -a /etc/hosts > /dev/null

echo "==> start backend on 127.0.0.1:${BACKEND_PORT}"
mkdir -p /tmp/ci-backend
echo "$MARKER" > /tmp/ci-backend/marker.txt
python3 -m http.server "$BACKEND_PORT" --bind 127.0.0.1 \
  --directory /tmp/ci-backend > /tmp/ci-backend.log 2>&1 &
BACKEND_PID=$!

echo "==> start relay (real ACME via DNS-01)"
export OT_ADMIN_TOKEN="$ADMIN_TOKEN"
sudo --preserve-env=OT_ADMIN_TOKEN "$RELAY_BIN" \
  --domain "$DOMAIN" \
  --cf-token "$CI_CF_TOKEN" \
  --cf-zone-id "$CI_CF_ZONE_ID" \
  --data-dir /tmp/ci-relay-data > /tmp/ci-relay.log 2>&1 &
RELAY_PID=$!
unset OT_ADMIN_TOKEN

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

export OPENTUNNEL_API="https://${DOMAIN}"
echo "==> provision a tunnel using the server admin token"
CREATED=$(curl -fsS --config "$TOKEN_CURL_CONFIG" \
  -H 'Content-Type: application/json' -d '{}' "https://${DOMAIN}/api/tunnel")
TUNNEL_ID=$(jq -er '.tunnel.id' <<<"$CREATED")
TUNNEL_HOST=$(jq -er '.tunnel.hostname' <<<"$CREATED")
TUNNEL_TOKEN=$(jq -er '.token' <<<"$CREATED")

echo "==> issue a tunnel certificate through the per-tunnel API"
mkdir -p "$CLIENT_PROFILE_DIR"
chmod 700 "$CLIENT_PROFILE_DIR"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$CLIENT_PROFILE_DIR/private-key.pem" \
  -out /tmp/ci-tunnel.csr -subj "/CN=${TUNNEL_HOST}" \
  -addext "subjectAltName=DNS:${TUNNEL_HOST}"
CSR=$(cat /tmp/ci-tunnel.csr)
jq -n --arg csr "$CSR" '{csr: $csr}' | \
  curl -fsS --config <(printf 'header = "Authorization: Bearer %s"\n' "$TUNNEL_TOKEN") \
    -H 'Content-Type: application/json' -d @- \
    "https://${DOMAIN}/api/tunnel/${TUNNEL_ID}/certificate" > /tmp/ci-bind-response.json

CERT_STATE=""
for _ in $(seq 1 90); do
  curl -fsS --config <(printf 'header = "Authorization: Bearer %s"\n' "$TUNNEL_TOKEN") \
    "https://${DOMAIN}/api/tunnel/${TUNNEL_ID}/certificate" > "$CERT_JSON"
  CERT_STATE=$(jq -r '.state.type // empty' "$CERT_JSON")
  if [ "$CERT_STATE" = ready ]; then
    break
  elif [ "$CERT_STATE" = failed ]; then
    jq -r '.state.reason' "$CERT_JSON" >&2
    exit 1
  fi
  sleep 5
done
[ "$CERT_STATE" = ready ] || { echo "certificate issuance did not finish"; exit 1; }

jq -r '.state.certificate' "$CERT_JSON" > "$CLIENT_PROFILE_DIR/certificate.pem"
jq -r '.state.chain' "$CERT_JSON" > "$CLIENT_PROFILE_DIR/chain.pem"
CERT_EXPIRY=$(jq -er '.state.expiry' "$CERT_JSON")
jq -n --arg id "$TUNNEL_ID" --arg hostname "$TUNNEL_HOST" \
  --arg expiry "$CERT_EXPIRY" \
  '{id: $id, hostname: $hostname, certificateExpiry: $expiry}' \
  > "$CLIENT_PROFILE_DIR/tunnel.json"
printf '%s\n' "$TUNNEL_TOKEN" > "$CLIENT_PROFILE_DIR/token"
chmod 600 "$CLIENT_PROFILE_DIR"/*

echo "==> attach the OFFICIAL client to the pre-provisioned tunnel"
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

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
#                 (no A record needed; its zone is hosted on one provider below)
#   RELAY_BIN     path to our opentunnel-relay binary
#   CLIENT_BIN    path to the official `opentunnel` binary
#
# DNS-01 provider, one of:
#   CI_CF_TOKEN, CI_CF_ZONE_ID          Cloudflare token with DNS-edit on the
#                                       zone of CI_DOMAIN, and that zone's ID
#   CI_ALIYUN_ACCESS_KEY_ID,            Alibaba Cloud RAM user with the DNS
#   CI_ALIYUN_ACCESS_KEY_SECRET,        permissions in README-zh.md, and the
#   CI_ALIYUN_DOMAIN                    registered domain that contains CI_DOMAIN
# Cloudflare wins when both are set, as in the relay (see dns-cleanup.sh).
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

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=dns-cleanup.sh
source "$here/dns-cleanup.sh"

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
DNS_PROVIDER="$(ci_dns_provider)"

dump_logs() {
  echo "----- relay log -----"
  tail -50 /tmp/ci-relay.log || true
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

echo "==> start relay (real ACME via DNS-01, ${DNS_PROVIDER})"
export OT_DNS_PROVIDER="$DNS_PROVIDER"
relay_dns_args=()
if [ "$DNS_PROVIDER" = aliyun ]; then
  : "${CI_ALIYUN_DOMAIN:?CI_ALIYUN_DOMAIN not set}"
  export OT_ALIYUN_ACCESS_KEY_ID="$CI_ALIYUN_ACCESS_KEY_ID"
  export OT_ALIYUN_ACCESS_KEY_SECRET="$CI_ALIYUN_ACCESS_KEY_SECRET"
  export OT_ALIYUN_DOMAIN="$CI_ALIYUN_DOMAIN"
else
  relay_dns_args=(--cf-token "$CI_CF_TOKEN" --cf-zone-id "$CI_CF_ZONE_ID")
fi
sudo --preserve-env=OT_DNS_PROVIDER,OT_ALIYUN_ACCESS_KEY_ID,OT_ALIYUN_ACCESS_KEY_SECRET,OT_ALIYUN_DOMAIN \
  "$RELAY_BIN" \
  --domain "$DOMAIN" \
  "${relay_dns_args[@]}" \
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

#!/usr/bin/env bash
set -euo pipefail

: "${OPENTUNNEL_API:?OPENTUNNEL_API must be set (e.g. https://tunnel.example.com)}"

export OPENTUNNEL_PROFILE="${OPENTUNNEL_PROFILE:-default}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/data/config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-/data/data}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-/data/state}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/opentunnel}"

mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"

ADMIN_PORT="${OT_CLIENT_ADMIN_PORT:-9080}"
SERVE_PID=""
MGMT_PID=""

stop_children() {
  if [[ -n "$MGMT_PID" ]] && kill -0 "$MGMT_PID" 2>/dev/null; then
    kill -TERM "$MGMT_PID" 2>/dev/null || true
    wait "$MGMT_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVE_PID" ]] && kill -0 "$SERVE_PID" 2>/dev/null; then
    kill -TERM "$SERVE_PID" 2>/dev/null || true
    wait "$SERVE_PID" 2>/dev/null || true
  fi
}
trap stop_children EXIT INT TERM

echo "==> starting opentunnel serve (profile=${OPENTUNNEL_PROFILE}, api=${OPENTUNNEL_API})"
opentunnel serve &
SERVE_PID=$!

sock="${XDG_RUNTIME_DIR}/opentunnel/${OPENTUNNEL_PROFILE}.sock"
for _ in $(seq 1 60); do
  if [[ -S "$sock" ]]; then
    break
  fi
  if ! kill -0 "$SERVE_PID" 2>/dev/null; then
    echo "opentunnel serve exited before the daemon socket appeared" >&2
    exit 1
  fi
  sleep 0.5
done
if [[ ! -S "$sock" ]]; then
  echo "timed out waiting for daemon socket at $sock" >&2
  exit 1
fi

echo "==> management UI on 0.0.0.0:${ADMIN_PORT}"
export OT_CLIENT_ADMIN_PORT="$ADMIN_PORT"
python3 /app/mgmt/server.py &
MGMT_PID=$!
wait "$MGMT_PID"

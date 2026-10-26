#!/usr/bin/env bash
set -euo pipefail

: "${OPENTUNNEL_API:?OPENTUNNEL_API must be set (e.g. https://tunnel.example.com)}"

export OPENTUNNEL_PROFILE="${OPENTUNNEL_PROFILE:-default}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-/data/config}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-/data/data}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-/data/state}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/opentunnel}"

# Older DIY images mounted host dirs under /root/.config|opentunnel and
# /root/.local/share|opentunnel without setting XDG_*. The client always
# reads $XDG_* paths, so those mounts were invisible when XDG pointed at /data.
tunnel_json() {
  echo "${XDG_DATA_HOME}/opentunnel/${OPENTUNNEL_PROFILE}/tunnel.json"
}
if [[ ! -f "$(tunnel_json)" && -f "/root/.local/share/opentunnel/${OPENTUNNEL_PROFILE}/tunnel.json" ]]; then
  echo "==> legacy tunnel data detected under /root/.local/share/opentunnel/${OPENTUNNEL_PROFILE}"
  echo "==> switching XDG paths to match typical root compose volume mounts"
  export XDG_CONFIG_HOME=/root/.config
  export XDG_DATA_HOME=/root/.local/share
  export XDG_STATE_HOME=/root/.local/state
fi

mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME" "$XDG_RUNTIME_DIR"

tunnel_file="$(tunnel_json)"
config_file="${XDG_CONFIG_HOME}/opentunnel/${OPENTUNNEL_PROFILE}.toml"
echo "==> XDG config=${XDG_CONFIG_HOME} data=${XDG_DATA_HOME} state=${XDG_STATE_HOME}"
if [[ -f "$tunnel_file" ]]; then
  echo "==> tunnel identity: ${tunnel_file} (present)"
else
  echo "==> tunnel identity: ${tunnel_file} (missing — UI will show no tunnel until created or volumes are fixed)" >&2
fi
if [[ -f "$config_file" ]]; then
  echo "==> routes config: ${config_file} (present)"
else
  echo "==> routes config: ${config_file} (missing)"
fi

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

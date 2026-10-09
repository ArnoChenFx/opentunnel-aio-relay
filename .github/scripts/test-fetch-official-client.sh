#!/usr/bin/env bash
#
# Offline test for fetch-official-client.sh. A localhost server stands in for
# the GitHub API and the release asset, so the success path and both
# fail-closed paths run without network access.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fetch="$here/fetch-official-client.sh"
work="$(mktemp -d)"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2> /dev/null || true; fi
  rm -rf "$work"
}
trap cleanup EXIT

asset="opentunnel-linux-x64.tar.gz"
port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
base="http://127.0.0.1:$port"
site="$work/site"
mkdir -p "$site/download" "$site/repos/anomalyco/opentunnel/releases" "$work/payload"

printf '#!/usr/bin/env bash\necho "opentunnel 0.0.0-test"\n' > "$work/payload/opentunnel"
chmod +x "$work/payload/opentunnel"
tar -czf "$site/download/$asset" -C "$work/payload" opentunnel
real_digest="sha256:$(sha256sum "$site/download/$asset" | cut -d' ' -f1)"
wrong_digest="sha256:$(printf '%064d' 0)"

write_release() {
  local digest_json="$1"
  cat > "$site/repos/anomalyco/opentunnel/releases/latest" <<JSON
{
  "tag_name": "v9.9.9",
  "assets": [
    {
      "name": "$asset",
      "browser_download_url": "$base/download/$asset",
      "digest": $digest_json
    }
  ]
}
JSON
}

python3 -m http.server "$port" --bind 127.0.0.1 --directory "$site" > "$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 50); do
  if curl -fsS "$base/" > /dev/null 2>&1; then break; fi
  sleep 0.1
done

run_fetch() {
  local dest="$1"
  : > "$work/github_env"
  OFFICIAL_CLIENT_API_URL="$base" \
    OFFICIAL_CLIENT_DEST="$dest" \
    GITHUB_TOKEN="test-token" \
    GITHUB_ENV="$work/github_env" \
    bash "$fetch"
}

expect_failure() {
  local name="$1" needle="$2" dest="$3"
  if run_fetch "$dest" > "$work/out.log" 2>&1; then
    echo "FAIL: $name: script succeeded" >&2
    cat "$work/out.log" >&2
    exit 1
  fi
  if ! grep -q -- "$needle" "$work/out.log"; then
    echo "FAIL: $name: output lacks '$needle'" >&2
    cat "$work/out.log" >&2
    exit 1
  fi
  if [[ -e "$dest/opentunnel" ]]; then
    echo "FAIL: $name: binary was extracted despite the failure" >&2
    exit 1
  fi
  echo "ok: $name"
}

write_release "\"$real_digest\""
run_fetch "$work/ok" > "$work/out.log" 2>&1 || { cat "$work/out.log" >&2; echo "FAIL: success path" >&2; exit 1; }
grep -q "sha256 verified" "$work/out.log" || { cat "$work/out.log" >&2; echo "FAIL: digest not verified" >&2; exit 1; }
grep -q "release v9.9.9" "$work/out.log" || { cat "$work/out.log" >&2; echo "FAIL: tag not logged" >&2; exit 1; }
grep -qx "OFFICIAL_CLIENT_TAG=v9.9.9" "$work/github_env" || { echo "FAIL: tag not exported" >&2; exit 1; }
[[ "$("$work/ok/opentunnel" --version)" == "opentunnel 0.0.0-test" ]] || { echo "FAIL: extracted binary is wrong" >&2; exit 1; }
echo "ok: success path verifies, logs the tag, and extracts"

write_release "\"$wrong_digest\""
expect_failure "digest mismatch fails closed" "sha256 mismatch" "$work/mismatch"

write_release "null"
expect_failure "missing digest fails closed" "no usable sha256 digest" "$work/missing"

echo "all fetch-official-client checks passed"

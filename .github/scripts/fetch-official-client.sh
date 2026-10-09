#!/usr/bin/env bash
#
# Download the official OpenTunnel client from its GitHub release and verify
# the tarball against the sha256 digest GitHub reports for that asset.
#
# Upstream publishes no checksum file, so the digest from the release API is
# the integrity reference. It comes from the same response that names the
# download URL, so the file we fetch is the one that digest describes. The
# download is verified before anything is extracted, and a missing or
# mismatched digest fails the job. The digest guards against corruption and
# substitution in transit; it does not defend against a compromised upstream
# release, since GitHub serves both values.
#
# Env:
#   GITHUB_TOKEN              token for the GitHub API (required)
#   OFFICIAL_CLIENT_RELEASE   "latest" (default) or a tag such as "v0.4.0"
#   OFFICIAL_CLIENT_DEST      extraction directory (default /tmp/official-client)
#   OFFICIAL_CLIENT_API_URL   API base URL; overridden by the offline test only
set -euo pipefail

REPO="anomalyco/opentunnel"
ASSET="opentunnel-linux-x64.tar.gz"
RELEASE="${OFFICIAL_CLIENT_RELEASE:-latest}"
DEST="${OFFICIAL_CLIENT_DEST:-/tmp/official-client}"
API="${OFFICIAL_CLIENT_API_URL:-https://api.github.com}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set to query the GitHub API}"

if [[ "$RELEASE" == "latest" ]]; then
  release_path="releases/latest"
else
  release_path="releases/tags/$RELEASE"
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fsSL \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -o "$work/release.json" \
  "$API/repos/$REPO/$release_path"

tag="$(jq -r '.tag_name // empty' "$work/release.json")"
if [[ ! "$tag" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "release metadata has no usable tag_name (got '${tag:-<none>}')" >&2
  exit 1
fi

asset_url="$(jq -r --arg name "$ASSET" \
  '.assets[] | select(.name == $name) | .browser_download_url // empty' "$work/release.json")"
if [[ -z "$asset_url" ]]; then
  echo "release $tag has no $ASSET asset" >&2
  exit 1
fi

digest="$(jq -r --arg name "$ASSET" \
  '.assets[] | select(.name == $name) | .digest // empty' "$work/release.json")"
if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "release $tag: $ASSET has no usable sha256 digest (got '${digest:-<none>}'); refusing to run an unverified binary" >&2
  exit 1
fi
expected="${digest#sha256:}"

echo "official client: release $tag, asset $ASSET, $digest"
curl -fsSL --retry 3 -o "$work/$ASSET" "$asset_url"

actual="$(sha256sum "$work/$ASSET" | cut -d' ' -f1)"
if [[ "$actual" != "$expected" ]]; then
  echo "sha256 mismatch for $ASSET from release $tag: expected $expected, got $actual" >&2
  exit 1
fi
echo "sha256 verified for $ASSET from release $tag"

mkdir -p "$DEST"
tar -xzf "$work/$ASSET" -C "$DEST"
"$DEST/opentunnel" --version

if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "OFFICIAL_CLIENT_TAG=$tag" >> "$GITHUB_ENV"
fi

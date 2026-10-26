#!/usr/bin/env bash
# Run from the repository root; archive modes do not depend on the build umask.
set -euo pipefail
target="${1:?target is required}"
binary="${2:?binary path is required}"
output="${3:-dist}"
case "$target" in
  x86_64-unknown-linux-gnu|x86_64-unknown-linux-musl|aarch64-unknown-linux-gnu) ;;
  *) echo "Unsupported release target: $target" >&2; exit 1 ;;
esac
name="opentunnel-relay-$target"
stage="$output/$name"
mkdir -p -- "$stage"
install -m 755 -- "$binary" "$stage/opentunnel-relay"
install -m 644 -- README.md "$stage/README.md"
tar -czf "$output/$name.tar.gz" -C "$output" "$name"

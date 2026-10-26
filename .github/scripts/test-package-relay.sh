#!/usr/bin/env bash
# Reproduce a non-executable build artifact under a restrictive umask.
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
umask 077
printf '#!/bin/sh\nprintf "packaged-relay-ok\\n"\n' > "$work/relay"
chmod 644 "$work/relay"
for target in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-gnu; do
  bash .github/scripts/package-relay.sh "$target" "$work/relay" "$work/dist"
  mkdir "$work/extracted-$target"
  tar -xzf "$work/dist/opentunnel-relay-$target.tar.gz" -C "$work/extracted-$target"
  extracted="$work/extracted-$target/opentunnel-relay-$target/opentunnel-relay"
  [[ -x "$extracted" ]]
  [[ "$("$extracted")" == packaged-relay-ok ]]
  # Inspect archive metadata independently of extraction's umask.
  python3 - "$work/dist/opentunnel-relay-$target.tar.gz" "$target" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1]) as archive:
    root = "opentunnel-relay-" + sys.argv[2]
    assert archive.getmember(root + "/opentunnel-relay").mode == 0o755
    assert archive.getmember(root + "/README.md").mode == 0o644
PY
done
echo "all release archive permission checks passed"

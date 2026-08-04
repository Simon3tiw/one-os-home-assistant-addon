#!/usr/bin/env bash
# Build a manually-installable Home Assistant app bundle for ONE.OS Edge
# Connector, matching what the CI release-bundle job produces. The
# repository stays private; this bundle is what gets copied onto the
# Home Assistant host's local add-ons/apps directory.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${1:-$repo_root/dist-bundle}"
bundle_name="one-os-edge-addon-bundle.tar.gz"

rm -rf "$out_dir"
mkdir -p "$out_dir"

tar -czf "$out_dir/$bundle_name" \
  -C "$repo_root" \
  --exclude 'one_os_edge/frontend/node_modules' \
  --exclude 'one_os_edge/frontend/dist' \
  --exclude 'one_os_edge/frontend/test-results' \
  --exclude 'one_os_edge/backend/.venv' \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  one_os_edge README.md

sha256sum "$out_dir/$bundle_name" > "$out_dir/$bundle_name.sha256"

echo "Bundle:   $out_dir/$bundle_name"
echo "Checksum: $out_dir/$bundle_name.sha256"
cat "$out_dir/$bundle_name.sha256"

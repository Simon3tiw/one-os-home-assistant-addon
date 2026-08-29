#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="${1:-$repo_root/dist}"
bundle_name="one-os-edge-addon-bundle.tar.gz"

mkdir -p "$out_dir"

python3 "$repo_root/scripts/build_release_bundle.py" \
  "$repo_root" \
  "$out_dir/$bundle_name" >/dev/null
(
  cd "$out_dir"
  sha256sum -c "$bundle_name.sha256" >/dev/null
)

echo "Bundle:   $out_dir/$bundle_name"
echo "Checksum: $out_dir/$bundle_name.sha256"
cat "$out_dir/$bundle_name.sha256"

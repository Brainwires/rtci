#!/usr/bin/env bash
# The test environment image's tag: a hash of everything the image is built from, so a change
# to any input builds a new image (run.sh and .github/workflows/test-env.yml use it). The
# inputs: the Dockerfile, the Playwright runner's package files, and each peer's image inputs
# (scripts/test-env/peers/<name>/image/: its pinned modules or wheels, fetched into the image).
set -euo pipefail
cd "$(dirname "$0")"
{
  cat Dockerfile interop/package.json interop/package-lock.json
  if [ -d peers ]; then
    find peers -path '*/image/*' -type f | LC_ALL=C sort | while read -r f; do
      printf '%s\n' "$f"
      cat "$f"
    done
  fi
} | sha256sum | cut -c1-12

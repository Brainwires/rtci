#!/usr/bin/env bash
# Browser interop stage (entry.sh calls it inside the test container): builds and starts
# examples/interop-peer in the "open-b" namespace (203.0.113.51), runs the Playwright suite in
# "open-a" (203.0.113.50) against it, and writes /artifacts/interop-matrix.md.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
A=${RTC_TESTENV_ARTIFACTS_DIR:-/artifacts}

cargo build --example interop-peer > "$A/interop-build.log" 2>&1 || { echo "interop-peer build failed"; tail -30 "$A/interop-build.log"; exit 1; }
PEER=${CARGO_TARGET_DIR:-/src/target}/debug/examples/interop-peer

ip netns exec open-b "$PEER" --listen 203.0.113.51:8080 --ice-ip 203.0.113.51 \
  --media-dir "${RTC_TESTENV_MEDIA:-/run/rtc-env/media}" > "$A/interop-peer.log" 2>&1 &
PEER_PID=$!
trap 'kill $PEER_PID 2>/dev/null; wait $PEER_PID 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  ip netns exec open-b ss -ltn | grep -q '203.0.113.51:8080' && break
  sleep 0.2
done

# The runner and its node_modules live in the image; the specs come from the checkout.
cp "$HERE"/*.mjs "$HERE"/peer.js /opt/interop/
cd /opt/interop
RTC_INTEROP_WS=ws://203.0.113.51:8080 RTC_INTEROP_JSON="$A/interop-results.json" \
  ip netns exec open-a npx playwright test --config playwright.config.mjs "$@"
rc=$?
node /opt/interop/matrix.mjs "$A/interop-results.json" > "$A/interop-matrix.md" || rc=1
cat "$A/interop-matrix.md"
exit $rc

#!/usr/bin/env bash
# Browser interop stage (entry.sh calls it inside the test container): builds and starts
# examples/interop-peer in the "open-b" namespace (203.0.113.51), runs the Playwright suite in
# "open-a" (203.0.113.50) against it, and writes /artifacts/interop-matrix.md,
# interop-summary.json and interop-gate.txt (gate.mjs: a failure or an uncited n/a fails it).
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

# A lossy band on the browser host's WAN interface that no packet takes unless a test adds a tc
# filter for its own session (common.mjs impair()): the loss-recovery tests run beside others.
# Bands 1-3 are the default priomap's; band 4 (1:4) is netem.
ip netns exec open-a tc qdisc del dev eth0 root 2>/dev/null || true
ip netns exec open-a tc qdisc add dev eth0 root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1 \
  && ip netns exec open-a tc qdisc add dev eth0 parent 1:4 handle 40: netem delay 20ms loss 5% \
  || { echo "tc setup for the loss tests failed"; exit 1; }

# The runner and its node_modules live in the image; the specs come from the checkout.
cp "$HERE"/*.mjs "$HERE"/peer.js /opt/interop/
cd /opt/interop
RTC_INTEROP_WS=ws://203.0.113.51:8080 RTC_INTEROP_JSON="$A/interop-results.json" \
  ip netns exec open-a npx playwright test --config playwright.config.mjs "$@"
rc=$?
node /opt/interop/matrix.mjs "$A/interop-results.json" "$A/interop-summary.json" > "$A/interop-matrix.md" || rc=1
cat "$A/interop-matrix.md"
# C3: every cell a pass or a cited n/a (na-browser / na-env), every browser present.
node /opt/interop/gate.mjs "$A/interop-summary.json" > "$A/interop-gate.txt" 2>&1 || rc=1
cat "$A/interop-gate.txt"
exit $rc

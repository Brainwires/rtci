#!/usr/bin/env bash
# Browser interop stage (entry.sh calls it inside the test container): builds and starts
# examples/interop-peer in the "open-b" namespace (203.0.113.51), runs the Playwright suite in
# "open-a" (203.0.113.50) against it, and writes /artifacts/interop-matrix.md,
# interop-summary.json and interop-gate.txt (gate.mjs: a failure or an uncited n/a fails it).
# The "-mdns" projects run apart, with a second peer in "lan-b" (10.99.0.51) and the browsers
# in "lan-a" (10.99.0.50): mDNS resolves names on a link, and the Rust side believes an mDNS
# answer only from an on-link (private) sender, which the TEST-NET WAN is not.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
A=${RTC_TESTENV_ARTIFACTS_DIR:-/artifacts}

cargo build --example interop-peer > "$A/interop-build.log" 2>&1 || { echo "interop-peer build failed"; tail -30 "$A/interop-build.log"; exit 1; }
PEER=${CARGO_TARGET_DIR:-/src/target}/debug/examples/interop-peer

ip netns exec open-b "$PEER" --listen 203.0.113.51:8080 --ice-ip 203.0.113.51 \
  --media-dir "${RTC_TESTENV_MEDIA:-/run/rtc-env/media}" > "$A/interop-peer.log" 2>&1 &
PEER_PID=$!
# The mDNS peer logs every mDNS packet it parses and each answer it takes or refuses.
RUST_LOG=${RTC_INTEROP_MDNS_LOG:-error,rtc_mdns=trace,rtc_ice::agent=debug} \
  ip netns exec lan-b "$PEER" --listen 10.99.0.51:8080 --ice-ip 10.99.0.51 \
  --media-dir "${RTC_TESTENV_MEDIA:-/run/rtc-env/media}" > "$A/interop-peer-mdns.log" 2>&1 &
MDNS_PEER_PID=$!
trap 'kill $PEER_PID $MDNS_PEER_PID 2>/dev/null; wait $PEER_PID $MDNS_PEER_PID 2>/dev/null' EXIT
for _ in $(seq 1 50); do
  ip netns exec open-b ss -ltn | grep -q '203.0.113.51:8080' \
    && ip netns exec lan-b ss -ltn | grep -q '10.99.0.51:8080' && break
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
RTC_INTEROP_WS=ws://203.0.113.51:8080 RTC_INTEROP_JSON="$A/interop-results-wan.json" \
  RTC_INTEROP_SDP_DIR="$A/browser-sdp" \
  ip netns exec open-a npx playwright test --config playwright.config.mjs \
  --project chromium --project firefox --project webkit "$@"
rc=$?
# Every mDNS packet on the LAN while the mDNS projects run, seen from the Rust peer's host.
ip netns exec lan-b tcpdump -i eth0 -n -vvv -l udp port 5353 > "$A/mdns-lan-b.txt" 2>&1 &
TCPDUMP_PID=$!
RTC_INTEROP_WS=ws://10.99.0.51:8080 RTC_INTEROP_BROWSER_IP=10.99.0.50 \
  RTC_INTEROP_JSON="$A/interop-results-mdns.json" \
  RTC_INTEROP_SDP_DIR="$A/browser-sdp" \
  ip netns exec lan-a npx playwright test --config playwright.config.mjs \
  --project chromium-mdns --project firefox-mdns --project webkit-mdns "$@" || rc=1
kill "$TCPDUMP_PID" 2>/dev/null; wait "$TCPDUMP_PID" 2>/dev/null
# One report for the matrix: both runs' suites.
node -e '
  const fs = require("fs");
  const [out, ...ins] = process.argv.slice(1);
  const reports = ins.filter((f) => fs.existsSync(f)).map((f) => JSON.parse(fs.readFileSync(f, "utf8")));
  const merged = { ...(reports[0] || {}), suites: reports.flatMap((r) => r.suites || []) };
  merged.errors = reports.flatMap((r) => r.errors || []);
  fs.writeFileSync(out, JSON.stringify(merged));
' "$A/interop-results.json" "$A/interop-results-wan.json" "$A/interop-results-mdns.json" || rc=1
node /opt/interop/matrix.mjs "$A/interop-results.json" "$A/interop-summary.json" > "$A/interop-matrix.md" || rc=1
cat "$A/interop-matrix.md"
# C3: every cell a pass or a cited n/a (na-browser / na-env), every browser present.
node /opt/interop/gate.mjs "$A/interop-summary.json" > "$A/interop-gate.txt" 2>&1 || rc=1
cat "$A/interop-gate.txt"
exit $rc

#!/usr/bin/env bash
# One or a few browser interop cells (scripts/test-env/interop) outside the test image, on a
# disposable Linux machine where sudo works (a GitHub-hosted ubuntu runner through
# agent-test.yml). It installs what the image would hold (iproute2 / iptables / ipset,
# GStreamer for the VP8 fixture, Playwright and its Chromium), builds the topology's network
# namespaces on the machine itself (topology.sh, normally run inside the container), adds the
# netem bands of interop/run.sh, starts examples/interop-peer in "open-b" and runs Playwright
# in "open-a" with `--project <project> -g <grep>`. No coturn: cells that need TURN fail here.
#
#   scripts/test-env/hosted-cell.sh '<grep>' [project]      (project: chromium by default)
#
# Never on a machine that matters: it changes the machine's network namespaces and installs
# packages. The exit status is Playwright's.
set -euo pipefail
GREP=${1:?usage: hosted-cell.sh <grep> [project]}
PROJECT=${2:-chromium}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
A=${RTC_TESTENV_ARTIFACTS_DIR:-$ROOT/target/hosted-cell}
mkdir -p "$A"
export RTC_TESTENV_ARTIFACTS_DIR=$A
MEDIA=/run/rtc-env/media
PW=/opt/pw-browsers

sudo apt-get update -qq
sudo apt-get install -y -qq iproute2 iptables ipset gstreamer1.0-tools \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-base gstreamer1.0-libav > "$A/apt.log" 2>&1

sudo mkdir -p "$MEDIA"
sudo gst-launch-1.0 -q videotestsrc num-buffers=300 pattern=ball ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! vp8enc deadline=1 keyframe-max-dist=60 target-bitrate=800000 ! avmux_ivf ! filesink location="$MEDIA/vp8.ivf"

# The peer interop/run.sh starts: examples/interop-peer built by the rtci-video-interop package
# with its `pipeline` feature (the same peer plus the video pipeline scenario, for the
# "pipeline receive" cells).
cargo build -p rtci-video-interop --features pipeline --bin interop-peer-video > "$A/interop-build.log" 2>&1 || { tail -30 "$A/interop-build.log"; exit 1; }
PEER=${CARGO_TARGET_DIR:-$ROOT/target}/debug/interop-peer-video

sudo bash "$HERE/topology.sh" down > /dev/null 2>&1 || true
sudo bash "$HERE/topology.sh" up > "$A/topology.log" 2>&1 || { tail -30 "$A/topology.log"; exit 1; }
for ns in open-a open-b; do
  sudo ip netns exec $ns tc qdisc add dev eth0 root handle 1: prio bands 4 priomap 1 2 2 2 1 2 0 0 1 1 1 1 1 1 1 1
  sudo ip netns exec $ns tc qdisc add dev eth0 parent 1:4 handle 40: netem delay 20ms loss 5%
done

sudo ip netns exec open-b "$PEER" --listen 203.0.113.51:8080 --ice-ip 203.0.113.51 \
  --media-dir "$MEDIA" > "$A/interop-peer.log" 2>&1 &
for _ in $(seq 1 50); do
  sudo ip netns exec open-b ss -ltn | grep -q '203.0.113.51:8080' && break
  sleep 0.2
done

cd "$HERE/interop"
npm install --no-audit --no-fund > "$A/npm.log" 2>&1
sudo env PATH="$PATH" PLAYWRIGHT_BROWSERS_PATH=$PW npx playwright install --with-deps "$PROJECT" > "$A/playwright-install.log" 2>&1
rc=0
sudo env PATH="$PATH" PLAYWRIGHT_BROWSERS_PATH=$PW RTC_TESTENV_ARTIFACTS_DIR="$A" \
  RTC_INTEROP_WS=ws://203.0.113.51:8080 RTC_INTEROP_JSON="$A/results.json" \
  RTC_INTEROP_SDP_DIR="$A/browser-sdp" RTC_TESTENV_MEDIA="$MEDIA" \
  ip netns exec open-a npx playwright test --config playwright.config.mjs \
  --project "$PROJECT" -g "$GREP" || rc=$?
echo "== interop-peer log (tail)"
tail -40 "$A/interop-peer.log" || true
sudo bash "$HERE/topology.sh" down > /dev/null 2>&1 || true
exit $rc

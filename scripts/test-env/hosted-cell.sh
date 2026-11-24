#!/usr/bin/env bash
# One or a few browser interop cells (scripts/test-env/interop) outside the test image, on a
# disposable Linux machine where sudo works (a GitHub-hosted ubuntu runner through
# agent-test.yml). It installs what the image would hold (iproute2 / iptables / ipset,
# GStreamer for the VP8 fixture, Playwright and its Chromium), builds the topology's network
# namespaces on the machine itself (topology.sh, normally run inside the container), adds the
# netem bands of interop/run.sh, starts examples/interop-peer in "open-b" and runs Playwright
# in "open-a" with `--project <project> -g <grep>`. No coturn: cells that need TURN fail here.
# Only the network set-up and the Rust peer run as root. Playwright and its browsers run as the
# invoking user inside open-a (`sudo ip netns exec open-a setpriv --reuid <user> ...`): Firefox
# refuses to start as root in a session whose $HOME / $XDG_RUNTIME_DIR belong to another user
# (the hosted runner's). The test process keeps CAP_NET_ADMIN as an ambient capability, as the
# image's root process has it: the loss cells add their own tc filters in open-a (common.mjs
# impair()). A cell whose name says "pipeline" gets the
# rtci-video-interop build (`interop-peer-video`, as interop/run.sh starts it where that package
# exists); every other cell the plain example.
#
#   scripts/test-env/hosted-cell.sh '<grep>' [project]      (project: chromium | firefox | webkit;
#                                                           chromium by default)
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
ME=$(id -un)
PW=${PLAYWRIGHT_BROWSERS_PATH:-$HOME/.cache/ms-playwright}

sudo apt-get update -qq
sudo apt-get install -y -qq iproute2 iptables ipset gstreamer1.0-tools \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-base gstreamer1.0-libav > "$A/apt.log" 2>&1

sudo mkdir -p "$MEDIA"
sudo gst-launch-1.0 -q videotestsrc num-buffers=300 pattern=ball ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! vp8enc deadline=1 keyframe-max-dist=60 target-bitrate=800000 ! avmux_ivf ! filesink location="$MEDIA/vp8.ivf"

if printf '%s' "$GREP" | grep -qi pipeline; then
  [ -f "$ROOT/rtci-video/interop/Cargo.toml" ] || { echo "a pipeline cell needs rtci-video-interop, which this tree does not have"; exit 1; }
  cargo build -p rtci-video-interop --features pipeline --bin interop-peer-video > "$A/interop-build.log" 2>&1 \
    || { tail -30 "$A/interop-build.log"; exit 1; }
  PEER=${CARGO_TARGET_DIR:-$ROOT/target}/debug/interop-peer-video
else
  cargo build --example interop-peer > "$A/interop-build.log" 2>&1 || { tail -30 "$A/interop-build.log"; exit 1; }
  PEER=${CARGO_TARGET_DIR:-$ROOT/target}/debug/examples/interop-peer
fi

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
# The browser into the user's cache, its system libraries with sudo.
PLAYWRIGHT_BROWSERS_PATH=$PW npx playwright install "$PROJECT" > "$A/playwright-install.log" 2>&1
sudo env PATH="$PATH" npx playwright install-deps "$PROJECT" >> "$A/playwright-install.log" 2>&1
rc=0
# Enter open-a as root, then drop back to the user with its own environment and CAP_NET_ADMIN
# (ambient, so the tc that a cell runs has it): the browser's sockets are in open-a, the browser
# itself is not root.
sudo ip netns exec open-a setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups \
  --inh-caps=+net_admin --ambient-caps=+net_admin env PATH="$PATH" HOME="$HOME" USER="$ME" \
  XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-}" PLAYWRIGHT_BROWSERS_PATH="$PW" RTC_TESTENV_ARTIFACTS_DIR="$A" \
  RTC_INTEROP_WS=ws://203.0.113.51:8080 RTC_INTEROP_JSON="$A/results.json" \
  RTC_INTEROP_SDP_DIR="$A/browser-sdp" RTC_TESTENV_MEDIA="$MEDIA" \
  npx playwright test --config playwright.config.mjs \
  --project "$PROJECT" -g "$GREP" || rc=$?
echo "== interop-peer log (tail)"
tail -40 "$A/interop-peer.log" || true
sudo bash "$HERE/topology.sh" down > /dev/null 2>&1 || true
exit $rc

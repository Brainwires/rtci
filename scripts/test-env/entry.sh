#!/usr/bin/env bash
# Inside the test container (run.sh starts it): builds the topology, starts coturn, makes the
# media fixtures, then runs the requested stages and writes /artifacts/report.md.
set -uo pipefail

STAGES=("$@")
[ ${#STAGES[@]} -eq 0 ] && STAGES=(unit env interop)
HERE=/src/scripts/test-env
A=/artifacts
mkdir -p "$A"
REPORT=$A/report.md
: > "$REPORT"
FAILED=()

log() { echo "== $*" | tee -a "$A/run.log"; }

finish() {
  # Hand the artifacts and target dir back to the invoking user.
  [ -n "${HOST_UID:-}" ] && chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$A" /target 2>/dev/null
  "$HERE/topology.sh" down >/dev/null 2>&1 || true
}
trap finish EXIT

log "topology"
"$HERE/topology.sh" up || { echo "topology failed"; exit 1; }
"$HERE/topology.sh" show > "$A/topology.txt" 2>&1
log "coturn"
"$HERE/coturn/start.sh" || exit 1

export RTC_TESTENV=1
export RTC_TESTENV_TURN_UDP=203.0.113.10:3478
export RTC_TESTENV_TURN_TCP=203.0.113.10:3478
export RTC_TESTENV_TURN_TLS=203.0.113.10:5349
export RTC_TESTENV_TURN_TLS_NAME=turn.rtc.test
export RTC_TESTENV_TURN_USER=test RTC_TESTENV_TURN_PASS=test RTC_TESTENV_TURN_REALM=rtc.test
export RTC_TESTENV_TURN_CA=/run/rtc-env/ca.crt
export RTC_TESTENV_MEDIA=/run/rtc-env/media

log "media fixtures (GStreamer)"
# H.264: one slice per picture (no tune=zerolatency, whose sliced threads code a picture as
# several slices; a sender packetizing NAL by NAL then marks every slice as a frame end).
# Opus: one packet per Ogg page (max-page-delay=1 ns), because OggReader returns whole pages
# and an RTP packet carries one Opus packet (RFC 7587).
M=$RTC_TESTENV_MEDIA
mkdir -p "$M"
gst-launch-1.0 -q videotestsrc num-buffers=300 pattern=ball ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! vp8enc deadline=1 keyframe-max-dist=60 target-bitrate=800000 ! avmux_ivf ! filesink location="$M/vp8.ivf" \
  && gst-launch-1.0 -q videotestsrc num-buffers=300 pattern=smpte ! video/x-raw,width=320,height=240,framerate=30/1 \
  ! vp9enc deadline=1 cpu-used=8 keyframe-max-dist=60 target-bitrate=400000 ! avmux_ivf ! filesink location="$M/vp9.ivf" \
  && gst-launch-1.0 -q videotestsrc num-buffers=300 ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! x264enc speed-preset=ultrafast bframes=0 key-int-max=60 ! video/x-h264,stream-format=byte-stream,profile=constrained-baseline \
  ! filesink location="$M/h264.h264" \
  && gst-launch-1.0 -q audiotestsrc num-buffers=500 wave=sine ! audio/x-raw,rate=48000,channels=2 \
  ! opusenc frame-size=20 ! oggmux max-page-delay=1 ! filesink location="$M/opus.ogg" \
  || { echo "fixture generation failed"; exit 1; }
ls -l "$M" | tee -a "$A/run.log"

# `cargo test` output is summarised as "N passed; M failed; K ignored" per binary.
summarise() {
  awk '/^test result:/ { p+=$4; f+=$6; i+=$8 } END { printf "%d passed, %d failed, %d ignored\n", p, f, i }' "$1"
}

stage_unit() {
  log "stage unit: cargo test --workspace (every test the environment does not need)"
  cargo test --workspace --no-fail-fast > "$A/unit.log" 2>&1
  local rc=$?
  echo "## unit: $(summarise "$A/unit.log") (exit $rc)" >> "$REPORT"
  grep -E '^test .* (FAILED|ignored, )' "$A/unit.log" | sed 's/^/    /' >> "$REPORT"
  return $rc
}

stage_env() {
  log "stage env: real networks (NAT matrix, TURN, mDNS) and netem impairment"
  cargo test --test testenv_ice --test testenv_mdns --test testenv_impairment --no-fail-fast \
    -- --ignored --nocapture > "$A/env.log" 2>&1
  local rc=$?
  echo "## env: $(summarise "$A/env.log") (exit $rc)" >> "$REPORT"
  grep -E '^test .* FAILED' "$A/env.log" | sed 's/^/    /' >> "$REPORT"
  { echo; echo '### NAT matrix'; grep -E '^NAT-MATRIX' "$A/env.log" | sort; } >> "$REPORT"
  { echo; echo '### impairment'; grep -E '^(NETEM|RTP over|unreliable:|VP8:|GCC target)' "$A/env.log"; } >> "$REPORT"
  if [ -f "$M/received-vp8.ivf" ]; then
    if gst-launch-1.0 -q filesrc location="$M/received-vp8.ivf" ! ivfparse ! vp8dec ! fakesink sync=false \
        > "$A/gst-decode.log" 2>&1; then
      echo "received VP8 decodes with GStreamer (vp8dec)" >> "$REPORT"
      cp "$M/received-vp8.ivf" "$A/"
    else
      echo "received VP8 does NOT decode with GStreamer (see gst-decode.log)" >> "$REPORT"; rc=1
    fi
  fi
  return $rc
}

stage_interop() {
  log "stage interop: Chromium, Firefox, WebKit (Playwright) against the Rust peer"
  if [ ! -x "$HERE/interop/run.sh" ]; then echo "## interop: not present" >> "$REPORT"; return 1; fi
  "$HERE/interop/run.sh" > "$A/interop.log" 2>&1
  local rc=$?
  echo "## interop (exit $rc)" >> "$REPORT"
  [ -f "$A/interop-matrix.md" ] && cat "$A/interop-matrix.md" >> "$REPORT"
  return $rc
}

for s in "${STAGES[@]}"; do
  if ! "stage_$s"; then FAILED+=("$s"); fi
done
echo >> "$REPORT"
if [ ${#FAILED[@]} -eq 0 ]; then echo "ALL STAGES PASSED (${STAGES[*]})" | tee -a "$REPORT"; else echo "FAILED STAGES: ${FAILED[*]}" | tee -a "$REPORT"; fi
cat "$REPORT"
[ ${#FAILED[@]} -eq 0 ]

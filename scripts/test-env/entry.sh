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
export RTC_TESTENV_TURN_STALE_UDP=203.0.113.10:3479
export RTC_TESTENV_TURN_STALE_LOG=/run/rtc-env/turnserver-stale.log
export RTC_TESTENV_TURN_CLIENT=203.0.113.10:3480
export RTC_TESTENV_TURN_CLIENT_LOG=/run/rtc-env/turnserver-client.log
export RTC_TESTENV_MEDIA=/run/rtc-env/media

log "media fixtures (GStreamer)"
# H.264: one slice per picture (no tune=zerolatency, whose sliced threads code a picture as
# several slices); h264-slices.h264 has four slices per picture on purpose.
# Opus: opus.ogg has one packet per Ogg page (max-page-delay=1 ns); opus-multi.ogg puts up to
# half a second of packets on a page (an RTP packet carries one Opus packet, RFC 7587, so a
# sender must read packets, not pages).
M=$RTC_TESTENV_MEDIA
mkdir -p "$M"
gst-launch-1.0 -q videotestsrc num-buffers=300 pattern=ball ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! vp8enc deadline=1 keyframe-max-dist=60 target-bitrate=800000 ! avmux_ivf ! filesink location="$M/vp8.ivf" \
  && gst-launch-1.0 -q videotestsrc num-buffers=300 pattern=smpte ! video/x-raw,format=I420,width=320,height=240,framerate=30/1 \
  ! vp9enc deadline=1 cpu-used=8 keyframe-max-dist=60 target-bitrate=400000 ! avmux_ivf ! filesink location="$M/vp9.ivf" \
  && gst-launch-1.0 -q videotestsrc num-buffers=300 ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! x264enc speed-preset=ultrafast bframes=0 key-int-max=60 ! video/x-h264,stream-format=byte-stream,profile=constrained-baseline \
  ! filesink location="$M/h264.h264" \
  && gst-launch-1.0 -q audiotestsrc num-buffers=500 wave=sine ! audio/x-raw,rate=48000,channels=2 \
  ! opusenc frame-size=20 ! oggmux max-page-delay=1 ! filesink location="$M/opus.ogg" \
  && gst-launch-1.0 -q audiotestsrc num-buffers=500 wave=sine ! audio/x-raw,rate=48000,channels=2 \
  ! opusenc frame-size=20 ! oggmux max-delay=500000000 max-page-delay=500000000 ! filesink location="$M/opus-multi.ogg" \
  && gst-launch-1.0 -q videotestsrc num-buffers=150 ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! x264enc speed-preset=ultrafast bframes=0 key-int-max=30 option-string=slices=4 \
  ! video/x-h264,stream-format=byte-stream,profile=constrained-baseline ! filesink location="$M/h264-slices.h264" \
  || { echo "fixture generation failed"; exit 1; }
# H.265 and AV1 for the browser matrix. An encoder the image's GStreamer lacks leaves its file
# out; the interop specs then report those cells na-env with this log as the citation.
gst-launch-1.0 -q videotestsrc num-buffers=300 ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! x265enc speed-preset=ultrafast tune=zerolatency key-int-max=60 \
  ! video/x-h265,stream-format=byte-stream ! filesink location="$M/h265.h265" \
  > "$A/fixture-h265.log" 2>&1 || { echo "no H.265 fixture (see fixture-h265.log)" | tee -a "$A/run.log"; rm -f "$M/h265.h265"; }
gst-launch-1.0 -q videotestsrc num-buffers=300 ! video/x-raw,width=640,height=480,framerate=30/1 \
  ! av1enc usage-profile=realtime cpu-used=8 end-usage=cbr target-bitrate=600 keyframe-max-dist=60 \
  ! av1parse ! video/x-av1,stream-format=obu-stream,alignment=tu ! avmux_ivf ! filesink location="$M/av1.ivf" \
  > "$A/fixture-av1.log" 2>&1 || { echo "no AV1 fixture (see fixture-av1.log)" | tee -a "$A/run.log"; rm -f "$M/av1.ivf"; }
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
  # The layer interop tests (scripts/test-env/peers/layers): rtc-dtls against dimpl, rtc-ice
  # against librice's rice-proto, in a crate outside the workspace.
  cargo test --locked --manifest-path "$HERE/peers/layers/Cargo.toml" --target-dir "${CARGO_TARGET_DIR:-/target}/peers" \
    --no-fail-fast > "$A/layers.log" 2>&1
  local lrc=$?
  echo "## layers (dimpl, rice-proto): $(summarise "$A/layers.log") (exit $lrc)" >> "$REPORT"
  grep -E '^test .* FAILED' "$A/layers.log" | sed 's/^/    /' >> "$REPORT"
  [ $rc -eq 0 ] && rc=$lrc
  return $rc
}

stage_env() {
  log "stage env: real networks (NAT matrix, TURN, mDNS) and netem impairment"
  cargo test --test testenv_ice --test testenv_mdns --test testenv_impairment \
    --test testenv_turn --test testenv_turn_client --test testenv_dtls --test testenv_ice_tcp --test testenv_turn_streams \
    --test testenv_media_fixtures \
    --no-fail-fast -- --ignored --nocapture > "$A/env.log" 2>&1
  local rc=$?
  echo "## env: $(summarise "$A/env.log") (exit $rc)" >> "$REPORT"
  grep -E '^test .* FAILED' "$A/env.log" | sed 's/^/    /' >> "$REPORT"
  { echo; echo '### NAT matrix'; grep -E '^NAT-MATRIX' "$A/env.log" | sort; } >> "$REPORT"
  { echo; echo '### impairment'; grep -E '^(NETEM|RTP over|unreliable:|VP8:|GCC target)' "$A/env.log"; } >> "$REPORT"
  { echo; echo '### TURN, DTLS, ICE-TCP, fixtures'; grep -E '^(TURN stale nonce|TURN client|wrong fingerprint|ICE-TCP|Ogg:|H.264:)' "$A/env.log"; } >> "$REPORT"
  cp /run/rtc-env/turnserver-client.log "$A/" 2>/dev/null || true
  local n438
  n438=$(grep -c '438' /run/rtc-env/turnserver-stale.log 2>/dev/null) || true
  echo "short-nonce coturn log lines with 438: ${n438:-0}" >> "$REPORT"
  # What the tests received, decoded by GStreamer (an independent decoder).
  decode() {
    local file=$1 what=$2; shift 2
    [ -f "$M/$file" ] || return 0
    if gst-launch-1.0 -q filesrc location="$M/$file" ! "$@" ! fakesink sync=false > "$A/gst-decode-$file.log" 2>&1; then
      echo "received $what decodes with GStreamer" >> "$REPORT"
      cp "$M/$file" "$A/"
    else
      echo "received $what does NOT decode with GStreamer (see gst-decode-$file.log)" >> "$REPORT"; rc=1
    fi
  }
  decode received-vp8.ivf "VP8 (vp8dec)" ivfparse ! vp8dec
  decode received-opus-multi.ogg "Opus from multi-packet pages (opusdec)" oggdemux ! opusparse ! opusdec
  decode received-h264-slices.h264 "multi-slice H.264 (avdec_h264)" h264parse ! avdec_h264
  return $rc
}

stage_interop() {
  log "stage interop: Chromium, Firefox, WebKit (Playwright) and the non-browser peers (scripts/test-env/peers) against the Rust peer"
  if [ ! -x "$HERE/interop/run.sh" ]; then echo "## interop: not present" >> "$REPORT"; return 1; fi
  "$HERE/interop/run.sh" > "$A/interop.log" 2>&1
  local rc=$?
  echo "## interop (exit $rc)" >> "$REPORT"
  [ -f "$A/interop-matrix.md" ] && cat "$A/interop-matrix.md" >> "$REPORT"
  [ -f "$A/interop-gate.txt" ] && { echo; echo '```'; cat "$A/interop-gate.txt"; echo '```'; } >> "$REPORT"
  return $rc
}

for s in "${STAGES[@]}"; do
  if ! "stage_$s"; then FAILED+=("$s"); fi
done
echo >> "$REPORT"
if [ ${#FAILED[@]} -eq 0 ]; then echo "ALL STAGES PASSED (${STAGES[*]})" | tee -a "$REPORT"; else echo "FAILED STAGES: ${FAILED[*]}" | tee -a "$REPORT"; fi
cat "$REPORT"
[ ${#FAILED[@]} -eq 0 ]

#!/usr/bin/env bash
# Evidence for the pure-Rust codec backends of rtc-video (docs/video-pipeline.md 4.6), run on a
# GitHub-hosted Ubuntu runner (agent-test.yml), never committed data:
#
#  1. VP8 decode, conformance: the WebM project's 59 VP8 test vectors, each shown frame's MD5
#     against the .md5 files the WebM project publishes beside them.
#  2. VP8 decode, against libvpx: every vector and examples/test-data/output_vp8.ivf decoded by
#     libvpx (through ffmpeg) and by vp8-decoder, the raw I420 compared byte for byte.
#  3. AV1 decode, against dav1d: libaom's AV1 test vectors decoded by libdav1d (through ffmpeg)
#     and by rav1d without assembly, compared byte for byte.
#  4. Encoders: vp8-encoder and rav1e (no assembly) on a real camera clip (the WebM project's
#     niklas_1280_720_30.y4m) at 720p and 360p and on the synthetic source: speed, bitrate,
#     PSNR; each stream also decoded by libvpx / libdav1d and compared with our decoder's output.
#
# ffmpeg is an outside reference tool here, never a dependency (`-fps_mode passthrough`: one
# output picture per decoded picture, no duplicates for the vectors' timestamps). Usage:
#   scripts/video-codec-check.sh [WORKDIR]
# Exit status: non-zero when any comparison fails.
set -u

work=${1:-${RUNNER_TEMP:-/tmp}/video-codec-check}
mkdir -p "$work/vp8" "$work/av1" "$work/out"
fail=0
note() { echo "CHECK $*"; }

if ! command -v ffmpeg >/dev/null 2>&1; then
    sudo apt-get update -qq >/dev/null && sudo apt-get install -y -qq ffmpeg >/dev/null || { note "ffmpeg: install failed"; exit 1; }
fi
ffmpeg -hide_banner -version | head -1
ffmpeg -hide_banner -decoders 2>/dev/null | grep -E "libvpx|libdav1d" || true

cargo build --release -q -p rtc-video --features vp8,av1 --example codec_check || exit 1
check=target/release/examples/codec_check

fetch() { # URL FILE
    [ -s "$2" ] || curl -sSf --retry 3 -A "codec-check (generic client)" -o "$2" "$1"
}

# 1. The VP8 test vectors. The list (and SHA-256s, checked here) is the one vp8-decoder's
#    repository pins, at the commit it was published from; the files come from the WebM project.
manifest=$work/vectors.sha256
fetch https://raw.githubusercontent.com/AlakazamLabs/vp8/28844d61964caca87961e0ea3ee92cd624d4b8d4/crates/vp8-decoder/tests/vectors.sha256 "$manifest" || { note "manifest: fetch failed"; exit 1; }
base=https://storage.googleapis.com/downloads.webmproject.org/test_data/libvpx
while read -r sum name; do
    [ -n "$name" ] || continue
    fetch "$base/$name" "$work/vp8/$name" || { note "$name: fetch failed"; fail=1; continue; }
    got=$(sha256sum "$work/vp8/$name" | cut -d' ' -f1)
    [ "$got" = "$sum" ] || { note "$name: SHA-256 mismatch"; fail=1; }
done < "$manifest"
$check vp8-vectors "$work/vp8" || fail=1

# 2. Against libvpx, byte for byte.
same=0; total=0
for ivf in "$work"/vp8/*.ivf examples/test-data/output_vp8.ivf; do
    n=$(basename "$ivf" .ivf)
    total=$((total + 1))
    ffmpeg -hide_banner -loglevel error -y -c:v libvpx -i "$ivf" -fps_mode passthrough -f rawvideo -pix_fmt yuv420p "$work/out/$n.libvpx.yuv"
    $check decode vp8 "$ivf" "$work/out/$n.ours.yuv" >/dev/null
    if cmp -s "$work/out/$n.libvpx.yuv" "$work/out/$n.ours.yuv"; then
        same=$((same + 1))
    else
        note "vp8 $n: differs from libvpx ($(wc -c < "$work/out/$n.libvpx.yuv") / $(wc -c < "$work/out/$n.ours.yuv") bytes)"
    fi
done
echo "MEASURE vp8 decode against libvpx: $same of $total streams byte-identical"
[ "$same" = "$total" ] || fail=1
echo "MEASURE output_vp8.ivf I420 md5 (libvpx): $(md5sum < "$work/out/output_vp8.libvpx.yuv" | cut -d' ' -f1)"

# 3. AV1 against dav1d.
aom=https://storage.googleapis.com/aom-test-data
same=0; total=0
for n in av1-1-b8-01-size-16x16 av1-1-b8-01-size-66x66 av1-1-b8-01-size-226x226 \
         av1-1-b8-02-allintra av1-1-b8-04-cdfupdate av1-1-b8-05-mv av1-1-b8-06-mfmv \
         av1-1-b8-22-svc-L1T2 av1-1-b8-22-svc-L2T1 av1-1-b8-22-svc-L2T2; do
    fetch "$aom/$n.ivf" "$work/av1/$n.ivf" || { note "$n: not available"; continue; }
    total=$((total + 1))
    ffmpeg -hide_banner -loglevel error -y -c:v libdav1d -i "$work/av1/$n.ivf" -fps_mode passthrough -f rawvideo -pix_fmt yuv420p "$work/out/$n.dav1d.yuv"
    $check decode av1 "$work/av1/$n.ivf" "$work/out/$n.ours.yuv"
    if cmp -s "$work/out/$n.dav1d.yuv" "$work/out/$n.ours.yuv"; then
        same=$((same + 1))
    else
        note "av1 $n: differs from dav1d ($(wc -c < "$work/out/$n.dav1d.yuv") / $(wc -c < "$work/out/$n.ours.yuv") bytes)"
    fi
done
echo "MEASURE av1 decode against dav1d: $same of $total streams byte-identical"
[ "$same" = "$total" ] || fail=1

# 4. Encoders: speed, rate, quality; the streams cross-decoded.
clip=$work/niklas_1280_720_30.y4m
fetch "$base/niklas_1280_720_30.y4m" "$clip" || { note "clip: fetch failed"; fail=1; }
cross() { # CODEC IVF
    local lib=libvpx; [ "$1" = av1 ] && lib=libdav1d
    ffmpeg -hide_banner -loglevel error -y -c:v "$lib" -i "$2" -fps_mode passthrough -f rawvideo -pix_fmt yuv420p "$2.ref.yuv"
    $check decode "$1" "$2" "$2.ours.yuv" >/dev/null
    if cmp -s "$2.ref.yuv" "$2.ours.yuv"; then
        echo "MEASURE cross-decode $1 $(basename "$2"): $lib and ours identical"
    else
        note "cross-decode $1 $(basename "$2"): $lib and ours DIFFER"; fail=1
    fi
}
enc() { # CODEC INPUT FRAMES BITRATE SPEED NAME
    $check encode "$1" "$2" "$3" 30 "$4" "$5" "$work/out/$6.ivf" || fail=1
    cross "$1" "$work/out/$6.ivf"
}
enc vp8 "$clip" 60 2000000 0 vp8-720p
enc vp8 "$clip@640x360" 60 600000 0 vp8-360p
enc vp8 synthetic:640x360 150 600000 0 vp8-360p-synthetic
enc vp8 synthetic:1280x720 90 1500000 0 vp8-720p-synthetic
for speed in 10 8 6; do
    enc av1 "$clip@640x360" 60 600000 $speed av1-360p-s$speed
done
enc av1 "$clip" 30 1500000 10 av1-720p-s10
enc av1 synthetic:640x360 90 600000 10 av1-360p-synthetic-s10
echo "MEASURE runner: $(nproc) CPUs, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2)"
exit $fail

# rtc-video

The video pipeline of the `rtc` WebRTC engine: sans-I/O, pure Rust by default.

Phase one, here, is the receive side, codec-agnostic: RTP packets in; frames assembled per
payload format (VP8, VP9, AV1, H.264, H.265), their references found (VP8 temporal layers,
VP9 flexible and non-flexible modes, the Dependency Descriptor, sequence numbers), held until
decodable and released at their render time (libwebrtc's jitter estimator, timestamp
extrapolator and timing model); key frames asked for (PLI) when the picture is lost; the W3C
video statistics (`framesDecoded`, `freezeCount`, `jitterBufferDelay`, ...) measured and handed
to the engine's `getStats()`. Decoding is the application's, behind the `VideoDecoder` trait.

Codecs (phase two), all opt-in; the default build decodes no video:

- `vp8`: VP8 decode and encode in pure Rust (`vp8-decoder` / `vp8-encoder`, pinned to `=0.1.3`;
  checked bit-exact on the WebM test vectors and against libvpx, real time to 720p, fuzzed).
  Opt-in until the owner decides on these weeks-old crates (docs/video-pipeline.md 4.7). An
  application that ships a binary built with `vp8` must include, with its licence notices, the
  BSD-3-Clause notice of the RFC 6386 reference decoder (Google) found in the crates' `NOTICE`
  files.
- `av1`: AV1 (`rav1d` / `rav1e` without assembly): decode real time to 720p30, encode not real
  time. **With rav1d 1.1.0 a malformed AV1 frame aborts the whole process** (a panic inside
  rav1d's C API that nothing can catch; rav1d issue 1497, fixed upstream but unreleased). Use it
  only for trusted senders, or with `isolation`.
- `isolation`: runs a decoder in a child process, so a decoder that aborts, crashes or hangs
  costs one frame instead of the application.

See `docs/video-pipeline.md` in the repository for the design, the phases and what was
measured.

Licence: MIT OR Apache-2.0.

# rtc-video

The video pipeline of the `rtc` WebRTC engine: sans-I/O, pure Rust by default.

Phase one, here, is the receive side, codec-agnostic: RTP packets in; frames assembled per
payload format (VP8, VP9, AV1, H.264, H.265), their references found (VP8 temporal layers,
VP9 flexible and non-flexible modes, the Dependency Descriptor, sequence numbers), held until
decodable and released at their render time (libwebrtc's jitter estimator, timestamp
extrapolator and timing model); key frames asked for (PLI) when the picture is lost; the W3C
video statistics (`framesDecoded`, `freezeCount`, `jitterBufferDelay`, ...) measured and handed
to the engine's `getStats()`. Decoding is the application's, behind the `VideoDecoder` trait.

Codecs (phase two): VP8 decode and encode in pure Rust by default (`vp8-decoder` /
`vp8-encoder`, pinned; checked bit-exact on the WebM test vectors and against libvpx, real
time to 720p, fuzzed); AV1 (`rav1d` / `rav1e` without assembly) behind the opt-in `av1`
feature: decode real time to 720p30, encode not real time, and rav1d aborts the process on a
hostile frame.

See `docs/video-pipeline.md` in the repository for the design, the phases and what was
measured.

Licence: MIT OR Apache-2.0.

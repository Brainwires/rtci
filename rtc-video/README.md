# rtc-video

The video pipeline of the `rtc` WebRTC engine: sans-I/O, pure Rust by default.

Phase one, here, is the receive side, codec-agnostic: RTP packets in; frames assembled per
payload format (VP8, VP9, AV1, H.264, H.265), their references found (VP8 temporal layers,
VP9 flexible and non-flexible modes, the Dependency Descriptor, sequence numbers), held until
decodable and released at their render time (libwebrtc's jitter estimator, timestamp
extrapolator and timing model); key frames asked for (PLI) when the picture is lost; the W3C
video statistics (`framesDecoded`, `freezeCount`, `jitterBufferDelay`, ...) measured and handed
to the engine's `getStats()`. Decoding is the application's, behind the `VideoDecoder` trait.

See `docs/video-pipeline.md` in the repository for the design, the phases and what was
measured.

Licence: MIT OR Apache-2.0.

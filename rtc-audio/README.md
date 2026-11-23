# rtc-audio

The audio pipeline for the `rtc` engine, which is a transport only and never encodes, decodes,
captures or plays out media:

- codecs: Opus (opus-rs, a pure-Rust port of libopus; the C libopus behind the opt-in feature
  `libopus`), G.711 (PCMU, PCMA), G.722, and the RFC 7587 Opus parameters;
- the receive pipeline: an adaptive jitter buffer with in-band FEC recovery, RED (RFC 2198),
  concealment, comfort noise (Opus DTX, RFC 3389), time-stretching and the W3C inbound audio
  statistics;
- capture processing: high-pass filter, delay estimation, echo canceller, residual echo and
  noise suppressor, voice activity detection, gain control;
- the send pipeline: processing, encoding, bitrate and FEC control, RFC 6464 audio levels;
- with feature `engine` (default), the glue to an `RTCRtpSender` / `RTCRtpReceiver` of the
  engine's peer connection.

## Status

Phase one of the media pipeline (audio) is complete. What was measured, and what is not done
(G.722 test vectors, multi-channel echo cancellation, clock-drift compensation in front of the
echo canceller, among others), is in
[docs/media-pipeline.md](../docs/media-pipeline.md).

## Use

Every part is a plain type usable without a peer connection. With the engine:
`engine::AudioSender::push_capture` every 10 ms of microphone audio,
`engine::AudioReceiver::handle_rtp` for each received RTP packet and `pull` every 10 ms of
playout. The example `audio-loopback` runs two peer connections over a lossy link in virtual
time through the whole pipeline. Capture and playout devices are in `rtc-devices`.

Like the engine, the crate does no I/O: it reads no clock, opens no device and starts no
thread. The default features are pure Rust; `libopus` builds the bundled C library with CMake.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

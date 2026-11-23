# rtc-media

Media samples and container I/O for WebRTC: a codec-agnostic `Sample` (one encoded frame
with its duration and timestamp), readers and writers for IVF (VP8, VP9, AV1), Ogg (Opus)
and H.264 / H.265 Annex B streams, and the audio and video helpers the examples use. It does
not encode, decode, capture or play media.

## Specifications

- RFC 6184 and RFC 7798, the H.264 and H.265 NAL unit structure the Annex B readers split on
- The IVF and Ogg container formats (not IETF payload formats)

Clause-by-clause status, with the test that proves each clause: [rfc6184](../docs/conformance/audit/rfc6184.md), [rfc7798](../docs/conformance/audit/rfc7798.md).

## Use

`Sample` goes to a sample-based track of the root crate (`rtc`), whose packetizers in
`rtc-rtp` make the RTP payloads. `io` has the readers and writers
(`io::ivf_reader::IVFReader`, `io::ogg_reader::OggReader`, `io::h26x_reader::H26xReader`, and
their writers); the root crate's `play-from-disk-*` and `save-to-disk-*` examples use them.

## Sans-I/O

The readers and writers work on any `std::io::Read` / `Write` the caller gives them; the crate opens no file or socket itself and reads no clock.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

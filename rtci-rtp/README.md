# rtci-rtp

RTP packets and headers, one-byte and two-byte header extensions with typed codecs for the
extensions WebRTC uses, and per-codec packetizers and depacketizers, including the SVC layer
structures and the SFrame payload format.

## Specifications

- RFC 3550, RTP; RFC 3551, the audio/video profile; RFC 8285, header extensions
- Payload formats: RFC 6184 (H.264), RFC 7798 (H.265), RFC 7741 (VP8), RFC 9628 (VP9), the AV1 RTP specification, RFC 7587 (Opus), RFC 4733 (DTMF), RFC 2198 (RED), RFC 3389 (comfort noise)
- Header extensions: RFC 6464 and RFC 6465 (audio levels), RFC 7941 (SDES items), abs-send-time, abs-capture-time, transport-wide sequence numbers, the AV1 dependency descriptor
- draft-ietf-avtcore-rtp-sframe, the SFrame payload format; W3C WebRTC SVC scalability modes

Clause-by-clause status, with the test that proves each clause: [rfc3550](../docs/conformance/audit/rfc3550.md), [rfc8285](../docs/conformance/audit/rfc8285.md), [rfc6184](../docs/conformance/audit/rfc6184.md), [rfc7798](../docs/conformance/audit/rfc7798.md), [rfc7741](../docs/conformance/audit/rfc7741.md), [rfc9628](../docs/conformance/audit/rfc9628.md), [av1-rtp](../docs/conformance/audit/av1-rtp.md), [rfc7587](../docs/conformance/audit/rfc7587.md), [rfc4733](../docs/conformance/audit/rfc4733.md).

## Use

`packet::Packet` and `header::Header` marshal and unmarshal through `rtci-shared`'s traits
and get or set extensions by id; `packetizer::Packetizer` with a `codec` payloader turns an
encoded frame into payloads, and the depacketizers reverse it. The root crate (`rtci`) uses it
for every media stream.

## Sans-I/O

Codecs and packetizers only: no socket, no clock (timestamps come from the caller), no encryption (that is `rtci-srtp`).

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

# rtc-sdp

SDP parsing and serialization as WebRTC uses it: session and media sections, and typed
attributes for codecs (`rtpmap`, `fmtp`, `rtcp-fb`), ICE, DTLS fingerprints, header extension
maps, grouping (BUNDLE, FID, LS), simulcast and RID, SSRC attributes and decoding
dependencies.

## Specifications

- RFC 8866, SDP; RFC 3264, the offer/answer model
- RFC 9429, JSEP, for the attributes it uses
- RFC 5576, source-specific attributes; RFC 5583, decoding dependencies; RFC 5888, grouping
- RFC 8285 (`extmap`), RFC 8859 (attribute multiplexing categories), RFC 8888 (`ccfb`)

Clause-by-clause status, with the test that proves each clause: [rfc8866](../docs/conformance/audit/rfc8866.md), [rfc3264](../docs/conformance/audit/rfc3264.md), [rfc5576](../docs/conformance/audit/rfc5576.md), [rfc5583](../docs/conformance/audit/rfc5583.md), [rfc8859](../docs/conformance/audit/rfc8859.md).

## Use

`SessionDescription::unmarshal` parses a description (`ParseOptions` names what else to
accept), `marshal` writes it back, and the builders make one section by section. The JSEP
logic (what an offer or answer contains) is in the root crate (`rtc`).

## Sans-I/O

A parser and writer: strings in, typed descriptions out, and back. No I/O, no clock.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

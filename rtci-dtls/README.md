# rtci-dtls

DTLS for WebRTC: DTLS 1.2 and DTLS 1.3, with the extensions WebRTC needs, chiefly the
`use_srtp` extension and the export of SRTP keying material from the handshake. SCTP data
channels run over the DTLS association.

## Specifications

- RFC 6347, DTLS 1.2, and RFC 5246, TLS 1.2, as DTLS 1.2 uses it
- RFC 9147, DTLS 1.3, and RFC 8446, TLS 1.3, as DTLS 1.3 uses it (no 0-RTT, no resumption across processes)
- RFC 5764, DTLS extension to establish keys for SRTP (`use_srtp`)
- RFC 7627, extended master secret; RFC 5746, renegotiation indication
- RFC 9146, connection identifiers for DTLS 1.2; RFC 5077, session tickets
- RFC 8122 and RFC 8827, certificate fingerprints and the WebRTC security architecture's DTLS rules

Clause-by-clause status, with the test that proves each clause: [rfc6347](../docs/conformance/audit/rfc6347.md), [rfc9147](../docs/conformance/audit/rfc9147.md), [rfc5246](../docs/conformance/audit/rfc5246.md), [rfc8446](../docs/conformance/audit/rfc8446.md), [rfc5764](../docs/conformance/audit/rfc5764.md), [rfc7627](../docs/conformance/audit/rfc7627.md), [rfc5746](../docs/conformance/audit/rfc5746.md), [rfc9146](../docs/conformance/audit/rfc9146.md), [rfc5077](../docs/conformance/audit/rfc5077.md).

## Use

Applications normally get DTLS from the root crate (`rtci`), which configures it from the
peer connection's certificates and fingerprints. Used on its own, `config::ConfigBuilder`
sets certificates, cipher suites, curves, the role and the SRTP protection profiles, and
`endpoint` is the entry point that takes datagrams in and gives datagrams and events out.
The crate documentation has an example.

## Sans-I/O

The handshake and the record layer are state machines: feed them datagrams and `Instant`s, poll them for the datagrams to send, the next retransmission deadline and the events (handshake complete, exported keys, alerts). The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller. All cryptography goes through `rtci-crypto`'s provider (`crypto-ring` by default, or `crypto-aws-lc-rs`).

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

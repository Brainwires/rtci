# rtci-ice

An ICE agent for WebRTC: candidates, their priorities and pairing, connectivity checks
over STUN, nomination, consent freshness and ICE restarts, with trickle ICE and ICE over
TCP.

## Specifications

- RFC 8445, Interactive Connectivity Establishment
- RFC 8838, Trickle ICE
- RFC 6544, TCP candidates with ICE
- RFC 7675, STUN usage for consent freshness
- RFC 8421, multihomed and dual-stack ICE
- RFC 8489, STUN, as ICE uses it
- draft-ietf-mmusic-mdns-ice-candidates, mDNS names for host candidates
- RFC 8839, the ICE candidate attribute grammar

Clause-by-clause status, with the test that proves each clause: [rfc8445](../docs/conformance/audit/rfc8445.md), [rfc8838](../docs/conformance/audit/rfc8838.md), [rfc6544](../docs/conformance/audit/rfc6544.md), [rfc7675](../docs/conformance/audit/rfc7675.md), [rfc8421](../docs/conformance/audit/rfc8421.md), [draft-ietf-mmusic-mdns-ice-candidates](../docs/conformance/audit/draft-ietf-mmusic-mdns-ice-candidates.md).

## Use

The root crate (`rtci`) runs an `Agent` per transport. Used on its own,
`agent::Agent` takes local and remote candidates (`candidate`), inbound STUN datagrams and
time, and gives the checks to send, the state changes and the selected pair.

## Sans-I/O

The agent never gathers by itself: the application binds the sockets and tells it which local candidates exist (the root crate's stream interface gathers TCP candidates for it). The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtci`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

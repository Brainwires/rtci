# rtc-datachannel

WebRTC data channels over SCTP: the Data Channel Establishment Protocol (the
`DATA_CHANNEL_OPEN` / `DATA_CHANNEL_ACK` handshake), the reliability and ordering
parameters of a channel, and the payload protocol identifiers that tell string, binary and
empty messages apart.

## Specifications

- RFC 8831, WebRTC Data Channels
- RFC 8832, WebRTC Data Channel Establishment Protocol

Clause-by-clause status, with the test that proves each clause: [rfc8831](../docs/conformance/audit/rfc8831.md), [rfc8832](../docs/conformance/audit/rfc8832.md).

## Use

Most applications use data channels through the root crate (`rtc`,
`RTCPeerConnection::create_data_channel`), which runs this crate over `rtc-sctp`. Used on its
own, [`data_channel`](https://docs.rs/rtc-datachannel/latest/rtc_datachannel/data_channel/)
holds one channel's state over an SCTP stream and
[`message`](https://docs.rs/rtc-datachannel/latest/rtc_datachannel/message/) the DCEP
messages.

## Sans-I/O

It reads and writes SCTP stream data through `rtc-sctp`'s association; it opens no socket and starts no timer. The crate does no I/O and reads no clock: every call that depends on time takes an `Instant` from the caller.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

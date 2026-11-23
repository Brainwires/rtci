# rtc-rtcp

RTCP packet parsing and serialization: sender and receiver reports, source description,
BYE, application-defined packets, the transport-layer and payload-specific feedback messages
(NACK, TWCC, PLI, FIR, REMB and others), extended reports and congestion control feedback,
and compound packets.

## Specifications

- RFC 3550, RTCP packet formats; RFC 5506, reduced-size RTCP
- RFC 4585, RTP/AVPF feedback; RFC 5104, codec control messages
- RFC 3611, RTCP extended reports; RFC 6679, ECN feedback
- RFC 8888, RTCP congestion control feedback; RFC 7728, pause and resume

Clause-by-clause status, with the test that proves each clause: [rfc3550](../docs/conformance/audit/rfc3550.md), [rfc4585](../docs/conformance/audit/rfc4585.md), [rfc5104](../docs/conformance/audit/rfc5104.md), [rfc3611](../docs/conformance/audit/rfc3611.md), [rfc6679](../docs/conformance/audit/rfc6679.md), [rfc8888](../docs/conformance/audit/rfc8888.md).

## Use

`rtc_rtcp::packet::unmarshal` parses a (compound) RTCP datagram into packets; every packet
type implements `rtc-shared`'s `Marshal` / `Unmarshal`. The RTCP session logic (when to send
what) is in `rtc-interceptor`.

## Sans-I/O

A codec only: bytes in, typed packets out, and back. It holds no state between packets and reads no clock.

## Licence

Licensed under either of the [MIT licence](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

This crate is part of the [`rtc`](../README.md) workspace, which descends from
[webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) and is developed independently;
[FORK.md](../FORK.md) lists what it carries over upstream. Upstream's licence and copyright
notices are retained.

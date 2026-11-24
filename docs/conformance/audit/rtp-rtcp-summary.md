# RTP / RTCP area: audit summary

Clause-level audit of the RTP, RTCP, congestion control, header extension, FEC and payload format
specifications against fork master 8916bc3. Read-only: no test was run; every verdict comes from
reading the code and the tests. One file per spec in this directory; this file holds the totals
and the gaps that cut across them.

39 specs, 1847 clauses. Each cell is `tested / untested / partial / missing / violated / n-a`,
counted mechanically from the tables (MUST includes MUST NOT, SHALL, REQUIRED; SHOULD includes
SHOULD NOT, RECOMMENDED; MAY includes OPTIONAL).

| Spec (file) | MUST | SHOULD | MAY |
|---|---|---|---|
| rfc3550 | 29 / 5 / 9 / 19 / 3 / 11 | 4 / 7 / 11 / 8 / 1 / 9 | 6 / 1 / 3 / 3 / 0 / 1 |
| rfc3551 | 5 / 0 / 2 / 1 / 1 / 8 | 6 / 0 / 1 / 2 / 2 / 3 | 1 / 2 / 0 / 1 / 0 / 2 |
| rfc4585 | 10 / 12 / 9 / 22 / 3 / 11 | 1 / 1 / 3 / 2 / 0 / 5 | 5 / 3 / 1 / 6 / 0 / 0 |
| rfc5104 | 2 / 3 / 5 / 31 / 0 / 11 | 1 / 1 / 0 / 6 / 0 / 3 | 1 / 1 / 0 / 8 / 0 / 2 |
| rfc5124 | 3 / 3 / 0 / 2 / 1 / 2 | 0 / 2 / 0 / 0 / 0 / 3 | 4 / 0 / 0 / 0 / 0 / 3 |
| rfc4588 | 13 / 4 / 4 / 3 / 2 / 12 | 2 / 1 / 5 / 2 / 1 / 2 | 1 / 2 / 1 / 1 / 0 / 1 |
| rfc5506 | 6 / 1 / 2 / 1 / 3 / 0 | 1 / 0 / 0 / 2 / 1 / 0 | 1 / 0 / 0 / 0 / 0 / 0 |
| rfc5761 | 4 / 3 / 2 / 0 / 3 / 1 | 1 / 2 / 0 / 0 / 0 / 3 | 0 / 0 / 0 / 0 / 0 / 1 |
| rfc8285 | 25 / 4 / 2 / 3 / 5 / 2 | 3 / 0 / 1 / 0 / 1 / 3 | 0 / 0 / 3 / 2 / 0 / 1 |
| rfc7941 | 3 / 2 / 2 / 1 / 0 / 0 | 0 / 2 / 0 / 4 / 0 / 1 | 0 / 0 / 1 / 2 / 0 / 0 |
| rfc8852 | 5 / 1 / 1 / 3 / 0 / 1 | 0 / 0 / 1 / 1 / 0 / 3 | 0 / 0 / 0 / 0 / 0 / 0 |
| rfc6464 | 2 / 3 / 1 / 5 / 0 / 3 | 0 / 0 / 0 / 0 / 0 / 1 | 0 / 0 / 0 / 1 / 0 / 0 |
| rfc6465 | 0 / 1 / 0 / 7 / 0 / 2 | 0 / 0 / 1 / 0 / 0 / 2 | 0 / 0 / 0 / 0 / 0 / 1 |
| rfc3611 | 20 / 5 / 5 / 18 / 3 / 0 | 1 / 2 / 2 / 11 / 1 / 2 | 4 / 1 / 1 / 2 / 0 / 1 |
| rfc8888 | 12 / 3 / 2 / 5 / 5 / 1 | 0 / 1 / 2 / 4 / 0 / 1 | 2 / 0 / 2 / 1 / 0 / 0 |
| draft-holmer-rmcat-transport-wide-cc-extensions | 22 / 4 / 6 / 1 / 3 / 0 | 0 / 0 / 2 / 1 / 0 / 0 | 0 / 0 / 1 / 0 / 0 / 0 |
| draft-ietf-rmcat-gcc | 20 / 3 / 6 / 5 / 1 / 0 | 7 / 3 / 4 / 3 / 0 / 0 | 0 / 0 / 0 / 1 / 0 / 0 |
| rfc8834 | 33 / 4 / 20 / 24 / 3 / 3 | 0 / 2 / 1 / 8 / 0 / 5 | 6 / 1 / 1 / 8 / 0 / 0 |
| rfc8835 | 6 / 10 / 1 / 6 / 0 / 2 | 0 / 0 / 0 / 4 / 0 / 2 | 0 / 0 / 0 / 3 / 0 / 2 |
| rfc8837 | 0 / 0 / 0 / 3 / 0 / 1 | 0 / 0 / 0 / 6 / 0 / 1 | 0 / 0 / 0 / 1 / 0 / 0 |
| rfc8836 | 1 / 5 / 0 / 1 / 0 / 0 | 3 / 8 / 7 / 6 / 0 / 0 | 0 / 0 / 0 / 0 / 0 / 0 |
| rfc7022 | 1 / 0 / 2 / 0 / 3 / 1 | 1 / 0 / 0 / 0 / 1 / 0 | 1 / 0 / 0 / 0 / 0 / 0 |
| rfc8108 | 2 / 1 / 2 / 11 / 1 / 5 | 1 / 0 / 2 / 2 / 3 / 2 | 0 / 0 / 0 / 3 / 0 / 0 |
| rfc7160 | 0 / 1 / 0 / 4 / 0 / 0 | 0 / 0 / 0 / 0 / 0 / 1 | 0 / 0 / 0 / 1 / 0 / 1 |
| rfc7164 | 0 / 0 / 0 / 1 / 0 / 0 | 0 / 0 / 1 / 3 / 0 / 2 | 0 / 0 / 0 / 3 / 0 / 0 |
| rfc2198 | 0 / 3 / 1 / 8 / 0 / 1 | 0 / 1 / 0 / 2 / 0 / 0 | 0 / 0 / 0 / 1 / 0 / 0 |
| rfc5109 | 0 / 1 / 0 / 32 / 0 / 1 | 0 / 1 / 0 / 4 / 0 / 1 | 0 / 1 / 0 / 4 / 0 / 0 |
| rfc8627 | 0 / 1 / 1 / 38 / 1 / 2 | 0 / 1 / 0 / 5 / 0 / 2 | 0 / 1 / 0 / 6 / 0 / 0 |
| draft-ietf-payload-flexible-fec-scheme-03 | 19 / 8 / 1 / 3 / 6 / 2 | 1 / 0 / 1 / 5 / 0 / 3 | 0 / 1 / 0 / 6 / 0 / 0 |
| rfc6184 | 22 / 14 / 9 / 7 / 4 / 17 | 5 / 1 / 3 / 8 / 0 / 12 | 1 / 0 / 0 / 8 / 1 / 5 |
| rfc7798 | 19 / 17 / 7 / 9 / 4 / 23 | 3 / 3 / 4 / 1 / 0 / 2 | 0 / 0 / 1 / 9 / 0 / 9 |
| rfc7741 | 27 / 9 / 0 / 4 / 2 / 6 | 2 / 1 / 0 / 4 / 1 / 6 | 3 / 2 / 0 / 4 / 0 / 2 |
| rfc9628 | 26 / 7 / 3 / 5 / 5 / 13 | 3 / 1 / 1 / 2 / 0 / 3 | 0 / 2 / 0 / 3 / 0 / 1 |
| av1-rtp | 15 / 6 / 1 / 37 / 0 / 12 | 4 / 2 / 4 / 4 / 0 / 1 | 1 / 1 / 0 / 3 / 0 / 5 |
| rfc7587 | 3 / 4 / 2 / 1 / 2 / 8 | 0 / 1 / 1 / 0 / 0 / 8 | 1 / 0 / 0 / 2 / 0 / 0 |
| rfc4733 | 0 / 3 / 1 / 17 / 0 / 5 | 0 / 0 / 1 / 9 / 0 / 7 | 0 / 1 / 0 / 5 / 0 / 1 |
| rfc3389 | 0 / 2 / 1 / 4 / 0 / 2 | 0 / 0 / 0 / 2 / 0 / 1 | 0 / 1 / 0 / 1 / 0 / 1 |
| rfc7742 | 3 / 2 / 4 / 0 / 0 / 9 | 0 / 0 / 1 / 1 / 0 / 4 | 1 / 1 / 1 / 1 / 0 / 1 |
| rfc7874 | 2 / 1 / 0 / 5 / 0 / 1 | 0 / 3 / 0 / 0 / 0 / 6 | 0 / 0 / 1 / 1 / 0 / 3 |
| **Area total** | **362 / 154 / 113 / 351 / 63 / 180** (1223) | **51 / 45 / 60 / 122 / 12 / 109** (399) | **39 / 23 / 17 / 101 / 1 / 44** (225) |

Of the 1043 MUST clauses that bind the engine, 362 (35%) are implemented and tested, 154 are
implemented without a test that would catch a regression, 113 are partial, 351 are missing and 63
are violated.

Notes on reading the table:

- `rfc5761.md` also holds three rows for RFC 8858 (`a=rtcp-mux-only`).
- `draft-ietf-rmcat-gcc.md` counts the `Gcc` estimator that `configure_congestion_control`
  installs; the second implementation (`gcc/twcc_gcc`) is listed there as divergences.
- `rfc8836.md` is judged for an application that opts into congestion control. With
  `register_default_interceptors` alone there is none.
- `rfc8627.md`, `rfc5109.md`, `rfc2198.md` are almost entirely `missing`: nothing implements
  them. The FlexFEC coder is draft-03 and is audited in its own file.
- `rfc8835.md` lists ICE/TURN/DTLS/SCTP clauses for completeness; their proof is in those areas'
  files, and ten of them are `untested` here for that reason.
- Two rows are deliberate deviations recorded as `violated` and should stay: FLEXFEC03-4.2-17
  (mask bit origin, as libwebrtc and RFC 8627) and FLEXFEC03-5.1-5 (subtype `flexfec-03`).
- Several specs with little BCP 14 language (the TWCC and GCC drafts, RFC 8852, the AV1
  dependency descriptor) have levels implied by the text; the files mark them.

## The gaps, as work packages, in order of importance

1. **RTCP is not scheduled, sized or negotiated (L).** Reports leave on a fixed 1 s timer and
   feedback on private timers. Missing: RTCP bandwidth (`b=RS`, `b=RR`, `b=AS`), member table,
   `avg_rtcp_size`, randomisation, reconsideration, source timeout, AVPF early/regular rules and
   `trr-int`, compound versus reduced-size by negotiation, aggregation and MTU split.
   `a=rtcp-mux` and `a=rtcp-rsize` are always written (in answers too) and never read; feedback
   is always sent bare. RFC3550-6.2/6.3, RFC4585-3.1/3.4/3.5, RFC5506-4/5, RFC5761-5.1.1,
   RFC8108-5.x, RFC8834-4.1-14..19, 4.5-2, 4.6-2/-3.
2. **RTCP sources are not participants (M).** RR, NACK, TWCC each use their own random sender
   SSRC, interval PLI and CCFB use 0; RTX and FEC SSRCs send no SR and no SDES; a silent sender
   sends SR forever; no BYE from `close()`. RFC8108-5.1-1, RFC3550-6.4, RFC4588-6.1-1,
   FLEXFEC03-4.2-8.
3. **CNAME (S).** The sender CNAME is the application's MediaStream id, one per stream, and
   receiver reports use another. RFC7022-4.x, RFC8834-4.9-2/-3/-4, RFC3550-6.5.1-3.
4. **RTCP parser robustness (S).** SDES items above type 8 (MID, RID) end the chunk and fail the
   datagram; a padded XR, one malformed XR block or a non-REMB PSFB FMT 15 fails every packet in
   the datagram; unknown types re-marshal with type 0. RFC3550-6.5-4, RFC3611-2-4/4-2,
   RFC8834-4.1-13, 4.1-23.
5. **No congestion control or circuit breaker by default; bandwidth limits ignored (M).** GCC and
   the pacer are opt-in; RFC 8083 is absent; `b=AS`/`TIAS`, TMMBR/TMMBN and REMB (advertised as
   `goog-remb`) are not honoured. RFC8834-7-1, 7.1-1, 7.1-3, 5.1.6-1/-2, RFC5104-4.2.x (27 rows),
   GCC-3-5..8.
6. **Repair streams and congestion control do not fit together (M).** RTX and FlexFEC packets get
   no transport-wide sequence number; FEC is computed before the TWCC sender rewrites the packet;
   repair packets are swallowed before the feedback recorders; recovered and retransmitted packets
   are reported as arrived; a lost feedback packet reads as media loss; `Gcc` has no feedback
   timeout. TWCC-2.2-2, TWCC-3-3, FLEXFEC03-4.1-1, RFC8888-3.1-15, RFC8836-2-10.
7. **SSRC collisions (M).** No detection, no BYE and re-key, no re-signalling. RFC3550-8.x,
   RFC8834-4.8-5/-6.
8. **Header extensions (M).** Parser: two-byte appbits, ID 0 with a length, one-byte form chosen
   for an ID above 14. SDP: session-level extmap ignored, direction dropped, ID 4096+ fails the
   description. Defaults: MID is video only, audio level and CVO are not registered; the engine
   never stamps MID or RID; RFC 6904 encryption and csrc-audio-level are absent;
   `get_contributing_sources` is never filled. RFC8285-4.x/7.x, RFC7941-4.1-2, RFC8852-3.3-1,
   RFC8834-5.2.2-1/-2, 5.2.4-1, 5.2.5-1, RFC6464, RFC6465.
9. **Negotiation of codec parameters (M).** The answer echoes the offer's fmtp; H.264 defaults
   and Table 5 profile matching are wrong and a MIME-only fallback negotiates what cannot be sent;
   VP9 and AV1 parameter defaults are not inferred; `a=rtcp-fb:*` is dropped; ccfb is written as
   `ack ccfb` per payload type; an `RTP/AVP` offer is accepted. RFC7587-7.1-8, RFC6184-8.x,
   RFC9628-6-5, AV1RTP-7.2-x, RFC8888-6-1, RFC5124-3.3.1-6.
10. **Payload formats (M each).** H.265 has no depacketizer and a broken TSCI reader; H.264
    reorders parameter sets and hard-codes the STAP-A header; VP8's depacketizer keeps state
    between packets and refuses packets under four octets; VP9 flexible mode always claims P=0
    and the payloader can flip F mid-stream; AV1 accepts malformed leb128 and treats a mid-unit
    packet as a frame start. No SVC/layer signalling for VP8 temporal layers, VP9 or AV1, and no
    AV1 dependency descriptor (35 rows).
11. **Missing formats and features (L in total).** telephone-event and comfort noise (RFC 7874
    requires both), RED, ULPFEC, FlexFEC as RFC 8627, RPSI, LRR, TSTR/TSTN/VBCM, `a=rtcp-xr`,
    XR blocks beyond RRTR/DLRR, RFC 6051, DSCP and priority (RFC 8837, RFC 8835 4), clock-rate
    switches (RFC 7160), leap seconds (RFC 7164), unbundled transports (decision D2).
12. **Tests for what works (M).** The 222 `untested` MUST/SHOULD/MAY rows; notably no
    `SampleBuilder` test with H.264, H.265 or AV1, no payloader-to-depacketizer round trips, and
    no VP9/AV1 offer/answer tests.

Items 3, 4 and the parser halves of 8 and 10 are small and are wire-level bugs a browser peer can
trigger today; they are the cheapest first step. Item 1 is the largest single block of missing
MUSTs and items 2, 6 and 7 build on it.

## Bugs found

Each spec file ends with its own "Bugs found" list with `path:line` and a reproduction idea. None
was reproduced by running. The ones a conformant peer can trigger:

- `rtci-rtcp/src/source_description/mod.rs:72-82,170`: an SDES item type above 8 ends the chunk and
  the datagram fails to parse.
- `rtci-rtcp/src/extended_report/mod.rs:285`: a padded XR fails the whole compound packet.
- `rtci-sdp/src/util/mod.rs:182-194`: `a=rtcp-fb:* ...` is dropped.
- `src/peer_connection/sdp/mod.rs:941-942`: `a=rtcp-mux` and `a=rtcp-rsize` written whatever was
  offered, never read; `RTCRtcpMuxPolicy` is dead configuration.
- `src/peer_connection/sdp/mod.rs:1241`, `handler/interceptor.rs:261-272`: CNAME is the stream id.
- `src/peer_connection/handler/endpoint.rs:293-311`: an inbound compound packet is routed by its
  first packet only (a PLI after an empty RR is dropped, or tagged with another track).
- `src/peer_connection/handler/interceptor.rs:425-452`: repair SSRCs are bound with the primary's
  feedback, so the receiver NACKs gaps between RTX padding probes; NACKs also continue after BYE.
- `rtci-interceptor/src/nack/responder.rs:323`: RTX sequence numbers restart at 0 on re-bind and
  collide with SRTP's sent index.
- `rtci-interceptor/src/rtpfb/history.rs:136-157`: a lost TWCC feedback counts its packets as lost.
- `rtci-rtcp/src/transport_feedbacks/transport_layer_cc/mod.rs`: a valid feedback with an even
  chunk count and no deltas is rejected; reference time not unwrapped.
- `rtci-interceptor/src/flexfec/coverage.rs:5`: 110 packets allowed in a 109-bit mask; FEC encoder
  runs before the TWCC sender rewrites the packet.
- `rtci-rtp/src/header/mod.rs:147-176,446-468`: appbits, ID 0 with length, `set_extension` above
  ID 14 (reachable from the TWCC sender).
- `rtci-rtp/src/codec/vp8/mod.rs:136-157,207`: packets under 4 octets refused, stale X/I/L/T/K,
  S bit alone taken as frame start.
- `rtci-rtp/src/codec/vp9/mod.rs:109-117,149,410`: F flips mid-stream, flexible mode P=0, F
  honoured with I=0; `fmtp/generic/mod.rs:8-23`: absent `profile-id` matches any profile.
- `rtci-rtp/src/codec/h265/mod.rs:1157,968-977`: depacketize returns the payload unchanged; TSCI
  misread. `rtci-rtp/src/codec/h264/mod.rs:174-180,347-357`: parameter sets reordered or lost,
  one-byte NAL units and empty FU-A refused.
- `rtci-rtp/src/codec/av1/leb128.rs:9-24`, `depacketizer.rs:227-240`: malformed or oversized
  leb128 accepted, W not checked, Z=0 mid-unit packet taken as a frame start.
- `rtci-interceptor/src/report/sender.rs:300`, `sender_stream.rs:102`,
  `receiver_stream.rs:142-164`: SR for a silent stream, saturating RTP time, late packets and
  duplicates miscounted.
- `rtci-rtp/src/packetizer/mod.rs:137,144`: MTU below 12 underflows; marker set on every audio
  packet. `rtci-shared/src/util.rs:63`: payload types 64 to 95 are classified as RTCP.
- `src/peer_connection/configuration/media_engine.rs:1178-1218`: the answer echoes the offer's
  fmtp; H.264 payload type 127 is registered twice in the defaults.

## Not finished

- RFC 3550 sections 7, 9 and 12 to 15 are single `n/a` rows; RFC 3551 covers PCMU, PCMA, G722 only.
- RFC 4585 multiparty suppression, the RFC 5104 bounding-set algorithm, RFC 3611 Appendix A, RFC
  6184 8.1 and RFC 7798 7.1 per-parameter semantics, and RFC 4733 section 4 are grouped rows, not
  one row per sentence.
- AV1 A.8.2 (descriptor syntax) is covered through the A.8.3 semantics rows only.
- RFC 8835's ICE/TURN/DTLS/SCTP rows were not verified at test level here.
- RFC 8083 (circuit breaker), RFC 8854 (FEC requirements), RFC 6051, RFC 6904 and RFC 8858 are
  referenced by RFC 8834 and have no file of their own in this area (RFC 6904 has one from
  another auditor).

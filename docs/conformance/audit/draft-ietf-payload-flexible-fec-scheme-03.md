# draft-ietf-payload-flexible-fec-scheme-03: RTP Payload Format for Flexible FEC (the implemented FlexFEC)

Spec: draft-ietf-payload-flexible-fec-scheme-03, 31 October 2016 (expired; superseded by RFC 8627, whose
payload format is not backward compatible). This is the format libwebrtc negotiates as
`video/flexfec-03` and the only FEC the engine implements (`rtc-interceptor/src/flexfec/`). Audited at
fork master 8916bc3. All sections with implementation requirements are covered: 4, 5.1, 5.2, 6, 8, 9.
Sections 1 to 3, 7 (examples), 10 to 13 carry no requirement on an endpoint.

The interceptors are opt-in: nothing registers `FlexFec03SendInterceptor` / `FlexFec03ReceiveInterceptor`
by default, and `video/flexfec-03` is not in `register_default_codecs`.

Totals:

- MUST: tested 19 / untested 8 / partial 1 / missing 3 / violated 6 / n-a 2 (total 39)
- SHOULD: tested 1 / untested 0 / partial 1 / missing 5 / violated 0 / n-a 3 (total 10)
- MAY: tested 0 / untested 1 / partial 0 / missing 6 / violated 0 / n-a 0 (total 7)

Paths are relative to the repo root; `fec/` abbreviates `rtc-interceptor/src/flexfec/`, `it/` abbreviates
`rtc-interceptor/tests/`.

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| FLEXFEC03-4.1-1 | 4.1 | MUST | Source packets are sent unmodified; the FEC covers the packets as they are on the wire | partial | `fec/draft03/sender.rs:136-170` | `it/flexfec_send.rs::media_precedes_the_repair_packets_that_protect_it` | The interceptor does not alter media, but it encodes at `Slot::FecEncoder` (5000), before `TwccSenderInterceptor` (2000) adds or rewrites the transport-cc header extension (`twcc/sender.rs:112-126`). The protected image is then not the wire image. See Bug 1 |
| FLEXFEC03-4.2-1 | 4.2 | MUST | Repair packet carries a FEC header identifying the source block and the packets protected | tested | `fec/draft03/encoder.rs:222-241` | `encoder.rs::the_header_names_the_stream_and_block_it_protects` | |
| FLEXFEC03-4.2-2 | 4.2 | MUST | Marker bit of a repair packet SHALL be 0 | untested | `fec/draft03/encoder.rs:249-262` (`..Default::default()`) | none | No test reads `header.marker` of a repair packet |
| FLEXFEC03-4.2-3 | 4.2 | MUST | Repair packets use a dynamic payload type determined out of band | tested | `fec/draft03/sender.rs:193-205`, `src/rtp_transceiver/rtp_sender/rtp_codec.rs:347-352` | `encoder.rs::repair_packets_form_their_own_stream`, `tests/repair_codec_negotiation.rs::flexfec_codec_is_offered_alongside_the_track_codec` | |
| FLEXFEC03-4.2-4 | 4.2 | MUST | Repair sequence number is one higher than the previous repair packet | tested | `fec/draft03/encoder.rs:243-244` | `encoder.rs::repair_packets_form_their_own_stream`, `it/flexfec_send.rs::the_repair_stream_has_its_own_identity_and_sequence_numbers` | |
| FLEXFEC03-4.2-5 | 4.2 | SHOULD | Initial repair sequence number is random | missing | `fec/draft03/encoder.rs:63-70` (starts at 0), `fec/draft03/sender.rs:199` | none | `with_base_sequence_number` exists but production never calls it |
| FLEXFEC03-4.2-6 | 4.2 | MUST | Repair timestamp SHALL correspond to the repair packet's transmission time | violated | `fec/draft03/encoder.rs:256-259` | none | Carries the RTP timestamp of the first covered media packet, so it is the media clock, not the send time; jitter computed on the repair stream is meaningless |
| FLEXFEC03-4.2-7 | 4.2 | MUST | Repair SSRC SHALL be randomly assigned | untested | `src/peer_connection/internal.rs:1651-1657` (`rand::random` when the track names none) | none (`tests/repair_codec_negotiation.rs::explicit_repair_ssrcs_are_used_verbatim` covers the application-supplied case) | An application-supplied SSRC is used verbatim |
| FLEXFEC03-4.2-8 | 4.2 | SHOULD | Repair flow uses the RTCP CNAME to associate itself with the source flow | partial | `src/peer_connection/sdp/mod.rs:1256-1263` (same `a=ssrc ... cname` for the FEC SSRC) | `tests/repair_codec_negotiation.rs::flexfec_repair_flow_is_grouped_with_fec_fr` (SDP only) | No SR or SDES is ever sent for the repair SSRC: the FEC SSRC is not bound as a local stream (`rtp_sender/internal.rs:395-430`), so the RTCP half is missing |
| FLEXFEC03-4.2-9 | 4.2 | MUST | SSRC collisions of the repair flow are resolved as in RFC 3550 | missing | none | none | No SSRC collision handling anywhere in the engine |
| FLEXFEC03-4.2-10 | 4.2 | MUST | R bit is 0 in repair packets | tested | `fec/draft03/encoder.rs:203` | `encoder.rs::the_version_bits_are_not_recovered` | |
| FLEXFEC03-4.2-11 | 4.2 | MAY | Retransmission packets (R=1, Figure 15 layout) | missing | `fec/draft03/decoder.rs:333-335` (discarded) | none | Never sent; received ones are dropped, and that drop is untested |
| FLEXFEC03-4.2-12 | 4.2 | MAY | F=1 repair packets (M columns / N rows offsets, Figures 13 and 14) | missing | `fec/draft03/decoder.rs:336-338` (discarded) | none | Never sent; received ones are dropped silently, so a peer using fixed offsets gets no recovery |
| FLEXFEC03-4.2-13 | 4.2 | MUST | SSRCCount 0 is invalid: the packet MUST be ignored | untested | `fec/draft03/decoder.rs:339-341` | none | Anything other than 1 is rejected |
| FLEXFEC03-4.2-14 | 4.2 | MUST | Reserved 24 bits set to zero by senders | tested | `fec/draft03/encoder.rs:223` | `encoder.rs::the_header_names_the_stream_and_block_it_protects` | |
| FLEXFEC03-4.2-15 | 4.2 | MUST | Reserved 24 bits ignored by receivers | untested | `fec/draft03/decoder.rs:329-408` (bytes 9..12 never read) | none | |
| FLEXFEC03-4.2-16 | 4.2 | MAY | One repair packet protects several SSRCs (SSRCCount > 1, one SSRC / SN base / mask block each) | missing | `fec/draft03/decoder.rs:339-341`, `fec/draft03/encoder.rs:222` | none | Sender always writes 1; receiver discards anything else |
| FLEXFEC03-4.2-17 | 4.2 | MUST | Mask bit j set means the packet SN base + j + 1 is protected (literal draft text) | violated | `fec/draft03/decoder.rs:410-417`, `fec/draft03/encoder.rs:266-306` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically` | Deliberate: the code uses SN base + j, which is what libwebrtc sends and what RFC 8627 4.2.2.1 later wrote down. Do not "fix"; record as a known deviation from the letter of draft-03 |
| FLEXFEC03-4.2-18 | 4.2 | MUST | k bit: marks whether another mask follows; masks are 15, then 31, then 63 bits | tested | `fec/draft03/encoder.rs:228-241`, `fec/draft03/decoder.rs:346-407` | `encoder.rs::a_short_block_carries_one_mask_with_the_k_bit_set`, `a_longer_block_adds_the_second_mask`, `a_block_beyond_46_packets_adds_the_third_mask` | Polarity follows libwebrtc (k=1 is the last mask); the draft's sentence reads the other way round and is self-contradictory |
| FLEXFEC03-4.2-19 | 4.2 | MUST | A repair packet describes at most 109 source packets (15 + 31 + 63 mask bits) | violated | `fec/coverage.rs:5` (`MAX_MEDIA_PACKETS = 110`), `fec/bit_array.rs:58-70` (`mask3_draft03` shifts bit 109 out) | none (`coverage.rs::the_full_range_reaches_the_last_mask` asserts only the RFC 8627 `mask3`) | A 110-packet block is accepted, packet 109 is XORed into the repair data but not named in the wire mask. See Bug 2 |
| FLEXFEC03-4.2-20 | 4.2 | MUST | A truncated FEC header is not parsed past its end | tested | `fec/draft03/decoder.rs:330-332, 363-365, 382-384` | `it/flexfec_round_trip.rs::a_truncated_repair_packet_is_discarded` | Only the 20-byte bound is tested; the 24 and 32 byte bounds are not |
| FLEXFEC03-5.1-1 | 5.1 | MUST | `rate` SHALL be larger than 1000 Hz | n/a | none | none | The application registers the codec and its rate; the engine validates neither side |
| FLEXFEC03-5.1-2 | 5.1 | SHOULD | `rate` matches the protected stream's rate | n/a | none | none | Application's codec registration |
| FLEXFEC03-5.1-3 | 5.1 | MUST | Required parameter `repair-window` (microseconds) is signalled and bounds what is sent and buffered | missing | `fec/draft03/decoder.rs:10-19` (fixed 100 / 100 / 192 packet limits) | none | The engine neither writes nor reads `repair-window`; the fmtp line is whatever the application registered, and the decoder window is a packet count unrelated to it |
| FLEXFEC03-5.1-4 | 5.1 | MAY | Optional parameters `L`, `D`, `ToP` | missing | none | none | Not parsed, not generated |
| FLEXFEC03-5.1-5 | 5.1 | MUST | Media subtype name is `flexfec` | violated | `src/peer_connection/configuration/media_engine.rs:180`, `rtp_codec.rs:343-345` | `rtp_codec_flexfec_test.rs` | Deliberate: the coder is bound to `flexfec-03` (libwebrtc's name) and never to `flexfec`, because `flexfec` now means RFC 8627 |
| FLEXFEC03-5.2-1 | 5.2 | MUST | Subtype and rate go in `a=rtpmap`, remaining parameters in `a=fmtp` | tested | `src/peer_connection/sdp/mod.rs` (codec lines) | `tests/repair_codec_negotiation.rs::flexfec_codec_is_offered_alongside_the_track_codec` | |
| FLEXFEC03-5.2.1-1 | 5.2.1 | SHOULD | Receiver offered several L/D combinations chooses one with sufficient interleaving | missing | none | none | L and D are not understood |
| FLEXFEC03-5.2.1-2 | 5.2.1 | MUST | Receiver takes the offered repair-window into account for its buffering when accepting | missing | `fec/draft03/decoder.rs:10-19` | none | Lower-case "must" in the draft; the buffer is fixed whatever is offered |
| FLEXFEC03-5.2.1-3 | 5.2.1 | MUST | Unknown fmtp options in the offer are ignored and deleted from the answer | violated | `src/peer_connection/configuration/media_engine.rs:1178-1218` (the remote codec entry becomes the negotiated one), `src/peer_connection/sdp/mod.rs:968` | none | Ignored for matching, but the answer repeats the offer's fmtp line verbatim, unknown options included (same root cause as RFC7587-7.1-8) |
| FLEXFEC03-5.2.1-4 | 5.2.1 | MAY | Receiver removes FEC from the answer when not desired | untested | `media_engine.rs:886-960, 1178-1218` (a codec that is not registered is not answered) | none | |
| FLEXFEC03-5.2.2-1 | 5.2.2 | MUST | Declarative SDP: use the configuration provided | n/a | none | none | Offer/answer only |
| FLEXFEC03-6.2-1 | 6.2 | MUST | FEC bit string: P, X, CC, M, PT recovery are the XOR of the source headers; first two bits skipped | tested | `fec/draft03/encoder.rs:200-203` | `encoder.rs::recovery_fields_are_the_xor_of_the_protected_packets` | |
| FLEXFEC03-6.2-2 | 6.2 | MUST | Length recovery is the XOR of (packet length - 12): CSRC list, extension, payload and padding included | tested | `fec/draft03/encoder.rs:205-207` | `encoder.rs::recovery_fields_are_the_xor_of_the_protected_packets` | Tested only with packets that have no CSRC, extension or padding |
| FLEXFEC03-6.2-3 | 6.2 | MUST | TS recovery is the XOR of the source timestamps | tested | `fec/draft03/encoder.rs:212-214` | `encoder.rs::recovery_fields_are_the_xor_of_the_protected_packets` | |
| FLEXFEC03-6.2-4 | 6.2 (4.2) | MUST | SN base MUST be the lowest sequence number of the source packets this repair packet protects | violated | `fec/draft03/encoder.rs:139, 225` | `encoder.rs::the_declared_mask_matches_the_interleaved_coverage` (asserts masks `[1,3,5]` against the block base, i.e. the violation) | Every repair packet of a block carries the block's first sequence number, also when its own first protected packet is later (interleaved packet 2 of N). See Bug 3 |
| FLEXFEC03-6.2-5 | 6.2 | MUST | Repair payload is the XOR of everything after the 12-byte header; shorter packets padded with zero octets at the end | tested | `fec/draft03/encoder.rs:181-220` | `encoder.rs::the_repair_payload_is_the_xor_of_the_protected_payloads`, `the_repair_payload_is_as_long_as_the_largest_protected_packet` | |
| FLEXFEC03-6.2-6 | 6.2 | MUST | CSRC list, header extension and RTP padding of source packets are part of the protected data | untested | `fec/draft03/encoder.rs:193-196` (marshals the whole packet) | none | No FlexFEC test builds a source packet with a CSRC, an extension or padding |
| FLEXFEC03-6.2-7 | 6.2 | SHOULD | Repair packet (largest source + 20 to 32 bytes) should not exceed the path MTU | missing | `fec/draft03/encoder.rs:181-186` | none | Advisory text ("may cause problems"). A repair packet for a full-MTU source packet is always over the MTU |
| FLEXFEC03-6.3-1 | 6.3 | MUST | Whatever algorithm is used, the result is identical to the specified one | tested | `fec/draft03/decoder.rs:259-318` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically`, `one_repair_packet_covering_the_whole_block_recovers_any_single_loss` | |
| FLEXFEC03-6.3.1-1 | 6.3.1 | MUST | A repair packet with more than one missing source packet recovers nothing | tested | `fec/draft03/decoder.rs:241-246` | `it/flexfec_round_trip.rs::two_losses_under_one_repair_packet_recover_neither` | |
| FLEXFEC03-6.3.1.1-1 | 6.3.1.1 | MAY | Association signalled entirely in SDP (L, D, ToP) | missing | none | none | |
| FLEXFEC03-6.3.1.2-1 | 6.3.1.2 | MUST | Bitmask association over 15, 46 and 109 bit masks | tested | `fec/draft03/decoder.rs:346-407` | `it/flexfec_round_trip.rs::a_block_using_the_second_packet_mask_round_trips`, `a_block_using_the_third_packet_mask_round_trips`, `a_block_that_wraps_the_sequence_space_round_trips` | |
| FLEXFEC03-6.3.1.3-1 | 6.3.1.3 | MAY | Association by M and N offsets | missing | none | none | See FLEXFEC03-4.2-12 |
| FLEXFEC03-6.3.2-1 | 6.3.2 | MUST | Recovered header: version 2; M, PT, SN (= SEQNUM), TS from the recovered bit string | tested | `fec/draft03/decoder.rs:262-300` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically` | |
| FLEXFEC03-6.3.2-2 | 6.3.2 | MUST | Recovered header: P, X and CC from the recovered bit string | untested | `fec/draft03/decoder.rs:283-289` | none | No test loses a packet that has padding, an extension or CSRCs. Recovery of such a packet also depends on `rtp::Packet` re-marshalling received packets byte-identically |
| FLEXFEC03-6.3.2-3 | 6.3.2 | MUST | Recovered length Y is taken from the length recovery field | tested | `fec/draft03/decoder.rs:291-295` | `it/flexfec_round_trip.rs::packets_of_different_lengths_are_recovered_at_their_own_length`, `a_repair_packet_with_a_truncated_payload_recovers_nothing` | |
| FLEXFEC03-6.3.2-4 | 6.3.2 | MUST | SSRC of the recovered packet is the source stream's SSRC | tested | `fec/draft03/decoder.rs:297` | `it/flexfec_round_trip.rs::a_single_loss_is_recovered_byte_identically` | |
| FLEXFEC03-6.3.3-1 | 6.3.3 | MUST | Payload recovery: XOR Y octets from octet 13 of each received packet, shorter ones zero padded at the end | tested | `fec/draft03/decoder.rs:299-311` | `it/flexfec_round_trip.rs::packets_of_different_lengths_are_recovered_at_their_own_length` | |
| FLEXFEC03-6.3.4-1 | 6.3.4 | MUST | Iterative decoding: a recovered packet is fed back so other repair packets can complete | untested | `fec/draft03/decoder.rs:232-257` (loop) | none | No test where one recovery enables a second (2-D or staircase pattern) |
| FLEXFEC03-8-1 | 8 | SHOULD | Consider the impact of FEC in congested networks before injecting repair flows | n/a | none | none | Application decides to register the interceptor |
| FLEXFEC03-8-2 | 8 | MUST | MUST NOT arbitrarily increase the amount of FEC | untested | `fec/draft03/sender.rs:12-16, 89-108` (fixed ratio) | none | True by construction: the ratio never changes after build |
| FLEXFEC03-8-3 | 8 | SHOULD | Do not send repair flows when they would not help recover anything | missing | none | none | No loss feedback reaches the FEC sender |
| FLEXFEC03-8-4 | 8 | SHOULD | Adjust the amount of FEC dynamically from the observed loss rate | missing | `fec/draft03/sender.rs:89-108` | none | The ratio is fixed at build time; there is no runtime setter |
| FLEXFEC03-8-5 | 8 | SHOULD | Multicast: offer several repair flows with different protection | n/a | none | none | No multicast |
| FLEXFEC03-9-1 | 9 | SHOULD | Repair packets get the same confidentiality, integrity and source authentication as media (SRTP) | tested | chain write path to the SRTP handler | `tests/flexfec03_encoder_decoder.rs::flexfec03_recovers_every_dropped_packet` | End to end over DTLS-SRTP |

## Gaps, in order of importance

1. **FEC and transport-wide CC cannot be used together (S/M).** FLEXFEC03-4.1-1, Bugs 1, 4 and 5. Move the
   encoder wire-ward of everything that edits a media header (or stamp the transport-cc extension before
   the encoder and only rewrite its value in a way the receiver undoes), let repair packets be seen by the
   arrival recorders (TWCC, RFC 8888, receiver report) before the decoder swallows them, and have those
   recorders skip packets tagged `RecoveredByFec`.
2. **Wire-format corrections (S).** FLEXFEC03-4.2-19 (cap blocks at 109), FLEXFEC03-6.2-4 (per-packet SN
   base), FLEXFEC03-4.2-6 (timestamp from the send clock), FLEXFEC03-4.2-5 (random initial sequence
   number), FLEXFEC03-4.2-2 (assert marker = 0).
3. **Repair stream as an RTP source (M).** FLEXFEC03-4.2-8, FLEXFEC03-4.2-9: sender reports and SDES CNAME
   for the repair SSRC, reception reports for an inbound repair SSRC, SSRC collision handling.
4. **`repair-window` (M).** FLEXFEC03-5.1-3, FLEXFEC03-5.2.1-2: generate the parameter, parse the peer's,
   size the decoder's buffers from it instead of fixed packet counts, never send a block spanning more.
5. **Adaptive protection (M).** FLEXFEC03-8-3, FLEXFEC03-8-4: a runtime control (or a loss-driven
   controller fed from receiver reports) for the media/repair ratio, and an MTU check
   (FLEXFEC03-6.2-7) so a repair packet is not built larger than the path allows.
6. **Receive-side generality (M).** FLEXFEC03-4.2-16 (several SSRCs per repair packet), FLEXFEC03-4.2-12 /
   6.3.1.3-1 (F=1 offsets), FLEXFEC03-4.2-11 (R=1 retransmission), FLEXFEC03-5.1-4, 5.2.1-1, 6.3.1.1-1
   (L, D, ToP). libwebrtc sends none of these, so this is last.
7. **Tests for what is implemented but unproven (S).** FLEXFEC03-4.2-13, 4.2-15, 6.2-6, 6.3.2-2, 6.3.4-1,
   5.2.1-3: parse-error paths, sources with CSRC / extension / padding, cascading recovery.
8. **Answer fmtp (shared, M).** FLEXFEC03-5.2.1-3: the answer must be written from the local codec, not
   echo the offer; tracked as gap 1 of the RFC 7587 audit.

## Bugs found

1. **FEC is computed over a packet that is not the one sent, when a TWCC sender is in the chain.**
   `Slot::FecEncoder` is 5000 and `Slot::TwccSender` is 2000 (`rtc-interceptor/src/registry.rs:45,81`); the
   write walk runs high to low, so `FlexFec03SendInterceptor::handle_write` XORs the packet before
   `TwccSenderInterceptor::handle_write` (`twcc/sender.rs:112-126`) calls `set_extension`. When the
   application's packet has no extension block, that call adds one (the packet grows and X flips); when it
   has one, the 16-bit counter is rewritten. The receiver XORs the wire packets, so the recovered packet has
   the wrong length recovery and shifted, corrupt contents (or, same-size case, a corrupt extension value).
   Reproduction: build a chain with `Slot::FecEncoder` + `Slot::TwccSender` bound to one stream with the
   transport-cc extension, write 5 media packets, feed all outputs but one media packet to a
   `FlexFec03Decoder`, and compare the recovered bytes with the wire bytes of the dropped packet.
2. **A 110-packet block corrupts recovery.** `fec/coverage.rs:5` allows 110 media packets, but draft-03's
   third mask has 63 bits (indices 46..108). `BitArray::mask3_draft03` (`fec/bit_array.rs:68-70`) shifts
   index 109 out, while `ProtectionCoverage::covered_by` still returns it, so `encode_one` XORs packet 109
   into the repair data without naming it in the mask. Any recovery from that repair packet is the lost
   packet XOR packet 109. Reproduction: `FlexFec03Encoder::encode(&run(110), 1)`, drop media packet 0, decode
   the rest plus the repair packet, compare with the original (expect mismatch); also
   `parse_packet_mask` of the repair payload shows bit 109 unset.
3. **SN base is not the lowest protected sequence number.** `fec/draft03/encoder.rs:139,225`: with two
   repair packets over a block starting at 100, the second carries SN base 100 and a mask starting at bit 1.
   Interoperable (a decoder honours any base), but it violates the MUST and wastes mask range: an
   interleaved block reaches the second and third masks earlier than needed. Reproduction: the existing
   `the_declared_mask_matches_the_interleaved_coverage` already shows it; assert `payload[16..18]` of the
   second repair packet equals 101.
4. **Repair packets are never acknowledged to the sender's congestion controller.**
   `FlexFec03ReceiveInterceptor::handle_read` (`fec/draft03/receiver.rs:104-111`) swallows repair packets
   at slot 6000, before `TwccReceiver` (8000), `Rfc8888` (9000) and `ReceiverReport` (10000). The sending
   side numbers them (they pass `TwccSender`) and records them in its send history, then sees every one as
   lost. Reproduction: sender chain with FEC + TWCC + congestion control, receiver chain with FEC decoder +
   TWCC receiver; inspect the TWCC feedback: the repair packets' transport sequence numbers are reported
   not received.
5. **Recovered packets are reported as arrived.** `Attribute::RecoveredByFec` is attached
   (`fec/draft03/receiver.rs:191`) and documented as the way an arrival recorder tells "present" from
   "arrived" (`rtc-interceptor/src/packet.rs:61-67`), but nothing in `rtc-interceptor/src` reads it: the TWCC
   recorder, the RFC 8888 recorder and the receiver-report stream count a rebuilt packet as received at
   recovery time. Loss is hidden from the remote's congestion control and from `fraction lost`.
   Reproduction: receiver chain with FEC decoder + `ReceiverReportInterceptor`; drop one media packet that
   FEC recovers; the next RR reports 0 lost.
6. **Repair timestamp is media time, not send time** (`fec/draft03/encoder.rs:256-259`), FLEXFEC03-4.2-6.
   Reproduction: encode a block whose media timestamps are constant (one large frame); every repair packet
   of every such block within the frame carries the same timestamp regardless of when it is sent.

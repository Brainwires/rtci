# draft-holmer-rmcat-transport-wide-cc-extensions: RTP Extensions for Transport-wide Congestion Control

Spec: draft-holmer-rmcat-transport-wide-cc-extensions-01, 19 October 2015 (expired individual draft; the format
browsers ship). Audited against fork master 8916bc3. Sections done: 2.1, 2.2, 2.3, 3, 3.1, 3.1.1 to 3.1.5 (all of
the draft's technical text; 4 to 8 hold no requirement).

The draft uses almost no BCP 14 keywords. Each wire field, symbol and behavioural statement is a clause here; the
level is what the text implies ("must", "is", a format definition: MUST; "recommended", "should": SHOULD;
"acceptable": MAY).

Code: header extension `rtc-rtp/src/extension/transport_cc_extension/mod.rs`; feedback packet
`rtc-rtcp/src/transport_feedbacks/transport_layer_cc/mod.rs`; sender numbering `rtc-interceptor/src/twcc/sender.rs`;
receiver `rtc-interceptor/src/twcc/{receiver,recorder,arrival_time_map}.rs`; feedback consumers
`rtc-interceptor/src/rtpfb/{convert,history}.rs`, `rtc-interceptor/src/cc/interceptor.rs`,
`rtc-interceptor/src/gcc/twcc_gcc/mod.rs`.

**Since the audit** (the table and the totals are current; the gap and bug lists below are the audit's):
bugs T1, T2 and T5 (interceptor side) are fixed, each first reproduced by a failing test
(`rtx_and_fec_packets_are_numbered_and_recorded`,
`packets_of_a_lost_feedback_packet_are_not_reported_as_lost`,
`the_twcc_reference_time_wrap_does_not_send_arrivals_back_in_time`). T3, T4 and the codec half of
T5 are in `rtc-rtcp`; T6 is unchanged (libwebrtc behaviour, a decision).

Totals (MUST includes MUST NOT/SHALL; SHOULD includes SHOULD NOT/RECOMMENDED):

- MUST: tested 25 / untested 4 / partial 4 / missing 1 / violated 2 / n-a 0
- SHOULD: tested 1 / untested 0 / partial 2 / missing 0 / violated 0 / n-a 0
- MAY: tested 0 / untested 0 / partial 1 / missing 0 / violated 0 / n-a 0

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| TWCC-2.1-1 | 2.1 | MUST | One counter serves all packets sent over the same connection (BUNDLE transport), across streams | tested | `twcc/sender.rs:101-110` | `the_counter_is_shared_across_streams`, `test_twcc_sender_multiple_streams_share_counter` | |
| TWCC-2.2-1 | 2.2 | MUST | Extension payload is a 16-bit big-endian sequence number (one-byte form, L=1) | tested | `transport_cc_extension/mod.rs:33-62` | `test_transport_cc_extension`, `test_transport_cc_extension_too_small`, `test_twcc_sender_adds_sequence_numbers` | |
| TWCC-2.2-2 | 2.2 | MUST | The number is attached to all packets sent | tested | `twcc/sender.rs` `bind_local_stream` (`twcc/mod.rs` `flow_ssrcs`: media, RTX and FEC SSRC), `cc/interceptor.rs` `bind_local_stream` | `rtx_and_fec_packets_are_numbered_and_recorded`, `a_retransmission_is_recorded_as_a_separate_departure`, `a_lost_packet_is_recovered_as_it_was_sent_when_the_twcc_sender_rewrites_it` (repair packet numbered) | The RTX and FEC SSRCs of a stream are registered with its media SSRC, in the TWCC sender and in the send history. Streams without the extension negotiated are skipped by design |
| TWCC-2.2-3 | 2.2 | MUST | The number increases by 1 per packet sent on the socket, wrapping at 16 bits | tested | `twcc/sender.rs:105-106` | `a_bound_stream_is_numbered_consecutively`, `test_twcc_sender_sequence_wraparound` | Holds for the packets that are numbered (see 2.2-2) |
| TWCC-2.2-4 | 2.2 | MUST (implied) | A receiver reads the number from every packet carrying the negotiated extension, whatever its SSRC | tested | `twcc/receiver.rs:141-170` | `test_twcc_receiver_records_unbound_ssrcs`, `test_twcc_receiver_ignores_unbound_ssrcs_without_any_binding`, `handle_rtp_message_drops_rtx_probe_packet` | |
| TWCC-2.3-1 | 2.3 | MUST | Use is signalled with `a=extmap:<id> http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01` | tested | `twcc/mod.rs:15-22`, `interceptor_registry.rs:473-503` | `test_stream_supports_twcc`, `tests/extmap_renegotiation.rs` | |
| TWCC-2.3-2 | 2.3 | MUST (de facto) | Feedback is sent only when `a=rtcp-fb:<pt> transport-cc` is negotiated | partial | `twcc/receiver.rs:203-215` | `test_twcc_receiver_ignores_streams_without_twcc` | The receiver keys on the header extension alone; `transport-cc` in `info.rtcp_feedback` is not checked. Not in the draft text; libwebrtc requires both |
| TWCC-3-1 | 3 | MUST | The receiver records an arrival timestamp and the transport-wide number of each packet received | tested | `twcc/receiver.rs:156-168`, `twcc/recorder.rs:112-134` | `test_twcc_receiver_feedback_contains_packet_info`, `test_recorder_basic` | |
| TWCC-3-2 | 3 | MUST | The sender keeps a map of in-flight packets and looks up each one's send time on feedback | tested | `rtpfb/history.rs:38-112`, `cc/interceptor.rs:137-146` | `reports_carry_the_transport_wide_sequence_numbers`, `every_departing_packet_is_recorded_at_its_release_instant` | |
| TWCC-3-3 | 3 | MUST | Lost feedback: the packets it would have reported are ignored, not counted as lost or received | tested | `rtpfb/history.rs` `take_reports` (only packets a feedback described are reported; the rest are released without a verdict, counted by `unreported()`) | `packets_whose_feedback_was_lost_are_not_reported_as_lost`, `packets_of_a_lost_feedback_packet_are_not_reported_as_lost`, `a_stream_the_feedback_does_not_cover_is_not_counted_as_lost` | A packet is a loss only when a feedback reported it not received |
| TWCC-3-4 | 3 | SHOULD | A feedback message is sent for every frame received | partial | `twcc/receiver.rs:13` (fixed 100 ms), `:187-196` | `test_twcc_receiver_generates_feedback_on_timeout`, `test_twcc_receiver_configurable_interval` | Timer-driven only; not tied to frames |
| TWCC-3-5 | 3 | MAY | With low uplink bandwidth feedback may be sent less often, e.g. once per RTT | partial | `twcc/receiver.rs:28-31` (`with_interval`) | `test_twcc_receiver_configurable_interval` | Static configuration; no adaptation to RTT or RTCP bandwidth |
| TWCC-3.1-1 | 3.1 | MUST | Packet is RTPFB (PT 205) with FMT 15, V=2 | tested | `transport_layer_cc/mod.rs` `header()`, `unmarshal` type check | `test_transport_layer_cc_marshal`, `test_transport_layer_cc_unmarshal` | |
| TWCC-3.1-2 | 3.1 | MUST | P bit set when padding octets follow; they are counted in `length` and are not control information | partial | `transport_layer_cc/mod.rs` `header()` (`padding: get_padding_size(..) != 0`), `put_padding` | `test_transport_layer_cc_marshal` | Marshal is right. Unmarshal never reads the P bit or the padding count; trailing bytes are skipped whatever they are |
| TWCC-3.1-3 | 3.1 | MUST | "SSRC of packet sender" is the originator's SSRC | partial | `twcc/receiver.rs:150` (`Recorder::new(rand::random())`) | none on the value | A random SSRC unrelated to any stream or to the SSRC in this endpoint's RR/SDES |
| TWCC-3.1-4 | 3.1 | MUST | "SSRC of media source" is one of the media SSRCs the feedback relates to | untested | `twcc/recorder.rs:113` (last packet's SSRC) | none asserts `media_ssrc` | |
| TWCC-3.1-5 | 3.1 | MUST | Base sequence number is the transport-wide number of the first packet in the feedback | tested | `twcc/recorder.rs:192-195` | `test_recorder_basic`, `test_recorder_with_gaps`, `test_combined_twcc_sender_and_receiver` | |
| TWCC-3.1-6 | 3.1 | MUST | Packet status count is the number of packets described, from the base | tested | `twcc/recorder.rs:255` (`sequence_number_count`); consumers stop at it: `rtpfb/convert.rs:95-109`, `gcc/twcc_gcc/mod.rs` `packet_statuses` | `runs_are_cut_at_the_packet_status_count`, `a_zero_count_describes_no_packets`, `a_zero_count_has_no_loss` | |
| TWCC-3.1-7 | 3.1 | MUST | The parser stops at the status count: symbols of the last chunk beyond it describe nothing and own no delta | partial | `transport_layer_cc/mod.rs` unmarshal, status-vector branch (`delta_bytes_needed` and `recv_deltas.push` walk the whole `symbol_list`) | `a_run_claiming_more_deltas_than_the_packet_holds_is_refused` (run-length only) | Run-length chunks are cut at the count. A status vector's trailing symbols are not: a "received" symbol past the count consumes a delta byte and shifts every later delta |
| TWCC-3.1-8 | 3.1 | MUST | Reference time is a 24-bit signed value in multiples of 64 ms | tested | `rtpfb/convert.rs` `FeedbackTimeline::convert_twcc` (24-bit counter followed through its wrap, forwards and backwards), `cc/interceptor.rs` `ingest` | `the_twcc_reference_time_is_followed_through_its_wrap`, `a_reference_time_behind_the_last_one_steps_back`, `the_twcc_reference_time_wrap_does_not_send_arrivals_back_in_time`, `deltas_accumulate_from_the_reference_time` | The codec field stays `u32` holding the 24 bits (rtc-rtcp); only differences are used, so signed and unsigned readings agree once the wrap is followed. `gcc/twcc_gcc` (implementation B) still reads it raw |
| TWCC-3.1-9 | 3.1 | MUST | The first recv delta is relative to the reference time; each later one to the previous received packet | tested | `twcc/recorder.rs:240-245`, `:263-299`; `rtpfb/convert.rs:36-64` | `deltas_accumulate_from_the_reference_time`, `test_feedback_add_received` | |
| TWCC-3.1-10 | 3.1 | MUST | Feedback packet count increments by one per feedback packet sent | untested | `twcc/recorder.rs:189-190` | none asserts `fb_pkt_count` across two feedbacks | Wraps at 8 bits |
| TWCC-3.1-11 | 3.1 | SHOULD (implied) | The sender uses the feedback packet count to detect lost feedback | tested | `rtpfb/history.rs` `on_twcc_feedback_count`, `lost_feedback()`; `cc/interceptor.rs` `ingest`, `lost_feedback()` | `a_gap_in_the_feedback_packet_count_is_a_lost_feedback_packet` | Gaps in the count are counted (8-bit wrap, reordered feedback not counted). The count is a statistic: what makes lost feedback harmless is TWCC-3-3 |
| TWCC-3.1-12 | 3.1 | MUST | The packet is padded with zeros to a 32-bit boundary | tested | `transport_layer_cc/mod.rs` `marshal_size`, `put_padding` | `test_transport_layer_cc_marshal` | |
| TWCC-3.1-13 | 3.1 | MUST | A well-formed packet whose chunks end exactly at the packet end (no deltas) is accepted | violated | `transport_layer_cc/mod.rs` unmarshal: `if packet_status_pos + PACKET_STATUS_CHUNK_LENGTH >= total_length { return Err(PacketTooShort) }` | `deltas_that_fill_the_packet_exactly_are_accepted` covers deltas, not this | With an even number of chunks and no recv deltas the last chunk ends at `total_length` and `>=` rejects the packet (inherited from pion) |
| TWCC-3.1.1-1 | 3.1.1 | MUST | 2-bit status symbols: 00 not received, 01 small delta, 10 large or negative delta, 11 reserved | tested | `transport_layer_cc/mod.rs:31-38`, `:63-72` | `test_transport_layer_cc_run_length_chunk_unmarshal`, `test_transport_layer_cc_status_vector_chunk_unmarshal`, `a_status_vector_converts_symbol_by_symbol` | 11 is read as "received without delta" (the -00 meaning), which libwebrtc also accepts |
| TWCC-3.1.1-2 | 3.1.1 | SHOULD | "Not received" is not necessarily lost: it may yet arrive | partial | `rtpfb/history.rs:118-131` (a later feedback can still flip `arrived`), `:136-157` | `unacknowledged_packets_are_written_off_after_the_prune_horizon` | A not-received packet becomes a loss as soon as any later packet is acknowledged; a late arrival reported in the next feedback is then unknown to the history |
| TWCC-3.1.1-3 | 3.1.1 | MUST | A receive delta block is appended for each packet received within +/-8191.75 ms of the previous one | tested | `twcc/recorder.rs:263-299` | `test_feedback_add_received`, `test_twcc_receiver_feedback_contains_packet_info` | |
| TWCC-3.1.1-4 | 3.1.1 | MUST | When the base sequence number moves back, packets already reported as received are marked "not received", with no delta | violated | `twcc/recorder.rs:117-121` (a reordered packet lowers `start_sequence_number`), `:171-205` (every packet still in the arrival map is reported again with its delta) | none | Same behaviour as libwebrtc's `RemoteEstimatorProxy`, which re-reports them as received; it contradicts the draft text |
| TWCC-3.1.1-5 | 3.1.1 | MUST (implied) | Only the first arrival of a transport-wide sequence number is recorded | untested | `twcc/recorder.rs:123-125` | none | |
| TWCC-3.1.2-1 | 3.1.2 | MUST | Chunks are 16 bits; the first bit selects run length (0) or status vector (1) | tested | `transport_layer_cc/mod.rs` chunk marshal/unmarshal | `test_transport_layer_cc_run_length_chunk_marshal`, `test_transport_layer_cc_status_vector_chunk_marshal` | |
| TWCC-3.1.3-1 | 3.1.3 | MUST | Run length chunk: T=0, 2-bit symbol, 13-bit run length | tested | `transport_layer_cc/mod.rs:106-146`, `twcc/recorder.rs:344-351` (cap 0x1fff) | `test_transport_layer_cc_run_length_chunk_unmarshal`, `test_transport_layer_cc_run_length_chunk_marshal`, `test_chunk_run_length` | |
| TWCC-3.1.4-1 | 3.1.4 | MUST | Status vector chunk: T=1, S bit, then 14 one-bit symbols (S=0) or 7 two-bit symbols (S=1) | tested | `transport_layer_cc/mod.rs:155-216`, `twcc/recorder.rs:353-383` | `test_transport_layer_cc_status_vector_chunk_unmarshal`, `test_transport_layer_cc_status_vector_chunk_marshal`, `test_chunk_status_vector` | |
| TWCC-3.1.4-2 | 3.1.4 | MUST | One-bit symbols: 0 is "not received", 1 is "received" (small delta); the draft's parenthesis has them swapped, the example does not | tested | `transport_layer_cc/mod.rs:197-204` | `test_transport_layer_cc_status_vector_chunk_unmarshal` | Follows the example and libwebrtc |
| TWCC-3.1.5-1 | 3.1.5 | MUST | Deltas are multiples of 250 us | tested | `transport_layer_cc/mod.rs` `TYPE_TCC_DELTA_SCALE_FACTOR`, `twcc/recorder.rs:264-270` | `test_transport_layer_cc_recv_delta_unmarshal`, `test_transport_layer_cc_recv_delta_marshal` | |
| TWCC-3.1.5-2 | 3.1.5 | MUST | Small delta: 8-bit unsigned, 0 to 63.75 ms | tested | `transport_layer_cc/mod.rs` `RecvDelta`, `twcc/recorder.rs:284-286` | `test_transport_layer_cc_recv_delta_marshal`, `a_run_claiming_more_deltas_than_the_packet_holds_is_refused` | |
| TWCC-3.1.5-3 | 3.1.5 | MUST | Large or negative delta: 16-bit signed, -8192.0 to 8191.75 ms | tested | same, `twcc/recorder.rs:287-290` | `a_large_delta_run_needs_two_bytes_each`, `a_negative_delta_moves_the_arrival_backwards` | |
| TWCC-3.1.5-4 | 3.1.5 | MUST | A delta beyond the 16-bit range starts a new feedback message, whose reference time absorbs the gap | untested | `twcc/recorder.rs:271-274` (`add_received` returns false), `:185-187`, `:154-164` | none (no test has an arrival gap above 8.19 s) | |
| TWCC-3.1.5-5 | 3.1.5 | MUST (implied) | The sender reconstructs each arrival time from the reference time and the running deltas, negative ones included | tested | `rtpfb/convert.rs:36-64`, `gcc/twcc_gcc/mod.rs` `process_status` | `deltas_accumulate_from_the_reference_time`, `a_negative_delta_moves_the_arrival_backwards`, `more_received_packets_than_deltas_does_not_panic` | |
| TWCC-3.1.5-6 | 3.1.5 | MUST (implied) | A feedback packet stays within the path MTU; a longer window continues in the next packet | missing | `twcc/recorder.rs:238` (`len` is counted, never compared with a limit) | none | A long reporting window yields one arbitrarily large packet |

## Gaps, in order of importance

1. **Number and account for every packet on the transport (M).** TWCC-2.2-2. `TwccSenderInterceptor` and
   `CongestionControlInterceptor` must also register `info.ssrc_rtx` and `info.ssrc_fec`. Today RTX and FEC bytes are
   invisible to the receiver's feedback and to the send history, which is the under-count the responder's own comment
   warns about.
2. **Lost feedback is not loss (M).** TWCC-3-3, TWCC-3.1-11, TWCC-3.1.1-2. Track `fb_pkt_count`; in
   `History::take_reports` report only packets a feedback actually covered, and drop (not "lose") the ones in a hole.
3. **Parser edge cases (S).** TWCC-3.1-13 (`>=` to `>`), TWCC-3.1-7 (cut status vectors at the count), TWCC-3.1-2
   (honour the P bit), TWCC-3.1-8 (sign-extend and unwrap the reference time).
4. **Feedback size and pacing (M).** TWCC-3.1.5-6, TWCC-3-4, TWCC-3-5. Cap a feedback packet at an MTU budget; send on
   frame boundaries (marker bit) with the timer as a floor.
5. **Overlap rule (S, decision).** TWCC-3.1.1-4. Either follow the draft (mark re-covered packets not received) or
   record in `docs/conformance.md` that the engine follows libwebrtc here.
6. **Negotiation and identity (S).** TWCC-2.3-2 (require `transport-cc`), TWCC-3.1-3 (a real sender SSRC).
7. **Tests (S).** TWCC-3.1.1-5 (duplicates), TWCC-3.1.5-4 (delta overflow starts a new packet), TWCC-3.1-4
   (`media_ssrc`), TWCC-3.1-10 (`fb_pkt_count` increments).

## Bugs found

- **T1. RTX and FlexFEC packets carry no transport-wide sequence number and are missing from the send history.**
  `rtc-interceptor/src/twcc/sender.rs:102`, `:141-146`; `rtc-interceptor/src/cc/interceptor.rs:204`, `:240-244`.
  Reproduce: the chain of `a_retransmission_is_recorded_as_a_separate_departure` with `info.ssrc_rtx = Some(..)` and
  `payload_type_rtx = Some(..)`; the retransmission leaves on the RTX SSRC with no extension at the TWCC id and
  `outstanding()` does not grow.
- **T2. A lost feedback packet is counted as lost media.** `rtc-interceptor/src/rtpfb/history.rs:136-157`. Reproduce:
  send 20 packets, deliver TWCC feedback for packets 10 to 19 only; `take_reports` returns packets 0 to 9 with
  `arrived: false`, and `Gcc` sees 50% loss in that batch.
- **T3. A valid feedback packet with an even number of chunks and no deltas is rejected.**
  `rtc-rtcp/src/transport_feedbacks/transport_layer_cc/mod.rs` (the `>= total_length` check at the top of the chunk
  loop). Reproduce: marshal a `TransportLayerCc` with two run-length "not received" chunks, `packet_status_count`
  equal to their sum and no deltas (24 bytes), unmarshal it: `PacketTooShort`.
- **T4. Status-vector symbols past the packet status count consume deltas.** Same file, status-vector branch.
  Reproduce: `packet_status_count = 1`, one two-bit vector `[small, small, 0...]`, one delta byte: the parser wants two
  delta bytes and fails, or with a spare padding byte reads it as a second delta.
- **T5. Reference time is unsigned and never unwrapped.** `transport_layer_cc/mod.rs` (`get_24bits_from_bytes`),
  `rtpfb/convert.rs:36`. Reproduce: two feedbacks with reference times 0xFFFFFF and 0x000000 (64 ms apart): the
  second converts to an arrival 12.4 days earlier, and `Gcc` reads a huge negative gradient.
- **T6. Overlapping feedback re-reports received packets as received.** `twcc/recorder.rs:117-121`. Reproduce:
  record 1, 2, 4, build feedback, record 3, build again: the second feedback starts at 3 and reports 4 as received
  with a delta. Matches libwebrtc, contradicts 3.1.1 (see gap 5).

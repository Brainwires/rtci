# AOM "RTP Payload Format For AV1": clause audit

Spec: Alliance for Open Media, "RTP Payload Format For AV1", v1.0.0, Final Deliverable, 15 December
2024 (`https://aomediacodec.github.io/av1-rtp-spec/v1.0.0.html`). Audited against fork master 8916bc3.
Read-only audit; no test was run. Sections covered: 4 (payload format), 5 (packetization rules),
6 (MANE / SFM, simulcast, scalable constraints), 7 (parameters, SDP), 8 (FIR, LRR), 10 (security),
Appendix A (Dependency Descriptor header extension, A.3 to A.9). Sections 1 to 3, 5.1, 6.1.1, 7.3, 9, 11
and A.10 carry no normative keyword. MUST NOT / SHALL / REQUIRED count as MUST, RECOMMENDED / SHOULD NOT
as SHOULD, OPTIONAL as MAY.

- MUST: tested 59 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 12
- SHOULD: tested 13 / untested 0 / partial 1 / missing 0 / violated 0 / n-a 1
- MAY: tested 7 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 3

96 clauses (71 MUST, 15 SHOULD, 10 MAY), counted from the table.

What exists:

- **Sender**: `Av1Payloader` (`rtci-rtp/src/codec/av1/mod.rs:27`) parses one temporal unit in low
  overhead format (`obu.rs:43`), drops temporal delimiter, tile list and padding OBUs (`obu.rs:115`),
  clears `obu_has_size_field`, and aggregates / fragments OBUs greedily (`packetizer.rs:41`), a port of
  libwebrtc's `rtp_packetizer_av1.cc`. The aggregation header (Z, Y, W, N) is built in
  `packetizer.rs:182`. The generic `PacketizerImpl` (`rtci-rtp/src/packetizer/mod.rs:136`) sets the marker
  on the last payload of one `packetize` call and one timestamp for all of them. The engine itself never
  packetizes: an application calls these helpers and writes RTP packets.
- **Receiver**: `Av1Depacketizer` (`depacketizer.rs:51`) strips the aggregation header, reassembles a
  fragmented OBU across packets (bounded at 4 MiB), drops temporal delimiter and tile list OBUs and
  writes each OBU with an `obu_size` field (low overhead format, the form libaom and dav1d read). It
  does not put a temporal delimiter back; `IVFWriter` does (`rtci-media/src/io/ivf_writer/mod.rs:180`).
  `SampleBuilder` (`rtci-media/src/io/sample_builder/mod.rs:224`) groups packets by timestamp and marker
  and takes `Z == 0` on the first packet as the frame start.
- **SDP**: the default codec is `video/AV1`, 90000, `profile=0`, payload type 41 with RTX
  (`src/peer_connection/configuration/media_engine.rs:604-614`). There is no AV1 fmtp matcher: AV1 goes
  through the generic key/value matcher (`src/rtp_transceiver/fmtp/mod.rs:50-56`,
  `fmtp/generic/mod.rs:9-25`), which knows no parameter names and no defaults.
- **Not there**: the Dependency Descriptor (no parser, no writer, no URI constant; a grep for
  `dependency`, `descriptor` and the extmap URI over all `*.rs` finds only a comment in
  `tests/answer_preserves_extmap_allow_mixed.rs:11-13`), layer-aware packetization (SVC, "S" modes), the
  Layer Refresh Request. `docs/conformance.md:61` lists "SVC layer packetization for VP9 and AV1" as not
  implemented on purpose; those clauses are `missing` below and counted.

The engine is a transport with no encoder or decoder. Clauses that constrain the bitstream an encoder
produces, or what a decoder does, are `n-a` and say so.

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| AV1RTP-4.2-1 | 4.2 | MUST | Marker is 0 on every packet that is not the last of the temporal unit | tested | `rtci-rtp/src/packetizer/mod.rs:146` | `the_marker_is_on_the_last_packet_of_the_temporal_unit_only` | For one temporal unit per `packetize` call. A caller that packetizes each spatial layer's frame separately sets the marker itself (`Av1Payloader::payload_frames` gives a unit's packets by frame) |
| AV1RTP-4.2-2 | 4.2 | SHOULD | Marker is 1 on the last packet of the temporal unit | tested | `rtci-rtp/src/packetizer/mod.rs:146` | `the_marker_is_on_the_last_packet_of_the_temporal_unit_only` | Same caveat |
| AV1RTP-4.4-1 | 4.4 | MUST NOT | Aggregation header is not presented to the decoder | tested | `depacketizer.rs:78` | `depacketizer.rs::fragment_chain_reassembles`, `::test_depacketizer_basic` | Exact output bytes asserted |
| AV1RTP-4.4-2 | 4.4 | MUST | Z = 1 when the first OBU element continues a fragment from the previous packet | tested | `packetizer.rs:187-190` | `av1_test.rs::test_split_single_obu_into_two_packets`, `::test_split_single_obu_into_many_packets`, `::test_split_two_obus_into_two_packet_force_split_obu_header` | |
| AV1RTP-4.4-3 | 4.4 | MUST | Z = 0 otherwise | tested | `packetizer.rs:187-190` | same tests (first packets), `::test_packetize_one_obu_without_size_and_extension` | |
| AV1RTP-4.4-4 | 4.4 | MUST | Y = 1 when the last OBU element continues in the next packet | tested | `packetizer.rs:193-202` | `av1_test.rs::test_split_single_obu_into_many_packets`, `::test_split_two_obus_into_two_packets` | |
| AV1RTP-4.4-5 | 4.4 | MUST | Y = 0 otherwise | tested | `packetizer.rs:193-202` | same tests (last packets), `::test_omits_size_for_last_obu_when_three_obus_fits_into_the_packet` | |
| AV1RTP-4.4-6 | 4.4 | MUST | W is 0 or the number of OBU elements in the packet | tested | `packetizer.rs:205-207` | `test_omits_size_for_last_obu_when_three_obus_fits_into_the_packet`, `test_use_size_for_all_obus_when_four_obus_fits_into_the_packet`, `test_split_two_obus_into_two_packets`, `w_must_match_the_number_of_elements` | The receiver now refuses a packet with fewer elements than W (Bugs 5) |
| AV1RTP-4.4-7 | 4.4 | MUST | With W = 0 every OBU element is preceded by a length field (sender) | tested | `mod.rs:67-70`, `mod.rs:95-97` | `av1_test.rs::test_use_size_for_all_obus_when_four_obus_fits_into_the_packet` | |
| AV1RTP-4.4-8 | 4.4 | MUST NOT | With W = 1, 2 or 3 the last OBU element has no length field (sender) | tested | `mod.rs:95-97` | `av1_test.rs::test_omits_size_for_last_obu_when_three_obus_fits_into_the_packet`, `::test_discards_temporal_delimiter_and_tile_list_obu` | |
| AV1RTP-4.4-9 | 4.4 | MUST | Receiver reads a length field before every element when W = 0 | tested | `rtci-rtp/src/codec/av1/depacketizer.rs` `depacketize_payload` | `w_zero_reads_a_length_before_every_element`, `a_temporal_unit_round_trips_at_every_mtu` | Two elements under W = 0 with exact output, and a payloader-to-depacketizer round trip over MTUs 3 to 300 |
| AV1RTP-4.4-10 | 4.4 | MUST | Receiver derives the last element's length from the payload size when W is 1 to 3 | tested | `depacketizer.rs:98-101` | `test_depacketizer_basic`, `fragment_chain_reassembles`, `w_two_and_three_take_the_last_element_from_the_packet_size` | W = 1, 2 and 3 |
| AV1RTP-4.4-11 | 4.4 | MUST | N = 1 on the first packet of a coded video sequence | tested | `packetizer.rs:214-216`, `:225-263` | `test_sets_n_bit_at_the_first_packet_of_a_key_frame_with_sequence_header`, `a_reduced_still_picture_sets_n`, `a_sequence_header_starts_its_packet_and_goes_with_its_layer` | Reads `reduced_still_picture_header`, `show_existing_frame`, `frame_type`, `show_frame`, `temporal_id` (AV1 7.5); the reduced still picture branch is tested |
| AV1RTP-4.4-12 | 4.4 | MUST | N = 0 on every other packet | tested | `packetizer.rs:214-216` | `av1_test.rs::test_doesnt_set_n_bit_for_a_sequence_header_alone`, `::test_doesnt_set_n_bit_at_the_packets_of_a_key_frame_without_sequence_header`, `::test_doesnt_set_n_bit_at_the_packets_of_a_delta_frame`, `::test_doesnt_set_n_bit_for_a_key_frame_of_a_higher_temporal_layer` | The note "N = 1 implies Z = 0" holds by construction (packet 0 starts at offset 0) |
| AV1RTP-4.5-1 | 4.5 | MUST | OBU element length fields are leb128 (declarative format rule) | tested | `leb128.rs:46-56` (write), `:15-25` (read), `depacketizer.rs:249-261` | `put_leb128_128_is_two_bytes`, `put_leb128_matches_size_and_roundtrips`, `read_leb128_5_byte`, `read_leb128_refuses_what_is_not_a_value`, `an_element_length_of_two_to_the_32_is_refused`, `a_leb128_longer_than_eight_bytes_is_refused`, `an_unterminated_obu_size_is_refused` | At most 8 bytes and 32 bits, terminated (Bugs 1, 2 fixed) |
| AV1RTP-4.5-2 | 4.5 | MAY | Fragmentation occurs with any W value; receiver handles Z / Y under W = 0, 2, 3 | tested | `rtci-rtp/src/codec/av1/depacketizer.rs` `depacketize_payload` | `fragments_reassemble_under_every_w`, `a_temporal_unit_round_trips_at_every_mtu` | A fragment chain across W = 2, 0 and 2 |
| AV1RTP-4.5-3 | 4.5 | SHOULD | `obu_has_size_field` is 0 in all OBUs sent | tested | `obu.rs:68-84`, `mod.rs:72`, `mod.rs:99` | `av1_test.rs::removes_obu_size_field_without_extension`, `::removes_obu_size_field_with_extension` | The receiver also accepts OBUs that keep the field (`depacketizer.rs:179-199`, `::test_fragmented_obu_with_size_field`) |
| AV1RTP-5-1 | 5 | MUST NOT | A packet does not carry OBUs of different temporal units | tested | `rtci-rtp/src/codec/av1/obu.rs` `parse_obus` | `two_temporal_units_in_one_call_are_refused` | A second temporal delimiter in one call is an error |
| AV1RTP-5-2 | 5 | SHOULD | Temporal delimiter OBU is removed when transmitting | tested | `obu.rs:87`, `:115-119` | `av1_test.rs::test_discards_temporal_delimiter_and_tile_list_obu` | |
| AV1RTP-5-3 | 5 | MUST | Receivers ignore a temporal delimiter OBU | tested | `depacketizer.rs:162-168` | `depacketizer.rs::test_skip_temporal_delimiter` | |
| AV1RTP-5-4 | 5 | SHOULD | Tile list OBUs are removed when transmitted | tested | `obu.rs:115-119` | `av1_test.rs::test_discards_temporal_delimiter_and_tile_list_obu` | |
| AV1RTP-5-5 | 5 | MUST | Receivers ignore tile list OBUs | tested | `rtci-rtp/src/codec/av1/depacketizer.rs` `write_obu` | `tile_list_and_temporal_delimiter_obus_are_ignored` | No receive test carries a tile list OBU |
| AV1RTP-5-6 | 5 | MUST | In a sequence header, each `operating_point_idc[i]` contains `operating_point_idc[i+1]` | n-a | | | Encoder writes the sequence header. The payloader reads one bit of it (`packetizer.rs:231`) |
| AV1RTP-5-7 | 5 | MAY | Sender produces a sequence header with one operating point, idc 0xFFF, level 0 | n-a | | | Encoder writes the sequence header |
| AV1RTP-5-8 | 5 | MUST | OBUs with extension headers in one packet share the same `temporal_id` and `spatial_id` | tested | `rtci-rtp/src/codec/av1/packetizer.rs` `packetize` (`layer_boundary`) | `the_specifications_example_is_packetized_by_spatial_layer`, `no_packet_mixes_layers_at_any_mtu` | A packet ends where `temporal_id` / `spatial_id` change (Bugs 7 fixed). The grouping of the specification's example 5.1 is reproduced |
| AV1RTP-5-9 | 5 | SHOULD | A sequence header OBU is the first OBU in its packet | tested | `rtci-rtp/src/codec/av1/packetizer.rs` `packetize` (`layer_boundary`) | `a_sequence_header_starts_its_packet_and_goes_with_its_layer` | A sequence header anywhere in the unit starts a packet |
| AV1RTP-5-10 | 5 | SHOULD | OBUs without an extension header are at the beginning of a packet, after the sequence header | tested | `rtci-rtp/src/codec/av1/packetizer.rs` `packetize` (`layer_boundary`) | `an_obu_of_no_layer_after_layered_ones_starts_a_packet` | An OBU without an extension header after layered ones starts the next packet |
| AV1RTP-5-11 | 5 | SHOULD | Sequence header is aggregated with the base layer when scalable encoding is used | tested | `rtci-rtp/src/codec/av1/packetizer.rs` `packetize` | `the_specifications_example_is_packetized_by_spatial_layer`, `a_sequence_header_starts_its_packet_and_goes_with_its_layer` | The sequence header is in the base layer's first packet |
| AV1RTP-5-12 | 5 | SHOULD | In an "S" mode a sequence header is aggregated with each spatial layer | tested | `rtci-rtp/src/codec/av1/mod.rs` `Av1Payloader::sequence_header_per_spatial_layer`, `repeat_sequence_header` | `the_sequence_header_can_be_repeated_for_every_spatial_layer`, `a_sequence_header_starts_its_packet_and_goes_with_its_layer` | An encoder's per-layer sequence headers stay with their layers; with the option on (off by default) the payloader repeats the unit's sequence header for layers that have none |
| AV1RTP-6-1 | 6 | MUST | A packet is associated with the layer of its OBU extension header, or with all operating points (declarative, for forwarding) | n-a | | | Endpoint, not SFU |
| AV1RTP-6.1-1 | 6.1 | MUST | Simulcast conveys only encodings of the same source | n-a | | | Application chooses track sources |
| AV1RTP-6.1-2 | 6.1 | SHOULD | In either simulcast mode a sequence header is aggregated with each spatial layer | tested | `rtci-rtp/src/codec/av1/mod.rs` `Av1Payloader::sequence_header_per_spatial_layer` | `the_sequence_header_can_be_repeated_for_every_spatial_layer` | Single-stream "S" mode: as AV1RTP-5-12. RID simulcast: each encoding has its own payloader and its sequence header passes through |
| AV1RTP-6.2-1 | 6.2 | MUST | `obu_extension_flag` is 0 in a sequence header OBU of a scalable stream | n-a | | | Encoder sets OBU headers. The payloader copies headers unchanged and does not check |
| AV1RTP-6.2-2 | 6.2 | MUST | `obu_extension_flag` is 1 in frame, frame header, redundant frame header and tile group OBUs of a scalable stream | n-a | | | Encoder sets OBU headers |
| AV1RTP-6.2-3 | 6.2 | MUST | `obu_extension_flag` is 0 in a scalability metadata OBU | n-a | | | Encoder sets OBU headers |
| AV1RTP-6.2-4 | 6.2 | MAY | `obu_extension_flag` may be 1 in a padding OBU | n-a | | | Encoder sets OBU headers. The payloader drops padding OBUs (`obu.rs:118`) |
| AV1RTP-7.2-1 | 7.2 | MUST | An absent `profile` is inferred to be 0 | tested | `src/rtp_transceiver/fmtp/av1/mod.rs` (`Av1Fmtp::profile`, `match_fmtp`) | `fmtp/av1/av1_test.rs::an_av1_format_is_its_profile_with_the_absent_parameters_inferred`, `tests/jsep_codec_parameters.rs::av1_formats_match_by_profile_and_the_answer_declares_its_own_parameters` | The profile is the format: an absent one is 0, another profile does not match |
| AV1RTP-7.2-2 | 7.2 | MUST | An absent `level-idx` is inferred to be 5 | tested | `src/rtp_transceiver/fmtp/av1/mod.rs` (`Av1Fmtp::level_idx`) | `fmtp/av1/av1_test.rs::an_av1_format_is_its_profile_with_the_absent_parameters_inferred` | Read as 5 when absent; not part of the format (section 7.2.3) |
| AV1RTP-7.2-3 | 7.2 | MUST | An absent `tier` is inferred to be 0 | tested | `src/rtp_transceiver/fmtp/av1/mod.rs` (`Av1Fmtp::tier`) | `fmtp/av1/av1_test.rs::an_av1_format_is_its_profile_with_the_absent_parameters_inferred` | Read as 0 when absent; not part of the format |
| AV1RTP-7.2.1-1 | 7.2.1 | MUST | The media name in the `m=` line is `video` | tested | `media_engine.rs:146`, `:632` | `the_default_video_formats_are_video_at_90_khz` | `tests/jsep_av1_fmtp.rs` finds the AV1 rtpmap but never looks at the `m=` line |
| AV1RTP-7.2.1-2 | 7.2.1 | MUST | The rtpmap encoding name is `AV1` | tested | `media_engine.rs:146`, `:606` | `tests/jsep_av1_fmtp.rs::the_default_av1_codec_offers_profile_not_profile_id` | Fails ("the default codecs offer AV1") if no `AV1/` rtpmap is offered |
| AV1RTP-7.2.1-3 | 7.2.1 | MUST | The rtpmap clock rate is 90000 | tested | `media_engine.rs:607` | `tests/jsep_codec_parameters.rs::av1_formats_match_by_profile_and_the_answer_declares_its_own_parameters` | The answered rtpmap is `AV1/90000` |
| AV1RTP-7.2.1-4 | 7.2.1 | MAY | `profile`, `level-idx`, `tier` appear in `a=fmtp` as semicolon-separated pairs | tested | `media_engine.rs:611` | `tests/jsep_av1_fmtp.rs::the_default_av1_codec_offers_profile_not_profile_id` | Default offers `profile=0` only; an application may register a codec with the others |
| AV1RTP-7.2.1-5 | 7.2.1 | MUST | Receiver ignores fmtp parameters this spec does not define | tested | `fmtp/mod.rs:37-57`, `fmtp/generic/mod.rs:9-25` | `fmtp/generic/generic_test.rs::test_generic_fmtp_compare` ("OneHasExtraParam") | Generic rule: a key only one side has never fails the match. An unknown key both sides carry with different values does fail the exact match, then falls back to a MIME-only match (`rtp_codec.rs:179-188`) |
| AV1RTP-7.2.2-1 | 7.2.2 | MUST | RID restrictions (`max-width`, `max-height`, `max-fps`, `max-fs`, `max-br`, `max-pps`, `max-bpp`) take the AV1 meanings | n-a | `src/peer_connection/sdp/mod.rs:1314-1319` | | Encoder applies restrictions. The engine keeps the restriction text as an opaque string (`SimulcastRid.params`) and interprets none |
| AV1RTP-7.2.2-2 | 7.2.2 | MUST | With negotiated restrictions the stream has an operating point within them | n-a | | | Encoder's bitstream |
| AV1RTP-7.2.3-1 | 7.2.3 | MAY | The answerer declares its own profile / level / tier (parameters are asymmetric) | tested | `media_engine.rs` `local_fmtp_line` (an exact AV1 match answers with the local fmtp) | `tests/jsep_codec_parameters.rs::av1_formats_match_by_profile_and_the_answer_declares_its_own_parameters` | The answer states this endpoint's own fmtp, not the offer's `level-idx` / `tier` |
| AV1RTP-7.2.3-2 | 7.2.3 | MUST | The stream sent stays within the profile, level and tier the receiving agent declared | n-a | | | Encoder's job; application reads the fmtp |
| AV1RTP-7.2.4-1 | 7.2.4 | MUST | Declarative SDP (RTSP, SAP): a receiver that cannot support the declared values rejects or stays out | n-a | | | RTSP and SAP, not WebRTC |
| AV1RTP-8.1-1 | 8.1 | MUST | On FIR the sender starts a new coded video sequence for each SSRC named, as soon as possible | tested | `src/peer_connection/handler/endpoint.rs` (`handle_rtcp_message`: by the FCI's SSRCs), `rtci-interceptor/src/keyframe.rs` (`drop_repeated_firs`) | `a_fir_reaches_only_the_senders_its_fci_names`, `a_fir_for_two_senders_reaches_both`, `a_repeated_fir_is_delivered_once`, `pli_and_fir_reach_the_application` | The engine's part, as for RFC5104-4.3.1.2-3: a FIR reaches the encoder (the application's) of each local sender its FCI names and of no other, once per command sequence number; starting the coded video sequence is the encoder's. `ccm fir` is offered for AV1 (`media_engine.rs:407`). media-21: the FCI routing test, checked to fail with the FIR routed by its media SSRC field |
| AV1RTP-8.1-2 | 8.1 | MAY | Sender also starts new coded video sequences on the other simulcast encodings | n-a | | | Application drives the encoders |
| AV1RTP-8.2-1 | 8.2 | MUST | Layer Refresh Requests use the VP9 LRR format with the SID high bit 0 | tested | `rtci-rtcp/src/payload_feedbacks/layer_refresh_request.rs` (`LrrEntry::av1`, `LrrEntry::vp9`) | `an_av1_layer_refresh_request_uses_the_vp9_format_with_a_two_bit_sid` | The VP9 layout with the SID's high bit 0. `ccm lrr` is not offered by default (JSEP) |
| AV1RTP-10-1 | 10 | SHOULD | Data origin authentication and integrity protection of the RTP packet (for example SRTP) | tested | `rtci-srtp/src/context/srtp.rs` | `rtci-srtp/src/context/srtp_test.rs::test_rtp_invalid_auth` | Always SRTP in WebRTC; clause detail in `rfc3711.md` |
| AV1RTP-10-2 | 10 | SHOULD | Header extensions such as the Dependency Descriptor are encrypted (RFC 6904 or a successor) | partial | `src/peer_connection/cryptex.rs` | | RFC 6904 is not implemented (`rfc6904.md`); Cryptex (RFC 9335) is, and covers any header extension when negotiated (`rfc9335.md` for its tested status). No Dependency Descriptor exists to protect |
| AV1RTP-10-3 | 10 | MUST | Decoders discard reserved OBU types and reserved metadata OBU types | n-a | | | Decoder's job. The depacketizer passes reserved types through (`depacketizer.rs:159-168`) |
| AV1RTP-10-4 | 10 | SHOULD | Temporal delimiter and tile list OBUs carried in the RTP payload are filtered out | tested | `depacketizer.rs:162-168` | `test_skip_temporal_delimiter`, `tile_list_and_temporal_delimiter_obus_are_ignored` | Both halves tested |
| AV1RTP-10-5 | 10 | SHOULD NOT | Middle boxes do not parse OBUs they do not support | n-a | | | Endpoint, not SFU |
| AV1RTP-A-1 | A.1, 4.3 | MAY | Dependency Descriptor RTP header extension, as a feature: parse on receive, write on send | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `the_l1t3_example_structure_is_written_bit_for_bit`, `the_l3t3_example_structure_is_written_bit_for_bit`, `every_mode_is_carried_by_the_dependency_descriptor` | `DependencyDescriptor` (marshal / unmarshal), `DependencyDescriptorWriter`, `DependencyDescriptorReader`. The application sets the bytes with `Header::set_extension`; the engine does not attach or negotiate it by itself (AV1RTP-A.9-1) |
| AV1RTP-A.3-1 | A.3 | MUST | A frame whose Referred frames are all decodable is itself decodable | n-a | | | Encoder's bitstream |
| AV1RTP-A.4-1 | A.4 | MUST | Sender signals the new set of active Decode targets whenever it changes | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `set_active_decode_targets` | `a_change_of_active_decode_targets_is_signalled_until_acknowledged`, `active_decode_targets_hold_until_the_next_update` |  |
| AV1RTP-A.4-2 | A.4 | SHOULD | Updates are signalled so that after loss a receiver knows the new set or sees a Chain break | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` | `a_change_of_active_decode_targets_is_signalled_until_acknowledged` | The bitmask is on every packet until acknowledged or until a key frame with all targets active |
| AV1RTP-A.5-1 | A.5 | MUST | Chains are built so a receiver holding every Chain frame resumes full fidelity without NACK or FIR | tested | `rtci-rtp/src/codec/svc/mod.rs` `ScalabilityPattern::next_picture` | `the_indications_and_chains_of_every_mode_hold` | For the structures the engine generates (every scalability mode): a chain's frames depend on chain frames only. An application's own structure is written as given |
| AV1RTP-A.5-2 | A.5 | MUST | Chains that protect no active Decode target are ignored | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` `chain_has_active_decode_target`, `rtci-rtp/src/codec/dependency_descriptor/selector.rs` | `a_chain_without_an_active_decode_target_is_ignored`, `the_chain_example_tells_a_needed_loss_from_a_harmless_one` |  |
| AV1RTP-A.7-1 | A.7 | MAY | An SFM starts forwarding a new Decode target at a decodable frame with a Switch indication | tested | `rtci-rtp/src/codec/dependency_descriptor/selector.rs` `DecodeTargetSelector::forward` | `the_upswitch_example_switches_at_the_frame_with_the_switch_indication`, `the_upswitch_example_switches_at_frame_106_the_other_way`, `no_switch_happens_without_a_switch_indication_or_an_intact_chain` | Forwarder-side helper for an SFU built on the engine |
| AV1RTP-A.7-2 | A.7 | MAY | An SFM switches to a Decode target at any point while its Chain is intact | tested | `rtci-rtp/src/codec/dependency_descriptor/selector.rs` `DecodeTargetSelector::forward` | `a_receiver_switched_between_layers_only_gets_decodable_frames`, `every_mode_is_carried_by_the_dependency_descriptor` | A switch is also taken at a frame of the wanted target when every frame of its chain was forwarded to the receiver |
| AV1RTP-A.8.3-1 | A.8.3 | MUST | `start_of_frame` is 1 when the packet's first payload byte begins a new frame | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position` | The caller says which packet is the frame's first and last; `Av1Payloader::payload_frames` groups a temporal unit's packets by frame |
| AV1RTP-A.8.3-2 | A.8.3 | MUST | `start_of_frame` is 0 otherwise | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position` | The caller says which packet is the frame's first and last; `Av1Payloader::payload_frames` groups a temporal unit's packets by frame |
| AV1RTP-A.8.3-3 | A.8.3 | MUST | `end_of_frame` is 1 on the final packet of a frame | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position` | The caller says which packet is the frame's first and last; `Av1Payloader::payload_frames` groups a temporal unit's packets by frame |
| AV1RTP-A.8.3-4 | A.8.3 | MUST | `end_of_frame` is 0 otherwise | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position` | The caller says which packet is the frame's first and last; `Av1Payloader::payload_frames` groups a temporal unit's packets by frame |
| AV1RTP-A.8.3-5 | A.8.3 | MAY | `frame_number` starts at a random value | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `DependencyDescriptorWriter::new` | `frame_numbers_count_up_from_the_start_and_wrap` | The application passes the first number |
| AV1RTP-A.8.3-6 | A.8.3 | MUST | `frame_number` (16 bits, increasing in decode order) wraps after its maximum | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `next_frame` | `frame_numbers_count_up_from_the_start_and_wrap`, `frame_differences_round_trip_at_their_limits_and_wrap` |  |
| AV1RTP-A.8.3-7 | A.8.3 | MUST | All packets of one frame carry the same `frame_number` | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position` |  |
| AV1RTP-A.8.3-8 | A.8.3 | MUST | `frame_dependency_template_id` lies in `template_id_offset` to `template_id_offset + TemplateCnt - 1` | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` `marshal`, `unmarshal` | `a_descriptor_without_its_structure_is_not_interpreted` | Writing an id outside the range is refused; reading one returns `Ok(None)`, "structure not known" |
| AV1RTP-A.8.3-9 | A.8.3 | MUST | `frame_dependency_template_id` is the same on all packets of one frame | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position` |  |
| AV1RTP-A.8.3-10 | A.8.3 | MUST | `zero_padding` is written as 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` `marshal` | `custom_indications_chains_and_the_bitmask_are_written_bit_for_bit`, `zero_padding_is_ignored_on_receipt` |  |
| AV1RTP-A.8.3-11 | A.8.3 | MUST | Receivers ignore `zero_padding` | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` `unmarshal` | `zero_padding_is_ignored_on_receipt` |  |
| AV1RTP-A.8.3-12 | A.8.3 | MUST | `template_dependency_structure` is present when its flag is 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `the_l1t3_example_structure_is_written_bit_for_bit`, `the_l3t3_example_structure_is_written_bit_for_bit` |  |
| AV1RTP-A.8.3-13 | A.8.3 | MUST NOT | `template_dependency_structure` is absent when its flag is 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `a_frame_that_follows_a_template_is_three_bytes`, `every_packet_of_a_frame_has_its_number_template_and_position` |  |
| AV1RTP-A.8.3-14 | A.8.3 | MUST | `template_dependency_structure_present_flag` is 1 on the first packet of a coded video sequence | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `next_frame`, `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position`, `the_structure_goes_out_with_a_coded_video_sequence` |  |
| AV1RTP-A.8.3-15 | A.8.3 | MUST | `template_dependency_structure_present_flag` is 0 on every other packet | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `FrameDescriptor::packet` | `every_packet_of_a_frame_has_its_number_template_and_position`, `the_structure_goes_out_with_a_coded_video_sequence` |  |
| AV1RTP-A.8.3-16 | A.8.3 | MUST | `active_decode_targets_bitmask` is present when its flag is 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `custom_indications_chains_and_the_bitmask_are_written_bit_for_bit`, `active_decode_targets_hold_until_the_next_update` |  |
| AV1RTP-A.8.3-17 | A.8.3 | MUST NOT | `active_decode_targets_bitmask` is absent when its flag is 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `a_frame_that_follows_a_template_is_three_bytes`, `active_decode_targets_hold_until_the_next_update` |  |
| AV1RTP-A.8.3-18 | A.8.3 | MUST | `frame_dtis` is present when `custom_dtis_flag` is 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `custom_indications_chains_and_the_bitmask_are_written_bit_for_bit`, `a_frame_off_the_pattern_gets_the_cheapest_template_and_custom_fields` |  |
| AV1RTP-A.8.3-19 | A.8.3 | MUST NOT | `frame_dtis` is absent when `custom_dtis_flag` is 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `a_frame_that_follows_a_template_is_three_bytes`, `custom_frame_differences_are_written_bit_for_bit` |  |
| AV1RTP-A.8.3-20 | A.8.3 | MUST | `frame_fdiffs` is present when `custom_fdiffs_flag` is 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `custom_frame_differences_are_written_bit_for_bit`, `the_dynamic_prediction_example_uses_custom_differences` |  |
| AV1RTP-A.8.3-21 | A.8.3 | MUST NOT | `frame_fdiffs` is absent when `custom_fdiffs_flag` is 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `a_frame_that_follows_a_template_is_three_bytes`, `custom_indications_chains_and_the_bitmask_are_written_bit_for_bit` |  |
| AV1RTP-A.8.3-22 | A.8.3 | MUST | `frame_chain_fdiff` is present when `custom_chains_flag` is 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `custom_indications_chains_and_the_bitmask_are_written_bit_for_bit`, `the_dynamic_prediction_example_uses_custom_differences` |  |
| AV1RTP-A.8.3-23 | A.8.3 | MUST NOT | `frame_chain_fdiff` is absent when `custom_chains_flag` is 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `a_frame_that_follows_a_template_is_three_bytes`, `custom_frame_differences_are_written_bit_for_bit` |  |
| AV1RTP-A.8.3-24 | A.8.3 | SHOULD | A new structure's template id range does not overlap the existing structure's range | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` `next_template_id_offset` | `a_new_structure_takes_new_template_ids` | The application picks the offset; `next_template_id_offset` gives one that does not overlap |
| AV1RTP-A.8.3-25 | A.8.3 | MUST | A new structure with the same `template_id_offset` has identical values in every field | tested | `rtci-rtp/src/codec/dependency_descriptor/writer.rs` `set_structure` | `a_new_structure_takes_new_template_ids` | Refused on the send side. A receiver takes the newer structure |
| AV1RTP-A.8.3-26 | A.8.3 | MUST | `render_resolutions` is present when `resolutions_present_flag` is 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `template_id_offset_and_resolutions_are_written_bit_for_bit`, `the_l3t3_example_structure_is_written_bit_for_bit` |  |
| AV1RTP-A.8.3-27 | A.8.3 | MUST NOT | `render_resolutions` is absent when `resolutions_present_flag` is 0 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `the_l1t3_example_structure_is_written_bit_for_bit` |  |
| AV1RTP-A.8.3-28 | A.8.3 | MUST | With `chain_cnt > 0` every Decode target is protected by exactly one Chain | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` `FrameDependencyStructure::validate` | `a_structure_the_syntax_cannot_carry_does_not_validate` |  |
| AV1RTP-A.8.3-29 | A.8.3 | MUST | `fdiff_minus_one` immediately follows `fdiff_follows_flag` = 1 | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `the_l1t3_example_structure_is_written_bit_for_bit`, `the_l3t3_example_structure_is_written_bit_for_bit` |  |
| AV1RTP-A.8.3-30 | A.8.3 | MUST | `fdiff_minus_one` immediately follows a non-zero `next_fdiff_size` | tested | `rtci-rtp/src/codec/dependency_descriptor/mod.rs` | `custom_frame_differences_are_written_bit_for_bit`, `frame_differences_round_trip_at_their_limits_and_wrap` |  |
| AV1RTP-A.9-1 | A.9 | MUST | The extmap URI is `https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension` | tested | `rtci-rtp/src/codec/dependency_descriptor`, `configuration/interceptor_registry.rs` (`configure_default_header_extensions`) | `the_dependency_descriptor_is_offered_for_video` | Registered for video by default |

Non-normative text checked (not counted):

- 4.2 note, "a receiver should be able to handle" a last packet without the marker, by the next
  packet's timestamp: `SampleBuilder` does (`sample_builder/mod.rs:270-274`); `IVFWriter` does not, it
  closes a frame on the marker only (`ivf_writer/mod.rs:173`).
- 4.1: one RTP timestamp for all packets of a temporal unit: `rtci-rtp/src/packetizer/mod.rs:149`, `:157`.
  The spec has no normative timestamp sentence beyond the 90000 clock rate.
- The spec has no MTU rule. Each payload, aggregation header included, stays within the `mtu` passed
  (`packetizer.rs:54`; `av1_test.rs::test_split_single_obu_into_many_packets` asserts 100-byte payloads).
  An `mtu` under 3 returns no packets and no error (`packetizer.rs:47`), so the frame is dropped silently.
- A.4 "an update is valid until the next update", A.6 `PartOfActiveChain`, A.8.2 syntax: all part of
  the missing Dependency Descriptor work.

## Status after the AV1 work (branch `conf/vpx-av1-svc-1`)

Gaps 1, 2 and 5 below are closed, and the marker and temporal unit tests of gap 7; Bugs 1, 2, 3
(as far as the payload tells: a unit that starts at a later frame header still looks like a
start), 5, 6 and 7 are fixed, and the latent branch is removed. Still open: gap 3 (AV1 fmtp:
AV1RTP-7.2-1 to 7.2-3, 7.2.3-1, Bug 8), gap 4 (LRR: 8.2-1), gap 6 for `IVFWriter` (Bug 4),
registering the Dependency Descriptor URI (A.9-1), the SDP tests of gap 7 (7.2.1-1, 7.2.1-3), gaps
8 and 9.

## Gaps, in order of importance

1. **Dependency Descriptor header extension (L).** AV1RTP-A-1, A.4-1, A.4-2, A.5-1, A.5-2, A.8.3-1
   to A.8.3-30, A.9-1. A bit reader and writer for the A.8.2 syntax (mandatory fields, template
   dependency structure, active decode targets bitmask, custom dtis / fdiffs / chains), the derived
   values (template spatial and temporal ids, decode target layers), the URI constant and an opt-in
   registration, a send-side API that takes the structure and per-frame data from the application's
   encoder, and receive-side state (structure by `template_id_offset`, active targets until the next
   update). Tests from the A.10 examples. Without it a receiver has no reliable frame start (Bugs 3)
   and an SFU peer cannot forward this endpoint's SVC or end-to-end encrypted streams.
2. **Layer-aware packetization (M).** AV1RTP-5-8, 5-10, 5-12, 6.1-2, 5-9, 5-11, and the marker caveat
   of 4.2-1. Start a new packet when `temporal_id` / `spatial_id` changes, keep extension-less OBUs and
   the sequence header at the head of a packet, repeat the sequence header per spatial layer in "S"
   modes, and keep the marker on the last packet of the temporal unit. Until then the payloader should
   at least refuse (or split) a temporal unit that mixes layers rather than emit packets that break 5-8.
3. **AV1 fmtp matcher and asymmetric answer (M).** AV1RTP-7.2-1, 7.2-2, 7.2-3, 7.2.3-1, plus tests for
   7.2.1-1 and 7.2.1-3. An `Av1Fmtp` beside `H264Fmtp` (`src/rtp_transceiver/fmtp/mod.rs:50`): compare
   `profile` with the default 0, treat `level-idx` (default 5) and `tier` (default 0) as receive
   capabilities that never fail a match, and answer with the local values instead of the offerer's.
4. **Layer Refresh Request (M).** AV1RTP-8.2-1. The LRR RTCP feedback packet (PSFB FMT 10), the AV1 / VP9
   layer id layout, `ccm lrr` negotiation, delivery to the application like PLI and FIR.
5. **Receive-side tests and input hardening (S).** AV1RTP-4.4-9, 4.5-2, 5-5, 10-4, 4.4-10 (W = 2, 3),
   4.4-11 (reduced still picture), Bugs 1, 2, 5. A payloader-to-depacketizer round trip test over
   several MTUs, multi-element W = 0, tile list on receive, leb128 limits (8 bytes, value below 2^32,
   terminated), W checked against the element count.
6. **Loss-safe reassembly outside `SampleBuilder` (M).** Bugs 3, 4. Give the depacketizer (or its
   callers) sequence continuity so a fragment chain with a hole is dropped, and a better frame start
   than `Z == 0` (previous packet's marker or a timestamp change; the Dependency Descriptor's
   `start_of_frame` when present).
7. **Marker and SDP tests for AV1 (S).** AV1RTP-4.2-1, 4.2-2, 5-1, 7.2.1-1, 7.2.1-3. A multi-packet AV1
   `packetize` test asserting the marker only on the last packet; an offer test asserting `m=video` and
   `AV1/90000`.
8. **FIR handling detail (S).** AV1RTP-8.1-1: filter by FCI SSRC and drop repeated sequence numbers
   before delivery (same work package as `rfc5104.md`).
9. **Header extension encryption (S, decision).** AV1RTP-10-2: record that Cryptex is the chosen
   mechanism and RFC 6904 is not implemented on purpose.

## Bugs found

All found by reading; none was run.

1. **Unterminated OBU size accepted by the payloader's parser.** `rtci-rtp/src/codec/av1/leb128.rs:24`
   returns `(0, 0)` when no byte ends the leb128, and `rtci-rtp/src/codec/av1/obu.rs:74-83` does not check
   for a zero length the way the depacketizer does (`depacketizer.rs:90`, `:183`). Reproduction:
   `Av1Payloader::default().payload(1200, &Bytes::from_static(&[0x32, 0x80]))`. Expected an error;
   by reading it returns `Ok` with one packet `[0x20, 0x01, 0x30, 0x80]`: an empty frame OBU and the
   size byte re-read as an OBU header of reserved type 0 with the forbidden bit set.
2. **leb128 values of 2^32 and more are truncated, and more than 8 bytes are accepted.**
   `rtci-rtp/src/codec/av1/leb128.rs:9` (`b as u32`) and `:22` (`encoded <<= 8` drops the first bytes
   after eight). AV1 4.10.5 limits leb128 to 8 bytes and a value of at most 2^32 - 1. Reproduction on the
   receiver: `Av1Depacketizer::new().depacketize(&Bytes::from_static(&[0x00, 0x80, 0x80, 0x80, 0x80,
   0x10, 0x02, 0x30, 0x01]))`. The first element declares 2^32 bytes; expected `ErrShortPacket`; by
   reading the length becomes 0, the element is skipped and the call returns `Ok([0x32, 0x01, 0x01])`.
   The same truncation applies to `obu_size` in `obu.rs:74` and `depacketizer.rs:182`.
3. **A packet with Z = 0 in the middle of a temporal unit is taken as its start.**
   `rtci-rtp/src/codec/av1/depacketizer.rs:235-240` with
   `rtci-media/src/io/sample_builder/mod.rs:306`. Z = 0 only says the first element is not a
   continuation; a unit whose packets each hold whole OBUs has Z = 0 on all of them. Reproduction:
   `SampleBuilder::new(2, Av1Depacketizer::new(), 90000)`; push a complete earlier sample, then of a
   three-packet unit with one timestamp, seq 10 `[0x10, 0x18, 0x10]` (frame header), seq 11
   `[0x10, 0x20, 0xAA]` (tile group), seq 12 with marker `[0x10, 0x20, 0xBB]`, push only 11 and 12,
   then enough later packets to pass `max_late`. Expected: the unit is dropped. By reading
   (`mod.rs:165-196`, `:264-268`, `:306`): a sample with the two tile groups and no frame header is
   emitted, flagged only by `prev_dropped_packets`.
4. **A fragment chain with a lost middle packet is spliced, not dropped.**
   `rtci-rtp/src/codec/av1/depacketizer.rs:108-134`: the depacketizer has no sequence number, so
   continuity is the caller's job. `SampleBuilder` gives it contiguous packets and each sample starts
   with Z = 0, which clears the buffer (`depacketizer.rs:73-75`), so that path is safe.
   `rtci-media/src/io/ivf_writer/mod.rs:151-189` is not: it calls `depacketize` on every packet in
   arrival order. Reproduction: `IVFWriter` with `AV01`, `write_rtp` seq 1 `[0x50, 0x30, 0x01, 0x02]`
   (Y = 1), skip seq 2 `[0xd0, 0x03]`, `write_rtp` seq 3 with marker `[0x90, 0x05]`. Expected: no frame.
   By reading: a frame holding OBU `[0x32, 0x03, 0x01, 0x02, 0x05]` is written. The same writer closes a
   frame on the marker only (`:173`), so a unit whose last packet lacks the marker is merged with the
   next one (4.2 note). The AV1 path of `IVFWriter` has no test.
5. **W is not checked against the element count on receive.**
   `rtci-rtp/src/codec/av1/depacketizer.rs:227`: the check compares the index after the loop, which is
   also `W - 1` when one element is missing. Reproduction:
   `depacketize(&Bytes::from_static(&[0x20, 0x02, 0x30, 0x01]))` (W = 2, one element with a length
   field, nothing after it). Expected an error (or a documented zero-length last element); by reading it
   returns `Ok([0x32, 0x01, 0x01])`. Low severity.
6. **An OBU that exactly fills the packet is fragmented.** `rtci-rtp/src/codec/av1/packetizer.rs:94`
   uses `<` where `<=` fits. Reproduction: `payload(8, ...)` of one frame OBU without size field and 6
   payload bytes (OBU size 7, room for 7). Expected one packet `[0x10, 0x30, 1, 2, 3, 4, 5, 6]`; by
   reading two packets, `[0x50, 0x30, 1, 2, 3, 4, 5]` and `[0x90, 6]`. Conformant, wasteful: an extra
   packet for every OBU or tail that lands on the boundary.
7. **Layers are mixed in one packet.** `rtci-rtp/src/codec/av1/packetizer.rs:62-101` (AV1RTP-5-8).
   Reproduction: `payload(1200, ...)` of two frame OBUs with extension headers `0x00` (spatial 0) and
   `0x08` (spatial 1) and a few payload bytes each. Expected two packets; by reading one packet with
   W = 2 holding both. Known gap (`docs/conformance.md:61`), listed because the output is silently
   non-conformant rather than refused.
8. **An AV1 offer with a different `profile` is still accepted, and the answer repeats the offerer's
   fmtp.** `src/rtp_transceiver/rtp_sender/rtp_codec.rs:179-188` (MIME-only fallback) with
   `src/rtp_transceiver/internal.rs:387`, `:421-422`. Reproduction: default `MediaEngine`
   (`profile=0`), remote offer whose only video codec is `a=rtpmap:45 AV1/90000` with
   `a=fmtp:45 profile=1;level-idx=8;tier=1`. Expected: AV1 rejected, or answered with the local
   `profile=0`. By reading, not confirmed by a run: the answer accepts AV1 and carries
   `profile=1;level-idx=8;tier=1`, declaring a receive capability the application never registered.
   The fallback is shared by every codec without a dedicated matcher.

Latent, not reachable today: `rtci-rtp/src/codec/av1/packetizer.rs:149-167` builds a "semi-last" packet
without setting `num_obu_elements`, which would underflow at `packetizer.rs:199` and `mod.rs:67`. The
loop at `packetizer.rs:134` guarantees `last_fragment_size <= max_payload_size`, so the branch is dead
(the libwebrtc original reaches it through `last_packet_reduction_len`, which this port does not have).
Remove it or fix it before adding a last-packet size reduction.

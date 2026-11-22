# AOM "RTP Payload Format For AV1": clause audit

Spec: Alliance for Open Media, "RTP Payload Format For AV1", v1.0.0, Final Deliverable, 15 December
2024 (`https://aomediacodec.github.io/av1-rtp-spec/v1.0.0.html`). Audited against fork master 8916bc3.
Read-only audit; no test was run. Sections covered: 4 (payload format), 5 (packetization rules),
6 (MANE / SFM, simulcast, scalable constraints), 7 (parameters, SDP), 8 (FIR, LRR), 10 (security),
Appendix A (Dependency Descriptor header extension, A.3 to A.9). Sections 1 to 3, 5.1, 6.1.1, 7.3, 9, 11
and A.10 carry no normative keyword. MUST NOT / SHALL / REQUIRED count as MUST, RECOMMENDED / SHOULD NOT
as SHOULD, OPTIONAL as MAY.

- MUST: tested 15 / untested 6 / partial 1 / missing 37 / violated 0 / n-a 12
- SHOULD: tested 4 / untested 2 / partial 4 / missing 4 / violated 0 / n-a 1
- MAY: tested 1 / untested 1 / partial 0 / missing 3 / violated 0 / n-a 5

96 clauses (71 MUST, 15 SHOULD, 10 MAY), counted from the table.

What exists:

- **Sender**: `Av1Payloader` (`rtc-rtp/src/codec/av1/mod.rs:27`) parses one temporal unit in low
  overhead format (`obu.rs:43`), drops temporal delimiter, tile list and padding OBUs (`obu.rs:115`),
  clears `obu_has_size_field`, and aggregates / fragments OBUs greedily (`packetizer.rs:41`), a port of
  libwebrtc's `rtp_packetizer_av1.cc`. The aggregation header (Z, Y, W, N) is built in
  `packetizer.rs:182`. The generic `PacketizerImpl` (`rtc-rtp/src/packetizer/mod.rs:136`) sets the marker
  on the last payload of one `packetize` call and one timestamp for all of them. The engine itself never
  packetizes: an application calls these helpers and writes RTP packets.
- **Receiver**: `Av1Depacketizer` (`depacketizer.rs:51`) strips the aggregation header, reassembles a
  fragmented OBU across packets (bounded at 4 MiB), drops temporal delimiter and tile list OBUs and
  writes each OBU with an `obu_size` field (low overhead format, the form libaom and dav1d read). It
  does not put a temporal delimiter back; `IVFWriter` does (`rtc-media/src/io/ivf_writer/mod.rs:180`).
  `SampleBuilder` (`rtc-media/src/io/sample_builder/mod.rs:224`) groups packets by timestamp and marker
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
| AV1RTP-4.2-1 | 4.2 | MUST | Marker is 0 on every packet that is not the last of the temporal unit | untested | `rtc-rtp/src/packetizer/mod.rs:146` | | Shared line, never asserted for AV1 or for any multi-packet frame in `rtc-rtp`; the only assertion is an H.264 fixture test (`tests/testenv_media_fixtures.rs::multi_slice_h264_arrives_as_whole_access_units`). Holds only if the application passes one whole temporal unit per `packetize` call; a caller that packetizes each spatial layer's frame separately gets a marker per frame |
| AV1RTP-4.2-2 | 4.2 | SHOULD | Marker is 1 on the last packet of the temporal unit | untested | `rtc-rtp/src/packetizer/mod.rs:146` | | Same line, same caveat |
| AV1RTP-4.4-1 | 4.4 | MUST NOT | Aggregation header is not presented to the decoder | tested | `depacketizer.rs:78` | `depacketizer.rs::fragment_chain_reassembles`, `::test_depacketizer_basic` | Exact output bytes asserted |
| AV1RTP-4.4-2 | 4.4 | MUST | Z = 1 when the first OBU element continues a fragment from the previous packet | tested | `packetizer.rs:187-190` | `av1_test.rs::test_split_single_obu_into_two_packets`, `::test_split_single_obu_into_many_packets`, `::test_split_two_obus_into_two_packet_force_split_obu_header` | |
| AV1RTP-4.4-3 | 4.4 | MUST | Z = 0 otherwise | tested | `packetizer.rs:187-190` | same tests (first packets), `::test_packetize_one_obu_without_size_and_extension` | |
| AV1RTP-4.4-4 | 4.4 | MUST | Y = 1 when the last OBU element continues in the next packet | tested | `packetizer.rs:193-202` | `av1_test.rs::test_split_single_obu_into_many_packets`, `::test_split_two_obus_into_two_packets` | |
| AV1RTP-4.4-5 | 4.4 | MUST | Y = 0 otherwise | tested | `packetizer.rs:193-202` | same tests (last packets), `::test_omits_size_for_last_obu_when_three_obus_fits_into_the_packet` | |
| AV1RTP-4.4-6 | 4.4 | MUST | W is 0 or the number of OBU elements in the packet | tested | `packetizer.rs:205-207` | `av1_test.rs::test_omits_size_for_last_obu_when_three_obus_fits_into_the_packet` (W=3), `::test_use_size_for_all_obus_when_four_obus_fits_into_the_packet` (W=0), `::test_split_two_obus_into_two_packets` (W=2) | Sender. The receiver accepts W=2 with one element (see Bugs 5) |
| AV1RTP-4.4-7 | 4.4 | MUST | With W = 0 every OBU element is preceded by a length field (sender) | tested | `mod.rs:67-70`, `mod.rs:95-97` | `av1_test.rs::test_use_size_for_all_obus_when_four_obus_fits_into_the_packet` | |
| AV1RTP-4.4-8 | 4.4 | MUST NOT | With W = 1, 2 or 3 the last OBU element has no length field (sender) | tested | `mod.rs:95-97` | `av1_test.rs::test_omits_size_for_last_obu_when_three_obus_fits_into_the_packet`, `::test_discards_temporal_delimiter_and_tile_list_obu` | |
| AV1RTP-4.4-9 | 4.4 | MUST | Receiver reads a length field before every element when W = 0 | untested | `depacketizer.rs:86-97` | | `depacketizer.rs::test_depacketizer_with_w_zero` is hollow: it asserts only a non-empty result with the size bit set, which also holds if the length byte were taken for an OBU header (0x04 has no size bit, so one is added). No test with two or more elements under W = 0, and no payloader-to-depacketizer round trip test |
| AV1RTP-4.4-10 | 4.4 | MUST | Receiver derives the last element's length from the payload size when W is 1 to 3 | tested | `depacketizer.rs:98-101` | `depacketizer.rs::test_depacketizer_basic`, `::fragment_chain_reassembles` | W = 1 only. W = 2 and W = 3 on receive (length fields then a bare last element) have no test |
| AV1RTP-4.4-11 | 4.4 | MUST | N = 1 on the first packet of a coded video sequence | tested | `packetizer.rs:214-216`, `:225-263` | `av1_test.rs::test_sets_n_bit_at_the_first_packet_of_a_key_frame_with_sequence_header` | Reads `reduced_still_picture_header`, `show_existing_frame`, `frame_type`, `show_frame`, `temporal_id` (AV1 7.5). The reduced still picture branch (`:246-250`) has no test |
| AV1RTP-4.4-12 | 4.4 | MUST | N = 0 on every other packet | tested | `packetizer.rs:214-216` | `av1_test.rs::test_doesnt_set_n_bit_for_a_sequence_header_alone`, `::test_doesnt_set_n_bit_at_the_packets_of_a_key_frame_without_sequence_header`, `::test_doesnt_set_n_bit_at_the_packets_of_a_delta_frame`, `::test_doesnt_set_n_bit_for_a_key_frame_of_a_higher_temporal_layer` | The note "N = 1 implies Z = 0" holds by construction (packet 0 starts at offset 0) |
| AV1RTP-4.5-1 | 4.5 | MUST | OBU element length fields are leb128 (declarative format rule) | tested | `leb128.rs:46-56` (write), `:15-25` (read), `depacketizer.rs:249-261` | `av1_test.rs::put_leb128_128_is_two_bytes`, `::put_leb128_matches_size_and_roundtrips`, `::read_leb128_5_byte`, `depacketizer.rs::test_write_leb128` | Reader accepts values of 2^32 and more (truncated) and more than 8 bytes; the payloader's OBU parser accepts an unterminated one. Bugs 1, 2 |
| AV1RTP-4.5-2 | 4.5 | MAY | Fragmentation occurs with any W value; receiver handles Z / Y under W = 0, 2, 3 | untested | `depacketizer.rs:96-97`, `:108-147` | | Lowercase "may" in the spec; listed as a feature. Only W = 1 fragments are tested. The sender fragments with W = 2 (`av1_test.rs::test_split_two_obus_into_two_packets`) |
| AV1RTP-4.5-3 | 4.5 | SHOULD | `obu_has_size_field` is 0 in all OBUs sent | tested | `obu.rs:68-84`, `mod.rs:72`, `mod.rs:99` | `av1_test.rs::removes_obu_size_field_without_extension`, `::removes_obu_size_field_with_extension` | The receiver also accepts OBUs that keep the field (`depacketizer.rs:179-199`, `::test_fragmented_obu_with_size_field`) |
| AV1RTP-5-1 | 5 | MUST NOT | A packet does not carry OBUs of different temporal units | untested | `mod.rs:27-122` | | By API shape: one `payload` call packetizes one buffer and never carries state to the next. Nothing checks the buffer holds one temporal unit: two units in one call have their delimiters dropped (`obu.rs:115`) and are aggregated together |
| AV1RTP-5-2 | 5 | SHOULD | Temporal delimiter OBU is removed when transmitting | tested | `obu.rs:87`, `:115-119` | `av1_test.rs::test_discards_temporal_delimiter_and_tile_list_obu` | |
| AV1RTP-5-3 | 5 | MUST | Receivers ignore a temporal delimiter OBU | tested | `depacketizer.rs:162-168` | `depacketizer.rs::test_skip_temporal_delimiter` | |
| AV1RTP-5-4 | 5 | SHOULD | Tile list OBUs are removed when transmitted | tested | `obu.rs:115-119` | `av1_test.rs::test_discards_temporal_delimiter_and_tile_list_obu` | |
| AV1RTP-5-5 | 5 | MUST | Receivers ignore tile list OBUs | untested | `depacketizer.rs:162-168` | | No receive test carries a tile list OBU |
| AV1RTP-5-6 | 5 | MUST | In a sequence header, each `operating_point_idc[i]` contains `operating_point_idc[i+1]` | n-a | | | Encoder writes the sequence header. The payloader reads one bit of it (`packetizer.rs:231`) |
| AV1RTP-5-7 | 5 | MAY | Sender produces a sequence header with one operating point, idc 0xFFF, level 0 | n-a | | | Encoder writes the sequence header |
| AV1RTP-5-8 | 5 | MUST | OBUs with extension headers in one packet share the same `temporal_id` and `spatial_id` | missing | `packetizer.rs:62-101` | | Aggregation is greedy and never looks at the extension header. A temporal unit with two spatial layers is packed across the layer boundary, so the output breaks this rule (Bugs 7). Single-layer streams are unaffected. In `docs/conformance.md:61` |
| AV1RTP-5-9 | 5 | SHOULD | A sequence header OBU is the first OBU in its packet | partial | `packetizer.rs:62-101` | | Input order is kept and an encoder puts the sequence header first in the unit, so it leads packet 0. A sequence header later in the buffer does not start a new packet |
| AV1RTP-5-10 | 5 | SHOULD | OBUs without an extension header are at the beginning of a packet, after the sequence header | missing | | | No layer awareness; order is the encoder's. Vacuous for single-layer streams |
| AV1RTP-5-11 | 5 | SHOULD | Sequence header is aggregated with the base layer when scalable encoding is used | partial | `packetizer.rs:70-101` | | Greedy aggregation puts the sequence header in the same packet as the OBUs that follow (`av1_test.rs::test_split_two_obus_into_two_packets` shows it for one layer). No scalable input is tested and nothing guarantees it |
| AV1RTP-5-12 | 5 | SHOULD | In an "S" mode a sequence header is aggregated with each spatial layer | missing | | | Would need the sequence header repeated per layer and layer-bounded packets; neither exists |
| AV1RTP-6-1 | 6 | MUST | A packet is associated with the layer of its OBU extension header, or with all operating points (declarative, for forwarding) | n-a | | | Endpoint, not SFU |
| AV1RTP-6.1-1 | 6.1 | MUST | Simulcast conveys only encodings of the same source | n-a | | | Application chooses track sources |
| AV1RTP-6.1-2 | 6.1 | SHOULD | In either simulcast mode a sequence header is aggregated with each spatial layer | partial | `mod.rs:49-53` | | RID simulcast: each encoding is its own bitstream and payloader, its sequence header passes through; no AV1 simulcast test. Single-stream "S" mode: missing (AV1RTP-5-12) |
| AV1RTP-6.2-1 | 6.2 | MUST | `obu_extension_flag` is 0 in a sequence header OBU of a scalable stream | n-a | | | Encoder sets OBU headers. The payloader copies headers unchanged and does not check |
| AV1RTP-6.2-2 | 6.2 | MUST | `obu_extension_flag` is 1 in frame, frame header, redundant frame header and tile group OBUs of a scalable stream | n-a | | | Encoder sets OBU headers |
| AV1RTP-6.2-3 | 6.2 | MUST | `obu_extension_flag` is 0 in a scalability metadata OBU | n-a | | | Encoder sets OBU headers |
| AV1RTP-6.2-4 | 6.2 | MAY | `obu_extension_flag` may be 1 in a padding OBU | n-a | | | Encoder sets OBU headers. The payloader drops padding OBUs (`obu.rs:118`) |
| AV1RTP-7.2-1 | 7.2 | MUST | An absent `profile` is inferred to be 0 | missing | `src/rtp_transceiver/fmtp/generic/mod.rs:9-25` | | No code names the parameter. An absent key matches any value, so a local `profile=1` codec is an exact match for a remote AV1 with no `profile`. With the default `profile=0` the outcome happens to be right |
| AV1RTP-7.2-2 | 7.2 | MUST | An absent `level-idx` is inferred to be 5 | missing | | | Not interpreted anywhere; the raw fmtp string is handed to the application |
| AV1RTP-7.2-3 | 7.2 | MUST | An absent `tier` is inferred to be 0 | missing | | | As above |
| AV1RTP-7.2.1-1 | 7.2.1 | MUST | The media name in the `m=` line is `video` | untested | `media_engine.rs:146`, `:632` | | `tests/jsep_av1_fmtp.rs` finds the AV1 rtpmap but never looks at the `m=` line |
| AV1RTP-7.2.1-2 | 7.2.1 | MUST | The rtpmap encoding name is `AV1` | tested | `media_engine.rs:146`, `:606` | `tests/jsep_av1_fmtp.rs::the_default_av1_codec_offers_profile_not_profile_id` | Fails ("the default codecs offer AV1") if no `AV1/` rtpmap is offered |
| AV1RTP-7.2.1-3 | 7.2.1 | MUST | The rtpmap clock rate is 90000 | untested | `media_engine.rs:607` | | No test contains `AV1/90000`; the test above stops at `AV1/` |
| AV1RTP-7.2.1-4 | 7.2.1 | MAY | `profile`, `level-idx`, `tier` appear in `a=fmtp` as semicolon-separated pairs | tested | `media_engine.rs:611` | `tests/jsep_av1_fmtp.rs::the_default_av1_codec_offers_profile_not_profile_id` | Default offers `profile=0` only; an application may register a codec with the others |
| AV1RTP-7.2.1-5 | 7.2.1 | MUST | Receiver ignores fmtp parameters this spec does not define | tested | `fmtp/mod.rs:37-57`, `fmtp/generic/mod.rs:9-25` | `fmtp/generic/generic_test.rs::test_generic_fmtp_compare` ("OneHasExtraParam") | Generic rule: a key only one side has never fails the match. An unknown key both sides carry with different values does fail the exact match, then falls back to a MIME-only match (`rtp_codec.rs:179-188`) |
| AV1RTP-7.2.2-1 | 7.2.2 | MUST | RID restrictions (`max-width`, `max-height`, `max-fps`, `max-fs`, `max-br`, `max-pps`, `max-bpp`) take the AV1 meanings | n-a | `src/peer_connection/sdp/mod.rs:1314-1319` | | Encoder applies restrictions. The engine keeps the restriction text as an opaque string (`SimulcastRid.params`) and interprets none |
| AV1RTP-7.2.2-2 | 7.2.2 | MUST | With negotiated restrictions the stream has an operating point within them | n-a | | | Encoder's bitstream |
| AV1RTP-7.2.3-1 | 7.2.3 | MAY | The answerer declares its own profile / level / tier (parameters are asymmetric) | missing | `src/rtp_transceiver/internal.rs:377-387`, `:421-422` | | By reading: the answer's codec entry is the remote codec cloned with the local payload type, so the answer repeats the offerer's fmtp instead of the local one. See Bugs 8 |
| AV1RTP-7.2.3-2 | 7.2.3 | MUST | The stream sent stays within the profile, level and tier the receiving agent declared | n-a | | | Encoder's job; application reads the fmtp |
| AV1RTP-7.2.4-1 | 7.2.4 | MUST | Declarative SDP (RTSP, SAP): a receiver that cannot support the declared values rejects or stays out | n-a | | | RTSP and SAP, not WebRTC |
| AV1RTP-8.1-1 | 8.1 | MUST | On FIR the sender starts a new coded video sequence for each SSRC named, as soon as possible | partial | `rtc-interceptor/src/keyframe.rs:58-64` | `keyframe.rs::pli_and_fir_reach_the_application` | The engine's part, handing the FIR to the application that owns the encoder, is done and tested. It does not filter by the FCI's SSRC or drop repeats (see `rfc5104.md`, RFC5104-4.3.1.2-3). `ccm fir` is offered for AV1 (`media_engine.rs:407`) |
| AV1RTP-8.1-2 | 8.1 | MAY | Sender also starts new coded video sequences on the other simulcast encodings | n-a | | | Application drives the encoders |
| AV1RTP-8.2-1 | 8.2 | MUST | Layer Refresh Requests use the VP9 LRR format with the SID high bit 0 | missing | | | No LRR packet type in `rtc-rtcp` (the only `LRR` in the tree is the DLRR "last RR" field), no `ccm lrr` feedback |
| AV1RTP-10-1 | 10 | SHOULD | Data origin authentication and integrity protection of the RTP packet (for example SRTP) | tested | `rtc-srtp/src/context/srtp.rs` | `rtc-srtp/src/context/srtp_test.rs::test_rtp_invalid_auth` | Always SRTP in WebRTC; clause detail in `rfc3711.md` |
| AV1RTP-10-2 | 10 | SHOULD | Header extensions such as the Dependency Descriptor are encrypted (RFC 6904 or a successor) | partial | `src/peer_connection/cryptex.rs` | | RFC 6904 is not implemented (`rfc6904.md`); Cryptex (RFC 9335) is, and covers any header extension when negotiated (`rfc9335.md` for its tested status). No Dependency Descriptor exists to protect |
| AV1RTP-10-3 | 10 | MUST | Decoders discard reserved OBU types and reserved metadata OBU types | n-a | | | Decoder's job. The depacketizer passes reserved types through (`depacketizer.rs:159-168`) |
| AV1RTP-10-4 | 10 | SHOULD | Temporal delimiter and tile list OBUs carried in the RTP payload are filtered out | untested | `depacketizer.rs:162-168` | `depacketizer.rs::test_skip_temporal_delimiter` | Addressed to decoders; the depacketizer does it. The temporal delimiter half is tested, the tile list half is not, so the clause as a whole is not rounded up |
| AV1RTP-10-5 | 10 | SHOULD NOT | Middle boxes do not parse OBUs they do not support | n-a | | | Endpoint, not SFU |
| AV1RTP-A-1 | A.1, 4.3 | MAY | Dependency Descriptor RTP header extension, as a feature: parse on receive, write on send | missing | | | Nothing in the tree. An application can still register the URI as an opaque extension and set raw bytes on its own packets; two-byte headers for the long template packets depend on `a=extmap-allow-mixed` (`tests/answer_preserves_extmap_allow_mixed.rs`) |
| AV1RTP-A.3-1 | A.3 | MUST | A frame whose Referred frames are all decodable is itself decodable | n-a | | | Encoder's bitstream |
| AV1RTP-A.4-1 | A.4 | MUST | Sender signals the new set of active Decode targets whenever it changes | missing | | | No Dependency Descriptor writer |
| AV1RTP-A.4-2 | A.4 | SHOULD | Updates are signalled so that after loss a receiver knows the new set or sees a Chain break | missing | | | No Dependency Descriptor writer |
| AV1RTP-A.5-1 | A.5 | MUST | Chains are built so a receiver holding every Chain frame resumes full fidelity without NACK or FIR | missing | | | No Dependency Descriptor writer; the structure itself comes from the encoder |
| AV1RTP-A.5-2 | A.5 | MUST | Chains that protect no active Decode target are ignored | missing | | | No Dependency Descriptor reader |
| AV1RTP-A.7-1 | A.7 | MAY | An SFM starts forwarding a new Decode target at a decodable frame with a Switch indication | n-a | | | Endpoint, not SFU |
| AV1RTP-A.7-2 | A.7 | MAY | An SFM switches to a Decode target at any point while its Chain is intact | n-a | | | Endpoint, not SFU |
| AV1RTP-A.8.3-1 | A.8.3 | MUST | `start_of_frame` is 1 when the packet's first payload byte begins a new frame | missing | | | No Dependency Descriptor |
| AV1RTP-A.8.3-2 | A.8.3 | MUST | `start_of_frame` is 0 otherwise | missing | | | |
| AV1RTP-A.8.3-3 | A.8.3 | MUST | `end_of_frame` is 1 on the final packet of a frame | missing | | | |
| AV1RTP-A.8.3-4 | A.8.3 | MUST | `end_of_frame` is 0 otherwise | missing | | | |
| AV1RTP-A.8.3-5 | A.8.3 | MAY | `frame_number` starts at a random value | missing | | | |
| AV1RTP-A.8.3-6 | A.8.3 | MUST | `frame_number` (16 bits, increasing in decode order) wraps after its maximum | missing | | | |
| AV1RTP-A.8.3-7 | A.8.3 | MUST | All packets of one frame carry the same `frame_number` | missing | | | |
| AV1RTP-A.8.3-8 | A.8.3 | MUST | `frame_dependency_template_id` lies in `template_id_offset` to `template_id_offset + TemplateCnt - 1` | missing | | | A reader also has to treat an out-of-range id as a lost structure, per the note |
| AV1RTP-A.8.3-9 | A.8.3 | MUST | `frame_dependency_template_id` is the same on all packets of one frame | missing | | | |
| AV1RTP-A.8.3-10 | A.8.3 | MUST | `zero_padding` is written as 0 | missing | | | |
| AV1RTP-A.8.3-11 | A.8.3 | MUST | Receivers ignore `zero_padding` | missing | | | |
| AV1RTP-A.8.3-12 | A.8.3 | MUST | `template_dependency_structure` is present when its flag is 1 | missing | | | |
| AV1RTP-A.8.3-13 | A.8.3 | MUST NOT | `template_dependency_structure` is absent when its flag is 0 | missing | | | |
| AV1RTP-A.8.3-14 | A.8.3 | MUST | `template_dependency_structure_present_flag` is 1 on the first packet of a coded video sequence | missing | | | |
| AV1RTP-A.8.3-15 | A.8.3 | MUST | `template_dependency_structure_present_flag` is 0 on every other packet | missing | | | |
| AV1RTP-A.8.3-16 | A.8.3 | MUST | `active_decode_targets_bitmask` is present when its flag is 1 | missing | | | |
| AV1RTP-A.8.3-17 | A.8.3 | MUST NOT | `active_decode_targets_bitmask` is absent when its flag is 0 | missing | | | |
| AV1RTP-A.8.3-18 | A.8.3 | MUST | `frame_dtis` is present when `custom_dtis_flag` is 1 | missing | | | |
| AV1RTP-A.8.3-19 | A.8.3 | MUST NOT | `frame_dtis` is absent when `custom_dtis_flag` is 0 | missing | | | |
| AV1RTP-A.8.3-20 | A.8.3 | MUST | `frame_fdiffs` is present when `custom_fdiffs_flag` is 1 | missing | | | |
| AV1RTP-A.8.3-21 | A.8.3 | MUST NOT | `frame_fdiffs` is absent when `custom_fdiffs_flag` is 0 | missing | | | |
| AV1RTP-A.8.3-22 | A.8.3 | MUST | `frame_chain_fdiff` is present when `custom_chains_flag` is 1 | missing | | | |
| AV1RTP-A.8.3-23 | A.8.3 | MUST NOT | `frame_chain_fdiff` is absent when `custom_chains_flag` is 0 | missing | | | |
| AV1RTP-A.8.3-24 | A.8.3 | SHOULD | A new structure's template id range does not overlap the existing structure's range | missing | | | |
| AV1RTP-A.8.3-25 | A.8.3 | MUST | A new structure with the same `template_id_offset` has identical values in every field | missing | | | |
| AV1RTP-A.8.3-26 | A.8.3 | MUST | `render_resolutions` is present when `resolutions_present_flag` is 1 | missing | | | |
| AV1RTP-A.8.3-27 | A.8.3 | MUST NOT | `render_resolutions` is absent when `resolutions_present_flag` is 0 | missing | | | |
| AV1RTP-A.8.3-28 | A.8.3 | MUST | With `chain_cnt > 0` every Decode target is protected by exactly one Chain | missing | | | |
| AV1RTP-A.8.3-29 | A.8.3 | MUST | `fdiff_minus_one` immediately follows `fdiff_follows_flag` = 1 | missing | | | |
| AV1RTP-A.8.3-30 | A.8.3 | MUST | `fdiff_minus_one` immediately follows a non-zero `next_fdiff_size` | missing | | | |
| AV1RTP-A.9-1 | A.9 | MUST | The extmap URI is `https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension` | missing | | | No constant, not in the default header extensions; the string appears nowhere in `*.rs` |

Non-normative text checked (not counted):

- 4.2 note, "a receiver should be able to handle" a last packet without the marker, by the next
  packet's timestamp: `SampleBuilder` does (`sample_builder/mod.rs:270-274`); `IVFWriter` does not, it
  closes a frame on the marker only (`ivf_writer/mod.rs:173`).
- 4.1: one RTP timestamp for all packets of a temporal unit: `rtc-rtp/src/packetizer/mod.rs:149`, `:157`.
  The spec has no normative timestamp sentence beyond the 90000 clock rate.
- The spec has no MTU rule. Each payload, aggregation header included, stays within the `mtu` passed
  (`packetizer.rs:54`; `av1_test.rs::test_split_single_obu_into_many_packets` asserts 100-byte payloads).
  An `mtu` under 3 returns no packets and no error (`packetizer.rs:47`), so the frame is dropped silently.
- A.4 "an update is valid until the next update", A.6 `PartOfActiveChain`, A.8.2 syntax: all part of
  the missing Dependency Descriptor work.

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

1. **Unterminated OBU size accepted by the payloader's parser.** `rtc-rtp/src/codec/av1/leb128.rs:24`
   returns `(0, 0)` when no byte ends the leb128, and `rtc-rtp/src/codec/av1/obu.rs:74-83` does not check
   for a zero length the way the depacketizer does (`depacketizer.rs:90`, `:183`). Reproduction:
   `Av1Payloader::default().payload(1200, &Bytes::from_static(&[0x32, 0x80]))`. Expected an error;
   by reading it returns `Ok` with one packet `[0x20, 0x01, 0x30, 0x80]`: an empty frame OBU and the
   size byte re-read as an OBU header of reserved type 0 with the forbidden bit set.
2. **leb128 values of 2^32 and more are truncated, and more than 8 bytes are accepted.**
   `rtc-rtp/src/codec/av1/leb128.rs:9` (`b as u32`) and `:22` (`encoded <<= 8` drops the first bytes
   after eight). AV1 4.10.5 limits leb128 to 8 bytes and a value of at most 2^32 - 1. Reproduction on the
   receiver: `Av1Depacketizer::new().depacketize(&Bytes::from_static(&[0x00, 0x80, 0x80, 0x80, 0x80,
   0x10, 0x02, 0x30, 0x01]))`. The first element declares 2^32 bytes; expected `ErrShortPacket`; by
   reading the length becomes 0, the element is skipped and the call returns `Ok([0x32, 0x01, 0x01])`.
   The same truncation applies to `obu_size` in `obu.rs:74` and `depacketizer.rs:182`.
3. **A packet with Z = 0 in the middle of a temporal unit is taken as its start.**
   `rtc-rtp/src/codec/av1/depacketizer.rs:235-240` with
   `rtc-media/src/io/sample_builder/mod.rs:306`. Z = 0 only says the first element is not a
   continuation; a unit whose packets each hold whole OBUs has Z = 0 on all of them. Reproduction:
   `SampleBuilder::new(2, Av1Depacketizer::new(), 90000)`; push a complete earlier sample, then of a
   three-packet unit with one timestamp, seq 10 `[0x10, 0x18, 0x10]` (frame header), seq 11
   `[0x10, 0x20, 0xAA]` (tile group), seq 12 with marker `[0x10, 0x20, 0xBB]`, push only 11 and 12,
   then enough later packets to pass `max_late`. Expected: the unit is dropped. By reading
   (`mod.rs:165-196`, `:264-268`, `:306`): a sample with the two tile groups and no frame header is
   emitted, flagged only by `prev_dropped_packets`.
4. **A fragment chain with a lost middle packet is spliced, not dropped.**
   `rtc-rtp/src/codec/av1/depacketizer.rs:108-134`: the depacketizer has no sequence number, so
   continuity is the caller's job. `SampleBuilder` gives it contiguous packets and each sample starts
   with Z = 0, which clears the buffer (`depacketizer.rs:73-75`), so that path is safe.
   `rtc-media/src/io/ivf_writer/mod.rs:151-189` is not: it calls `depacketize` on every packet in
   arrival order. Reproduction: `IVFWriter` with `AV01`, `write_rtp` seq 1 `[0x50, 0x30, 0x01, 0x02]`
   (Y = 1), skip seq 2 `[0xd0, 0x03]`, `write_rtp` seq 3 with marker `[0x90, 0x05]`. Expected: no frame.
   By reading: a frame holding OBU `[0x32, 0x03, 0x01, 0x02, 0x05]` is written. The same writer closes a
   frame on the marker only (`:173`), so a unit whose last packet lacks the marker is merged with the
   next one (4.2 note). The AV1 path of `IVFWriter` has no test.
5. **W is not checked against the element count on receive.**
   `rtc-rtp/src/codec/av1/depacketizer.rs:227`: the check compares the index after the loop, which is
   also `W - 1` when one element is missing. Reproduction:
   `depacketize(&Bytes::from_static(&[0x20, 0x02, 0x30, 0x01]))` (W = 2, one element with a length
   field, nothing after it). Expected an error (or a documented zero-length last element); by reading it
   returns `Ok([0x32, 0x01, 0x01])`. Low severity.
6. **An OBU that exactly fills the packet is fragmented.** `rtc-rtp/src/codec/av1/packetizer.rs:94`
   uses `<` where `<=` fits. Reproduction: `payload(8, ...)` of one frame OBU without size field and 6
   payload bytes (OBU size 7, room for 7). Expected one packet `[0x10, 0x30, 1, 2, 3, 4, 5, 6]`; by
   reading two packets, `[0x50, 0x30, 1, 2, 3, 4, 5]` and `[0x90, 6]`. Conformant, wasteful: an extra
   packet for every OBU or tail that lands on the boundary.
7. **Layers are mixed in one packet.** `rtc-rtp/src/codec/av1/packetizer.rs:62-101` (AV1RTP-5-8).
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

Latent, not reachable today: `rtc-rtp/src/codec/av1/packetizer.rs:149-167` builds a "semi-last" packet
without setting `num_obu_elements`, which would underflow at `packetizer.rs:199` and `mod.rs:67`. The
loop at `packetizer.rs:134` guarantees `last_fragment_size <= max_payload_size`, so the branch is dead
(the libwebrtc original reaches it through `last_packet_reduction_len`, which this port does not have).
Remove it or fix it before adding a last-packet size reduction.

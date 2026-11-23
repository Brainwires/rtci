# draft-ietf-avtcore-rtp-sframe — RTP Payload Format for SFrame: clause audit

Spec: draft-ietf-avtcore-rtp-sframe-03, 21 October 2026 (WG document of AVTCORE, not yet in
last call; text in `specs/draft-ietf-avtcore-rtp-sframe-03.txt`). The implementation is pinned
to this revision: the descriptor bits, the reassembly algorithm, `a=sframe` and the per-SSRC
key derivation are concrete there, and a later revision that changes them is a new pin. Audited
and implemented on branch `conf/pc-18-sframe-transform`. RECOMMENDED counts as SHOULD; the
"expected" of section 9.7 is counted as SHOULD.

Scope: `rtc-rtp/src/codec/sframe/mod.rs` (`rtp`), `rtc-sframe/src/kdf.rs` (`kdf`),
`src/rtp_transceiver/internal.rs` (`[[useSFrame]]`, `t`), `src/peer_connection/sdp/mod.rs`
(`a=sframe`), `src/peer_connection/handler/endpoint.rs` and the sender's `write_rtp`. The engine
does not encode or decode media: the application encrypts with `rtc::sframe`, fragments with
`SFramePayloader` and reassembles with `SFrameReassembler`.

Totals (36 rows):

- MUST: tested 24 / untested 3 / partial 1 / missing 1 / violated 1 / n-a 0
- SHOULD: tested 1 / untested 0 / partial 0 / missing 1 / violated 0 / n-a 2
- MAY: tested 1 / untested 0 / partial 0 / missing 0 / violated 0 / n-a 1

Tests: `st` = `rtc-rtp/src/codec/sframe/sframe_test.rs`, `kt` = `rtc-sframe/src/kdf_test.rs`,
`sig` = `tests/encoded_transform_sframe_signalling.rs`, `e2e` = `tests/encoded_transform_sframe_rtc2rtc.rs`.

| ID | § | Level | Clause (short paraphrase) | Verdict | Code | Test | Note |
|---|---|---|---|---|---|---|---|
| SFRAMERTP-4-1 | 4 | MUST | The S bit is 0 on every fragment but the first of the SFrame frame | tested | rtp (SFramePayloader) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin | |
| SFRAMERTP-4-2 | 4 | MUST | The E bit is 0 on every fragment but the last | tested | rtp (SFramePayloader) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin | |
| SFRAMERTP-4-3 | 4 | MUST | T is 0 for a fragment of a raw (encoded-transform) frame | tested | rtp (SFramePayloadOrigin::Raw) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin, e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | |
| SFRAMERTP-4-4 | 4 | MUST | T is 1 for a fragment of packetized media | tested | rtp (SFramePayloadOrigin::Packetized) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin | |
| SFRAMERTP-4-5 | 4 | MUST | All fragments of a frame have the same T | tested | rtp (SFramePayloader, SFrameDepacketizer) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin, st::the_depacketizer_joins_s_to_e_and_discards_mixed_t | sent so; a receiver discards a frame that mixes them |
| SFRAMERTP-4-6 | 4 | MUST | Senders set the 5 reserved bits to 0 | tested | rtp (SFramePayloader) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin | |
| SFRAMERTP-4-7 | 4 | MUST | Receivers ignore the reserved bits | tested | rtp (SFrameDepacketizer, SFrameReassembler) | st::the_depacketizer_joins_s_to_e_and_discards_mixed_t | |
| SFRAMERTP-4-8 | 4 | MUST | SSRC, timestamp, marker and CSRCs of the SFrame packets are those of the media packetization's output | partial | `src/rtp_transceiver/rtp_sender/mod.rs` (write_rtp) | e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | the application writes the headers and the engine keeps SSRC, timestamp and marker (tested end to end); CSRCs are kept too but no SFrame test sends them |
| SFRAMERTP-4-9 | 4 | SHOULD | Header extensions as the media packetization's, some may be omitted | n/a | | | the application's choice per packet |
| SFRAMERTP-5.1-1 | 5.1 | MUST | Packetization: fragments no larger than the MTU, each behind its descriptor (S, E, T) | tested | rtp (SFramePayloader::payload) | st::the_descriptor_marks_the_first_and_last_fragment_and_the_origin | an MTU of 1 is refused |
| SFRAMERTP-5.1-2 | 5.1 | MUST | With the frame's marker set, the RTP marker is the E bit | tested | rtp (Payloader::marker_rule, LastPacketOfFrame) | e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | |
| SFRAMERTP-5.1.1-1 | 5.1.1 | MUST | Per-frame sending: the ciphertext of the media frame, payload origin raw, metadata from the last media packet | tested | rtp (SFramePayloadOrigin::Raw) | e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | |
| SFRAMERTP-5.1.2-1 | 5.1.2 | MUST | Per-packet sending: one ciphertext per media packet payload, origin packetized, its marker kept | tested | rtp (SFramePayloadOrigin::Packetized) | st::the_reassembler_completes_frames_in_any_order | |
| SFRAMERTP-5.2-1 | 5.2 | MUST | Receive steps 1 to 5: the smallest run of consecutive sequence numbers from an S packet to an E packet is taken out of the received set | tested | rtp (SFrameReassembler::push) | st::the_reassembler_completes_frames_in_any_order, e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | across the sequence-number wrap, packets in any order |
| SFRAMERTP-5.2-2 | 5.2 | MUST | Step 6: fragments that disagree on T are discarded | tested | rtp (SFrameReassembler, SFrameDepacketizer) | st::the_depacketizer_joins_s_to_e_and_discards_mixed_t | |
| SFRAMERTP-5.2-3 | 5.2 | MUST | Step 7: fragments that disagree on the payload type are discarded | tested | rtp (SFrameReassembler) | st::the_reassembler_completes_frames_in_any_order | |
| SFRAMERTP-5.2-4 | 5.2 | MUST | Steps 8 to 10: descriptors removed, payloads concatenated; metadata marker from the last packet, origin from T | tested | rtp (SFrameRtpFrame) | st::the_reassembler_completes_frames_in_any_order | |
| SFRAMERTP-5.2-5 | 5.2 | MUST | Steps 11 to 13: decrypt (abort on failure); a raw frame goes to the pipeline, a packetized one to the payload type's depacketizer | tested | `rtc-sframe/src/context.rs` (decrypt), rtp (SFrameRtpFrame::origin, payload_type) | e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | the application routes by origin and payload type |
| SFRAMERTP-5.2-6 | 5.2 | SHOULD | A discarded frame is treated as lost (PLI / FIR) | n/a | rtp (SFrameReassembler::discarded) | | the application's recovery: it reads `discarded()` and writes the PLI / FIR on the receiver |
| SFRAMERTP-5.3-1 | 5.3 | MUST | The SFrame metadata input is empty by default | tested | `rtc-sframe/src/context.rs` (encrypt, decrypt) | e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | the application passes the metadata |
| SFRAMERTP-6-1 | 6 | MUST | `a=sframe` is a media-level attribute, never at session level | tested | `src/peer_connection/sdp/mod.rs` (add_transceiver_sdp) | sig::an_sframe_transform_offers_and_answers_sframe | |
| SFRAMERTP-6-2 | 6 | MUST | An answerer includes `a=sframe` only when the offer had it | tested | t (describe_sframe, note_remote_sframe) | sig::an_sframe_transform_offers_and_answers_sframe, sig::without_a_transform_the_transceiver_does_not_use_sframe | |
| SFRAMERTP-6-3 | 6 | MUST | An answerer that requires SFrame rejects m-sections without `a=sframe` | missing | | | an existing transceiver with `[[useSFrame]]` true answering an offer without it: the answer section should be rejected (port 0); JSEP answer generation |
| SFRAMERTP-6-4 | 6 | MUST | Offered and not answered: the offerer sends no media for the section | tested | t (apply_sframe_answer), `src/rtp_transceiver/rtp_sender/mod.rs` (write_rtp_inner) | sig::an_answer_without_sframe_stops_the_offerers_media | `ErrSFrameRefused` |
| SFRAMERTP-6-5 | 6 | MUST | ... and never falls back to unencrypted RTP | tested | `src/rtp_transceiver/rtp_sender/mod.rs` (write_rtp_inner) | sig::an_answer_without_sframe_stops_the_offerers_media | |
| SFRAMERTP-6-6 | 6 | MUST | ... and discards the RTP received for the section | untested | `src/peer_connection/handler/endpoint.rs` (find_track_id) | | dropped like a stopped transceiver's; no rtc-to-rtc test |
| SFRAMERTP-6-7 | 6 | SHOULD | ... and closes the section in subsequent offers | missing | | | |
| SFRAMERTP-6-8 | 6 | MUST | An offered `a=sframe` appears in every re-offer unless the section is closed | tested | t (describe_sframe) | sig::an_sframe_transform_offers_and_answers_sframe | `[[useSFrame]]` never goes back to false |
| SFRAMERTP-6-9 | 6 | MUST | Under BUNDLE, a section with `a=sframe` and one without do not share payload types of SFrame-relevant formats | violated | `src/peer_connection/configuration/media_engine.rs` | | one payload-type table for the whole connection: mixing SFrame and plain sections in one bundle reuses the types; JSEP payload-type allocation |
| SFRAMERTP-7-1 | 7 | MAY | A per-SSRC key may be derived from the base key | tested | kdf (derive_ssrc_key) | kt::the_per_ssrc_key_is_hkdf_of_the_base_key_salted_with_the_ssrc | |
| SFRAMERTP-7-2 | 7 | MUST | When used, every SSRC stream derives ssrc_key = HKDF-Expand(HKDF-Extract(SSRC, base_key), "SFrame 1.0 RTP Stream", Nh) | tested | kdf (derive_ssrc_key, hkdf_extract_salted) | kt::the_per_ssrc_key_is_hkdf_of_the_base_key_salted_with_the_ssrc, kt::salted_hkdf_matches_rfc5869_test_case_1, e2e::the_sframe_payload_format_carries_per_ssrc_keyed_frames_end_to_end | the HKDF is checked against RFC 5869 A.1 |
| SFRAMERTP-7-3 | 7 | MUST | The SSRC is the 4-byte big-endian salt; the suite is the one the key is used with | tested | kdf (derive_ssrc_key) | kt::the_per_ssrc_key_is_hkdf_of_the_base_key_salted_with_the_ssrc | |
| SFRAMERTP-8-1 | 8 | MUST | With ratcheting, the per-SSRC derivation is done once at the start, then each ratchet runs on the per-SSRC key | untested | kdf (ratchet_base_key, derive_ssrc_key) | | the application composes them: `ratchet_base_key(derive_ssrc_key(...))` |
| SFRAMERTP-8-2 | 8 | MUST | The KID comes from key_generation and ratchet_steps as in RFC 9605 5.1 | untested | `rtc-sframe/src/key_id.rs` (SenderKeyId) | | RFC 9605's sender-key ids, unchanged by the per-SSRC keys |
| SFRAMERTP-9.7-1 | 9.7 | SHOULD | Receivers bound the buffered packets and discard incomplete frames | tested | rtp (SFrameReassembler::new, max_buffered) | st::the_reassembler_bounds_what_it_holds | oldest evicted first; fragments older than a completed frame are kept for a late retransmission |
| SFRAMERTP-10-1 | 10 | MAY | IANA registration of `a=sframe` | n/a | | | registry action |

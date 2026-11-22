# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Bug Fixes

- **dtls**: the roles of a DTLS association are fixed for its life (RFC 8842 section 5.3). The
  answer to a later offer took its `a=setup` from the answering configuration and the offer
  alone, so the peer that had offered first (the DTLS server) answered `active` and flipped the
  roles: libwebrtc refuses such an answer, and with an ICE restart in the same exchange two
  `rtc` peers tore their own association down. The answer now states the role the transport
  has, and an `actpass` offer never changes it, whatever the ICE role and
  `answering_dtls_role` say.
- **dtls**: a new association is established when a description changes the fingerprints, the
  `tls-id` or the roles, with or without an ICE restart (RFC 8842 section 3.1). A changed
  fingerprint or role on the same ICE session was accepted and ignored. The DTLS client of the
  new association starts its handshake at once when ICE already has a pair.
- **dtls**: a peer that negotiates no `use_srtp` connects when the session has no audio or
  video section (RFC 5764 section 4.1). As the DTLS server the engine left its transport in
  `connecting`; as the client it aborted the handshake. A session with a media section still
  needs it: the transport fails, and a description that adds media to an association without
  SRTP keys is refused (`ErrSessionDescriptionMediaWithoutSrtp`).
- **dtls**: a certificate is verified with any fingerprint hash function of RFC 8122 section 5
  (sha-256, sha-512, sha-384, sha-224, sha-1; never md5 or md2), using the most preferred one
  the peer offers. Only sha-256 was compared, so a peer that gave another one could not connect.
- **dtls**: `RTCCertificate::get_fingerprints` gives the fingerprints of the end-entity
  certificate only (it gave one per certificate of a chain, the issuer's included), with the
  hash function of the certificate's signature next to sha-256 when that is sha-384, sha-512 or
  sha-224 (RFC 8122 section 5.1).
- **sdp**: malformed DTLS attributes are refused by `set_remote_description`, before anything
  is applied: an `a=fingerprint` that is not colon-separated hex of its hash function's length,
  an `a=setup` that is not `active`, `passive` or `actpass` (`holdconn` is not used with DTLS,
  RFC 8842 section 5.1), an `a=tls-id` outside its syntax, and a description whose only
  fingerprints are md5 / md2 or unknown.
- **sdp**: a session-level `a=setup` is read (RFC 4145 section 4); a media-level
  `a=fingerprint` overrides the session-level one (RFC 8122 section 5) instead of conflicting
  with it.
- **demux**: datagrams whose first byte is in no RFC 7983 / RFC 9443 range (4 to 19, 64 to 127,
  192 to 255) are dropped by the demultiplexer. They went to the ICE agent, which recorded the
  remote candidate as heard from and logged a warning for each.
- **srtp**: a serialized RTP packet written into the pipeline is refused instead of leaving
  unprotected (RFC 8827 section 6.5; nothing in the engine writes one).

### Features

- **sdp**: `a=tls-id` (RFC 8842 section 4). Offers carry the association's value on the
  BUNDLE-tag m-section, answers carry one when the offer did; the value is kept while the
  association is and replaced with it; a changed remote value asks for a new association.
  `SettingEngineBuilder::with_disable_sdp_tls_id` leaves it out.
- **sdp**: `a=identity` (RFC 8827 section 5) is carried: `RTCPeerConnection::
  set_identity_assertion` and `remote_identity_assertion`. Making and verifying an assertion
  stays the application's.
- **dtls**: `SettingEngineBuilder::with_disable_dtls_use_srtp` for a data-channel-only
  endpoint (no `use_srtp`, media sections refused); `RTCCertificate::fingerprint` for one hash
  function; `rtc_dtls::config::ConfigBuilder::with_use_srtp_optional`.
- **crypto**: `HashAlgorithm::{Sha1, Sha224, Sha384, Sha512}` in the built-in providers, for
  certificate fingerprints.

### Changed

- **dtls**: an `rtc-dtls` server configured with no SRTP profile ignores a client's `use_srtp`
  (RFC 5764 section 4.1.1) instead of aborting with `ErrServerNoMatchingSrtpProfile`; the
  client, which asked for SRTP, is the one that aborts (`ErrRequestedButNoSrtpExtension`)
  unless built with `with_use_srtp_optional`.
- **sdp**: errors `ErrSessionDescriptionInvalidSetup`, `ErrSessionDescriptionInvalidTlsId`,
  `ErrSessionDescriptionMediaWithoutSrtp`, `ErrInvalidIdentityAssertion`.

## [0.22.0+brainwires.5] - 2026-11-20

### Bug Fixes

- **ice**: the controlled agent follows a later nomination (RFC 8445 sections 7.3.1.5 and
  8.1.1). It took only the first USE-CANDIDATE and ignored every later one, so when the
  controlling agent moved the session to another pair, this side kept sending DTLS / SRTP / SCTP
  on the pair the peer had left and dropped the peer's packets from the new one: media and data
  stopped. Chrome does this about a second after connecting when it has camera / microphone
  permission and gathers on more interfaces. A USE-CANDIDATE on another succeeded pair now makes
  it the selected pair, emits `SelectedCandidatePairChange`, and the media path follows at once
  (the DTLS session is kept).
- **ice**: libwebrtc's renomination attribute (`NOMINATION`, 0xC001,
  draft-thatcher-ice-renomination) is honoured: the pair with the highest value is used, so a
  delayed earlier nomination does not move the session back. A plain USE-CANDIDATE counts as 1,
  as libwebrtc counts it.
- **ice**: a nomination on a pair whose check has not succeeded is answered (RFC 8445 section
  7.3.1.4; it went unanswered, so the peer could only retransmit it) and takes effect when the
  triggered check succeeds.
- **ice**: USE-CANDIDATE and `NOMINATION` count only ahead of MESSAGE-INTEGRITY (RFC 8489
  section 14.5); appended after it they are not authenticated.

### Features

- **ice**: `rtc_ice::attributes::nomination` (`ATTR_NOMINATION`, `NominationAttr`,
  `nomination_of`).

## [0.22.0+brainwires.4] - 2026-11-20

### Features

- **ecn**: ECN (RFC 3168) and L4S (RFC 9331) on RTP media. The engine is sans-I/O, so the
  application's socket layer carries the codepoint in `TransportContext::ecn`: on a datagram
  handed to `handle_read`, the codepoint it arrived with (`IP_RECVTOS` / `IPV6_RECVTCLASS`,
  `None` for Not-ECT); on a datagram from `poll_write`, the codepoint to set (`IP_TOS` /
  `IPV6_TCLASS`, `None` for Not-ECT). New `SettingEngineBuilder::with_ecn(bool)` (off by
  default) says the socket layer does both: RTP packets (RTX included) of a stream whose codec
  negotiated RFC 8888 feedback are then sent ECT(1); STUN, DTLS, SCTP and RTCP never are, and
  nothing is marked without `ack ccfb` negotiated.
- **interceptor**: `configure_congestion_control_feedback` negotiates
  `a=rtcp-fb:<pt> ack ccfb` (RFC 8888 section 5) and registers the RFC 8888 recorder without a
  congestion controller. Opt-in: TWCC stays the default and the default SDP is unchanged. New
  constant `RTCP_FB_ACK_CCFB`.
- **rfc8888**: the recorder reports each packet with the ECN codepoint its datagram arrived with
  (it reported Not-ECT for every packet).
- **stats**: inbound-rtp `packetsReceivedWithEct1` / `packetsReceivedWithCe` and outbound-rtp
  `packetsSentWithEct1` (with ECN on); inbound-rtp `packetsReportedAsLost` /
  `packetsReportedAsLostButRecovered` from the RFC 8888 reports this side sends, and
  remote-inbound-rtp `packetsReceivedWithEct1`, `packetsReceivedWithCe`, `packetsReportedAsLost`,
  `packetsReportedAsLostButRecovered` and `packetsWithBleachedEct1Marking` from the ones it
  receives (where `ack ccfb` is negotiated), each packet counted once however many reports
  describe it. An RFC 8888 report also creates the remote-inbound object.
- **shared**: `EcnCodepoint`'s variants are documented (they were hidden).

## [0.22.0+brainwires.3] - 2026-11-20

### Behaviour changes

- **jsep**: once an answer (local or remote) is applied, a stopped transceiver whose m= section is
  rejected is removed from the set of transceivers (W3C webrtc-pc 4.4.1.6). A transceiver id is
  its index, so the ids after it move down by one. Mirror the list with the new
  `RTCPeerConnection::take_removed_transceivers()`, which returns the removed ids (rollback
  removals included) in removal order.
- **interceptor**: `register_default_interceptors` now also calls
  `configure_receiver_reference_time`, so the default SDP offers `a=rtcp-fb:<pt> rrtr` on video
  codecs.

### Features

- **stats**: remote-outbound-rtp `roundTripTime`, `totalRoundTripTime` and
  `roundTripTimeMeasurements` are measured over RTCP XR (RFC 3611): the receiver of a stream
  that negotiated `rrtr` sends a receiver reference time block with each receiver report, the
  sender answers every one with a DLRR block (as libwebrtc does), and the receiver turns the
  answer into a round trip time. New: `configure_receiver_reference_time`,
  `rtc_interceptor::RTCP_FB_RRTR`.
- **peer_connection**: `RTCPeerConnection::take_removed_transceivers()`.
- **interceptor**: `StreamInfo`, `RTPHeaderExtension` and `RTCPFeedback` implement `PartialEq`
  and `Eq`.

### Bug Fixes

- **rtp_sender**: a renegotiation that changed the codec a sender's encoding is sent with (the
  first negotiated media codec for an encoding that names none, or the matched codec), its RTX
  payload type or SSRC, its FEC flow or the header extensions left the interceptors on the old
  stream info. The streams are now unbound and bound again with the new information, keeping
  their SSRCs; a negotiation that changes nothing re-binds nothing. The NACK responder's buffer
  and the TWCC send side start again for a re-bound stream; the stats reference the new codec.
- **interceptor**: the sender report interceptor keeps a stream that is unbound and bound again
  with the same SSRC (its counts and timing carry on) and sends no RTCP BYE for it; a sender that
  really stops still says goodbye.
- **rtp_sender**: when RTX is not negotiated, the RTX SSRC is dropped from the track's codings
  too (it was dropped from the sender's encodings only), so no stream is bound with an RTX SSRC
  and no RTX payload type.
- **rtp_sender**: `write_rtp` refused every packet of an encoding that names no codec whose
  payload type was not negotiated; it now rewrites it to the payload type of the codec the
  encoding is sent with, as for an encoding that names one.
- **jsep**: a rejected m= section in a remote offer or answer now stops the transceiver it
  belongs to (W3C 4.4.1.6), firing no track event; a rollback leaves it stopped. A remote offer
  that keeps a section the last exchange rejected creates no transceiver for it again.
- **stats**: when a rollback removed a transceiver, the stats kept the old transceiver ids, so a
  sender or receiver selector could pick another transceiver's streams; they now follow the
  removal.

## [0.22.0+brainwires.2] - 2026-11-20

### Features

- **rtp_transceiver**: `RTCRtpTransceiver::stopped()`, whether the transceiver is stopped (by
  `stop()`, or created stopped for a rejected m= section of a remote offer).

### Bug Fixes

- **rtp_sender**: a sender whose encoding names no codec (W3C `sendEncodings` that leave the codec
  to negotiation) was never bound to the interceptors: it sent no RTCP sender reports and had no
  NACK responder, RTX or TWCC send side. Such an encoding is now sent with the first media codec
  of the sender's negotiated codecs, and its stream is bound with it.
- **stats**: the outbound stream of such an encoding referenced no codec, so its clock rate was 0
  and the remote-inbound `jitter` was missing; it now references the codec it is sent with.
- **peer_connection**: encodings the application passes (`sendEncodings`, and the encoding
  `add_transceiver_from_kind` fills in) got no RTX repair flow; they get one whenever the media
  engine carries RTX, as encodings derived from a track do (`rtxSsrc`, NACK repairs over RTX).
- **jsep**: a rejected m= section (port 0) of a remote offer got no transceiver; it now gets one,
  created stopped, with no track event (RFC 9429 section 5.10, W3C setRemoteDescription). A
  rollback of the offer removes it.

## [0.22.0+brainwires.1] - 2026-11-20

A conformance release: every claim the README, `FORK.md`, a public option, the default SDP or the
statistics report makes is now a row of [`docs/conformance.md`](docs/conformance.md) with its
specification section and the test that proves it, and what is not implemented is listed there.
Fixes across SCTP, JSEP, ICE, TURN, DTLS, SRTP, RTP / RTCP and the statistics report came out of
that work. The minor version moves because the public API changes (see "Breaking changes").

### Breaking changes

- **rtp**: `Header` has a public `padding_size: u8`, the number of padding octets a parsed packet
  carried, kept on re-marshal (0 pads as before). Struct literals add `padding_size: 0` or
  `..Default::default()`.
- **stats**: members the engine cannot measure are `Option` and left out of the JSON when `None`
  (webrtc-stats: an unmeasured member is not present), instead of 0 / `""`. This covers the
  encoder, decoder, frame, audio, jitter buffer, pause / freeze, corruption, PSNR and quality
  limitation members of `RTCInboundRtpStreamStats` / `RTCOutboundRtpStreamStats`, their
  `remote_id`, `rtx_ssrc`, `fec_ssrc` and `encoding_index`, the received streams' `jitter` and ECN
  / RFC 8888 members, `round_trip_time` of the remote-inbound and remote-outbound streams,
  `RTCCodecStats::channels`, `RTCIceCandidateStats::related_port`, the candidate pair's
  last-packet timestamps, `current_round_trip_time` and available bitrates, and every member of
  `RTCAudioSourceStats`, `RTCVideoSourceStats` and `RTCAudioPlayoutStats`. Read them with
  `if let Some(v)` or `.unwrap_or_default()`.
- **stats**: `RTCIceCandidateStats::priority` is `u32` (the full RFC 8445 priority; it was
  truncated to `u16`). Widen the receiving type.
- **stats**: `RTCMediaSourceStats::track_id` is `track_identifier`, as webrtc-stats names it.
  Rename the field access.
- **stats**: `RTCCodecStats` has a `transport_id: String`. Struct literals add it.
- **ice**: `AgentConfig` has `nat_1to1_ips`, `nat_1to1_ip_candidate_type`,
  `allow_loopback_remote_candidates`, `allow_link_local_remote_candidates` and
  `remote_address_filter`; `SettingEngine`'s `Candidates` has the last three. Struct literals add
  `..Default::default()`.
- **rtp**: `Vp9Payloader` has a public `flexible_mode: bool`. Struct literals add
  `..Default::default()`.
- **data channel**: `RTCDataChannelInit` has `priority: u16` (default 256, W3C Priority
  Control). Struct literals add `priority: 256` or `..Default::default()`.
- **rtp_transceiver**: `RTCRtpEncodingParameters::default()` has `active: true`, as W3C defines
  it; an encoding with `active: false` is not sent and is a paused rid in `a=simulcast`. Code that
  relied on the old `false` default sets `active` explicitly.
- **rtcp**: `ReceptionReport::total_lost` holds the 24 wire bits unclamped; read the signed RFC
  3550 count with `ReceptionReport::cumulative_lost()` and write one with `set_cumulative_lost()`.
- **setting_engine**: `with_receive_mtu`, `with_include_loopback_candidate` and
  `with_disable_media_engine_copy` are `#[deprecated]`: they had no effect in the sans-I/O engine.
  Remove the calls (add a loopback candidate with `add_local_candidate` instead).
- **media_engine**: `register_default_codecs` no longer offers ULPFEC (nothing encodes or decodes
  it); an application with its own coder registers `MIME_TYPE_ULP_FEC` itself. The FlexFEC coder
  is selected only for an exact `video/flexfec-03`.
- **ice**: only `<uuid>.local` remote candidate names are resolved over mDNS, and remote
  candidates on unspecified, multicast, broadcast or port-0 addresses are dropped; checks to a
  loopback or link-local remote address need a local candidate of the same scope unless
  `SettingEngineBuilder::with_remote_candidate_scopes` allows them.

### Features

- **setting_engine / ice**: `SettingEngineBuilder::with_remote_candidate_scopes` and
  `with_remote_address_filter` (`ice::agent::remote_policy::RemoteAddressFilter`) decide which
  remote addresses connectivity checks may reach (RFC 8445 §5.1.1.1).
- **ice**: `nat_1to1_ips` is applied to the host candidates the application adds: `Host`
  announces the external address, `Srflx` adds a server-reflexive candidate.
- **media_engine**: each media section negotiates its own codecs, one entry per format;
  `with_disable_media_engine_multiple_codecs(true)` restores one shared set. The default codecs
  carry H.264 High profile at levels 4.0 to 5.1, each with an RTX pairing, and the default AV1
  fmtp is `profile=0`.
- **stats**: `RTCPeerConnection::update_decoder_stats`, `update_audio_receiver_stats`,
  `update_encoder_stats`, `update_audio_source_stats`, `update_video_source_stats` and
  `update_audio_playout_stats` supply the members only the application can measure (the
  `*StatsUpdate` types are exported from `statistics`); updates merge.
- **sctp**: `TransportConfig::with_max_receive_message_size` and `with_remote_sctp_port`;
  `Association::is_ended`.
- **rtcp / rtp**: a stopped sender sends a final SR and BYE, and an inbound BYE ends the remote
  track; `H264Payloader::with_packetization_mode`; `ReceptionReport::cumulative_lost` /
  `set_cumulative_lost`.
- **media**: `OggReader::next_packet` and `OggPageHeader::{segment_table, packets,
  is_continued_packet}`; `MAX_ACCESS_UNIT_NALS` / `MAX_ACCESS_UNIT_BYTES` bound an H.26x access
  unit.
- **ice / dtls / srtp**: `Agent::set_candidate_types`, `Candidate::last_consent`,
  `DTLSConn::is_failed`, `srtp::Context::cryptex` / `set_cryptex`.

### Bug Fixes

- **SCTP and data channels**: SHUTDOWN carries the last TSN received and acknowledges our DATA;
  a graceful shutdown sends queued DATA first, and the initiator ends after SHUTDOWN COMPLETE. Fast
  Recovery counts misses only for TSNs a SACK reports missing; T3-rtx keeps recovering past its
  limit by default (a finite limit closes the association); congestion window arithmetic
  saturates. A performed outgoing stream reset restarts the stream's SSN. The INIT goes to the
  remote `a=sctp-port`. A failed handshake closes the association, the transport and its data
  channels. Messages up to the advertised `max-message-size` are received, and an oversized one is
  dropped alone instead of ending the read. A fragment set's completeness is checked in constant
  time.
- **Peer connection and SDP (JSEP)**: `stop()` and `setStreams()` raise negotiation-needed and a
  stopped transceiver settles; a recycled m-line drops the stopped transceiver's section;
  `addTransceiver` accepts `inactive` and `send` without encodings, and remote tracks are labelled
  `"remote <kind>"`; `setParameters` runs the W3C validation steps and refuses duplicate rids; a
  new `iceTransportPolicy` from `set_configuration` reaches the ICE agent; a remote description
  that fails to apply leaves the negotiated codecs alone; codec preferences survive a remote
  offer; `Require` header encryption refuses a remote description without `a=cryptex`; a FEC
  repair flow is described only for FlexFEC-03.
- **ICE, TURN, STUN, mDNS**: consent is granted only by authenticated responses to our own
  checks; a closed agent refuses an ICE restart; the bare `.local` is not an mDNS host name; an
  mDNS answer is taken only from an on-link sender that owns the address, and a query ends at its
  timeout. TURN: a 438 Stale Nonce answer to CreatePermission, Refresh or ChannelBind is retried
  with the new nonce; a Refresh or ChannelBind that timed out is sent again; permissions are per
  peer IP; the authenticated Allocate uses a fresh transaction id; Data indications are accepted
  only from the TURN server; a permission refresh is split into bounded requests. STUN: the
  message length no longer wraps.
- **DTLS**: a fatal alert, handshake error or exhausted retransmissions sets
  `RTCDtlsTransportState::Failed` and fails the peer connection; a repeated peer flight is
  answered at once; alerts are not echoed; an invalid epoch-0 record cannot stall the handshake;
  the AES-GCM / CCM explicit nonce is the record's epoch and sequence number (RFC 5288, RFC 6655);
  CBC padding and MAC checks have a constant structure; a server does no key exchange work for a
  source address before the cookie exchange.
- **SRTP**: the AES-GCM cipher constructor returns errors instead of panicking. The inbound replay
  window defaults to 1024 packets (was 64): a NACK retransmission without RTX reuses the lost
  packet's sequence number, and one repaired on a third try at 200 packets/s was already more
  than 64 packets behind and refused as too old, so the packet was lost for good.
- **RTP, RTCP, codecs, interceptors**: a packet keeps its padding size across unmarshal and
  marshal; every compound report carries an SDES CNAME; a reception report's cumulative loss is
  read as signed 24-bit; TWCC receive deltas and status chunks are checked against the packet.
  RTX is de-encapsulated before the interceptor chain, and NACK retransmissions keep the
  original's CSRCs and extensions and are held to the stream's own send rate. GCC scales its delay
  trend and measures the received rate on arrival time. FlexFEC-03 decoder packets are ordered by
  a total key; the adaptive jitter buffer is bounded per stream and drops an evicted packet's
  deadline; a wide sequence gap clears in one step. H.264 honours `packetization-mode=0`, and
  only the last slice of a picture is a timed sample; H.265 tells a continuing fragmentation unit
  from a partition head; VP9 accepts three reference indices, reads G as one bit and sends
  non-flexible mode with the scalability structure on key frames; AV1 sets N only at a coded video
  sequence start. `H26xSampleReader` returns whole access units and `OggReader` reads packets;
  reads of untrusted media files are bounded.
- **Statistics**: every id a stats object names resolves in the same report; remote-inbound
  `roundTripTime`, `packetsReceived` and `jitter` follow RFC 3550 (jitter in seconds); reception
  reports inside sender reports are counted; remote objects exist only after their first report;
  every candidate pair is reported with its state, and candidates carry their full priority;
  `dtlsState`, data channel `state`, `transportId`, `trackIdentifier` and the congestion
  controller's estimate (`targetBitrate`, `availableOutgoingBitrate`) are reported; `tlsVersion`
  is the ServerHello version in hex; per-SSRC stream maps shrink with their streams.

### Testing

- Upstream test parity: every test of upstream `webrtc-rs/rtc` and `webrtc-rs/webrtc` v0.17.1 has
  a fork test, a mapped equivalent, or a recorded reason (`docs/upstream-test-parity.md`);
  commented-out and never-compiled tests across SCTP, data channels, DTLS, ICE, TURN, STUN, mDNS,
  SRTP, SDP and media were restored.
- A Linux network-namespace environment runs ICE across NAT topologies, TURN over UDP / TCP / TLS,
  mDNS on a LAN, ICE-TCP through a NAT, and data channels, NACK, the jitter buffer and GCC over
  impaired links; a browser matrix (Chromium, Firefox, WebKit) covers data channels,
  renegotiation, ICE restart, every codec both ways, simulcast with RTX, Cryptex, TURN, ICE-TCP,
  mDNS-hidden candidates, JSEP flows, wrong fingerprints and stats.
- Fuzzing: every parser a peer, a server or an untrusted file reaches has a fuzz target, with
  stateful targets for the state machines above them; CI checks every target is run and built by
  OSS-Fuzz.
- CI fails on hidden tests (ignored, commented out, orphaned or platform-gated without a listed
  reason) and on conformance rows whose test does not exist, runs the workspace tests on macOS and
  Windows as well as Linux, and pins every action by commit SHA.
- The workspace with `--all-features`: 2746 tests pass.

## [0.21.1+brainwires.6] - 2026-11-20

### Bug Fixes

- **sctp**: a data channel could fail to open when the first SCTP INIT ACK was lost: the peer's
  retransmitted INIT was treated as a second association and refused by the one-association limit
  added in 0.21.1+brainwires.5.

## [0.21.1+brainwires.5] - 2026-11-20

Hardening across the stack: bounds on the state a peer can make the stack hold, and stricter
handling of protocol state in DTLS, SCTP and data channels, SRTP / SRTCP, SDP, ICE and RTP. No
change to the public API beyond the additions below (`cargo semver-checks` against
`0.21.1+brainwires.4`: no semver update required). Details follow in advisories.

### Features

- **sctp**: `ServerConfig::concurrent_associations`, the number of associations a server holds at
  once.
- **shared**: two `Error` variants (the enum is `#[non_exhaustive]`), `SrtpIndexReused` and
  `SrtpTooManySsrcs`.
- **sdp**: limit constants for a session description (`MAX_SDP_SIZE`, `MAX_SDP_LINES`,
  `MAX_MEDIA_DESCRIPTIONS`, `MAX_ATTRIBUTES_PER_SECTION`, `MAX_FORMATS_PER_MEDIA`).

### Bug Fixes

- **dtls**, **sctp**, **datachannel**, **srtp**, **sdp**, **ice**, **rtp**, **peer_connection**:
  hardening (bounds on held state, stricter state transitions, linear-time processing).

### Testing

- The workspace with `--all-features`: 2330 tests pass.

## [0.21.1+brainwires.4] - 2026-11-19

ICE restarts that keep data flowing and four JSEP / webrtc-stats points the Deno WebRTC
extension's web-platform-tests run into (Brainwires/deno `ext/webrtc`). `FORK.md` lists everything
the fork carries over upstream.

### Features

- **rtp_transceiver**: `RTCRtpTransceiver::set_associable_with_remote_offer` lets an application
  mark a transceiver it made for `addTransceiver` so a remote offer's new media section does not
  take it (RFC 9429 §5.10: only one "created by addTrack" is a candidate). The default keeps the
  old behaviour.
- **ice**: `Agent::media_path()`, the selected pair's path or, during a restart, the one the
  session had when the restart was applied.

### Bug Fixes

- **ice**: an ICE restart keeps using the previously selected pair until the restart selects a new
  one (RFC 8445 §9). `apply_restart` dropped it at once (the offerer at setLocalDescription of the
  restart offer, the answerer at setRemoteDescription of it), so every DTLS / SRTP packet, and
  every data channel message, between that point and the new generation's first nomination was
  lost on both peers. This holds with `discard_local_candidates_during_ice_restart` too, which
  forgets what was signalled but doesn't close the selected pair's socket.
- **peer_connection**: `a=msid` is one line per MediaStream of the sender (RFC 9429 §5.2.1),
  without duplicates; a sender in none writes its track's own stream id. One line with the track's
  stream id was written whatever `set_streams` had been given.
- **peer_connection**: a remote `a=inactive` media section sets the transceiver's direction to
  inactive for the answer and no longer stops it, so a later offer, or a rollback, resumes it. Only
  a rejected section stops a transceiver.
- **stats**: the selected candidate pair's local and remote candidates are always in the report; a
  peer-reflexive remote candidate was never registered, so the pair's `remoteCandidateId` named an
  object the report did not have.

### Testing

- `tests/ice_restart_keeps_path_rtc2rtc.rs`: two peers on a simulated UDP network in virtual time,
  a message each way after every signalling step of a restart and on the new pair, with and
  without discarding the local candidates. `rtp_transceiver` tests for one `a=msid` line per stream
  and a transceiver that a remote offer may not take.
- `tests/ice_restart_by_webrtc_interop.rs` treats a datagram its loopback-bound socket can't send
  to a non-loopback candidate (`EADDRNOTAVAIL`, macOS) as lost, as the sibling tests do, instead
  of failing.

## [0.21.1+brainwires.3] - 2026-11-19

W3C WebRTC behaviour the Deno WebRTC extension (Brainwires/deno `ext/webrtc`) relies on: JSEP
negotiation edge cases from the web-platform-tests, the data channel lifecycle (ids, closing,
failure, stream-id reuse, `bufferedAmount`), stats timestamps in milliseconds, and RTCP that no
longer stops at a nested interceptor. `FORK.md` lists everything the fork carries over upstream.

### Features

- **sctp, data channel**: `Stream::bytes_dequeued`, `Association::stream_bytes_dequeued` and
  `RTCDataChannel::bytes_dequeued` count the application bytes taken from a stream's send queue
  (first transmission, or abandoned before it), for W3C `bufferedAmount`, which falls on
  transmission rather than on acknowledgement. `outstanding_bytes` is unchanged.
- **interceptor**: `PassThroughInterceptor` (exported) hands every packet on in both directions;
  it is the inner end of a nested interceptor in a registry slot
  (`PassThroughInterceptor::new().with(builder.build())`).

### Bug Fixes

- **interceptor**: the documented recipe for a nested interceptor in a registry slot,
  `NoopInterceptor::new().with(...)`, put the chain's RTCP terminus inside the slot: in
  `Slot::CongestionControl` (the fork's GCC) no NACK, receiver report, PLI or FIR reached the
  interceptors after it or the application. The recipe, the GCC and adaptive jitter buffer
  modules and `FORK.md` now use `PassThroughInterceptor`.
- **ice**: `RTCIceCandidate::to_json` wrote `sdpMid: ""` with `sdpMLineIndex: 0`; the empty mid
  matched no media section, so `add_remote_candidate` on the other peer refused it. A candidate
  built from a bare ICE candidate now has no mid and names the first section by index.
- **peer_connection**: JSEP negotiation (W3C web-platform-tests): a BUNDLE group's m-sections may
  carry their own ICE credentials (the offerer-tagged section's are the transport's, RFC 8843
  §7.2); a description with no m-section starts no transport, so a remote offer can be
  re-applied or rolled back; `have-remote-offer` takes another remote offer and the pranswer
  states another pranswer, a remote pranswer deciding the ICE role; `add_remote_candidate`
  follows W3C `addIceCandidate` (mid or m-line index, `usernameFragment` checked, the candidate or
  `a=end-of-candidates` recorded in the descriptions); `ice-ufrag` / `ice-pwd` syntax checked
  (RFC 8839 §5.4); `a=ice-options:trickle` written; one `a=fingerprint` per local certificate and
  every remote one kept; an answer to `setup:active` / `setup:passive` takes the other role;
  media sections without `a=ssrc` accepted with several m-sections (bound by the MID header
  extension, RFC 8843 §9.2); `RTCTransportStats.dtlsRole` serializes as W3C `RTCDtlsRole`.
- **data channel**: a channel gets its RFC 8832 id when an answer negotiates the DTLS role, and
  one created after that gets it at once, before SCTP connects.
- **data channel**: a close the remote starts fires `OnClosing` before `OnClose`; an association
  lost to the peer's ABORT (now `AssociationError::AssociationClosed`, not `Reset`), a protocol
  error or a timeout fires `OnError` before `OnClose`, on every channel of the association, an
  idle pre-negotiated one included (`Event::AssociationClosed`).
- **sctp, data channel**: a stream id is freed only once both directions are reset (RFC 8831
  §6.7); a reset this side started is not echoed back, and a reset of a stream with no state here
  is reported and answered. A new channel no longer takes an id the peer is still resetting.
- **data channel**: `close()` follows the messages sent before it instead of resetting the stream
  ahead of them, and a read that completes a deferred stream reset no longer loses that pass's
  messages.
- **sctp**: `SctpTransport.state` is `Connecting` while the association handshakes (it reported
  the accepting side `Closed`); an ended association is passed over for a live one.
- **shared**: stats timestamps serialize as epoch milliseconds with sub-millisecond precision (they
  were seconds, truncated to whole milliseconds).
- **peer_connection**: an offer made while an ICE restart is staged carries no candidates of the
  previous generation.

### Dependencies

- The workspace audit ignores RUSTSEC-2026-0543 (`chrono` unmaintained, published after the
  previous release): `chrono` is a dev-dependency only, for log timestamps in examples and
  tests. The library's own audit, which ignores nothing, is unaffected.

### Testing

- Interceptor tests that a PLI passes the GCC slot to a later interceptor and the application, and
  that the old `NoopInterceptor` recipe ends it there; an ICE candidate JSON round-trip test
  (`tests/ice_tcp_rtc2rtc.rs` passes again); SCTP tests for stream-id release, idle-stream resets,
  association failure and the dequeued byte count.

## [0.21.1+brainwires.2] - 2026-11-14

ICE over TCP between two `rtc` peers in both role assignments, mDNS host candidates published one
name per address (IPv4 and IPv6), and inbound key-frame requests delivered to the application.
`FORK.md` lists what the fork carries over upstream.

### Features

- **interceptor**: `KeyFrameRequestInterceptor` marks inbound RTCP PLI (RFC 4585 §6.3.1) and FIR
  (RFC 5104 §4.3.1) `DeliverToApplication`, so they pass the chain's terminus and reach the
  application as `RTCMessage::RtcpPacket`: only the encoder can answer them, and upstream's
  terminus swallowed them. It sits at the new `Slot::KeyFrameRequests` (14 000, past every
  default interceptor). `configure_key_frame_requests(registry)` registers it, and
  `register_default_interceptors` now does too: an application using the defaults gets the
  compound RTCP packets that carry a PLI or FIR (other RTCP still ends at the terminus).
- **ice**: `MulticastDnsMode::QueryAndGather` without `multicast_dns_local_ip` publishes every
  local address under its own `<uuid>.local` name, IPv4 and IPv6, UDP and TCP candidates alike,
  as browsers do. Each name is made when the address's first host candidate is added and kept for
  its other candidates and across ICE restarts; at most `rtc_mdns::MAX_LOCAL_NAMES` (64) are
  published, and a host candidate past that is dropped rather than sent with its address. Before,
  this mode's one name pointed at 127.0.0.1 and no candidate was hidden. With
  `multicast_dns_local_ip` set, that address's candidates are hidden behind
  `multicast_dns_local_name` as before, now its TCP candidates too.
- **mdns**: `Mdns::add_local_name(name, ip)` answers for a name with its own address: an A record
  for IPv4, an AAAA record for IPv6, each only to a question for its type (or ANY). Queries ask
  for both A and AAAA, and AAAA answers resolve (to IPv6 candidates).
- **shared**: `try_frame_packet` (RFC 4571 framing without the panic) and
  `TcpFrameDecoder::push`, which refuses data past the decoder's limit (`DEFAULT_MAX_BUFFERED`,
  two whole frames, or `with_max_buffered`) instead of growing without bound.
- **ice**: `TcpType::complement`.

### Bug Fixes

- **ice**: a peer-reflexive candidate learned over TCP takes the TCP type that pairs with the
  local candidate its check arrived on (active for a check on a passive candidate). It had none,
  so it paired with nothing; a controlling agent, which only checks and nominates pairs it has,
  never connected to a peer that dialled its passive candidate (a browser answering with active
  TCP candidates, for one). Signalled active candidates are still not added (they have no port).
- **ice**: an inbound TCP packet's local address matches a candidate's exact address before an
  active candidate's IP-only match, so a connection accepted on a passive candidate is no longer
  credited to an active candidate on the same IP listed before it.
- **peer_connection**: a datagram between port 5353 on both ends (the mDNS socket) goes to the
  ICE agent whatever its first byte. RFC 7983's ranges don't apply to DNS: a message ID in the
  DTLS or SRTP range sent the answer to DTLS or SRTP.
- **mdns**: answers for registered names are sent from the IPv4 side for IPv6 records too (they go
  to the IPv4 group).

### Performance

- **shared**: `TcpFrameDecoder::next_packet` is amortised O(1) in the buffered length (the consumed
  prefix is compacted only once it outweighs the rest), not a shift of the whole buffer per packet.

### Testing

- `tests/ice_tcp_rtc2rtc.rs`: two peers over ICE-TCP on a simulated network (RFC 4571 frames
  reassembled by `TcpFrameDecoder`, virtual time), active offerer with passive answerer and
  passive controlling offerer with active answerer, carrying a 60 000-byte message and 50 ordered
  ones over one connection. Agent tests for the peer-reflexive TCP type, signalled active
  candidates and exact address matching; mDNS tests for per-address names, IPv4/IPv6 resolution
  between two agents, the fixed-IP form's TCP candidates, A/AAAA questions and the name cap;
  interceptor tests for PLI/FIR delivery; a demuxer test for mDNS routing; framing tests for the
  bound and compaction.
- Fuzzing: `rtc-ice/fuzz` target `agent_mdns_and_tcp`, an agent publishing mDNS names with
  ICE-TCP candidates fed arbitrary mDNS datagrams, TCP traffic and remote candidate lines.

## [0.21.1+brainwires.1] - 2026-11-13

First Brainwires fork release on upstream 0.21. It merges webrtc-rs/rtc master through `0fbcaa74`
(v0.21.1 plus later fixes; the upstream entries follow under "Upstream changes merged") and adds
the fork's own hardening. `FORK.md` lists everything the fork carries over upstream.

### Security

- DTLS: handshake fragment reassembly is iterative and bounded (at most 256 fragments per message
  and 32 buffered messages), so a peer can no longer overflow the stack or grow the buffer
  without limit. The queue of records awaiting decryption (64) and the handshake cache (64) are
  bounded.
- DTLS: the default WebRTC cipher suites are AEAD only (AES-128-GCM, ChaCha20-Poly1305). The
  AES-256-CBC-SHA suites are no longer offered by default. To opt back in, list them explicitly:

  ```rust
  use dtls::cipher_suite::CipherSuiteId;
  let setting_engine = SettingEngineBuilder::new()
      .with_dtls_cipher_suites(vec![
          CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
          CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
          CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha,
      ])
      .build();
  ```
- SRTP/SRTCP: per-SSRC state is created only once a packet authenticates.
- SRTCP (AES-CM/HMAC profiles): a packet with the E flag clear was returned as plaintext
  without checking its authentication tag, so anyone could inject RTCP (BYE, REMB, ...) with no
  keys. The tag is now verified first, whatever the E flag says (RFC 3711 §3.4). The AEAD
  profiles were not affected.
- DTLS: a ChangeCipherSpec is acted on only for the handshake's 0 to 1 epoch transition, before
  the handshake completes. A spoofed one after the handshake used to move the peer's epoch on,
  after which every genuine record was dropped as old (a keyless denial of service), and each
  claimed epoch added a replay detector.
- ICE: once a pair is selected, non-STUN datagrams from any address but its remote are dropped.
  Role conflicts are handled only for requests that pass MESSAGE-INTEGRITY. Consent freshness is
  judged on authenticated STUN only. Remote candidates (256) and pending mDNS queries (32) are
  capped.
- SCTP: FORWARD-TSN processing no longer steps one TSN at a time (a cumulative TSN 2^31 ahead
  spun for billions of iterations); a SACK acknowledging never-sent DATA is ignored; DATA more than
  65535 TSNs past the cumulative TSN, or on a stream id past the negotiated count, is dropped.
- TURN client: STUN messages and ChannelData are accepted only from the configured servers.
- TURN client: a response to an authenticated request (Allocate after the 401 exchange, Refresh,
  CreatePermission, ChannelBind; success or error) must carry a MESSAGE-INTEGRITY made with the
  long-term key the request was signed with. One that does not is dropped and the transaction
  keeps retransmitting. Only 401 and 438 error responses, which servers send unsigned, may lack
  it (RFC 8489 §9.2.4). A forged LIFETIME=0 Refresh response no longer releases an allocation.
- DCEP: the stack's internal message types 0x00 (threshold) and 0x01 (close) are refused by
  type when they arrive from the peer, before their body is read.
- ICE: mDNS answers are taken only from the mDNS socket (the one bound to port 5353), not from
  any datagram whose source port is 5353, which let a sender point a `.local` candidate at an
  address of its choosing. mDNS-resolved candidates count against the 256-candidate cap.
- Data channels: an in-band channel the peer opens on a stream id of this side's parity (even for
  the DTLS client, odd for the server, RFC 8832 §6) is refused and its stream reset, so the peer
  cannot take an id this side may assign. Negotiated channels are unaffected.
- Depacketizers: AV1 reassembly across packets is bounded at 4 MiB and appends in place (it
  copied the whole buffer for every packet, quadratic in the fragment count). VP9 reference
  indices describe the current packet only (they accumulated, so a long-lived depacketizer
  failed every flexible-mode packet after the second), and a scalability structure replaces the
  previous picture-group description instead of appending to it.
- RTP: the header extension block is always consumed whole, so a one-byte block containing
  ID 15 no longer leaves its remainder at the front of the payload, and an item longer than its
  block is an error instead of swallowing payload bytes. `Header::marshal_size()` now matches the
  wire, which the SRTP keystream offset depends on; a header that claimed more than the packet
  made SRTP's AEAD cipher panic splitting it (found by the `context_decrypt` fuzz target).
- RTCP: Slice Loss Indication is payload-specific feedback (PT 206, RFC 4585 §6.3.2); it was
  marshalled as, and only parsed from, PT 205, so a received SLI never parsed.
- Media writers: the IVF writer's frame buffer is bounded at 16 MiB and the H.265 writer's FU
  reassembly at 4 MiB; an H.265 fragment with no start fragment is skipped.
- Malformed peer input is an error instead of a panic: DTLS handshake message_seq exhaustion and
  a ChangeCipherSpec at the last epoch; SCTP error causes longer than their ABORT/ERROR chunk
  (reachable on an association's first packet) and TSN arithmetic at the u32 wrap (a peer initial
  TSN of 0, FORWARD-TSN to u32::MAX, fragmented messages across the wrap, reconfig sequence
  numbers); a DCEP threshold message without its body (also found by the
  `data_channel_handle_dcep` fuzz target); ICE candidates with a component outside
  1..=256 (they underflowed the priority); a remote numeric mid of `isize::MAX` (the next local
  offer overflowed); RTCP FIR / transport-cc length multiplication in `u16`; the sample builder's
  drop counters and the OGG writer's granule position on wrapping or reordered timestamps.
- NACK responder: each packet is resent at most once per 20 ms however often it is NACKed, and
  the retransmission queue is bounded.
- Depacketizers: H.264 FU-A reassembly needs a start fragment and is bounded at 4 MiB; a one-byte
  AV1 OBU claiming an extension header is rejected instead of panicking.
- SDP: the sha-256 `a=fingerprint` is used when a section lists several (it used to take the first
  and could reject a valid peer); DTLS verification skips non-sha-256 entries.
- Fuzzing CI fails on crashes again (`set -o pipefail`), runs with debug assertions and overflow
  checks, and gains stateful SCTP targets (checksum-fixed packet parsing, a server endpoint and
  association driven by datagram sequences).
- Dependency audit: a new `audit` workflow runs `cargo generate-lockfile` and `cargo deny check
  advisories` on every pull request, twice: on the library's graph (normal and build
  dependencies, all features), where nothing is ignored, and on the whole workspace. The interop
  dev-dependency moves from `webrtc` 0.14 to 0.17.3, the last release of that independent
  implementation, whose DTLS uses `p256` 0.14 (`crypto-bigint` 0.7.11, past RUSTSEC-2026-0387)
  and no `bincode` (RUSTSEC-2025-0141). The examples' signaling, `rtc-signal` and the `rtc-ice`
  ping-pong example move from `hyper` 0.14 to `hyper` 1 (HTTP/1 only), so `h2` 0.3
  (RUSTSEC-2026-0258) is gone. None of these reached the library's own dependency graph.
- Fuzzing: stateful targets that drive the real state machines, deterministically (seeded
  randomness, a fixed key exchange and certificate, the clock passed in, no sockets): a DTLS
  handshake to an in-memory peer with records injected before, during and after it — plaintext or
  encrypted under the peer's keys, so they reach the fragment buffer, the handshake cache, epoch
  handling and GCM / CCM / ChaCha20 / CBC decryption (`rtc-dtls`, `conn_handle_records`);
  SRTP/SRTCP decryption with fixed keys, of raw packets and of packets the sender protected
  (`rtc-srtp`, `context_decrypt`); an ICE agent fed authenticated binding requests and responses
  and non-STUN datagrams in the Checking, Connected and Failed states and across restarts
  (`rtc-ice`, `agent_handle_inbound`); a TURN client fed server responses, Data indications and
  ChannelData (`rtc-turn`, `client_handle_inbound`); the data-channel handler fed DCEP and user
  messages (`rtc`, `data_channel_handle_dcep`); and the H.264, H.265, VP8, VP9, AV1 and Opus
  depacketizers fed payload sequences (`rtc-rtp`, `depacketize_sequence`). All run in the fuzz
  workflow and OSS-Fuzz.

### Fork features kept across the sync

- TWCC GCC interceptor with `GccHandle` (beside upstream's GCC), the adaptive jitter buffer
  (`AdaptiveJitterBuffer*`), `rtc-interceptor-derive` and `Interceptor::with`, DTLS restart on ICE
  restart (now only when the remote fingerprint or DTLS role changes), RRID association for RTX
  simulcast, rejected m-lines in answers, `RTCConfiguration` serde, RTP marshal bounds checks,
  TURN accessors and the TCP TURN example (now with TURN stream framing).

### Upstream removals not taken

- ULPFEC stays in the default codecs; `write_rtp` keeps its payload-type fallback and passes
  un-negotiated header extensions through; a Relay policy without a TURN URL is accepted with a
  warning; the `openssl` / `vendored-openssl` / `pem` features and `RTCCertificate::from_key_pair`
  are kept.

### Breaking changes (upstream replacements taken, no shims)

| Removed | Use instead |
|---|---|
| `dtls::crypto::CryptoPrivateKeyKind` and `CryptoPrivateKey::{kind, serialized_der}` | `CryptoPrivateKey::signing_key` (`Arc<dyn crypto::SigningKey>`); export with `SigningKey::to_pkcs8_der()` |
| `KeyingMaterialExporter` trait | the inherent `dtls::state::State::export_keying_material` |
| `srtp` `extract_session_keys_from_dtls` | `set_session_keys_from_keying_material` |
| `MessageIntegrity::default()` (an empty key) | `MessageIntegrity::new_short_term_integrity_with_provider` / `new_long_term_integrity_with_provider` / `new_raw_integrity_with_provider` |
| `FnTimeGen` / the packetizer's `time_gen` | pass the time: `new_packetizer(now, …)`, `packetize(now, …)` |
| `rtc_interceptor::Packet` as the chain's message type | `AttributedPacket { attributes, packet: Packet }` (`TaggedPacket` now carries it; match on `msg.message.packet`) |
| `SettingEngine::set_*` setters | `SettingEngineBuilder::new().with_*(…).build()` (every former setter has a `with_*`) |

### Fixed

- `test_ice_restart_by_rtc_interop` is no longer ignored and passes, with
  `test_ice_restart_interop`: the DTLS session is kept across an ICE restart that changes nothing
  DTLS depends on.
- The release workflow finds `cliff.toml`. The GCC docs cite draft-ietf-rmcat-gcc-02, not RFC 8698.

## Upstream changes merged (webrtc-rs/rtc 0.21.x through `0fbcaa74`)

### Added

- `RTCCrypto::new_hmac` returns a keyed `Mac` whose key schedule is derived once, mirroring the
  existing keyed cipher factories. It replaces the removed one-shot `hmac`/`verify_hmac`.
- **New `rtc-crypto` crate: a provider-neutral cryptographic API**
  ([webrtc#839](https://github.com/webrtc-rs/webrtc/issues/839),
  [rtc#128](https://github.com/webrtc-rs/rtc/issues/128)). `RTCCryptoProvider` bundles an
  `RTCCrypto` operations trait and an `RTCRandom` CSPRNG. Two built-in providers ship,
  `RingProvider` and `AwsLcRsProvider`, and applications can supply their own — for OpenSSL, a
  FIPS-validated module, an HSM, or a platform backend — by implementing the public traits. A
  reusable conformance suite (`rtc_crypto::conformance::assert_provider`, behind the
  `test-support` feature) validates any implementation against the same RFC vectors the built-ins
  pass.
- `SettingEngine::set_crypto_provider` selects the provider per peer connection. Two peer
  connections in one process may use different providers. There is no process-global provider to
  install.
- Explicit provider constructors on the standalone protocol crates:
  `rtc_dtls::ConfigBuilder::with_crypto_provider`, `rtc_srtp::Context::new_with_provider`, and
  `MessageIntegrity::{new_raw,new_short_term,new_long_term}_integrity_with_provider`.
- Provider-neutral certificate construction: `RTCCertificate::generate`,
  `RTCCertificate::generate_from_signing_key`, and `RTCCertificate::from_pkcs8`.
  `rcgen::CertificateParams` is re-exported from `rtc::peer_connection::certificate`, so callers
  no longer need a direct `rcgen` dependency to name it.
- DTLS record-protection benchmarks (`cargo bench --package rtc-dtls --bench record_protection`)
  and SRTP AEAD plus context-construction benchmarks, all reporting each enabled provider under
  identical inputs and separating one-time key-schedule cost from per-packet cost.

### Changed

- **No library code resolves a default crypto provider.** `crypto::default_provider()` is now
  called in exactly one place — peer-connection construction — where the application either
  supplied one via `SettingEngine::set_crypto_provider` or gets the feature-selected built-in.
  Every constructor below that takes an `Arc<dyn RTCCryptoProvider>` from its caller, so a
  `--no-default-features` build fails at configuration time instead of deep inside a handshake.
  The `*_with_provider` constructor pairs are collapsed into single provider-taking constructors
  (`Context::new`, `Client::new`, `Agent::new`, `Certificate::generate_self_signed`,
  `Certificate::from_pem`, `RTCCertificate::from_pem`, `RTCCertificate::get_fingerprints`, the
  `MessageIntegrity` constructors). `Default` impls that resolved a provider — `HandshakeConfig`,
  `rtc_dtls::State`, `Agent`, `RTCDtlsTransport` — are removed in favour of those constructors,
  and `ConfigBuilder::build` errors when no provider was configured rather than inventing one.
- Each protocol crate re-exports the crypto API (`rtc_srtp::crypto`, `rtc_stun::crypto`,
  `rtc_ice::crypto`, `rtc_turn::crypto`, `rtc_dtls::crypto_provider`) so standalone users can name
  `Arc<dyn RTCCryptoProvider>` without a direct `rtc-crypto` dependency.
- **`crypto-ring` and `crypto-aws-lc-rs` Cargo features are now additive.** Enabling both builds successfully
  and is covered in CI. Previously each of `rtc`, `rtc-dtls`, `rtc-srtp`, and `rtc-stun` carried a
  `compile_error!` rejecting the combination, which made an otherwise valid build fail whenever
  Cargo feature unification pulled in both. `rtc_crypto::default_provider()` still prefers `ring`
  when both are enabled, so default behaviour is unchanged.
- DTLS, SRTP, STUN, ICE, TURN, and the top-level `rtc` crate perform all cryptography through the
  configured provider. Protocol composition is unchanged and stays in its own crate: the TLS 1.2
  PRF in DTLS, SRTP key derivation and packet layout in SRTP, STUN integrity framing in STUN.
  Default algorithm selection and wire behaviour are unchanged.
- `rtc_dtls::State::export_keying_material` is now an inherent method returning `SecretVec`, and
  `rtc_srtp::Config::set_session_keys_from_keying_material` consumes the exported bytes. The
  top-level crate performs the handoff, so `rtc-srtp` and `rtc-dtls` remain independent of each
  other. `rtc_srtp::config::LABEL_EXTRACTOR_DTLS_SRTP` is now public for standalone callers.
- `rtc_stun::MessageIntegrity` changed from a public tuple struct to named fields and now holds
  its provider, because `Setter::add_to` and `check` have no parameter through which to receive
  one. Its key is stored as a `SecretVec`.
- **`MediaEngine::register_default_codecs` no longer registers `video/ulpfec`**
  ([#837](https://github.com/webrtc-rs/webrtc/issues/837)). The receive path does not recover
  media from ULPFEC packets, so offering the codec invited peers to send repair packets that
  could not be used. Applications that want it can still register it explicitly with
  `MIME_TYPE_ULP_FEC`, which remains public. **This changes the default offer's SDP**: payload
  type 116 is no longer present. ULPFEC will return to the defaults once receive-side recovery
  is implemented.
- Upgrade `nix` to the newer version that allow compile `ohos` targets.

### Deprecated

-

### Removed

These are deliberate pre-1.0 API removals, not behaviour changes. Every entry has a replacement;
see `docs/crypto-provider-migration.md` for before/after examples.

- Removed the partial `openssl` and `vendored-openssl` Cargo features from `rtc-srtp` and `rtc`; SRTP cryptography now uses the selected `rtc-crypto` provider for every protection profile. They selected only an alternate AES-CTR path and never implemented the full provider contract. An OpenSSL backend can return as a complete downstream `RTCCryptoProvider`.
- Removed `rtc_shared::crypto::KeyingMaterialExporter`. `rtc-shared` performs no cryptography and
  no longer carries a crypto bridge.
- Removed `rtc_srtp::Config::extract_session_keys_from_dtls`; use
  `set_session_keys_from_keying_material` with material exported from the DTLS session.
- Removed the default-resolving `MessageIntegrity::{new_raw_integrity, new_short_term_integrity,
  new_long_term_integrity}` constructors and the derived `Default` impl. `Default` produced a
  credential with an empty key, which is never valid; use the `_with_provider` constructors.
- Removed `rtc_dtls::crypto::CustomSigner` and `CryptoPrivateKey::from_custom_signer`. Implement
  `rtc_crypto::SigningKey` and use `CryptoPrivateKey::from_signing_key`. This is a superset of the
  old capability: non-exportable HSM and KMS keys are supported, and `to_pkcs8_der()` returns
  `Ok(None)` for them instead of fabricating key bytes.
- Removed `CryptoPrivateKey::from_key_pair`, its `TryFrom<&rcgen::KeyPair>` impl, and the
  `serialized_der` field.
- Removed `RTCCertificate::from_key_pair` and `from_key_pair_with_provider`; use
  `RTCCertificate::generate` or `generate_from_signing_key`.
- Removed the `Sec1`, `P256`, `RcGen`, `AesGcm`, and `Aes` variants from `rtc_shared::Error`,
  along with the `sec1`, `p256`, `rcgen`, `aes`, and `aes-gcm` dependencies of `rtc-shared`. These
  put crypto-crate types in the public API of every crate in the workspace and pinned their major
  versions there. Crypto failures now cross crate boundaries as `Error::Crypto(String)`.
- Removed `RTCCrypto::hmac` and `RTCCrypto::verify_hmac`. They are exactly
  `new_hmac(..)?.sign(..)` and `new_hmac(..)?.verify(..)`, and retaining them preserved a path
  that re-derives the HMAC key schedule on every call.
- Removed the four duplicated `compile_error!` backend guards and the four
  `extern crate aws_lc_rs as ring;` aliases.

### Fixed

- A message that reaches a peer in the same read sweep as the COOKIE-ACK (or COOKIE-ECHO) that
  completes its SCTP handshake is no longer dropped. The data now waits for
  `SCTPHandshakeComplete`, on which negotiated data channels open; it used to reach the data
  channel handler first and be discarded with `ErrDataChannelNotExisted`, after SCTP had already
  acknowledged it, so the first message the peer sent on a negotiated channel could be lost.
- ICE: a controlling agent now answers a Binding request that carries USE-CANDIDATE without
  ICE-CONTROLLING, and ignores the USE-CANDIDATE, instead of dropping it with
  `ErrUnexpectedStunrequestMessage`. Peers that always act as controlling can now complete ICE
  ([#299](https://github.com/webrtc-rs/rtc/issues/299)).
- ICE: the controlling agent now sends a triggered check (RFC 8445 §7.3.1.4) when a Binding
  request arrives on a pair it had marked Failed, so a late-opening direct path is no longer
  lost to the relay ([#282](https://github.com/webrtc-rs/rtc/issues/282)).
- Incoming RTCP reaches `get_stats()` again. Receiver reports, NACK, PLI and FIR now update the
  outbound stream's remote-inbound and feedback counts, and sender reports update the inbound
  stream. The read-side stats hook was lost when the interceptor started consuming RTCP
  ([#310](https://github.com/webrtc-rs/rtc/issues/310)).

- Ignore unrelated post-handshake DTLS records without consuming the final-flight
  retry budget or modifying the completed handshake cache.

- Preserve the DTLS retransmission deadline when a repeated or incomplete peer flight
  arrives while waiting for the next flight.

- `rtc-crypto`'s AES-CTR keystream now uses a batched implementation instead of one
  `encrypt_block` call per 16-byte block, which defeated AES-NI / ARMv8 instruction pipelining.
  Roughly 9-10% faster on a 1200-byte SRTP payload.
- **SRTP no longer derives the HMAC key schedule on every packet.** `RTCCrypto::new_hmac` returns
  a keyed `Mac`, and `rtc-srtp` keys its SRTP and SRTCP MACs once per context instead of passing
  raw key bytes per packet. Roughly 40% faster per RTCP packet and 7% per 1200-byte RTP packet.
  A counting provider in `rtc-srtp/tests/provider_profiles.rs` guards the invariant.
- **DTLS CBC no longer derives its record MAC key on every record.** `CryptoCbc` holds two keyed
  `Mac` objects instead of passing raw key bytes to `prf_mac` per record: ~4% faster on encrypt and
  ~7% on decrypt, with the key schedule moving to epoch setup.
- STUN `MESSAGE-INTEGRITY` was measured against its pre-migration baseline and shows no regression
  (see `rtc-stun/benches/README.md`); it already used `ring`'s HMAC-SHA1 before G3.
- **The built-in `RTCRandom` implementations no longer read the operating system on every call.**
  DTLS generates a GCM explicit nonce and a CBC record IV per record; routing those through the
  backend's `SystemRandom` cost ~829 ns on `ring` and ~2196 ns on `aws-lc-rs`, against ~8 ns for
  the thread-local CSPRNG the pre-provider code used. They now use an OS-seeded, periodically
  reseeded thread-local CSPRNG, as BoringSSL and OpenSSL do internally. `SystemRandom` is still
  used where the backend owns the operation — keypair generation and signing. DTLS GCM encryption
  went from 1.015 µs to 262 ns per record. A deployment needing validated entropy everywhere
  supplies its own `RTCRandom`.
- **The `ring` provider composes RustCrypto's HMAC-SHA1.** `ring` exposes SHA-1 only as
  `HMAC_SHA1_FOR_LEGACY_USE_ONLY` and does not use the ARMv8 SHA-1 instructions: 4469 ns against
  RustCrypto's 1373 ns over a 1212-byte message. The built-in providers are already composite —
  AES-CTR, CCM, CBC and MD5 come from RustCrypto — so HMAC-SHA1 is composed the same way. This
  closes the gap without making `aws-lc-rs` the default, which would impose the `aws-lc-sys` C
  toolchain on every downstream build. SHA-256 stays on `ring`; `aws-lc-rs` keeps its own SHA-1.

**Net effect: every per-packet and per-record benchmark is at parity with or faster than the
pre-migration baseline on the default provider.** SRTP AES-CM/HMAC RTP encryption 1.725 µs before
and 1.723 µs after; DTLS GCM record encryption 270.5 ns before and 270.1 ns after; DTLS CBC 6-8%
faster than before. Context and epoch setup costs rose, which is the intended trade — key
schedules moved off the per-packet path. See the three `benches/README.md` files for the full
tables and methodology.

- Add RSA as an allowed private key kind in rtc_dtls::ConfigBuilder::
  validate- [PR #141](https://github.com/webrtc-rs/rtc/pull/141)

### Security

-

## [0.20.0] - 2026-07-31

### Added

- The `rtc` v0.20.0 is Sans-I/O protocol core with complete WebRTC stack (95%+ W3C API compliance)

[Unreleased]: https://github.com/webrtc-rs/rtc/compare/0.20.0...HEAD

[0.20.1]: https://github.com/webrtc-rs/rtc/compare/0.20.0...0.20.1

[0.20.0]: https://github.com/webrtc-rs/rtc/releases/tag/0.20.0

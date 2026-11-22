# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking changes

- **sframe**: the SFrame RTP payload format and `[[useSFrame]]` (pc-18), pinned to
  draft-ietf-avtcore-rtp-sframe-03 (21 October 2026).
  - `rtc::rtp::codec::sframe`: `SFramePayloader` (the S / E / T payload descriptor, origin
    raw or packetized), `SFrameDepacketizer`, and `SFrameReassembler`, the receive algorithm
    of section 5.2 over packets in any order with a bounded buffer.
  - `rtc::sframe::derive_ssrc_key`: the per-SSRC key of section 7.
  - `RTCRtpTransceiver::use_sframe` / `set_transform_use_sframe` (webrtc-encoded-transform
    2.1, 2.2): an SFrame transform puts `a=sframe` in the media section; a remote
    description's `a=sframe` sets it; the other kind of transform is then an
    InvalidModificationError. An answer that leaves out the offered `a=sframe` stops the
    offerer's media (`write_rtp` refused with the new `Error::ErrSFrameRefused`, received RTP
    discarded), `RTCRtpTransceiver::sframe_refused`.
- **webrtc-extensions** (pc-17).
  - `RTCRtpEncodingParameters` has `scale_resolution_down_to: Option<RTCResolutionRestriction>`,
    `ptime: Option<u32>` and `adaptive_ptime: bool` (section 5): validated in addTransceiver
    (OperationError) and setParameters (InvalidModificationError); `adaptive_ptime` with
    `ptime` is an InvalidModificationError; `scale_down_factor(width, height)` gives the
    encoder's factor (never an upscale, orientation agnostic). A struct literal needs the
    new fields.
  - `RTCRtpHeaderEncryptionPolicy::default()` is `Negotiate` (W3C 10.2), so a connection
    offers and answers `a=cryptex` unless configured otherwise; `RTCConfiguration` has
    `rtp_header_encryption_policy` and `always_negotiate_data_channels`
    (`RTCConfigurationBuilder::with_rtp_header_encryption_policy`,
    `with_always_negotiate_data_channels`), and `set_configuration` refuses another value
    (InvalidModificationError). `set_rtp_header_encryption_policy` and
    `set_always_negotiate_data_channels` return `Result<()>` and are refused once a
    description was set.
  - Events `OnSsrcChange(receiver)` and `OnCsrcChange(receiver)` (section 11:
    `ssrcchange`, `csrcchange`), `OnIceCandidatePairNominate(pair)` (section 7).
  - Cancelable nomination (section 7): `SettingEngineBuilder::with_candidate_pair_proposals`
    has the controlling agent propose each nomination; `resolve_candidate_pair_nomination`
    accepts or cancels it; `select_candidate_pair` / `remove_candidate_pair` refuse while a
    proposal is pending. rtc-ice: `AgentConfig::candidate_pair_proposals`,
    `Event::CandidatePairNominationProposed`, `Agent::proposal_pending`,
    `Agent::resolve_nomination_proposal` (additive; an `AgentConfig` literal needs the field).
  - Header extension control (section 4.1): an extension the section's negotiated direction
    leaves no use for is "stopped" after the answer.
- **jsep**: what descriptions say of the selected ICE pair (RFC 8839 sections 4.2.1.2, 4.3.4,
  4.4.1.2.2, 4.4.1.3, 4.4.2, 5.1, 5.2; RFC 8445 section 8.2). Descriptions differ on the wire:
  - Once ICE has selected a pair (and no restart is staged), the `m=` / `c=` destination of
    later offers and answers is the pair's local candidate; an offer of the controlling agent
    carries `a=remote-candidates:1 <address> <port>` of its remote candidate, and an answer to
    such an offer takes the local candidate it names as its destination.
  - Every candidate line a description carries ends with the `ufrag` extension (the section's
    `ice-ufrag`). A trickled candidate without `usernameFragment` whose line's `ufrag` names
    another ICE generation is ignored (RFC 8838 section 9).
  - A remote `a=remote-candidates` line that does not parse refuses the description (RFC 9429
    section 5.8.2).
  - Two lite agents: the controlling one's `Event::LiteCandidateUpdate` raises
    negotiation-needed; its next offer lists the chosen local candidate alone with
    `a=remote-candidates`, and the controlled peer connection applies it with
    `ice::Agent::replace_remote_candidates`, its answer listing the named candidate alone.
- **jsep**: a rolled-back remote offer leaves the transports as they were (RFC 9429 section
  5.7). The answerer's ICE and DTLS transports take a remote offer's parameters when the local
  answer (or provisional answer) is applied, not when the offer is: the first offer starts
  ICE and DTLS then, an offer with new ICE credentials restarts ICE then, an offer that asks
  for a new DTLS association (another `tls-id`, fingerprint or role) replaces it then, and the
  candidates of the offer's ICE generation, in the description or trickled, reach the agent
  then. What the answer states is staged when the offer is applied (the restart's new local
  credentials, the new association's `a=setup` role and `tls-id`) and dropped by a rollback.
  Observable: after `set_remote_description(offer)` the answerer's ICE transport is still
  `new` until `set_local_description(answer)`. New `ice::Agent::discard_restart_credentials`.
- **media_stream**: remote tracks and the mediacapture-main model (pc-16).
  - `MediaStreamTrack::apply_constraints` returns `Result<()>`: on a remote track (a
    receiver's; new `is_remote()`) constraints naming `width`, `height`, `frameRate` or
    `aspectRatio` are `Error::OverconstrainedError(<property>)` (webrtc-pc 9.3.1);
    `apply_constraints(None)` now clears the constraints. New error variant
    `Error::OverconstrainedError` in rtc-shared.
  - `Constrain` and `ConstrainRange` are public (`ConstrainRange`'s members are `Option`);
    `MediaTrackConstraintSet::with_width` / `with_height` / `with_aspect_ratio` /
    `with_frame_rate` and getters, `MediaTrackConstraints::new` / `basic` / `advanced`.
  - Remote video settings (webrtc-pc 9.3.1): new `RTCRtpReceiver::report_received_frame(now,
    width, height)`, the feed the application's decoder or depacketizer supplies; the
    track's `MediaTrackSettings::width` / `height` / `aspect_ratio` / `frame_rate` report the
    latest frame and an estimate over the last second. New `RTCRtpReceiver::track_mut`.
  - mediacapture-main: `generate_id()` (UUID version 4), `MediaStream::with_generated_id`,
    `MediaStream::clone_stream`, `MediaStreamTrack::with_generated_id`,
    `MediaStreamTrack::clone_track`; `MediaStreamTrackEvent` / `MediaStreamTrackEventKind`
    and `RTCRemoteStreamsChange::media_stream_track_events` (addtrack / removetrack).
  - Fixed: a transceiver that `stop()` made stopping still handed the RTP that kept arriving
    to the application; its receiver receives nothing any more (webrtc-pc 5.4).
- **peer_connection**: the open webrtc-pc rows of the W3C object model (pc-15).
  - `RTCRtpTransceiver::current_direction()` returns `Option<RTCRtpTransceiverDirection>`:
    `None` (W3C null) before an exchange has negotiated the transceiver.
  - `Default` for `RTCIceTransportPolicy`, `RTCBundlePolicy` and `RTCRtcpMuxPolicy` is the
    W3C default (`All`, `Balanced`, `Require`; serialised "all", "balanced", "require"), not
    `Unspecified`; `Unspecified` still behaves as those. `RTCRtcpMuxPolicy::Negotiate` is
    documented as RFC 9429's policy, an engine setting outside the W3C enum.
  - `add_remote_candidate` refuses a candidate that names neither `sdp_mid` nor
    `sdp_mline_index` (`Error::TypeError`), and every call on a closed connection
    (`ErrConnectionClosed`), as `add_local_candidate` now does too. A candidate for a media
    section whose transceiver is stopped is ignored.
  - A remote candidate on a port of the Fetch bad-port list, and an mDNS candidate under the
    "relay" policy, is administratively prohibited: written into the remote description and
    listed, kept in the stats report, never given to the ICE agent.
  - `RTCIceTransport::get_remote_candidates()` lists the remote description's candidates
    (never a peer-reflexive one the agent learned); `get_local_parameters()` is `None` until
    a local description is set and reads it; `role()` is `Unspecified` ("unknown") until the
    first offer, and a local offer makes it controlling at once;
    `get_selected_candidate_pair()` is `None` in the new and closed states.
  - `set_local_description` takes `RTCSessionDescription::default()`: without a type it is an
    offer in stable / have-local-offer / have-remote-pranswer and an answer otherwise, and
    without an sdp the connection creates the offer or answer.
  - Negotiation-needed is false with no current local description and nothing to negotiate
    (a rollback to an empty stable state no longer fires it).
  - New `RTCPeerConnection::add_track_with_streams(track, streams)` (W3C `addTrack` with
    streams). A sender whose transceiver negotiated a direction without send lists no codecs
    in `get_parameters`. `close()` sets every data channel's state to closed without an
    event. `iceCandidatePoolSize` is fixed once `set_local_description` has been called,
    after a rollback too.
- **jsep**: a rolled-back remote offer leaves the transports as they were (RFC 9429 section
  5.7). The answerer's ICE and DTLS transports take a remote offer's parameters when the local
  answer (or provisional answer) is applied, not when the offer is: the first offer starts
  ICE and DTLS then, an offer with new ICE credentials restarts ICE then, an offer that asks
  for a new DTLS association (another `tls-id`, fingerprint or role) replaces it then, and the
  candidates of the offer's ICE generation, in the description or trickled, reach the agent
  then. What the answer states is staged when the offer is applied (the restart's new local
  credentials, the new association's `a=setup` role and `tls-id`) and dropped by a rollback.
  Observable: after `set_remote_description(offer)` the answerer's ICE transport is still
  `new` until `set_local_description(answer)`. New `ice::Agent::discard_restart_credentials`.
- **jsep**: small rules.
  - `RTCRtpSender::write_rtp` takes out the header extension elements whose id is not
    negotiated for the sender (RFC 8285 section 4.1.2); they were passed through. New
    `SettingEngineBuilder::with_unnegotiated_header_extensions(true)` passes them through.
  - A remote description with `a=extmap` lines at both session and media level is refused
    (`SdpInvalidValue`, RFC 8285 section 5).
  - A remote `a=simulcast` line that does not parse (a rid-id or a direction twice, RFC 8853
    section 5.2) refuses the description (RFC 9429 section 5.8); it was ignored.
  - `RTCRtpContributingSource` has a new public field `voice_activity_flag`: the V bit of the
    client-to-mixer audio level on a synchronization source, `None` when the extension was
    negotiated `vad=off` (RFC 6464 sections 3, 4).
- **jsep**: description rules.
  - Lip synchronization groups (RFC 5888 section 7, RFC 9429 sections 5.2.1, 5.2.2, 5.3.1):
    an offer has `a=group:LS` for each stream more than one transceiver is associated with,
    and keeps the groups of the most recent answer; an answer keeps an offered group's
    transceivers that share a stream or have none, when there are two. New
    `RTCPeerConnection::remote_lip_sync_groups`.
  - Default destination (RFC 8839 section 4.2.1.2, RFC 9429 sections 5.2.1 to 5.3.2): once
    there are local candidates the `m=` port and `c=` address are the default candidate's
    (relayed, else server-reflexive, else host; never an mDNS name), shared by every bundled
    section that is not bundle-only (RFC 9143 section 7.2); a new section of an offer says
    `a=rtcp:9 IN IP4 0.0.0.0` (or the default candidate's), and no other description has
    `a=rtcp`. Descriptions with candidates differ from before.
  - A minted local SSRC is drawn again while a remote description mentions it or another
    local stream has it (RFC 5576 sections 5, 8).
- **jsep**: codec parameters, the rest.
  - H.265 formats match by their configuration (RFC 7798 section 7.2.2: `profile-space`,
    `profile-id`, `tier-flag`, `interop-constraints`, `profile-compatibility-indicator` and
    `tx-mode`, each with its section 7.1 default; `level-id` and the `sprop-*` parameters do
    not count), and an answer's `level-id` is not above the offer's. The default H.265 format
    states `level-id=93;profile-id=1;tier-flag=0;tx-mode=SRST`, so an offer of Main 10 or of
    MRST / MRMT is no longer answered with it.
  - H.264: a `packetization-mode` other than 0, 1 or 2 matches no format and has no payloader
    (it was sent as mode 1). New `RTCRtpCodec::h264_depacketizer` (mode 2 de-interleaving
    from `sprop-interleaving-depth` / `sprop-max-don-diff`), `h265_depacketizer` (DONL and
    the de-packetization buffer from `sprop-max-don-diff` / `sprop-depack-buf-nalus`; SRST
    only) and `sprop_parameter_sets` (the decoded `sprop-parameter-sets`, `sprop-vps` /
    `sprop-sps` / `sprop-pps` / `sprop-sei`).
  - `a=ptime` / `a=maxptime` (RFC 8866 sections 6.4, 6.5; Opus's `ptime` / `maxptime`, RFC
    7587 section 7): written in audio sections when set with the new
    `MediaEngine::set_audio_packet_time(RTCPacketTime)`, and the remote side's read into
    `RTCRtpTransceiver::remote_packet_time`.
  - `ccm tmmbr smaxpr=<n>` (RFC 5104 section 7.2) is answered as `ccm tmmbr` with the higher
    `smaxpr` of the two sides, and without `smaxpr` when the offer has none (an offer with
    `smaxpr` lost TMMBR before).
  - `a=rtcp-xr` (RFC 3611 section 5): an offer whose video formats take receiver reference
    times (`configure_receiver_reference_time`, part of the default interceptors) says
    `a=rtcp-xr:rcvr-rtt=all` beside `a=rtcp-fb:<pt> rrtr`, so default video offers have one
    more line. A remote `a=rtcp-xr:rcvr-rtt=<mode>` negotiates them as the `rrtr` feedback
    does; a remote `a=rtcp-xr` that does not list `rcvr-rtt` turns them off whatever its
    `a=rtcp-fb` lines say (section 5.1). An answer to an offer with the attribute states the
    offered mode it takes, or an empty `a=rtcp-xr:` (section 5.2); a session-level attribute
    applies to sections without their own.
- **jsep**: ICE options. Every description says `a=ice-options:trickle ice2` (a lite agent
  `ice2`; RFC 8445 section 10), so the line differs from before. A Ta configured with the new
  `SettingEngineBuilder::with_ice_pacing` (it was not reachable before) is proposed as
  `a=ice-pacing` (RFC 8839 section 5.5) when it is not the default, and the peer's
  `a=ice-pacing` reaches the ICE agent, which uses the higher value (RFC 8445 section 14.2).
  New `RTCPeerConnection::remote_ice_options`.
- **abs-capture-time** (webrtc-extensions 8): `RTCRtpContributingSource` gains
  `capture_timestamp` and `sender_capture_time_offset` (milliseconds; struct literals need
  them). The receiver takes them from the `abs-capture-time` extension when it was negotiated,
  or interpolates the capture time by RTP timestamp from the source's last one;
  `RTCRtpSender::write_rtp_with_capture_time` stamps a packet.

- **ice candidate pairs** (webrtc-extensions 7): new `RTCPeerConnectionEvent::
  OnIceCandidatePairAdd` / `OnIceCandidatePairRemove` (the enum is `#[non_exhaustive]`), new
  `ice::Event::CandidatePairAdded` / `CandidatePairRemoved` (an exhaustive match on the agent's
  events needs the arms), `RTCIceTransport::get_candidate_pairs`,
  `RTCPeerConnection::select_candidate_pair` / `remove_candidate_pair` (InvalidStateError when
  closed or the ICE state is new / failed / closed, new `Error::NotFoundError` for a pair not
  listed), `ice::Agent::{get_candidate_pairs, select_candidate_pair, remove_candidate_pair}`.
  A removed pair is not checked again and not listed; removing the selected pair hands the
  data to the best other valid pair. The cancelable `icecandidatepairnominate` and the
  cancelable removal proposals are not implemented.

- **rtp header extension control** (webrtc-extensions 4): `RTCRtpTransceiver::
  set_header_extensions_to_negotiate` takes a `Vec<RTCRtpHeaderExtensionToNegotiate>` (uri and
  direction, "stopped" for not negotiated) and returns a `Result`: an InvalidModificationError
  for another size, another URI at an index, the mid not "sendrecv", or a mandatory-to-implement
  extension (mid, audio level) stopped. New `get_header_extensions_to_negotiate` and
  `get_negotiated_header_extensions`. Offers carry each extension that is not stopped with its
  direction (`/inactive` too); answers carry an offered one within the offer's direction; an
  applied answer sets both lists (reversed for a remote one, stopped for one it left out); a
  new transceiver copies the list of the first of its kind that is not stopping.

- **srtp**: `RTCPeerConnectionBuilder::build` refuses an SRTP or SRTCP replay window of 1 to
  63 packets (new `Error::ErrSrtpReplayWindowTooSmall`; RFC 3711 3.3.2); it used to fail when
  the first DTLS handshake completed. DTLS-SRTP keys of the AES-CM profiles live 2^31 packets
  (RFC 5764 4.1.2; they had RFC 3711's 2^48); at a key's limit the DTLS transport fails with
  `dtls-failure` (no re-keying: a browser does not take a new DTLS association on a transport
  that has one).
- **svc**: `RTCRtpEncodingParameters` has a new public member `scalability_mode`
  (`Option<String>`, W3C webrtc-svc), validated by `add_transceiver_*` (new
  `Error::ErrOperationError`) and `set_parameters` (`InvalidModificationError`). The default
  header extensions (`register_default_interceptors`) offer the Dependency Descriptor for
  video.
- **priority**: `RTCRtpEncodingParameters` has two new public members, `priority`
  (`RTCPriorityType`, `low` by default) and `network_priority` (`Option<RTCPriorityType>`): a
  struct literal without `..Default::default()` needs them.
- **data channels** (W3C webrtc-pc 6.1, 6.2): `send()` / `send_text()` refuse on a closing
  channel (`ErrDataChannelNotOpen`; an in-band channel awaiting its ACK still accepts data, as
  RFC 8832 section 6 allows); they refuse data that would take `buffered_amount()` above the SCTP transport's
  `[[MaxBufferSize]]` (new `Error::ErrDataChannelBufferFull`): the larger of the peer's
  `max-message-size` and this side's send buffer, which the spec leaves to the implementation
  ("the size of the local send buffer", 6.1.1.2) and which is 16 MiB, Chromium's, unless
  `SettingEngineBuilder::with_data_channel_max_buffer_size` sets a limit (64 KiB, the
  larger max-message-size between two default engines, broke the browser interop echo of
  twenty 64 KiB messages; `twenty_64_kib_messages_are_echoed`,
  `a_16_mib_burst_and_back_pressure_deliver_everything`). A negotiated id at
  or above the connected transport's `maxChannels` is refused (new
  `Error::ErrDataChannelIdAboveMaxChannels`). A closed channel's stats object stays in the
  report, closed (the last 64 channels).
- **jsep**: codec parameters.
  - The default audio formats include comfort noise, `CN/8000` on payload type 13 (RFC 7874
    section 3, RFC 3389): default audio offers have one more format. New `MIME_TYPE_CN`,
    with a payloader. A track that names its codec keeps the telephone-event and CN formats on
    that codec's clock in the offer (they were dropped). A CN or telephone-event packet the
    application writes when its format is not negotiated is dropped, not rewritten to the
    media payload type.
  - Codec matching compares the channel count when both formats state one (RFC 7587 section
    7: Opus is `opus/48000/2`; a remote `opus/48000/1` is not answered).
  - H.264: an absent `packetization-mode` is 0 and an absent `profile-level-id` is `42000a`
    (RFC 6184 section 8.1); profiles compare by RFC 6184 Table 5, so `42e01f` and `4d801f`
    (both Constrained Baseline) match. Offers without these parameters are now answered.
  - AV1: formats match by `profile` (absent: 0), and an answer states this endpoint's own
    `level-idx` / `tier` (AV1 RTP section 7.2); a remote `profile=1` no longer matches a
    `profile=0` codec.
- **jsep**: header extensions per RFC 8285, RFC 6904, RFC 6464 and RFC 6465.
  - Ids up to 255: offers take 1 to 14, then 16 to 255 (never 15), and up to 254 extensions
    can be registered (`ErrRegisterHeaderExtensionNoFreeID` beyond that; it was 15).
  - `a=extmap-allow-mixed` is read at media level too and reaches the sender: without it on
    both sides a stream stays in one form (two-byte throughout once an id above 14 is
    negotiated for it, or from its first two-byte packet on); the stamped MID / RtpStreamId
    take the two-byte form when they need it instead of failing `write_rtp`.
  - A received description whose `a=extmap` lines map one id to two extensions, or one
    extension to two ids, in a section or a BUNDLE group, is refused (`SdpInvalidValue`); a
    mapping to the reserved id 15 is not used.
  - An offer's extensions numbered 4096 to 4351 are remapped to a free id and answered
    (RFC 8285 section 7), the first registered alternative of each id.
  - An extension registered for one direction says so (`a=extmap:N/recvonly`); an answer
    keeps a reversed direction only where the registration allows it, and drops the extension
    otherwise.
  - RFC 6904 header extension encryption is negotiated: `a=extmap:N
    urn:ietf:params:rtp-hdrext:encrypt <uri>` is written and read, an answer takes the
    encrypted form whenever it is offered (the clear one answered `inactive`), and the SRTP
    contexts encrypt and decrypt the negotiated ids. New
    `MediaEngine::set_header_extension_encryption` with `RTCRtpHeaderExtensionEncryption`
    (`Clear`, the default for application extensions, `BestEffort`, `Encrypted`).
  - The default interceptors register the mixer-to-client audio level
    (`urn:ietf:params:rtp-hdrext:csrc-audio-level`, receive only) and offer both audio level
    extensions encrypted as well as in the clear (RFC 8834 sections 5.2.2, 5.2.3): default
    audio offers have four more `a=extmap` lines. Registering an audio level extension for
    video, or the `encrypt` URI itself, is a `TypeError`.
  - `RTCRtpHeaderExtensionParameters` has a new public field `attributes` (the peer's
    extension attributes, e.g. `vad=off`); `encrypted` is now set.
- **states and events** (W3C webrtc-pc 4.3, 4.4.1.3, 4.4.1.5, 4.8, 4.9, 5.5, 5.6, 11, 12):
  - `RTCPeerConnectionIceEvent::candidate` is `Option<RTCIceCandidate>` (`None` is the
    "gathering complete" indication) and `url` is `Option<String>`. `RTCIceCandidate` has new
    public members `sdp_mid`, `sdp_mline_index` and `end_of_candidates`; `to_json` gives the
    candidate's own mid and index, and an empty `candidate` for an end-of-candidates
    candidate. New `RTCIceCandidate::candidate()` and `end_of_candidates_for()`.
  - The end of gathering (an empty local candidate) is an `OnIceCandidateEvent` with the
    generation's end-of-candidates candidate, the gathering state "complete" with
    `OnIceGathererStateChange` and `OnIceGatheringStateChangeEvent`, then an
    `OnIceCandidateEvent` with no candidate; once per ICE generation (a second empty candidate
    changes nothing). Gathering begins, with its events, at the first local description and
    after an ICE restart only: a later local description no longer resets the state to
    "gathering".
  - `close()` fires no `OnConnectionStateChangeEvent(Closed)` (W3C: the states are set
    "without firing any event"); it stops every transceiver and sets the ICE connection state
    to closed. What the ICE agent reports after `close()` is not delivered.
  - `RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent` now comes before the
    `OnConnectionStateChangeEvent` it causes (it came after).
  - `set_configuration` is atomic and compares the certificates with the constructor's (a
    different or missing list is `ErrModifyingCertificates`); the configuration keeps its
    certificates (`get_configuration` reports them). ICE server urls are validated as W3C
    "validate an ICE server URL" says, in the constructor too: a STUN url with a query, a
    fragment, userinfo, a path, an unknown query and an empty `urls` (new
    `Error::ErrNoIceServerUrls`) are refused; a TURN username of 509 bytes or more is
    `InvalidAccessError`. At most 32 servers are kept (`MAX_ICE_SERVERS`).
  - `restart_ice` raises negotiation-needed, and every offer restarts ICE until an answer has
    replaced the credentials (an offer that was discarded no longer consumes the request).
  - A description that does not parse is `Error::SdpSyntaxError { line_number, error }`
    (the parser's error inside); `RTCError::from_error` maps it to `sdp-syntax-error`.
  - The connection's default certificate expires 30 days after the connection is created.
  - Internal `RTCEventInternal::SCTPFailureCause` added.
- **remote tracks**: by description, not by media (W3C webrtc-pc 4.4.1.6, 5.1.1, 5.3, 9.3).
  New `RTCTrackEvent` variants: `OnRemoteTrack(RTCRemoteTrackEventInit)` (the W3C `track`
  event, queued when a description makes a transceiver receive or adds streams, with the
  receiver, transceiver, track and every msid stream), `OnMute` / `OnUnmute`,
  `OnStreamsChanged(RTCRemoteStreamsChange)`. `OnOpen` still fires per RTP stream. A
  receiver's track has an id the engine generates (not the msid appdata) and keeps it across
  descriptions; it starts muted and its first RTP packet unmutes it. An RTCP BYE mutes the
  track instead of ending it (`OnClose` no longer follows a BYE); a remote track ends only
  by negotiation: `stop()`, a rejected section, or a rollback that removes its transceiver.
  A section without `a=msid` puts the track in one random "default" stream per session
  (RFC 9429 5.8). `MediaStream` keys its tracks by track id (tracks of one stream no longer
  overwrite each other), does not add a track twice, and computes `active`.
- **rtp_transceiver**: the W3C object model (webrtc-pc 5.1 to 5.4). Every transceiver has a
  sender and a receiver: `get_senders` / `get_receivers` list those of every transceiver that
  is not stopped, whatever its direction, and `rtp_sender(id)` / `rtp_receiver(id)` exist for
  every transceiver. API changes:
  - `RTCRtpSender::track()` returns `Option<&MediaStreamTrack>` (`None` for a sender without
    a track: one made by `add_transceiver_from_kind`, or after `remove_track` /
    `replace_track(None)`); new `track_mut()`, `ssrcs()` and `streams()`.
  - `RTCRtpSender::replace_track(Option<MediaStreamTrack>)`: `None` stops sending (and
    `write_rtp` is then refused with `ErrRTPSenderTrackRemoved`); a replacement keeps the
    sender's SSRCs, msid and streams and needs no negotiation; refused when the transceiver is
    stopping (`InvalidStateError`).
  - `RTCRtpSender::set_streams` returns `Result<()>` (refused when closed); the streams are
    exactly the given ids, deduplicated; an empty list is `a=msid:-`.
  - `RTCRtpTransceiver::set_direction` returns `Result<()>`: `InvalidStateError` when stopping,
    `ErrInvalidDirection` for `Stopped` / `Unspecified`, refused when closed.
  - `RTCRtpTransceiverDirection::Stopped` (the enum is `#[non_exhaustive]`):
    `direction()` reads it once `stop()` was called, `current_direction()` once the
    transceiver is stopped. `stop()` is stopping first (the next offer rejects the section,
    an answer made before still answers it) and stopped once an exchange rejects it; it ends
    the receiver's track (`RTCTrackEvent::OnClose`). New `is_stopped()`.
  - `add_transceiver_from_kind(kind, None)` is sendrecv (W3C default) with a sender without a
    track; `RTCRtpTransceiverInit::recvonly()` and `with_direction()` give the old behaviour.
    Only the `Unspecified` kind is refused: `Application` (the fork's RTP in `m=application`,
    SMPTE ST 336) stays accepted, an extension beyond the W3C kinds.
    `add_transceiver_from_track` takes any direction. `sendEncodings` are validated (rid
    syntax: new `Error::TypeError(String)`; `RangeError`s) and normalised (audio members
    removed, at most `MAX_SEND_ENCODINGS` = 16, `scale_resolution_down_by` filled, a lone rid
    dropped).
  - `remove_track` keeps the sender (track null, direction loses send) and does nothing on a
    stopping transceiver or a sender without a track; `add_track` refuses a track a sender
    already has (`InvalidAccessError`) and reuses a trackless transceiver of its kind that is
    not stopping and never sent.
  - `set_codec_preferences` uses the codec dictionary match (clock rate, channels, fmtp),
    removes duplicates and refuses a list of only RTX / RED / FEC / CN
    (`InvalidModificationError`).
  - `get_capabilities(kind)` on senders and receivers lists the media engine's codecs (RTX
    once, without `apt`) and header extensions, with no negotiation read.
  - `RTCRtpSender::set_parameters` also refuses a changed encoding count, a codec the sender
    cannot choose and changed read-only members; `get_parameters` carries `rtcp.cname`.
  - `RTCRtpReceiver::jitter_buffer_target()` / `set_jitter_buffer_target()` (RangeError above
    4000 ms).
  - `RTCRtpContributingSource::audio_level` is `Option<f64>`: `None` when no level was received;
    contributing sources take their RFC 6465 levels. `get_contributing_sources` /
    `get_synchronization_sources` list the sources most recent first, and only those heard in
    the 10 seconds before the connection's newest time.
- **simulcast**: `a=rid` and `a=simulcast` follow RFC 8851 and RFC 8853 (`src/peer_connection/sdp/simulcast.rs`).
  `RTCRtpCodingParameters` has a new public field `rid_restrictions: RTCRtpRidRestrictions`
  (`pt=`, `max-width`, `max-height`, `max-fps`, `max-fs`, `max-br`, `max-pps`, `max-bpp`,
  `depend`; RFC 8851 section 5): struct literals need `..Default::default()`. An offer writes
  a sender encoding's restrictions on its `a=rid ... send` line (a `pt=` keeps the formats the
  section has), an answer echoes the offered restrictions with the direction reversed, and a
  receiver's coding parameters carry what the remote `a=rid ... send` line says.
  - An answer adds a `send` rid only for a `recv` rid the offer listed and the sender has an
    encoding for (RFC 8853 section 5.3.2: "MUST NOT add any simulcast streams"); it used to
    echo every offered `recv` rid as `send`, and to add the sender's own rids to an offer that
    listed none.
  - An applied answer (local or remote) leaves the sender the encodings it accepted, or its
    first encoding when it accepted none or has no simulcast (W3C webrtc-pc "set a session
    description", RFC 8853 section 5.3.3). The removed encodings leave `getParameters` and
    later offers, their streams are not bound, and `write_rtp` drops their packets. A remote
    answer's `a=rid` line that loosens a restriction or adds a `pt=` is discarded with its
    stream (RFC 8851 section 6.4); one that tightens a restriction sets it on the encoding.
  - The pause mark `~` is no longer written, neither for an inactive encoding nor echoed from
    an offer: RFC 8853 section 5.2 has it go with RFC 7728 pause / resume, which the engine
    does not implement. `SettingEngineBuilder::with_rid_pause_marks(true)` writes it as
    before (and as libwebrtc does).
  - Received lines are checked per RFC 8851 section 6.2.2: a rid-id on two lines discards
    both, a `pt=` keeps the m= line's formats only, a `recv` line with an unknown restriction
    and a line whose `depend` does not resolve are discarded; per RFC 8853 section 5.2 a
    rid-id is used only with its own direction, the first usable alternative of a stream is
    taken, and a section with more than one `a=simulcast` line (or one that repeats a rid-id)
    has no simulcast stream. A remote description whose `a=simulcast` names a rid-id without
    an `a=rid` line is refused with `SdpInvalidValue` (RFC 9429 section 5.8.3).
  - A local encoding's rid must be 1 to 255 alphanumeric characters (RFC 8852 section 3.1,
    W3C webrtc-pc addTransceiver): anything else is the new `Error::ErrRTPSenderRidInvalid`.
- **sender**: `RTCRtpSender::write_rtp` writes the MID header extension (the transceiver's mid)
  and RtpStreamId (the rid of the packet's encoding) into every packet when the extension is
  negotiated (RFC 9143 section 15, RFC 8852 section 3.3); the application had to. A packet
  that already carries the extension keeps its value.
- **media_engine**: `register_default_codecs` offers `audio/telephone-event` at 48000 Hz
  (payload type 112) and 8000 Hz (115) with the DTMF events `0-15` (RFC 7874 section 3, RFC
  4733 section 2.4.1). An application that registered telephone-event itself under one of
  these numbers keeps its own registration only if it comes first.
- **interceptors**: `register_default_interceptors` also registers the MID header extension
  for audio, the client-to-mixer audio level (RFC 6464) for audio and the video orientation
  extension for video (`configure_default_header_extensions`): descriptions carry three more
  `a=extmap` lines.
- **sctp, datachannel**: a peer connection's SCTP association follows the RFCs by default
  where it left them to settings or did without. Each is a change in what goes on the wire
  or in what `send` accepts, and each has a setting:
  - **weighted fair queueing** is the stream scheduler (RFC 8831 section 6.4: the priorities
    of data channels "MUST be interpreted as weighted-fair-queuing scheduling priorities");
    it was first come, first served unless asked for.
    `SettingEngineBuilder::with_sctp_weighted_fair_queueing(false)` is the old order.
  - **user message interleaving** (RFC 8260) is announced (RFC 8831 sections 6.1 and 6.6: it
    "SHOULD be used") and used when the peer announces it too; the association sends DATA
    chunks otherwise. `with_sctp_message_interleaving(false)` does not announce it.
  - **a message over 16 KB is refused on an association without interleaving** (RFC 8831
    section 6.6: "the sender SHOULD limit the maximum message size to 16 KB"), and
    `RTCSctpTransport::max_message_size` reports at most 16384 there. Two engines interleave,
    so nothing changes between them; browsers do not announce interleaving, and an
    application that sends more than 16 KB at a time to one sets
    `with_sctp_message_size_limit_without_interleaving(false)`, which is what browsers do.
  - **the zero checksum** (RFC 9653) is announced, the association running over DTLS, and
    used towards a peer that announces it; `with_sctp_zero_checksum(false)` turns it off.
  - **the size of an SCTP packet follows the path** (RFC 8831 section 5: an initial path MTU
    of at most 1200 bytes at the IP layer over IPv4 and 1280 over IPv6): 1135 bytes over
    IPv4 and UDP with AES-GCM where it was 1191 on every path, 1195 over IPv6, less on a
    relayed or a TCP candidate. What a DTLS record adds is the DTLS association's own figure
    for the negotiated version, suite and connection id (`Endpoint::record_overhead`): over
    DTLS 1.3 with AES-GCM and no connection id (a 5-byte unified header, the inner content
    type and the tag) 1150 and 1210. `with_sctp_mtu` still sets it outright.
  - **State Cookies carry a MAC** from the connection's crypto provider and the accepting
    side keeps nothing for an INIT (RFC 9260 sections 5.1 and 5.1.3); the association is made
    when the COOKIE ECHO arrives. No setting: nothing a peer can tell changes.
- **sdp**: the data section of an offer says `TCP/DTLS/SCTP` when every candidate the offer
  carries is a TCP candidate, and when the selected candidate pair is a TCP pair (RFC 8841
  section 12.2); it always said `UDP/DTLS/SCTP`.
- **sctp**: an association that signalling closed by rejecting the data section takes a new
  `a=sctp-port` when a data section is negotiated again (RFC 8841 section 10.5).
- **sender**: `RTCRtpSender::write_rtp` writes the MID header extension (the transceiver's mid)
  and RtpStreamId (the rid of the packet's encoding) into every packet when the extension is
  negotiated (RFC 9143 section 15, RFC 8852 section 3.3); the application had to. A packet
  that already carries the extension keeps its value.
- **media_engine**: `register_default_codecs` offers `audio/telephone-event` at 48000 Hz
  (payload type 112) and 8000 Hz (115) with the DTMF events `0-15` (RFC 7874 section 3, RFC
  4733 section 2.4.1). An application that registered telephone-event itself under one of
  these numbers keeps its own registration only if it comes first.
- **interceptors**: `register_default_interceptors` also registers the MID header extension
  for audio, the client-to-mixer audio level (RFC 6464) for audio and the video orientation
  extension for video (`configure_default_header_extensions`): descriptions carry three more
  `a=extmap` lines.

- **ice**: a checking agent no longer fails at its timeout (`disconnected_timeout +
  failed_timeout`, 30 s by default) while a pair is still being checked: it fails by the timer
  only once no pair is Frozen, Waiting or In-Progress, no triggered check is queued, no valid
  pair is being nominated and the peer has not been heard from on any pair for 30 s (RFC 8445
  sections 6.1.4.2 and 8.1.2: the checklist fails when every pair has failed; section 14.3: a
  check is a transaction of Rc requests, 39.5 s at the defaults). A short `failed_timeout` no
  longer cuts a check's transaction short. A controlling agent whose nomination's transaction
  times out sends the nomination again while the peer is heard from on the pair, and gives the
  pair up after 30 s of silence (`FailedNomination::Retry`); before, the pair failed, or the
  agent with it at the 30 s timer. `AgentConfig` has a new field, `failed_nomination`: a struct
  literal without `..Default::default()` no longer compiles.
- **turn**: the client's Binding request (`send_binding_request`, `send_binding_request_to`)
  ends with FINGERPRINT, as every other message it sends does (RFC 8489 section 7).
- **ice**: where the fork followed libwebrtc or its own hardening instead of the RFC, the RFC is
  now the default and the other behaviour a setting (`AgentConfig`, and
  `SettingEngineBuilder::with_ice_*`):
  - a controlled agent uses the nominated pair with the highest priority (RFC 8445 section
    8.1.1) and moves to a nominated pair of lower priority only when consent is lost on the
    selected one. Following the latest nomination and libwebrtc's `NOMINATION` value, as
    before, is `NominationAcceptance::Latest` (`with_ice_nomination_acceptance`);
  - data (DTLS, SRTP) is accepted on any local candidate from the remote candidate of every
    valid pair (section 12.2), no longer from the selected pair's address only;
    `data_from_selected_pair_only` (`with_ice_data_from_selected_pair_only`) restores that.
    `Agent::data_path` / `accepts_data` are the test the engine applies;
  - consent checks are plain Binding requests: the controlling agent's no longer carry
    USE-CANDIDATE (`nominate_on_consent_checks`, `with_ice_nomination_on_consent_checks`, turns
    it back on). A controlling agent that wins a role conflict (section 7.3.1.1) after it
    nominated sends its nomination again by itself, which is what the attribute on consent
    checks was there for;
  - a Binding request that fails the short-term credential check is answered 400 or 401 (RFC
    8489 section 9.1.3) instead of being dropped: unsigned, never longer than the request, at
    most five in a burst and one more per 200 ms. `UnauthenticatedRequests::Drop`
    (`with_ice_unauthenticated_requests`) keeps the drop.
- **ice**: `Agent::set_role` re-prioritises the pairs and drops a nomination in the making (it
  only stored the flag). The peer connection sets the role again at an ICE restart only when
  one agent is lite and the other is not (RFC 8445 section 6.1.1), and for a transport set up
  again after it was closed.
- **ice**: a local candidate added after a pair is nominated is not taken, and so not
  announced (RFC 8838 section 13: "an agent MUST NOT trickle any new candidates within an ICE
  session after nomination"); `add_local_candidate` returns `Ok(false)`. An ICE restart takes
  candidates again.
- **ice**: the first mDNS query for a remote `.local` candidate waits a random 20 to 120 ms
  (RFC 6762 section 5.2) instead of leaving with the next `handle_timeout`;
  `multicast_dns_first_query_delay: Some(false)` /
  `with_multicast_dns_first_query_delay(false)` keeps the old timing. A driver must keep
  following `poll_timeout`.
- **ice**: an IPv6 link-local local candidate is no longer paired with a remote candidate that
  is not link-local (RFC 8445 section 6.1.2.2), and `allow_link_local_remote_candidates` no
  longer pairs an IPv6 link-local remote candidate with another local one (it still does for
  IPv4 link-local).
- **ice**: a lite agent told that its peer is lite too (`Agent::set_remote_lite`; the peer
  connection passes `a=ice-lite`) sends no checks and selects its pair from the candidate
  exchange (RFC 8445 section 8.2); as the controlling agent it used to run a full agent's
  checks.
- **ice**: what arrives on the mDNS socket (local port 5353) goes to the mDNS connection
  whatever its source port (it had to be 5353), so that a legacy unicast query is answered
  (RFC 6762 section 6.7). The peer connection's demultiplexer does the same when its mDNS mode
  is `QueryAndGather`; in the other modes a datagram on port 5353 from another port is still
  demultiplexed as STUN / DTLS / SRTP.
- **api**: `RTCIceCandidate` has a new public field, `username_fragment`; `rtc_ice::Event`
  has the variants `LocalCandidateRenamed` and `LiteCandidateUpdate`; `AgentConfig` the fields
  `multicast_dns_first_query_delay`, `multicast_dns_destination_reported`,
  `multicast_dns_unicast_response`, `multicast_dns_rate_limit`; `setting_engine::MulticastDNS`
  the fields `first_query_delay`, `destination_reported`, `unicast_response`, `rate_limit`.
- **api**: `rtc_ice::AgentConfig` has new public fields (`tie_breaker`,
  `nomination_acceptance`, `nominate_on_consent_checks`, `unauthenticated_requests`,
  `data_from_selected_pair_only`, `send_data_before_nomination`): a struct literal without
  `..Default::default()` no longer compiles.
- **interceptor**: the default interceptor set offers RFC 8888 congestion control feedback
  (`a=rtcp-fb:* ack ccfb`) beside `transport-cc`, and `a=rtcp-fb:<pt> ccm tmmbr`, on audio and
  video; its chain has the RFC 8888 recorder at `Slot::Rfc8888` beside the TWCC receiver
  (`register_default_interceptors_without_congestion_control` too). An answer to an offer with
  both feedback mechanisms keeps `ack ccfb` and drops `transport-cc` (RFC 8888 section 6), and
  two engines now run on RFC 8888; a browser answers `transport-cc` alone and nothing changes
  towards it. `CongestionFeedback::Twcc` in `DefaultInterceptorOptions` restores the old offer.
- **interceptor**: `REMOTE_BITRATE_LIMIT_SLOT` moves from 2_500 to 2_250: at 2_500 the remote
  bit rate limit and the circuit breaker (`Slot::CircuitBreaker`) displaced each other in a
  chain that had both. The default interceptor set now carries the limit too, so the remote
  description's `b=TIAS` / `b=AS` bounds its estimate.
- **interceptor**: `CongestionFeedback` has a new default variant, `Negotiated`; `Twcc` and
  `Rfc8888` now mean that mechanism only.
- **interceptor**: a TMMBR is honoured, and answered with a TMMBN, only for a stream that
  negotiated `ccm tmmbr` (RFC 5104 sections 7.1 and 7.2). It was honoured for every stream.
  `CongestionControlBuilder::with_unnegotiated_tmmbr(true)` (`unnegotiated_tmmbr` in
  `DefaultInterceptorOptions`) is the lenient setting.
- **interceptor**: `TwccReceiverBuilder` and `Rfc8888Builder` stretch their interval to what the
  RTCP bandwidth holds one report in, up to 400 ms (`with_adaptive_interval`, on by default);
  `with_interval` is now the shortest interval, not the only one. `with_adaptive_interval(false)`
  keeps it fixed.
- **interceptor**: the pacer releases a packet that is inside its budget, with nothing queued
  ahead, from `handle_write` instead of from the next `handle_timeout`
  (`PacerBuilder::with_immediate_release(false)` restores the wait).
- **interceptor**: `RedPlacement::WithNextMedia` is the default of `UlpfecSendBuilder::red` and
  of `configure_ulpfec` (RFC 5109 section 14.2: FEC is not sent by itself). libwebrtc reads only
  the other form: towards a browser use `configure_ulpfec_with_placement(..,
  RedPlacement::OwnPacket)`.
- **media engine**: a remote description that carries both RFC 8627 `flexfec` and `rtx`
  negotiates no `rtx` (RFC 8627 section 1.1.7); `MediaEngine::set_flexfec_with_retransmission`
  is the setting that keeps it. `flexfec-03` is not affected.
- **dtls**: `SettingEngineBuilder::with_dtls_use_srtp_on_every_association(false)` follows RFC
  5764 section 4.1: the DTLS client offers `use_srtp` only when the session has an audio or
  video section, a data-channel-only session is set up without it, and when it gains a media
  section a new DTLS association with `use_srtp` replaces it (the offer carries a new
  `a=tls-id`, RFC 8842 section 5.5; the DTLS roles are kept). The default offers it on every
  association, as browsers and the engine always did: the RFC form was the default for a
  while, and Chromium, Firefox and WebKit do not act on the new `tls-id`, so media added to a
  data-channel-only session never flowed and the data channels stopped too (browser matrix,
  train round 8: "Rust offers media, the browser answers and decodes it", "rollback",
  "glare"). The earlier, never released, setting to turn `use_srtp` off and the error for
  media on an association without SRTP keys are gone.
- **sdp**: a remote `a=fingerprint` with lower-case hex digits is refused (RFC 8122 section 5:
  `UHEX`); `SettingEngineBuilder::with_lowercase_fingerprints_accepted(true)` reads it, as
  browsers do.
- **dtls**: an `rtc-dtls` server that shares no SRTP profile with the client leaves `use_srtp`
  out and the association falls back to DTLS without SRTP (RFC 5764 section 4.1.1, SHOULD); it
  aborted with `ErrServerNoMatchingSrtpProfile`. `ConfigBuilder::with_use_srtp_required(true)`
  keeps the alert; the peer connection sets it for a session with a media section.
- **dtls**: a new association asked for by an `actpass` description keeps the DTLS roles (it
  chose them anew from the configuration and the ICE role); only a transport that was closed
  chooses again.
- **sender**: `RTCRtpSender::write_rtp` writes the MID header extension (the transceiver's mid)
  and RtpStreamId (the rid of the packet's encoding) into every packet when the extension is
  negotiated (RFC 9143 section 15, RFC 8852 section 3.3); the application had to. A packet
  that already carries the extension keeps its value.
- **media_engine**: `register_default_codecs` offers `audio/telephone-event` at 48000 Hz
  (payload type 112) and 8000 Hz (115) with the DTMF events `0-15` (RFC 7874 section 3, RFC
  4733 section 2.4.1). An application that registered telephone-event itself under one of
  these numbers keeps its own registration only if it comes first.
- **interceptors**: `register_default_interceptors` also registers the MID header extension
  for audio, the client-to-mixer audio level (RFC 6464) for audio and the video orientation
  extension for video (`configure_default_header_extensions`): descriptions carry three more
  `a=extmap` lines.

- **rtcp**: `configure_rtcp_reports` (and so `register_default_interceptors`) builds the RTCP
  session with a `T_rr_interval` of zero, the RFC 4585 section 4.2 default when no `trr-int`
  is signalled: regular reports are spaced by the RTCP bandwidth (5% of the session's, RFC
  3550 section 6.2), no longer at least a second apart. The browsers' one second is
  `configure_rtcp_reports_with(registry, RtcpSessionBuilder::new())`.
- **media_engine**: `MediaEngine::register_codec` refuses a payload type of 64 to 95
  (`Error::SdpInvalidValue`), and a format a remote description numbers so is not used: RFC 5761
  section 4, "RTP payload types in the range 64-95 MUST NOT be used" where RTP and RTCP share a
  port. With the marker bit set such a packet was demultiplexed as RTCP.
- **jsep**: `a=ssrc:<ssrc> cname:` carries the connection's RTCP CNAME
  (`RTCPeerConnection::rtcp_cname()`, RFC 7022), the one its RTCP SDES packets carry (RFC 5576
  section 6.1); it carried the track's stream id. `RTCRtcpParameters::cname` of senders and
  receivers reports it; it was empty.
- **transceiver**: `RTCRemoteBandwidth` has a new field, `session_bitrate` (`b=TIAS`, else
  `b=AS` times 1000: what `max_bitrate` was), and `max_bitrate` derived from `b=AS` follows RFC
  9429 section 5.10: `AS * 1000 * 0.95 - 16000`. A struct literal needs the new field.
- **jsep**: an answer states this endpoint's own `trr-int` for a format offered with one; it
  left the feedback out unless the two numbers were equal (RFC 4585 section 4.2: the value is
  each side's own minimum interval).

- **setting_engine**: `with_bundle_attributes_in_tagged_section_only` is replaced by
  `SettingEngineBuilder::with_bundle_attributes_repeated(bool)`. Answers and subsequent offers
  repeat the BUNDLE attributes (`a=ice-ufrag`, `a=ice-pwd`, `a=setup`, a media-level
  `a=fingerprint`, `a=rtcp-mux`, `a=rtcp-mux-only`, `a=rtcp-rsize`, candidates) in every
  bundled section by default, as before; `false` carries them in the tagged m= section only,
  as RFC 9143 section 7.1.3 requires. That form was the default for a short while and is not
  any more: no browser takes it (Chromium and WebKit: "rtcp-mux must be enabled when BUNDLE is
  enabled"; Firefox: "m-section at level 1 is missing a=rtcp-mux, which is required by
  rtcpMuxPolicy"). A tagged section that is the data section carries `a=rtcp-mux` (and
  `a=rtcp-rsize`) for the RTP sections of its group in the tagged-only form (the note of RFC
  9143 section 7.1.3).
- **jsep**: `RTCBundlePolicy::MustBundle` (`must-bundle`, RFC 9429 section 4.1.1) is new, and
  `RTCBundlePolicy::MaxBundle` selects it: W3C webrtc-pc section 4.2.5 defines `max-bundle`,
  and RFC 9429 `must-bundle` as "identically defined". Every m= section of an initial offer
  but the first is then bundle-only.
  `SettingEngineBuilder::with_max_bundle_as_must_bundle(false)` has `max-bundle` ignored (the
  SHOULD of RFC 9429 section 4.1.1): the default policy (`balanced`) then stays in effect.
- **jsep**: a remote offer applied while a local offer is pending rolls the local offer back
  first, in the one `set_remote_description` call (W3C webrtc-pc section 4.4.2,
  `setRemoteDescription`); it was
  refused. `SettingEngineBuilder::with_implicit_rollback(false)` leaves the rollback to the
  application (RFC 9429 sections 5.6 and 5.7).
- **jsep**: an initial remote offer whose bundled RTP section is not bundle-only and has no
  `a=rtcp-mux` of its own is refused under the RTCP mux policy `require` and has that section
  rejected under `negotiate` (RFC 9143 section 9.3.1.1). The offerer-tagged section's
  attribute was taken for it. A subsequent offer, where RFC 9143 section 7.1.3 puts the
  attribute in the tagged section only, is unchanged.

- **ice**: candidate constructors and `unmarshal_candidate` return an error for a priority above
  2^31 - 1 or a component above 256.
- **ice**: a local candidate added without a priority after another of its type no longer has
  the same priority as that one (its local preference is lower by its rank), and foundations of
  server-reflexive candidates change (they follow the base, not the mapped address).

- **ice**: `AgentConfig::keepalive_interval` (`with_ice_timeouts`) is the basic period of the
  consent checks: default 5 seconds (was 2), a shorter non-zero value is raised to 5 seconds,
  and each interval is 0.8 to 1.2 times it.
- **ice**: a connected full agent is `Disconnected` when a consent request has gone unanswered
  for `disconnected_timeout` (9 to 11 seconds after the last response by default; it was 5
  seconds after it), and `Failed` 30 seconds after the last response at the latest:
  `disconnected_timeout + failed_timeout` above 30 seconds, or a zero `failed_timeout`, no
  longer keeps it alive longer. A shorter sum still fails it sooner.

- **ice**: `AgentConfig` has two new fields (`ta`, `max_candidate_pairs`): a struct literal
  without `..Default::default()` no longer compiles. `max_binding_requests` now counts the
  requests of one transaction (Rc of RFC 8489), which back off from 500 ms: with the default 7
  an unanswered pair fails after 39.5 s (it was 1.6 s), so in practice a silent pair is given up
  by the agent's checking timeout or by end-of-candidates.
- **ice**: `Agent::add_remote_candidate` returns `false` for a candidate it does not hold (a
  duplicate, one after end-of-candidates); it returned `true` for a duplicate.
- **ice**: the state after a nomination is `Completed`, not `Connected`, when the application
  has signalled the end of local candidates and the peer the end of its own. Code that waits
  for `Connected` alone should accept both (`RTCPeerConnectionState::Connected` covers both).
- **ice**: `Agent::get_local_candidates` also returns the local peer-reflexive candidates the
  agent learns; the selected pair's local candidate can be one of them (type `prflx`), its
  base being the socket in use.

- **stun**: `Message::decode` (and `unmarshal_binary`, `write`, `read_from`, `clone_to`) refuses
  what RFC 8489 section 6.3 has a receiver check: a first byte with either of its top two bits
  set, a length that is not a multiple of four, and bytes after the message the header
  describes. `is_stun_message` is false for the first of these.
- **stun**: `addr::AlternateServer`, `ResponseOrigin` and `OtherAddress` are types of their own
  that encode and decode under their own attribute types (0x8023, 0x802b, 0x802c). They were
  aliases of `MappedAddress`, so `add_to` wrote a MAPPED-ADDRESS.
- **stun**: what is sent keeps RFC 8489's limits: a USERNAME is at most 508 bytes (was 513); a
  REALM, NONCE or SOFTWARE is fewer than 128 characters and at most 509 bytes (was 763 bytes);
  an ERROR-CODE has a code from 300 to 699 and a UTF-8 reason phrase of fewer than 128
  characters. A received ERROR-CODE whose class is not 3 to 6 or whose number is over 99 is an
  error. The default reason phrase of 401 is "Unauthenticated" (new constant
  `CODE_UNAUTHENTICATED`).
- **stun**: `FingerprintAttr::check` fails when FINGERPRINT is not the last attribute (RFC 8489
  section 14.7).
- **stun**: `MessageIntegrity::new_long_term_integrity_with_provider` and
  `long_term_integrity_key` apply the OpaqueString profile (RFC 8265) to the user name, realm
  and password, as RFC 8489 section 9.2.2 has it: a string the profile does not allow (a
  control character, say) is an error, and one it normalises gives the normalised key.
- **stun**: `Client` follows RFC 8489 section 6.2. The initial RTO is 500 ms (was 300 ms); the
  interval doubles (it grew linearly); a request is sent 7 times (was 8) and its transaction
  fails 16 x RTO after the last, 39.5 s by default (was 10.8 s); over
  `TransportProtocol::TCP` a request is sent once and fails after Ti = 39.5 s;
  `handle_timeout(t)` acts on a deadline equal to `t` (it needed a later instant, so a driver
  that slept until `poll_timeout` made no progress) and queues the retransmission itself (it
  was queued by `poll_event`); at most ten transactions are outstanding and a UDP message fits
  the path MTU (548 / 1232 bytes of STUN when it is unknown), `handle_write` failing otherwise;
  an indication starts no transaction. `with_no_retransmit` is Rc = 1.
  `ClientBuilder::with_timeout_rate` and `with_buffer_size`, which had no effect, are
  deprecated.

- **ice**: candidate constructors and `unmarshal_candidate` return an error for a priority above
  2^31 - 1 or a component above 256.
- **ice**: a local candidate added without a priority after another of its type no longer has
  the same priority as that one (its local preference is lower by its rank), and foundations of
  server-reflexive candidates change (they follow the base, not the mapped address).

- **ice**: `AgentConfig::keepalive_interval` (`with_ice_timeouts`) is the basic period of the
  consent checks: default 5 seconds (was 2), a shorter non-zero value is raised to 5 seconds,
  and each interval is 0.8 to 1.2 times it.
- **ice**: a connected full agent is `Disconnected` when a consent request has gone unanswered
  for `disconnected_timeout` (9 to 11 seconds after the last response by default; it was 5
  seconds after it), and `Failed` 30 seconds after the last response at the latest:
  `disconnected_timeout + failed_timeout` above 30 seconds, or a zero `failed_timeout`, no
  longer keeps it alive longer. A shorter sum still fails it sooner.

- **turn**: `Event::AllocateError` and `Event::CreatePermissionError` carry a
  `rtc_turn::client::RequestError` instead of a `shared::error::Error`: `Rejected(ErrorResponse)`
  with the server's error code, reason, ALTERNATE-SERVER and UNKNOWN-ATTRIBUTES, or
  `Failed(Error)`. It implements `Display` and converts into `Error` (`err.into()`).
- **turn**: `ChannelData::encode` and `ChannelData::write_header` return `Result<()>`: data longer
  than 65 535 bytes is refused (see below).
- **turn**: the client delivers a Data indication or ChannelData only from a peer address it
  holds a permission for (asked for or installed), as RFC 8656 sections 11.4 and 12.6 recommend.
- **turn**: `Relay::send_to` fails with `ErrNoPermission` once a permission's 300 s have run out
  without a refresh, and with `ErrConnClosed` after `Relay::close`.
- **stun**: `Message::decode` (and `unmarshal_binary`, `write`, `read_from`, `clone_to`) refuses
  what RFC 8489 section 6.3 has a receiver check: a first byte with either of its top two bits
  set, a length that is not a multiple of four, and bytes after the message the header
  describes. `is_stun_message` is false for the first of these.
- **stun**: `addr::AlternateServer`, `ResponseOrigin` and `OtherAddress` are types of their own
  that encode and decode under their own attribute types (0x8023, 0x802b, 0x802c). They were
  aliases of `MappedAddress`, so `add_to` wrote a MAPPED-ADDRESS.
- **stun**: what is sent keeps RFC 8489's limits: a USERNAME is at most 508 bytes (was 513); a
  REALM, NONCE or SOFTWARE is fewer than 128 characters and at most 509 bytes (was 763 bytes);
  an ERROR-CODE has a code from 300 to 699 and a UTF-8 reason phrase of fewer than 128
  characters. A received ERROR-CODE whose class is not 3 to 6 or whose number is over 99 is an
  error. The default reason phrase of 401 is "Unauthenticated" (new constant
  `CODE_UNAUTHENTICATED`).
- **stun**: `FingerprintAttr::check` fails when FINGERPRINT is not the last attribute (RFC 8489
  section 14.7).
- **stun**: `MessageIntegrity::new_long_term_integrity_with_provider` and
  `long_term_integrity_key` apply the OpaqueString profile (RFC 8265) to the user name, realm
  and password, as RFC 8489 section 9.2.2 has it: a string the profile does not allow (a
  control character, say) is an error, and one it normalises gives the normalised key.
- **stun**: `Client` follows RFC 8489 section 6.2. The initial RTO is 500 ms (was 300 ms); the
  interval doubles (it grew linearly); a request is sent 7 times (was 8) and its transaction
  fails 16 x RTO after the last, 39.5 s by default (was 10.8 s); over
  `TransportProtocol::TCP` a request is sent once and fails after Ti = 39.5 s;
  `handle_timeout(t)` acts on a deadline equal to `t` (it needed a later instant, so a driver
  that slept until `poll_timeout` made no progress) and queues the retransmission itself (it
  was queued by `poll_event`); at most ten transactions are outstanding and a UDP message fits
  the path MTU (548 / 1232 bytes of STUN when it is unknown), `handle_write` failing otherwise;
  an indication starts no transaction. `with_no_retransmit` is Rc = 1.
  `ClientBuilder::with_timeout_rate` and `with_buffer_size`, which had no effect, are
  deprecated.

- **turn**: the client's requests follow the retransmission timer of RFC 8489 section 6.2, the
  one `rtc-stun` has (`rtc_stun::timer`). The default initial RTO is 500 ms (was 200 ms) and
  doubles without the 1600 ms cap; a request is sent 7 times, at 0, 0.5, 1.5, 3.5, 7.5, 15.5
  and 31.5 s, and its transaction fails 16 x RTO after the last, at 39.5 s (was 7.8 s). So an
  `Event::TransactionTimeout`, and the second attempt of a Refresh or ChannelBind, come that
  much later. `ClientConfig::rto_in_ms` sets the initial RTO as before; with the new
  `ClientConfig::retransmission` (`RetransmissionConfig`: `rc`, `rm`, `ti`, `rto_estimation`,
  `max_outstanding_transactions`) an application can have the old pace back.
- **turn**: at most ten transactions are outstanding to a server (RFC 8489 section 6.2). A
  request past that is kept and sent when one of the ten ends; `Client::has_transaction` is
  true for it meanwhile. `RetransmissionConfig::max_outstanding_transactions` changes the
  limit, 0 lifts it.
- **turn**: `ClientConfig` has two new fields, `retransmission` and `password_algorithms`; a
  literal that names every field needs them, or `..Default::default()`. `ClientConfig::realm`
  is no longer read: the realm is the one the server's 401 names, as it always was after the
  first Allocate.
- **turn**: a request whose responses were all discarded because their integrity did not hold
  no longer ends as `Event::TransactionTimeout`. It ends with the error event of its kind
  (`AllocateError`, `CreatePermissionError`, `RefreshError`, `ChannelBindError`,
  `ConnectError`, `BindingError`) carrying `RequestError::Failed(Error::ErrIntegrityMismatch)`,
  and over TCP or TLS the first such response ends it at once (RFC 8489 section 9.2.5). On a
  data connection a ConnectionBind response that is unsigned or wrongly signed is a
  `DataConnectionEvent::BindError` at once; it was passed over.
- **turn**: a 401 (Unauthenticated) to a ConnectionBind that carried the credential is not
  answered with the same credential again unless it names another realm (RFC 8489 section
  9.2.5 forbids the retry that changes nothing); it was, once. A 438 (Stale Nonce), which is
  what a server with nonces per connection sends, is answered as before.
- **turn**: a received message with a FINGERPRINT that does not match, an indication or a
  response with a comprehension-required attribute the client does not know, and a response
  of another method than its request's are no longer processed (RFC 8489 sections 6.3 and
  14.7). A 401 without NONCE or REALM to the first Allocate is reported as
  `RequestError::Rejected` with its code; it was `Failed(attribute not found)`.

- **mdns**: `MdnsConfig` has private fields: build it with `MdnsConfig::default()` and the
  `with_*` methods, not as a struct literal. `MdnsConfig::query_timeout` defaults to 30
  seconds (was `None`), and `query_interval` under one second is taken as one second.
- **mdns**: a local name that is not `<uuid>.local` is answered only after probing for it,
  about 750 ms after the first `handle_timeout` (`MdnsProbePolicy::Never` restores the old
  behaviour). `MdnsEvent::QueryTimeout` also ends a query whose name has more than one
  address. `Mdns::close` leaves goodbye packets in `poll_write`.

- **dtls**: a server `Endpoint` makes no association for a datagram that is not a ClientHello
  with a valid cookie (such a datagram from an unknown address is dropped), and reports
  `HandshakeComplete` a second time for an address when its client completes a new handshake
  (RFC 6347 section 4.2.8). A datagram for a failed server association returns `Ok` (it was fed
  to a fresh association). New: `ConfigBuilder::with_cookie_exchange`.
- **dtls**: a handshake nobody answers fails after 30 seconds with `ErrHandshakeTimeout`, where
  it failed after 8 seconds with `ErrInvalidFsmTransition`; its retransmissions are 1, 3, 7 and
  15 seconds in instead of every second.
- **dtls**: `CipherSuite` has a new required method, `record_expansion`. `DTLSConn::write` and
  `Endpoint::write` return `ErrRecordOverflow` above 2^14 bytes. `ConfigBuilder::build` refuses
  an MTU below 128. New: `ConfigBuilder::{with_maximum_flight_interval, with_handshake_timeout}`,
  `conn::MAX_RECORD_PAYLOAD`, `Error::{ErrHandshakeTimeout, ErrRecordOverflow}`.
- **dtls**: a ServerHello no longer carries renegotiation_info, supported_groups or
  ec_point_formats to a client that did not offer them; a client that sends no
  signature_algorithms extension is no longer served by a certificate suite unless SHA-1
  signatures are enabled (`with_insecure_hashes`).
- **dtls**: `State::export_keying_material` returns `ErrExportWithoutExtendedMasterSecret` for a
  session without the extended master secret. The serialized `State`
  (`marshal_binary` / `unmarshal_binary`) carries the flag, so a state serialized by an earlier
  version does not load.
- **dtls**: new variants on non-exhaustive enums: `Extension::Unknown`,
  `CipherSuiteId::Tls_Empty_Renegotiation_Info_Scsv`, and seven `shared::error::Error` variants
  (`ErrRenegotiationInfoNotEmpty`, `ErrUnsolicitedExtension`, `ErrCompressionMethodNotOffered`,
  `ErrNoNullCompressionMethod`, `ErrInvalidUseSrtpAnswer`, `ErrExportWithoutExtendedMasterSecret`,
  `ErrDuplicateExtension`). `Extension::extension_type` is new.

- **srtp**: `srtp_replay_protection` and `srtcp_replay_protection` return `Result<ContextOption>`
  and refuse a window below 64 packets (RFC 3711 section 3.3.2). With
  `SettingEngineBuilder::with_srtp_replay_protection_window` / `with_srtcp_replay_protection_window`
  set to 1..=63, the SRTP contexts now fail to build when the DTLS handshake completes.
- **srtp**: `Context::new` with `None` for a replay option gives replay protection with a
  64-packet window, as its documentation said; it gave none. Pass `srtp_no_replay_protection()` /
  `srtcp_no_replay_protection()` to go without. Peer connections are not affected (they pass
  their windows).
- **srtp**: the first SRTCP packet of an SSRC carries index 0 (RFC 3711 section 3.4), not 1.
  Receivers accept any first index.
- **srtp**: a master key stops at its lifetime: `encrypt_rtp`, `encrypt_rtcp`, `decrypt_rtp` and
  `decrypt_rtcp` fail with `ErrExceededMaxPackets` after 2^48 SRTP or 2^31 SRTCP packets under
  one key (2^31 of each for the AES-256 counter-mode profiles, RFC 6188 section 4), counted over
  all the SSRCs that share it.
- **srtp**: with `Cryptex { require: true, .. }`, `encrypt_rtp` fails for a packet that has
  CSRCs or a header extension and cannot be protected with Cryptex. A received clear packet under
  the same setting is authenticated before it is refused.
- **srtp**: `SessionKeys` no longer prints its keys (`Debug` shows lengths) and has a `Drop`
  that zeroizes them, so its fields can no longer be moved out of it.
- **srtp**: the AES-GCM profiles require the provider's AES-CTR as well (for RFC 6904), and
  `ProtectionProfile::Aes256CmHmacSha1_*` are documented as having no DTLS-SRTP code point (their
  discriminants 0x0003 / 0x0004 are not wire values; see `ProtectionProfile::dtls_srtp_id`).
- **srtp**: an AES-CM packet whose encrypted portion is over 2^16 AES blocks (1 MiB) is refused
  (RFC 3711 section 4.1.1).

- **rtcp**: `PacketType`, `SdesType` and `extended_report::BlockType` gain an `Other(u8)` variant that
  keeps a value the crate does not model, so they are no longer `#[repr(u8)]`: convert with
  `u8::from(x)` / `X::from(octet)` instead of `as u8`. `SdesType::from` no longer maps an unknown
  type to `SdesEnd`, `PacketType::from` no longer maps one to `Unsupported`, `BlockType::from` no
  longer maps one to `Unknown` (each of those is now the octet 0 only).
- **rtcp**: `extended_report::UnknownReportBlock` has two more fields, `block_type` and
  `type_specific`, and refuses to marshal a body that is not a whole number of 32-bit words.
- **rtcp**: `VoIPMetricsReportBlock::default()` is "nothing available" (127 for the levels, the R
  factors and the MOS scores, Gmin 16), not all zeros.
- **rtcp**: a typed `unmarshal` reads the one packet its header describes: it fails
  (`PacketTooShort`) when the length field runs past the buffer, and it leaves what follows the
  packet in the buffer. `SenderReport` / `ReceiverReport` used to take everything left in the buffer
  as a profile-specific extension.
- **rtcp**: stricter writers. Refused now: a generic NACK, an SLI or a FIR with no entry; a profile
  extension, APP data or an unparsed XR block that is not whole words; an RLE block with a null chunk
  among its chunks, a run of length zero or a range of 65,534 or more; VoIP metrics with an R factor
  or a MOS score outside its range, or Gmin 0; a compound packet with a padded packet that is not its
  last. `FullIntraRequest` writes the header's media SSRC as 0 whatever `media_ssrc` holds
  (RFC 5104 section 4.3.1.2).
- **rtcp**: stricter readers. Refused now: a PLI or an RRR with FCI; an SLI with no entry; a REMB whose
  SSRC count does not match its length; a padding count of zero or beyond the packet; transport-cc
  feedback whose chunks or deltas reach into its padding; an SDES whose chunks do not match its source
  count. A BYE without a reason is written without a length octet (8 octets for one source, was 12).
- **rtcp**: the parsed `chunks` of a Loss / Duplicate RLE block no longer include the terminating null
  chunk; statistics-summary fields whose flag is clear read as zero; the reserved octet of VoIP
  metrics reads as zero.

- **sdp**: `SessionDescription::unmarshal` is the RFC 8866 section 9 grammar and nothing else
  (RFC 9429 section 5.8: a description that is not well formed is rejected). It now refuses what
  it used to let through: empty lines between lines, `i=` / `c=` / `b=` / `k=` after `a=` lines in
  a media section, fields separated by more than one space or with white space around them, a
  `c=` line without an address or with an address that does not fit its address type, a unicast
  address with a `/`, a `t=` time that is neither 0 nor ten digits or more, a negative `r=` value,
  extra fields after the stop time, an empty `s=` or `i=`, `e=` / `p=` text that is not an email
  address or a phone number, an attribute name or a format that is not a token, a NUL or a bare CR
  in a line. An application that reads SDP from software that writes such things asks for it:
  `SessionDescription::unmarshal_with_options` with `ParseOptions { blank_lines,
  unordered_media_lines, loose_fields }`, or `ParseOptions::lenient()` for all three. What every
  mode still accepts beyond the grammar (a bare LF line ending, a last line without one, `z=`
  where RFC 4566 put it, `a=name:` with an empty value) is listed in the `ParseOptions`
  documentation.
- **sdp**: values are no longer trimmed. `s= ` is a session name of one space, and an attribute
  value keeps its leading and trailing white space (`a=msid-semantic: WMS` has the value
  `" WMS"`). Structured lines never had any to trim.
- **sdp**: `SessionDescription::email_address` and `phone_number` (`Option<String>`) are
  `email_addresses` and `phone_numbers` (`Vec<String>`): RFC 8866 allows any number of `e=` and
  `p=` lines, and a second one was a parse error.
- **sdp**: `SessionDescription::time_zones` is `TimeDescription::time_zones`: a `z=` line belongs
  to the time description it follows (RFC 8866 section 9) and is written there. A `z=` may now be
  followed by another `t=`.
- **sdp**: `k=` lines are parsed, checked and dropped, and never written (RFC 8866 section 5.12).
  The `encryption_key` fields of `SessionDescription` and `MediaDescription` remain so that code
  naming them builds; the parser never sets them and `marshal` ignores them.
- **sdp**: `MediaDescription::with_media_source` writes the `cname` and `msid` source attributes
  only. `a=ssrc:<n> mslabel:...` and `a=ssrc:<n> label:...` (Plan B, never registered; RFC 5576
  section 4.1) are no longer in the engine's offers and answers.
- **sdp**: `SessionDescription::new_jsep_session_description(true)` no longer adds a bare
  `a=identity` line, which was not valid SDP (RFC 8827 section 5: the attribute is an assertion).
  The parameter is ignored.
- **sdp**: an `a=rtpmap` without a clock rate (`a=rtpmap:96 VP8`) is malformed and gives no codec
  (it gave one with clock rate 0); a payload type above 127 in `a=rtpmap`, `a=fmtp` or `a=rtcp-fb`
  gives none either. Any network and address type token is accepted in `o=` and `c=` (only `IN`,
  `IP4` and `IP6` were).
- **sdp**: `ExtMap::unmarshal` accepts only `extmap:` / `a=extmap:` in front of the value (it took
  any text before the first colon), and an `a=extmap` with nothing or only a space after the URI
  is refused.

- **sctp**: `PayloadProtocolIdentifier::Unknown` is sent as 0 ("not specified", RFC 9260
  section 3.3.1), not 58. `Chunks` has a new public field, `ppid`.
- **sctp**: `Stream::write*` with an empty message returns an error.
- **sctp**: `Association::open_stream` fails for a stream id at or past the negotiated
  outbound stream count.
- **sctp**: `TimerConfig::default().max_t2_shutdown_retrans` is 10, not unlimited.
- **sctp**: `TimerConfig::default().max_t3_rtx_retrans` is 10, not unlimited: an association
  whose peer answers nothing for about five minutes ends with `TimedOut`. `usize::MAX` keeps
  the old behaviour.
- **sctp**: an established association sends HEARTBEATs when idle and so always has a timer
  running; `with_heartbeat_interval(None)` turns them off.
- **sctp**: slow start grows the congestion window by one packet per SACK, as the RFC has
  it, not by everything the SACK acknowledges. A receiver that acknowledges many packets with
  one SACK slows the sender's ramp; `with_slow_start_growth_limit` sets a larger L.
- **sctp**: the retransmissions after a timeout are paced by the congestion window (one
  packet, then slow start) instead of leaving at once.
- **sctp**: a SACK for a TSN never sent, and an INIT ACK without a State Cookie, end the
  association with an ABORT (`TransportError`, `HandshakeFailed`).

- **flexfec-03**: `FlexFec03Encoder::encode` takes the repair stream's RTP timestamp as a third
  argument.
- **interceptor**: `StreamInfo` has two more public fields (`mime_type_fec`,
  `sdp_fmtp_line_fec`); a struct literal without `..Default::default()` needs them. The draft-03
  FlexFEC interceptors bind a stream whose `mime_type_fec` is empty or `<type>/flexfec-03`, and
  no longer one that names another FEC format.
- **codecs**: with `video/flexfec` registered and negotiated, a sender's FEC SSRC is now
  described (`a=ssrc-group:FEC-FR`) and its streams are bound with the repair flow, as for
  `video/flexfec-03`. Before, `video/flexfec` was written to SDP with nothing behind it.
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
  SRTP keys gets a new association with them.
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

- **rtp**: `Header::unmarshal` and `Header::marshal_to` refuse a version other than 2
  (`Error::BadVersion`), and `marshal_to` a payload type above 127. `Header::default().version`
  is 2.
- **rtp**: `Header::set_extension` on a header without extensions returns an error for ID 0 and
  for an element over 255 bytes (it made a header that could not be marshalled).
  `del_extension` of the last element clears `extension`.
- **rtp**: `HevcPayloader` is no longer a unit struct: write `HevcPayloader::default()`.
- **rtp**: `H265Packet::depacketize` returns NAL units behind Annex B start codes, not the RTP
  payload.
- **rtp**: `H264Packet::depacketize` returns an empty result, not an error, for reserved packet
  types; `H264Payloader` drops NAL units of types 0 and 24 to 31; parameter sets given alone are
  all held, and sent with the next call that has another NAL unit.
- **rtp**: a `Packetizer` built on an audio payloader no longer sets the marker bit on every
  packet.
- **twcc**: a lost TWCC feedback packet no longer turns the packets it would have described
  into losses (draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3). The send history
  reported every unacknowledged packet below the highest acknowledged one as lost, so one lost
  feedback read as a burst of loss, and so did every stream the receiver does not report on (an
  audio stream without the transport-cc extension, an SSRC outside an RFC 8888 report). Only a
  packet a feedback described is reported now; the rest are released without a verdict
  (`History::unreported`), and gaps in the feedback packet count are counted
  (`CongestionControlInterceptor::lost_feedback`).
- **twcc**: RTX and FEC packets get a transport-wide sequence number and a place in the send
  history (section 2.2: the number is attached to every packet sent). The TWCC sender and the
  congestion controller registered a stream's media SSRC only, so retransmissions and repair
  packets were invisible to the receiver's feedback and to the estimator.
- **twcc / rfc8888**: the receiver's clock is followed through its wraps
  (`FeedbackTimeline`): the 24-bit TWCC reference time every 12.4 days, the RFC 8888 report
  timestamp every 18.2 hours. An RFC 8888 arrival time is now the report timestamp minus the
  arrival time offset; the offset itself was handed to the estimator, so within every report
  arrivals ran backwards and GCC over RFC 8888 saw a queue draining for ever. The over-range
  offset 0x1FFE is no longer taken as an arrival 8 seconds before the report.
- **rfc8888**: feedback is sent only for streams that negotiated `ack ccfb` (RFC 8888 section 6,
  RFC 4585 section 4.2), from a real SSRC instead of 0 (the first local stream's, or a random
  one for a receive-only endpoint), and covers a stream's FEC SSRC. A duplicate keeps the first
  copy's arrival time and reports ECN-CE if any copy carried it (section 3.1). A packet that
  never arrives no longer makes every later report repeat everything since: each arrival is
  reported once, a late one in an overlapping report within 500 ms, and feedback larger than
  the report size is split into several packets instead of being cut.
- **fec**: the FlexFEC encoder protects the packets as they are sent. It read them above the
  TWCC sender, which then wrote the transport-wide sequence number into them (adding the header
  extension when the packet had none), so the receiver XORed different bytes and recovered a
  corrupt packet. The encoder now reads the wire image from a tap below the TWCC sender
  (`FlexFec03SendInterceptor::wire_tap`, `Slot::FecWireImage`).
- **fec**: the arrival recorders (TWCC receiver, RFC 8888, receiver reports) run before the FEC
  decoder. A repair packet was swallowed before they saw it and reported lost for ever, and a
  packet rebuilt from FEC was reported as arrived, hiding the loss from the sender's congestion
  controller and from `fraction lost`.
- **gcc**: the delay-based estimate stays below 1.5 times the received rate
  (draft-ietf-rmcat-gcc-02 section 5.5); an application-limited sender let it climb 8% per
  second to the configured maximum. "Close to convergence" is now the draft's: the average and
  deviation of the received rate at each decrease, additive increase within three deviations
  (scaled by the response time), and back to multiplicative increase when the received rate
  rises above them; the controller stayed additive for ever after the first over-use. It starts
  in the Increase state.
- **gcc**: the loss-based estimate is held at or below the delay-based one
  (draft-ietf-rmcat-gcc-02 section 6). Left free it grew 5% per interval whenever loss was
  under 2%, to several times the rate being sent, and a loss episode was absorbed by the
  inflated estimate before the target moved. `Gcc::with_loss_estimate_capped_by_delay_estimate(false)`
  keeps the old behaviour.
- **fec**: the ULPFEC encoder protects the packets as sent, in RED carriage and as a separate
  stream (`UlpfecSendInterceptor::wire_tap`). With the tap, a media packet gets its wire
  sequence number and RED wrapping as it passes the encoder, the sequence numbers its block's
  FEC packets will take are set aside there, and the FEC is computed from the wire images when
  the block's last packet has left and sent in those numbers: no gap and no duplicate on the
  media stream, and a FEC packet may leave a few packets after its number when a pacer holds
  media in between. A media packet dropped before the wire does not stall the encoder.
- **fec decoders**: the ULPFEC decoder keeps no state for, and rebuilds nothing at, a sequence
  number its window does not cover (a mask reaches 47 packets past an SN base at the window's
  edge); the RFC 8627 decoder ignores a repair packet whose block lies wholly outside what the
  stream's buffer holds.
- **fec**: the RFC 8627 encoder protects the packets as sent too
  (`FlexFecSendInterceptor::wire_tap`), and keeps the wire image for its retransmissions.
- **cc**: TMMBR is read from, and TMMBN written as, the typed packets of `rtc-rtcp`
  (`TemporaryMaximumBitrateRequest` / `Notification`); the raw form is still read.
- **circuit breaker**: with the RTCP session wire-ward of it the breaker sees no sender report
  leave and could not measure a round trip time, so its congestion breaker could never trip.
  It now takes the round trip time the congestion controller measures
  (`CircuitBreakerHandle::report_round_trip_time`).
- **gcc**: the missing-feedback timeout follows the receiver's own feedback rhythm (three of
  its intervals when that is more than 500 ms, and not before two reports have shown one): a
  receiver that holds its feedback to the RTCP bandwidth is not a receiver gone silent.
- **twcc**: `FeedbackTimeline` and `GccInterceptor` follow the reference time with
  `rtcp`'s `ReferenceTimeUnwrapper`; `GccInterceptor` read it raw and jumped 12.4 days at the
  wrap.
- **pacer**: the pacer starts at the estimator's rate. `configure_congestion_control` builds it
  with the estimator's starting target, and `CongestionControlInterceptor` announces the target
  on the first inbound packet, not only when it changes; the pacer ran at 1 Mbit/s against
  GCC's 300 kbit/s until the first change.

- **interceptor**: `Slot::FecDecoder` moves from 6_000 to 10_300 and `Slot::NackGenerator` from
  7_000 to 10_600, after the arrival recorders; an interceptor placed with `Slot::from(n)`
  relative to either has to move with them. `Slot::FecWireImage` (1_500) is new.
- **interceptor**: an RFC 8888 arrival time from `convert_ccfb` is the report timestamp minus
  the offset, not the offset. `Rfc8888Interceptor` reports only streams bound with `ack ccfb`
  in `rtcp_feedback`. `History::take_reports` returns only packets a feedback described.
  `RateControlState::default()` is `Increase`.
- **defaults**: `register_default_interceptors` adds congestion control, a pacer and the RTP
  circuit breaker. Media written faster than the estimate (300 kbit/s until feedback raises
  it) is queued by the pacer and released on `handle_timeout`, outgoing packets carry the
  transport-cc extension, and a flow whose receiver sends no RTCP for 15 s stops. An
  application that relied on the old set calls
  `register_default_interceptors_without_congestion_control`.
- **pacer**: the derived burst is 5 ms of the target instead of 100 ms; `with_burst_bits` still
  pins one.

- **stats**: report ids are opaque: `report.get("RTCPeerConnection")` and ids built from an
  SSRC no longer find anything; use the typed accessors or follow a reference.
- **stats**: field types. `RTCInboundRtpStreamStats`: `fir_count`, `pli_count`: `Option<u32>`;
  `retransmitted_packets_received`, `retransmitted_bytes_received`: `Option<u64>`.
  `RTCOutboundRtpStreamStats`: `fir_count`, `pli_count`: `Option<u32>`; `target_bitrate`:
  `Option<f64>`; `total_packet_send_delay`: `f64`; `total_encoded_bytes_target` removed (also
  from `EncoderStatsUpdate`). `RTCRemoteOutboundRtpStreamStats::remote_timestamp`:
  `Option<SystemInstant>`. `RTCIceCandidatePairStats`: `packets_discarded_on_send`:
  `Option<u32>`, `bytes_discarded_on_send`: `Option<u64>`.
  `RTCDataChannelStats::data_channel_identifier`: `Option<u16>`. The update structs
  (`DecoderStatsUpdate`, `AudioReceiverStatsUpdate`, `EncoderStatsUpdate`) have new fields.
- **stats**: the id an application passes to `update_audio_playout_stats` is no longer the
  `media-playout` object's id in the report; an inbound stream's `playoutId` names it.

- **sctp**: `PayloadProtocolIdentifier::Unknown` is sent as 0 ("not specified", RFC 9260
  section 3.3.1), not 58. `Chunks` has a new public field, `ppid`.
- **sctp**: `Stream::write*` with an empty message returns an error.
- **sctp**: `Association::open_stream` fails for a stream id at or past the negotiated
  outbound stream count.
- **sctp**: `TimerConfig::default().max_t2_shutdown_retrans` is 10, not unlimited.
- **sctp**: `TimerConfig::default().max_t3_rtx_retrans` is 10, not unlimited: an association
  whose peer answers nothing for about five minutes ends with `TimedOut`. `usize::MAX` keeps
  the old behaviour.
- **sctp**: an established association sends HEARTBEATs when idle and so always has a timer
  running; `with_heartbeat_interval(None)` turns them off.
- **sctp**: slow start grows the congestion window by one packet per SACK, as the RFC has
  it, not by everything the SACK acknowledges. A receiver that acknowledges many packets with
  one SACK slows the sender's ramp; `with_slow_start_growth_limit` sets a larger L.
- **sctp**: the retransmissions after a timeout are paced by the congestion window (one
  packet, then slow start) instead of leaving at once.
- **sctp**: a SACK for a TSN never sent, and an INIT ACK without a State Cookie, end the
  association with an ABORT (`TransportError`, `HandshakeFailed`).

- **sctp**: Max.Burst is 4 by default (RFC 9260 sections 6.1 D and 16);
  `TransportConfig::with_max_burst(None)` restores the unlimited burst.
- **sctp**: `rtc-sctp` depends on `rtc-crypto` (the traits only, no backend).
  `ServerConfig` no longer derives `Debug` (it implements it).
- **sctp**: `Stream::stop` and `close` return an error when the peer did not announce
  RE-CONFIG; `TimerConfig::max_reconfig_retrans` is no longer a limit of its own.
- **sctp**: `PayloadProtocolIdentifier::Unknown` is sent as 0 ("not specified", RFC 9260
  section 3.3.1), not 58. `Chunks` has a new public field, `ppid`.
- **sctp**: `Stream::write*` with an empty message returns an error.
- **sctp**: `Association::open_stream` fails for a stream id at or past the negotiated
  outbound stream count.
- **sctp**: `TimerConfig::default().max_t2_shutdown_retrans` is 10, not unlimited.
- **sctp**: `TimerConfig::default().max_t3_rtx_retrans` is 10, not unlimited: an association
  whose peer answers nothing for about five minutes ends with `TimedOut`. `usize::MAX` keeps
  the old behaviour.
- **sctp**: an established association sends HEARTBEATs when idle and so always has a timer
  running; `with_heartbeat_interval(None)` turns them off.
- **sctp**: slow start grows the congestion window by one packet per SACK, as the RFC has
  it, not by everything the SACK acknowledges. A receiver that acknowledges many packets with
  one SACK slows the sender's ramp; `with_slow_start_growth_limit` sets a larger L.
- **sctp**: the retransmissions after a timeout are paced by the congestion window (one
  packet, then slow start) instead of leaving at once.
- **sctp**: a SACK for a TSN never sent, and an INIT ACK without a State Cookie, end the
  association with an ABORT (`TransportError`, `HandshakeFailed`).

### Security

- **dtls**: the server verifies the client's Finished (RFC 5246 section 7.4.9). `Flight4` only
  checked that a Finished message had arrived, so nothing confirmed to the server that the client
  had seen the same handshake: a ClientHello altered on the way (cipher suites, SRTP profiles,
  extensions) was noticed by the client alone, after the server had completed, exported SRTP keys
  and started sending. Both sides now compare verify_data in constant time and answer a mismatch
  with decrypt_error; the client's alert, sent after its ChangeCipherSpec, is protected so that
  the server can read it.
- **dtls**: unauthenticated input no longer ends a handshake (RFC 6347 sections 4.1.2.7 and
  4.2.1). A plaintext application-data record during the handshake was answered with a fatal
  unexpected_message, and a ClientHello with a wrong cookie with a fatal access_denied; either
  failed the association, and the wrong-cookie one also took the place of the genuine
  ClientHello, so one spoofed datagram denied the handshake. Both are now discarded without an
  alert, the server answers the cookieless one with HelloVerifyRequest again, and the genuine
  ClientHello is still accepted. Nothing is negotiated (and no alert sent) from a ClientHello
  that does not echo the cookie.
- **dtls**: `State::export_keying_material` refuses a session without the extended master secret
  (RFC 7627 section 5.4), so DTLS-SRTP keys never come from a master secret that is not bound to
  the handshake, whatever `ExtendedMasterSecretType` a crate user picks. The engine already
  requires the extension.
- **dtls**: a non-empty renegotiation_info in an initial handshake is a fatal handshake_failure on
  both sides (RFC 5746 sections 3.4 and 3.6); it was skipped with a warning. The server recognises
  `TLS_EMPTY_RENEGOTIATION_INFO_SCSV`.

### Behaviour changes

- **fec**: an encoding the application gives without a FEC SSRC gets one when a FEC format
  (flexfec-03, RFC 8627 FlexFEC) is registered, as it gets an RTX SSRC: the offer carries the
  `a=ssrc-group:FEC-FR` and the repair flow is bound
  (`a_minted_fec_ssrc_carries_the_repair_flow_that_recovers_a_lost_packet`).
- **tmmbr**: new `RTCRtpReceiver::set_remote_bitrate_limit(now, Option<u64>)` asks the remote
  sender for an RFC 5104 TMMBR limit through the congestion control interceptor (only for a
  stream that negotiated `ccm tmmbr`; `None` lifts it)
  (`a_receiver_asks_the_sender_to_limit_its_rate_with_tmmbr`).

- **sctp / dscp** (RFC 8837 section 5): when the data channels' codepoint changes (a channel
  of another priority comes or goes) the association's congestion control and RTO start over,
  at the next `handle_timeout`, as on a path change. New diagnostic
  `RTCSctpTransport::congestion_window`
  (`a_new_codepoint_restarts_the_associations_congestion_control`).
- **tests**: SFrame-encrypted frames sent by the application through the opaque payloader
  survive loss with NACK / RTX between two engines
  (`sframe_encrypted_frames_survive_loss_through_nack_and_rtx`); Cryptex end to end
  (`with_cryptex_the_extensions_are_encrypted_on_the_wire_and_read_in_the_clear`); the
  webrtc-svc `setParameters` checks and the data channel priority on the wire.

- **rtp receiver** (W3C webrtc-pc 4.4.1.4): `RTCRtpReceiver::get_parameters` lists no codecs
  once a description negotiated a direction that does not receive (sendonly, inactive): W3C
  `[[ReceiveCodecs]]` is then empty. It listed every engine codec
  (`get_parameters_reports_the_codecs_negotiated_for_each_way`).

- **ice restart**: a local candidate the agent kept across an ICE restart (the default,
  `discard_local_candidates_during_ice_restart` off) and the application gathers again for the
  new generation is announced in an `OnIceCandidateEvent` with the new username fragment, once
  per generation. It was dropped silently as a duplicate, so a trickling peer, which discards
  the old generation's candidates (RFC 8838 section 9), never learned it
  (`each_ice_restart_gathers_and_ends_its_own_generation`).

- **rtcp_session**: without `b=` lines the session bandwidth is the nominal one of the media
  bound (`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH` 1 Mbit/s with video,
  `RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH` 64 kbit/s with audio), or the measured media rate when
  that is more (RFC 3550 section 6.2: a share of the *session* bandwidth). It was the measured
  rate alone, so a sender that started low got little RTCP from its receiver, hence little
  congestion feedback, and climbed slowly: a browser sending three simulcast layers to the
  engine was held near 300 kbit/s (6.3 feedback datagrams a second, gaps to 387 ms). Now 10 a
  second at every rate from 64 kbit/s, no gap over 110 ms, the receiver's RTCP 2.4% of the
  session bandwidth (37% of a 64 kbit/s stream, 8% of 300 kbit/s, 2.4% of 1 Mbit/s: RTP/AVPF
  with `T_rr_interval` zero spends its RTCP share). The TWCC and RFC 8888 generators' cadence
  reads the same nominal figure. A `Gcc` sender fed by the engine's receiver reaches 2 Mbit/s
  from 300 kbit/s in 0.24 s (0.58 s before).
- **gcc**: a pause in sending lowers the estimate the flow resumes at, the more the longer
  the pause (RFC 8836 section 2, requirement 5a): up to 2 s it is kept, beyond that each 10 s
  halves it, never below the starting estimate (`PAUSE_KEEPS_SHARE`, `PAUSE_HALVING`). It was
  kept across any pause.
- **rtcp_session**: when the report blocks do not all fit the MTU, streams losing 10% or more
  since their last report go first, worst first, in up to half the blocks; the rest stay round
  robin (RFC 8083 section 4.3).
- **fec**: the amount of FEC follows the loss the receiver reports (draft-ietf-payload-flexible-fec-scheme-03
  section 8, RFC 8627 section 8, RFC 5109 section 12). The FlexFEC draft-03, RFC 8627 FlexFEC and
  ULPFEC senders read the receiver reports of their protected streams (smoothed, weight 0.3) and
  give each block `ceil(2 x loss x block)` repair packets, none under 0.5% loss and at most half
  the block; flexible masks take the number, the fixed RFC 8627 shapes are sent or not. Before
  any report the configured amount is sent. The repair bit rate of the last second is taken out
  of the congestion controller's target (`Attribute::TargetBitrateChanged`) on its way to the
  application, so media and FEC together stay at the target. New `rtc_interceptor::FecRate`,
  `FEC_MIN_LOSS` and `with_adaptive_rate(bool)` on `FlexFec03SendBuilder`, `FlexFecSendBuilder`
  and `UlpfecSendBuilder` (`false`: the configured amount whatever the loss, as before).
- **ecn**: ECN is initiated and watched as RFC 8888 section 7 requires (RFC 6679 sections
  7.2-7.4). With `SettingEngineBuilder::with_ecn(true)` and `ack ccfb` negotiated, a stream
  no longer sends every packet ECT(1) from the first: one packet in ten (and one at least every
  500 ms) is an ECT(1) probe until the RFC 8888 feedback shows two arrived ECT or CE, then every
  packet is ECT(1). A probe reported Not-ECT, or more than three lost with none received, fails
  the initiation (retried after 60 s); in use, a path that clears the ECN field stops the
  marking, and a high loss of ECT packets sends Not-ECT to compare, initiating again when the
  loss went with the marking (the second time ECN stays off for the stream). New
  `rtc_interceptor::{EcnValidation, EcnState, EcnInitiation}` and
  `SettingEngineBuilder::with_ecn_initiation` (`EcnInitiation::LeapOfFaith`, RFC 6679 section
  7.2.3, marks from the first packet as browsers sending L4S do; failure detection still
  applies). `packetsWithBleachedEct1Marking` counts only packets that were sent ECT(1).
- **rfc8888**: an RTX packet is reported under the RTX SSRC and the sequence number it arrived
  with (sections 3.1 and 6), read from `Attribute::Retransmitted`; it was reported as the
  original packet it is rewritten into before the chain, which told the sender a lost packet
  had arrived, at the retransmission's arrival time.
- **jsep**: offered both `ack ccfb` and `nack ecn`, an answer keeps `ack ccfb` only (RFC 8888
  section 7). New `RTCP_FB_NACK_ECN`.
- **rtcp_session**: without `b=` lines the session bandwidth is the nominal one of the media
  bound (`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH` 1 Mbit/s with video,
  `RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH` 64 kbit/s with audio), or the measured media rate when
  that is more (RFC 3550 section 6.2: a share of the *session* bandwidth). It was the measured
  rate alone, so a sender that started low got little RTCP from its receiver, hence little
  congestion feedback, and climbed slowly: a browser sending three simulcast layers to the
  engine was held near 300 kbit/s (6.3 feedback datagrams a second, gaps to 387 ms). Now 10 a
  second at every rate from 64 kbit/s, no gap over 110 ms, the receiver's RTCP 2.4% of the
  session bandwidth (37% of a 64 kbit/s stream, 8% of 300 kbit/s, 2.4% of 1 Mbit/s: RTP/AVPF
  with `T_rr_interval` zero spends its RTCP share). The TWCC and RFC 8888 generators' cadence
  reads the same nominal figure. A `Gcc` sender fed by the engine's receiver reaches 2 Mbit/s
  from 300 kbit/s in 0.24 s (0.58 s before).
- **rtcp_session**: congestion control feedback (TWCC, RFC 8888) leaves as its generator
  builds it, outside RFC 4585's one Early packet per regular interval and outside the
  regular reports' timing (`RtcpSessionBuilder::with_immediate_congestion_feedback`, default
  `true`; reduced-size where negotiated, else a minimal compound packet). The generators size
  it to the media it reports on: 5% of the media received, every 50 to 250 ms
  (`FeedbackCadence`; the RTCP bandwidth no longer stretches it). The rest of RTCP follows RFC
  3550 section 6.2 on the media measured both ways, with a start-up value before it is
  measured (`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH` 1 Mbit/s with video,
  `RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH` 64 kbit/s with audio). Before, feedback waited for the
  RTCP bandwidth of the measured rate: a sender that started low (a browser with three
  simulcast layers) heard 6.3 times a second, with gaps to 387 ms, and did not climb. Measured
  now (receiver side, one stream / three layers): feedback gaps at most 250 ms from 64 kbit/s
  up, 50 ms from 300 kbit/s; the receiver's RTCP 5.6% of the media at 64 kbit/s, 5.1% at 300
  kbit/s, 3.1% at 1 Mbit/s, 2.5% at 2.5 Mbit/s; a `Gcc` sender fed by it reaches 2 Mbit/s from
  300 kbit/s in 0.49 s. Regular reports at 1 and 2.5 Mbit/s are 50 and 125 a second (RTP/AVPF
  with `T_rr_interval` zero spends the RTCP share).
- **data_channel**: no DCEP handshake timeout by default
  (`SettingEngine::data_channel.dcep_handshake_timeout` is `None`; it was 30 s). RFC 8832 has
  none: the DATA_CHANNEL_OPEN and DATA_CHANNEL_ACK travel on a reliable stream. Under heavy
  loss (`tests/lossy_link_rtc2rtc.rs`, 30 % each way, seed 0x5eed) the ACK took longer than
  30 s, because the peer's half of the SCTP handshake was still in progress (its COOKIE ACK
  lost, the OPEN discarded in COOKIE-ECHOED until a retransmitted COOKIE ECHO was answered) or
  the OPEN was retransmitted at a doubling RTO, and the timeout closed the channel, with no
  error, while ICE, DTLS and SCTP were up. A timeout configured with
  `with_dcep_handshake_timeout(Some(..))` now fails the channel with `OnError` before
  `OnClose`. Test: `a_channel_whose_ack_takes_longer_than_thirty_seconds_still_opens`.
- **data_channel**: a send over 16 KB to a peer without message interleaving (RFC 8831
  section 6.6; every current browser) is refused with the new
  `Error::ErrMessageTooLargeWithoutInterleaving { size, limit }` instead of
  `ErrOutboundPacketTooLarge`, so the message says what the limit is and that
  `SettingEngineBuilder::with_sctp_message_size_limit_without_interleaving(false)` lifts it.
  A send over the peer's `max-message-size` still gets `ErrOutboundPacketTooLarge`. Test:
  `the_16_kb_limit_applies_only_when_i_data_was_not_negotiated`.
- **rtcp_session**: congestion control feedback (TWCC, RFC 8888) leaves as its generator
  builds it, outside RFC 4585's one Early packet per regular interval and outside the
  regular reports' timing (`RtcpSessionBuilder::with_immediate_congestion_feedback`, default
  `true`; reduced-size where negotiated, else a minimal compound packet). The generators size
  it to the media it reports on: 5% of the media received, every 50 to 250 ms
  (`FeedbackCadence`; the RTCP bandwidth no longer stretches it). The rest of RTCP follows RFC
  3550 section 6.2 on the media measured both ways, with a start-up value before it is
  measured (`RTCP_SESSION_NOMINAL_VIDEO_BANDWIDTH` 1 Mbit/s with video,
  `RTCP_SESSION_NOMINAL_AUDIO_BANDWIDTH` 64 kbit/s with audio). Before, feedback waited for the
  RTCP bandwidth of the measured rate: a sender that started low (a browser with three
  simulcast layers) heard 6.3 times a second, with gaps to 387 ms, and did not climb. Measured
  now (receiver side, one stream / three layers): feedback gaps at most 250 ms from 64 kbit/s
  up, 50 ms from 300 kbit/s; the receiver's RTCP 5.6% of the media at 64 kbit/s, 5.1% at 300
  kbit/s, 3.1% at 1 Mbit/s, 2.5% at 2.5 Mbit/s; a `Gcc` sender fed by it reaches 2 Mbit/s from
  300 kbit/s in 0.49 s. Regular reports at 1 and 2.5 Mbit/s are 50 and 125 a second (RTP/AVPF
  with `T_rr_interval` zero spends the RTCP share).
- **interceptor**: bandwidth probing is on in the default interceptor set
  (`DefaultInterceptorOptions::bandwidth_probing` now `true`; `false` is the opt-out). RFC 8836
  section 2 (requirement 4, a SHOULD) asks a congestion controller to adapt as quickly as
  possible to the initial conditions: 90% of a 2.5 Mbit/s path from a 300 kbit/s start in 0.2 s,
  against 26 s without. `CongestionControlBuilder::with_bandwidth_probing` stays off for a chain
  built by hand.
- **nack**: a probe cluster the application's media does not fill is filled with padding-only
  packets on the RTX stream (no original sequence number, `PROBE_PADDING_OCTETS` = 255 octets of
  RFC 3550 padding), which receivers drop; they were retransmissions of recent packets, which a
  receiver hands to its application again (this crate's endpoint does, after de-encapsulating
  RTX). An application sending a fifth of the path spends 3.7% of its octets on probes (3.8% with
  the retransmissions).
- **cc**: after a large drop of the target (below two thirds of its high of the last two
  seconds) the rate before the drop is probed for, once a second from a second after it, for
  five seconds (`ProbeController::with_probe_after_drop`, default `true`; libwebrtc's
  `RequestProbe` in outline). A 2 s burst of cross traffic at half the capacity costs 2 s of
  share instead of 23 s (RFC 8836 section 2, requirement 1f).
- **gcc**: a packet lost out of a queue at its limit is over-use for the delay-based controller
  (`Gcc::with_loss_at_queue_limit_as_overuse`, default `true`; `QueueLimitDetector`): a feedback
  batch with a loss whose arrived packets all waited at least 75% of the highest queueing delay
  of the last five seconds, and at least 10 ms. At a full tail-drop queue the delay gradient is
  zero and the loss-based controller holds between 2% and 10% loss (draft-ietf-rmcat-gcc-02
  section 6), so `Gcc` held the queue full: on a shared bottleneck it took 0.97 of the path from
  a TCP-like transfer and held a late-joining flow at the floor (RFC 8836 section 2, 3 and 2a).
  Now 0.21 / 0.79 against the transfer and 0.49 / 0.45 with the late flow. The adaptive
  threshold (section 5.4) was checked for the late-joiner case and is not the cause: it is the
  draft's, bounded to 6..600 ms and quick to fall back.
- **gcc**: over-use that lasts cuts the target once per round trip (10 to 200 ms), at once
  when the received rate has fallen below half the target
  (`Gcc::with_one_decrease_per_round_trip`, `RateController::with_one_decrease_per_round_trip`,
  default `true`; libwebrtc's `TimeToReduceFurther`). draft-ietf-rmcat-gcc-02 section 5.5 cuts on
  every update while over-use lasts; `false` is that.
- **cc**: `ProbeController::poll_timeout` no longer names an instant `poll` has already been
  called at: a deadline that passed with nothing to send (the application caught up with its
  target, or stopped sending) asked to be woken again at once, over and over.
- **rtcp_session**: the SDES chunk of each local SSRC carries, after the CNAME, the MID of
  its m= section (RFC 9143 section 15.1: "SHOULD be sent in the first few RTCP packets ... and
  regularly thereafter"), the encoding's rid as RtpStreamId and, on RTX and FEC SSRCs, as
  RepairedRtpStreamId (RFC 8852 sections 3.1, 3.2), in every compound packet. The peer
  connection hands them over after each negotiation with the new
  `RtcpSessionControl::StreamIdentifiers`.
- **association**: an RtpStreamId / RepairedRtpStreamId SDES item from the remote names the
  rid of a stream whose packets carry no RID / RRID header extension, as an SDES MID item
  already named its m= section (RFC 8852 section 3). A value that is not 1 to 255
  alphanumerics is ignored.
- **sctp, sdp**: both endpoints initiate the SCTP association (RFC 8841 section 9.3), in either
  DTLS role; only the DTLS client did. The peer's INIT is answered by the association this side
  initiated (RFC 9260 section 5.2.1), so the two make one association, and an association no
  longer waits for a retransmission when one of the two INITs is lost.
- **sdp**: a data channel section without a valid `a=sctp-port` is refused with
  `ErrSDPSctpPortInvalid` (RFC 8841 section 5.1); it was taken with port 5000 assumed, and
  `a=sctpmap` is no longer read as a port. A section is a data channel section only with
  proto `UDP/DTLS/SCTP` or `TCP/DTLS/SCTP`.
- **sctp**: an SCTP packet that is not between the two negotiated `a=sctp-port` values is
  dropped (RFC 8841 section 9.3).
- **datachannel**: an in-band channel that the peer resets before acknowledging it reports
  `OnError` before `OnClose`, and no `OnClosing` (RFC 8832 section 6: its setup failed).
- **datachannel**: `rtc_datachannel::DataChannel::handle_read` returns an error for a
  DATA_CHANNEL_OPEN on a channel in use (it answered with a DATA_CHANNEL_ACK) and for a message
  under a PPID that is not a data channel's (it queued it for `poll_read`); a refused message
  is not counted. `DataChannelOpen::marshal` returns an error for a label or protocol over 65535
  bytes.

- `Vp8Packet` and `Vp9Packet` have a new public field `picture_id_15_bits`, and every field
  describes the packet last parsed (a field the packet did not carry reads 0 / empty; they kept
  the previous packet's values). `Vp9Packet::f` is false when `I` is 0.
- `Av1Payloader` has a public field (`sequence_header_per_spatial_layer`): `Av1Payloader {}`
  no longer compiles, `Av1Payloader::default()` does. It refuses a buffer with two temporal
  units.
- `Vp9Payloader` sends a frame that is not VP9 with `P=1` and a reference index, unless it is
  the stream's first frame (it was `P=0`).
- `ErrTooManySpatialLayers` is no longer returned by `Vp9Packet`.

### Changed

- **rtcp**: `configure_rtcp_reports` registers the RTCP session instead of
  `SenderReportInterceptor` and `ReceiverReportInterceptor` (both stay, for a chain built by
  hand: fixed timers, no scheduling). What changes on the wire with the default interceptors:
  - every feedback packet (NACK, PLI, FIR, TWCC, REMB, anything the application writes) leaves
    inside a compound packet behind an RR or SR and an SDES, with the connection's SSRC as
    packet sender (it left bare, from a random or zero SSRC);
  - feedback is held to the RTCP bandwidth (5% of the measured media bitrate, 64 kbit/s at
    least): one early packet per regular interval, the rest merged into the next packet. With
    little media this spaces TWCC feedback out; give the session bandwidth or a larger
    `with_rtcp_fraction` to change it;
  - receiver reports come from one SSRC per connection, with all report blocks in one packet;
    sender reports stop two seconds after a stream falls silent; the CNAME in RTCP is the
    connection's, not the MediaStream id (the SDP still writes that one);
  - a retransmission is counted in the report of the RTX stream, not of the stream it repairs;
  - an SR, RR or SDES the application writes is dropped (the session's own stand for it);
  - `close()` sends a BYE.
- **nack**: `NackGeneratorBuilder` defaults to ten requests per packet and a two second age
  (they were unlimited); `with_max_nacks_per_packet(0)` and `with_max_packet_age(None)` lift
  them.
- **rtcp**: a sender report's SDES written by the peer connection for a chain without the
  session names the connection's CNAME, not the MediaStream id.

- **dtls**: an `rtc-dtls` server configured with no SRTP profile ignores a client's `use_srtp`
  (RFC 5764 section 4.1.1) instead of aborting with `ErrServerNoMatchingSrtpProfile`; the
  client, which asked for SRTP, is the one that aborts (`ErrRequestedButNoSrtpExtension`)
  unless built with `with_use_srtp_optional`.
- **sdp**: errors `ErrSessionDescriptionInvalidSetup`, `ErrSessionDescriptionInvalidTlsId`,
  `ErrInvalidIdentityAssertion`.
- **rtp**: a two-byte header-extension block is parsed whatever its appbits (RFC 8285 section
  4.3). Only the exact profile `0x1000` selected the two-byte parser; `0x1001` to `0x100F` came
  back as one opaque element with ID 0, so MID, RID and the transport-wide number in it were not
  found.
- **rtp**: ID 0 with a non-zero length ends a one-byte extension block and the elements before
  it are kept (RFC 8285 section 4.1.2). It was parsed as an element with ID 0, and the header
  could then not be marshalled again.
- **rtp**: `Header::set_extension` on a header without extensions takes the two-byte form for an
  ID above 14 or an empty element (RFC 8285 section 4.2). It chose the form from the length
  alone, so `set_extension(20, ..)` returned `Ok` and the header could not be marshalled. The
  TWCC sender stamped packets that way when the peer mapped transport-cc above 14 and discarded
  the error; it now converts a one-byte header, so every packet of such a stream is two-byte.
- **rtp**: `Header::default()` is version 2, and `Header` marshals and unmarshals version 2 only
  (RFC 3550 section 5.1). A header built from `Default` went out as version 0, which a peer reads
  as STUN or DTLS.
- **rtp**: a marshalled extension block is as long as `marshal_size()` says when a parsed block
  had more than three bytes after its elements (an ignored tail after ID 15).
- **rtp**: the packetizer sets the marker bit as the payload format has it. Every Opus, G.711
  and G.722 packet carried it (the video rule); audio now carries it only on the first packet
  after a silence skipped with `skip_samples` (RFC 3551 section 4.1, RFC 7587 section 4.1).
- **rtp**: a G.711 / G.722 buffer split over several packets gets a timestamp per packet (RFC
  3551 section 4.3); the fragments shared one.
- **rtp**: `packetize` returns an error for an MTU that leaves no room after the RTP header; an
  MTU below 12 underflowed (a panic in debug builds, a huge MTU in release builds).
- **rtp**: the H.264 payloader sends NAL units in the order given and loses none (RFC 6184
  sections 5.5 and 6.3). `SPS, SEI, PPS, IDR` went out as `SEI, STAP-A, IDR`; a second SPS or PPS
  of an access unit replaced the first; an SPS without a PPS was never sent. The STAP-A header
  has the highest NRI and the OR of the F bits of what it aggregates (it was the constant
  `0x78`), an FU-A keeps the F bit, and NAL units of reserved or packet types (0, 24 to 31) are
  not sent.
- **rtp**: the H.264 depacketizer takes a NAL unit that is its header octet alone (end of
  sequence, end of stream) and an FU-A with an empty payload (RFC 6184 section 5.8); both were
  `ErrShortPacket`. Reserved packet types are ignored instead of an error that made
  `SampleBuilder` drop the sample (section 5.4).
- **rtp**: `H265Packet::depacketize` returns NAL units (RFC 7798 section 6). It returned the RTP
  payload unchanged, so a `SampleBuilder<H265Packet>` sample held AP and FU headers. Single NAL
  units, the units of an aggregation packet, a NAL unit reassembled from its fragmentation
  units (bounded at 4 MiB) and what a PACI packet carries come out as Annex B; nothing of type
  48 to 63 does. A NAL unit that is its two-byte header alone is accepted.
- **rtp**: `H265PACIPacket::tsci()` reads TL0PICIDX, IrapPicID, S, E and RES from the first
  three octets of the PHES (RFC 7798 section 4.5); it read the first octet twice and never the
  third.
- **rtp**: the H.265 payloader splits an Annex B stream at start codes of either length; a
  four-byte code followed by three-byte ones made one "NAL unit" of the whole access unit.
- **media**: `H26xWriter` writes what the H.265 depacketizer returns, so the media in a PACI
  packet is written and reserved packet types are not.
- **turn**: a 437 (Allocation Mismatch) to a Refresh, CreatePermission or ChannelBind ends the
  allocation (RFC 8656 sections 5 and 8.3). The error was returned from `handle_read` or logged,
  the relay stayed in the client and a Refresh went out every half lifetime for ever. The client
  now drops the allocation, with its permissions, channel bindings and outstanding requests, and
  raises `Event::AllocationLost`.
- **turn**: an allocation released with `Relay::close` stays released. If the Refresh with
  LIFETIME 0 and its retry went unanswered, or the server answered 437, the next periodic
  refresh asked for the old lifetime again and kept the allocation alive. `close` now stops
  every refresh at once; `Event::AllocationReleased` reports the end (success, 437, or no
  answer).
- **turn**: channel bindings belong to their allocation (RFC 8656 section 12). They were kept per
  client, so a new allocation sent ChannelData on channel numbers only the previous one had
  bound, which the server drops.
- **turn**: permissions and channel bindings follow the RFC's timers. A permission lasts 300 s
  from its last accepted CreatePermission or ChannelBind: one whose refresh the server refuses
  is dropped (`Event::PermissionLost`), and a refused refresh of several addresses is repeated
  address by address so only the refused ones end. A channel binding lasts 10 minutes: one that
  carried data is rebound from a timer, one left idle is bound again (with the data in Send
  indications) before ChannelData is used on it, and a channel number is reused for another
  peer address only 15 minutes after the last ChannelBind sent for it.
- **turn**: the first Allocate response is read for what it is. A success (a server that asks
  for no credential, RFC 8656 section 7.2) is an allocation; an error other than 401 keeps its
  code. Both were reported as `AllocateError(attribute not found)`, the first while the server
  held the allocation.
- **turn**: an Allocate success response without XOR-RELAYED-ADDRESS or LIFETIME is reported as
  `AllocateError` under the caller's id and the allocation is deleted with a Refresh of
  LIFETIME 0. It ended `handle_read` with an error and no event, and left the allocation on the
  server.
- **turn**: with all 4096 channel numbers taken, data to one more peer address goes as Send
  indications; the send failed.
- **turn**: ChannelData cannot carry more than 65 535 bytes; `Relay::send_to` and
  `ChannelData::encode` refuse a longer payload instead of writing a wrapped length, which over
  TCP or TLS broke the framing of every later message.
- **turn**: an allocation whose Refresh requests all fail is refreshed again at half the time
  it has left, and is dropped (`Event::AllocationLost`) when its lifetime has run out.
- **turn**: a ChannelBind the server refuses is reported (`Event::ChannelBindError`) and tried
  again after a minute; it was sent again with every packet. A 400 (the channels of client and
  server are out of step) deletes the allocation, as RFC 8656 section 12.3 recommends.
- **turn**: a ChannelBind success refreshes the peer's permission (RFC 8656 section 12.3).
- **turn**: `Client::update_credentials` documents that a live allocation takes a new password,
  not a new username (the server answers 441, RFC 8656 section 5).
- **turn**: the `turn_client_tcp` example no longer names RFC 6062; it is a UDP allocation
  reached over TCP (RFC 8656 section 3.1).
- **stun**: `Client` delivers a response of any length. It read into a 120-byte buffer, so a
  132-byte Binding response (what coturn sends over IPv6) failed to decode and the transaction
  timed out. `Message::read_from` reads its reader to the end.
- **stun**: `Client` takes as the response only a success or error response of the request's
  method that comes from the server (RFC 8489 section 6.3). Any message with a known
  transaction id, a request or an indication from any address included, ended the transaction.
- **stun**: a truncated MAPPED-ADDRESS or XOR-MAPPED-ADDRESS is an error; it decoded to an
  address filled up with zeros. The first byte of the value is ignored (RFC 8489 section 14.1);
  a non-zero one failed the attribute.
- **stun**: the reserved bits of ERROR-CODE are ignored (RFC 8489 section 14.8). With one set
  next to the class, a 438 decoded as 1238 and a stale nonce went unrecognised.
- **stun**: `Uri`'s `Display` writes every IPv6 host in brackets; one without `::` came out as
  `stun:2001:db8:1:2:3:4:5:6:3478`, which does not parse back.
- **stun**: `MessageIntegrity::check` no longer rewrites the message's length field while it
  runs, and checks by the attribute's position, whatever follows it.

- **turn**: an attribute after the MESSAGE-INTEGRITY of a response is not read (RFC 8489
  section 9). The client checked the HMAC and then read attributes wherever they sat, so
  anyone on the path could append one to a genuine response: an XOR-MAPPED-ADDRESS appended to
  an Allocate success response was handed out as the client's server-reflexive address
  (`Relay::mapped_addr`), and so for a RESERVATION-TOKEN, an ADDRESS-ERROR-CODE or an
  ALTERNATE-SERVER. Every received message now goes through `rtc_stun::validated::Validator`
  and the handlers read the validated message only. The same holds for indications: nothing
  after an integrity attribute in a Data or ConnectionAttempt indication is read.
- **turn**: an XOR-RELAYED-ADDRESS of 0.0.0.0:0 in an Allocate success response is passed
  over. coturn 4.6 sends one beside the real address when it refused the same client another
  address family before (an IPv6 request answered 440, then an IPv4 one): the client took the
  two for a family mismatch, deleted the allocation and refused to allocate again.
- **test-env**: three expectations of `tests/testenv_turn_client.rs` that coturn 4.6.1 does
  not meet are corrected: it ignores ADDITIONAL-ADDRESS-FAMILY (comprehension-optional; one
  IPv4 address comes back), its 441 to a Refresh under another username carries no integrity
  the client can verify (RFC 8489 section 9.2.5 has the client discard it; the test is now
  `a_refresh_under_another_username_is_not_accepted`), and its Allocate after a 440 carries
  the all-zero address above.
- **turn**: a response of another method than its request's no longer ends the transaction. An
  Allocate success response carrying the transaction id of an outstanding Binding request
  removed the transaction and raised no event, so the caller waited for ever.
- **turn**: a 401 to an authenticated request that names another realm is answered with the
  credential for that realm (RFC 8489 section 9.2.5); it was reported as a failure. A 438 with
  a new realm re-keys the allocation it is about, not every allocation of the client.

### Features

- **cc**: the media receiver's side of TMMBR (RFC 5104 section 4.2.1.2). An application asks a
  remote sender to stay under a bit rate with `TmmbrControl::Limit` (and lifts it with
  `TmmbrControl::Clear`) written into the chain; the congestion control interceptor sends the
  TMMBR at once for a remote stream that negotiated `ccm tmmbr` (and never for one that did
  not), with the overhead measured on the stream as section 4.2.1.2's running average, capped
  at `TmmbrControl::NegotiatedMaximum`. It keeps the latest TMMBN of each sender, asks again
  as owner when its tuple changed or as non-owner when its tuple would enter the bounding set,
  and repeats an unacknowledged request every `TMMBR_REPEAT_INTERVAL` (1 s). Inbound TMMBN,
  typed or raw, is read (it was dropped).
- **gcc**: the receive-side variant of draft-ietf-rmcat-gcc-02 (section 3) in the default
  set (`configure_remb`): `RembGeneratorInterceptor` sends a REMB for every remote stream that
  negotiated `goog-remb` and neither transport-wide feedback nor RFC 8888, from the delay-based
  controller run on its arrivals against abs-send-time or the RTP timestamp, at once when the
  estimate falls by 3% or more and otherwise once a second; `AbsSendTimeInterceptor` stamps
  abs-send-time on the packets of local streams that negotiated it, as they leave the pacer.
  `goog-remb` was offered on video without any REMB ever being sent.
- **srtp**: `OnSrtpKeyLifetimeExpiring` (the SRTP contexts' `KeyLifetimeExpiring`) and
  `OnCryptexRequiredViolation` reach the application; `SettingEngineBuilder::with_srtp_key_lifetime`;
  the SRTP profile is mapped from its DTLS-SRTP code point (`ProtectionProfile::from_dtls_srtp_id`),
  a NULL-cipher profile never taken. rtc-srtp: `keying::validate_key_lifetime`.
- **encoded transform**: `rtc::sframe` re-exports `rtc-sframe` (RFC 9605); `rtp::codec::opaque`
  is a format-agnostic payloader / depacketizer for bytes the RTP layer does not parse (a
  whole-frame SFrame ciphertext over several packets; start and end flags in a one-byte
  header; a unit missing a fragment is dropped whole).
- **priority** (W3C webrtc-priority, RFC 8837): `RTCPriorityType` with its DCEP values,
  encodings' `priority` / `network_priority` (set with `setParameters`),
  `RTCDataChannel::priority_type()`, and `RTCPeerConnection::dscp(&datagram)`: the DSCP of
  RFC 8837 Table 1 the socket layer sets on each datagram `poll_write` returned (per RTP
  stream, one for the SCTP association, one for everything over TCP).
  `SettingEngineBuilder::with_non_interactive_video` selects the AF3x video codepoints.
- **dtmf**: `RTCDTMFSender` (W3C webrtc-pc section 7) as `RTCRtpSender::dtmf()` for an audio
  sender: `insert_dtmf(now, tones, duration, inter_tone_gap)`, `tone_buffer()`,
  `can_insert_dtmf()`; `RTCPeerConnectionEvent::OnDtmfToneChange`. The tones play out on the
  connection's timers as RFC 4733 telephone-event packets in the sender's first stream: the
  engine numbers them in the stream's sequence and moves the application's later audio
  packets past them (`write_rtp` adds the count of event packets sent), timestamps follow the
  last audio packet, the final packet goes three times 50 ms apart.
- **rtp**: `TelephoneEventSender` sends the final report of each segment of a long event three
  times, as the final report of the event (RFC 4733 section 2.5.1.4 SHOULD).
- **data channels**: `RTCDataChannel::buffered_amount()` (W3C `bufferedAmount`). At the
  SCTP connected procedure a channel without a usable id fails alone (`OnError` with
  `data-channel-failure`, then `OnClose`) instead of the whole event failing; the DCEP
  handshake timeout fires `OnError` before `OnClose`; a second `close()` while closing does
  nothing.
- **states and events** (W3C webrtc-pc): the getters `signaling_state()`,
  `ice_gathering_state()`, `ice_connection_state()`, `connection_state()`; the transport
  events `OnIceTransportStateChange`, `OnIceGathererStateChange`,
  `OnSelectedCandidatePairChange`, `OnDtlsTransportStateChange`, `OnDtlsTransportError` and
  `OnSctpTransportStateChange`, each before the connection-level event it causes; `RTCError`
  and `RTCErrorDetailType` (`rtc::peer_connection::rtc_error`), on the DTLS error event (with
  the fatal alert sent or received, or `fingerprint-failure`) and for data channels through
  `RTCPeerConnection::data_channel_error(id)` (`sctp-failure` with the SCTP cause code,
  `data-channel-failure`); `report_ice_candidate_error` for the application that gathers
  (`icecandidateerror`: 701 once per URL, the address withheld unless exposed);
  `RTCCertificate::generate_certificate` (W3C generateCertificate: 30 days by default, at most
  365, random name and serial). rtc-sdp: `SessionDescription::parse_located` and
  `SdpParseError` give the line of a parse error. rtc-dtls: `Endpoint::connection_fatal_alerts`.
  rtc-sctp: `Association::abort_cause_code`.
- **dtls**: `DTLSConn::record_overhead` and `Endpoint::record_overhead`: what each protected
  record adds to its content (the record header, the connection id it carries under DTLS 1.3
  or a DTLS 1.2 `tls12_cid` record, and the suite's expansion), for a layer above that sizes
  its datagrams for a path MTU
  (RFC 6347 section 4.1.1.1, RFC 9147 section 4.4). The peer connection sizes SCTP packets by
  it.
- **interceptor**: bandwidth probing, as an option that is off by default
  (`CongestionControlBuilder::with_bandwidth_probing`, `bandwidth_probing` in
  `DefaultInterceptorOptions`). The congestion controller asks for clusters of packets at a
  multiple of the target (three and six times the starting rate at the start, twice the result
  while the path carries what is asked, one every five seconds while the application sends less
  than the target), the pacer releases a cluster at its rate and marks its packets, the NACK
  responder fills it with retransmissions of recent packets on the RTX stream, and the estimator
  takes the rate the cluster arrived at (`BandwidthEstimator::on_probe_result`, `ProbeController`,
  `ProbeRequest`, `ProbePacket`, `probe_estimate`). On a virtual clock `Gcc` goes from 300 kbit/s
  to 2.5 Mbit/s in 0.4 s with it and in 26.1 s without
  (`rtc-interceptor/tests/bandwidth_probing.rs`). No RFC requires probing (RFC 8836 section 2
  names it as one way to start faster; draft-ietf-rmcat-gcc-02 has none), and it sends packets
  the application did not write, so it is not a default.
  With probing, an application that sends less than the target keeps the estimate near
  the path's capacity: over-use after a probe backs off from what the probe measured, and a
  probe that arrives at about the estimate renews the measurement
  (`gcc::estimator::PROBE_CONFIRMS_ESTIMATE`); before, the estimate fell back to one and a half
  times what the application sent, and with it what the application was told to send, to the
  floor (0.04 of the capacity after 30 s; now 0.95).
- **test**: `rtc-interceptor/tests/rfc8836_multi_flow.rs`, a deterministic multi-flow
  bottleneck (FIFO with tail drop or random early drop, capacity changes, `Gcc` flows probed as
  in the default set, a TCP-like transfer, cross traffic) for the RFC 8836 section 2
  properties. Two flows share evenly, a late flow gets its share, `Gcc` and TCP neither starve
  the other, bursts leave no queue, a pause and an AQM leave the flow stable. The TCP-like model
  is checked on its own (it fills a path alone and takes what a constant-rate flow leaves).
- **test**: `rtc-interceptor/tests/nack_recovery_under_loss.rs`: NACK recovers every packet
  over 5% loss each way with jitter on the virtual clock, with and without the RTCP session.
  `tests/testenv_impairment.rs` prints the packets NACK left lost, and the first one received.
- **gcc**: a packet the receiver reports as arrived with ECN-CE counts as a lost one in the
  loss-based controller (RFC 8888 section 7, RFC 6679 section 7.3.3); the mark was only counted
  in statistics.
- **cc**: several TMMBRs in one compound RTCP packet are answered with one TMMBN (RFC 5104
  section 4.2.2.2).
- **interceptor**: the congestion controller notices a path change by itself: when inbound
  packets keep arriving between other addresses than before (another candidate pair), the
  estimator is told (`BandwidthEstimator::on_path_change`) and `Gcc` starts its delay side over
  (RFC 8836 section 2, requirement 1).
- **test**: the `interceptor_inbound` fuzz target's logic runs as a unit test over a fixed
  corpus (`tests/interceptor_inbound_fuzz_corpus.rs`).

- **sctp**: `RTCPeerConnection::reject_data_section` asks for the data section to be rejected
  (m= port zero) in the next offer, or in the answer to the peer's next offer: RFC 8841
  section 10.5, closing the SCTP association and the DTLS association under it. A data
  channel created afterwards brings a new section, with a new `a=tls-id` and `a=sctp-port`.
- **sctp**: when ICE selects another candidate pair the association is told (RFC 8831
  section 5): its congestion control and RTO start over and its packet size is set for the
  new path.
- **sctp**: a stream reset the peer answers with "denied" or an error fails the data channel
  it was closing (`OnError`, `OnClose`) instead of leaving it `closing`; an inactive path
  (RFC 9260 section 8.2) changes neither the transport's state nor a channel's.
- **setting_engine**: `SettingEngineBuilder::with_implicit_rollback`: a remote offer applied
  while a local offer is pending rolls the local offer back first (W3C webrtc-pc "set a session
  description"), in one call; an offer that is then refused leaves the local offer pending.
  On by default; `false` has the application roll back (RFC 9429 sections 5.6 and 5.7).
- **media_engine**: a VP9 format without `profile-id` is the same format as one with
  `profile-id=0` when negotiated codecs are merged (RFC 9628 section 6).

- **receiver**: an RTP stream whose SSRC no description declares and whose packets carry no
  MID is delivered to the one transceiver that receives its payload type (RFC 9143 section
  9.2); with several transceivers it was dropped. An RTCP SDES MID item maps its SSRC to the m=
  section it names, for such a stream. The MID header extension is read when RtpStreamId is
  not negotiated; it was ignored then.
- **sctp**: `RTCPeerConnection::reject_data_section` asks for the data section to be rejected
  (m= port zero) in the next offer, or in the answer to the peer's next offer: RFC 8841
  section 10.5, closing the SCTP association and the DTLS association under it. A data
  channel created afterwards brings a new section, with a new `a=tls-id` and `a=sctp-port`.
- **sctp**: when ICE selects another candidate pair the association is told (RFC 8831
  section 5): its congestion control and RTO start over and its packet size is set for the
  new path.
- **sctp**: a stream reset the peer answers with "denied" or an error fails the data channel
  it was closing (`OnError`, `OnClose`) instead of leaving it `closing`; an inactive path
  (RFC 9260 section 8.2) changes neither the transport's state nor a channel's.

- **ice**: `AgentConfig::failed_nomination` / `SettingEngineBuilder::with_ice_failed_nomination`
  (`FailedNomination::{Retry, FailChecklist}`): what a controlling agent does when its
  nomination times out. `Retry`, the default, nominates the pair again while the peer is heard
  from; `FailChecklist` is RFC 8445 section 7.2.5.3.4 to the letter (the pair and the checklist
  fail). The one ICE default that is not the RFC's; see `docs/conformance/audit/rfc8445.md`
  ("Decisions").
- **ice**: `rank_local_candidates` and `Agent::add_local_candidates` rank candidates gathered
  together as RFC 8421 section 4 recommends for a dual-stack host: the IPv6 candidates of a type
  get a head start of (N4 + N6) / N4 places, then the families alternate. Candidates added one
  at a time are ranked in their order, as before.
- **ice**: a Binding request authenticated by MESSAGE-INTEGRITY-SHA256 is answered (success,
  487, 420) with MESSAGE-INTEGRITY-SHA256 alone (RFC 8489 section 9.1.3); it was answered with
  MESSAGE-INTEGRITY.
- **dtls**: a DTLS 1.3 client whose second ClientHello is refused with illegal_parameter (its
  HelloRetryRequest cookie had expired: a server endpoint's is good for 60 to 120 s) starts the
  handshake over with a new ClientHello, without a cookie (RFC 9147 section 5.1), at most twice;
  it failed.
- **ice**: `Agent::handle_transport_error` / `RTCPeerConnection::handle_ice_transport_error`:
  the application reports a hard ICMP error (RFC 8445 section 7.2.5.2.2), a TCP connection
  that could not be established, or one whose first answer is not STUN (RFC 6544 section 7.1),
  and the pair fails at once. A pair a check has validated is never failed that way.
- **ice**: Ta agreed with the peer (RFC 8445 section 14.2): `Agent::proposed_pacing`,
  `set_remote_pacing`, `pacing`. (Writing and reading `a=ice-pacing` is not wired yet.)
- **ice**: at most five TCP connection attempts are outstanding to one remote IP address (RFC
  6544 section 12).
- **ice**: the peer connection fails the pairs of a remote TCP candidate whose first answer, on
  a connection its active candidate opened, is not STUN (RFC 6544 section 7.1);
  `Agent::handle_non_stun_before_validation` for other drivers.
- **ice**: an mDNS name lost to another host (RFC 6762 section 9) is replaced by a new
  `<uuid>.local` name and the candidate announced again (`Event::LocalCandidateRenamed`,
  `OnIceCandidateEvent`).
- **ice**: mDNS options of `rtc-mdns` reachable from the agent and the peer connection:
  the datagram's destination reported by the driver, the QU bit, and one `MdnsRateLimit`
  shared by several peer connections (`with_multicast_dns_destination_reported`,
  `with_multicast_dns_unicast_response`, `with_multicast_dns_rate_limit`).
- **ice**: the candidate of `OnIceCandidateEvent` carries the username fragment of its ICE
  generation, and `to_json` hands it on (RFC 8838 section 9).
- **ice**: `AgentConfig::tie_breaker` / `SettingEngineBuilder::with_ice_tie_breaker` fix the ICE
  tiebreaker (RFC 8445 section 5.2); `Agent::tie_breaker`, `Agent::is_lite`.
- **ice**: `AgentConfig::send_data_before_nomination` /
  `SettingEngineBuilder::with_ice_data_before_nomination`: data on the best valid pair before
  a pair is selected (RFC 8445 section 12.1).
- **interceptor**: `negotiated_congestion_feedback` / `CongestionFeedbackFormat`: the one
  feedback format a stream runs on, from its negotiated feedback (RFC 8888 when `ack ccfb` is
  there, transport-wide congestion control otherwise). The TWCC sender does not number a stream
  that runs on RFC 8888, the TWCC receiver does not report it, and the congestion controller
  reads each stream's packets from one format only.
- **interceptor**: `DefaultInterceptorOptions` and `register_default_interceptors_with_options`:
  the settings of the default set in one place (`congestion_feedback`, `unnegotiated_tmmbr`,
  `pacer_immediate_release`). `configure_tmmbr`, `configure_ulpfec_with_placement`.
- **interceptor**: congestion control feedback follows the RTCP bandwidth. The generators read
  the session's `b=` lines and `a=rtcp-rsize` (`RtcpSessionControl`) and measure the media rate
  as the RTCP session does, and build one report per RTCP packet the session may send. Measured
  on a virtual clock, two engines, RFC defaults (5% RTCP bandwidth, `T_rr_interval` 0, compound
  RTCP): at 64 kbit/s of media 2.5 feedback datagrams a second with at most 0.66 s (TWCC) or
  0.79 s (RFC 8888) between two, where a fixed 100 ms interval gave 2.07 and 1.87 a second with
  gaps of 1.15 s and 1.35 s; at 100 kbit/s 3.1 and 2.5 a second (gaps 0.5 s; fixed: 4.0 and 3.5
  with gaps of 0.6 s and 0.7 s); from 300 kbit/s up 10 a second either way
  (`rtc-interceptor/tests/congestion_feedback_rate.rs`).
- **interceptor**: with reduced-size RTCP negotiated, TWCC and RFC 8888 feedback leave as early
  RTCP without a compound packet around them (RFC 8888 section 3.1, RFC 5506).

- **congestion control is on by default** (RFC 8834 section 7). `register_default_interceptors`
  now installs `Gcc` over the receiver's TWCC or RFC 8888 feedback, the pacer that releases
  media at its target, the TWCC sender, and the RTP circuit breaker.
  `register_default_interceptors_with_handles` also returns the handles
  (`DefaultInterceptorHandles`); `register_default_interceptors_without_congestion_control` is
  the explicit opt-out and is the set the default used to be. The fork's pull-style `GccHandle`
  / `GccInterceptor` stays: placed in `Slot::CongestionControl` it replaces the default
  estimator, and it now announces its estimate so the default pacer follows it.
- **RTP circuit breaker** (RFC 8083; RFC 8834 section 7.1): `CircuitBreakerInterceptor` at the
  new `Slot::CircuitBreaker`, with all four breakers (RTCP timeout, media timeout, congestion
  against ten times the TCP throughput, media usability), ceasing transmission per flow or per
  group, the optional reduction by ten before ceasing, and restart only on request and not
  before the triggering interval (`CircuitBreakerHandle`). `configure_circuit_breaker` installs
  it on its own.
- **external limits on the estimate**: `CongestionControlInterceptor` holds the target under
  the tightest of the negotiated session bit rate
  (`CongestionControlHandle::set_session_bitrate_limit`, for `b=AS` / `b=TIAS`), the receiver's
  REMB (advertised as `goog-remb` and ignored until now; it lapses after 3 s without a repeat),
  the TMMBR bounding set (RFC 5104 sections 3.5.4 and 4.2: bounding set, owners, overhead at
  the packet rate in use, the `2 * RTT` hold-off before a looser limit, and a TMMBN for every
  TMMBR, on owner BYE and on owner timeout), and the circuit breaker's reduced rate.
  `BandwidthEstimator` gains `on_packet_sent`, `on_round_trip_time`, `set_external_bounds`,
  `on_receiver_report` and `on_path_change`, all with defaults.
- **gcc**: missing feedback is treated as over-use (RFC 8888 section 5, RFC 8836 requirement
  10): 500 ms without feedback while packets are being sent halves the target, and again for
  each further 500 ms; the change reaches the pacer on an empty RTCP carrier. The round trip
  time measured from feedback scales the additive increase and is in `EstimatorStats`. The
  loss-based controller runs on the fraction lost of receiver reports when the receiver sends
  no per-packet feedback (draft section 7). `CongestionControlHandle::notify_path_change` restarts the delay side.
- **pacer**: the burst is one 5 ms group at the target rate (draft-ietf-rmcat-gcc-02 section
  4), floored at one 1500-byte packet; it was 100 ms of the target.
- **setting_engine**: `SettingEngineBuilder::with_implicit_rollback`: a remote offer applied
  while a local offer is pending rolls the local offer back first (W3C webrtc-pc "set a session
  description"), in one call; an offer that is then refused leaves the local offer pending.
  Off by default: RFC 9429 sections 5.6 and 5.7 have the application roll back.
- **media_engine**: a VP9 format without `profile-id` is the same format as one with
  `profile-id=0` when negotiated codecs are merged (RFC 9628 section 6).

- **receiver**: an RTP stream whose SSRC no description declares and whose packets carry no
  MID is delivered to the one transceiver that receives its payload type (RFC 9143 section
  9.2); with several transceivers it was dropped. An RTCP SDES MID item maps its SSRC to the m=
  section it names, for such a stream. The MID header extension is read when RtpStreamId is
  not negotiated; it was ignored then.

- **jsep**: what an applied answer negotiates reaches the interceptors that act on it, as
  control messages written into the chain (`RTCPeerConnection` did not feed them):
  `a=rtcp-rsize` in the offer and the answer as `RtcpSessionControl::ReducedSize`; the remote
  `b=TIAS` / `b=AS`, `b=RS` and `b=RR`, summed over the media sections (RFC 8859 section 6), as
  `RtcpSessionControl::Bandwidth`; the local `trr-int` as `RtcpSessionControl::TrrInt`; and
  `rtx-time` of the RTX formats as the new `NackControl`.
- **interceptor**: `NackControl::{LocalRtxTime, RemoteRtxTime}` (RFC 4588 section 8.1), by
  retransmission payload type: the NACK responder keeps a sent packet for the `rtx-time` this
  endpoint announced, and the NACK generator stops asking for a packet the remote sender no
  longer keeps (the shorter of its `rtx-time` and `with_max_packet_age`).
- **congestion control**: the remote description's send limit (`b=TIAS`, else the value derived
  from `b=AS`; the sum over the sections this endpoint sends in) bounds the congestion
  controller's estimate on its way to the pacer and the statistics:
  `configuration::remote_bitrate_limit::{RemoteBitrateLimitInterceptor, RemoteBitrateLimit,
  REMOTE_BITRATE_LIMIT_SLOT}`, part of `configure_congestion_control`.
- **sctp**: the peer connection sends what the SCTP endpoint answers a packet for none of its
  associations with (RFC 9260 section 8.4: an ABORT, or a SHUTDOWN COMPLETE to a SHUTDOWN ACK);
  `Endpoint::poll_transmit` was never polled. And an association whose packets start to arrive
  over another 5-tuple (ICE selected another candidate pair) starts its congestion control and
  RTO over (`Association::on_path_change`, RFC 9260 section 7.2.5).

- **ice**: `Agent::checklist_state` (`ChecklistState`: Running, Completed, Failed), the state of
  the checklist in RFC 8445's terms. The transport state reaches `Completed` (it never did):
  a nominated pair, local gathering complete and end-of-candidates received.
- **ice**: `AgentConfig::ta` and `AgentConfig::max_candidate_pairs`;
  `Agent::set_remote_end_of_candidates`, `set_local_gathering_complete`,
  `get_local_candidates_to_signal`; `CandidatePairState::Frozen`.
- **ice**: `Candidate::set_local_preference_rank` / `local_preference_rank` (rank a local
  candidate among those of its type, for example an unreliable interface last, RFC 8421
  section 3) and `Candidate::peer_reflexive_priority`.

- **stun**: `rtc_stun::validated`, the receive path for every usage. `Validator` runs the
  FINGERPRINT check (required with `require_fingerprint`; always right and last), the integrity
  check (`authenticate`: MESSAGE-INTEGRITY-SHA256 when present, else MESSAGE-INTEGRITY;
  `authenticate_with` for the algorithm the request used; `unauthenticated` for messages
  without credentials) and the unknown comprehension-required attribute check
  (`known_attributes`, `STUN_ATTRIBUTES`), and returns a `ValidatedMessage` that holds only the
  attributes ahead of the first integrity attribute. RFC 8489 section 9 has agents ignore
  everything after it; reading attributes off the raw `Message` after
  `MessageIntegrity::check` does not, and an attribute appended to a genuine message was
  obeyed. `unknown_attributes_response` builds the 420 with UNKNOWN-ATTRIBUTES. `rtc-ice` and
  `rtc-turn` are to receive through it.
- **stun**: MESSAGE-INTEGRITY-SHA256 (`MessageIntegritySha256`, truncation only where the usage
  allows it), USERHASH (`userhash::Userhash`), PASSWORD-ALGORITHM and PASSWORD-ALGORITHMS
  (`password_algorithm`), ALTERNATE-DOMAIN (`textattrs::AlternateDomain`), the SHA-256
  long-term key (`integrity::long_term_key`), the OpaqueString profile (`opaque::opaque_string`,
  `MessageIntegrity::short_term`) and the nonce cookie's security features
  (`nonce_cookie::SecurityFeatures`). Checked against RFC 5769 and RFC 8489 appendix B.1.
- **stun**: `long_term::LongTermCredentials`, the client rules of the long-term credential
  mechanism (RFC 8489 section 9.2) without I/O: the first request carries no credentials; a
  401 / 438 is turned into the retry's attributes (USERNAME or USERHASH, REALM, NONCE,
  PASSWORD-ALGORITHMS, PASSWORD-ALGORITHM, the integrity attribute), or refused when the nonce
  cookie shows PASSWORD-ALGORITHMS was stripped (bid-down), when no offered algorithm is
  supported, or when the same credentials were just rejected; `check_response` says whether a
  response is authenticated, a challenge, or to be discarded.
- **stun**: `alternate::TryAlternate` reads the alternate servers and domain out of an
  authenticated 300 (Try Alternate); `RedirectGuard` refuses a redirection to a server tried
  within five minutes (RFC 8489 section 10).
- **stun**: `Client` computes its RTO as RFC 6298 does (kept per server for ten minutes,
  `with_rto_estimation`), has `with_rc`, `with_rm`, `with_ti`,
  `with_max_outstanding_transactions`, `with_path_mtu` and `with_known_attributes`, drops a
  response with a wrong FINGERPRINT, fails a transaction whose response has unknown
  comprehension-required attributes or no ERROR-CODE (`StunEvent::TransactionFailed`), and with
  `with_response_integrity` discards unauthentic responses and reports an integrity violation
  instead of a timeout (at once over TCP), as RFC 8489 section 9.1.4 requires.
- **stun**: `Uri::port_or_default`, `Uri::srv_query_name`, `Uri::is_secure`, `Uri::host_is_ip`,
  and `Uri::parse_uri_strict`, which refuses a `stuns` URI with an IP address (RFC 8489 section
  8.1; `parse_uri` keeps accepting it, as browsers do). `Message::unknown_required_attributes`.

- **ice**: `Candidate::set_local_preference_rank` / `local_preference_rank` (rank a local
  candidate among those of its type, for example an unreliable interface last, RFC 8421
  section 3) and `Candidate::peer_reflexive_priority`.

- **turn**: `Event::AllocationLost`, `AllocationReleased`, `RefreshError`, `PermissionLost` and
  `ChannelBindError`; `RequestError` and `ErrorResponse` with the typed STUN error code.
- **turn**: an allocation a server gave without a credential is used without one, and takes the
  long-term credential when the server asks with a 401.
- **turn**: `Client::allocate_with(now, AllocateOptions)` for what RFC 8656 section 7.1 lets an
  Allocate ask: `address_family` (REQUESTED-ADDRESS-FAMILY, an IPv6 relayed address),
  `additional_ipv6` (ADDITIONAL-ADDRESS-FAMILY, an IPv4 and an IPv6 address on one allocation),
  `lifetime`, `dont_fragment`, `even_port` (with the R bit) and `reservation_token`. The
  combinations the RFC forbids are refused before anything is sent.
- **turn**: `Relay::relayed_addrs`, `mapped_addr` (the XOR-MAPPED-ADDRESS of the Allocate
  response, the client's server-reflexive address), `lifetime`, `reservation_token`,
  `dont_fragment` and `address_error` (ADDRESS-ERROR-CODE). A dual allocation is found by either
  of its addresses and takes peers of both families; `Relay::release_family` deletes one
  family's address with a Refresh of LIFETIME 0 naming it (section 8.1).
- **turn**: `Relay::send_to_dont_fragment` sends a Send indication with DONT-FRAGMENT, on an
  allocation made with it. A 420 naming DONT-FRAGMENT to the Allocate is answered with the
  request again without it (section 7.4).
- **turn**: `Event::IcmpError(peer, Icmp)` for a Data indication carrying the ICMP attribute
  (sections 11.6, 18.13).
- **turn**: a 300 (Try Alternate) carries its ALTERNATE-SERVER in
  `ErrorResponse::alternate_server`; a 420 its UNKNOWN-ATTRIBUTES.
- **turn**: a 438 (Stale Nonce) to the authenticated Allocate is retried once with the new
  nonce, as it already was for the other requests.
- **turn**: SOFTWARE (`ClientConfig::software`) goes in every TURN request (section 5), not
  only in Binding requests.
- **turn**: the client keeps to the families the server refused: after a 440 to an Allocate,
  or ADDRESS-ERROR-CODE 440, `allocate_with` refuses that family; after ADDRESS-ERROR-CODE 508,
  for a minute; after a relayed address of a family that was not asked for, the allocation is
  deleted and `allocate` fails (sections 7.3, 7.4) until
  `Client::clear_allocate_restrictions`.
- **turn**: peers of a family the allocation has no relayed address of are refused by
  `create_permission` and `send_to` (sections 10.1, 12.1), before the server's 443 could fail
  the refresh of every other permission.
- **turn**: `proto::addfamily` (ADDITIONAL-ADDRESS-FAMILY, 0x8000), `proto::addrerror`
  (ADDRESS-ERROR-CODE, 0x8001), `proto::icmp` (ICMP, 0x8004); `EvenPort::reserve_port` is
  public; `Lifetime` sends a duration past 32 bits of seconds as the largest value instead of
  its low bits.
- **turn**: TCP allocations, client side (RFC 6062). On a client that reaches the server over
  TCP or TLS, `allocate_with` with `AllocateOptions::transport = RelayTransport::Tcp` asks for
  a TCP relayed address (REQUESTED-TRANSPORT 6; refused over UDP and with DONT-FRAGMENT,
  EVEN-PORT or RESERVATION-TOKEN). `Relay::connect` sends Connect for a peer (one outstanding
  per peer address, ten seconds after a 447) and `Event::ConnectResponse` carries the
  CONNECTION-ID; `Event::ConnectionAttempt` reports a permitted peer's connection.
  `Relay::data_connection` gives a sans-I/O `DataConnection` for a new TCP connection the
  application opens to the same server address from another local address: it sends
  ConnectionBind with the CONNECTION-ID and the control connection's credential (30 s to be
  answered; a 401 or 438 with a nonce is answered once), reports
  `DataConnectionEvent::Bound`, and from then on passes the peer's bytes as they are, both
  ways. `Event::ConnectError`; `proto::connid` (CONNECTION-ID, 0x002a); a
  `data_connection_handle_read` fuzz target.
- **test-env**: a third coturn (port 3480, an IPv4 and an IPv6 relay address, two users) and
  `tests/testenv_turn_client.rs`: the TURN client's Allocate options, IPv6 and dual
  allocations, 440 and 441, and a TCP allocation with a connection out and one in, against a
  real server.
- **mdns**: a record the resolver does not read no longer hides the records after it. A TXT or
  NSEC record ahead of the address record in a response ended the scan, so the name did not
  resolve (RFC 6762 section 6.1).
- **mdns**: every record of a response is read, in the Answer and Additional sections; only
  the first four Answer records were, so a responder that aggregates (RFC 6762 section 6.4)
  resolved nothing past the fourth.
- **mdns**: query retries back off: after one second, then at doubling intervals up to an hour
  (RFC 6762 section 5.2). They came every second for the life of the query. A query nobody
  answers ends after 30 seconds unless a timeout is configured (`without_query_timeout`
  restores the endless query); it never ended.
- **mdns**: names compare without regard to ASCII case (RFC 1035 section 2.3.3), in questions
  and in answers. A peer that spelled a `<uuid>.local` name in upper case got no answer, and
  an answer in another case than the question's resolved nothing.
- **mdns**: questions inside a response are ignored (RFC 6762 section 6); they were answered,
  so two responders could be made to answer each other. Messages with a non-zero OPCODE or
  RCODE, responses from a port other than 5353 and datagrams over 9000 bytes are ignored
  (sections 18.3, 18.11, 6, 17).
- **mdns**: a record is multicast at most once a second (RFC 6762 section 6). Every question
  was answered at once, and the fixed-IP responder answered a query for A and AAAA twice. A
  question for a record type the name lacks gets the NSEC record (section 6.1), not the
  address record the fixed-IP responder sent for any type.
- **mdns**: `MulticastSocket` sends with IP TTL 255 (RFC 6762 section 11); it sent multicast
  with the system default, 1.
- **mdns**: a compressed SRV target decodes (RFC 6762 section 18.14).

- **mdns**: the responder life cycle of RFC 6762. A name is probed for (section 8.1; not a
  random `<uuid>.local` name, which draft-ietf-mmusic-mdns-ice-candidates exempts), announced
  twice with the cache-flush bit (sections 8.3, 10.2), defended against probes, sent back to
  probing by a conflicting record (section 9; a name lost to another host is reported as
  `MdnsEvent::LocalNameConflict`), and withdrawn with a goodbye when it is removed
  (`Mdns::remove_local_name`) or the connection closes (section 10.1).
  `Mdns::network_changed` starts every name over and empties the cache.
- **mdns**: responses follow RFC 6762 sections 5.4 to 7.2: known-answer suppression,
  truncated queries and their follow-up packets, the 20 to 120 ms delay for a message another
  host may also answer, unicast replies to questions that ask for them, conventional replies
  to legacy queriers, NSEC records, aggregation, messages split to fit a datagram.
- **mdns**: the resolver caches the addresses it hears for their TTL (at most
  `MAX_CACHED_ADDRESSES`, 256), so a name its owner announced resolves without a query;
  honours goodbyes and the cache-flush bit; counts another host's identical question as its
  own sent (section 7.3); and does not resolve a name with more than one address
  (draft-ietf-mmusic-mdns-ice-candidates section 3.2.2).
- **mdns**: `MdnsRateLimit`, a token bucket over every message an `Mdns` sends (40 at once,
  10 a second by default), shareable between connections: the rate limit
  draft-ietf-mmusic-mdns-ice-candidates section 7.1 requires.
- **mdns**: `MdnsConfig` options `with_probe_policy` (`MdnsProbePolicy`),
  `with_announce_count`, `with_rate_limit`, `with_first_query_delay`,
  `with_unicast_response`, `with_unicast_replies`, `with_destination_reported`,
  `with_multiple_addresses`, `with_on_link_subnets`, `with_jitter_seed`,
  `without_query_timeout`.

- **srtp**: key exhaustion is reported. `Context::poll_event` yields
  `ContextEvent::KeyLifetimeExpiring` when a sixteenth of a master key's lifetime is left and
  `KeyExhausted` at the first refused packet, so the application can re-key;
  `Context::set_key_lifetime`, `key_lifetime`, `key_usage` (`keying::{KeyLifetime, KeyUsage,
  PacketKind}`).
- **srtp**: encrypted header extensions (RFC 6904, and RFC 7714 section 8.3 for AES-GCM),
  selectable per extension id: `Context::set_encrypted_header_extensions`,
  `header_extension::EncryptedHeaderExtensions`. Not signalled by a peer connection.
- **srtp**: Master Key Identifier, sending and receiving, with a master-key table:
  `Context::with_keying`, `add_master_key`, `set_sending_mki`, `remove_master_key`,
  `sending_mki`, `mkis`, `key_usage_of` (`keying::Keying`).
- **srtp**: key derivation rate (RFC 3711 section 4.3.1): `keying::KeyDerivationRate`.
- **srtp**: AES-192 counter mode (RFC 6188): `ProtectionProfile::Aes192CmHmacSha1_80` / `_32`;
  **crypto**: `BlockCipherAlgorithm::Aes192`, `StreamCipherAlgorithm::Aes192Ctr`.
- **srtp**: the NULL cipher with HMAC-SHA1, which RFC 3711 section 5.1 makes mandatory to
  implement: `ProtectionProfile::NullHmacSha1_80` / `_32`. Never offered by a peer connection
  (RFC 8827 section 6.5).
- **srtp**: unencrypted SRTCP can be sent: `Context::set_srtcp_encryption`.
- **srtp**: `ProtectionProfile::dtls_srtp_id`, `from_dtls_srtp_id` (the IANA code points),
  `ALL`, `is_aead`, `is_null_cipher`, `default_key_lifetime`; it is `PartialEq`, `Eq`, `Hash`.
  `ContextEvent::CryptexRequiredViolation`; `Context::profile`.
- **srtp**: known-answer tests from RFC 3711 Appendix B, RFC 6188 section 7, RFC 6904 Appendix
  A, RFC 7714 sections 16 and 17, and libsrtp's RFC 6904 vectors.

- **sctp**: `RTCPeerConnection::replace_sctp_association` (the next offer carries a new
  `a=sctp-port`) and `RTCPeerConnection::close_sctp_association` (it carries
  `a=sctp-port:0`), RFC 8841 section 10.5.
- **shared**: `Error::ErrLabelTooLarge`, `Error::ErrDataChannelIdInUse`,
  `Error::ErrSDPSctpPortInvalid`.

- **rtcp**: new packet types, each with marshal, unmarshal and a fuzz target: `ApplicationDefined`
  (APP, RFC 3550 section 6.7); `TemporaryMaximumBitrateRequest` / `Notification` (TMMBR, TMMBN,
  RFC 5104 section 4.2); `TemporalSpatialTradeoffRequest` / `Notification` (TSTR, TSTN, section
  4.3.2 and 4.3.3); `VideoBackChannelMessage` (VBCM, section 4.3.4);
  `ReferencePictureSelectionIndication` (RPSI, RFC 4585 section 6.3.3); `LayerRefreshRequest` (LRR,
  RFC 9627); `ApplicationLayerFeedback` (PSFB FMT 15 that is not REMB). These are wire
  codecs: nothing negotiates or acts on the new messages yet.
- **rtcp**: SDES items MID (15), RtpStreamId (12) and RepairedRtpStreamId (13) (RFC 7941, RFC 8852);
  `SourceDescriptionItem::private` / `as_private` for PRIV items.
- **rtcp**: `compound_packet::validate_compound` (the header checks of RFC 3550 Appendix A.2 and the
  rules of section 6.1) and `validate_reduced_size` (what RFC 5506 leaves of them).
- **rtcp**: `packet::unmarshal_lenient`: a malformed packet of a known type comes back as a
  `RawPacket` and the packets around it are read. `packet::unmarshal` still fails the datagram.
- **rtcp**: `TransportLayerCc::reference_time_signed` and `ReferenceTimeUnwrapper`, which follows the
  24-bit reference time across its wrap (every 12.4 days).
- **rtcp**: `StatisticsSummaryReportBlock::reported`, `ApplicationDefined::name_str`, the `FORMAT_*`
  constants of the new feedback messages.

- **rtp: SVC**. `rtc_rtp::codec::svc`: `ScalabilityMode`, the 36 modes of the W3C webrtc-svc
  table (case sensitive, `supported_by(mime_type)` per codec), and `ScalabilityPattern`, each
  mode's dependency structure as a generator of `LayerFrame`s that feed the payloaders.
- **rtp: Dependency Descriptor** (AV1 RTP appendix A). `rtc_rtp::codec::dependency_descriptor`:
  `DependencyDescriptor` (marshal / unmarshal), `FrameDependencyStructure`,
  `DependencyDescriptorWriter`, `DependencyDescriptorReader`, `DecodeTargetSelector`,
  `DEPENDENCY_DESCRIPTOR_URI`.
- **rtp (VP8)**: `Vp8Payloader::payload_frame` with `Vp8FrameInfo` (N, TID, Y, KEYIDX; the
  payloader counts TL0PICIDX), `set_initial_picture_id`, `set_initial_tl0_pic_idx`;
  `Vp8TemporalLayerFilter`.
- **rtp (VP9)**: `Vp9Payloader::payload_layer_frame` with `Vp9FrameInfo` (TID, U, SID, D, Z,
  end of picture, reference indices), `set_scalability_structure` with
  `Vp9ScalabilityStructure`, `initial_tl0_pic_idx`; `Vp9Packet::scalability_structure`,
  `referenced_picture_id`; `Vp9LayerFilter`.
- **rtp (AV1)**: `Av1Payloader::payload_frames` (a temporal unit's packets by frame),
  `Av1Payloader::sequence_header_per_spatial_layer`.

- **rtcp**: the RTCP session of a connection (`RtcpSessionInterceptor`, `Slot::RtcpSession`,
  registered by `configure_rtcp_reports` and so by `register_default_interceptors`). One
  interceptor closest to the wire is the connection's whole RTCP voice:
  - one identity: one CNAME per connection (RFC 7022: 96 random bits, Base64) in every SDES,
    for senders, RTX and FEC SSRCs and receiver reports; reports and feedback from the
    connection's media SSRCs, or from one reporting SSRC (never zero, never one in use) when
    it sends no media; `RTCPeerConnection::rtcp_cname` and `remote_rtcp_cname`;
  - reports: a sender report for every SSRC that sent in the last two report intervals (RTX
    and FEC included), a receiver report otherwise, the reception report blocks inside them,
    an empty RR when there is nothing to report, BYE for an SSRC that stops and for all of
    them on `close()`;
  - timing: RFC 3550 6.3 (interval from the members, senders, average packet size and RTCP
    bandwidth, randomised, timer and reverse reconsideration, source timeout, BYE back-off)
    and the RTP/AVPF rules of RFC 4585 3.5 (early feedback, `T_rr_interval`), one timer per
    local SSRC aggregated into one compound packet (RFC 8108 5.3); sans-I/O, with an
    injectable random source (`RtcpRandom`);
  - packets: everything leaves as a compound packet, reduced-size (RFC 5506) only when the
    session is told it was negotiated;
  - membership: sources and their CNAMEs, BYE, timeouts, and SSRC collisions (RFC 3550 8.2).
  Inputs for what a session description negotiates: `RtcpSessionBuilder` and
  `RtcpSessionControl` (`Bandwidth` for `b=AS` / `b=TIAS` / `b=RS` / `b=RR`, `ReducedSize` for
  `a=rtcp-rsize`, `TrrInt` for `trr-int`, `Cname`). Outputs: `RtcpSessionEvent`.
- **nack**: a request policy (RFC 4588 6.3, Appendix A): a lost packet is asked for at most ten
  times and for two seconds (`with_max_nacks_per_packet`, `with_max_packet_age`), not again
  before a round trip has passed (measured by the RTCP session, or `with_round_trip_time`),
  optionally after a reordering delay (`with_reorder_delay`). `NackResponderBuilder::
  with_max_packet_age` is the sender's `rtx-time`.
- **rtcp**: `FirCommands` numbers the FIR commands an application sends (RFC 5104 4.3.1); a
  repeated FIR command is delivered to the application once.
- **rtcp**: `RTCPeerConnectionEvent::OnSsrcCollision` when a remote source uses a sender's SSRC.
- **interceptor**: `Attribute::Retransmitted` carries what a de-encapsulated RTX packet was on
  the wire.

- **sdp**: typed, validated attributes (`rtc_sdp::attribute`, re-exported as
  `rtc::sdp::attribute`). Each type parses the value of one attribute against the ABNF of the RFC
  that defines it and prints it back: `Group`, `Mid`, `Msid`, `MsidSemantic`, `Ssrc` (with
  `cname`, `previous-ssrc`, `fmtp`, `msid`), `SsrcGroup`, `Rid` (with `pt=` and every
  restriction), `Simulcast` (alternatives and `~`), `ExtMap`, `Rtcp`, `RtcpFb` (wildcard, and
  every feedback type through `RtcpFb::kind`), `RtcpXr`, `RtpMap`, `Fmtp` (`parameter_list` keeps
  order and text), `Ptime`, `MaxPtime`, `FrameRate`, `ImageAttr`, `Content`, `Candidate`,
  `RemoteCandidates`, `IceUfrag`, `IcePwd`, `IceOptions`, `IcePacing`, `Fingerprint`, `Setup`,
  `TlsId`, `Identity`, `SctpPort`, `MaxMessageSize`, `SctpMap`. `SessionDescription` and
  `MediaDescription` have an accessor for each (`mid()`, `msids()`, `rids()`, `simulcast()`,
  `rtcp_fbs()`, `candidates()`, `fingerprints()`, `direction()`, `rtcp_mux()`, `bundle_only()`,
  ...), the generic `typed::<T>()` / `typed_all::<T>()` / `flag(name)`, and `with_typed(&T)` to
  write one. An accessor returns `Err` when the attribute is present and malformed.
- **sdp**: `SessionDescription::validate` checks a whole description: a `c=` line for every media
  section, the value of every attribute with a type, the level each attribute is defined for,
  attributes a level holds once (one direction, one `mid`, ...), unique `a=mid`, `a=rid` /
  `a=simulcast` consistency, payload types as the formats of an RTP section.
- **sdp**: the RFC 8859 multiplexing category and level of every attribute as data
  (`rtc_sdp::attribute::mux`): the attribute table of RFC 8859 section 15.2.2 plus the attributes
  registered since (`msid`, `rid`, `simulcast`, `extmap-allow-mixed`, `rtcp-mux-only`,
  `ice-pacing`, `end-of-candidates`, `tls-id`, `sctp-port`, `max-message-size`, `identity`,
  `cryptex`, `bundle-only`), and the tables for `b=` modifiers, `rtcp-fb` values, grouping
  semantics and source attributes.
- **sdp**: `ParseOptions`, `SessionDescription::unmarshal_with_options`, `parse_with_options` and
  `impl FromStr for SessionDescription`.
- **sdp**: `a=extmap` ids 256 (the appbits) and 4096 to 4351 (extensions the offerer leaves the
  answerer to number, RFC 8285 section 6) parse through `ExtMap::parse` and `extmaps()`, with
  `ExtMap::is_element_id`, `is_answerer_assigned` and `fits_one_byte_header` to tell them apart.
  `ExtMap::unmarshal`, whose id callers put into RTP headers, still returns only 1 to 255.
- **sdp**: `ConnectionInformation::parse`, `Address::parse`, `Bandwidth::parse`,
  `Bandwidth::kind` (`BandwidthKind`), `Bandwidth::bits_per_second`, `bandwidth_of` on both
  description levels, `Attribute::parts`, and `ATTR_KEY_*` constants for the attributes above.

- **sctp**: `Stream::write_sctp_with_ppid` and `Chunks::ppid` for a Payload Protocol
  Identifier `PayloadProtocolIdentifier` has no name for; `PayloadProtocolIdentifier::number`;
  `ChunkPayloadData::ppid`; `Association::verification_tag`.
- **sctp**: `Endpoint::poll_transmit` (the endpoint's answers to out-of-the-blue packets);
  `TransportConfig::with_valid_cookie_life` / `valid_cookie_life`.
- **sctp**: `TransportConfig::with_heartbeat_interval` / `heartbeat_interval`,
  `Association::set_heartbeat_interval`, `Event::PathInactive`, `Event::PathActive`.
- **sctp**: `Association::on_path_change` restarts congestion control and the RTO when the
  transport underneath moves to another path (RFC 9260 section 7.2.5; for the peer
  connection to call when ICE selects another candidate pair).
  `Association::congestion_window`, `slow_start_threshold`, `rto`.
- **sctp**: `TransportConfig::with_slow_start_growth_limit` (L of RFC 9260 section 7.2.1,
  default 1), `with_max_burst` (Max.Burst, off by default), `with_sack_delay` (200 ms by
  default, at most 500 ms).
- **sctp**: `Association::partial_reliability` (whether PR-SCTP is in use),
  `TransportConfig::with_partial_reliability`.
- **fuzz**: `rtc-sctp` targets `association_handle_chunks` (an established association fed
  chunks, timers running) and `chunk_chunk_unknown_unmarshal`.

- **sframe**: new crate `rtc-sframe`, SFrame (RFC 9605) for end-to-end encrypted media. The
  header codec; key derivation; the five cipher suites of the RFC and the three AES-256-CTR
  suites of the IANA registry (0x0006 to 0x0008, which the W3C Encoded Transform API lists);
  `SFrameContext` with a key store in which a key encrypts or decrypts, never both, a counter per
  sending key (a (key, nonce) pair is never used twice, and a key that has used every counter
  stops) and an anti-replay window per receiving key; the sender-keys ratchet of section 5.1
  (`SenderKeyRatchet`, `SenderKeyReceiver`) and MLS-keyed contexts of section 5.2 (`MlsContext`,
  which takes each epoch's exported secret; no MLS in the engine); `PendingCiphertexts` for
  frames whose key has not arrived. Checked against every test vector of RFC 9605 Appendix C.
  Sans-I/O, on the `rtc-crypto` provider. Standalone: the application applies it to a frame
  before packetizing or to a packet's payload; there is no SFrame RTP payload format or SDP
  signalling yet.
- **crypto**: `HmacAlgorithm::Sha512`, implemented by both built-in providers and part of the
  provider conformance suite (`conformance::assert_provider`). A downstream provider that runs
  the suite has to implement it.

- **flexfec**: RFC 8627 FlexFEC as its own coder, negotiated as `video/flexfec` (the draft-03
  coder keeps `video/flexfec-03`; the two wire formats are not compatible and each name selects
  its coder exactly). `FlexFecEncoder` builds flexible-mask repair packets (15, 46 or 110 bits),
  fixed L columns / D rows packets (row, column and 2-D protection, `FlexFecProtection`) and
  retransmission packets (R=1), with the protected SSRCs in the CSRC list. `FlexFecDecoder`
  recovers under all of them, iteratively for 2-D, for several source streams per repair packet,
  and takes retransmissions; its buffers follow the negotiated `repair-window`
  (`FlexFecParameters`, `FlexFecDecoderConfig`) and are bounded against the peer (RFC 8627
  section 9). `FlexFecSendBuilder` / `FlexFecReceiveBuilder` install the interceptors at
  `Slot::FecEncoder` / `Slot::FecDecoder`; both are opt-in, like the draft-03 pair. A sender
  protects no block that outlasts the repair window; FlexFEC retransmission in answer to NACK
  is `with_retransmissions(true)`; in-band SSRC mapping (section 7.1.1) is
  `with_in_band_ssrc_mapping`.
- **interceptor**: `StreamInfo::mime_type_fec` and `StreamInfo::sdp_fmtp_line_fec` name a
  stream's FEC format and its parameters, with `fec_is_flexfec03()` / `fec_is_flexfec()`.
- **flexfec-03**: `FlexFec03SendBuilder::with_initial_sequence_number` and
  `with_initial_timestamp`; `FLEXFEC03_MAX_MEDIA_PACKETS` (109).
- **fuzz**: targets `flexfec_header_parse`, `flexfec_decoders` and `flexfec_receive`.

- **sdp**: `a=tls-id` (RFC 8842 section 4). Offers carry the association's value on the
  BUNDLE-tag m-section, answers carry one when the offer did; the value is kept while the
  association is and replaced with it; a changed remote value asks for a new association.
  `SettingEngineBuilder::with_disable_sdp_tls_id` leaves it out.
- **sdp**: `a=identity` (RFC 8827 section 5) is carried: `RTCPeerConnection::
  set_identity_assertion` and `remote_identity_assertion`. Making and verifying an assertion
  stays the application's.
- **dtls**: `SettingEngineBuilder::with_dtls_use_srtp_on_every_association`;
  `RTCCertificate::fingerprint` for one hash function;
  `rtc_dtls::config::ConfigBuilder::with_use_srtp_optional`.
- **crypto**: `HashAlgorithm::{Sha1, Sha224, Sha384, Sha512}` in the built-in providers, for
  certificate fingerprints.

- **rtp**: `Header::set_extension_upgrading` and `Header::upgrade_to_two_byte` convert a
  one-byte extension block to the two-byte form, for a stream that negotiated
  `a=extmap-allow-mixed` or is two-byte throughout; `Header::extension_form`, `ExtensionForm`.
  `Header::del_extension` clears the X bit with the last element (RFC 8285 section 4.1.1).
- **rtp**: `header::validity::check_rtp_validity`, the header validity checks of RFC 3550
  Appendix A.1 on raw bytes, and `sequence::SourceSequence`, its per-source sequence number state
  (probation, restart after a jump, loss by Appendix A.3).
- **rtp**: `Payloader::marker_rule` (`MarkerRule`) and `Payloader::payload_duration`, provided
  methods a payload format overrides to say which packets carry the marker and how long a
  sample-based payload is.
- **rtp**: typed header extensions: `CsrcAudioLevelExtension` (RFC 6465), `Mid`, `RtpStreamId`,
  `RepairedRtpStreamId` (RFC 7941, RFC 8852: UTF-8 checked, stream ids alphanumeric),
  `AbsCaptureTimeExtension`, `TransmissionOffsetExtension` (RFC 5450);
  `AudioLevelExtension::voice_activity` and `parse_vad_attribute` (RFC 6464 `vad`); URI
  constants and `HeaderExtension` variants for each.
- **rtp**: H.264 interleaved mode (RFC 6184 section 6.4). `H264Payloader::with_packetization_mode(2)`
  sends STAP-B and FU-B / FU-A with consecutive decoding order numbers
  (`with_initial_don`); `H264Packet` receives STAP-B, MTAP16, MTAP24 and FU-B
  (`H264Packet::nal_units` gives each NAL unit's DON and timestamp offset);
  `H264DeinterleavingBuffer` puts NAL units back in decoding order (section 7.2.2); `stap_a`,
  `stap_b`, `mtap` and `don_diff` are public. `try_with_packetization_mode` refuses a mode
  above 2.
- **rtp**: H.265 decoding order numbers (RFC 7798 sections 4.4.1 to 4.4.3, 4.6, 6):
  `HevcPayloader::with_donl` writes DONL and DOND, `H265Packet::nal_units` derives each NAL
  unit's DON, `H265DepacketizationBuffer` passes NAL units on by AbsDon.
  `H265Packet::with_length_prefix` for length-prefixed output.
- **rtp**: `H264Packet::depacketize_with_sequence_number` and
  `H265Packet::depacketize_with_sequence_number` drop a NAL unit when one of its fragments was
  lost, instead of splicing over the gap (RFC 6184 section 5.8, RFC 7798 section 4.4.3).
- **rtp**: `codec::telephone_event` (RFC 4733): the event payload, the DTMF codes, the `events`
  list, and sender and receiver state machines for an application or a DTMF sender to drive
  (marker on the first packet, cumulative duration, segments of 0xFFFF for long events, the end
  packet three times).
- **rtp**: `codec::comfort_noise` (RFC 3389): the CN payload, its reflection coefficients, one
  payload per channel.
- **rtp**: `codec::red` (RFC 2198): block headers, `RedEncoder` (the last N primaries as
  redundancy), `RedDecoder` (recovers a lost primary once), the fmtp list.
- **rtp**: `clock_rate` (RFC 7160): `ClockRateHistory`, `MultiRateTimestamp`,
  `interarrival_difference`, `JitterEstimator`.
- **rtp**: `codec::opus::opus_packet_samples`, the duration of an Opus packet from its TOC;
  static payload type and clock constants for PCMU, PCMA, G722 and Opus.

- **ulpfec**: ULPFEC (RFC 5109), new in `rtc-interceptor` (`ulpfec` module) and opt-in.
  `UlpfecPacket` reads and writes the FEC header and the level headers (16- and 48-bit masks, any
  number of levels); `UlpfecEncoder` is the protection operation of section 8, with
  `validate_ulpfec_scheme` for the mask rules of 7.4; `UlpfecDecoder` recovers level by level,
  iterating until nothing more can be rebuilt, over a bounded window, and does not hand out a
  packet rebuilt only in part. The examples of RFC 5109 section 10 are test vectors.
- **ulpfec**: two carriages as interceptors (`UlpfecSendBuilder`, `UlpfecReceiveBuilder`). In RED
  (RFC 2198; `video/red` + `video/ulpfec`, what browsers negotiate) media leaves as RED primary
  blocks and FEC either as a RED packet of its own in the media stream's sequence space
  (`RedPlacement::OwnPacket`, libwebrtc's form; later media packets are renumbered to make room)
  or as a redundant block of the next media packet (`RedPlacement::WithNextMedia`, RFC 5109
  10.3). Received RED is delivered as the media it carries, with lost packets rebuilt and marked
  `Attribute::RecoveredByFec`; a RED packet that held only FEC travels the read leg emptied and
  marked `UlpfecRepair`, so sequence-number accounting stays whole, and is not delivered to the
  application. As a separate stream the FEC goes on the stream's repair SSRC
  (`StreamInfo::ssrc_fec`). `onelevelonly` is honoured (`with_one_level_only`,
  `ulpfec_one_level_only_from_fmtp`).
- **ulpfec**: `configure_ulpfec(registry, red_payload_type, ulpfec_payload_type)` adds the RED
  carriage in both directions. The default codecs still do not offer `ulpfec` or `red`; register
  them and pass the negotiated payload types.
- **fuzz**: targets `ulpfec_packet` and `ulpfec_receive` (crate `rtc`).
- **jsep**: a description is checked in full before any of it is applied (RFC 9429 sections 5.9
  and 5.10, W3C webrtc-pc "set a session description"). `set_remote_description` changed the
  signaling state, stored the description and created transceivers, and only then looked at
  the ICE credentials, the candidates and the fingerprints: a remote offer without
  `a=fingerprint` returned an error and left the connection in `have-remote-offer`. The checks
  now run first; a description that is refused changes nothing, and should a transport fail
  while one is applied, the signaling state, the descriptions, the transceivers, the negotiated
  codecs and the queued events are put back.
- **jsep**: a remote answer is checked against the offer it answers (RFC 3264 section 6, RFC
  9429 section 5.8.3, RFC 5888 section 9.1, RFC 9143 section 7.4, RFC 4585 section 4.2): the
  number and order of the m= sections, each one's media type, proto and mid, a direction the
  offered direction allows, and BUNDLE groups that bundle only what the offer bundled. An
  answer with fewer or swapped sections was applied. It is now
  `Error::ErrAnswerDoesNotMatchOffer`, and the offer stays pending. An `a=rtcp-fb` line the
  offer did not have does not refuse the answer (real peers answer with their own list): it is
  logged and never enabled, the negotiated feedback of a format being what both sides have.
  The transceiver's codecs used to take the remote description's feedback as it came.
- **jsep**: a rollback is taken through either `set_local_description` or
  `set_remote_description` (RFC 9429 section 5.7: "the same effect"). A local offer could be
  rolled back only through the first and a remote offer only through the second.
- **jsep**: a rollback restores what the last completed exchange negotiated: the negotiated
  codecs and header extensions, each transceiver's codecs, and the RTX / FEC flows of the
  senders' encodings. An abandoned remote offer left its codecs negotiated (the next local offer
  listed only those) and the senders without the repair flows it lacked.
- **jsep**: a staged ICE restart is applied only by the description that carries it.
  `set_local_description` applied it before it looked at the description, so a refused
  description and a rollback restarted ICE.
- **jsep**: `create_offer` is refused outside the `stable` and `have-local-offer` states
  (`Error::ErrIncorrectSignalingState`; W3C createOffer, RFC 9429 section 5.2.2). It made an
  offer in any state, gave transceivers mids and used up a requested ICE restart.
- **jsep**: `OnSignalingStateChangeEvent` is emitted only when the state changes; an offer
  applied over a pending one and a repeated provisional answer emitted it again.
- **jsep**: an applied answer forgets the last created offer and answer (W3C "set a session
  description"), so the offer of a finished exchange is not accepted for the next
  (`Error::ErrSDPDoesNotMatchOffer`).

- **jsep**: the `o=` session version goes up by one with each generated description that
  differs from the one before (RFC 9429 sections 5.2.2 and 5.3.2, RFC 3264 section 8). It was
  the clock's sub-second nanoseconds plus one on every call, so versions were unrelated and
  could go down.
- **jsep**: the answer's BUNDLE group is the offered BUNDLE group, in its tag order (RFC 9429
  section 5.3.1, RFC 9143 sections 7.3 and 7.3.1). It was read from the first `a=group` line
  of any semantics, so an offer listing `a=group:LS` first had sections rejected; and an offer
  with no group at all had every section answered with port 0. It is now answered without a
  group, accepted.
- **jsep**: an answer repeats the `<proto>` of each offered m= line (RFC 9429 section 5.1.2),
  rejected and data sections included; it said `UDP/TLS/RTP/SAVPF` / `UDP/DTLS/SCTP` whatever
  was offered. An audio or video section whose profile is none of the eight RTP profiles of
  that section is rejected.
- **jsep**: a media section with no direction attribute is sendrecv, and a session-level
  direction is the section's when it has none (RFC 8866 section 6.7, RFC 3264 section 6.1).
  Such a section was skipped when the offer was applied, and `create_answer` then failed with
  `ErrPeerConnTransceiverMidNil`.
- **jsep**: the transceiver created for a remote m= section has direction `recvonly` whatever
  was offered (W3C "set a session description"); for a section offered recvonly it was
  `sendonly`, with no sender. Such a section is answered `inactive` until `add_track`.
- **jsep**: a remote description that repeats a mid, or whose mid is not a token, is refused
  (RFC 5888 section 4, RFC 9429 section 5.8.2); both sections used to share one transceiver.
- **jsep**: `a=bundle-only` in a section outside every BUNDLE group, or in an answer, is
  discarded (RFC 9143 section 6): a port-zero section is then rejected, as port zero says.
- **jsep**: local descriptions list each candidate once, for the RTP component (RFC 8858
  section 5.3, RFC 5761 section 5.1.3); every candidate was repeated as component 2.
- **jsep**: the unregistered `mslabel` and `label` source attributes are no longer written
  (RFC 5576 section 4.1); `a=ssrc` carries `cname` and `msid`.

- **jsep**: `a=msid:<stream>` without appdata, the form RFC 9429 section 5.2.1 has senders
  write, is read (RFC 8830 section 3): it was dropped, leaving the remote track without a
  stream or, with no `a=ssrc` lines, no track at all. The recipient names the track and keeps
  the name across descriptions. Every `a=msid` line of a section counts (a track in several
  streams, RFC 8830 section 2); only the last did. The `a=msid` lines win over a legacy
  `a=ssrc:<n> msid:` attribute.

- **jsep**: `a=rtcp-mux` of a remote description is read (RFC 9429 sections 5.8.3 and 5.11, RFC
  8858, RFC 5761 section 5.1.1). The engine has no RTCP component, and it multiplexed whatever
  the peer said. A remote offer whose RTP section lacks the attribute is now refused under the
  RTCP mux policy `require` (the default; `RTCRtcpMuxPolicy` had no effect) and has that
  section answered rejected under `negotiate`; a remote answer without it is refused, the offer
  staying pending. `a=rtcp-mux-only` without `a=rtcp-mux` is refused.
- **jsep**: new m= sections of an offer say `a=rtcp-mux-only` under the `require` policy (RFC
  9429 sections 4.1.1 and 5.2.1); the answerer-tagged section repeats it when the
  offerer-tagged one had it (RFC 9143 section 9.3.1.2).
- **jsep**: `a=rtcp-rsize` is answered only when offered, kept in a subsequent offer only when
  the most recent answer had it, and reduced-size RTCP counts as negotiated only when both
  descriptions carry it (RFC 5506 section 5, RFC 9429 sections 5.2.2, 5.3.1 and 5.11). It was
  written in every description and never read.
- **jsep**: `a=rtcp-fb:*` (the wildcard payload type, RFC 4585 section 4.2) is read and applies
  to every format of the section; such lines were dropped. RFC 8888 feedback is written as
  `a=rtcp-fb:* ack ccfb`, as its section 6 requires, not once per payload type, so a peer that
  follows the RFC now negotiates it. A feedback value keeps everything after its type as its
  parameter.

- **jsep**: a description states this endpoint's own `a=fmtp` parameters for a negotiated
  format, not the ones the peer stated (RFC 3264 section 6.1). An answer echoed the offer's
  line, and so did every later offer: Opus parameters the peer asked for itself (RFC 7587
  section 7.1), the peer's AV1 level and tier, its H.264 level. An H.264 answer keeps the
  offered profile and states this endpoint's level when both sides allow level asymmetry, else
  the lower of the two (RFC 6184 section 8.2.2).
- **jsep**: an H.264, VP9 or AV1 format whose configuration this endpoint did not register is
  no longer negotiated because its name matches (RFC 6184 section 8.2.2: "maintain all
  configuration parameters or remove the media format"); when it was the section's only
  format the section is rejected. Other codecs keep the name-only match. A codec registered
  with no fmtp parameters at all states no configuration and still matches by name.
- **media_engine**: the H.264 default listed twice under payload type 127 is listed once (the
  second was discarded at registration; the registered codecs do not change).

- **jsep**: the bundle policy is read (RFC 9429 section 4.1.1); it was a stored value with no
  effect. In an initial offer, `balanced` (the default, also for an unset policy) marks the
  second and later m= section of each media type `a=bundle-only`, `max-bundle` (accepted as
  must-bundle) every section but the first, and `max-compat` none. A bundle-only section has
  port zero and none of the BUNDLE attributes (RFC 9143 sections 6 and 7.1.3); an answerer
  reads its `a=rtcp-mux` and `a=rtcp-rsize` from the offerer-tagged section. Subsequent offers
  mark nothing bundle-only (RFC 9429 section 5.2.2). Answering an offer with no BUNDLE group,
  `balanced` accepts the first section of each type, `max-bundle` the first section, and
  `max-compat` all of them. **The default offer changes**: a second audio or video section of
  an initial offer now has port 0 and `a=bundle-only`.

- **jsep**: session-level `a=extmap` lines of a remote description are read (RFC 8285 section
  5, RFC 9429 section 5.8.1); an offer that maps its header extensions once for the session
  negotiated none. An extension offered `sendonly` is answered `recvonly`, `recvonly` as
  `sendonly` and `inactive` as `inactive` (RFC 8285 section 7); the answer wrote no direction,
  which claims both.

- **jsep**: a remote answer or subsequent offer that carries the BUNDLE attributes in the
  tagged m= section only (RFC 9143 section 7.1.3) is accepted, and `a=rtcp-mux` and
  `a=rtcp-rsize` of the tagged section apply to every bundled section.

- **shared**: `Error::ErrAnswerDoesNotMatchOffer(String)`.
- **setting_engine**: `SettingEngineBuilder::with_bundle_attributes_repeated(false)`: answers
  and subsequent offers carry the BUNDLE attributes in the tagged m= section only, as RFC 9143
  section 7.1.3 says. The default repeats them in every bundled section, as browsers do and
  need.
- **configuration**: `RTCBundlePolicy::MustBundle` (RFC 9429 section 4.1.1) and
  `SettingEngineBuilder::with_max_bundle_as_must_bundle`.
- **transceiver**: `RTCRtpTransceiver::remote_bandwidth()` (`RTCRemoteBandwidth`: `b=TIAS` /
  `b=AS`, `b=RS`, `b=RR` of the remote media section, RFC 9429 section 5.10),
  `RTCRtpTransceiver::remote_rtcp_xr()` (the remote `a=rtcp-xr` formats, RFC 3611 section 5.1)
  and `RTCRtpTransceiver::rtcp_reduced_size()`; `RTCRtcpParameters::reduced_size` of the
  sender's and receiver's parameters is the negotiated value.
- **receiver**: `RTCRtpReceiver::streams()`, the ids of the remote MediaStreams the track is
  in (W3C `[[AssociatedRemoteMediaStreams]]`).

- **stats**: `RTCPeerConnection::on_send_discarded`, `update_available_incoming_bitrate` and
  `try_get_stats` (an `InvalidAccessError` for a selector that is not the connection's).
- **stats**: the application feed carries `estimatedPlayoutTimestamp`, corruption
  probability, `fecPacketsDiscarded`, in-band FEC, `psnrSum` / `psnrMeasurements`,
  `qualityLimitationDurations` and a per-stream `targetBitrate` (`PsnrSum`,
  `QualityLimitationDurations`).
- **stats**: `totalPacketSendDelay` (time between `write_rtp` and `poll_write`),
  `issuerCertificateId` (certificate chains), `relayProtocol` of a local relay candidate (from
  its TURN URL), a `media-source` object for every track attached to a sender, one `codec`
  object per payload type shared by both directions.
- **shared**: `SystemInstant::at`, `Error::InvalidAccessError`.

- **sctp**: the other re-configuration requests of RFC 6525, in both directions: Incoming SSN
  Reset (`Association::request_incoming_stream_reset`), SSN/TSN Reset
  (`request_ssn_tsn_reset`) and Add Outgoing / Incoming Streams (`add_outgoing_streams`,
  `add_incoming_streams`, with `set_stream_limits` for what a peer may add). They were
  answered "Denied". `Event::Reconfig` reports the outcome of a request and what the peer
  changed.
- **sctp**: `Stream::write_sctp_with_ppid` and `Chunks::ppid` for a Payload Protocol
  Identifier `PayloadProtocolIdentifier` has no name for; `PayloadProtocolIdentifier::number`;
  `ChunkPayloadData::ppid`; `Association::verification_tag`.
- **sctp**: `Endpoint::poll_transmit` (the endpoint's answers to out-of-the-blue packets);
  `TransportConfig::with_valid_cookie_life` / `valid_cookie_life`.
- **sctp**: `TransportConfig::with_heartbeat_interval` / `heartbeat_interval`,
  `Association::set_heartbeat_interval`, `Event::PathInactive`, `Event::PathActive`.
- **sctp**: `Association::on_path_change` restarts congestion control and the RTO when the
  transport underneath moves to another path (RFC 9260 section 7.2.5; for the peer
  connection to call when ICE selects another candidate pair).
  `Association::congestion_window`, `slow_start_threshold`, `rto`.
- **sctp**: `TransportConfig::with_slow_start_growth_limit` (L of RFC 9260 section 7.2.1,
  default 1), `with_max_burst` (Max.Burst, off by default), `with_sack_delay` (200 ms by
  default, at most 500 ms).
- **sctp**: `Association::partial_reliability` (whether PR-SCTP is in use),
  `TransportConfig::with_partial_reliability`.
- **fuzz**: `rtc-sctp` targets `association_handle_chunks` (an established association fed
  chunks, timers running) and `chunk_chunk_unknown_unmarshal`.

- **sctp**: State Cookie with a MAC (RFC 9260 section 5.1.3).
  `ServerConfig::cookie_authentication` takes a crypto provider (`rtc-crypto`); the cookie
  then holds the association's parameters, its creation time and an HMAC-SHA-256 under a
  random key replaced hourly, and the accepting endpoint keeps nothing between INIT and
  COOKIE ECHO: the INIT ACK leaves by `Endpoint::poll_transmit` and the association is
  returned when the cookie verifies. Without a provider the handshake is unchanged.
- **sctp**: zero checksum for SCTP over DTLS (RFC 9653): `TransportConfig::with_zero_checksum`,
  `Association::zero_checksum`.
- **sctp**: `Association::set_path_mtu` / `path_mtu`, the entry point for a transport that
  learns the path MTU.
- **sctp**: user message interleaving (RFC 8260 section 2). With
  `TransportConfig::with_message_interleaving(true)` on both sides, user data travels in
  I-DATA chunks and abandoned messages are reported with I-FORWARD-TSN: the fragments of
  messages on different streams interleave, so a large message no longer holds up the other
  streams. Off by default. `Association::message_interleaving` says whether it is in use.
- **sctp**: the stream schedulers of RFC 8260 section 3: `StreamScheduler::RoundRobin`,
  `RoundRobinPerPacket`, `Priority` and `FairCapacity` beside `FirstComeFirstServed` and
  `WeightedFairQueueing`. They choose between messages, and between chunks when
  interleaving. `Stream::set_priority` is the rank under `Priority` and the weight under
  `WeightedFairQueueing`, and applies to what the stream has queued.
- **fuzz**: `rtc-sctp` targets `chunk_chunk_i_data_unmarshal`,
  `chunk_chunk_i_forward_tsn_unmarshal`, `association_handle_chunks_interleaved` and the three
  RE-CONFIG request parameters.
- **sctp**: the other re-configuration requests of RFC 6525, in both directions: Incoming SSN
  Reset (`Association::request_incoming_stream_reset`), SSN/TSN Reset
  (`request_ssn_tsn_reset`) and Add Outgoing / Incoming Streams (`add_outgoing_streams`,
  `add_incoming_streams`, with `set_stream_limits` for what a peer may add). They were
  answered "Denied". `Event::Reconfig` reports the outcome of a request and what the peer
  changed.
- **sctp**: `Stream::write_sctp_with_ppid` and `Chunks::ppid` for a Payload Protocol
  Identifier `PayloadProtocolIdentifier` has no name for; `PayloadProtocolIdentifier::number`;
  `ChunkPayloadData::ppid`; `Association::verification_tag`.
- **sctp**: `Endpoint::poll_transmit` (the endpoint's answers to out-of-the-blue packets);
  `TransportConfig::with_valid_cookie_life` / `valid_cookie_life`.
- **sctp**: `TransportConfig::with_heartbeat_interval` / `heartbeat_interval`,
  `Association::set_heartbeat_interval`, `Event::PathInactive`, `Event::PathActive`.
- **sctp**: `Association::on_path_change` restarts congestion control and the RTO when the
  transport underneath moves to another path (RFC 9260 section 7.2.5; for the peer
  connection to call when ICE selects another candidate pair).
  `Association::congestion_window`, `slow_start_threshold`, `rto`.
- **sctp**: `TransportConfig::with_slow_start_growth_limit` (L of RFC 9260 section 7.2.1,
  default 1), `with_max_burst` (Max.Burst, off by default), `with_sack_delay` (200 ms by
  default, at most 500 ms).
- **sctp**: `Association::partial_reliability` (whether PR-SCTP is in use),
  `TransportConfig::with_partial_reliability`.
- **fuzz**: `rtc-sctp` targets `association_handle_chunks` (an established association fed
  chunks, timers running) and `chunk_chunk_unknown_unmarshal`.

### Bug Fixes

- **ice**: at 30 % loss (seeds 0x4a, 0xff and 0x127 of `tests/lossy_link_rtc2rtc.rs` with
  aws-lc-rs) and 40 % loss (0x1c and 0x21, both backends) the controlling peer went `failed`
  about 30 s in, still checking, 29.5 s after the Binding success response that validated its
  pair: every response to its nomination had been lost, the nomination's transaction (seven
  requests over 39.5 s) was still open and the other peer had accepted it and was connected.
  The checking timer inherited from the pion agent (`disconnected_timeout + failed_timeout`
  from entering checking) failed the agent with a pair in progress. Tests:
  `agent_checklist_test.rs::test_an_unanswered_nomination_is_sent_again_while_the_peer_is_heard_from`
  and `tests/lossy_link_rtc2rtc.rs::ice_does_not_fail_while_a_nomination_is_in_progress_over_heavy_loss`.
- **test**: `tests/lossy_link_rtc2rtc.rs` seeds the engine's provider randomness: each peer's
  `RTCCryptoProvider::random()` (ICE credentials, the tie-breaker, the consent intervals, DTLS
  randoms and cookies) is a generator seeded from the test's seed, so ICE takes the same course
  under every crypto provider. Still drawn from the OS: the providers' own key generation and
  signatures, STUN transaction IDs, SCTP's tags and heartbeat jitter (`rtc-sctp` uses `rand`
  directly). Seeded, two failures outside ICE reproduce on every run: with aws-lc-rs only
  (DTLS 1.3, X25519MLKEM768 key share, a two-datagram ClientHello) the 5 % and 10 % sessions
  of seed 1 never open: the server's HelloRetryRequest is lost and no retransmitted
  ClientHello is answered for 30 s; and seed 0x5eed at 30 % does not open its channel within
  400 s, on every backend, with the path up.
- **ice**: a Binding success response without XOR-MAPPED-ADDRESS was taken as a success: it
  made the checked pair valid and refreshed consent. RFC 8489 section 6.3.3 has the client
  check the attribute is present and process the response only if the checks succeed: it is
  now discarded (the transaction goes on), also for the consent checks of a restart's
  previous path. A response whose address cannot be decoded is still processed, the value
  ignored. Test: `agent_rfc8445_test.rs::test_a_success_response_without_xor_mapped_address_is_discarded`;
  with `test_a_retransmitted_check_gets_the_same_answer_and_changes_nothing` and
  `test_every_message_the_agent_sends_ends_with_fingerprint` for RFC 8489 6.3.1, 6.3.1.1, 7
  and 9.1.3.
- **test**: `tests/ice_restart_by_webrtc_interop.rs` failed now and then on macOS with "ICE
  Agent can not be restarted when gathering": the webrtc 0.17 peer refuses a restart while it
  still gathers (its server-reflexive candidate from the public STUN server can take longer
  than the connection did). The test waits for the peer's gathering to complete before the
  restart.
- **test**: `tests/lossy_link_rtc2rtc.rs` at 30 % loss could pass or fail with the same seed
  and crypto backend (it failed the crypto-ring baseline job of round 18cd90cd with every seed
  lapsing): the engine's randomness (ICE credentials, the tie-breaker, the 4 to 6 s consent
  intervals, DTLS randoms, SCTP) changes each run's datagram sequence and so which datagrams
  the seeded link drops, and whether consent lapses at 30 % loss is chance. Every run is now
  judged by RFC 7675 section 5.1 on every datagram, whatever the number a run takes: no
  application data before the first Binding success response or more than 30 s after the
  last; both peers are built at the virtual start time. New:
  `ice_does_not_fail_while_consent_is_fresh_over_thirty_percent_loss` (seeds 0xa, 0x1c, 0x21,
  0x24), where the peer connection fails at 30 s with ICE connected: the DTLS handshake's
  deadline, not ICE.
- **test**: ICE on a relayed TCP candidate through coturn
  (`tests/testenv_turn_client.rs::ice_connects_on_a_relayed_tcp_candidate_through_coturn`,
  environment test): the active relayed candidate's checks over a Connect and its data
  connection; the TCP allocation's XOR-MAPPED-ADDRESS as an active server-reflexive TCP
  candidate is paired and checked (RFC 6544 section 5).
- **twcc**: a transport-wide feedback packet is kept within `MAX_FEEDBACK_OCTETS` (1100); a
  longer reporting window continues in the next packet (draft-holmer-rmcat-transport-wide-cc-
  extensions-01 section 3.1.5). A long window yielded one packet of any size.
- **gcc**: the pre-filter and the Kalman filter as draft-ietf-rmcat-gcc-02 sections 5.1 to 5.3
  have them: a packet that arrives within burst_time of its group with a negative delay
  variation joins the group (a backlog delivered at once after an outage was read as a draining
  queue); a packet received out of order is left out of the arrival-time model; the noise
  variance weight is `1 - (1 - chi)^(30 / (1000 f_max))` over the last 60 groups' rate
  (`Kalman::update_with_period`, chi 0.001; it was a constant); a residual beyond three
  deviations enters the variance as three deviations (the outlier filter was missing). The
  multi-flow properties hold as before (late flow 0.48 / 0.49, `Gcc` / TCP 0.19 / 0.81 and 0.37
  / 0.63, burst recovered in 4 s).
- **data channels**: an in-band channel created once the SCTP association is up had no DCEP
  handshake deadline, so a lost `DATA_CHANNEL_ACK` left it connecting for ever; it has the
  deadline now. Stream id assignment refused the last id below `maxChannels`.
- **sctp**: a stream parked by back-pressure resumed only from `poll_read` or the peer's next
  datagram, and the SACK that reopens the window waited for the next `poll_write`, which a
  caller has usually made before it reads: a sender stopped by a zero window then waited for
  its own window probe, a retransmission timeout later, or for whatever woke the caller
  (RFC 9260 section 6.2). `poll_timeout` now reports a deadline when a drain from `poll_read`
  has made a window update due, and while a parked stream's pipeline has room again
  (`handle_timeout` drains it, also for a caller that empties the pipeline with
  `poll_data_read`); never while the pipeline is full, and never twice for the same work. The
  two comments that spoke of a retry timer that did not exist are corrected. Tests:
  `a_receiver_that_reads_again_reopens_the_window_without_an_inbound_datagram`,
  `a_parked_stream_resumes_from_its_deadline_when_the_pipeline_is_drained_directly`.
- **jsep**: an answer has only the `a=rtcp-fb` the offer has for each format (RFC 4585 section
  4.2: "The answerer MUST NOT add feedback parameters"). A renegotiation whose offer dropped a
  feedback type (or `trr-int`) was answered with what the first offer had, because the
  transceiver kept the codecs of that first exchange.
- **rtcp_session**: a `trr-int` that a renegotiation no longer has is undone: the peer
  connection sends the new `RtcpSessionControl::TrrIntCleared` and the session goes back to the
  interval it was built with (RFC 4585 section 4.2). The negotiated value used to stay.
- **association**: a DTMF (`telephone-event`, RFC 4733) or comfort-noise (`CN`, RFC 3389)
  packet that arrives before any media on an SSRC no longer becomes the receiver track's codec;
  the stream is established by its first media packet.
- **ice**: a controlling agent could lose the nomination it had queued: an answer to a second
  check on the same pair (one the peer's request triggered) took the pair off the
  triggered-check queue, so no request with USE-CANDIDATE left and the agent stayed in
  checking until its failed timeout. It made `test_data_channel_create_rtc_to_webrtc` time
  out about once in 200 runs.
- **sctp**: an association accepted from the peer's INIT after an earlier one was lost left
  the transport reporting the loss, so every later offer asked for a new `a=sctp-port` and
  replaced the association it had.
- **stats**: a remote mDNS candidate has its statistics object, with its name as the address,
  from the moment it is submitted, resolved or not (draft-ietf-mmusic-mdns-ice-candidates
  section 3.3.1). It appeared only once resolved, and then as a candidate "learned from a
  check": type `host` with a null address, which is what the browser interop cell "mDNS-hidden
  browser candidates resolve on the Rust side" read. A signalled candidate that takes the
  place of a peer-reflexive one (it keeps that one's id and pairs) now shows its own type and
  its signalled address.
- **test**: the four mDNS interop tests share the host's mDNS group, port and names; they run
  one at a time. On a timeout they report the rtc peer's candidates and pairs, and they log
  the mDNS traffic.
- **test**: sessions over a simulated lossy, reordering link in virtual time
  (`tests/lossy_link_rtc2rtc.rs`): nothing fails at 5 % (with reordering) or 10 % loss, and at
  30 % a peer fails only after 30 s without a Binding success response (RFC 7675 section 5.1).
  The netem impairment test prints both peers' state changes when it fails.
- **test**: relayed TCP candidates (RFC 6544 sections 4.1, 4.5 over RFC 6062 allocations) pair
  by `tcptype` and are checked on the relayed path; server-reflexive TCP direction preferences.
- **test**: the mDNS interop tests' upstream peer gathers on the mDNS egress interface only: it
  publishes every host candidate under one name, and on a host with a second interface the
  wrong one froze the right one past the timeout (hosted Linux runners). The browser cell's
  WebKit `na-env` rule asks whether the `.local` candidate got a pair, now that every submitted
  mDNS candidate is in the report. `stats_conformance_rtc2rtc` adds its late candidates before
  the nomination (RFC 8838 section 13).
- **jsep**: two retransmission formats that differ only in `rtx-time` are one format (RFC
  4588 section 8.1: each sender's own figure); an offer whose RTX `fmtp` had another
  `rtx-time` than the local one was answered without RTX.
- **jsep**: a remote description with `a=extmap:256 ...` (the `appbits` mapping) or an id of
  4096 to 4351 (an extension left for the answerer to number, RFC 8285 section 6) is applied;
  `set_remote_description` failed on it. This endpoint uses neither and leaves them out of its
  answer.

- **ice**: attributes after MESSAGE-INTEGRITY are ignored (RFC 8489 section 14.5). The HMAC does
  not cover them, so someone who saw one valid check could replay it with ICE-CONTROLLED or
  ICE-CONTROLLING appended and flip the agent's role.
- **ice**: role conflicts follow RFC 8445 section 7.3.1.1. A conflicting request gets one
  answer: the 487 when this agent keeps its role (and then nothing else comes of the request),
  the success response when it switches. It got both. A controlled agent switches on an equal
  tiebreaker (`>=`, it was `>`).
- **ice**: a 487 (Role Conflict) response is acted on (section 7.2.5.1): the role switches, the
  tiebreaker changes and the pair is checked again. Error responses were dropped unread, so an
  agent whose peer answered 487 never left the conflict. Any other authenticated error response
  fails the pair (section 7.2.5.2.4).
- **ice**: a Binding request that arrives before the remote description is answered at once and
  finished when the peer's credentials arrive: peer-reflexive candidate, triggered check,
  nomination (section 7.3). It was dropped, so an offerer whose answerer started checking first
  left those checks to time out. A request's USERNAME is valid when its first part is the local
  fragment.
- **ice**: pair priority is `2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D)` (section 6.1.2.3); it
  multiplied MIN by `2^32 - 1`. `test_candidate_pair_priority` pinned the wrong values.
- **ice**: PRIORITY in a check is the local candidate's priority as a peer-reflexive candidate
  (section 7.1.1), not its own; a peer-reflexive remote candidate takes its priority from the
  request (section 7.3.1.3) and is paired only with the local candidate the request arrived on.
- **ice**: local candidates of one type get unique local preferences, IPv4 and IPv6 interleaved
  (RFC 8445 section 5.1.2.1, RFC 8421 section 4; RFC 6544 section 4.2 for a TCP candidate's
  other-pref). Two host candidates on two interfaces had the same priority.
- **ice**: a candidate's foundation is made of its type, its base's IP address, its server and
  its transport (section 5.1.1.3); it used the candidate's own address and no server.
- **ice**: a nomination that gets no answer is given up after `max_binding_requests` requests
  and the controlling agent nominates its next valid pair. It repeated the nomination until the
  agent failed.
- **ice**: a lite agent sends no connectivity checks (sections 6.2 and 7.3.2): a request with
  USE-CANDIDATE selects the pair. It sent a triggered check and waited for the answer.
- **ice**: a request on a pair that already succeeded triggers no check from the controlled
  agent (section 7.3.1.4; every consent check of the peer cost a check back), and a request on a
  Failed pair gives the pair a fresh budget on the controlled side too.
- **ice**: an ICE restart given the credentials in use (`SettingEngine::set_ice_credentials`)
  generates new ones (section 9). The offer carried the old pair, so the peer saw no restart
  while this side had flushed its state.
- **ice**: candidate constructors take component 0 (the `Default`) as 1 and refuse a component
  above 256 or a priority above 2^31 - 1; `COMPONENT_RTCP` is 2.

- **ice**: consent freshness follows RFC 7675 section 5.1. Consent checks on the selected pair
  are 0.8 to 1.2 times the period apart, drawn anew each time, the period 5 seconds by default
  and never less (it was a fixed 2 seconds); `poll_timeout` returns the drawn instant. Consent
  expires 30 seconds after the last response whatever the configured timeouts (a zero
  `failed_timeout` kept a connected agent sending for ever), and the open transactions go with
  it.
- **ice**: consent is kept up on the path an ICE restart leaves in use (RFC 7675 section 5.1).
  The agent goes on sending consent requests there with the replaced generation's credentials,
  answers the peer's, and gives the path up 30 seconds after the last response. Until now data
  flowed on it unchecked until the restart selected a pair or failed.
- **ice**: a lite agent keeps its selected pair alive with a Binding indication after 15
  silent seconds (RFC 8445 section 11); it sent nothing.

- **ice**: the agent runs the checklist of RFC 8445 instead of pinging every pair every 200 ms.
  - Pairs have the five states of section 6.1.2.6, `Frozen` included: of the pairs with one
    foundation the best is checked first and the others wait for it (RFC 8838 section 12 for
    pairs that arrive later).
  - Checks start one per Ta (50 ms by default, never under 5 ms), the highest-priority Waiting
    pair first; a request from the peer puts its pair on the triggered-check queue, which is
    served first (sections 6.1.4.1 and 6.1.4.2). A triggered check was sent the instant the
    request arrived, and all pairs were pinged in one burst.
  - A check is one STUN transaction: the same request is retransmitted after RTO, 2 RTO,
    4 RTO, ... (RTO = max(500 ms, Ta x pairs Waiting or In-Progress), section 14.3), seven
    requests by default, and the pair fails 16 RTO after the last. Over TCP it is sent once
    (RFC 6544 section 7.1). The pair used to get a new request, with a new transaction id,
    every 200 ms and failed after 1.6 s.
  - A reflexive local candidate stands for its base: its pair with a remote candidate is
    pruned as redundant with the host candidate's (section 6.1.2.4), so each check leaves a
    socket once. The checklist holds 100 pairs at most (section 6.1.2.5), the best ones.
  - A response is matched to its pair by transaction id and must come back the way the
    request went, source and local address both, or the pair fails (section 7.2.5.2.1). Its
    mapped address names the valid pair's local candidate, a new local peer-reflexive candidate
    when the agent does not know it (sections 7.2.5.3.1 and 7.2.5.3.2).
  - Once a pair is nominated the other pairs' transactions are cancelled and no ordinary check
    is started (section 8.1.2); the controlling agent nominates one pair, with one transaction.
  - A checking agent fails as soon as every pair has failed, once no candidate is to come (local
    gathering complete and end-of-candidates received; section 7.2.5.4, RFC 8838 section 8).
- **ice**: end-of-candidates reaches the agent (RFC 8838 sections 13 and 14): a remote candidate
  that follows it, trickled or in a description, is ignored (it was paired and written into the
  remote description after `a=end-of-candidates`), and a local candidate added after the empty
  one is refused until an ICE restart.
- **ice**: a signalled candidate with the address of a peer-reflexive one learned from a check
  replaces it (RFC 8838 section 11); it was kept as a second candidate whose pair could never
  succeed. A local candidate with the address and base of one already added is not kept (RFC
  8445 section 5.1.3), and candidates of different components are not paired.
- **ice**: a consent request waits for its response four times the pair's round-trip time
  (500 ms to 4 s; RFC 7675 section 5.1) instead of a fixed 4 s.
- **stats**: a candidate pair's state can be `frozen`.
- **ice**: a remote candidate of a component other than RTP is ignored (the engine is rtcp-mux
  only). pion and webrtc-rs signal every candidate for both components on one address; held,
  the RTCP one could not be paired and kept the RTP one out when its mDNS name resolved first.
- **ice**: the controlling agent's consent checks carry USE-CANDIDATE (as libwebrtc's do), so a
  peer that takes over an address and its credentials without an ICE restart learns the pair in
  use; and an agent leaves `Disconnected` with the consent response, not at its next check.
- **ice**: the agent receives STUN through `rtc_stun::validated::Validator`: FINGERPRINT is
  verified when present (it never was), a request with an unknown comprehension-required
  attribute is answered 420 with UNKNOWN-ATTRIBUTES and a response with one is discarded (RFC
  8489 section 6.3), and only what the integrity covers is read.
- **ice**: `Url`'s `Display` writes every IPv6 host in brackets (one without `::` was not).
- **ice**: mDNS privacy (draft-ietf-mmusic-mdns-ice-candidates). A local relay candidate is not
  paired with a remote mDNS candidate (section 3.3.2: the TURN server learned the hidden
  address); a relay-only agent ignores remote mDNS candidates instead of resolving them
  (section 3.2.1); with `QueryAndGather` a reflexive or relayed candidate is signalled with
  raddr 0.0.0.0 rport 9 (section 3.1.2.2: it gave the hidden host address away); the address
  of a peer-reflexive remote candidate is left out of the statistics unless the peer signalled
  it (section 3.3.1).
- **ice**: `tcptype` is written after raddr / rport and read wherever it stands among the
  extension attributes, for every candidate type (RFC 6544 section 4.5); a TCP
  server-reflexive or relayed candidate lost it on the way to SDP and back.
- **ice**: when the selected TCP pair's connection is opened again (another source port), the
  passive side moves to the new connection once its check succeeds (RFC 6544 section 11.1);
  it kept writing to the dead one.

- **twcc**: a NACK retransmission sent without RTX keeps the transport-wide sequence number it
  was first given. `TwccSenderInterceptor` numbered it as a new packet, so its header extension
  changed and the SRTP sender, which protects one packet per index (RFC 3711 section 3.3.1,
  RFC 7714 section 8.1), refused it after the congestion controller had counted it as sent: no
  lost packet was repaired, the NACK generator asked again every 100 ms, and the phantom losses
  drove the estimate to its floor. The sender now remembers the number it gave each of a
  stream's last 1024 RTP sequence numbers; an RTX retransmission is still numbered as a new
  packet.

- **stun**: `Client` delivers a response of any length. It read into a 120-byte buffer, so a
  132-byte Binding response (what coturn sends over IPv6) failed to decode and the transaction
  timed out. `Message::read_from` reads its reader to the end.
- **stun**: `Client` takes as the response only a success or error response of the request's
  method that comes from the server (RFC 8489 section 6.3). Any message with a known
  transaction id, a request or an indication from any address included, ended the transaction.
- **stun**: a truncated MAPPED-ADDRESS or XOR-MAPPED-ADDRESS is an error; it decoded to an
  address filled up with zeros. The first byte of the value is ignored (RFC 8489 section 14.1);
  a non-zero one failed the attribute.
- **stun**: the reserved bits of ERROR-CODE are ignored (RFC 8489 section 14.8). With one set
  next to the class, a 438 decoded as 1238 and a stale nonce went unrecognised.
- **stun**: `Uri`'s `Display` writes every IPv6 host in brackets; one without `::` came out as
  `stun:2001:db8:1:2:3:4:5:6:3478`, which does not parse back.
- **stun**: `MessageIntegrity::check` no longer rewrites the message's length field while it
  runs, and checks by the attribute's position, whatever follows it.

- **turn**: a 437 (Allocation Mismatch) to a Refresh, CreatePermission or ChannelBind ends the
  allocation (RFC 8656 sections 5 and 8.3). The error was returned from `handle_read` or logged,
  the relay stayed in the client and a Refresh went out every half lifetime for ever. The client
  now drops the allocation, with its permissions, channel bindings and outstanding requests, and
  raises `Event::AllocationLost`.
- **turn**: an allocation released with `Relay::close` stays released. If the Refresh with
  LIFETIME 0 and its retry went unanswered, or the server answered 437, the next periodic
  refresh asked for the old lifetime again and kept the allocation alive. `close` now stops
  every refresh at once; `Event::AllocationReleased` reports the end (success, 437, or no
  answer).
- **turn**: channel bindings belong to their allocation (RFC 8656 section 12). They were kept per
  client, so a new allocation sent ChannelData on channel numbers only the previous one had
  bound, which the server drops.
- **turn**: permissions and channel bindings follow the RFC's timers. A permission lasts 300 s
  from its last accepted CreatePermission or ChannelBind: one whose refresh the server refuses
  is dropped (`Event::PermissionLost`), and a refused refresh of several addresses is repeated
  address by address so only the refused ones end. A channel binding lasts 10 minutes: one that
  carried data is rebound from a timer, one left idle is bound again (with the data in Send
  indications) before ChannelData is used on it, and a channel number is reused for another
  peer address only 15 minutes after the last ChannelBind sent for it.
- **turn**: the first Allocate response is read for what it is. A success (a server that asks
  for no credential, RFC 8656 section 7.2) is an allocation; an error other than 401 keeps its
  code. Both were reported as `AllocateError(attribute not found)`, the first while the server
  held the allocation.
- **turn**: an Allocate success response without XOR-RELAYED-ADDRESS or LIFETIME is reported as
  `AllocateError` under the caller's id and the allocation is deleted with a Refresh of
  LIFETIME 0. It ended `handle_read` with an error and no event, and left the allocation on the
  server.
- **turn**: with all 4096 channel numbers taken, data to one more peer address goes as Send
  indications; the send failed.
- **turn**: ChannelData cannot carry more than 65 535 bytes; `Relay::send_to` and
  `ChannelData::encode` refuse a longer payload instead of writing a wrapped length, which over
  TCP or TLS broke the framing of every later message.
- **turn**: an allocation whose Refresh requests all fail is refreshed again at half the time
  it has left, and is dropped (`Event::AllocationLost`) when its lifetime has run out.
- **turn**: a ChannelBind the server refuses is reported (`Event::ChannelBindError`) and tried
  again after a minute; it was sent again with every packet. A 400 (the channels of client and
  server are out of step) deletes the allocation, as RFC 8656 section 12.3 recommends.
- **turn**: a ChannelBind success refreshes the peer's permission (RFC 8656 section 12.3).
- **turn**: `Client::update_credentials` documents that a live allocation takes a new password,
  not a new username (the server answers 441, RFC 8656 section 5).
- **turn**: the `turn_client_tcp` example no longer names RFC 6062; it is a UDP allocation
  reached over TCP (RFC 8656 section 3.1).

- **dtls**: a ClientHello with a session id is parsed (RFC 5246 section 7.4.1.2). The length byte
  was read and the id left in place, so the cookie, cipher suites and extensions of a client
  offering a cached session were read from the wrong offset and it could not connect.
- **dtls**: a hello may end before the extensions block (RFC 5246 sections 7.4.1.2, 7.4.1.3); such
  a ClientHello or ServerHello was dropped. A hello with bytes after the block, or with one
  extension type twice, is refused. An extension of an unknown type is kept
  (`Extension::Unknown`) instead of being dropped at parse.
- **dtls**: the ServerHello carries only the extensions the ClientHello offered (RFC 5246 section
  7.4.1.4): renegotiation_info was sent always, and supported_groups (which is not a ServerHello
  extension, RFC 8422 section 5.2) and ec_point_formats for every certificate suite. A client
  refuses an extension it did not offer with unsupported_extension, and a compression method it
  did not offer with illegal_parameter.
- **dtls**: the peer's signature algorithm lists are honoured (RFC 5246 sections 7.4.1.4.1, 7.4.2,
  7.4.3, 7.4.4, 7.4.8). The server signs its ServerKeyExchange with a pair from the client's
  signature_algorithms (the SHA-1 defaults when the extension is absent) and offers a certificate
  only if it is signed with such a pair; with none usable no certificate suite is selected. The
  client answers a CertificateRequest with a certificate only if its type, its signature and a
  CertificateVerify pair fit the request, and sends an empty Certificate otherwise. A client also
  checks that the server's key is of the kind the negotiated key exchange names.
- **dtls**: with no curve of the client's supported_groups in common, an ECDHE suite is not
  selected and the handshake fails with handshake_failure (RFC 8422 section 5.1); the server went
  on with its default curve.
- **dtls**: the reserved alert no_certificate(41) is no longer sent (RFC 5246 section 7.2.2): a
  missing required client certificate is a handshake_failure. Alert descriptions follow section
  7.2.2 elsewhere too: handshake_failure when no parameters are acceptable (it was
  insufficient_security), decrypt_error for a signature or Finished that does not verify,
  illegal_parameter for a value that was not offered.
- **dtls**: a client refuses a ServerHello whose `use_srtp` holds an MKI or not exactly one
  profile (RFC 5764 sections 4.1.1, 4.1.3) with illegal_parameter. A server configured without
  SRTP profiles ignores a client's `use_srtp` instead of aborting.
- **dtls**: a ClientHello offering a later DTLS version than 1.2 is answered with 1.2, under any
  record-layer version of the family in epoch 0 (RFC 5246 section E.1); it was refused.

- **srtp** (security): the SRTCP index wrapped to 0 after 2^31 − 1 and sending went on under the
  same master key, reusing the AES-CM keystream, or the AES-GCM nonce, of the first packets
  (RFC 3711 section 9.2, RFC 7714 section 9.4). The context now counts packets per master key and
  refuses the one past the limit.
- **srtp** (security): the receiver followed a rollover counter past 2^32 − 1: after ROC
  0xFFFFFFFF a packet with a low sequence number was tried, and accepted, with ROC 0
  (RFC 3711 section 3.3.1, RFC 7714 section 13.1).
- **srtp** (security): with Cryptex required, a packet whose extension profile is not RFC 8285's
  (or has two-byte "appbits") left with its header extension and CSRCs in the clear
  (RFC 9335 section 5.2).
- **srtp**: a valid unencrypted (E = 0) SRTCP packet under AEAD_AES_128_GCM / AEAD_AES_256_GCM
  failed authentication: the receiver always treated the body as ciphertext (RFC 7714 section
  9.3). It is now authenticated as the RFC has it, and still refused with a wrong tag or a
  flipped E flag.

- **datachannel**: a DATA_CHANNEL_OPEN on a stream that already carries a channel closes that
  channel and is not acknowledged (RFC 8832 section 6). It was acknowledged and the channel left
  open.
- **datachannel**: a malformed DATA_CHANNEL_OPEN, and user data or a stray ACK on a stream no
  OPEN opened, reset the stream (RFC 8832 section 6). The error was returned and dropped, and
  the stream stayed half open.
- **datachannel**: user data sent before the DATA_CHANNEL_ACK arrives is sent ordered on an
  unordered channel too (RFC 8832 section 6). It left unordered, could overtake the OPEN, and
  the peer then dropped it: between two of these engines none of it arrived.
- **datachannel**: a message under an unsupported PPID (the deprecated partial PPIDs 52 and 54
  included) and a DCEP message that does not parse close the channel (RFC 8831 section 6.6).
  The first was delivered to the application as binary data, the second left the channel open.
- **datachannel**: `create_data_channel` refuses a label over 65535 bytes (`ErrLabelTooLarge`;
  the OPEN went out with a length taken modulo 65536), a negotiated id whose stream already
  carries a channel (`ErrDataChannelIdInUse`; the second channel took the stream over, RFC
  8831 section 6.5) and the id 65535 (`ErrMaxDataChannelID`).
- **datachannel**: the channel priority is the weight of its SCTP stream under weighted fair
  queueing (RFC 8831 section 6.4), for channels opened locally, by the peer and out of band.
  It was carried in the OPEN and reported, never applied.
- **sdp**: a rejected data section (m= port zero, in the offer or the answer) and an
  `a=sctp-port` of zero start no SCTP transport, and close the association that exists (RFC
  8841 sections 10.3 and 10.4). A rejected section started it all the same, port 0 became the
  destination port of the INIT, and the data channels stayed `connecting`: they now fail with
  `OnError` and `OnClose`.
- **sdp**: the answer to an offer with a new `a=sctp-port` carries a new port, to one with
  port zero carries zero (RFC 8841 section 10.3), and repeats the offer's proto, so
  `TCP/DTLS/SCTP` is answered as such; it always said `UDP/DTLS/SCTP` and 5000.
- **sdp**: an `m=application` line that is neither a data channel section nor RTP (the
  pre-RFC `DTLS/SCTP 5000` form with `a=sctpmap`, which no current browser sends) is answered
  like a media type the endpoint does not know: rejected, with its own proto and fmt. It was
  taken for application media over RTP, and no answer could be made.
- **sctp**: a new `a=sctp-port` on either side closes the association and establishes a new
  one over the same DTLS transport (RFC 8841 section 9.3); later descriptions never reached the
  SCTP transport. An association added to a session whose DTLS transport is already connected
  is initiated at once.
- **sctp**: a DTLS handshake that completes again starts no second association (RFC 8841
  section 10.5); the SCTP transport stays `closed`, not `connecting`, once a lost association
  has been let go of, and the next offer carries a new `a=sctp-port` for a new one.

- **rtcp**: an SDES item of a type above 8 (MID, RID, anything registered later) ended the chunk and
  failed the whole datagram, the SR or RR in it included. Items are read by their length whatever
  their type (RFC 3550 section 6.5).
- **rtcp**: a padded XR packet failed to parse and took the datagram with it; one XR block with a
  length its type does not allow did the same. Padding is cut first, and such a block is kept
  unparsed with its type (RFC 3611 sections 2 and 4).
- **rtcp**: an RTCP packet of an unknown type was written back as type 0, and an XR block of an
  unknown type as block type 0. Both keep what they arrived with.
- **rtcp**: transport-cc feedback with an even number of chunks and no delta was rejected; the
  symbols of a status vector beyond the packet status count consumed deltas.
- **rtcp**: application layer feedback that is not REMB failed the datagram.
- **rtcp**: RTCP padding was read as content: as a profile extension of an SR / RR, as report blocks
  of an XR, as the report timestamp of RFC 8888 feedback.
- **rtcp**: an SDES chunk and a BYE reason were padded with a count octet, as if by the P bit, and
  the BYE set the P bit. Both are padded with null octets (RFC 3550 sections 6.5 and 6.6).
- **rtcp**: an RLE block with an odd number of chunks was written misaligned with a truncated block
  length; it now ends with the terminating null chunk (RFC 3611 section 4.1).
- **rtcp**: a generic NACK or an SLI could not hold more than 253 entries; the limit is the 16-bit
  length field.
- **rtcp**: a REMB with a zero mantissa was read as 2^(exp + 23) bit/s, not zero; printing a REMB
  above 1000 Eb/s panicked (an index past the unit table, on a value a peer chooses).

- **rtcp**: each packet of an inbound compound RTCP packet reaches the application with the track
  it is about (RFC 3550 6.1). The whole datagram was routed by its first packet, so a PLI behind
  an empty receiver report was dropped and one behind a report about another stream arrived
  tagged with that stream's track.
- **rtcp**: reception reports follow RFC 3550 Appendix A.1 / A.3: the cumulative loss is expected
  less received (a late packet is no longer lost, duplicates make it negative, it is clamped to
  the signed 24 bits at both ends) and a source that restarts starts the statistics again. Loss
  was counted per report from a bitmap and never revisited.
- **rtcp**: a stream that stopped sending issues no sender report after two report intervals
  (RFC 3550 6.4). It issued one every interval for as long as it was bound.
- **rtcp**: a sender report's RTP timestamp wraps modulo 2^32; it stopped at `u32::MAX` once a
  stream had been idle for 2^32 ticks.
- **nack**: no NACK is sent for an RTX or FEC SSRC (RFC 4588 6.3). Repair flows were bound with
  their primary's feedback, so the gaps between padding-only RTX probes were asked for every
  100 ms, for ever.
- **nack**: retransmission requests for a source stop at its BYE (RFC 4588 5.3).
- **rtx**: an RTX stream's sequence numbers carry on when its stream is bound again by a
  renegotiation, and start at a random value (RFC 4588 4). They restarted at 0, repeating SRTP
  packet indices of a live SSRC, which the SRTP layer refuses: retransmissions stopped until the
  counter passed its old high-water mark.
- **receiver**: `RTCRtpReceiver::get_synchronization_sources` and `get_contributing_sources` list
  the sources of the packets delivered in the last ten seconds (W3C webrtc 5.3). They were always
  empty.

- **sdp**: `a=fmtp` parameters that contain a space were dropped
  (`a=fmtp:96 level-asymmetry-allowed=1; packetization-mode=1; profile-level-id=42e01f` left the
  codec without parameters, so H.264 profiles did not match). The parameters are everything
  after the first space (RFC 8866 section 6.15).
- **sdp**: `a=rtcp-fb:* <type>` was dropped. It applies to every format of the media section
  (RFC 4585 section 4.2), in its place among the other `a=rtcp-fb` lines.
- **sdp**: the extension attributes of `a=extmap` are everything after the URI (RFC 8285 section
  5); they were cut at their first space.

- **flexfec-03**: a block of 110 media packets is refused. Draft-03's masks hold 109 bits
  (15 + 31 + 63); the 110th packet was XORed into the repair data without being named in the
  mask, so anything recovered from that repair packet was corrupt.
- **flexfec-03**: SN base is the lowest sequence number each repair packet protects (draft-03
  section 4.2). Every repair packet of a block carried the block's first sequence number.
- **flexfec-03**: the repair packet's timestamp is its transmission time on the repair stream's
  clock, from the instant the block is written with (section 4.2). It was the media timestamp
  of the first protected packet.
- **flexfec-03**: the initial sequence number of a repair stream is random (section 4.2). It
  was 0.

- **stats**: a remote-outbound object's `remoteTimestamp` is the NTP time of the latest RTCP
  sender report (it was the time of the `get_stats` call), and is left out when that time is
  before 1970; the `timestamp` of a remote-inbound / remote-outbound object is when its report
  arrived. Every timestamp of a report is now on one wall-clock anchor: `lastPacketReceivedTimestamp`
  and `lastPacketSentTimestamp` were the time of the call too.
- **stats**: `active` follows the encoding's `active` (`set_parameters`); it was always `true`.
- **stats**: members that do not apply or that nothing measures are left out instead of written
  as 0: `firCount` / `pliCount` (and every other video-only member) on an audio stream,
  audio-only members on a video stream, `retransmittedPacketsReceived` /
  `retransmittedBytesReceived` without RTX, `packetsDiscardedOnSend` / `bytesDiscardedOnSend`
  until the application reports a discard, `dataChannelIdentifier` before the channel has an
  id, `totalEncodedBytesTarget` (removed from webrtc-stats).
- **stats**: `dataChannelsClosed` no longer counts a channel that never opened.
- **stats**: a remote candidate's `address` is null unless the application supplied that
  address; a peer-reflexive remote candidate learned from a check no longer shows its address
  or a `usernameFragment`.
- **stats**: RTP accounting. `packetsSent` / `bytesSent` / `headerBytesSent` include the
  packets sent on the RTX SSRC; a retransmission on the stream's own SSRC (no RTX) counts in
  `retransmittedPacketsSent`; retransmitted bytes are the repeated payload, without the RTX
  original sequence number; a padding-only RTX packet is not a retransmission; header bytes
  include padding; packets on the FEC SSRC count in `packetsReceived` / `bytesReceived`.
  Arrivals are counted before the interceptor chain, so a packet a FEC decoder rebuilds is not
  counted as received.
- **stats**: transport `bytesSent` / `bytesReceived` leave out STUN and mDNS datagrams.
- **stats**: an id is hashed with a salt drawn per peer connection (W3C: "MUST NOT be
  predictable by an application"), and a recycled SSRC gets a new id, never the deleted
  object's.
- **stats**: `roundTripTime` gating as webrtc-stats words it (no measurement from a DLSR or
  DLRR delay of 0; the remote-outbound value is cleared by a sender report without a DLRR
  block); the remote receiver's `packetsReceived` never decreases; `selectedCandidatePairChanges`
  counts the loss of the selected pair; a pair that stops being selected gives up its bitrate
  estimates; candidates no agent and no reported pair holds are deleted (ICE restart);
  `targetBitrate` is no longer the connection's estimate copied to every stream.
- **stun**: `rtc_stun::validated`, the receive path for every usage. `Validator` runs the
  FINGERPRINT check (required with `require_fingerprint`; always right and last), the integrity
  check (`authenticate`: MESSAGE-INTEGRITY-SHA256 when present, else MESSAGE-INTEGRITY;
  `authenticate_with` for the algorithm the request used; `unauthenticated` for messages
  without credentials) and the unknown comprehension-required attribute check
  (`known_attributes`, `STUN_ATTRIBUTES`), and returns a `ValidatedMessage` that holds only the
  attributes ahead of the first integrity attribute. RFC 8489 section 9 has agents ignore
  everything after it; reading attributes off the raw `Message` after
  `MessageIntegrity::check` does not, and an attribute appended to a genuine message was
  obeyed. `unknown_attributes_response` builds the 420 with UNKNOWN-ATTRIBUTES. `rtc-ice` and
  `rtc-turn` are to receive through it.
- **stun**: MESSAGE-INTEGRITY-SHA256 (`MessageIntegritySha256`, truncation only where the usage
  allows it), USERHASH (`userhash::Userhash`), PASSWORD-ALGORITHM and PASSWORD-ALGORITHMS
  (`password_algorithm`), ALTERNATE-DOMAIN (`textattrs::AlternateDomain`), the SHA-256
  long-term key (`integrity::long_term_key`), the OpaqueString profile (`opaque::opaque_string`,
  `MessageIntegrity::short_term`) and the nonce cookie's security features
  (`nonce_cookie::SecurityFeatures`). Checked against RFC 5769 and RFC 8489 appendix B.1.
- **stun**: `long_term::LongTermCredentials`, the client rules of the long-term credential
  mechanism (RFC 8489 section 9.2) without I/O: the first request carries no credentials; a
  401 / 438 is turned into the retry's attributes (USERNAME or USERHASH, REALM, NONCE,
  PASSWORD-ALGORITHMS, PASSWORD-ALGORITHM, the integrity attribute), or refused when the nonce
  cookie shows PASSWORD-ALGORITHMS was stripped (bid-down), when no offered algorithm is
  supported, or when the same credentials were just rejected; `check_response` says whether a
  response is authenticated, a challenge, or to be discarded.
- **stun**: `alternate::TryAlternate` reads the alternate servers and domain out of an
  authenticated 300 (Try Alternate); `RedirectGuard` refuses a redirection to a server tried
  within five minutes (RFC 8489 section 10).
- **stun**: `Client` computes its RTO as RFC 6298 does (kept per server for ten minutes,
  `with_rto_estimation`), has `with_rc`, `with_rm`, `with_ti`,
  `with_max_outstanding_transactions`, `with_path_mtu` and `with_known_attributes`, drops a
  response with a wrong FINGERPRINT, fails a transaction whose response has unknown
  comprehension-required attributes or no ERROR-CODE (`StunEvent::TransactionFailed`), and with
  `with_response_integrity` discards unauthentic responses and reports an integrity violation
  instead of a timeout (at once over TCP), as RFC 8489 section 9.1.4 requires.
- **stun**: `Uri::port_or_default`, `Uri::srv_query_name`, `Uri::is_secure`, `Uri::host_is_ip`,
  and `Uri::parse_uri_strict`, which refuses a `stuns` URI with an IP address (RFC 8489 section
  8.1; `parse_uri` keeps accepting it, as browsers do). `Message::unknown_required_attributes`.

- **turn**: the long-term credential mechanism of RFC 8489 section 9.2, through
  `rtc_stun::long_term::LongTermCredentials`. When the server's 401 offers PASSWORD-ALGORITHMS
  the client echoes it, sends PASSWORD-ALGORITHM, derives the key with it and authenticates
  with MESSAGE-INTEGRITY-SHA256 alone, in that request and every later one, expecting the same
  attribute in responses; with SHA-256 on offer it takes SHA-256 wherever the server listed it
  (RFC 8656 section 6). It sends USERHASH in place of USERNAME when the nonce cookie has the
  "username anonymity" bit. It does not retry after a 401 or 438 whose nonce cookie announces
  PASSWORD-ALGORITHMS when the response has none (a bid-down), nor when no offered algorithm
  is supported, and it ignores any other response with such a nonce. The user name is sent as
  an OpaqueString (RFC 8265). `ClientConfig::password_algorithms` restricts the algorithms
  accepted, for example to SHA-256 alone (RFC 8489 section 18.5.1.1 keeps MD5 for servers that
  have nothing else). `Client::update_credentials` keeps the negotiated realm, nonce and
  algorithm. A data connection's ConnectionBind carries the same credential.
- **turn**: the RTO follows each server's round-trip time as RFC 6298 computes it (never below
  the initial RTO, no sample from a retransmitted request, dropped after ten minutes without a
  transaction); `RetransmissionConfig::rto_estimation` turns it off.
- **turn**: `ErrorResponse::try_alternate` is the redirection (`rtc_stun::alternate::TryAlternate`:
  every ALTERNATE-SERVER and the ALTERNATE-DOMAIN) of a 300 that was authenticated with the
  request's credential; `alternate_server` still reports the address of any 300. The client
  follows none by itself. `Client::follow_alternate(now, &redirect)` is for the application
  that does: it moves the client to the alternate server of the address family in use, so
  that the next `allocate` goes there over the same transport with the same credentials, and
  refuses a server an Allocate was sent to within the last five minutes (RFC 8489 section 10).
- **stun**: `rtc_stun::timer` (`Schedule`, `RtoEstimator`, the RFC's defaults): the
  retransmission arithmetic of section 6.2, moved out of `Client` so that the TURN client runs
  on the same code.
- **test-env**: `tests/testenv_turn_client.rs` checks against coturn that a wrong password's
  401 is not answered again, and that requests keep the 500 ms initial RTO.

### DTLS 1.3

- **dtls**: DTLS 1.3 (RFC 9147, on the TLS 1.3 handshake of RFC 8446), next to DTLS 1.2. A
  client offers both in one ClientHello and a server takes 1.3 from a client that offers it;
  the downgrade sentinel of RFC 8446 section 4.1.3 is set and checked.
  `ConfigBuilder::with_protocol_versions` sets the range (default 1.2 to 1.3), and
  `State::negotiated_version` says which was negotiated (`DtlsVersion::protocol_version` gives
  the bytes of webrtc-stats' `tlsVersion`: `FEFC` for 1.3).
- **dtls**: the record layer of RFC 9147 section 4: the unified header, record number
  encryption, epochs with their own keys and replay windows, ACK records.
- **dtls**: the handshake with certificates (ECDSA P-256, Ed25519, RSASSA-PSS), a stateless
  cookie exchange by HelloRetryRequest (on by default), client certificates, `use_srtp` in
  EncryptedExtensions and the exporter of RFC 8446 section 7.5 behind the same
  `State::export_keying_material` (which takes a context for a DTLS 1.3 association).
  Suites: `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256`, `TLS_AES_256_GCM_SHA384`
  by default, `TLS_AES_128_CCM_SHA256` and `TLS_AES_128_CCM_8_SHA256` when named. Groups:
  P-256, X25519, P-384.
- **dtls**: flights, retransmission and ACKs as RFC 9147 sections 5.8 and 7 define them; the
  timer follows the measured round trip once a flight gets through without loss.
- **dtls**: key update (`Endpoint::update_keys`, `DTLSConn::update_keys`), started by
  itself before a key reaches the number of records its AEAD allows; an association is closed
  when too many records fail authentication under one key (RFC 9147 section 4.5.3).
- **dtls**: connection ids for DTLS 1.3 (RFC 9147 section 9): `ConfigBuilder::with_connection_id`,
  `Endpoint::{new_connection_ids, request_connection_ids}`, `DTLSConn::use_next_connection_id`,
  and `with_connection_id_migration` for an endpoint that may follow a peer to a new address.
- **dtls**: RSASSA-PSS (`rsa_pss_rsae_sha256/384/512`) in DTLS 1.2 as well: listed by default
  after PKCS#1 v1.5, verified and signed.
- **crypto**: `hkdf_extract`, `hkdf_expand`, `hkdf_expand_label`; `HashAlgorithm::Sha384`,
  `HmacAlgorithm::Sha384`; `RTCCrypto::new_header_mask` with `HeaderMask` and
  `HeaderMaskAlgorithm` (record number encryption); `SignatureScheme::RsaPssSha256/384/512`,
  which an imported RSA key signs with.
- Not in it: pre-shared keys in DTLS 1.3 (resumption, external PSKs, 0-RTT), post-handshake
  authentication. A configuration with a pre-shared key negotiates DTLS 1.2.

### DTLS 1.3 in the peer connection, connection ids for DTLS 1.2

- **peer connection**: the TLS 1.3 suites come first in the default cipher suite list, so two
  engines negotiate DTLS 1.3 and a peer without it (webrtc 0.17, which ignores the extensions)
  gets DTLS 1.2 from the same ClientHello. `tlsVersion` is `FEFC` for DTLS 1.3. The client's
  retransmission timer starts at 400 ms (RFC 9147 section 5.8.2, DTLS-SRTP), or at 1.5 times
  the selected pair's ICE round trip time, at least 100 ms
  (`HandshakeConfig::with_flight_interval`).
- **peer connection**: an SCTP packet is sized by the record overhead of the DTLS version and
  suite negotiated (`Endpoint::record_overhead`, `DTLSConn::record_overhead`): a DTLS 1.3 record
  adds 22 bytes where a DTLS 1.2 AES-GCM record adds 37, and packets were 15 bytes short of the
  path MTU under DTLS 1.3.
- **dtls**: RFC 9146 for DTLS 1.2: the `connection_id` extension in the DTLS 1.2 hellos (a
  ClientHello for both versions carries one, for whichever is negotiated; by default it asks
  for no id), `tls12_cid` records with the additional data and MAC input of section 5 for
  every cipher family, records without the negotiated id discarded, and the peer address
  update of section 6 behind `with_connection_id_migration` (off by default).
- **dtls**: a DTLS 1.3 client that authenticates completes only on the server's ACK or first
  application-epoch record; a DTLS 1.3 server picks a certificate chain signed with algorithms
  the client lists (RFC 8446 section 4.4.2.2); the retransmission timer returns to its start
  after ten intervals of quiet (RFC 9147 section 5.8.2); too_many_cids_requested ends an
  association after 32 RequestConnectionId messages; `ConfigBuilder::with_invalid_record_limit`
  gives up on a peer that keeps sending records that fail (opt-in: they are unauthenticated).
- **dtls**, **crypto**: the hybrid post-quantum key share X25519MLKEM768 (0x11EC,
  draft-ietf-tls-ecdhe-mlkem) in DTLS 1.3, offered first where the provider has ML-KEM
  (aws-lc-rs; ring has none and does not offer it): `ConfigBuilder::with_post_quantum_key_share`
  (default on), `KeyExchangeAlgorithm::X25519MlKem768`, `RTCCrypto::key_exchange_respond` (the
  server's side of a KEM; the default is the Diffie-Hellman key pair and agreement). Its
  1216-byte share makes the ClientHello two fragments; the stateless cookie exchange reassembles
  them. Checked against OpenSSL 4.1 in both roles. The group is offered only where one exchange
  through the provider gives both ends the same secret.
- **dtls**: a DTLS 1.3 suite is offered only if the provider can make its record-number mask,
  so a provider that wraps another and leaves `new_header_mask` at its default gets DTLS 1.2
  instead of failing every record (`isolates_crypto_providers_across_simultaneous_peer_connections`
  failed on the train).

### DTLS 1.3 pre-shared keys

- **dtls**: session resumption with tickets for DTLS 1.3 (RFC 8446 sections 2.2, 4.2.9,
  4.2.11, 4.6.1). A server sends `ConfigBuilder::with_session_tickets(n)` NewSessionTicket
  messages after each handshake (default 0: none), sealed under a key its configuration makes
  at random and valid for `with_session_ticket_lifetime` (two hours by default, seven days at
  most); each ticket is accepted once. A client given a `SessionStore`
  (`with_session_store`; `session::MemorySessionStore`) keeps them by server name and offers
  one, with its binder, as the last extension of its next ClientHello to that name (computed
  again after a HelloRetryRequest). A resumed handshake has no Certificate or
  CertificateVerify; the association reports the certificates of the handshake the ticket
  came from (`State::resumed`), and the peer-certificate check runs on them again.
- **dtls**: external PSKs for DTLS 1.3 (`with_external_psks`, `session::ExternalPsk`, with
  their hash, which steers the suite a server picks). `psk_dhe_ke` is the only mode by
  default; `with_psk_without_key_exchange` allows `psk_ke` as well.
- **dtls**: `DTLSConn::set_clock` gives an association the time ahead of a datagram (the
  endpoint calls it): what tickets are dated by. The engine reads no clock.
- **peer connection**: no session tickets, no session store and no PSK in the DTLS
  configuration: WebRTC authenticates every association by the fingerprints of its SDP and
  makes a new one per session (`the_peer_connection_neither_sends_nor_accepts_session_tickets`).

### DTLS 1.3 post-handshake authentication

- **dtls**: post-handshake authentication for DTLS 1.3 (RFC 8446 sections 4.2.6 and 4.6.2).
  A client configured with `ConfigBuilder::with_post_handshake_auth` offers it; a server asks
  with `Endpoint::request_client_certificate` (`DTLSConn::request_client_certificate`), and
  the client answers at once with its certificate (or an empty Certificate where it has none
  the request allows). The server checks the answer as it checks a client certificate in the
  handshake and reports `EndpointEvent::PeerAuthenticated`; `State::peer_certificates` then
  holds the new chain.

### DTLS 1.3 0-RTT

- **dtls**: 0-RTT data for DTLS 1.3 (RFC 8446 sections 2.3 and 4.2.10), off by default on
  both sides. `ConfigBuilder::with_max_early_data(n)` makes a server's tickets allow n bytes
  and has it take them: only with the first PSK, a ticket of its own used for the first time
  (section 8.1), of the same suite, in a first ClientHello, whose age agrees with the
  server's within ten seconds (section 8.3); it is delivered as `EndpointEvent::EarlyData`
  before the handshake completes. `Endpoint::connect_with_early_data` sends it from a client
  whose session store has such a ticket; `State::early_data_accepted` says whether it was
  taken. A HelloRetryRequest rules 0-RTT out, so it needs `with_cookie_exchange(false)`.

### Robustness under loss (DTLS, SCTP)

Found by the seeded lossy-link test (`tests/lossy_link_rtc2rtc.rs`).

- **dtls**: a DTLS 1.3 server that answered a ClientHello too long for one datagram (the
  X25519MLKEM768 hybrid key share makes it two) sent its HelloRetryRequest once and forgot
  it: when it was lost, every retransmitted ClientHello was taken for a repeat and answered
  with nothing, and the handshake stalled until its deadline. The association keeps the
  HelloRetryRequest and sends it again for every repeat of the ClientHello it answered (RFC
  9147 sections 5.1 and 5.8.1), never on a timer of its own. Its cookies are now the
  endpoint's, bound to the client's address, so the endpoint or any later association
  verifies the second ClientHello (a second ClientHello that no longer fitted one datagram used
  to be refused with illegal_parameter). Such an association for an unverified address is
  dropped, silently, two minutes after the last datagram from that address, whatever the
  handshake deadline: long enough for fragments of several transmissions to add up when the
  client, at full backoff, cuts its ClientHello smaller (`hello_loss_test.rs`).
- **dtls** (behaviour change): no handshake deadline by default. RFC 6347 section 4.2.4 and
  RFC 9147 section 5.8 define the retransmission timer (doubling to 60 seconds) and no total
  limit; a handshake nobody answers is retransmitted at most once a minute for as long as the
  association lives. `ConfigBuilder::with_handshake_timeout(Some(..))` sets a deadline (it was
  30 seconds by default). In a peer connection the handshake now ends only on ICE failure
  (consent expiry), a fatal alert or a close: at 30 % loss with ICE connected and consent
  fresh, the peer connection used to go `failed` 30 seconds in. New:
  `Endpoint::handshake_retransmissions`, `DTLSConn::handshake_retransmissions`, for a
  handshake that goes on and on.
- **dtls**: the Finished of a DTLS 1.3 post-handshake authentication is checked with the
  client's traffic secret of the epoch it arrived in: a client that answered while its own
  KeyUpdate was unacknowledged keys it from its old secret (its new keys take effect on the
  acknowledgement, RFC 9147 section 8), and the server used its newest one and refused the
  answer with decrypt_error.
- **sctp**: an endpoint that announces the zero checksum over DTLS (RFC 9653, as a peer
  connection's does) answers an out-of-the-blue packet with a zero checksum as RFC 9260
  section 8.4 says, with an ABORT (RFC 9653 section 5.3 allows it: "faster SCTP association
  failure detection"); it used to drop it. A data channel neither opened nor failed for
  minutes over a lossy path: the INITs crossed, one side (its COOKIE ACKs lost) was
  established and sent DATA_CHANNEL_OPEN, the other discarded it in COOKIE-ECHOED until its
  handshake ran out and its association ended, and the established side's DATA and
  HEARTBEATs then reached no association and were dropped unanswered. It is now aborted by
  its next packet, and the channel fails with an error. INIT and COOKIE ECHO still need their
  CRC32c (`a_peer_whose_association_ended_here_is_aborted_by_its_next_packet`).
- **sctp**: `EndpointConfig::random_source(provider)` draws every random value of an
  endpoint and its associations (verification tags, initial TSNs, unauthenticated State
  Cookies, the Initiate Tag of an INIT ACK for an existing association, HEARTBEAT nonces and
  jitter) from `provider.random()`, as ICE and DTLS take theirs; without it they still come
  from `rand`. The peer connection passes its crypto provider, so a seeded provider makes a
  whole session reproducible.

### DTLS 1.2: the RFC by default

- **dtls**: `HelloVerifyRequest.server_version` is DTLS 1.0, as RFC 6347 section 4.2.1 asks
  whatever version follows; `ConfigBuilder::with_hello_verify_request_version` restores DTLS 1.2.
- **dtls**: the `server_name` extension is not sent for an IP address (RFC 6066 section 3),
  and is sent without a trailing dot.
- **dtls**: a server with an Ed25519 certificate offers the ECDHE_ECDSA suites (RFC 8422
  section 5.1.1); its configuration used to fail to build.
- **dtls**: a client that receives authentic application data before the server's Finished
  sends its last flight again at once (RFC 6347 section 4.2.4;
  `ConfigBuilder::with_early_data_retransmit`), and that data is delivered when the handshake
  completes: it used to be dropped when the early-record queue was drained.

### Breaking changes (DTLS 1.3)

- **dtls**: a `ConfigBuilder` without a cipher suite list negotiates DTLS 1.3 with a peer that
  has it. A list is exact: one without a TLS 1.3 suite negotiates DTLS 1.2 only, as before.
- **dtls**: `CipherSuiteId` has the five TLS 1.3 suites, `CipherSuiteHash` has `Sha384`,
  `SignatureAlgorithm` has the three RSASSA-PSS values (and `Unsupported` is `0xff`), and the
  default signature schemes list them.
- **dtls**: a HelloVerifyRequest says DTLS 1.0 (see above).
- **dtls**: `State::marshal_binary` fails for a DTLS 1.3 association.
- **crypto**: `HashAlgorithm`, `HmacAlgorithm`, `SignatureScheme` and `CryptoAlgorithm` have
  new variants (all `non_exhaustive`).

### Dependencies

- **stun**: `precis-profiles` 0.2 (MIT / Apache-2.0, pure Rust) for the OpaqueString profile.
- **ice**: attributes after MESSAGE-INTEGRITY are ignored (RFC 8489 section 14.5). The HMAC does
  not cover them, so someone who saw one valid check could replay it with ICE-CONTROLLED or
  ICE-CONTROLLING appended and flip the agent's role.
- **ice**: role conflicts follow RFC 8445 section 7.3.1.1. A conflicting request gets one
  answer: the 487 when this agent keeps its role (and then nothing else comes of the request),
  the success response when it switches. It got both. A controlled agent switches on an equal
  tiebreaker (`>=`, it was `>`).
- **ice**: a 487 (Role Conflict) response is acted on (section 7.2.5.1): the role switches, the
  tiebreaker changes and the pair is checked again. Error responses were dropped unread, so an
  agent whose peer answered 487 never left the conflict. Any other authenticated error response
  fails the pair (section 7.2.5.2.4).
- **ice**: a Binding request that arrives before the remote description is answered at once and
  finished when the peer's credentials arrive: peer-reflexive candidate, triggered check,
  nomination (section 7.3). It was dropped, so an offerer whose answerer started checking first
  left those checks to time out. A request's USERNAME is valid when its first part is the local
  fragment.
- **ice**: pair priority is `2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D)` (section 6.1.2.3); it
  multiplied MIN by `2^32 - 1`. `test_candidate_pair_priority` pinned the wrong values.
- **ice**: PRIORITY in a check is the local candidate's priority as a peer-reflexive candidate
  (section 7.1.1), not its own; a peer-reflexive remote candidate takes its priority from the
  request (section 7.3.1.3) and is paired only with the local candidate the request arrived on.
- **ice**: local candidates of one type get unique local preferences, IPv4 and IPv6 interleaved
  (RFC 8445 section 5.1.2.1, RFC 8421 section 4; RFC 6544 section 4.2 for a TCP candidate's
  other-pref). Two host candidates on two interfaces had the same priority.
- **ice**: a candidate's foundation is made of its type, its base's IP address, its server and
  its transport (section 5.1.1.3); it used the candidate's own address and no server.
- **ice**: a nomination that gets no answer is given up after `max_binding_requests` requests
  and the controlling agent nominates its next valid pair. It repeated the nomination until the
  agent failed.
- **ice**: a lite agent sends no connectivity checks (sections 6.2 and 7.3.2): a request with
  USE-CANDIDATE selects the pair. It sent a triggered check and waited for the answer.
- **ice**: a request on a pair that already succeeded triggers no check from the controlled
  agent (section 7.3.1.4; every consent check of the peer cost a check back), and a request on a
  Failed pair gives the pair a fresh budget on the controlled side too.
- **ice**: an ICE restart given the credentials in use (`SettingEngine::set_ice_credentials`)
  generates new ones (section 9). The offer carried the old pair, so the peer saw no restart
  while this side had flushed its state.
- **ice**: candidate constructors take component 0 (the `Default`) as 1 and refuse a component
  above 256 or a priority above 2^31 - 1; `COMPONENT_RTCP` is 2.

- **ice**: consent freshness follows RFC 7675 section 5.1. Consent checks on the selected pair
  are 0.8 to 1.2 times the period apart, drawn anew each time, the period 5 seconds by default
  and never less (it was a fixed 2 seconds); `poll_timeout` returns the drawn instant. Consent
  expires 30 seconds after the last response whatever the configured timeouts (a zero
  `failed_timeout` kept a connected agent sending for ever), and the open transactions go with
  it.
- **ice**: consent is kept up on the path an ICE restart leaves in use (RFC 7675 section 5.1).
  The agent goes on sending consent requests there with the replaced generation's credentials,
  answers the peer's, and gives the path up 30 seconds after the last response. Until now data
  flowed on it unchecked until the restart selected a pair or failed.
- **ice**: a lite agent keeps its selected pair alive with a Binding indication after 15
  silent seconds (RFC 8445 section 11); it sent nothing.

### Record layer and handshake transport

- **dtls**: the handshake retransmission timer follows RFC 6347 section 4.2.4.1: one second,
  doubled at each retransmission up to 60 seconds, the value kept until a flight is answered
  without loss. It was a fixed second, and the handshake failed after seven retransmissions
  (8 seconds), which ends a handshake a browser would still have completed. A handshake is now
  given up at a deadline: `ConfigBuilder::with_handshake_timeout`, 30 seconds by default, `None`
  for never. `with_maximum_flight_interval` sets what the timer doubles up to.
  `Endpoint::poll_timeout` returns the deadline when it comes before the next retransmission, and
  `handle_timeout` fails the association with `ErrHandshakeTimeout`.
- **dtls**: handshake messages reassemble from fragments that overlap, repeat or arrive in any
  order (RFC 6347 section 4.2.3). Only fragments that each started where the previous one ended
  were joined, so a peer that retransmitted with another fragmentation never completed its
  message. A fragment that disagrees with bytes already placed is left out, and fragments of
  different epochs are never joined.
- **dtls**: no handshake datagram is larger than the configured MTU (RFC 6347 section 4.1.1).
  The message body was cut at the MTU and the record and handshake headers added on top, so
  datagrams reached MTU + 25. When a flight's retransmissions go unanswered its records are cut
  for half the size, down to 228 bytes (section 4.1.1.1).
- **dtls**: a record carries at most 2^14 bytes (RFC 5246 section 6.2.1). `write` refuses a longer
  payload with `ErrRecordOverflow`; above 65535 bytes the record length used to wrap. A received
  record that authenticates and opens to more is answered with a fatal record_overflow; a header
  that announces more than a protected record may hold is discarded.
- **dtls**: junk after the valid records of a datagram no longer costs them (RFC 6347 section
  4.1.2.7): the whole datagram was dropped.
- **dtls**: alerts. A record that fails authentication during a PSK handshake draws bad_record_mac
  (RFC 6347 section 4.1.2.1; it was unknown_psk_identity). An authenticated record of an unknown
  type, or a protected handshake message other than Finished, draws unexpected_message. A
  plaintext handshake message of a type the peer's role never sends is dropped without taking
  the genuine message's place. A fatal alert is sent again, at most seven times, when the peer
  repeats the flight it was about (section 4.2.7).
- **dtls**: a client waiting for the server's first answer no longer ends the handshake over a
  handshake record that delivers nothing (a stray fragment, a discarded message): it sent a fatal
  internal_error, so one spoofed datagram failed the association.
- **dtls**: renegotiation is refused as RFC 5746 section 4.2 and RFC 5246 section 7.2.2 say: a
  HelloRequest (to a client) or a ClientHello in the established epoch (to a server) is answered
  with a protected no_renegotiation warning, and the association goes on. Both were ignored
  silently.
- **dtls**: a replay window below 32 is raised to 32 (RFC 6347 section 4.1.2.6).
- **dtls**: the master secret is overwritten when an association fails or is dropped, and the
  premaster secret once the master secret exists (RFC 5246 sections 7.2.2, 8.1).
- **dtls**: `CipherSuite::record_expansion` reports what a suite adds to a record's payload, so an
  application can size its datagrams (RFC 6347 section 4.1.1.1).

### Cookie exchange and new associations

- **dtls**: a server `Endpoint` performs the cookie exchange without keeping state (RFC 6347
  section 4.2.1). The cookie is an HMAC-SHA-256, under a secret that changes every 60 seconds
  (the previous one still verifies), over the client's address and the ClientHello's version,
  random, session id, cipher suites and compression methods. A ClientHello without a valid
  cookie is answered with a HelloVerifyRequest and forgotten; an association is made only when
  the cookie comes back. It used to make an association per source address at the first
  ClientHello (at most 256 unverified ones), whose replacement left a genuine client's second
  ClientHello unanswerable. The HelloVerifyRequest record carries the ClientHello's record
  sequence number and message_seq, and the first ServerHello record that of the ClientHello with
  the cookie. `ConfigBuilder::with_cookie_exchange(false)` switches the exchange off (section
  4.2.1 allows it; ICE has already shown the client reachable in WebRTC).
- **dtls**: a new association on an address that has one (RFC 6347 section 4.2.8). A ClientHello
  that echoes a cookie, on an address with an established association, starts a new handshake
  beside it. The established association stays in use until the new handshake completes, and is
  then replaced: `EndpointEvent::HandshakeComplete` is reported again. A new handshake that fails
  or times out changes nothing. A failed server association is replaced the same way.

### Testing

- **interceptor**: larger fixed corpora for the fuzz targets' logic (ULPFEC and FlexFEC receive:
  four seeds of 3000 inputs; the inbound interceptor chain: three seeds of 1500 sessions), and
  fixed-corpus invariant tests for the ECN validation and the FEC rate. Writing the latter found
  a panic in `FecRate::fec_packets` with a bound of zero (`clamp(1, 0)`), fixed before release.
- **fec**: a FlexFEC repair SSRC is an RTCP participant between two peer connections: it sends
  sender reports and the connection's CNAME once it has sent, and the receiver learns that CNAME
  for it (`the_receiver_learns_the_cname_of_the_fec_ssrc_from_its_rtcp`). The test fixes the
  amount of FEC (`with_adaptive_rate(false)`): with the loss-driven rate a lossless path's first
  receiver report could stop the repair before the first block closed, so the FEC SSRC never
  sent and never became a participant (about one run in four). It now checks that repair
  packets were sent and waits for both CNAMEs, within ten seconds of virtual time.
- **interceptor (nack)**: the test environment's `nack_recovers_lost_rtp` counts from the
  first packet that arrives, as its virtual-clock twin `nack_recovery_under_loss.rs` does: a
  receiver knows of no packet sent before the first it receives, and a Generic NACK names
  packets missing between ones it saw (RFC 4585 section 6.2.1), so with 5% loss one run in
  twenty lost the stream's first packet and failed although NACK repaired every gap. It still
  prints what stayed lost and fails on any gap after the first packet.
- **rtp**: `a_stream_mixes_header_forms_only_when_extmap_allow_mixed_was_negotiated` takes the
  media stream's SSRC from the sender, not from the first packet on the wire, which with
  bandwidth probing on by default is an RTX padding probe.
- **sctp**: the SCTP association across DTLS changes, between two engines
  (`tests/sctp_across_dtls_associations_rtc2rtc.rs`): a new DTLS association (a changed
  `tls-id`, swapped roles) leaves the association and its channels as they are, and a DTLS
  transport the peer closed closes them, after which the next exchange brings a new
  association on a new port. `tests/sctp_rfc_defaults_rtc2rtc.rs` runs the defaults above
  against a peer with each turned off.
- **ice**: `test_ice_tcp_bidirectional_data_channel` no longer depends on which side's
  messages arrive first: both sides stopped sending once four messages had arrived in total,
  and when three of them had gone one way the test waited for its 30 second timeout.
- **sctp**: two handler tests expected DATA that overtakes the COOKIE ACK to be kept; it is
  discarded (RFC 9260 section 6) and delivered when the peer sends it again.
- **dtls**: known-answer tests against handshakes recorded from OpenSSL 3.5.4 (`openssl s_client`
  against `openssl s_server -dtls1_2 -listen`, five cipher suites): the Finished values, the
  extended master secret, the `EXTRACTOR-dtls_srtp` exporter output and the protected records
  OpenSSL produced are recomputed by this crate from the recorded messages
  (`rtc-dtls/src/conn/openssl_kat_test.rs`). Until now the PRF had vectors and everything above
  it was tested only against this crate itself.

- **conformance**: the clause audits of RFC 8831, RFC 8832, RFC 8841 and RFC 8261 under
  `docs/conformance/audit/`, with the rows this change closes.
`rtc-rtcp` becomes a complete codec for the RTCP packets and blocks of the WebRTC spec set, from the
clause audit of RFC 3550, 4585, 5104, 5506, 3611, 8888, 7941, 8852, 5761 and the transport-cc draft.
Each bug below was confirmed by a failing test first (`rtc-rtcp/tests/audit_bugs.rs`).

- **rtcp**: 117 new tests (wire layout, round trip and malformed input for every packet and block
  type; a fixed set of 60,000 damaged datagrams that must not panic and must keep one wire form) and
  12 new fuzz targets, among them `packet_roundtrip`, a round-trip oracle over whole datagrams.
- **shared**: `is_rtcp` / `match_srtp` / `match_srtcp` are tested over every value of the first two
  octets (RFC 5761 section 4, RFC 7983). The classifier was right and is unchanged.
- Inherited fixtures corrected: RTCP length fields that counted octets instead of words
  (`goodbye_test.rs`, `sender_report_test.rs`, `source_description_test.rs`); two transport-cc
  fixtures whose padding count was larger than their padding; XR fixtures that listed the
  terminating null chunk as a chunk and used VoIP values outside their range; a REMB expectation of
  2^70 for a zero mantissa.
- **rtp (VP8, RFC 7741)**: `Vp8Packet` refused every packet shorter than four octets, among them
  the two and three octet packets `Vp8Payloader` emits for a frame's tail (section 4.2). It kept
  `I`/`L`/`T`/`K`, PictureID, TL0PICIDX, TID, Y and KEYIDX from the previous packet, so an `X=0`
  packet after an `X=1` one lost its first data octets. TID / Y are read only with `T`, KEYIDX
  only with `K`. A frame starts at `S=1` with `PID=0` (section 4.5.1), not at `S=1` alone:
  `SampleBuilder` emitted a frame whose first partition was lost.
- **rtp (VP9, RFC 9628)**: `F` is ignored without `I` (reference indices were read out of the
  frame data); `SID` 5 to 7 are accepted; layer indices and the scalability structure of an
  earlier packet no longer stay in `Vp9Packet`. `Vp9Payloader` changed `F` in the middle of a
  stream when a frame's header did not parse: the mode is now fixed at a key picture. Flexible
  mode sent every frame with `P=0`: `P` follows the frame's header in both modes (an intra-only
  frame is `P=0`, it was `P=1`), and flexible mode carries the reference indices of the slots
  the frame reads. A key frame larger than 65535 pixels a side is announced without
  resolutions instead of switching the stream to flexible mode.
- **rtp (AV1)**: a leb128 value is at most 8 bytes and 32 bits and must end (AV1 4.10.5): an
  unterminated `obu_size` read as 0, 2^32 wrapped to 0, a ninth byte pushed the first out. `W`
  is checked against the number of OBU elements. A packet whose first OBU is a tile group or a
  redundant frame header does not start a temporal unit (`Z=0` alone counted). A packet no
  longer mixes OBUs of different `temporal_id` / `spatial_id` (AV1 RTP section 5); a sequence
  header starts its packet. An OBU that exactly fills a packet is not split. A malformed packet
  drops the OBU being reassembled.
- **VP9 fmtp**: a format without `profile-id` is profile 0 (RFC 9628 section 6); it matched
  every profile. `max-fr` and `max-fs` no longer count in the match.

- **sdp**: the RFC 8866 grammar line type by line type, every typed attribute against its ABNF
  with the examples of its RFC, the Safari and Firefox captures and a Chrome-format offer parsed
  strictly and written back byte for byte, and a deterministic mutation test of the parse and
  marshal fixed point. Fuzzing: `description_roundtrip` checks that fixed point (strict and
  lenient) and reads every typed accessor; new target `attribute_parse`.
- **sctp**: one received packet is answered with one packet of control chunks (RFC 9260
  section 12.4); a packet of HEARTBEATs got a packet per HEARTBEAT ACK. A SACK that is due
  and a FORWARD TSN travel with outbound DATA when the packet has room (sections 6.1, 6.10;
  RFC 3758 section 3.5).
- **sctp**: DATA is received only in ESTABLISHED, SHUTDOWN-PENDING and SHUTDOWN-SENT, and a
  SACK or DATA for an association that has seen no COOKIE ECHO is answered as out of the
  blue (RFC 9260 section 6). DATA was taken in every state.
- **sctp**: RTT measurement follows RFC 9260 section 6.3.1: one per round trip for
  gap-acknowledged chunks too (C4), none with a chunk sent before a retransmission (C5), and
  an RTTVAR of zero becomes the clock granularity (G1).
- **sctp**: the default stream scheduler sends messages in the order they were written (RFC
  8260 section 3.1). Unordered messages used to go ahead of every ordered one, so a steady
  flow of them kept ordered messages, DCEP and stream resets included, from ever leaving. A
  stream reset now waits for the messages of its own stream only.
- **sctp**: an I-DATA or I-FORWARD-TSN chunk on an association that did not negotiate user
  message interleaving is answered with an ABORT, "Protocol Violation" (RFC 8260 sections
  2.2.3, 2.3.1). The packet was dropped whole and unanswered.
- **sctp**: stream resets follow the rest of RFC 6525. One re-configuration request is in
  flight at a time and the others wait (section 5.1.1); closing several data channels put
  several in flight. A request names the peer's last request sequence number (5.1.2), and the
  peer's numbers are checked: a request older than the ones remembered is answered "Error -
  Bad Sequence Number" where it used to be performed again, resetting a stream that had been
  reused (5.2.1). The response and this side's own reset of the stream leave in one chunk,
  with a SACK. Data written to a stream whose reset is not answered yet waits, without a
  Stream Sequence Number, where it used to be sent with the old sequence and held back by the
  peer for good (5.1.2 A1); DATA received beyond the last TSN of a deferred reset is kept for
  the stream as it is after the reset, where it used to be dropped (5.2.2 E2). `Stream::stop`
  and `close` fail when the peer did not announce the extension. An unanswered request now
  counts against the association like an unanswered HEARTBEAT (5.1.1), except after "In
  progress".
- **sctp**: Gap Ack Blocks are offsets in serial number arithmetic (RFC 9260 section 3.3.4).
  Once the received TSNs had wrapped past zero and the cumulative TSN had not, a SACK named a
  TSN the peer never sent, and a peer running this engine closed the association over it.
- **sctp**: the stream counts are negotiated as RFC 9260 section 5.1.1 says: own outbound
  streams against the peer's inbound count, own inbound streams against the peer's outbound
  count. They were paired outbound with outbound, so DATA on a stream the peer was entitled to
  use was thrown away. `open_stream` refuses a stream past the negotiated outbound count.
- **sctp**: a chunk of an unrecognized type is handled by the upper two bits of its type (RFC
  9260 section 3.2: stop or skip, with or without an ERROR "Unrecognized Chunk Type") and an
  unrecognized INIT / INIT ACK parameter by the upper two bits of its (section 3.2.1; reported
  in the INIT ACK, or in an ERROR bundled with the COOKIE ECHO). Either one used to drop the
  whole packet: DATA bundled with a PAD chunk was lost, and a peer whose INIT carried
  Supported Address Types, an address or a Cookie Preservative could not connect. HEARTBEAT
  ACK is parsed. INIT and INIT ACK chunk flags are ignored, and a partial chunk at the end of
  a packet no longer costs the complete chunks before it (section 6.10).
- **sctp**: an established association survives a late copy of the peer's INIT (RFC 9260
  section 5.2.2: it is answered with an INIT ACK and changes nothing) and an INIT or INIT ACK
  that fails its validity checks (sections 3.3.2, 3.3.3: the packet is discarded). Both closed
  the association with a transport error. An INIT in SHUTDOWN-ACK-SENT repeats the SHUTDOWN
  ACK (section 9.2).
- **sctp**: an association that has ended processes nothing more (RFC 9260 sections 3.3.7,
  9.1): chunks after an ABORT in its packet, and later packets, are discarded. A copy of the
  COOKIE ECHO re-established an aborted association and reported `Connected` again. The
  endpoint stops routing to an ended association and gives its place to the next one, so with
  one association allowed (SCTP over DTLS) a peer can connect again.
- **sctp**: an accepting association that never gets a COOKIE ECHO ends after 120 seconds
  (`HandshakeFailed`), and a new INIT from the same peer restarts it. It lasted for ever and
  every later INIT with another Initiate Tag was refused.
- **sctp**: DATA on a stream the peer may not use is acknowledged and answered with ERROR
  "Invalid Stream Identifier" (RFC 9260 section 6.5). It was dropped unrecorded: the
  cumulative TSN could never pass it and the peer retransmitted it for ever.
- **sctp**: at most 32767 TSNs are outstanding at a time, so the ordered messages of a stream
  in flight never span the Stream Sequence Number space (RFC 9260 section 6.1). With small
  messages and a large window the receiver could not tell SSN n from n + 65536 after a loss.
- **sctp**: a SHUTDOWN (or SHUTDOWN ACK) that reaches its retransmission limit ends the
  association with `TimedOut` (RFC 9260 section 9.2); it stayed in SHUTDOWN-SENT with no
  timer running.
- **sctp**: error causes are read and written with their padding (RFC 9260 section 3.3.10),
  so the cause after one of odd length is no longer read from the wrong offset.
- **sctp**: a zero-length write is an error and uses no Stream Sequence Number (RFC 9260
  section 3.3.1). It was accepted, sent nothing, and held back every later ordered message of
  the stream at the receiver.
- **sctp**: any Payload Protocol Identifier is carried unchanged (RFC 9260 section 3.3.1).
  Values other than the five WebRTC ones were received as `Unknown` and sent as 58.
- **sctp**: the Forward-TSN-Supported parameter (RFC 3758 section 3.3) is honoured in an INIT
  as it was in an INIT ACK.

- **sctp**: the association checks the Verification Tag of what it receives (RFC 9260
  sections 8.5, 8.5.1): its own tag, 0 for a lone INIT, and for ABORT and SHUTDOWN COMPLETE
  its own tag or the peer's with the T bit. The T bit was never read, and nothing but the
  endpoint's routing looked at the tag. A packet that carries an ABORT is not answered.
- **sctp**: packets that belong to no association are handled as RFC 9260 section 8.4 says: a
  SHUTDOWN ACK is answered with SHUTDOWN COMPLETE and anything else that calls for it with
  ABORT, the tag reflected and the T bit set; `Endpoint::poll_transmit` returns the answers.
  A SHUTDOWN ACK received while an association is being set up is answered the same way.
- **sctp**: ABORT is sent where RFC 9260 asks for one: an INIT the endpoint cannot accept
  (to its Initiate Tag), an INIT or INIT ACK with invalid values, a Host Name Address, an INIT
  ACK without a State Cookie, a SACK that acknowledges a TSN never sent ("Protocol
  Violation"). These were dropped or closed the association without a word to the peer, and
  a SACK with a Cumulative TSN Ack past the last TSN sent was ignored.
- **sctp**: a State Cookie has a lifetime (`TransportConfig::with_valid_cookie_life`, 60 s):
  echoed later it is refused with "Stale Cookie", and the side that receives that error in
  COOKIE-ECHOED starts over with a new INIT (RFC 9260 sections 5.1.5, 5.2.6). A COOKIE ECHO
  with a cookie that was not sent, or between other ports, has its whole packet discarded;
  the cookie of the association that exists is acknowledged again in every state.
- **sctp**: an INIT that crosses this side's own is answered without touching the TCB, and
  the peer's tag is taken when the cookie comes back (RFC 9260 sections 5.2.1, 5.2.4 B). It
  overwrote the peer's tag, ports, window and stream counts at once.
- **sctp**: the first DATA chunk of an association and DATA bundled with the COOKIE ECHO are
  acknowledged at once (RFC 9260 sections 5.1, 5.1.5).
- **sctp**: shutdown (RFC 9260 section 9.2): DATA received in SHUTDOWN-SENT is answered at
  once with a SACK and the SHUTDOWN again; a packet from the peer restarts the SHUTDOWN
  retransmissions; a SHUTDOWN received in SHUTDOWN-PENDING is taken; T5-shutdown-guard (300
  s) aborts a shutdown that never finishes; SHUTDOWN is retransmitted at most 10 times by
  default (`TimerConfig::max_t2_shutdown_retrans`, it was unlimited).

- **sctp**: an established association whose path is idle sends a HEARTBEAT every RTO +
  HB.interval (30 s, `TransportConfig::with_heartbeat_interval`; RFC 9260 section 8.3). The
  HEARTBEAT ACK measures the round trip, so an idle association no longer keeps a stale RTO,
  and a HEARTBEAT without an answer counts against the peer. None was ever sent.
- **sctp**: the peer is given up after Association.Max.Retrans (10) consecutive T3-rtx
  expiries or unanswered HEARTBEATs (RFC 9260 section 8.1), with `TimedOut`; past
  Path.Max.Retrans (5) the path is reported inactive (`Event::PathInactive`, then
  `Event::PathActive` when it answers again). `TimerConfig::max_t3_rtx_retrans` was unlimited
  by default, so SCTP itself never declared a peer unreachable.

- **sctp**: congestion control follows RFC 9260 section 7.2. The initial cwnd is min(4 x
  PMDCS, max(2 x PMDCS, 4404)) (4344 over IPv6). In slow start a SACK grows cwnd by at most
  one packet, and only when cwnd was in full use (a single SACK could double it); new DATA is
  sent while less than cwnd is outstanding, so the last chunk may cross it (section 6.1 B).
  In congestion avoidance `partial_bytes_acked` counts every SACK, is capped while cwnd is not
  in full use, and starts over when everything is acknowledged. Fast Recovery lasts until all
  that was outstanding at the loss is acknowledged (it ended at the highest TSN newly
  acknowledged, so a second loss in the window cut cwnd again); a Fast Retransmit of the
  first outstanding chunk restarts T3-rtx, and chunks that do not fit its one packet wait
  for the window. An idle cwnd decays, once per RTO, to no less than 4 x PMDCS.
- **sctp**: after a T3-rtx expiry one packet is in flight until it is acknowledged (RFC 9260
  sections 6.3.3, 7.2.3). Retransmissions were bounded by cwnd per call, and each poll sent
  another window's worth: everything outstanding was retransmitted at once.
- **sctp**: a SACK announces the receive window when the application drains a window that
  was advertised as closed (RFC 9260 section 6.2). Reading never sent a SACK, so a sender
  stopped by a_rwnd 0 waited for its next window probe, a retransmission timeout later.
- **sctp**: a DATA chunk dropped for lack of receive window is answered with a SACK at once,
  and a window smaller than a packet is advertised as closed (RFC 9260 section 6.2, silly
  window syndrome avoidance).

- **sctp**: PR-SCTP is announced with the Forward-TSN-Supported parameter (RFC 3758 section
  3.3) in INIT and INIT ACK, beside chunk 192 in Supported Extensions; a peer that reports
  the parameter as unrecognized gets no FORWARD TSN.
- **sctp**: a received FORWARD TSN is applied whatever this side's own setting for the stream
  (RFC 3758 section 3.6). On a stream this side sends ordered, abandoned unordered fragments
  stayed in the receive buffer for the life of the stream; on a stream this side sends
  unordered, the stream sequence numbers were ignored and ordered data stayed held back.
- **sctp**: an ordered message whose lifetime ran out while it waited for the window is not
  sent (RFC 3758 section 4.1); only unordered ones were dropped.
- **sctp**: a FORWARD TSN fits one packet (RFC 3758 section 3.5, C4): with abandoned messages
  on more streams than fit, it covers the TSNs whose streams do and the next one goes on.

- **sctp**: the Outgoing SSN Reset Request sent in answer to a peer's reset is retransmitted
  (RFC 6525 section 5.1.1); lost once, the peer's data channel stayed closing for good. No
  request is given up after five timer expiries any more, and "In progress" answers restart
  its timer without counting (section 5.2.7).
- **sctp**: an Outgoing SSN Reset Request without stream numbers resets every stream (RFC
  6525 section 5.2.2); it reset none and was answered "Success - Performed".
- **sctp**: the re-configuration requests that are not performed (Incoming SSN Reset, SSN/TSN
  Reset, Add Streams) are answered "Denied" (RFC 6525 section 5.2.1) instead of not at all.

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

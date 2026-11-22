# Brainwires fork of webrtc-rs/rtc

This repository is [webrtc-rs/rtc](https://github.com/webrtc-rs/rtc) plus the changes listed
below. It is what ReachMyDevice pins, and what the Deno WebRTC extension (Brainwires/deno
`ext/webrtc`) builds on.

## Sync point

| | |
|---|---|
| Upstream | `webrtc-rs/rtc` `master` |
| Last upstream commit merged | `0fbcaa74` (after v0.21.1, 2026-11-12) |
| Previous sync point (original fork point) | `bf30a00c` (2026-04-06) |
| Fork master before this sync | `81bc7c6b` |
| Fork release | `0.22.0+brainwires.5` (build metadata marks the fork; it is based on upstream 0.21.1 and takes a minor bump for its breaking API changes) |

The fork is kept in sync by **merging** upstream into a branch (never rebasing), so the fork's
history stays intact.

## Standing rules for syncing

1. **Never take an upstream change that removes, deprecates or disables a feature, API, flag or
   platform, or narrows behaviour by default.** If such a commit bundles a fix, port only the fix
   and revert the removal inside the merge resolution. Record it in the table below.
2. Every fork feature is kept unless upstream's version is a strict superset; when one is dropped
   for that reason, say so here.
3. Security fixes are always taken.

## What the fork carries over upstream

### Fork features

| Feature | Where | Notes |
|---|---|---|
| TWCC-driven GCC interceptor with a shared bitrate handle | `rtc-interceptor/src/gcc/twcc_gcc/` | `GccInterceptorBuilder`, `GccHandle`, `GccInterceptor`, `GccShared`. Trendline filter + AIMD (draft-ietf-rmcat-gcc-02). Lives beside upstream's GCC (`Gcc`, `configure_congestion_control`), which is the more complete estimator; the fork's keeps its pull-style `GccHandle` API, which ReachMyDevice uses. Place it in `Slot::CongestionControl`, below `Slot::TwccSender`, around a `PassThroughInterceptor`: `PassThroughInterceptor::new().with(gcc_builder.build())`. |
| Adaptive jitter buffer | `rtc-interceptor/src/adaptive_jitter_buffer/` | Exported as `AdaptiveJitterBufferBuilder` / `AdaptiveJitterBufferInterceptor` (renamed because upstream now owns `JitterBufferBuilder`). Delay adapts to RFC 3550 interarrival jitter and honours the `playout-delay` header extension; upstream's is fixed-depth. |
| `rtc-interceptor-derive` (`#[derive(Interceptor)]`, `#[interceptor]`) and `Interceptor::with` | `rtc-interceptor-derive/`, `rtc-interceptor/src/lib.rs` | Upstream deleted both with the list-based chain. A nested interceptor built with them is an ordinary interceptor and goes in a `Registry` slot around `PassThroughInterceptor` (`PassThroughInterceptor::new().with(builder.build())`), never `NoopInterceptor`: that is the chain's RTCP terminus, and inside a slot it would end every unmarked inbound RTCP packet there, before the interceptors after it and the application. |
| DTLS re-handshake on ICE restart | `src/peer_connection/transport/dtls/mod.rs` (`restart`), `src/peer_connection/mod.rs` | Only when the remote fingerprints or the derived DTLS role change, or the session is Failed/Closed; an ICE restart alone keeps the session (browsers do not re-handshake). Keeps the local certificate; replaces the DTLS endpoint so the next selected pair starts a fresh handshake. |
| RRID (RFC 8852 repaired-rtp-stream-id) association for RTX simulcast | `src/peer_connection/handler/interceptor.rs` (`bind_repair_by_rrid`) | Upstream still has this as TODO #12. |
| Repair codecs never establish a layer | `src/peer_connection/handler/endpoint.rs` (`is_repair_mime_type`) | RTX/FEC payload types are not used as a layer's primary codec. |
| Rejected m-lines reflected in answers (RFC 8829 §5.3.1) | `src/peer_connection/internal.rs`, `src/peer_connection/sdp/mod.rs` | Port 0 in the offer stays port 0 in the answer. |
| `RTCConfiguration` Serialize/Deserialize | `src/peer_connection/configuration/mod.rs` | W3C camelCase; certificates are skipped. |
| PeerConnection close collects every handler's error and closes in reverse order | `src/peer_connection/handler/mod.rs` | On top of upstream's ABORT + close_notify. The fork's per-channel closing procedure and SCTP state release were dropped: upstream aborts the association (W3C `close()`) and derives `SctpTransport.state` from the aborted association. |
| Duplicate negotiated DATA_CHANNEL_OPEN is not fatal | `src/peer_connection/handler/sctp.rs` | Both peers may open the same pre-negotiated stream. |
| RTP marshal bounds checks | `rtc-rtp/src/header/mod.rs`, `codec/h264`, `codec/h265` | CSRC count, one/two-byte extension lengths, total extension length, NALU sizes. |
| `DataChannelMessage::new` | `rtc-datachannel` | |
| TURN client `turn_server_addr()` / `local_addr()` accessors, TCP TURN example | `rtc-turn` | The example now uses upstream's TURN stream framing (RFC 8656 §12.5); the fork's original example used RFC 4571 framing, which TURN does not use. |
| `RTCCertificate::from_key_pair` | `src/peer_connection/certificate/mod.rs` | Kept (upstream removed it); wraps `generate_from_signing_key` with the built-in provider. |
| Inbound key-frame requests reach the application | `rtc-interceptor/src/keyframe.rs` (`KeyFrameRequestInterceptor`, `Slot::KeyFrameRequests`), `src/peer_connection/configuration/interceptor_registry.rs` (`configure_key_frame_requests`, in `register_default_interceptors`) | Upstream's terminus ends every inbound RTCP packet no interceptor vouches for, PLI and FIR included, though only the application (the encoder) can answer them. The fork marks them `DeliverToApplication` by default. |
| ICE over TCP between `rtc` peers in both role assignments | `rtc-ice/src/agent/mod.rs` (`handle_inbound`, `add_remote_candidate`, `find_local_candidate`), `rtc-ice/src/tcp_type` (`complement`) | A peer-reflexive candidate learned over TCP takes the complementary TCP type, so a controlling agent with a passive candidate pairs with (and nominates) the peer that dialled it; exact local address matches win over an active candidate's IP-only match. `tests/ice_tcp_rtc2rtc.rs`. |
| mDNS host candidates per address | `rtc-ice/src/agent/mod.rs` (`mdns_name_for`), `rtc-ice/src/mdns`, `rtc-mdns/src/proto` (`add_local_name`, AAAA) | `QueryAndGather` without a fixed IP publishes each local address (IPv4 and IPv6, UDP and TCP) under its own `<uuid>.local` name, as browsers do; queries ask for A and AAAA. The fixed-IP form also hides that address's TCP candidates. |
| mDNS datagrams reach ICE whatever their first byte | `src/peer_connection/handler/demuxer.rs` | Port 5353 on both ends goes to the agent before RFC 7983 demultiplexing. |
| Bounded RFC 4571 decoding | `rtc-shared/src/tcp_framing.rs` (`TcpFrameDecoder::push`, `try_frame_packet`) | `push` refuses data past two frames' worth; packets are taken without shifting the buffer each time. |
| Data channel ids when the DTLS role is negotiated (W3C webrtc-pc) | `src/peer_connection/mod.rs` (`assign_data_channel_ids`, `create_data_channel`) | Applying an answer (local or remote) gives every in-band channel its RFC 8832 id, and a channel created after that gets one at once, before SCTP connects; the SCTP connected procedure still assigns any left. |
| Data channel closing procedure and failure | `src/peer_connection/handler/{datachannel,sctp}.rs` (`SCTPStreamFailed`), `rtc-sctp/src/association/mod.rs` | A close the remote starts fires `OnClosing` before `OnClose`; an association lost to the peer's ABORT (now `AssociationError::AssociationClosed`, not `Reset`), a protocol error or a timeout fires `OnError` before `OnClose`. |
| `SctpTransport.state` while the association handshakes | `src/peer_connection/transport/sctp/mod.rs` (`association`, `state`) | An association still handshaking is `Connecting` (SCTP's initial state is `CLOSED`, which reported the accepting side `Closed`); an ended association is passed over for a live one. |
| Stats timestamps in milliseconds | `rtc-shared/src/serde.rs` (`instant_to_epoch`) | Epoch milliseconds with sub-millisecond precision (was seconds, truncated to whole milliseconds), as `DOMHighResTimeStamp` and the module's own docs have it. |
| An ICE restart offer carries no previous-generation candidates | `src/peer_connection/internal.rs` (`offered_local_candidates`) | While a restart is staged the offer advertises the new credentials only; the new gathering phase signals its candidates. |
| A data channel's stream id is free only once both directions are reset (RFC 8831 section 6.7) | `src/peer_connection/handler/sctp.rs` (`DataChannelClose`), `rtc-sctp/src/association/mod.rs` (`reset_streams_if_any`) | A local close completes when the peer resets its direction, not when ours is sent; a reset this side started is not echoed back; a reset of a stream with no state here (an idle pre-negotiated channel) is reported and echoed. A new channel no longer takes an id the peer is still resetting. |
| Association failure reaches idle channels | `rtc-sctp` (`Event::AssociationClosed`), `src/peer_connection/handler/{sctp,datachannel}.rs` (`SCTPAssociationFailed`) | Every channel over an association lost to an error fires `OnError`, one without an SCTP stream included. |
| One `a=msid` line per stream (RFC 9429 section 5.2.1) | `src/peer_connection/sdp/mod.rs` (`add_sender_sdp`) | A sender in several MediaStreams (`set_streams`) writes a line for each, in order, without duplicates; a sender in none writes its track's own stream id, which an application sets to `-`. It wrote one line, with the track's stream id, whatever `set_streams` had been given. |
| A transceiver the application made with `addTransceiver` is not taken by a remote offer (RFC 9429 section 5.10) | `src/rtp_transceiver/{mod,internal}.rs` (`set_associable_with_remote_offer`), `src/peer_connection/sdp/mod.rs` (`satisfy_type_and_direction`) | Off by default (every unassociated transceiver of the kind and a fitting direction is a candidate, as before); an application that tells `addTrack` from `addTransceiver` clears the flag for the latter, and a remote offer's new media section then gets a transceiver of its own. |
| A remote `a=inactive` section pauses a transceiver, it does not stop it; an answer states [[Direction]] intersected with the offered direction (RFC 9429 section 5.3.1) | `src/peer_connection/mod.rs` (`set_remote_description`), `src/peer_connection/internal.rs` (`generate_matched_sdp`, `answered_direction`) | Applying a remote offer leaves the transceiver's [[Direction]] alone (W3C 4.4.1.6); the answer intersects it with the reverse of the offered direction, so a sendonly offer is answered recvonly, an inactive one inactive, and a later sendrecv offer sendrecv again. It was stopped, for good, and then a one-way offer rewrote [[Direction]]: a sendonly offer was answered sendrecv (RFC 3264 section 6.1 forbids it) and a return to sendrecv after inactive was answered recvonly. Only a rejected section (port 0) stops one. |
| The selected pair's candidates are always in the stats report | `src/peer_connection/internal.rs` (`update_ice_agent_stats`) | A remote candidate learned from a connectivity check (peer-reflexive) was never registered, so the pair's `remoteCandidateId` named a stats object the report did not have. |
| An ICE restart keeps the previous pair's path until it selects a new one (RFC 8445 section 9) | `rtc-ice/src/agent/mod.rs` (`MediaPath`, `Agent::media_path`, `apply_restart`), `src/peer_connection/handler/ice.rs` | DTLS and SRTP are written to, and accepted from, the path the session had when the restart was applied, on both peers, until the new generation nominates a pair (or the agent fails or closes). The selected pair was dropped at `apply_restart`, so data stopped for as long as the offer/answer exchange took. Kept also when the restart discards the local candidates (`discard_local_candidates_during_ice_restart`): that forgets what was signalled, not the socket. `tests/ice_restart_keeps_path_rtc2rtc.rs`. |
| The controlled ICE agent follows a later nomination (RFC 8445 section 7.3.1.5) and libwebrtc's renomination | `rtc-ice/src/agent/agent_selector.rs` (`ControlledSelector::handle_binding_request`, `Agent::accept_nomination`), `rtc-ice/src/attributes/nomination/` (`NominationAttr`, `nomination_of`) | A USE-CANDIDATE on another succeeded pair moves the selected pair, and the media path with it; a `NOMINATION` (0xC001) value higher than the selected pair's does too, a lower one does not. The first nomination was final, so when Chrome (controlling) moved a session to a pair it found later, this side kept sending on the abandoned pair and dropped the browser's DTLS / SRTP from the new one. A nomination on a pair whose check has not succeeded is answered (it went unanswered) and takes effect when the triggered check succeeds. `tests/ice_controlled_follows_renomination_rtc2rtc.rs`. |
| Bytes a data channel's stream has transmitted | `rtc-sctp/src/association/{mod,stream}.rs` (`bytes_dequeued`, `stream_bytes_dequeued`), `src/data_channel/mod.rs` (`RTCDataChannel::bytes_dequeued`) | Application bytes taken from the send queue (first transmission, or abandoned before it), for W3C `bufferedAmount`, which falls on transmission rather than on acknowledgement (`outstanding_bytes`, the back-pressure count, is unchanged). |
| A data channel's close follows its sends; the last message before a reset is delivered | `src/data_channel/mod.rs` (`close`), `src/peer_connection/handler/{mod,datachannel,sctp}.rs` (`write_data_channel_close`, `drain_stream`) | `close()` enters the pipeline at the endpoint behind the messages already sent, instead of resetting the stream ahead of them; a read that completes a deferred stream reset no longer loses that pass's messages to the closed stream's error. |
| VP9 non-flexible mode with the scalability structure | `rtc-rtp/src/codec/vp9/mod.rs` (`Vp9Payloader::flexible_mode`, `Vp9FrameHeader`) | Pion's behaviour: the payloader reads each frame's uncompressed header, sets `P` from the frame type and sends the SS (frame size) on key frames; Firefox decodes nothing else. A frame that isn't VP9 goes out in flexible mode as before. |
| H.264 / H.265 samples are whole access units | `rtc-media/src/io/h26x_reader/sample_reader.rs` | So a packetizer sets the RTP marker on an access unit's last packet only (RFC 6184 5.1); it was set on every slice and parameter set. |
| Ogg packets by the segment table | `rtc-media/src/io/ogg_reader/mod.rs` (`OggPageHeader::{segment_table, packets, is_continued_packet}`, `OggReader::next_packet`) | The reader dropped the segment table, so a page of several Opus packets could only be sent whole. |
| `SettingEngine` mid generator is used | `src/peer_connection/mod.rs` (`create_offer`) | `with_mid_generator` was stored and never read. `receive_mtu`, `include_loopback_candidate` and `disable_media_engine_copy` have no effect in the sans-I/O engine (it reads no sockets, gathers no candidates and owns its `MediaEngine`), so their builder methods are `#[deprecated]` with the reason. `nat_1to1_ips` and `disable_media_engine_multiple_codecs` are implemented (rows below). |
| Stopped transceivers in offers and answers, m-line recycling (W3C `stop()`, RFC 9429 section 5.2.2) | `src/peer_connection/{mod,internal}.rs` (`create_offer`, `generate_matched_sdp`), `src/peer_connection/sdp/mod.rs` (`MediaSection::stopped`) | A stopped transceiver with no mid gets none and no m= section; an offer rejects a stopped one's section (port 0, `a=inactive`, out of BUNDLE), an answer answers it inactive; an offer reuses a rejected section for a transceiver that has none yet; a rejected section of a remote offer or answer stops the transceiver it has (W3C 4.4.1.6); once an answer is applied, a stopped transceiver whose section is rejected is removed from the set of transceivers (`take_removed_transceivers` reports the ids, which a removal shifts). |
| A remote offer's transceiver can get a sender | `src/peer_connection/mod.rs` (`add_track_to_transceiver`, `ensure_transceiver_sender`), `src/rtp_transceiver/mod.rs` (`keep_on_rollback`) | For W3C `addTrack` reusing such a transceiver, and direction + `replaceTrack`. A rollback removes a transceiver the rolled-back offer created unless `addTrack` touched it (RFC 9429 section 5.7). |
| Remote m= sections without `a=mid` (RFC 9429 sections 5.10, 5.11) | `src/peer_connection/mod.rs` | Take the mid of our section at the same position (answer) or their index (offer), instead of failing the description. |
| `a=rid` takes each simulcast layer's first alternative, once | `src/peer_connection/sdp/mod.rs` (`get_rids`) | W3C webrtc-pc "set the RTCSessionDescription", RFC 8853 section 5.2: alternatives and duplicate rids are not answered as layers. |
| Static audio payload types without `a=rtpmap`; undefined dynamic ones skipped | `src/peer_connection/sdp/mod.rs` (`codecs_from_media_description`) | RFC 3551's static audio types are read; an undefined dynamic payload type is left out instead of failing the description (RFC 9429 sections 5.3.1, 5.8). |
| Unknown media types | `rtc-sdp/src/description/session.rs`, `src/peer_connection/internal.rs` (`generate_matched_sdp`), `src/peer_connection/sdp/mod.rs` (`MediaSection::rejected_name`, `unknown_media_name`) | `<media>` is any RFC 8866 token; a section of an unknown type is answered, and kept in later offers, rejected with its media type, protocol and formats (RFC 9429 sections 5.3.1, 5.2.2). |
| Codec preferences keep only the repair formats they list | `src/rtp_transceiver/rtp_receiver/internal.rs` (`get_codecs`), `src/rtp_transceiver/rtp_sender/rtp_codec.rs` (`repair_family`), `src/peer_connection/sdp/mod.rs` (`add_sender_sdp`) | W3C `setCodecPreferences` can remove RTX, ULPFEC and FlexFEC; RTX / FEC SSRC groups are written only when the section has the format. |
| The default AV1 codec's fmtp is `profile=0` | `src/peer_connection/configuration/media_engine.rs` | The AV1 RTP payload format's parameter is `profile`; it said VP9's `profile-id`. |
| Per-transceiver header extensions to negotiate (webrtc-extensions RTP header extension control) | `src/rtp_transceiver/{mod,internal}.rs` (`set_header_extensions_to_negotiate`), `src/peer_connection/sdp/mod.rs` | Limits a section's `a=extmap` lines to the listed URIs; `None` (the default) is every extension the media engine negotiates. |
| An `a=extmap` whose name isn't a URI is skipped | `src/peer_connection/sdp/mod.rs` (`rtp_extensions_from_media_description`) | It failed the description; RFC 8285 section 5 leaves an unsupported extension out of the answer. A malformed id or direction still fails. |
| Cryptex (RFC 9335) and `RTCRtpHeaderEncryptionPolicy` | `rtc-srtp/src/cryptex.rs`, `rtc-srtp/src/cipher`, `rtc-srtp/src/context` (`set_cryptex`), `src/peer_connection/cryptex.rs` (`set_rtp_header_encryption_policy`, `add_cryptex_attribute`), `src/peer_connection/handler/srtp.rs` | CSRCs and header extensions are encrypted with the payload once both descriptions carry `a=cryptex`; `Require` refuses packets without it. `Disable` stays the default. |
| `alwaysNegotiateDataChannels` (webrtc-extensions) | `src/peer_connection/always_negotiate.rs` | With `set_always_negotiate_data_channels(true)` every offer carries the `m=application` section (first in an initial offer). Off by default. |
| `tlsVersion` is the ServerHello version in hex | `src/statistics/stats/transport.rs` | `"FEFD"` for DTLS 1.2, as webrtc-stats defines it; it said `"DTLS 1.2"`. |
| Data channel priority in the DCEP OPEN (W3C WebRTC Priority Control) | `src/data_channel/{init,internal,mod}.rs` (`RTCDataChannelInit::priority`, `RTCDataChannel::priority`), `src/peer_connection/handler/datachannel.rs` | `dial()` sends the channel's priority (default 256) and an accepted channel keeps the peer's (RFC 8832 section 5.1); every channel sent 256 and an accepted one dropped the value. |
| An exhausted partially reliable loss is abandoned in Fast Recovery | `rtc-sctp/src/association/mod.rs` | Its miss indications count from every SACK in Fast Recovery, so it reaches fast retransmit and FORWARD TSN (RFC 3758 section 3.5) instead of waiting for T3-rtx. Reliable DATA keeps RFC 4960's HTNA rule. |
| An empty data channel message counts as 0 bytes received | `src/peer_connection/handler/datachannel.rs` | RFC 8831 section 6.6's padding byte is not counted, so `bytesReceived` matches the peer's `bytesSent`. |
| Remote candidate scopes and an address filter | `rtc-ice/src/agent/remote_policy.rs` (`RemotePolicy`, `RemoteAddressFilter`), `AgentConfig::{allow_loopback_remote_candidates, allow_link_local_remote_candidates, remote_address_filter}`, `SettingEngineBuilder::{with_remote_candidate_scopes, with_remote_address_filter}` | A remote candidate that is never a unicast destination (unspecified, multicast, broadcast, port 0) is dropped; checks go to a loopback or link-local remote address only from a local candidate of the same scope unless allowed; an application filter can refuse any remote address (RFC 8445 section 5.1.1.1). |
| `nat_1to1_ips` applies to the host candidates the application adds | `rtc-ice/src/external_ip_mapper/`, `Agent::apply_nat_1to1`, `RTCPeerConnection::add_local_candidate` | `Host` announces the external address (base kept); `Srflx` adds a server-reflexive candidate; an invalid configuration fails construction (pion's `external_ip_mapper`). It was stored and never read. |
| Each media section negotiates its own codecs | `src/peer_connection/configuration/media_engine.rs` (`merge_negotiated_codecs`, `update_from_remote_description`) | One entry per format and one format per payload type (RFC 9429 section 5.10, RFC 8843 section 7.5); `with_disable_media_engine_multiple_codecs(true)` restores one shared codec set. |
| Data channel messages up to the advertised `max-message-size` | `rtc-sctp` (`TransportConfig::with_max_receive_message_size`), `src/peer_connection/transport/sctp/mod.rs` (`start`), `src/peer_connection/handler/sctp.rs` (`drain_stream`) | The receive limit is what this side advertises (RFC 8841 section 6.1), not the negotiated minimum; an oversized inbound message is dropped alone instead of ending the read. The INIT goes to the remote `a=sctp-port` (`TransportConfig::with_remote_sctp_port`). |
| Statistics feeds for what the engine cannot measure | `src/statistics/feed.rs` (`RTCPeerConnection::update_{decoder,audio_receiver,encoder,audio_source,video_source,audio_playout}_stats`), `src/statistics/stats/` | Encoder, decoder, capture and playout members are `None`, and left out of the JSON, until the application supplies them; updates merge. Members the engine never measures are absent rather than 0, and every id in a report resolves (webrtc-stats). |
| A renegotiated codec re-binds a sender's streams | `src/rtp_transceiver/rtp_sender/internal.rs` (`rebind_local_streams`, `local_stream_infos`), `src/peer_connection/internal.rs` (`start_rtp_senders`), `rtc-interceptor/src/report/sender.rs` | A negotiation that changes the codec an encoding is sent with (or its RTX / FEC flow or header extensions) unbinds and re-binds its streams with the same SSRCs; the sender report keeps its counts and sends no BYE over it; the NACK responder's buffer and the TWCC send side restart. Bound streams name no RTX / FEC SSRC without the repair payload type. |
| Remote-outbound round trip time over RTCP XR | `rtc-interceptor/src/report/{receiver,sender}.rs` (`RTCP_FB_RRTR`), `src/statistics/accumulator/{rtcp_reports.rs,rtp_stream/inbound.rs}`, `src/peer_connection/configuration/interceptor_registry.rs` (`configure_receiver_reference_time`) | A stream that negotiated `a=rtcp-fb:<pt> rrtr` (libwebrtc's name) gets an XR receiver reference time block with each receiver report (RFC 3611 section 4.4); the sender answers every one with a DLRR block (section 4.5), as libwebrtc does; the receiver's remote-outbound stats report `roundTripTime`, `totalRoundTripTime`, `roundTripTimeMeasurements`. |
| ECN / L4S on RTP media and the ECN / RFC 8888 statistics | `rtc-shared/src/transport.rs` (`TransportContext::ecn`), `SettingEngineBuilder::with_ecn`, `src/peer_connection/handler/{ice,interceptor}.rs`, `rtc-interceptor/src/rfc8888/sender.rs`, `src/statistics/accumulator/{ccfb,rtcp_reports}.rs`, `configure_congestion_control_feedback` | The sans-I/O engine takes each received datagram's ECN codepoint in `TransportContext::ecn` and names the one to set on each datagram it sends. With `with_ecn(true)`, RTP media (RTX included) of a stream that negotiated `a=rtcp-fb:<pt> ack ccfb` (RFC 8888) is sent ECT(1), the L4S identifier; nothing else is marked. RFC 8888 reports carry each packet's codepoint. Stats: inbound `packetsReceivedWithEct1` / `packetsReceivedWithCe` / `packetsReportedAsLost` / `packetsReportedAsLostButRecovered`, outbound `packetsSentWithEct1`, remote-inbound `packetsReceivedWithEct1` / `packetsReceivedWithCe` / `packetsReportedAsLost` / `packetsReportedAsLostButRecovered` / `packetsWithBleachedEct1Marking`. Opt-in: off by default, TWCC stays the default feedback and the default SDP is unchanged. `tests/ecn_l4s_rtc2rtc.rs`. |
| A NACK retransmission without RTX keeps its transport-wide number | `rtc-interceptor/src/twcc/sender.rs` (`LocalStream::numbers`, `REMEMBERED`) | A packet whose RTP sequence number is among the last 1024 its stream numbered is that packet again (the NACK responder's no-RTX path) and keeps its transport-wide sequence number, so it is the same bytes and SRTP protects it again; upstream renumbers it and SRTP refuses it as an index reuse. An RTX retransmission is numbered as a new packet. |
| STUN as RFC 8489 has it, and a receive path that shows only authenticated attributes | `rtc-stun/src/{validated,long_term,nonce_cookie,password_algorithm,userhash,opaque,alternate,integrity,client}.rs` | `rtc_stun::validated` (`Validator`, `ValidatedMessage`): FINGERPRINT, MESSAGE-INTEGRITY(-SHA256) and unknown comprehension-required attributes checked in one place, and only the attributes ahead of the integrity attribute readable afterwards. MESSAGE-INTEGRITY-SHA256, USERHASH, PASSWORD-ALGORITHM(S), ALTERNATE-DOMAIN, OpaqueString (`precis-profiles`), the nonce cookie and bid-down protection (`LongTermCredentials`), 300 (Try Alternate) data with the loop rule, and the retransmission timer of section 6.2 in `Client` (doubling RTO, Rc, Rm, Ti, RFC 6298 estimate, ten outstanding transactions, path MTU). Upstream follows RFC 5389, reads attributes wherever they sit, and its client truncates responses over 120 bytes and backs off linearly. |
| CI: benchmarks, fuzzing, OSS-Fuzz, git-cliff release notes | `.github/workflows/{bench,fuzz,release}.yml`, `oss-fuzz/`, `cliff.toml` | |

### Hardening (fork only)

Peer-input hardening upstream does not have: bounded DTLS fragment reassembly, early-record queue
and handshake cache; AEAD-only default DTLS suites; ChangeCipherSpec honoured only for the
handshake's one epoch transition; SRTP state only after authentication, and SRTCP authenticated
whatever its E flag; ICE source filtering, authenticated role conflicts and consent (role
attributes, PRIORITY and nominations are read only from what MESSAGE-INTEGRITY covers; a 487
is obeyed only when signed and matched to a pending check; consent expires after 30 seconds
whatever the timeouts, also on the path an ICE restart leaves in use), candidate
caps (mDNS-resolved ones included), mDNS answers only from the mDNS socket, at most 64 published
mDNS names (a host candidate past them is dropped, not sent with its address); bounded RFC 4571
frame decoding; bounded SCTP
FORWARD-TSN/SACK/receive window and stream-id checks; DCEP stream-id parity and internal message
types refused from the wire; TURN client server-address filtering and response MESSAGE-INTEGRITY
checks; errors instead of panics on malformed DTLS/SCTP/DCEP/ICE/SDP/RTCP input; NACK
retransmission de-duplication and rate limit; bounded H.264 FU-A and AV1 reassembly, AV1 OBU
checks, VP9 per-picture state; RTP extension blocks consumed whole; SLI on PT 206; bounded IVF and
H.265 writer buffers; sha-256 fingerprint selection; fuzzing CI fixes and stateful SCTP targets.
See CHANGELOG.md.

Left as the RFCs require: the TURN client accepts 401 (Unauthorized) and 438 (Stale Nonce) error
responses without MESSAGE-INTEGRITY (RFC 8489 §9.2.4; a server cannot sign a reply about the
credential or nonce it would sign with). So a forged 438 can still end the request it answers
with a stale-nonce error and replace the allocation's nonce; the server's own 438 on the next
request restores it. Only a sender that passes the server-address filter can do this, and it
cannot release the allocation or forge any other response.

### Dependency audit (fork only)

`.github/workflows/audit.yml` resolves dependencies afresh and runs `cargo deny check advisories`
on every PR: first on the library's own graph with `.github/deny-library.toml` (normal and build
dependencies, all features, no ignores), then on the whole workspace with `deny.toml`. Ignores are
allowed only in `deny.toml`, only for advisories that cannot reach the library, each with its
reason. Today there are two:

| Advisory | Crate | Why it is ignored |
| --- | --- | --- |
| RUSTSEC-2026-0441 (unmaintained, no vulnerability) | `pin-utils` 0.1.1 | Dev-dependency only, interop tests: `webrtc` 0.17.3 -> `webrtc-util` -> `nix` 0.26. `webrtc` 0.17.3 is the last release of the independent implementation the interop tests exercise; 0.20+ is built on the upstream `rtc` crates. |
| RUSTSEC-2026-0543 (unmaintained, no vulnerability) | `chrono` 0.4 | Dev-dependency only: the examples' and tests' log timestamps (`chrono::Local::now()`). No release fixes it; replacing it in 48 example and test files is not worth a dev-only timestamp. |

### Defaults the fork widens

- `register_default_interceptors` includes `KeyFrameRequestInterceptor`: an application on the
  defaults now receives the compound RTCP packets that carry a PLI or FIR as
  `RTCMessage::RtcpPacket` (upstream delivers no RTCP by default). Build the chain without it to
  keep upstream's behaviour.
- `register_default_interceptors` registers `configure_receiver_reference_time`: the default
  SDP offers `a=rtcp-fb:<pt> rrtr` on video, and a video stream's receiver sends RTCP XR
  receiver reference time blocks. Register the interceptors one by one without it to keep
  upstream's SDP.
- `MulticastDnsMode::QueryAndGather` without `multicast_dns_local_ip` hides every host candidate
  (upstream's points one name at 127.0.0.1 and hides none).

### Defaults the fork narrows on purpose

- DTLS: the default WebRTC cipher suites are AEAD only (AES-128-GCM, ChaCha20-Poly1305); the
  AES-256-CBC-SHA suites are opt-in. This is the one deliberate exception to rule 1, decided by
  the maintainer for security. To offer CBC again, list the suites with
  `SettingEngineBuilder::with_dtls_cipher_suites` (for example
  `CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha`).
- Codecs: `register_default_codecs` no longer offers ULPFEC (`video/ulpfec`, PT 116). Nothing
  in the engine encodes or decodes RFC 5109 FEC (and RED, which carries it from browsers, was
  never offered), so offering it invited repair packets that were dropped: a claim the engine
  did not keep. This takes upstream's `4d0c5070` (#837), which the fork had reverted under
  rule 1; the maintainer decided the exception. An application with its own coder registers
  `MIME_TYPE_ULP_FEC` itself. RED + ULPFEC receive is planned work, not a default.

### Upstream API replacements taken

Removed upstream APIs with a replacement that covers them are taken as breaking changes, without
shims: `CryptoPrivateKeyKind`, `KeyingMaterialExporter`, `extract_session_keys_from_dtls`,
`MessageIntegrity::default`, `FnTimeGen`, the old `Packet` message type and the
`SettingEngine::set_*` setters. CHANGELOG.md lists the new API for each.

### Upstream changes not taken (reverted inside the merge)

| Upstream commit | What it removed or narrowed | What the fork does instead |
|---|---|---|
| `14d89bb2` interceptor redesign | Deleted `rtc-interceptor-derive` and `Interceptor::with` | Takes the redesign, keeps the crate and `with` (see above). |
| `8080cef3` | `write_rtp` stopped rewriting an un-negotiated payload type to the encoding's codec | The fuzzy-match fallback stays; only a packet with no matching codec at all is an error. |
| `1f1b0874` (#123) | `write_rtp` errors on header extension ids not negotiated on the sender | They are passed through (with a trace log), as before. |
| `702ffbc0` | `RTCConfiguration::validate` rejects a Relay policy without a TURN URL | Warns instead; an application may add its own relay candidates. |
| `fd81f68f` (crypto P4) | Removed the `openssl` / `vendored-openssl` features (rtc, rtc-srtp) | Features kept: the AES-CM SRTP keystream comes from OpenSSL when enabled (`rtc-crypto/src/openssl_ctr.rs`, reached through `rtc-srtp`'s `openssl` feature so `rtc-crypto` stays the only crate naming a crypto implementation). |
| crypto P5/P6 | Removed the `pem` feature name (rtc, rtc-dtls) | Kept as a no-op feature (PEM is always built now), so dependents that enable it still build. |

### Fork features dropped because upstream's is a strict superset

| Fork change | Upstream replacement |
|---|---|
| `check_partial_reliability_status` `>=` → `>` fix (PR-SCTP max_retransmits) | Upstream's message-based reliability (`retransmission_policy_exhausted`, #242) uses `nsent > max_retransmits` and also defers abandonment to retransmission. |
| DTLS `CryptoPrivateKey` private fields + panic-free `Clone` | Upstream's provider-neutral `SigningKey` (no DER re-parse, no panic). |
| `HandshakeConfig::default()` placeholder verifier | Upstream has no `Default`; the verifier is an `Option` built by `ConfigBuilder`. |
| Negotiated data channels (#61) and `set_direction` renegotiation (#51) | Upstream #101 and #102 implement the same behaviour; the fork's integration tests are kept. |
| RTX/FEC SSRC routing to the primary track | Upstream de-encapsulates RTX onto the primary (#120) and binds declared repair SSRCs (#197); the fork's RRID part is kept. |
| `total_lost` clamp | Merged cleanly with upstream; the fork's clamp to the signed 24-bit maximum stays. |

## How to sync with upstream

```sh
git clone https://github.com/Brainwires/webrtc-rs-rtc.git && cd webrtc-rs-rtc
git remote add upstream https://github.com/webrtc-rs/rtc.git
git fetch upstream
git switch -c sync/upstream-<version> master
git log --oneline "$(git merge-base master upstream/master)"..upstream/master   # audit these
git merge --no-ff upstream/master
```

1. Audit every new upstream commit against the standing rules above, before resolving. For
   each removal or narrowed default, plan how the resolution keeps the old behaviour.
2. Resolve the conflicts. Keep fork features, port bundled fixes from commits you leave out, and
   add a row to the tables above for each.
3. Build and test with the pinned toolchain:
   `RUSTUP_TOOLCHAIN=1.92.0 cargo build --workspace && cargo test --workspace --no-fail-fast`.
4. Update the sync point at the top of this file, then open a PR into `master`.

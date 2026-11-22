use super::*;
use crate::peer_connection::configuration::remote_bitrate_limit::RemoteBitrateLimit;
use crate::peer_connection::configuration::{RTCBundlePolicy, RTCRtcpMuxPolicy};
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCPeerConnectionIceEvent};
use crate::peer_connection::handler::datachannel::DataChannelHandlerContext;
use crate::peer_connection::handler::demuxer::DemuxerHandlerContext;
use crate::peer_connection::handler::endpoint::EndpointHandlerContext;
use crate::peer_connection::handler::interceptor::InterceptorHandlerContext;
use crate::peer_connection::handler::srtp::SrtpHandlerContext;
use crate::peer_connection::sdp::answered_extension_directions;
use crate::peer_connection::sdp::has_bundle_attribute;
use crate::peer_connection::sdp::section_multiplexes_rtcp;
use crate::peer_connection::sdp::{
    ATTR_KEY_RTCP_MUX_ONLY, BundleMode, MediaSection, PopulateSdpParams,
    add_candidates_to_media_descriptions, bundle_group_mids, effective_direction,
    get_application_media, get_application_media_section_sctp_port, get_by_mid, get_peer_direction,
    get_rids, have_data_channel, is_ext_map_allow_mixed_set, is_rejected_media, is_rtp_profile,
    is_unknown_application_media, rtp_extensions_from_media_description, superseded_clear_extensions,
    track_details_from_sdp,
    unknown_media_name,
};
use crate::peer_connection::state::signaling_state::check_next_signaling_state;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::ice::candidate::RTCIceServerTransportProtocol;
use crate::peer_connection::transport::ice::candidate::{
    RTCIceCandidate, rtc_ice_candidates_from_ice_candidates,
};
use crate::peer_connection::transport::ice::candidate_type::RTCIceCandidateType;
use crate::peer_connection::transport::{RTCTransportId, TransportKind};
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::RTCRtpCodec;
use crate::rtp_transceiver::rtp_sender::negotiates_ccfb;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    encoding_send_codec, is_repair_codec, is_rtx_mime_type, parse_rtx_apt, parse_rtx_time,
};
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::{
    RTCRtpCodingParameters, RTCRtpFecParameters, RTCRtpRtxParameters,
};
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::{
    PayloadType, RTCRemoteBandwidth, RTCRtpTransceiverDirection, RTCRtpTransceiverId,
};
use crate::statistics::accumulator::{
    IceCandidateAccumulator, local_candidate_stats_id, remote_candidate_stats_id,
};
use ::sdp::description::common::Attribute;
use ::sdp::description::media::MediaDescription;
use ::sdp::description::session::*;
use ::sdp::util::ConnectionRole;
use rand::RngExt;
use std::collections::HashSet;
use std::collections::VecDeque;

/// What the last completed offer/answer exchange negotiated, remembered when an offer is
/// applied in the stable state and brought back by a rollback (W3C webrtc-pc "set a session
/// description": the `[[LastStableState...]]` slots; RFC 9429 section 5.7).
#[derive(Clone)]
pub(super) struct LastStableState {
    /// The negotiated codecs and header extensions (a remote offer replaces them).
    media_engine: MediaEngine,
    /// The transceivers as they were: their codecs and their senders' repair flows are what a
    /// rollback restores.
    rtp_transceivers: Vec<RTCRtpTransceiverInternal>,
    can_trickle_ice_candidates: Option<bool>,
    transport_closed: bool,
}

/// See [`RTCPeerConnection::description_snapshot`].
pub(super) struct DescriptionSnapshot {
    signaling_state: RTCSignalingState,
    current_local_description: Option<RTCSessionDescription>,
    pending_local_description: Option<RTCSessionDescription>,
    current_remote_description: Option<RTCSessionDescription>,
    pending_remote_description: Option<RTCSessionDescription>,
    media_engine: MediaEngine,
    rtp_transceivers: Vec<RTCRtpTransceiverInternal>,
    removed_transceivers: usize,
    can_trickle_ice_candidates: Option<bool>,
    trickled_remote_candidates: usize,
    last_offer: String,
    last_answer: String,
    transport_closed: bool,
    negotiation_needed_state: NegotiationNeededState,
    is_negotiation_ongoing: bool,
    last_stable_state: Option<LastStableState>,
    events: usize,
}

impl RTCPeerConnection {
    pub(super) fn new(
        now: Instant,
        mut configuration: RTCConfiguration,
        mut media_engine: MediaEngine,
        mut setting_engine: SettingEngine,
        interceptor: Box<dyn Interceptor>,
    ) -> Result<Self> {
        configuration.validate()?;

        // Each media section negotiates its own codecs unless the application asked for one
        // codec set (RFC 9429 section 5.10 answers every m= section from its own formats).
        media_engine
            .set_multi_codec_negotiation(!setting_engine.disable_media_engine_multiple_codecs);

        // The one place in `rtc` that resolves a default crypto provider. The application
        // either supplies one through `SettingEngineBuilder::with_crypto_provider` — which is also how
        // a wrapper crate injects a provider it resolved itself — or gets the feature-selected
        // built-in here, once, at construction. Everything downstream —
        // ICE, DTLS, SRTP, STUN, certificates — receives it explicitly, so no library code
        // reaches for a default behind the caller's back.
        let crypto_provider = match setting_engine.crypto_provider.take() {
            Some(crypto_provider) => crypto_provider,
            None => crypto::default_provider().map_err(|error| {
                Error::Crypto(format!(
                    "peer connection requires a crypto provider: {error}; configure one with SettingEngineBuilder::with_crypto_provider"
                ))
            })?,
        };
        // Record the resolution so `SettingEngine::crypto_provider` reports the provider this
        // connection actually uses, not merely what was requested.
        setting_engine.crypto_provider = Some(crypto_provider.clone());

        let mut candidate_types = vec![];
        if setting_engine.candidates.ice_lite {
            candidate_types.push(ice::candidate::CandidateType::Host);
        } else if configuration.ice_transport_policy == RTCIceTransportPolicy::Relay {
            candidate_types.push(ice::candidate::CandidateType::Relay);
        }

        let mut validated_servers = vec![];
        if !configuration.ice_servers.is_empty() {
            for server in &configuration.ice_servers {
                let url = server.urls()?;
                validated_servers.extend(url);
            }
        }

        let network_types = if setting_engine.candidates.ice_network_types.is_empty() {
            ice::network_type::supported_network_types()
        } else {
            setting_engine.candidates.ice_network_types.clone()
        };

        let agent_config = AgentConfig {
            lite: setting_engine.candidates.ice_lite,
            urls: validated_servers,
            disconnected_timeout: setting_engine.timeout.ice_disconnected_timeout,
            failed_timeout: setting_engine.timeout.ice_failed_timeout,
            keepalive_interval: setting_engine.timeout.ice_keepalive_interval,
            candidate_types,
            network_types,
            check_interval: setting_engine
                .timeout
                .ice_check_interval
                .unwrap_or(std::time::Duration::from_millis(0)),
            max_binding_requests: setting_engine.timeout.ice_max_binding_requests,
            host_acceptance_min_wait: setting_engine.timeout.ice_host_acceptance_min_wait,
            srflx_acceptance_min_wait: setting_engine.timeout.ice_srflx_acceptance_min_wait,
            prflx_acceptance_min_wait: setting_engine.timeout.ice_prflx_acceptance_min_wait,
            relay_acceptance_min_wait: setting_engine.timeout.ice_relay_acceptance_min_wait,
            multicast_dns_mode: setting_engine.multicast_dns.mode,
            multicast_dns_local_name: setting_engine.multicast_dns.local_name.clone(),
            multicast_dns_local_ip: setting_engine.multicast_dns.local_ip,
            multicast_dns_query_timeout: setting_engine.multicast_dns.timeout,
            multicast_dns_first_query_delay: setting_engine.multicast_dns.first_query_delay,
            multicast_dns_destination_reported: setting_engine.multicast_dns.destination_reported,
            multicast_dns_unicast_response: setting_engine.multicast_dns.unicast_response,
            multicast_dns_rate_limit: setting_engine.multicast_dns.rate_limit.clone(),
            local_ufrag: setting_engine.candidates.username_fragment.clone(),
            local_pwd: setting_engine.candidates.password.clone(),
            allow_loopback_remote_candidates: setting_engine
                .candidates
                .allow_loopback_remote_candidates,
            allow_link_local_remote_candidates: setting_engine
                .candidates
                .allow_link_local_remote_candidates,
            remote_address_filter: setting_engine.candidates.remote_address_filter.clone(),
            tie_breaker: setting_engine.ice.tie_breaker,
            nomination_acceptance: setting_engine.ice.nomination_acceptance,
            nominate_on_consent_checks: setting_engine.ice.nominate_on_consent_checks,
            unauthenticated_requests: setting_engine.ice.unauthenticated_requests,
            data_from_selected_pair_only: setting_engine.ice.data_from_selected_pair_only,
            send_data_before_nomination: setting_engine.ice.send_data_before_nomination,
            nat_1to1_ips: setting_engine.candidates.nat_1to1_ips.clone(),
            nat_1to1_ip_candidate_type: match setting_engine.candidates.nat_1to1_ip_candidate_type {
                RTCIceCandidateType::Srflx => ice::candidate::CandidateType::ServerReflexive,
                RTCIceCandidateType::Prflx => ice::candidate::CandidateType::PeerReflexive,
                RTCIceCandidateType::Relay => ice::candidate::CandidateType::Relay,
                RTCIceCandidateType::Host => ice::candidate::CandidateType::Host,
                _ => ice::candidate::CandidateType::Unspecified,
            },

            ..Default::default()
        };

        // One random nonce per peer connection, combined with a per-transport discriminator to
        // form the three `RTCTransportId`s. Drawn here rather than from a process-wide counter:
        // a counter is ambient state, and `rtc` may be used many times over in one process.
        // Randomness is what keeps two connections' transports from comparing equal — see
        // `RTCTransportId`.
        let transport_id_nonce: u64 = rand::rng().random();
        let ice_transport_id = RTCTransportId::new(transport_id_nonce, TransportKind::Ice);
        let dtls_transport_id = RTCTransportId::new(transport_id_nonce, TransportKind::Dtls);
        let sctp_transport_id = RTCTransportId::new(transport_id_nonce, TransportKind::Sctp);

        // Create the ICE transport
        let ice_transport =
            IceTransport::new(now, agent_config, crypto_provider.clone(), ice_transport_id)?;

        // Create the DTLS transport
        let certificates = std::mem::take(&mut configuration.certificates);
        let dtls_transport = DtlsTransport::new(RTCDtlsTransportConfig {
            id: dtls_transport_id,
            ice_transport_id,
            certificates,
            answering_dtls_role: setting_engine.answering_dtls_role,
            srtp_protection_profiles: setting_engine.srtp_protection_profiles.clone(),
            use_srtp_always: setting_engine.dtls_use_srtp_on_every_association,
            dtls_cipher_suites: setting_engine.dtls_cipher_suites.clone(),
            allow_insecure_verification_algorithm: setting_engine
                .allow_insecure_verification_algorithm,
            disable_certificate_fingerprint_verification: setting_engine
                .disable_certificate_fingerprint_verification,
            replay_protection: setting_engine.replay_protection,
            crypto_provider: crypto_provider.clone(),
        })?;

        // Create the SCTP transport. The RFC behaviour is the default for each of these: the
        // weighted fair queueing scheduler (RFC 8831 section 6.4), message interleaving
        // (sections 6.1 and 6.6), the zero checksum over DTLS (RFC 9653) and State Cookies
        // with a MAC (RFC 9260 section 5.1.3).
        let sctp_transport = SctpTransport::new(
            setting_engine.sctp_max_message_size,
            setting_engine.sctp_max_receive_buffer_size,
            setting_engine.sctp_mtu,
            sctp_transport_id,
            dtls_transport_id,
        )
        .with_weighted_fair_queueing(setting_engine.sctp_weighted_fair_queueing.unwrap_or(true))
        .with_message_interleaving(setting_engine.sctp_message_interleaving.unwrap_or(true))
        .with_zero_checksum(setting_engine.sctp_zero_checksum.unwrap_or(true))
        .with_message_size_limit_without_interleaving(
            setting_engine
                .sctp_message_size_limit_without_interleaving
                .unwrap_or(true),
        )
        .with_cookie_provider(crypto_provider);

        // Create Pipeline Context
        let ice_handler_context = IceHandlerContext::new(ice_transport);
        let dtls_handler_context = DtlsHandlerContext::new(dtls_transport);
        let sctp_handler_context = SctpHandlerContext::new(now, sctp_transport);

        // Listed in full rather than filled from `Default`: the ICE and DTLS handler contexts
        // own a crypto provider, and deriving `Default` for them would mean resolving one
        // implicitly. The provider is chosen once above and threaded from here.
        let pipeline_context = PipelineContext {
            demuxer_handler_context: DemuxerHandlerContext {
                mdns_legacy_unicast: setting_engine.multicast_dns.mode
                    == ice::mdns::MulticastDnsMode::QueryAndGather,
                ..Default::default()
            },
            ice_handler_context,
            dtls_handler_context,
            sctp_handler_context,
            datachannel_handler_context: DataChannelHandlerContext::new(now),
            srtp_handler_context: SrtpHandlerContext::default(),
            interceptor_handler_context: InterceptorHandlerContext::default(),
            endpoint_handler_context: EndpointHandlerContext::default(),
            media_read_outs: VecDeque::new(),
            data_read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            // The salt of the report ids, drawn per connection so an application cannot
            // predict them (webrtc 8.4).
            stats: RTCStatsAccumulator::for_connection(setting_engine.ecn, rand::rng().random()),
            now,
        };

        // One CNAME for the connection (RFC 7022, RFC 8834 section 4.9): what RTCP says, what
        // the descriptions say (`a=ssrc:<ssrc> cname:`) and what the parameters report.
        media_engine.rtcp_cname = pipeline_context.interceptor_handler_context.cname.clone();

        Ok(Self {
            configuration,
            media_engine,
            setting_engine,
            interceptor,
            local_description: None,
            current_local_description: None,
            pending_local_description: None,
            remote_description: None,
            current_remote_description: None,
            pending_remote_description: None,
            signaling_state: RTCSignalingState::Stable,
            peer_connection_state: RTCPeerConnectionState::New,
            can_trickle_ice_candidates: None,
            trickled_remote_candidates: 0,
            pipeline_context,
            data_channels: DataChannelRegistry::new(),
            rtp_transceivers: Vec::new(),
            removed_transceivers: Vec::new(),
            greater_mid: -1,
            sdp_origin: Origin::default(),
            last_generated_sdp: String::new(),
            last_offer: String::new(),
            last_answer: String::new(),
            ice_restart_requested: None,
            transport_closed: false,
            identity_assertion: None,
            last_stable_state: None,
            negotiation_needed_state: NegotiationNeededState::Empty,
            is_negotiation_ongoing: false,
            always_negotiate_data_channels: false,
        })
    }

    /// The local candidates an offer or answer carries: none while an ICE restart is staged,
    /// because the description advertises the new credentials and the candidates gathered
    /// so far belong to the old ones (RFC 8839 section 5.4, JSEP section 5.2.3.1: a restart
    /// starts a new gathering phase, whose candidates are signalled as they come).
    /// The bundle policy in effect: `max-bundle` (W3C webrtc-pc section 4.2.5) is the policy
    /// RFC 9429 section 4.1.1 names `must-bundle`, unless the application has it ignored as
    /// that section's SHOULD says, which leaves the default.
    fn effective_bundle_policy(&self) -> RTCBundlePolicy {
        match self.configuration.bundle_policy {
            RTCBundlePolicy::MaxBundle if !self.setting_engine.max_bundle_ignored => {
                RTCBundlePolicy::MustBundle
            }
            RTCBundlePolicy::MaxBundle => RTCBundlePolicy::Unspecified,
            policy => policy,
        }
    }

    /// No offer/answer exchange has completed yet: an offer applied now is an initial offer
    /// (RFC 9143 section 2, "initial BUNDLE offer").
    pub(super) fn is_initial_exchange(&self) -> bool {
        self.current_local_description.is_none() && self.current_remote_description.is_none()
    }

    /// Whether the data section of an offer says `TCP/DTLS/SCTP` rather than `UDP/DTLS/SCTP`
    /// (RFC 8841 section 12.2), given the candidates the offer carries.
    ///
    /// "When a subsequent SDP offer or answer is sent after ICE nomination is complete, and it
    /// does not initiate ICE restart, ... the proto value MUST match the transport protocol
    /// associated with the nominated ICE candidate pair": the selected pair's, when there is
    /// one and no restart is staged. Otherwise "The proto value MUST match the transport
    /// protocol associated with the default candidate", which "SHOULD be chosen from one of
    /// those UDP candidates" when there are any: TCP only when every candidate gathered so
    /// far is a TCP one, and UDP while none is gathered (the dummy values of RFC 9429 section
    /// 5.2.1). An answer repeats the offer's proto instead (section 10.3).
    fn offers_sctp_over_tcp(&self, candidates: &[RTCIceCandidate]) -> bool {
        let ice_transport = self.ice_transport();
        if !ice_transport.has_pending_restart()
            && let Some((local, _)) = ice_transport.agent.get_selected_candidate_pair()
        {
            return local.network_type().is_tcp();
        }
        !candidates.is_empty()
            && candidates.iter().all(|candidate| {
                candidate.protocol == crate::peer_connection::transport::RTCIceProtocol::Tcp
            })
    }

    fn offered_local_candidates(&self) -> Result<Vec<RTCIceCandidate>> {
        if self.ice_transport().has_pending_restart() {
            return Ok(Vec::new());
        }
        self.ice_transport().get_local_candidates()
    }

    /// The fingerprints of every local certificate: W3C `RTCPeerConnection` writes an
    /// `a=fingerprint` line for each of its certificates (RFC 8829 §5.2.1), and the remote side
    /// accepts the one DTLS presents if it matches any of them (RFC 8122 §5).
    fn local_dtls_fingerprints(&self) -> Result<Vec<RTCDtlsFingerprint>> {
        let dtls_transport = self.dtls_transport();
        if dtls_transport.certificates.is_empty() {
            return Err(Error::ErrNonCertificate);
        }
        let mut fingerprints = vec![];
        for cert in &dtls_transport.certificates {
            for fingerprint in cert.get_fingerprints(dtls_transport.crypto_provider.crypto())? {
                if !fingerprints.contains(&fingerprint) {
                    fingerprints.push(fingerprint);
                }
            }
        }
        Ok(fingerprints)
    }

    /// generate_unmatched_sdp generates an SDP that doesn't take remote state into account
    /// This is used for the initial call for CreateOffer
    pub(super) fn generate_unmatched_sdp(&mut self) -> Result<SessionDescription> {
        let d = SessionDescription::new_jsep_session_description(false);

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.offered_local_candidates()?;

        let local_mids = self.local_description_mids();
        let mut media_sections = vec![];

        for (i, t) in self.rtp_transceivers.iter_mut().enumerate() {
            if t.stopped() {
                // RFC 9429 Section 5.2.2: a stopped transceiver has no m= section of its own; one
                // a local description already has stays, rejected, so the m= lines keep their
                // order.
                if let Some(mid) = t.mid().clone()
                    && local_mids.contains(&mid)
                {
                    media_sections.push(MediaSection {
                        mid,
                        transceiver_index: usize::MAX,
                        rejected: true,
                        rejected_kind: t.kind().to_string(),
                        stopped: true,
                        ..Default::default()
                    });
                }
                continue;
            }

            if let Some(sender) = t.sender_mut() {
                sender.set_negotiated();
            }

            if let Some(mid) = t.mid().clone() {
                media_sections.push(MediaSection {
                    mid,
                    transceiver_index: i,
                    ..Default::default()
                });
            }
        }

        if self.always_negotiate_data_channels {
            // wpt100:hdrext — alwaysNegotiateDataChannels: the data section comes first.
            media_sections.insert(
                0,
                MediaSection {
                    mid: self.added_data_section_mid(),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                },
            );
        } else if !self.data_channels.is_empty() {
            media_sections.push(MediaSection {
                mid: free_data_mid(&media_sections, &self.rtp_transceivers),
                transceiver_index: usize::MAX,
                data: true,
                ..Default::default()
            });
        }

        let dtls_fingerprints = self.local_dtls_fingerprints()?;

        let params = PopulateSdpParams {
            media_description_fingerprint: self.setting_engine.sdp_media_level_fingerprints,
            is_ice_lite: self.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed: true,
            connection_role: DEFAULT_DTLS_ROLE_OFFER.to_connection_role(),
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            bundle: BundleMode::Offer,
            offered_tag_rtcp_mux_only: false,
            rtcp_mux_only: self.configuration.rtcp_mux_policy != RTCRtcpMuxPolicy::Negotiate,
            bundle_policy: self.effective_bundle_policy(),
            initial_offer: true,
            bundle_attributes_in_tagged_section_only: self
                .setting_engine
                .bundle_attributes_tagged_only,
            sctp_max_message_size: self.setting_engine.sctp_max_message_size.as_usize(),
            sctp_port: self.sctp_transport().offer_port(),
            sctp_over_tcp: self.offers_sctp_over_tcp(&candidates),
            ignore_rid_pause_for_recv: false,
            rid_pause_marks: self.setting_engine.rid_pause_marks,
            write_ssrc_attributes_for_simulcast: self
                .setting_engine
                .write_ssrc_attributes_for_simulcast,
        };
        RTCPeerConnection::populate_sdp(
            d,
            &dtls_fingerprints,
            &self.media_engine,
            &mut self.rtp_transceivers,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )
    }

    /// generate_matched_sdp generates a SDP and takes the remote state into account
    /// this is used everytime we have a remote_description
    pub(super) fn generate_matched_sdp(
        &mut self,
        include_unmatched: bool,
        connection_role: ConnectionRole,
        ignore_rid_pause_for_recv: bool,
    ) -> Result<SessionDescription> {
        let mut d = SessionDescription::new_jsep_session_description(false);
        d = d.with_value_attribute(ATTR_KEY_MSID_SEMANTIC.to_owned(), "WMS *".to_owned());

        let ice_params = self.ice_transport().get_local_parameters()?;
        let candidates = self.offered_local_candidates()?;

        let mut media_sections = vec![];
        let mut already_have_application_media_section = false;
        let is_extmap_allow_mixed = is_ext_map_allow_mixed_set(self.remote_description());
        let local_mids = self.local_description_mids();
        let initial_remote_offer = !include_unmatched && self.is_initial_exchange();

        // Extract the description to avoid borrowing conflicts
        let remote_parsed = self
            .remote_description()
            .and_then(|r| r.parsed.as_ref())
            .cloned();
        let media_descriptions = remote_parsed
            .as_ref()
            .map(|parsed| parsed.media_descriptions.clone());
        // An answer repeats each offered m= line's proto (RFC 9429 section 5.1.2); an offer
        // states this endpoint's own.
        let offered_protos = |media: &MediaDescription| {
            (!include_unmatched).then(|| media.media_name.protos.clone())
        };

        // The mids the remote description has: a transceiver whose mid isn't among them is new
        // to this negotiation, and may take a rejected m-line's place in an offer.
        let remote_mids: HashSet<String> = media_descriptions
            .iter()
            .flatten()
            .filter_map(|m| get_mid_value(m).cloned())
            .collect();
        let mut recycled: HashSet<usize> = HashSet::new();
        // The remote mids of the rejected m= lines a new transceiver took over: the stopped
        // transceiver that had one is done with it, and gets no rejected section of its own.
        let mut recycled_mids: HashSet<String> = HashSet::new();

        if let Some(media_descriptions) = media_descriptions {
            let transceiver_by_mid =
                RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
            for media in &media_descriptions {
                if let Some(mid_value) = get_mid_value(media) {
                    if mid_value.is_empty() {
                        return Err(Error::ErrPeerConnRemoteDescriptionWithoutMidValue);
                    }

                    // RFC 9429 Section 5.2.2: an offer may reuse a rejected m= section (whose
                    // transceiver, if any, is stopped) for a transceiver that has no m= section
                    // yet; it keeps its own new mid.
                    if include_unmatched && is_rejected_media(media) {
                        let free = match self
                            .rtp_transceivers
                            .iter()
                            .position(|t| t.mid().as_ref() == Some(mid_value))
                        {
                            Some(i) => self.rtp_transceivers[i].stopped(),
                            None => true,
                        };
                        let candidate = if free {
                            self.rtp_transceivers.iter().enumerate().position(|(j, t)| {
                                !t.stopped()
                                    && !recycled.contains(&j)
                                    && t.mid()
                                        .as_ref()
                                        .is_some_and(|m| !m.is_empty() && !remote_mids.contains(m))
                            })
                        } else {
                            None
                        };
                        if let Some(j) = candidate {
                            if let Some(sender) = self.rtp_transceivers[j].sender_mut() {
                                sender.set_negotiated();
                            }
                            recycled.insert(j);
                            recycled_mids.insert(mid_value.to_owned());
                            media_sections.push(MediaSection {
                                mid: self.rtp_transceivers[j].mid().clone().unwrap_or_default(),
                                transceiver_index: j,
                                ..Default::default()
                            });
                            continue;
                        }
                    }

                    // RFC 8829 §5.3.1: rejected m-lines (port=0) in the offer MUST be
                    // reflected as rejected in the answer to preserve m-line indexing.
                    if is_rejected_media(media) {
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            rejected: true,
                            rejected_kind: media.media_name.media.clone(),
                            transceiver_index: usize::MAX,
                            rejected_name: unknown_media_name(media),
                            offered_protos: offered_protos(media),
                            ..Default::default()
                        });
                        continue;
                    }

                    if media.is_webrtc_datachannel() {
                        // RFC 8841 section 10.5: the application asked for the SCTP
                        // association and the DTLS association under it to be closed, which
                        // is said by a zero port on the data section's m= line, in an offer
                        // as in an answer (`RTCPeerConnection::reject_data_section`).
                        if self.sctp_transport().staged == Some(SctpRenegotiation::Reject) {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                rejected: true,
                                rejected_kind: media.media_name.media.clone(),
                                transceiver_index: usize::MAX,
                                offered_protos: offered_protos(media),
                                ..Default::default()
                            });
                            already_have_application_media_section = true;
                            continue;
                        }
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            transceiver_index: usize::MAX,
                            data: true,
                            offered_protos: offered_protos(media),
                            ..Default::default()
                        });
                        already_have_application_media_section = true;
                        continue;
                    }

                    let kind = RtpCodecKind::from(media.media_name.media.as_str());
                    if kind == RtpCodecKind::Unspecified || is_unknown_application_media(media) {
                        // A media type this endpoint doesn't know (RFC 8866
                        // lets <media> be any token): rejected with port 0,
                        // its media type, protocol and formats kept, so the
                        // answer lines up with the offer and later offers
                        // carry it (RFC 9429 5.3.1, 5.2.2).
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            rejected: true,
                            rejected_kind: media.media_name.media.clone(),
                            transceiver_index: usize::MAX,
                            rejected_name: unknown_media_name(media),
                            ..Default::default()
                        });
                        continue;
                    }

                    // An audio or video section offered with a profile that is none of the
                    // RTP profiles of RFC 9429 section 5.1.2 is not RTP this endpoint can
                    // answer: rejected, its proto and formats kept. So is one offered without
                    // `a=rtcp-mux`: there is no RTCP component to answer it with (RFC 8858
                    // section 4.3: an answerer that only multiplexes "MUST reject the 'm='
                    // section"; RFC 9429 section 5.3.1). Under the mux policy "require" such
                    // an offer was refused when it was applied.
                    if !include_unmatched
                        && matches!(kind, RtpCodecKind::Audio | RtpCodecKind::Video)
                        && (!is_rtp_profile(media)
                            || !remote_parsed.as_ref().is_some_and(|parsed| {
                                section_multiplexes_rtcp(parsed, media, initial_remote_offer)
                            }))
                    {
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            rejected: true,
                            rejected_kind: media.media_name.media.clone(),
                            transceiver_index: usize::MAX,
                            rejected_name: Some(media.media_name.clone()),
                            ..Default::default()
                        });
                        continue;
                    }

                    if let Some(&i) = transceiver_by_mid.get(mid_value.as_str()) {
                        // RFC 9429 Section 5.2.2: an offer rejects a stopped transceiver's m=
                        // section. An answer doesn't: a transceiver stopped after the offer
                        // arrived answers inactive, and is rejected by the next offer (W3C
                        // `stop()`).
                        if include_unmatched && self.rtp_transceivers[i].stopped() {
                            media_sections.push(MediaSection {
                                mid: mid_value.to_owned(),
                                rejected: true,
                                rejected_kind: media.media_name.media.clone(),
                                stopped: true,
                                transceiver_index: usize::MAX,
                                ..Default::default()
                            });
                            continue;
                        }
                        if let Some(sender) = self.rtp_transceivers[i].sender_mut() {
                            sender.set_negotiated();
                        }

                        let extensions = rtp_extensions_from_media_description(media)?;
                        // Answering, the section states [[Direction]] intersected with the
                        // reverse of the offered direction (RFC 9429 section 5.3.1): a sendonly
                        // offer is answered recvonly or inactive, never sendrecv (RFC 3264
                        // section 6.1). Applying the offer leaves [[Direction]] alone, so a later
                        // offer is answered from the application's direction again.
                        let answer_direction = (!include_unmatched).then(|| {
                            answered_direction(
                                self.rtp_transceivers[i].direction(),
                                remote_parsed.as_ref().map_or_else(
                                    || get_peer_direction(media),
                                    |parsed| effective_direction(parsed, media),
                                ),
                            )
                        });
                        media_sections.push(MediaSection {
                            mid: mid_value.to_owned(),
                            transceiver_index: i,
                            match_extensions: extensions,
                            match_extension_directions: if include_unmatched {
                                Default::default()
                            } else {
                                answered_extension_directions(media)
                            },
                            superseded_extensions: if include_unmatched {
                                vec![]
                            } else {
                                superseded_clear_extensions(media)?
                            },
                            rid_map: get_rids(media),
                            answer_direction,
                            offered_protos: offered_protos(media),
                            offered_rtcp_rsize: Some(if include_unmatched {
                                self.rtp_transceivers[i].rtcp_reduced_size()
                            } else {
                                remote_parsed.as_ref().is_some_and(|parsed| {
                                    has_bundle_attribute(parsed, media, ATTR_KEY_RTCPRSIZE)
                                })
                            }),
                            renegotiated: include_unmatched,
                            offered_codecs: (!include_unmatched)
                                .then(|| codecs_from_media_description(media).unwrap_or_default()),
                            ..Default::default()
                        });
                    } else {
                        return Err(Error::ErrPeerConnTransceiverMidNil);
                    }
                }
            }
        }

        // If we are offering also include unmatched local transceivers
        let match_bundle_group = if include_unmatched {
            let already_matched: HashSet<String> = media_sections
                .iter()
                .map(|s| s.mid.clone())
                .chain(recycled_mids.iter().cloned())
                .collect();

            // wpt100:hdrext — alwaysNegotiateDataChannels: a data section the session doesn't
            // have yet goes after the negotiated sections, ahead of the new ones.
            if self.always_negotiate_data_channels && !already_have_application_media_section {
                media_sections.push(MediaSection {
                    mid: self.added_data_section_mid(),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                });
                already_have_application_media_section = true;
            }

            for (i, t) in self.rtp_transceivers.iter_mut().enumerate() {
                if let Some(mid) = t.mid().clone() {
                    if already_matched.contains(&mid) {
                        continue;
                    }

                    // A stopped transceiver the remote side never saw: no m= section, unless a
                    // local description already has it (then rejected, keeping the order).
                    if t.stopped() {
                        if local_mids.contains(&mid) {
                            media_sections.push(MediaSection {
                                mid,
                                transceiver_index: usize::MAX,
                                rejected: true,
                                rejected_kind: t.kind().to_string(),
                                stopped: true,
                                ..Default::default()
                            });
                        }
                        continue;
                    }

                    if let Some(sender) = t.sender_mut() {
                        sender.set_negotiated();
                    }

                    media_sections.push(MediaSection {
                        mid,
                        transceiver_index: i,
                        ..Default::default()
                    });
                }
            }

            if !self.data_channels.is_empty() && !already_have_application_media_section {
                media_sections.push(MediaSection {
                    mid: free_data_mid(&media_sections, &self.rtp_transceivers),
                    transceiver_index: usize::MAX,
                    data: true,
                    ..Default::default()
                });
            }
            BundleMode::Offer
        } else {
            // The offered BUNDLE group, whatever other `a=group` lines the offer has
            // (RFC 9429 section 5.3.1); none when the offer has none.
            remote_parsed
                .as_ref()
                .map_or(BundleMode::Answer(None), BundleMode::answering)
        };

        let dtls_fingerprints = self.local_dtls_fingerprints()?;

        // RFC 8841 section 10: an offer says which SCTP port this side wants next (section
        // 10.5); an answer follows the offer's data section, in its port (section 10.3: a new
        // port for a new port, zero for zero) and in its proto, which the answer repeats.
        let (sctp_port, sctp_over_tcp) = if include_unmatched {
            (
                self.sctp_transport().offer_port(),
                self.offers_sctp_over_tcp(&candidates),
            )
        } else {
            let offered = self
                .remote_description()
                .and_then(|d| d.parsed.as_ref())
                .and_then(get_application_media);
            let offered_port = offered
                .and_then(|media| {
                    get_application_media_section_sctp_port(media)
                        .ok()
                        .flatten()
                })
                .unwrap_or(0);
            (
                self.sctp_transport().answer_port(offered_port),
                offered.is_some_and(|media| {
                    media.media_name.protos.first().is_some_and(|p| p == "TCP")
                }),
            )
        };

        let params = PopulateSdpParams {
            media_description_fingerprint: self.setting_engine.sdp_media_level_fingerprints,
            is_ice_lite: self.setting_engine.candidates.ice_lite,
            is_extmap_allow_mixed,
            connection_role,
            ice_gathering_state: self.ice_transport().ice_gathering_state,
            bundle_policy: self.effective_bundle_policy(),
            initial_offer: false,
            bundle_attributes_in_tagged_section_only: self
                .setting_engine
                .bundle_attributes_tagged_only,
            rtcp_mux_only: self.configuration.rtcp_mux_policy != RTCRtcpMuxPolicy::Negotiate,
            offered_tag_rtcp_mux_only: !include_unmatched
                && remote_parsed
                    .as_ref()
                    .is_some_and(offerer_tagged_section_is_rtcp_mux_only),
            bundle: match_bundle_group,
            sctp_max_message_size: self.setting_engine.sctp_max_message_size.as_usize(),
            sctp_port,
            sctp_over_tcp,
            ignore_rid_pause_for_recv,
            rid_pause_marks: self.setting_engine.rid_pause_marks,
            write_ssrc_attributes_for_simulcast: self
                .setting_engine
                .write_ssrc_attributes_for_simulcast,
        };
        RTCPeerConnection::populate_sdp(
            d,
            &dtls_fingerprints,
            &self.media_engine,
            &mut self.rtp_transceivers,
            &candidates,
            &ice_params,
            &media_sections,
            params,
        )
    }

    pub(super) fn populate_local_candidates(
        &self,
        session_description: Option<&RTCSessionDescription>,
    ) -> Option<RTCSessionDescription> {
        if session_description.is_none() {
            return session_description.cloned();
        }

        if let Some(sd) = session_description {
            // The candidates to signal: not the peer-reflexive ones the agent learned from
            // its checks (RFC 8445 section 7.2.5.3.1).
            let candidates = rtc_ice_candidates_from_ice_candidates(
                &self.ice_transport().agent.get_local_candidates_to_signal(),
            );

            let mut parsed = match sd.unmarshal() {
                Ok(parsed) => parsed,
                Err(_) => return Some(sd.clone()),
            };

            if !parsed.media_descriptions.is_empty() {
                let mut m = parsed.media_descriptions.remove(0);
                m = match add_candidates_to_media_descriptions(
                    &candidates,
                    m,
                    self.ice_transport().ice_gathering_state,
                ) {
                    Ok(m) => m,
                    Err(_) => return Some(sd.clone()),
                };
                parsed.media_descriptions.insert(0, m);
            }

            Some(RTCSessionDescription {
                sdp_type: sd.sdp_type,
                sdp: parsed.marshal(),
                parsed: Some(parsed),
            })
        } else {
            None
        }
    }

    /// The signaling state a description leads to (W3C webrtc-pc "set a session description",
    /// RFC 9429 sections 5.5 and 5.6), or the error that refuses it. Nothing is changed: both
    /// `set_local_description` and `set_remote_description` call this before they touch the
    /// connection, and [`Self::commit_description`] once every other check has passed.
    pub(super) fn check_description(
        &self,
        sd: &RTCSessionDescription,
        op: StateChangeOp,
    ) -> Result<RTCSignalingState> {
        let cur = self.signaling_state;
        let next = match (op, sd.sdp_type) {
            (_, RTCSdpType::Unspecified) => return Err(Error::ErrPeerConnSDPTypeInvalidValue),
            // stable->SetLocal(offer)->have-local-offer
            (StateChangeOp::SetLocal, RTCSdpType::Offer) => {
                if sd.sdp != self.last_offer {
                    return Err(Error::ErrSDPDoesNotMatchOffer);
                }
                RTCSignalingState::HaveLocalOffer
            }
            // have-remote-offer->SetLocal(answer)->stable
            // have-local-pranswer->SetLocal(answer)->stable
            (StateChangeOp::SetLocal, RTCSdpType::Answer) => {
                if sd.sdp != self.last_answer {
                    return Err(Error::ErrSDPDoesNotMatchAnswer);
                }
                RTCSignalingState::Stable
            }
            // have-remote-offer->SetLocal(pranswer)->have-local-pranswer
            (StateChangeOp::SetLocal, RTCSdpType::Pranswer) => {
                if sd.sdp != self.last_answer {
                    return Err(Error::ErrSDPDoesNotMatchAnswer);
                }
                RTCSignalingState::HaveLocalPranswer
            }
            // stable->SetRemote(offer)->have-remote-offer
            (StateChangeOp::SetRemote, RTCSdpType::Offer) => RTCSignalingState::HaveRemoteOffer,
            // have-local-offer->SetRemote(answer)->stable
            // have-remote-pranswer->SetRemote(answer)->stable
            (StateChangeOp::SetRemote, RTCSdpType::Answer) => RTCSignalingState::Stable,
            // have-local-offer->SetRemote(pranswer)->have-remote-pranswer
            (StateChangeOp::SetRemote, RTCSdpType::Pranswer) => {
                RTCSignalingState::HaveRemotePranswer
            }
            // have-local-offer or have-remote-offer->rollback->stable, through either method
            (_, RTCSdpType::Rollback) => RTCSignalingState::Stable,
        };
        check_next_signaling_state(cur, next, op, sd.sdp_type)
    }

    /// Records a description [`Self::check_description`] accepted: the pending and current
    /// descriptions, what a rollback has to restore, and the signaling state `next_state`
    /// (W3C webrtc-pc "set a session description").
    pub(super) fn commit_description(
        &mut self,
        sd: &RTCSessionDescription,
        op: StateChangeOp,
        next_state: RTCSignalingState,
    ) -> Result<()> {
        // A remote offer applied in the stable state: what the last completed exchange
        // negotiated is remembered, so that a rollback can bring it back (W3C: the
        // [[LastStableState...]] slots). An offer applied over a pending one keeps what was
        // remembered. A local offer changes none of it, so there is nothing to remember, and
        // what the application sets while its own offer is pending (codec preferences, say)
        // survives the rollback.
        if sd.sdp_type == RTCSdpType::Offer
            && op == StateChangeOp::SetRemote
            && self.signaling_state == RTCSignalingState::Stable
        {
            self.last_stable_state = Some(LastStableState {
                media_engine: self.media_engine.clone(),
                rtp_transceivers: self.rtp_transceivers.clone(),
                can_trickle_ice_candidates: self.can_trickle_ice_candidates,
                transport_closed: self.transport_closed,
            });
        }

        match (op, sd.sdp_type) {
            (StateChangeOp::SetLocal, RTCSdpType::Offer | RTCSdpType::Pranswer) => {
                self.pending_local_description = Some(sd.clone());
            }
            (StateChangeOp::SetRemote, RTCSdpType::Offer | RTCSdpType::Pranswer) => {
                self.pending_remote_description = Some(sd.clone());
            }
            (StateChangeOp::SetLocal, RTCSdpType::Answer) => {
                self.current_remote_description = self.pending_remote_description.take();
                self.pending_local_description = None;
                self.current_local_description = Some(sd.clone());
                self.transport_closed = rejects_every_media_section(sd);
            }
            (StateChangeOp::SetRemote, RTCSdpType::Answer) => {
                self.current_local_description = self.pending_local_description.take();
                self.pending_remote_description = None;
                self.current_remote_description = Some(sd.clone());
                self.transport_closed = rejects_every_media_section(sd);
            }
            (_, RTCSdpType::Rollback) => {
                self.pending_local_description = None;
                self.pending_remote_description = None;
                // Undo what the abandoned offer changed (RFC 9429, Section 5.7).
                self.rollback_transceivers()?;
                self.restore_last_stable_state();
            }
            (_, RTCSdpType::Unspecified) => return Err(Error::ErrPeerConnSDPTypeInvalidValue),
        }

        if matches!(sd.sdp_type, RTCSdpType::Answer) {
            // W3C "set a session description": an answer resets [[LastCreatedOffer]] and
            // [[LastCreatedAnswer]], so a description created for an exchange that is over
            // cannot be applied to the next one.
            self.last_offer.clear();
            self.last_answer.clear();
            self.last_stable_state = None;
        }

        let changed = self.signaling_state != next_state;
        self.signaling_state = next_state;
        let reached_stable = next_state == RTCSignalingState::Stable;
        if reached_stable {
            self.is_negotiation_ongoing = false;
            // Negotiation has committed: any transceiver that was created while applying
            // a remote offer is now part of the stable state, so clear the
            // created-by-remote flag. This keeps the flag meaning exactly "created by the
            // current pending (uncommitted) offer", which is what rollback relies on.
            for t in &mut self.rtp_transceivers {
                t.set_created_by_remote_description(false);
            }
        }
        // W3C "set a session description": "If connection.[[SignalingState]] changed above,
        // fire an event named signalingstatechange". An offer applied over a pending offer and
        // a repeated provisional answer change nothing.
        if changed {
            self.do_signaling_state_change(next_state);
        }
        if reached_stable {
            // W3C "update the negotiation-needed flag" is re-run each time the connection
            // returns to a stable signaling state. A transceiver added while the
            // connection was mid-negotiation (`negotiation_needed_op` step 2.3 bails out
            // when not stable) had its negotiation-needed check deferred; re-running it now
            // fires `OnNegotiationNeededEvent` if anything is still un-negotiated.
            self.trigger_negotiation_needed();
        }
        Ok(())
    }

    /// Brings back what the last completed exchange negotiated, after a rollback (W3C
    /// webrtc-pc "set a session description", the rollback steps; RFC 9429 section 5.7: "the
    /// state of the session is restored to the state it was in before the offer"): the
    /// negotiated codecs and header extensions, each transceiver's codecs, the repair (RTX /
    /// FEC) flows of its sender's encodings, and what the remote description said about
    /// trickling. The transceivers the offer created are already gone
    /// ([`Self::rollback_transceivers`]); one the offer stopped stays stopped, as the stop
    /// algorithm is not undone.
    fn restore_last_stable_state(&mut self) {
        let Some(saved) = self.last_stable_state.take() else {
            return;
        };
        self.media_engine = saved.media_engine;
        self.can_trickle_ice_candidates = saved.can_trickle_ice_candidates;
        self.transport_closed = saved.transport_closed;
        // No transceiver is removed while an offer is pending, other than the ones the offer
        // created, which come after every transceiver that existed when it was applied: the
        // saved ones are the first of the list, in order.
        for (transceiver, saved) in self
            .rtp_transceivers
            .iter_mut()
            .zip(&saved.rtp_transceivers)
        {
            transceiver.restore_negotiated_state(saved);
        }
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
    }

    /// The part of the connection a description changes that is not a transport, copied so
    /// that a description which fails while it is applied leaves all of it as it was (RFC 9429
    /// sections 5.9 and 5.10: "the session state MUST be restored to its state before").
    pub(super) fn description_snapshot(&self) -> DescriptionSnapshot {
        DescriptionSnapshot {
            signaling_state: self.signaling_state,
            current_local_description: self.current_local_description.clone(),
            pending_local_description: self.pending_local_description.clone(),
            current_remote_description: self.current_remote_description.clone(),
            pending_remote_description: self.pending_remote_description.clone(),
            media_engine: self.media_engine.clone(),
            rtp_transceivers: self.rtp_transceivers.clone(),
            removed_transceivers: self.removed_transceivers.len(),
            can_trickle_ice_candidates: self.can_trickle_ice_candidates,
            trickled_remote_candidates: self.trickled_remote_candidates,
            last_offer: self.last_offer.clone(),
            last_answer: self.last_answer.clone(),
            transport_closed: self.transport_closed,
            negotiation_needed_state: self.negotiation_needed_state,
            is_negotiation_ongoing: self.is_negotiation_ongoing,
            last_stable_state: self.last_stable_state.clone(),
            events: self.pipeline_context.event_outs.len(),
        }
    }

    /// Puts back what [`Self::description_snapshot`] copied, dropping the events queued since.
    pub(super) fn restore_description_snapshot(&mut self, snapshot: DescriptionSnapshot) {
        self.signaling_state = snapshot.signaling_state;
        self.current_local_description = snapshot.current_local_description;
        self.pending_local_description = snapshot.pending_local_description;
        self.current_remote_description = snapshot.current_remote_description;
        self.pending_remote_description = snapshot.pending_remote_description;
        self.media_engine = snapshot.media_engine;
        self.rtp_transceivers = snapshot.rtp_transceivers;
        self.removed_transceivers
            .truncate(snapshot.removed_transceivers);
        self.can_trickle_ice_candidates = snapshot.can_trickle_ice_candidates;
        self.trickled_remote_candidates = snapshot.trickled_remote_candidates;
        self.last_offer = snapshot.last_offer;
        self.last_answer = snapshot.last_answer;
        self.transport_closed = snapshot.transport_closed;
        self.negotiation_needed_state = snapshot.negotiation_needed_state;
        self.is_negotiation_ongoing = snapshot.is_negotiation_ongoing;
        self.last_stable_state = snapshot.last_stable_state;
        self.pipeline_context.event_outs.truncate(snapshot.events);
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
        self.update_cryptex();
    }

    pub(super) fn do_signaling_state_change(&mut self, new_state: RTCSignalingState) {
        log::info!("signaling state changed to {new_state}");
        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnSignalingStateChangeEvent(new_state),
        );
    }

    pub(crate) fn ice_transport(&self) -> &IceTransport {
        &self.pipeline_context.ice_handler_context.ice_transport
    }

    pub(crate) fn ice_transport_mut(&mut self) -> &mut IceTransport {
        &mut self.pipeline_context.ice_handler_context.ice_transport
    }

    pub(crate) fn dtls_transport(&self) -> &DtlsTransport {
        &self.pipeline_context.dtls_handler_context.dtls_transport
    }

    pub(crate) fn dtls_transport_mut(&mut self) -> &mut DtlsTransport {
        &mut self.pipeline_context.dtls_handler_context.dtls_transport
    }

    pub(crate) fn sctp_transport(&self) -> &SctpTransport {
        &self.pipeline_context.sctp_handler_context.sctp_transport
    }

    pub(crate) fn sctp_transport_mut(&mut self) -> &mut SctpTransport {
        &mut self.pipeline_context.sctp_handler_context.sctp_transport
    }

    /// add_rtp_transceiver appends t into rtp_transceivers
    /// and fires onNegotiationNeeded;
    /// caller of this method should hold `self.mu` lock
    pub(super) fn add_rtp_transceiver(
        &mut self,
        t: RTCRtpTransceiverInternal,
    ) -> RTCRtpTransceiverId {
        self.rtp_transceivers.push(t);
        self.trigger_negotiation_needed();
        self.rtp_transceivers.len() - 1
    }

    /// Removes the transceiver at `i` from the set of transceivers. The ids of the transceivers
    /// after it move down by one, as the stats' references to them do; the removed id is
    /// recorded for [`RTCPeerConnection::take_removed_transceivers`].
    fn remove_rtp_transceiver(&mut self, i: RTCRtpTransceiverId) {
        self.rtp_transceivers.remove(i);
        self.removed_transceivers.push(i);
        self.pipeline_context.stats.transceiver_removed(i);
        // Cached SSRC owners are transceiver ids, now shifted.
        self.pipeline_context
            .interceptor_handler_context
            .ssrc_owners
            .clear();
        self.pipeline_context
            .endpoint_handler_context
            .ssrc_owners
            .clear();
    }

    /// Whether the m= section with `mid` is rejected (port 0) in the current local or the
    /// current remote description: the last completed offer/answer exchange rejected it (an
    /// answer rejects every section its offer rejected, and may reject more).
    pub(super) fn rejected_in_current_description(&self, mid: &str) -> bool {
        let rejected_in = |desc: Option<&RTCSessionDescription>| {
            desc.and_then(|d| d.parsed.as_ref()).is_some_and(|parsed| {
                parsed.media_descriptions.iter().any(|media| {
                    get_mid_value(media).is_some_and(|m| m == mid) && is_rejected_media(media)
                })
            })
        };
        rejected_in(self.current_local_description.as_ref())
            || rejected_in(self.current_remote_description.as_ref())
    }

    /// W3C webrtc-pc 4.4.1.6 (set the session description, once an answer is applied and the
    /// signaling state is stable): every stopped transceiver whose m= section is rejected in
    /// the current local or the current remote description is removed from the set of
    /// transceivers (RFC 9429 section 5.2.2: the m= section stays, rejected, and may be
    /// recycled). A stopped transceiver the exchange still answered (stopped after the offer
    /// arrived) stays until the next offer rejects its section.
    pub(super) fn remove_stopped_rejected_transceivers(&mut self) {
        if self.signaling_state != RTCSignalingState::Stable {
            return;
        }
        for i in (0..self.rtp_transceivers.len()).rev() {
            let t = &self.rtp_transceivers[i];
            if t.stopped()
                && let Some(mid) = t.mid().clone()
                && self.rejected_in_current_description(&mid)
            {
                self.remove_rtp_transceiver(i);
            }
        }
    }

    /// Undoes the transceiver changes made by an offer/answer transaction that is being rolled
    /// back, as required by RFC 9429, Section 5.7.
    ///
    /// - Transceivers that were implicitly created by applying the remote offer now being rolled
    ///   back are stopped and removed, unless a track has since been attached to them via
    ///   `add_track` (i.e. they have a sender). The latter are kept but disassociated so a
    ///   subsequent `create_offer` can re-add an "m=" section for the attached track.
    /// - Any remaining transceiver that was associated with an "m=" section solely by the
    ///   rolled-back description — i.e. its mid is not present in the current (last stable)
    ///   local or remote description — is disassociated: its mid is cleared and the "m=" section
    ///   index mapping is discarded. Transceivers associated by a prior, already-negotiated
    ///   exchange keep their mid.
    ///
    /// The effect is identical regardless of whether the rollback was applied via
    /// `set_local_description` or `set_remote_description`, as the spec requires.
    pub(super) fn rollback_transceivers(&mut self) -> Result<()> {
        // Mids that were associated by the last stable offer/answer exchange. A transceiver
        // whose mid appears here was not associated by the rolled-back description and must be
        // left untouched.
        let negotiated_mids = self.current_description_mids();

        // Stop and remove transceivers created by the rolled-back remote offer that `add_track`
        // never touched (it clears the flag; a sender made for `replaceTrack` or a sending
        // direction doesn't keep one, W3C 4.4.1.6 rollback). `created_by_remote_description` is
        // cleared once negotiation reaches stable, so a set flag denotes a transceiver created by
        // the pending, not-yet-committed offer. Iterate in reverse so index-based removal is
        // stable.
        for i in (0..self.rtp_transceivers.len()).rev() {
            let t = &self.rtp_transceivers[i];
            if t.created_by_remote_description() {
                self.rtp_transceivers[i].stop(&self.media_engine, &mut self.interceptor)?;
                self.remove_rtp_transceiver(i);
            }
        }

        // Disassociate any remaining transceiver that was associated with an "m=" section solely
        // by the rolled-back description.
        for t in &mut self.rtp_transceivers {
            let associated_by_rolled_back_desc = t
                .mid()
                .as_ref()
                .is_some_and(|mid| !negotiated_mids.contains(mid));
            if associated_by_rolled_back_desc {
                t.disassociate();
            }
        }

        // The created-by-remote flag on any survivors is cleared by the caller once the state
        // machine settles back to `stable` (see `set_description`).

        Ok(())
    }

    /// Gives each transceiver the `a=rtcp-xr` attribute (RFC 3611 section 5.1) and the `b=`
    /// lines of its section of a remote description (RFC 9429 section 5.10): `b=TIAS` (bits per second, RFC 3890), else `b=AS` (kilobits per second,
    /// RFC 8866 section 5.8), is the most this endpoint may send there; `b=RS` and `b=RR`
    /// (RFC 3556) are the RTCP bandwidth of senders and receivers. A session-level `b=` line
    /// and `b=CT` are ignored, as RFC 9429 section 5.10 says. A section without the lines
    /// clears what an earlier description set.
    pub(super) fn apply_remote_bandwidth(&mut self, remote: &SessionDescription) {
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for media in &remote.media_descriptions {
            let Some(&i) =
                get_mid_value(media).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            let of = |bandwidth_type: &str| {
                media
                    .bandwidth
                    .iter()
                    .find(|b| !b.experimental && b.bandwidth_type == bandwidth_type)
                    .map(|b| b.bandwidth)
            };
            // RFC 3611 section 5.1: "a=rtcp-xr" at media level replaces the session's.
            let rtcp_xr = media
                .attribute(ATTR_KEY_RTCP_XR)
                .map(|value| value.map(str::to_owned))
                .or_else(|| {
                    remote
                        .attributes
                        .iter()
                        .find(|a| a.key == ATTR_KEY_RTCP_XR)
                        .map(|a| a.value.clone())
                })
                .map(|value| {
                    value
                        .unwrap_or_default()
                        .split_whitespace()
                        .map(str::to_owned)
                        .collect()
                });
            self.rtp_transceivers[i].set_remote_rtcp_xr(rtcp_xr);
            let application_specific = of("AS").map(|kbps| kbps.saturating_mul(1000));
            self.rtp_transceivers[i].set_remote_bandwidth(RTCRemoteBandwidth {
                // RFC 9429 section 5.10: "TIAS = AS * 1000 * 0.95 - (50 * 40 * 8)".
                max_bitrate: of("TIAS").or_else(|| {
                    application_specific
                        .map(|bps| (bps / 100).saturating_mul(95).saturating_sub(50 * 40 * 8))
                }),
                session_bitrate: of("TIAS").or(application_specific),
                rtcp_senders_bitrate: of("RS"),
                rtcp_receivers_bitrate: of("RR"),
            });
        }
    }

    /// What an applied answer negotiated for RTCP, section by section, given to the
    /// transceivers: reduced-size RTCP is used when both the offer and the answer carry
    /// `a=rtcp-rsize` (RFC 5506 section 5; RFC 9429 section 5.11: "If the answer does not
    /// contain 'a=rtcp-rsize', ... reduced-size RTCP MUST NOT be used"). The senders' and
    /// receivers' parameters report it (`rtcp.reduced_size`), which is what an RTCP session
    /// reads to choose between compound and reduced-size packets.
    pub(super) fn apply_negotiated_rtcp(
        &mut self,
        offer: &SessionDescription,
        answer: &SessionDescription,
    ) {
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for (offered, answered) in offer
            .media_descriptions
            .iter()
            .zip(&answer.media_descriptions)
        {
            let Some(&i) =
                get_mid_value(answered).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            // A bundled section takes the tagged section's when it has none of its own.
            let reduced_size = !is_rejected_media(answered)
                && has_bundle_attribute(offer, offered, ATTR_KEY_RTCPRSIZE)
                && has_bundle_attribute(answer, answered, ATTR_KEY_RTCPRSIZE);
            self.rtp_transceivers[i].set_rtcp_reduced_size(reduced_size);
        }
    }

    /// What an applied answer leaves of the simulcast encodings this endpoint offered or was
    /// asked for (RFC 8853 section 5.3.3, W3C webrtc-pc "set a session description": "If
    /// description is missing any of the previously negotiated layers, then remove the
    /// dictionaries that correspond to the missing layers from [[SendEncodings]]"; without
    /// simulcast, or without any of them, the first encoding stays).
    ///
    /// The encodings that stay take the restrictions of the answer's `a=rid` line. In a
    /// remote answer, a line that does not keep to what the offer said (RFC 8851 section 6.4)
    /// is discarded, so its stream goes.
    pub(super) fn apply_negotiated_simulcast(
        &mut self,
        offer: &SessionDescription,
        answer: &SessionDescription,
        answer_is_local: bool,
    ) {
        use super::sdp::SimulcastDirection;
        use super::sdp::simulcast::{answered_rid_is_valid, same_format};
        use crate::rtp_transceiver::rtp_sender::RTCRtpRidRestrictions;
        // The direction this endpoint's streams have in the answer.
        let ours = if answer_is_local {
            SimulcastDirection::Send
        } else {
            SimulcastDirection::Recv
        };
        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        for (offered, answered) in offer
            .media_descriptions
            .iter()
            .zip(&answer.media_descriptions)
        {
            if is_rejected_media(answered) {
                continue;
            }
            let Some(&i) =
                get_mid_value(answered).and_then(|mid| transceiver_by_mid.get(mid.as_str()))
            else {
                continue;
            };
            let Some(sender) = self.rtp_transceivers[i].sender_mut() else {
                continue;
            };
            let offered_rids = get_rids(offered);
            let formats = same_format(offered, answered);
            let accepted: Vec<(String, RTCRtpRidRestrictions)> = get_rids(answered)
                .into_iter()
                .filter(|rid| rid.direction == ours && rid.simulcast)
                .filter(|rid| {
                    answer_is_local
                        || offered_rids
                            .iter()
                            .find(|offered| {
                                offered.id == rid.id
                                    && offered.direction == SimulcastDirection::Send
                            })
                            .is_some_and(|offered| answered_rid_is_valid(offered, rid, &formats))
                })
                .map(|rid| {
                    let restrictions = rid.to_restrictions();
                    (rid.id, restrictions)
                })
                .collect();
            sender.apply_simulcast_answer(&accepted);
        }
    }

    /// Hands what an applied answer negotiated to the parts of the interceptor chain that
    /// act on it. Each goes as a control message written into the chain; a chain without
    /// the interceptor a message is for drops it.
    ///
    /// - Reduced-size RTCP (`a=rtcp-rsize` in the offer and in the answer, RFC 5506 section
    ///   5), when every media section negotiated it:
    ///   [`RtcpSessionControl::ReducedSize`](interceptor::RtcpSessionControl).
    /// - The bandwidth of the remote description's `b=` lines, summed over the media sections
    ///   when each has the line (RFC 8859 section 6: `b=AS`, `b=RS` and `b=RR` are of the SUM
    ///   category, and the values of `b=TIAS` are added): the session bandwidth (RFC 3550
    ///   section 6.2) and
    ///   the RTCP bandwidth of senders and receivers (RFC 3556 section 2), as
    ///   [`RtcpSessionControl::Bandwidth`](interceptor::RtcpSessionControl).
    /// - `trr-int` of the local description (RFC 4585 section 4.2: this endpoint's minimum
    ///   interval between regular RTCP packets), the longest when sections differ:
    ///   [`RtcpSessionControl::TrrInt`](interceptor::RtcpSessionControl); without one,
    ///   `TrrIntCleared`, so that a value an earlier negotiation set does not stay.
    /// - The most the remote side accepts (`b=TIAS`, else `b=AS`; RFC 9429 section 5.10),
    ///   summed over the sections this endpoint sends in when each has a limit, as the upper
    ///   bound of the congestion controller's estimate ([`RemoteBitrateLimit`]).
    /// - `rtx-time` of the retransmission formats (RFC 4588 section 8.1): the local
    ///   description's is how long the NACK responder keeps a sent packet, the remote
    ///   description's how long the NACK generator asks for a missing one
    ///   ([`NackControl`](interceptor::NackControl)).
    /// - What identifies each stream this endpoint sends, for the SDES chunk of its SSRC: the
    ///   mid of its m= section (RFC 9143 section 15.1), the encoding's rid as RtpStreamId and,
    ///   on its RTX and FEC SSRCs, as RepairedRtpStreamId (RFC 8852 sections 3.1, 3.2):
    ///   [`RtcpSessionControl::StreamIdentifiers`](interceptor::RtcpSessionControl).
    pub(super) fn apply_negotiated_session(
        &mut self,
        now: Instant,
        local: &SessionDescription,
        remote: &SessionDescription,
    ) -> Result<()> {
        use interceptor::{NackControl, RtcpBandwidth, RtcpSessionControl};
        use std::time::Duration;

        let live = |t: &&RTCRtpTransceiverInternal| t.mid().is_some() && !t.stopped();
        let sum = |values: Vec<Option<u64>>| -> Option<u64> {
            if values.is_empty() {
                return None;
            }
            values
                .into_iter()
                .try_fold(0u64, |total, value| Some(total.saturating_add(value?)))
        };
        let of_live = |value: fn(&RTCRemoteBandwidth) -> Option<u64>| -> Vec<Option<u64>> {
            self.rtp_transceivers
                .iter()
                .filter(live)
                .map(|t| value(&t.remote_bandwidth()))
                .collect()
        };

        let reduced_size = self.rtp_transceivers.iter().any(|t| live(&t))
            && self
                .rtp_transceivers
                .iter()
                .filter(live)
                .all(|t| t.rtcp_reduced_size());
        let bandwidth = RtcpBandwidth {
            session: sum(of_live(|b| b.session_bitrate)),
            rs: sum(of_live(|b| b.rtcp_senders_bitrate)),
            rr: sum(of_live(|b| b.rtcp_receivers_bitrate)),
        };
        let send_limit = sum(self
            .rtp_transceivers
            .iter()
            .filter(live)
            .filter(|t| t.describes_sender() && t.current_direction().has_send())
            .map(|t| t.remote_bandwidth().max_bitrate)
            .collect());

        let transceiver_by_mid =
            RTCPeerConnection::transceiver_index_by_mid(&self.rtp_transceivers);
        let negotiated_sections = |desc: &SessionDescription| -> Vec<Vec<RTCRtpCodecParameters>> {
            desc.media_descriptions
                .iter()
                .filter(|media| {
                    !is_rejected_media(media)
                        && get_mid_value(media)
                            .is_some_and(|mid| transceiver_by_mid.contains_key(mid.as_str()))
                })
                .filter_map(|media| codecs_from_media_description(media).ok())
                .collect()
        };
        let local_sections = negotiated_sections(local);
        let remote_sections = negotiated_sections(remote);
        let trr_int = local_sections
            .iter()
            .flatten()
            .flat_map(|codec| &codec.rtp_codec.rtcp_feedback)
            .filter(|feedback| feedback.typ == "trr-int")
            .filter_map(|feedback| feedback.parameter.trim().parse::<u64>().ok())
            .max();
        let rtx_times = |sections: &[Vec<RTCRtpCodecParameters>]| -> Vec<(u8, Option<Duration>)> {
            sections
                .iter()
                .flatten()
                .filter(|codec| is_rtx_mime_type(&codec.rtp_codec.mime_type))
                .map(|codec| {
                    (
                        codec.payload_type,
                        parse_rtx_time(&codec.rtp_codec.sdp_fmtp_line),
                    )
                })
                .collect()
        };

        let mut controls = vec![
            RtcpSessionControl::ReducedSize(reduced_size).into_packet(now),
            RtcpSessionControl::Bandwidth(bandwidth).into_packet(now),
        ];
        // A `trr-int` an earlier negotiation set and this one does not have is undone.
        controls.push(
            match trr_int {
                Some(trr_int) => RtcpSessionControl::TrrInt(Duration::from_millis(trr_int)),
                None => RtcpSessionControl::TrrIntCleared,
            }
            .into_packet(now),
        );
        controls.push(RemoteBitrateLimit(send_limit.map(|limit| limit as f64)).into_packet(now));
        for (payload_type_rtx, rtx_time) in rtx_times(&local_sections) {
            controls.push(
                NackControl::LocalRtxTime {
                    payload_type_rtx,
                    rtx_time,
                }
                .into_packet(now),
            );
        }
        for (payload_type_rtx, rtx_time) in rtx_times(&remote_sections) {
            controls.push(
                NackControl::RemoteRtxTime {
                    payload_type_rtx,
                    rtx_time,
                }
                .into_packet(now),
            );
        }
        for transceiver in self.rtp_transceivers.iter().filter(live) {
            let (Some(mid), Some(sender)) = (transceiver.mid(), transceiver.sender()) else {
                continue;
            };
            if !sender.has_sent() {
                continue;
            }
            for encoding in sender.send_encodings() {
                let coding = &encoding.rtp_coding_parameters;
                let Some(ssrc) = coding.ssrc else {
                    continue;
                };
                let rid = (!coding.rid.is_empty()).then(|| coding.rid.clone());
                let repair = coding
                    .rtx
                    .as_ref()
                    .map(|rtx| rtx.ssrc)
                    .into_iter()
                    .chain(coding.fec.as_ref().map(|fec| fec.ssrc));
                controls.push(
                    RtcpSessionControl::StreamIdentifiers {
                        ssrc,
                        mid: Some(mid.clone()),
                        rid: rid.clone(),
                        repaired_rid: None,
                    }
                    .into_packet(now),
                );
                for repair_ssrc in repair {
                    controls.push(
                        RtcpSessionControl::StreamIdentifiers {
                            ssrc: repair_ssrc,
                            mid: Some(mid.clone()),
                            rid: None,
                            repaired_rid: rid.clone(),
                        }
                        .into_packet(now),
                    );
                }
            }
        }
        for control in controls {
            self.interceptor.handle_write(control)?;
        }
        Ok(())
    }

    /// Gives each m= section of a remote description that has no `a=mid` one (RFC 9429,
    /// Section 5.10 / 5.11: an endpoint that predates mids). In an answer it is the mid of our
    /// m= section at the same position; in an offer, the section's index (or the next number no
    /// other section has). Only the parsed description changes: the SDP text stays as given.
    pub(super) fn assign_missing_mids(&self, parsed: &mut SessionDescription, answers: bool) {
        let local: Vec<Option<String>> = if answers {
            self.pending_local_description
                .as_ref()
                .or(self.current_local_description.as_ref())
                .and_then(|d| d.parsed.as_ref())
                .map(|d| {
                    d.media_descriptions
                        .iter()
                        .map(|m| get_mid_value(m).filter(|mid| !mid.is_empty()).cloned())
                        .collect()
                })
                .unwrap_or_default()
        } else {
            vec![]
        };
        let mut taken: HashSet<String> = parsed
            .media_descriptions
            .iter()
            .filter_map(|m| get_mid_value(m).filter(|mid| !mid.is_empty()).cloned())
            .collect();
        for (index, media) in parsed.media_descriptions.iter_mut().enumerate() {
            if get_mid_value(media).is_some_and(|mid| !mid.is_empty()) {
                continue;
            }
            let mid = match local.get(index).cloned().flatten() {
                Some(mid) if !taken.contains(&mid) => mid,
                _ => {
                    let mut n = index;
                    while taken.contains(&n.to_string()) {
                        n += 1;
                    }
                    n.to_string()
                }
            };
            taken.insert(mid.clone());
            media.attributes.retain(|a| a.key != ATTR_KEY_MID);
            media.attributes.push(Attribute {
                key: ATTR_KEY_MID.to_owned(),
                value: Some(mid),
            });
        }
    }

    /// The mids of the pending and current local descriptions.
    pub(super) fn local_description_mids(&self) -> HashSet<String> {
        let mut mids = HashSet::new();
        for desc in [
            self.pending_local_description.as_ref(),
            self.current_local_description.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(parsed) = desc.parsed.as_ref() {
                for media in &parsed.media_descriptions {
                    if let Some(mid) = get_mid_value(media)
                        && !mid.is_empty()
                    {
                        mids.insert(mid.clone());
                    }
                }
            }
        }
        mids
    }

    /// Collects the set of mids associated by the current (last stable) local and remote
    /// descriptions. Used by rollback to distinguish transceivers associated by a prior,
    /// already-negotiated exchange from those associated only by the description being rolled back.
    fn current_description_mids(&self) -> HashSet<String> {
        let mut mids = HashSet::new();
        for desc in [
            self.current_local_description.as_ref(),
            self.current_remote_description.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(parsed) = desc.parsed.as_ref() {
                for media in &parsed.media_descriptions {
                    if let Some(mid) = get_mid_value(media)
                        && !mid.is_empty()
                    {
                        mids.insert(mid.clone());
                    }
                }
            }
        }
        mids
    }

    pub(super) fn start_rtp_senders(&mut self) -> Result<()> {
        // Collect SSRCs, kinds, mids, rids, encoding indices, rtx_ssrc, and transceiver_id for outbound stream accumulators
        // We do this in two phases to avoid borrow conflicts
        #[allow(clippy::type_complexity)]
        let mut outbound_streams_to_create: Vec<(
            u32,
            RtpCodecKind,
            String,
            String,
            u32,
            Option<u32>,
            RTCRtpTransceiverId,
        )> = Vec::new();

        for (transceiver_id, transceiver) in self.rtp_transceivers.iter_mut().enumerate() {
            // Get kind and mid before mutable borrow of sender
            let kind = transceiver.kind();
            let mid = transceiver.mid().clone().unwrap_or_default();
            let transceiver_stopped = transceiver.stopped();

            // A started sender's streams were bound with what an earlier negotiation decided;
            // one that changed the codec an encoding is sent with (or its RTX / FEC flow, or the
            // header extensions) re-binds them, keeping the SSRCs.
            if let Some(sender) = transceiver.sender_mut()
                && sender.is_negotiated()
                && sender.has_sent()
                && !transceiver_stopped
            {
                sender.rebind_local_streams(&self.media_engine, &mut self.interceptor);
                continue;
            }

            if let Some(sender) = transceiver.sender_mut()
                && sender.is_negotiated()
                && !sender.has_sent()
                && !sender.track().codings().is_empty()
            {
                // Collect SSRCs for stats accumulator creation
                for (encoding_index, coding) in sender.track().codings().iter().enumerate() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc
                        && !sender.is_removed_ssrc(ssrc)
                    {
                        let rid = coding.rtp_coding_parameters.rid.clone();
                        let rtx_ssrc = coding
                            .rtp_coding_parameters
                            .rtx
                            .as_ref()
                            .map(|rtx| rtx.ssrc);
                        outbound_streams_to_create.push((
                            ssrc,
                            kind,
                            mid.clone(),
                            rid,
                            encoding_index as u32,
                            rtx_ssrc,
                            transceiver_id,
                        ));
                    }
                }

                sender.bind_local_streams(&self.media_engine, &mut self.interceptor);

                sender.set_sent();
            }
        }

        // Create outbound stream accumulators
        for (ssrc, kind, mid, rid, encoding_index, rtx_ssrc, transceiver_id) in
            outbound_streams_to_create
        {
            self.pipeline_context
                .stats
                .get_or_create_outbound_rtp_streams(
                    ssrc,
                    kind,
                    &mid,
                    &rid,
                    encoding_index,
                    rtx_ssrc,
                    transceiver_id,
                );
        }

        // Whether each bound stream negotiated RFC 8888 feedback: its remote-inbound stats
        // have the RFC 8888 members, and with ECN on its packets go out ECT(1). Taken from what
        // the streams are bound with now, so a renegotiation that adds or drops `ack ccfb`
        // takes effect with it.
        for transceiver in &self.rtp_transceivers {
            let Some(sender) = transceiver.sender().as_ref() else {
                continue;
            };
            for info in sender.bound_streams() {
                let ccfb = negotiates_ccfb(
                    info.rtcp_feedback
                        .iter()
                        .map(|f| (f.typ.as_str(), f.parameter.as_str())),
                );
                self.pipeline_context
                    .stats
                    .set_outbound_ccfb(info.ssrc, ccfb);
            }
        }

        Ok(())
    }

    pub(super) fn start_rtp(&mut self, remote_desc: RTCSessionDescription) -> Result<()> {
        self.start_rtp_senders()?;

        let incoming_tracks = if let Some(parsed) = &remote_desc.parsed {
            track_details_from_sdp(parsed)
        } else {
            vec![]
        };

        for incoming_track in incoming_tracks.into_iter() {
            if let Some(transceiver) = self.rtp_transceivers.iter_mut().find(|transceiver| {
                transceiver.mid().as_ref() == Some(&incoming_track.mid)
                    && incoming_track.kind == transceiver.kind()
                    && transceiver.direction().has_recv()
            }) && let Some(receiver) = transceiver.receiver_mut()
            {
                // The MediaStreams the track is in, one per `a=msid` line (RFC 8830 section 2).
                receiver.set_streams(incoming_track.stream_ids.clone());

                if is_same_remote_track(receiver, &incoming_track) {
                    // Keep SSRCs and codecs learned from RTP; the sender may no longer attach
                    // the MID/RID header extension needed to learn them again.
                    continue;
                }

                // An `a=msid` without appdata names no track: "the recipient can assign the
                // track ID itself" (RFC 8830 section 3; RFC 9429 section 5.2.1 has senders
                // write that form). The receiver's track keeps the id it was given before.
                let mut incoming_track = incoming_track;
                if incoming_track.track_id.is_empty() {
                    incoming_track.track_id = if receiver.track().track_id().is_empty() {
                        math_rand_alpha(16)
                    } else {
                        receiver.track().track_id().clone()
                    };
                }

                let mut receive_codings = vec![];
                if !incoming_track.rids.is_empty() {
                    // for incoming_track with rids, defer adding track until received the first RTP
                    // packet with rtp header extension with "urn:ietf:params:rtp-hdrext:sdes:mid" and
                    // "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", so that endpoint handler can
                    // map the unknown ssrc to m= line. Here, we should add a track but with 0 ssrc.
                    // The reason is to provide stream_id and track_id information for later usage
                    // when received the first RTP packet. So, it is placeholder here.
                    let mut codings = vec![];
                    let mut rid_restrictions = std::mem::take(&mut incoming_track.rid_restrictions);
                    for rid in std::mem::take(&mut incoming_track.rids) {
                        // RFC 8851 section 5: the restrictions the sender's `a=rid` line put on
                        // the stream, as the application reads them from the receiver.
                        let restrictions = rid_restrictions.remove(&rid).unwrap_or_default();
                        let rtp_coding_parameters = RTCRtpCodingParameters {
                            rid,
                            ssrc: None, // Defer receiver's track's ssrc until received the first RTP packet with mid/rid header extension in endpoint handler
                            rtx: None,
                            fec: None,
                            rid_restrictions: restrictions,
                        };
                        receive_codings.push(rtp_coding_parameters.clone());
                        codings.push(RTCRtpEncodingParameters {
                            rtp_coding_parameters,
                            codec: Default::default(),
                            ..Default::default()
                        })
                    }

                    receiver.set_track(MediaStreamTrack::new(
                        incoming_track.stream_id.clone(),
                        incoming_track.track_id.clone(),
                        // W3C webrtc 4.4.1.6 (create an RTCRtpReceiver): "remote " + kind.
                        format!("remote {}", incoming_track.kind),
                        incoming_track.kind,
                        codings,
                    ));
                } else if let Some(ssrc) = incoming_track.ssrc {
                    let rtp_coding_parameters = RTCRtpCodingParameters {
                        rid: "".to_string(),
                        ssrc: Some(ssrc),
                        rtx: incoming_track
                            .rtx_ssrc
                            .map(|rtx_ssrc| RTCRtpRtxParameters { ssrc: rtx_ssrc }),
                        fec: incoming_track
                            .fec_ssrc
                            .map(|fec_ssrc| RTCRtpFecParameters { ssrc: fec_ssrc }),
                        ..Default::default()
                    };

                    receive_codings.push(rtp_coding_parameters.clone());

                    receiver.set_track(MediaStreamTrack::new(
                        incoming_track.stream_id,
                        incoming_track.track_id,
                        // W3C webrtc 4.4.1.6 (create an RTCRtpReceiver): "remote " + kind.
                        format!("remote {}", incoming_track.kind),
                        incoming_track.kind,
                        vec![RTCRtpEncodingParameters {
                            rtp_coding_parameters,
                            codec: Default::default(), // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                            ..Default::default()
                        }],
                    ));

                    // Deliberately no `interceptor_remote_streams_op` here. It bound nothing: that
                    // walks the track's codings and skips any whose codec does not resolve, and the
                    // codec above is `Default::default()` — deferred until the first RTP packet
                    // names a payload type. So the call read as "bound", always did nothing, and
                    // the streams stayed unbound for the life of the connection.
                    //
                    // The bind happens once the codec is known, in the endpoint handler's
                    // `find_track_id_by_ssrc`.
                } else {
                    // No a=ssrc: the SSRC doesn't have to be declared (RFC 8843 §9.2). With one
                    // media section its packets are that section's; with several, the MID header
                    // extension says which. Add a track with no coding as a placeholder, carrying
                    // the stream and track ids, until the first RTP packet binds its SSRC in the
                    // interceptor handler (`bind_undeclared_ssrc`).
                    receiver.set_track(MediaStreamTrack::new(
                        incoming_track.stream_id,
                        incoming_track.track_id,
                        // W3C webrtc 4.4.1.6 (create an RTCRtpReceiver): "remote " + kind.
                        format!("remote {}", incoming_track.kind),
                        incoming_track.kind,
                        vec![], // Defer receiver's track's codec until received the first RTP packet with payload_type in endpoint handler
                    ));
                }

                receiver.set_coding_parameters(receive_codings);
            }
        }

        Ok(())
    }

    /// Update the PeerConnectionState given the state of relevant transports
    /// <https://www.w3.org/TR/webrtc/#rtcpeerconnectionstate-enum>
    pub(crate) fn update_connection_state(&mut self, is_closed: bool) {
        // Once closed, the state is terminal — ignore any subsequent transport
        // state changes that would otherwise re-evaluate to e.g. `New`.
        if self.peer_connection_state == RTCPeerConnectionState::Closed && !is_closed {
            return;
        }

        let connection_state =
            // The RTCPeerConnection object's [[IsClosed]] slot is true.
            if is_closed {
                RTCPeerConnectionState::Closed
            } else if self.ice_transport().ice_connection_state == RTCIceConnectionState::Failed || self.dtls_transport().state == RTCDtlsTransportState::Failed {
                // Any of the RTCIceTransports or RTCDtlsTransports are in a "failed" state.
                RTCPeerConnectionState::Failed
            } else if self.ice_transport().ice_connection_state == RTCIceConnectionState::Disconnected {
                // Any of the RTCIceTransports or RTCDtlsTransports are in the "disconnected"
                // state and none of them are in the "failed" or "connecting" or "checking" state.
                RTCPeerConnectionState::Disconnected
            } else if (self.ice_transport().ice_connection_state == RTCIceConnectionState::New || self.ice_transport().ice_connection_state == RTCIceConnectionState::Closed) &&
                (self.dtls_transport().state == RTCDtlsTransportState::New || self.dtls_transport().state == RTCDtlsTransportState::Closed) {
                // None of the previous states apply and all RTCIceTransports are in the "new" or "closed" state,
                // and all RTCDtlsTransports are in the "new" or "closed" state, or there are no transports.
                RTCPeerConnectionState::New
            } else if (self.ice_transport().ice_connection_state == RTCIceConnectionState::New || self.ice_transport().ice_connection_state == RTCIceConnectionState::Checking) ||
                (self.dtls_transport().state == RTCDtlsTransportState::New || self.dtls_transport().state == RTCDtlsTransportState::Connecting) {
                // None of the previous states apply and any IceTransport is in the "new" or "checking" state or
                // any DtlsTransport is in the "new" or "connecting" state.
                RTCPeerConnectionState::Connecting
            } else if (self.ice_transport().ice_connection_state == RTCIceConnectionState::Connected || self.ice_transport().ice_connection_state == RTCIceConnectionState::Completed || self.ice_transport().ice_connection_state == RTCIceConnectionState::Closed) &&
                (self.dtls_transport().state == RTCDtlsTransportState::Connected || self.dtls_transport().state == RTCDtlsTransportState::Closed) {
                // All RTCIceTransports and RTCDtlsTransports are in the "connected", "completed" or "closed"
                // state and all RTCDtlsTransports are in the "connected" or "closed" state.
                RTCPeerConnectionState::Connected
            } else {
                RTCPeerConnectionState::New
            };

        if self.peer_connection_state == connection_state {
            return;
        }

        log::info!("peer connection state changed: {connection_state}");
        self.peer_connection_state = connection_state;

        self.pipeline_context.event_outs.push_back(
            RTCPeerConnectionEvent::OnConnectionStateChangeEvent(connection_state),
        );
    }

    /// Called by the public `RTCRtpTransceiver::set_direction` when a transceiver's preferred
    /// direction actually changes, to update the connection's negotiation-needed flag.
    ///
    /// This is a narrow, purpose-specific entry point so the general-purpose
    /// [`Self::trigger_negotiation_needed`] can stay `pub(super)`.
    ///
    /// See <https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction>.
    pub(crate) fn on_transceiver_direction_changed(&mut self) {
        self.trigger_negotiation_needed();
    }

    /// W3C `RTCRtpTransceiver.stop()` and `RTCRtpSender.setStreams()` end by updating the
    /// negotiation-needed flag (W3C webrtc 5.4, 5.2).
    pub(crate) fn on_transceiver_stopped_or_streams_changed(&mut self) {
        self.trigger_negotiation_needed();
    }

    /// Helper to trigger a negotiation needed.
    pub(super) fn trigger_negotiation_needed(&mut self) {
        if !self.do_negotiation_needed() {
            return;
        }
        let _ = self.negotiation_needed_op();
    }

    fn do_negotiation_needed(&mut self) -> bool {
        // https://www.w3.org/TR/webrtc/#updating-the-negotiation-needed-flag
        // non-canon step 1
        if self.negotiation_needed_state == NegotiationNeededState::Run {
            self.negotiation_needed_state = NegotiationNeededState::Queue;
            false
        } else if self.negotiation_needed_state == NegotiationNeededState::Queue {
            false
        } else {
            self.negotiation_needed_state = NegotiationNeededState::Run;
            true
        }
    }

    fn negotiation_needed_op(&mut self) -> bool {
        // https://www.w3.org/TR/webrtc/#updating-the-negotiation-needed-flag
        // Step 2.1
        if self.peer_connection_state == RTCPeerConnectionState::Closed {
            return false;
        }
        // non-canon step 2.2
        // no need to check ops

        // non-canon, run again if there was a request
        // starting defer(after_do_negotiation_needed(params).await);

        // Step 2.3
        if self.signaling_state != RTCSignalingState::Stable {
            return self.after_negotiation_needed_op();
        }

        // Step 2.4
        if !self.check_negotiation_needed() {
            self.is_negotiation_ongoing = false;
            return self.after_negotiation_needed_op();
        }

        // Step 2.5
        if self.is_negotiation_ongoing {
            return self.after_negotiation_needed_op();
        }

        // Step 2.6
        // set negotiation is in middle of ongoing
        self.is_negotiation_ongoing = true;

        // Step 2.7
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnNegotiationNeededEvent);

        //TODO: do we need this call with new event-based handling?
        self.after_negotiation_needed_op()
    }

    fn after_negotiation_needed_op(&mut self) -> bool {
        let old_negotiation_needed_state = self.negotiation_needed_state;

        self.negotiation_needed_state = NegotiationNeededState::Empty;

        if old_negotiation_needed_state == NegotiationNeededState::Queue {
            self.do_negotiation_needed()
        } else {
            false
        }
    }

    fn check_negotiation_needed(&self) -> bool {
        // To check if negotiation is needed for connection, perform the following checks:
        // Skip 1, 2 steps
        // Step 3

        if let Some(local_desc) = &self.current_local_description {
            let len_data_channel = self.data_channels.len();

            if len_data_channel != 0 && have_data_channel(local_desc).is_none() {
                return true;
            }

            for transceiver in &self.rtp_transceivers {
                // https://www.w3.org/TR/webrtc/#dfn-update-the-negotiation-needed-flag
                // Steps 5.1 and 5.4. This engine stops a transceiver at once (no separate
                // "stopping" state), so `stopped()` covers both: one that never had an m=
                // section needs none, and one that has needs negotiating until that section is
                // rejected in both current descriptions (or has gone to another transceiver).
                if transceiver.stopped() {
                    let Some(mid) = transceiver.mid().as_deref() else {
                        continue;
                    };
                    let rejected_in = |desc: Option<&RTCSessionDescription>| {
                        desc.and_then(|desc| get_by_mid(mid, desc))
                            .is_none_or(is_rejected_media)
                    };
                    if rejected_in(Some(local_desc))
                        && rejected_in(self.current_remote_description.as_ref())
                    {
                        continue;
                    }
                    return true;
                }
                let m = transceiver
                    .mid()
                    .as_ref()
                    .and_then(|mid| get_by_mid(mid.as_str(), local_desc));
                // Step 5.2
                if m.is_none() {
                    return true;
                }

                if let Some(m) = m {
                    // Step 5.3.1
                    // A transceiver can carry a send direction without a sender: answering a
                    // `recvonly` offer creates one implicitly, and `remove_track` leaves one
                    // behind. There is then no track, so no msid for this step to compare, and
                    // nothing a renegotiation could settle - claiming otherwise re-offers on
                    // every return to a stable signaling state, forever.
                    if transceiver.direction().has_send()
                        && transceiver.describes_sender()
                        && let Some(sender) = transceiver.sender()
                    {
                        // The stream ids of the section's a=msid lines (one per stream,
                        // RFC 8830 section 2) against the sender's associated streams:
                        // `setStreams` changes those without changing the track.
                        let mut described: Vec<&str> = m
                            .attributes
                            .iter()
                            .filter(|a| a.key == ATTR_KEY_MSID)
                            .filter_map(|a| a.value.as_deref())
                            .filter_map(|msid| msid.split_whitespace().next())
                            .collect();
                        if described.is_empty() {
                            return true; // doesn't contain a single a=msid line
                        }
                        described.sort_unstable();
                        described.dedup();
                        let mut associated: Vec<&str> =
                            sender.streams().iter().map(String::as_str).collect();
                        associated.sort_unstable();
                        associated.dedup();
                        if described != associated {
                            return true;
                        }
                    }
                    match local_desc.sdp_type {
                        RTCSdpType::Offer => {
                            // Step 5.3.2
                            if let Some(remote_desc) = &self.current_remote_description {
                                if let Some(rm) = transceiver
                                    .mid()
                                    .as_ref()
                                    .and_then(|mid| get_by_mid(mid.as_str(), remote_desc))
                                {
                                    if get_peer_direction(m) != transceiver.direction()
                                        && get_peer_direction(rm)
                                            != transceiver.direction().reverse()
                                    {
                                        return true;
                                    }
                                } else {
                                    return true;
                                }
                            }
                        }
                        RTCSdpType::Answer => {
                            // Step 5.3.3: the answer's direction against [[Direction]]
                            // intersected with the offered direction (RFC 9429 section 5.3.1),
                            // the direction an answer made now would state.
                            let offered = self
                                .current_remote_description
                                .as_ref()
                                .zip(transceiver.mid().as_ref())
                                .and_then(|(remote_desc, mid)| {
                                    get_by_mid(mid.as_str(), remote_desc)
                                })
                                .map(get_peer_direction);
                            let expected = match offered {
                                Some(offered) => {
                                    answered_direction(transceiver.direction(), offered)
                                }
                                None => transceiver.direction(),
                            };
                            if m.attribute(expected.to_string().as_str()).is_none() {
                                return true;
                            }
                        }
                        _ => {}
                    };
                }

                // Step 5.4
            }
            // Step 6
            false
        } else {
            true
        }
    }

    pub(super) fn new_transceiver_from_track(
        &self,
        track: MediaStreamTrack,
        mut init: RTCRtpTransceiverInit,
    ) -> Result<RTCRtpTransceiverInternal> {
        if init.direction == RTCRtpTransceiverDirection::Unspecified {
            Err(Error::ErrPeerConnAddTransceiverFromTrackSupport)
        } else {
            if init.send_encodings.is_empty() {
                init.send_encodings = self.send_encodings_from_track(&track);
            }
            Ok(RTCRtpTransceiverInternal::new(
                track.kind(),
                Some(track),
                init,
            ))
        }
    }

    pub(super) fn send_encodings_from_track(
        &self,
        track: &MediaStreamTrack,
    ) -> Vec<RTCRtpEncodingParameters> {
        let (is_rtx_enabled, is_fec_enabled) = (
            self.media_engine
                .is_rtx_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
            self.media_engine
                .is_fec_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly),
        );

        track
            .codings()
            .iter()
            .map(|coding| RTCRtpEncodingParameters {
                rtp_coding_parameters: RTCRtpCodingParameters {
                    rid: coding.rtp_coding_parameters.rid.to_owned(),
                    ssrc: coding.rtp_coding_parameters.ssrc.to_owned(),
                    // Whether there is a repair flow at all is the media engine's call: without a
                    // codec registered to carry it, an `a=ssrc-group` naming a repair SSRC has no
                    // `a=rtpmap` to give it a format, and that is an offer no peer can act on.
                    //
                    // Given one, the SSRC follows the same rule as the media SSRC on the line
                    // above: what the application named is what gets used, and one is minted only
                    // when the track left it unset.
                    rtx: is_rtx_enabled.then(|| {
                        coding.rtp_coding_parameters.rtx.clone().unwrap_or_else(|| {
                            RTCRtpRtxParameters {
                                ssrc: rand::random::<u32>(),
                            }
                        })
                    }),
                    fec: is_fec_enabled.then(|| {
                        coding.rtp_coding_parameters.fec.clone().unwrap_or_else(|| {
                            RTCRtpFecParameters {
                                ssrc: rand::random::<u32>(),
                            }
                        })
                    }),
                    rid_restrictions: coding.rtp_coding_parameters.rid_restrictions.clone(),
                },
                codec: coding.codec.clone(),
                ..Default::default()
            })
            .collect()
    }

    pub(crate) fn stats(&self) -> &RTCStatsAccumulator {
        &self.pipeline_context.stats
    }

    pub(crate) fn stats_mut(&mut self) -> &mut RTCStatsAccumulator {
        &mut self.pipeline_context.stats
    }

    /// Stages an ICE restart so the next offer advertises fresh credentials.
    ///
    /// The live session is untouched: inbound STUN keeps validating against the current ufrag/pwd
    /// until [`Self::apply_ice_restart`] runs at `set_local_description`. JSEP requires
    /// `createOffer` to be free of side effects, and an offer that is created and then discarded
    /// must leave a working connection working.
    ///
    /// The gathering state does move here, because SDP generation reads it and a restart offer
    /// must not claim end-of-candidates.
    pub(super) fn stage_ice_restart(&mut self) -> Result<()> {
        let (local_ufrag, local_pwd) = (
            self.setting_engine.candidates.username_fragment.clone(),
            self.setting_engine.candidates.password.clone(),
        );
        self.ice_transport_mut()
            .generate_restart_credentials(local_ufrag, local_pwd)?;
        self.ice_transport_mut().ice_gathering_state = RTCIceGatheringState::Gathering;

        Ok(())
    }

    /// Applies a staged ICE restart, restarting the agent's timers at `now`.
    ///
    /// A no-op when nothing is staged, so `set_local_description` can call it unconditionally
    /// without tearing down a session that was never asked to restart.
    pub(super) fn apply_ice_restart(&mut self, now: Instant) -> Result<()> {
        let keep_local_candidates = !self
            .setting_engine
            .candidates
            .discard_local_candidates_during_ice_restart;
        self.ice_transport_mut()
            .apply_restart(now, keep_local_candidates)
    }

    pub(super) fn start_transports(
        &mut self,
        now: Instant,
        local_ice_role: RTCIceRole,
        remote_ice_parameters: RTCIceParameters,
        remote_dtls_parameters: RTCDtlsParameters,
    ) -> Result<()> {
        // Update ICE role (may change after ICE restart if peer roles swap)
        self.pipeline_context.stats.transport.ice_role = local_ice_role;

        // Start the ice transport
        self.ice_transport_mut()
            .start(now, local_ice_role, remote_ice_parameters)?;

        // Start the dtls transport
        self.dtls_transport_mut()
            .start(local_ice_role, remote_dtls_parameters)?;

        self.update_connection_state(false);

        Ok(())
    }

    /// Converts an RTCIceCandidate to an IceCandidateAccumulator for stats collection.
    ///
    /// # Parameters
    ///
    /// * `candidate` - The ICE candidate to convert.
    /// * `username_fragment` - The ICE username fragment.
    /// * `url` - Optional STUN/TURN server URL. Per W3C spec, this should only be
    ///   provided for local candidates of type "srflx" or "relay".
    pub(super) fn candidate_to_accumulator(
        &self,
        candidate: &RTCIceCandidate,
        username_fragment: &str,
        url: Option<&str>,
    ) -> IceCandidateAccumulator {
        // Per W3C spec, URL is only valid for local srflx/relay candidates
        let url_for_stats = match candidate.typ {
            RTCIceCandidateType::Srflx | RTCIceCandidateType::Relay => {
                url.map(|s| s.to_string()).unwrap_or_default()
            }
            _ => String::new(),
        };

        IceCandidateAccumulator {
            transport_id: self.pipeline_context.stats.transport.transport_id.clone(),
            address: if candidate.address.is_empty() {
                None
            } else {
                Some(candidate.address.clone())
            },
            port: candidate.port,
            protocol: candidate.protocol.to_string(),
            candidate_type: candidate.typ,
            priority: candidate.priority,
            // webrtc-stats `relayProtocol`: how the endpoint reaches the TURN server of a local
            // relay candidate. The application does that, so the candidate does not say; the
            // TURN URL it was gathered from does (RFC 7065).
            relay_protocol: match candidate.relay_protocol {
                RTCIceServerTransportProtocol::Unspecified
                    if candidate.typ == RTCIceCandidateType::Relay =>
                {
                    relay_protocol_of_turn_url(&url_for_stats)
                }
                protocol => protocol,
            },
            url: url_for_stats,
            foundation: candidate.foundation.clone(),
            related_address: candidate.related_address.clone(),
            related_port: candidate.related_port,
            username_fragment: username_fragment.to_string(),
            tcp_type: candidate.tcp_type,
            signalled: false,
        }
    }

    pub(super) fn add_ice_remote_candidate(&mut self, candidate_value: &str) -> Result<()> {
        let candidate: Candidate = unmarshal_candidate(candidate_value)?;
        self.add_signalled_remote_candidate(candidate)
    }

    /// Gives the ICE agent a remote candidate the application supplied, through
    /// `add_remote_candidate` or in a candidate line of a remote description, and registers
    /// its statistics.
    pub(super) fn add_signalled_remote_candidate(&mut self, candidate: Candidate) -> Result<()> {
        // Register remote candidate with stats accumulator, only once the agent keeps it (one
        // past its cap is dropped there and here).
        // Per W3C spec, URL must NOT be present for remote candidates
        let rtc_candidate: RTCIceCandidate = (&candidate).into();
        let candidate_id = remote_candidate_stats_id(&rtc_candidate.id);
        let (ufrag, _) = self.ice_transport().get_remote_user_credentials();
        let mut accumulator = self.candidate_to_accumulator(&rtc_candidate, ufrag, None);
        // The application supplied this candidate, so its address may be shown in the stats.
        accumulator.signalled = true;

        // An mDNS candidate is held by the agent only once its name resolves, and not at all
        // when it is ignored. Its statistics object exists from the moment it is submitted
        // all the same, so that the report does not say whether the name resolved
        // (draft-ietf-mmusic-mdns-ice-candidates section 3.3.1).
        let is_mdns = candidate.address().ends_with(".local");
        let kept = self.ice_transport_mut().add_remote_candidate(candidate)?;
        if kept
            || (is_mdns
                && self.stats().remote_candidates.len() < MAX_UNRESOLVED_MDNS_CANDIDATE_STATS)
        {
            self.stats_mut()
                .register_remote_candidate(candidate_id, accumulator);
        }
        Ok(())
    }

    pub(super) fn add_ice_local_candidate(
        &mut self,
        candidate_value: &str,
        url: Option<&str>,
    ) -> Result<()> {
        let candidate: Candidate = unmarshal_candidate(candidate_value)?;
        let known = self.ice_transport().agent.get_local_candidates().len();
        if !self.ice_transport_mut().add_local_candidate(candidate)? {
            return Ok(());
        }

        // Usually one candidate is added; with a server-reflexive 1:1 NAT mapping
        // (`nat_1to1_ips`) the agent adds a second, on the external address. Each is announced.
        let added: Vec<RTCIceCandidate> = self
            .ice_transport()
            .agent
            .get_local_candidates()
            .iter()
            .skip(known)
            .map(RTCIceCandidate::from)
            .collect();
        if added.is_empty() {
            return Err(Error::Other(
                "local candidate missing after registration".to_owned(),
            ));
        }

        for mut rtc_candidate in added {
            // Register local candidate with stats accumulator
            let candidate_id = local_candidate_stats_id(&rtc_candidate.id);
            let (ufrag, _) = self.ice_transport().get_local_user_credentials();
            // The candidate is of this ICE generation: `to_json` carries the fragment, and
            // the peer ignores it if it arrives after an ICE restart (RFC 8838 section 9).
            rtc_candidate.username_fragment = Some(ufrag.to_owned());
            let accumulator = self.candidate_to_accumulator(&rtc_candidate, ufrag, url);
            self.stats_mut()
                .register_local_candidate(candidate_id, accumulator);

            // Emit OnIceCandidateEvent
            self.pipeline_context.event_outs.push_back(
                RTCPeerConnectionEvent::OnIceCandidateEvent(RTCPeerConnectionIceEvent {
                    candidate: rtc_candidate,
                    url: url.unwrap_or_default().to_string(),
                }),
            );
        }

        Ok(())
    }

    /// Update the candidate pair stats from the ICE agent: every pair it holds, with its state,
    /// nomination and STUN transaction counters.
    ///
    /// This is called automatically by `get_stats()`. webrtc-stats reports a
    /// `RTCIceCandidatePairStats` for each pair of the ICE transport, not only the selected one,
    /// and every candidate a pair names has a candidate stats object of its own (every id a
    /// stats object names resolves in the same report). Pairs the agent no longer holds (an ICE
    /// restart drops them) are dropped from the stats too.
    pub(super) fn update_ice_agent_stats(&mut self, now: Instant) {
        let agent = &self
            .pipeline_context
            .ice_handler_context
            .ice_transport
            .agent;
        let pairs = agent.get_candidate_pairs_stats(now);

        // A local candidate is normally registered when gathered, a remote one when signalled;
        // one the agent learned from a connectivity check (peer-reflexive, RFC 8445 section
        // 7.3.1.3) was never signalled, so it has no stats object yet.
        let unregistered_local: Vec<RTCIceCandidate> = agent
            .get_local_candidates()
            .iter()
            .filter(|c| {
                pairs.iter().any(|p| p.local_candidate_id == c.id())
                    && !self
                        .pipeline_context
                        .stats
                        .local_candidates
                        .contains_key(&local_candidate_stats_id(c.id()))
            })
            .map(RTCIceCandidate::from)
            .collect();
        // A remote candidate also needs (new) statistics when it is no longer what its object
        // says: a peer-reflexive candidate that the signalled candidate with its address
        // replaced keeps its id, and so its pairs (RFC 8838 section 11), but is a signalled
        // host or server-reflexive candidate now, with the address that was signalled (the
        // name, for an mDNS candidate that resolved to it).
        let unregistered_remote: Vec<RTCIceCandidate> = agent
            .get_remote_candidates()
            .iter()
            .filter(|c| {
                pairs.iter().any(|p| p.remote_candidate_id == c.id())
                    && self
                        .pipeline_context
                        .stats
                        .remote_candidates
                        .get(&remote_candidate_stats_id(c.id()))
                        .is_none_or(|known| {
                            known.candidate_type != RTCIceCandidateType::from(c.candidate_type())
                        })
            })
            .map(|c| {
                let mut candidate = RTCIceCandidate::from(c);
                // draft-ietf-mmusic-mdns-ice-candidates section 3.3.1: a peer-reflexive
                // candidate's address is shown only when the peer signalled that address
                // itself; it may be the one an mDNS name hides.
                if c.candidate_type() == ::ice::candidate::CandidateType::PeerReflexive
                    && !agent.is_signalled_remote_ip(c.addr().ip())
                {
                    candidate.address.clear();
                }
                candidate
            })
            .collect();

        if !unregistered_local.is_empty() {
            let ufrag = self
                .ice_transport()
                .get_local_user_credentials()
                .0
                .to_owned();
            for candidate in unregistered_local {
                let accumulator = self.candidate_to_accumulator(&candidate, &ufrag, None);
                self.stats_mut()
                    .register_local_candidate(local_candidate_stats_id(&candidate.id), accumulator);
            }
        }
        if !unregistered_remote.is_empty() {
            let remote_ufrag = self
                .ice_transport()
                .get_remote_user_credentials()
                .0
                .to_owned();
            for candidate in unregistered_remote {
                let id = remote_candidate_stats_id(&candidate.id);
                let accumulator = if candidate.typ == RTCIceCandidateType::Prflx {
                    // Learned from a check, never signalled: no username fragment was given
                    // for it (webrtc-stats `usernameFragment`), and its address is not shown
                    // (`RTCStatsAccumulator::remote_candidate_entries`).
                    self.candidate_to_accumulator(&candidate, "", None)
                } else {
                    // Every other remote candidate the agent holds was signalled: one whose
                    // mDNS name resolved after it was submitted, or one that took the place
                    // of a learned candidate. The object made when it was submitted, under the
                    // id it had then, gives way to this one.
                    let mut accumulator =
                        self.candidate_to_accumulator(&candidate, &remote_ufrag, None);
                    accumulator.signalled = true;
                    let (address, port, protocol) = (
                        accumulator.address.clone(),
                        accumulator.port,
                        accumulator.protocol.clone(),
                    );
                    self.stats_mut().remote_candidates.retain(|other, known| {
                        *other == id
                            || !(known.signalled
                                && known.address == address
                                && known.port == port
                                && known.protocol == protocol)
                    });
                    accumulator
                };
                self.stats_mut().register_remote_candidate(id, accumulator);
            }
        }

        // Sync each pair's STUN stats, state and nomination from the agent, and drop the pairs
        // it no longer holds.
        self.pipeline_context.stats.sync_ice_candidate_pairs(&pairs);

        // And the candidates it no longer holds (an ICE restart lets go of them), unless a
        // pair that is still reported names them.
        let agent = &self
            .pipeline_context
            .ice_handler_context
            .ice_transport
            .agent;
        let local_held: HashSet<String> = agent
            .get_local_candidates()
            .iter()
            .map(|c| local_candidate_stats_id(c.id()))
            .collect();
        let mut remote_held: HashSet<String> = agent
            .get_remote_candidates()
            .iter()
            .map(|c| remote_candidate_stats_id(c.id()))
            .collect();
        // The mDNS candidates that were submitted for this ICE generation stay in the report
        // whether their name has resolved, has not yet, or never will (mDNS draft section
        // 3.3.1: the report does not leak whether resolution succeeded).
        let remote_ufrag = agent
            .get_remote_credentials()
            .map(|credentials| credentials.ufrag.as_str())
            .unwrap_or_default();
        remote_held.extend(
            self.pipeline_context
                .stats
                .remote_candidates
                .iter()
                .filter(|(_, known)| {
                    known.signalled
                        && known.username_fragment == remote_ufrag
                        && known
                            .address
                            .as_deref()
                            .is_some_and(|address| address.ends_with(".local"))
                })
                .map(|(id, _)| id.clone()),
        );
        self.pipeline_context
            .stats
            .retain_candidates(&local_held, &remote_held);
    }

    /// Update the media source stats from the senders: the track each sender has attached has
    /// a `media-source` object, from the moment it is attached until no sender has it
    /// (webrtc-stats 8.11).
    ///
    /// This is called automatically by `get_stats()`.
    pub(super) fn update_media_source_stats(&mut self) {
        let attached: Vec<(usize, String, RtpCodecKind)> = self
            .rtp_transceivers
            .iter()
            .enumerate()
            .filter_map(|(transceiver_id, transceiver)| {
                let sender = transceiver.sender().as_ref()?;
                Some((
                    transceiver_id,
                    sender.attached_track()?.track_id().clone(),
                    sender.kind(),
                ))
            })
            .collect();
        self.pipeline_context.stats.sync_media_sources(&attached);
    }

    /// Whether `selector` names a sender or a receiver of this peer connection (or nothing).
    pub(super) fn stats_selector_is_ours(&self, selector: &StatsSelector) -> bool {
        match selector {
            StatsSelector::Sender(id) => self
                .rtp_transceivers
                .get(id.0)
                .is_some_and(|transceiver| transceiver.sender().is_some()),
            StatsSelector::Receiver(id) => self
                .rtp_transceivers
                .get(id.0)
                .is_some_and(|transceiver| transceiver.receiver().is_some()),
            _ => true,
        }
    }

    /// Update the transport stats from the DTLS transport itself: webrtc-stats
    /// `RTCTransportStats.dtlsState` is the `RTCDtlsTransport`'s state, which goes through
    /// `new`, `connecting`, `connected`, `closed` and `failed`, not only `connected`. (The ICE
    /// state follows the agent's events already.)
    ///
    /// This is called automatically by `get_stats()`.
    pub(super) fn update_transport_stats(&mut self) {
        let dtls_state = self.dtls_transport().state();
        // webrtc-stats `iceLocalUsernameFragment`: the local username fragment in use for
        // message validation, which is the ICE agent's current one: the first description's,
        // then each applied restart's.
        let ufrag = self
            .ice_transport()
            .get_local_user_credentials()
            .0
            .to_owned();
        let transport = &mut self.pipeline_context.stats.transport;
        transport.on_dtls_state_changed(dtls_state);
        transport.ice_local_username_fragment = ufrag;
    }

    /// Update the data channel stats from the data channels themselves: every channel the peer
    /// connection holds has a stats object, from `connecting` (before it opens) through
    /// `closing` (once `close()` is called), not only from its open.
    ///
    /// This is called automatically by `get_stats()`. A channel that has gone from the registry
    /// keeps the stats object its close left (`closed`), as webrtc-stats keeps a closed channel's.
    pub(super) fn update_data_channel_stats(&mut self) {
        let channels: Vec<_> = self
            .data_channels
            .values()
            .map(|dc| {
                (
                    dc.id,
                    dc.label.clone(),
                    dc.protocol.clone(),
                    dc.ready_state,
                    dc.stream_id,
                )
            })
            .collect();
        for (id, label, protocol, state, stream_id) in channels {
            self.pipeline_context
                .stats
                .get_or_create_data_channel(id, &label, &protocol)
                .on_state_changed(state);
            if let Some(stream_id) = stream_id {
                self.pipeline_context
                    .stats
                    .set_data_channel_stream_id(id, stream_id);
            }
        }
    }

    /// Drops the stats of the RTP streams whose SSRC no longer belongs to a receiver's or a
    /// sender's track (a stopped transceiver, a removed track, a rebound simulcast layer), and
    /// with them their RTX / FEC reverse lookups. The outbound streams that stay take their
    /// encoding's `active` (webrtc-stats `RTCOutboundRtpStreamStats.active`: whether the stream
    /// is configured to be sent, which `set_parameters` changes).
    ///
    /// This is called automatically by `get_stats()`.
    pub(super) fn retire_rtp_stream_stats(&mut self) {
        let mut inbound_live = HashSet::new();
        let mut outbound_live = HashSet::new();
        let mut outbound_active = Vec::new();
        for transceiver in &self.rtp_transceivers {
            if let Some(receiver) = transceiver.receiver() {
                inbound_live.extend(
                    receiver
                        .track()
                        .codings()
                        .iter()
                        .filter_map(|coding| coding.rtp_coding_parameters.ssrc),
                );
            }
            if let Some(sender) = transceiver.sender() {
                outbound_live.extend(
                    sender
                        .track()
                        .codings()
                        .iter()
                        .filter_map(|coding| coding.rtp_coding_parameters.ssrc),
                );
                outbound_active.extend(sender.send_encodings().iter().filter_map(|encoding| {
                    Some((encoding.rtp_coding_parameters.ssrc?, encoding.active))
                }));
            }
        }
        let stats = &mut self.pipeline_context.stats;
        stats.retire_rtp_streams(&inbound_live, &outbound_live);
        for (ssrc, active) in outbound_active {
            if let Some(stream) = stats.outbound_rtp_streams.get_mut(&ssrc) {
                stream.active = active;
            }
        }
    }

    /// The transceiver, id and kind of the track `sender` sends: what the stats of its media
    /// source are keyed and linked by. `None` for a sender that does not exist.
    pub(crate) fn sender_track_for_stats(
        &self,
        sender: crate::rtp_transceiver::RTCRtpSenderId,
    ) -> Option<(usize, String, RtpCodecKind)> {
        let transceiver_id = sender.0;
        let sender = self
            .rtp_transceivers
            .get(transceiver_id)?
            .sender()
            .as_ref()?;
        Some((
            transceiver_id,
            sender.attached_track()?.track_id().clone(),
            sender.kind(),
        ))
    }

    /// Update codec stats from transceivers to the stats accumulator.
    ///
    /// This is called automatically by `get_stats()` to ensure codec statistics
    /// are registered for all active RTP streams. Per W3C spec, codecs are only
    /// exposed when referenced by an RTP stream.
    pub(super) fn update_codec_stats(&mut self) {
        // Collect codec info from transceivers to avoid borrow conflicts
        let mut inbound_codecs: Vec<(u32, RTCRtpCodec, PayloadType)> = Vec::new();
        let mut outbound_codecs: Vec<(u32, RTCRtpCodec, PayloadType)> = Vec::new();

        for transceiver in &self.rtp_transceivers {
            // Process receivers (inbound streams)
            if let Some(receiver) = transceiver.receiver() {
                let codec_prefs = receiver.get_codec_preferences();
                let track = receiver.track();

                for coding in track.codings() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        // Find the codec for this encoding
                        if let Some(codec) = track.get_codec_by_ssrc(ssrc)
                            && !codec.mime_type.is_empty()
                                // Find matching payload type from codec preferences
                                && let Some(codec_params) = codec_prefs.iter().find(|cp| {
                                    cp.rtp_codec.mime_type == codec.mime_type
                                        && (cp.rtp_codec.sdp_fmtp_line.is_empty()
                                            || cp.rtp_codec.sdp_fmtp_line == codec.sdp_fmtp_line)
                                })
                        {
                            inbound_codecs.push((ssrc, codec.clone(), codec_params.payload_type));
                        }
                    }
                }
            }

            // Process senders (outbound streams)
            if let Some(sender) = transceiver.sender()
                && sender.has_sent()
            {
                let track = sender.track();
                let send_codecs = sender.get_send_codecs();
                for coding in track.codings() {
                    if let Some(ssrc) = coding.rtp_coding_parameters.ssrc {
                        let codec = &coding.codec;
                        if codec.mime_type.is_empty() {
                            // An encoding without a codec of its own is sent with the codec
                            // negotiation picked; its stream references that one (and takes its
                            // clock rate, which the remote-inbound jitter is converted with).
                            if let Some(codec_params) = encoding_send_codec(codec, send_codecs) {
                                outbound_codecs.push((
                                    ssrc,
                                    codec_params.rtp_codec,
                                    codec_params.payload_type,
                                ));
                            }
                        } else if let Some(codec_params) = send_codecs.iter().find(|cp| {
                            // Find matching payload type from send codecs
                            cp.rtp_codec.mime_type == codec.mime_type
                                && (cp.rtp_codec.sdp_fmtp_line.is_empty()
                                    || cp.rtp_codec.sdp_fmtp_line == codec.sdp_fmtp_line)
                        }) {
                            outbound_codecs.push((ssrc, codec.clone(), codec_params.payload_type));
                        }
                    }
                }
            }
        }

        // Register inbound codecs
        for (ssrc, codec, payload_type) in inbound_codecs {
            self.pipeline_context
                .stats
                .register_inbound_codec(ssrc, &codec, payload_type);
        }

        // Register outbound codecs
        for (ssrc, codec, payload_type) in outbound_codecs {
            self.pipeline_context
                .stats
                .register_outbound_codec(ssrc, &codec, payload_type);
        }

        // Clean up unreferenced codecs
        self.pipeline_context.stats.cleanup_unreferenced_codecs();
    }

    pub(super) fn codec_preferences_from_encodings(
        &self,
        kind: RtpCodecKind,
        encodings: &[RTCRtpEncodingParameters],
    ) -> Result<Vec<RTCRtpCodecParameters>> {
        let media_engine_codecs = self.media_engine.get_codecs_by_kind(kind);
        let mut codec_preferences = vec![];

        for encoding in encodings {
            if encoding.codec.mime_type.is_empty() {
                continue;
            }

            let (codec, match_type) =
                codec_parameters_fuzzy_search(&encoding.codec, &media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }

            if !codec_preferences
                .iter()
                .any(|preference: &RTCRtpCodecParameters| {
                    preference.payload_type == codec.payload_type
                })
            {
                codec_preferences.push(codec);
            }
        }

        // The encodings name media codecs; the repair formats that accompany them (RTX for a
        // named primary, FEC, RED) stay offered, so they are listed too (a preference list
        // keeps only the repair kinds it lists, RTCRtpReceiverInternal::get_codecs).
        if !codec_preferences.is_empty() {
            for codec in &media_engine_codecs {
                if !is_repair_codec(&codec.rtp_codec)
                    || codec_preferences
                        .iter()
                        .any(|preference| preference.payload_type == codec.payload_type)
                {
                    continue;
                }
                if let Some(apt) = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
                    && !codec_preferences
                        .iter()
                        .any(|preference| preference.payload_type == apt)
                {
                    continue;
                }
                codec_preferences.push(codec.clone());
            }
        }

        Ok(codec_preferences)
    }

    pub(super) fn normalize_sender_track(
        &self,
        track: MediaStreamTrack,
        mut send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Result<(
        MediaStreamTrack,
        Vec<RTCRtpEncodingParameters>,
        Vec<RTCRtpCodecParameters>,
    )> {
        // RTX is the implementation's choice, not the application's (W3C webrtc-pc has no
        // `rtx` member in `sendEncodings`): encodings the application gave get a repair flow
        // whenever the media engine can carry one, as those `send_encodings_from_track` derives
        // from the track do. Without it, NACKed packets could only be resent on the media SSRC
        // and the outbound stream would have no `rtxSsrc`. A negotiation without RTX drops it
        // again (`configure_rtx_and_fec`).
        let is_rtx_enabled = self
            .media_engine
            .is_rtx_enabled(track.kind(), RTCRtpTransceiverDirection::Sendonly);
        for encoding in &mut send_encodings {
            if encoding.rtp_coding_parameters.ssrc.is_none() {
                encoding.rtp_coding_parameters.ssrc = Some(rand::random::<u32>());
            }
            if is_rtx_enabled && encoding.rtp_coding_parameters.rtx.is_none() {
                encoding.rtp_coding_parameters.rtx = Some(RTCRtpRtxParameters {
                    ssrc: rand::random::<u32>(),
                });
            }
        }

        let codec_preferences =
            self.codec_preferences_from_encodings(track.kind(), &send_encodings)?;
        let has_rid = send_encodings
            .iter()
            .any(|encoding| !encoding.rtp_coding_parameters.rid.is_empty());
        let all_have_rid = send_encodings
            .iter()
            .all(|encoding| !encoding.rtp_coding_parameters.rid.is_empty());
        if send_encodings.len() > 1 && has_rid && !all_have_rid {
            return Err(Error::ErrRTPSenderRidNil);
        }
        // W3C webrtc-pc addTransceiver: a rid that "does not conform to the grammar
        // requirements specified in Section 10 of [RFC8851]" is a TypeError. The rid is sent as
        // the RtpStreamId of RFC 8852, whose section 3.1 narrows it to 1 to 255 alphanumeric
        // characters; a rid outside that could be signalled but never sent.
        if send_encodings.iter().any(|encoding| {
            let rid = &encoding.rtp_coding_parameters.rid;
            !rid.is_empty() && (rid.len() > 255 || !rid.bytes().all(|b| b.is_ascii_alphanumeric()))
        }) {
            return Err(Error::ErrRTPSenderRidInvalid);
        }

        let is_simulcast = send_encodings.len() > 1 && all_have_rid;
        // A rid names one encoding (RFC 8851 §4: rid-ids are unique within the m= section, and
        // W3C addTransceiver refuses a repeated rid); two alike would be written as duplicate
        // `a=rid` lines.
        if is_simulcast
            && send_encodings.iter().enumerate().any(|(i, encoding)| {
                send_encodings[..i].iter().any(|earlier| {
                    earlier.rtp_coding_parameters.rid == encoding.rtp_coding_parameters.rid
                })
            })
        {
            return Err(Error::ErrRTPSenderRIDCollision);
        }
        if !is_simulcast {
            send_encodings.truncate(1);
        }

        let track = MediaStreamTrack::new(
            track.stream_id().clone(),
            track.track_id().clone(),
            track.label().clone(),
            track.kind(),
            send_encodings.clone(),
        );

        Ok((track, send_encodings, codec_preferences))
    }
}

fn is_same_remote_track(
    receiver: &RTCRtpReceiverInternal,
    incoming_track: &sdp::TrackDetails,
) -> bool {
    let track = receiver.track();
    // A description without msid-appdata leaves the track id to this side: any id it gave
    // the track is the same track.
    if (!incoming_track.track_id.is_empty() && track.track_id() != &incoming_track.track_id)
        || track.track_id().is_empty()
        || track.stream_id() != &incoming_track.stream_id
    {
        return false;
    }

    let codings = receiver.get_coding_parameters();
    if !incoming_track.rids.is_empty() {
        let mut current: Vec<&str> = codings.iter().map(|c| c.rid.as_str()).collect();
        let mut remote: Vec<&str> = incoming_track.rids.iter().map(String::as_str).collect();
        current.sort_unstable();
        remote.sort_unstable();
        return current == remote;
    }

    match (codings, incoming_track.ssrc) {
        ([coding], Some(ssrc)) => {
            coding.rid.is_empty()
                && coding.ssrc == Some(ssrc)
                && coding.rtx.as_ref().map(|r| r.ssrc) == incoming_track.rtx_ssrc
                && coding.fec.as_ref().map(|f| f.ssrc) == incoming_track.fec_ssrc
        }
        _ => false,
    }
}

/// A mid for a new data m= section: the number of m= sections so far, or the next number that
/// no m= section and no transceiver has (a stopped transceiver left out of the offer keeps its
/// mid, which must not come back on another section).
fn free_data_mid(
    media_sections: &[MediaSection],
    transceivers: &[RTCRtpTransceiverInternal],
) -> String {
    let mut n = media_sections.len();
    loop {
        let mid = n.to_string();
        if !media_sections.iter().any(|s| s.mid == mid)
            && !transceivers.iter().any(|t| t.mid().as_ref() == Some(&mid))
        {
            return mid;
        }
        n += 1;
    }
}

/// The direction an answer states for a media section offered with `offered`: `local` (the
/// transceiver's [[Direction]]) intersected with the reverse of the offered direction (RFC 9429
/// section 5.3.1, RFC 3264 section 6.1). A section with no direction attribute is sendrecv
/// (RFC 3264 section 5.1).
pub(crate) fn answered_direction(
    local: RTCRtpTransceiverDirection,
    offered: RTCRtpTransceiverDirection,
) -> RTCRtpTransceiverDirection {
    let offered = if offered == RTCRtpTransceiverDirection::Unspecified {
        RTCRtpTransceiverDirection::Sendrecv
    } else {
        offered
    };
    local.intersect(offered.reverse())
}

/// `a=rtcp-xr` (RFC 3611 section 5.1).
const ATTR_KEY_RTCP_XR: &str = "rtcp-xr";

/// Whether the offerer-tagged section of `offer` (the first tag of its BUNDLE group that is not
/// rejected, RFC 9143 section 7.2) carries `a=rtcp-mux-only`.
fn offerer_tagged_section_is_rtcp_mux_only(offer: &SessionDescription) -> bool {
    bundle_group_mids(offer)
        .into_iter()
        .find_map(|tag| {
            offer.media_descriptions.iter().find(|media| {
                get_mid_value(media).is_some_and(|mid| mid == tag) && !is_rejected_media(media)
            })
        })
        .is_some_and(|media| media.has_attribute(ATTR_KEY_RTCP_MUX_ONLY))
}

/// Whether the description has m-sections and rejects every one (port 0): a completed
/// offer/answer like that leaves no transport (RFC 8843 §7.1.3, RFC 9429 §5.10).
fn rejects_every_media_section(desc: &RTCSessionDescription) -> bool {
    desc.parsed.as_ref().is_some_and(|parsed| {
        !parsed.media_descriptions.is_empty()
            && parsed.media_descriptions.iter().all(is_rejected_media)
    })
}

/// The transport a TURN URL (RFC 7065) says its server is reached over: TLS for `turns:`, else
/// the `transport` parameter, UDP when there is none. `Unspecified` for anything that is not a
/// TURN URL.
fn relay_protocol_of_turn_url(url: &str) -> RTCIceServerTransportProtocol {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("turns:") {
        return RTCIceServerTransportProtocol::Tls;
    }
    if !lower.starts_with("turn:") {
        return RTCIceServerTransportProtocol::Unspecified;
    }
    match lower
        .split_once("?transport=")
        .map(|(_, transport)| transport)
    {
        Some("tcp") => RTCIceServerTransportProtocol::Tcp,
        _ => RTCIceServerTransportProtocol::Udp,
    }
}

#[cfg(test)]
mod transport_closed_tests {
    use super::*;
    use crate::peer_connection::sdp::session_description::RTCSessionDescription;

    fn offer(media: &str) -> RTCSessionDescription {
        let sdp =
            format!("v=0\r\no=- 1 2 IN IP4 0.0.0.0\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 1\r\n{media}");
        RTCSessionDescription::offer(sdp).expect("offer")
    }

    /// A description whose every m-section is rejected closes the transport; one live section
    /// or none at all does not.
    #[test]
    fn rejects_every_media_section_only_when_all_are_rejected() {
        let rejected_video =
            "m=video 0 UDP/TLS/RTP/SAVPF 120\r\nc=IN IP4 0.0.0.0\r\na=inactive\r\na=mid:0\r\n";
        let live_audio = "m=audio 9 UDP/TLS/RTP/SAVPF 109\r\nc=IN IP4 0.0.0.0\r\na=mid:1\r\n\
                          a=ice-ufrag:abcd\r\na=ice-pwd:abcdefghijklmnopqrstuv\r\n\
                          a=rtpmap:109 opus/48000/2\r\n";
        assert!(rejects_every_media_section(&offer(rejected_video)));
        assert!(!rejects_every_media_section(&offer(&format!(
            "{rejected_video}{live_audio}"
        ))));
        assert!(!rejects_every_media_section(&offer("")));
    }
}

#[cfg(test)]
mod rejected_mline_generate_matched_sdp_tests {
    use super::*;
    use crate::peer_connection::configuration::media_engine::{MIME_TYPE_VP8, MediaEngine};
    use crate::peer_connection::sdp::session_description::RTCSessionDescription;
    use crate::rtp_transceiver::rtp_sender::RTCRtpCodec;
    use crate::rtp_transceiver::rtp_sender::rtp_codec::RtpCodecKind;
    use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;

    /// Helper: build a peer connection with video-only codec support.
    fn build_video_only_pc() -> RTCPeerConnection {
        let mut me = MediaEngine::default();
        me.register_codec(
            RTCRtpCodecParameters {
                rtp_codec: RTCRtpCodec {
                    mime_type: MIME_TYPE_VP8.to_owned(),
                    clock_rate: 90000,
                    channels: 0,
                    sdp_fmtp_line: String::new(),
                    rtcp_feedback: vec![],
                },
                payload_type: 96,
            },
            RtpCodecKind::Video,
        )
        .unwrap();

        let se = crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::new()
            .with_answering_dtls_role(RTCDtlsRole::Client)
            .build();

        RTCPeerConnectionBuilder::new()
            .with_media_engine(me)
            .with_setting_engine(se)
            .build(std::time::Instant::now())
            .unwrap()
    }

    /// Offer with audio (port=0) rejected and video active.
    /// Exercises the `media.media_name.port.value == 0` branch for audio kind.
    #[test]
    fn test_generate_matched_sdp_rejected_audio_port_zero() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic: WMS\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:11111 cname:test\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // Video should be accepted (non-zero port)
        let video = lines.iter().find(|l| l.starts_with("m=video")).unwrap();
        assert!(
            !video.starts_with("m=video 0"),
            "video must not be rejected"
        );

        // Audio should be rejected (port=0) in the answer
        let audio = lines.iter().find(|l| l.starts_with("m=audio")).unwrap();
        assert!(
            audio.starts_with("m=audio 0"),
            "rejected audio m-line must have port 0, got: {audio}"
        );

        // Must have exactly 2 m-lines
        let m_count = lines.iter().filter(|l| l.starts_with("m=")).count();
        assert_eq!(m_count, 2, "answer must preserve m-line count");
    }

    /// Offer with application/datachannel (port=0) rejected.
    /// Exercises the `media.media_name.port.value == 0` branch for application kind.
    #[test]
    fn test_generate_matched_sdp_rejected_application_port_zero() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
a=msid-semantic: WMS\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:0\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:11111 cname:test\r\n\
m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // Application m-line must be rejected (port=0) with SCTP proto
        let app = lines
            .iter()
            .find(|l| l.starts_with("m=application"))
            .unwrap();
        assert!(
            app.starts_with("m=application 0"),
            "rejected application m-line must have port 0, got: {app}"
        );
    }

    /// First m-line is rejected (port=0), second is active video.
    /// Tests that ICE candidates are correctly added to the first *non-rejected* m-line.
    #[test]
    fn test_generate_matched_sdp_first_mline_rejected() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 1\r\n\
a=msid-semantic: WMS\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:1\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:22222 cname:test\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // First m-line (audio) must be rejected
        let audio = lines.iter().find(|l| l.starts_with("m=audio")).unwrap();
        assert!(audio.starts_with("m=audio 0"), "audio must be rejected");

        // Second m-line (video) must be accepted
        let video = lines.iter().find(|l| l.starts_with("m=video")).unwrap();
        assert!(!video.starts_with("m=video 0"), "video must be accepted");

        // The rejected audio m-line must NOT have ICE attributes
        // Find the audio section and check for ice-ufrag
        let mut in_audio = false;
        let mut audio_has_ice = false;
        for line in &lines {
            if line.starts_with("m=audio") {
                in_audio = true;
            } else if line.starts_with("m=") {
                in_audio = false;
            }
            if in_audio && line.starts_with("a=ice-ufrag") {
                audio_has_ice = true;
            }
        }
        assert!(
            !audio_has_ice,
            "rejected audio m-line must not contain ICE attributes"
        );
    }

    /// All m-lines rejected (port=0). Answer must preserve all with port=0.
    #[test]
    fn test_generate_matched_sdp_all_mlines_rejected() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=msid-semantic: WMS\r\n\
m=video 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:1\r\n\
m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:2\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        // All 3 m-lines must be present and rejected
        let m_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("m=")).collect();
        assert_eq!(m_lines.len(), 3, "must have 3 m-lines");

        for m in &m_lines {
            // Extract the port (second space-separated token)
            let port: &str = m.split_whitespace().nth(1).unwrap();
            assert_eq!(port, "0", "all m-lines must have port=0, got: {m}");
        }
    }

    /// Mix of rejected and accepted m-lines in various positions.
    /// audio(rejected) -> video(accepted) -> application(rejected)
    #[test]
    fn test_generate_matched_sdp_mixed_rejected_accepted() {
        let offer_sdp = "\
v=0\r\n\
o=- 0 0 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 1\r\n\
a=msid-semantic: WMS\r\n\
m=audio 0 UDP/TLS/RTP/SAVPF 0\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 0.0.0.0\r\n\
a=ice-ufrag:test\r\n\
a=ice-pwd:testpasswordtestpassword\r\n\
a=fingerprint:sha-256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00\r\n\
a=setup:actpass\r\n\
a=mid:1\r\n\
a=sendonly\r\n\
a=rtcp-mux\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:33333 cname:test\r\n\
m=application 0 UDP/DTLS/SCTP webrtc-datachannel\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:2\r\n";

        let mut pc = build_video_only_pc();
        let offer = RTCSessionDescription::offer(offer_sdp.to_string()).unwrap();
        pc.set_remote_description(std::time::Instant::now(), offer)
            .unwrap();

        let answer = pc.create_answer(None).unwrap();
        let lines: Vec<&str> = answer.sdp.lines().collect();

        let m_lines: Vec<&&str> = lines.iter().filter(|l| l.starts_with("m=")).collect();
        assert_eq!(m_lines.len(), 3, "answer must have 3 m-lines");

        // audio rejected
        assert!(
            m_lines[0].starts_with("m=audio 0"),
            "audio must be rejected, got: {}",
            m_lines[0]
        );
        // video accepted
        assert!(
            m_lines[1].starts_with("m=video") && !m_lines[1].starts_with("m=video 0"),
            "video must be accepted, got: {}",
            m_lines[1]
        );
        // application rejected
        assert!(
            m_lines[2].starts_with("m=application 0"),
            "application must be rejected, got: {}",
            m_lines[2]
        );
    }
}

/// The most remote-candidate statistics objects held while an mDNS candidate that the agent
/// does not hold (unresolved, or ignored) is still given one: what a remote description can
/// make the report grow to.
const MAX_UNRESOLVED_MDNS_CANDIDATE_STATS: usize = 320;

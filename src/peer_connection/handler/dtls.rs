use crate::peer_connection::configuration::setting_engine::ReplayProtection;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::dtls::resumption::{StartGate, leader_wait_bound};
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
use crate::peer_connection::transport::dtls::{DTLS_SRTP_FLIGHT_INTERVAL, DtlsTransport};
use crate::statistics::accumulator::{
    CertificateStatsAccumulator, RTCStatsAccumulator, base64_encode,
};
use crypto::RTCCryptoProvider;
use dtls::endpoint::EndpointEvent;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls::state::State;
use log::{debug, warn};
use shared::TransportContext;
use shared::error::{Error, Result};
use srtp::option::{srtcp_replay_protection, srtp_replay_protection};
use srtp::protection_profile::ProtectionProfile;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

#[cfg(test)]
mod tls_version_test;

pub(crate) struct DtlsHandlerContext {
    pub(crate) dtls_transport: DtlsTransport,

    pub(crate) read_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) write_outs: VecDeque<TaggedRTCMessageInternal>,
    pub(crate) event_outs: VecDeque<TaggedRTCEventInternal>,

    /// Set by [`DtlsHandler::request_close`]: queue a `close_notify`, stamped with this instant,
    /// at the next `poll_write`.
    pub(crate) close_requested: Option<Instant>,

    /// Set when a new DTLS association replaces the old one on an ICE transport that already
    /// has a selected pair (RFC 8842 section 3.1: a changed fingerprint, `tls-id` or role with
    /// no ICE restart): no `ICESelectedCandidatePairChange` will come to start the client's
    /// handshake, so the next `poll_write` starts it, stamped with this instant.
    pub(crate) connect_requested: Option<Instant>,

    /// Set when the client's handshake was due while another transport of the connection was
    /// establishing the connection's DTLS session (RFC 5764 section 3): it starts, offering
    /// a ticket of that session if one came, once the other is done
    /// (`DtlsSessionGroup::ready_at`), and with a full handshake at the latest at the second
    /// instant (`leader_wait_bound`: `LEADER_WAIT_FLIGHTS` of its initial flight intervals
    /// after the first, the instant it was due at, and at most `LEADER_WAIT_MAX`).
    pub(crate) waiting_for_session: Option<(Instant, Instant)>,

    /// Set when the client's first flight was left in the endpoint on a pair change (see
    /// `start_client_handshake`), to the instant the handshake started: `poll_timeout` names
    /// it, so the next `handle_timeout`, at once, hands the flight out (RFC 8842 section 5:
    /// the `active` endpoint starts the handshake when ICE has a path; RFC 6347 section 4.2.4
    /// and RFC 9147 section 5.8 time the flight's retransmission, not its first sending).
    pub(crate) first_flight_due: Option<Instant>,
}

impl DtlsHandlerContext {
    pub(crate) fn new(dtls_transport: DtlsTransport) -> Self {
        Self {
            dtls_transport,
            read_outs: VecDeque::new(),
            write_outs: VecDeque::new(),
            event_outs: VecDeque::new(),
            close_requested: None,
            connect_requested: None,
            waiting_for_session: None,
            first_flight_due: None,
        }
    }
}

/// DtlsHandler implements DTLS Protocol handling
pub(crate) struct DtlsHandler<'a> {
    ctx: &'a mut DtlsHandlerContext,
    stats: &'a mut RTCStatsAccumulator,
}

impl<'a> DtlsHandler<'a> {
    /// Asks for a `close_notify` alert (RFC 5246 §7.2.1) to be sent to the peer, so that closing
    /// the connection tells the peer at once instead of leaving it to notice by timeout
    /// (rtc#255).
    ///
    /// The alert is queued at this handler's next `poll_write`, not here. In a pipeline flush that
    /// is after this handler has taken the writes still coming down from above, so they are
    /// encrypted while the connection exists and go out before the alert, and before the ICE
    /// handler routes them all.
    pub(crate) fn request_close(&mut self, now: Instant) {
        self.ctx.close_requested = Some(now);
    }

    /// Queues the `close_notify` for every connection and closes the endpoint. A no-op before
    /// DTLS has started or once the transport is closed.
    fn queue_close_notify(&mut self, now: Instant) -> Result<()> {
        if self.ctx.dtls_transport.state == RTCDtlsTransportState::Closed {
            return Ok(());
        }
        let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_mut() else {
            return Ok(());
        };
        dtls_endpoint.close(now)?;
        while let Some(transmit) = dtls_endpoint.poll_transmit() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
            });
        }
        Ok(())
    }

    pub(crate) fn new(ctx: &'a mut DtlsHandlerContext, stats: &'a mut RTCStatsAccumulator) -> Self {
        DtlsHandler { ctx, stats }
    }

    /// Starts the client's handshake (RFC 8842 section 5.3 / 5.4: the endpoint that is
    /// `active` sends the ClientHello) and queues its first flight. A no-op for a server, and
    /// for a client whose handshake has started: the config is held only until then.
    fn connect_client(&mut self, now: Instant, queue_flight: bool) -> Result<()> {
        if self.ctx.dtls_transport.dtls_role != RTCDtlsRole::Client {
            return Ok(());
        }
        // dtls_endpoint only connect once when acts as DTLSRole::Client
        if self.ctx.dtls_transport.dtls_handshake_config.is_none() {
            return Ok(());
        }
        // RFC 5764 section 3: "all other DTLS associations wait until that connection is
        // established before proceeding with their handshakes", for a bounded time.
        if let Some(group) = self.ctx.dtls_transport.session_group()
            && group.start_gate(&self.ctx.dtls_transport.resumption_token, now) == StartGate::Wait
        {
            if self.ctx.waiting_for_session.is_none() {
                let bound = leader_wait_bound(self.initial_flight_interval());
                debug!("dtls handshake waits for the connection's session, at most {bound:?}");
                self.ctx.waiting_for_session = Some((now, now + bound));
            }
            return Ok(());
        }
        self.start_client_handshake(now, queue_flight)
    }

    /// The initial value of the client's retransmission timer (RFC 9147 section 5.8.2): where
    /// ICE has measured the round trip time of the path, the retransmission timer starts from
    /// 1.5 times it (`DtlsFlightInterval`; libwebrtc's rule takes twice it).
    fn initial_flight_interval(&self) -> std::time::Duration {
        self.ctx
            .dtls_transport
            .flight_interval_rule
            .initial(self.selected_pair_round_trip_time())
    }

    /// Sends the client's ClientHello now, whatever other transports do.
    fn start_client_handshake(&mut self, now: Instant, queue_flight: bool) -> Result<()> {
        self.ctx.waiting_for_session = None;
        let Some(dtls_handshake_config) = self.ctx.dtls_transport.dtls_handshake_config.take()
        else {
            return Ok(());
        };
        let dtls_handshake_config = match self.selected_pair_round_trip_time() {
            Some(_) => {
                Arc::new(dtls_handshake_config.with_flight_interval(self.initial_flight_interval()))
            }
            None => dtls_handshake_config,
        };
        self.ctx.dtls_transport.flight_interval = Some(dtls_handshake_config.flight_interval());
        self.ctx.dtls_transport.handshake_began = Some(now);
        let token = self.ctx.dtls_transport.resumption_token.clone();
        let group = self.ctx.dtls_transport.session_group().cloned();
        let connected = match self.ctx.dtls_transport.dtls_endpoint.as_mut() {
            Some(dtls_endpoint) => dtls_endpoint.connect(
                now,
                TransportContext::default().peer_addr, // always use default for transport to make DTLS tunneled
                dtls_handshake_config,
                None,
            ),
            None => Err(Error::ErrDtlsTransportNotStarted),
        };
        // The ClientHello took its ticket, if there was one. A handshake that could not
        // start leads nothing: the others start too (review F9).
        if let Some(group) = group {
            match connected {
                Ok(()) => group.started(&token),
                Err(_) => group.ended(&token, Some(now)),
            }
        }
        connected?;
        let dtls_endpoint = self
            .ctx
            .dtls_transport
            .dtls_endpoint
            .as_mut()
            .ok_or(Error::ErrDtlsTransportNotStarted)?;
        // On a pair change the first flight is left in the endpoint and goes out with the
        // next read or timeout, once every handler has seen the event (the ICE handler counts
        // a pair's packets from then); `poll_timeout` names the instant, so that timeout is
        // at once. Asked for outside an event, it is queued here.
        if !queue_flight {
            self.ctx.first_flight_due = Some(now);
        } else {
            while let Some(transmit) = dtls_endpoint.poll_transmit() {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
                });
            }
        }
        Ok(())
    }

    pub(crate) fn name(&self) -> &'static str {
        "DtlsHandler"
    }

    /// The selected pair changed. When it is a change of path (not the first selection), an
    /// association that sends connection ids switches to a fresh one (RFC 9147 sections 9
    /// and 11), so that the records on the new path cannot be linked to the old by it.
    fn on_new_path(&mut self, now: Instant) {
        let current = self.stats.transport.selected_candidate_pair_id.clone();
        let previous = self
            .ctx
            .dtls_transport
            .selected_pair_id
            .replace(current.clone());
        if previous.is_none_or(|previous| previous == current) {
            return;
        }
        let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_mut() else {
            return;
        };
        let remote = TransportContext::default().peer_addr;
        match dtls_endpoint.path_changed(now, remote) {
            Ok(switched) => debug!("new ICE path: switched to a fresh connection id: {switched}"),
            Err(err) => debug!("new ICE path: connection ids unchanged: {err}"),
        }
        while let Some(transmit) = dtls_endpoint.poll_transmit() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
            });
        }
    }

    /// The round trip time ICE has measured on the selected candidate pair, if it has.
    fn selected_pair_round_trip_time(&self) -> Option<std::time::Duration> {
        let pair = self
            .stats
            .ice_candidate_pairs
            .get(&self.stats.transport.selected_candidate_pair_id)?;
        (pair.current_round_trip_time > 0.0)
            .then(|| std::time::Duration::try_from_secs_f64(pair.current_round_trip_time).ok())
            .flatten()
    }

    /// Update stats when DTLS handshake completes
    fn update_dtls_stats_from_profile(
        &mut self,
        srtp_profile: SrtpProtectionProfile,
        peer_certificates: &[Vec<u8>],
        dtls_cipher: Option<String>,
        version: Option<dtls::config::DtlsVersion>,
    ) -> Result<()> {
        // Update transport DTLS state
        self.stats
            .transport
            .on_dtls_state_changed(RTCDtlsTransportState::Connected);

        // Retain the peer's chain for `DtlsTransport::get_remote_certificates()`. The stats
        // registration below keeps only a fingerprint-derived id, which is not reversible.
        self.ctx.dtls_transport.remote_certificates = peer_certificates.to_vec();

        // Update DTLS role from transport
        self.stats.transport.dtls_role = self.ctx.dtls_transport.dtls_role;

        // Update SRTP cipher from DTLS negotiation
        let srtp_cipher = match srtp_profile {
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => "SRTP_AEAD_AES_128_GCM",
            SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => "SRTP_AEAD_AES_256_GCM",
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => "SRTP_AES128_CM_HMAC_SHA1_80",
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => "SRTP_AES128_CM_HMAC_SHA1_32",
            // No `use_srtp` on this association (a data-channel-only peer): no SRTP cipher.
            SrtpProtectionProfile::Unsupported => "",
            _ => "Unknown",
        };
        self.stats.transport.srtp_cipher = srtp_cipher.to_string();

        // webrtc-stats `tlsVersion`: the negotiated version as the uppercase hex of its two
        // bytes: "FEFD" for DTLS 1.2 (RFC 6347 section 4.1, `{254, 253}`), "FEFC" for DTLS
        // 1.3 (RFC 9147 section 5.3, the value of `supported_versions`).
        let version = version
            .unwrap_or(dtls::config::DtlsVersion::Dtls1_2)
            .protocol_version();
        self.stats.transport.tls_version = format!("{:02X}{:02X}", version.major, version.minor);

        // Update DTLS cipher from the negotiated cipher suite
        if let Some(cipher) = dtls_cipher {
            self.stats.transport.dtls_cipher = cipher;
        }

        // Register the local certificate and the certificates it was issued through, and set
        // local_certificate_id
        if let Some(local_cert) = self.ctx.dtls_transport.certificates.first() {
            let fingerprints =
                local_cert.get_fingerprints(self.ctx.dtls_transport.crypto_provider.crypto())?;
            if let Some(fp) = fingerprints.first() {
                let chain: Vec<Vec<u8>> = local_cert
                    .dtls_certificate
                    .certificate
                    .iter()
                    .map(|der| der.as_ref().to_vec())
                    .collect();
                let issuer_certificate_id = self.register_issuers(&chain, "local")?;
                // Register certificate in accumulator, the DER base64-encoded (webrtc-stats
                // `base64Certificate`)
                if let Some(der) = chain.first() {
                    self.stats.register_certificate(
                        fp.value.clone(),
                        CertificateStatsAccumulator {
                            fingerprint: fp.value.clone(),
                            fingerprint_algorithm: fp.algorithm.clone(),
                            base64_certificate: base64_encode(der),
                            issuer_certificate_id,
                        },
                    );
                }

                // Set local certificate ID in transport stats
                self.stats.transport.local_certificate_id = fp.value.clone();
            }
        }

        // Register the remote certificate chain and set remote_certificate_id
        if let Some(peer_cert_der) = peer_certificates.first() {
            let fingerprint = self.sha256_fingerprint(peer_cert_der)?;
            let cert_id = format!("remote-certificate-{}", &fingerprint[..8]);
            let issuer_certificate_id = self.register_issuers(peer_certificates, "remote")?;

            // Register remote certificate in accumulator
            self.stats.register_certificate(
                cert_id.clone(),
                CertificateStatsAccumulator {
                    fingerprint,
                    fingerprint_algorithm: "sha-256".to_string(),
                    base64_certificate: base64_encode(peer_cert_der),
                    issuer_certificate_id,
                },
            );

            // Set remote certificate ID in transport stats
            self.stats.transport.remote_certificate_id = cert_id;
        }
        Ok(())
    }

    /// The SHA-256 fingerprint of a DER certificate, as RFC 8122 writes one (lower case here).
    fn sha256_fingerprint(&self, der: &[u8]) -> Result<String> {
        let hash = self
            .ctx
            .dtls_transport
            .crypto_provider
            .crypto()
            .hash(crypto::HashAlgorithm::Sha256, der)
            .map_err(|error| Error::Crypto(error.to_string()))?;
        Ok(hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":"))
    }

    /// Registers the certificates after the first of `chain` (the ones the end-entity
    /// certificate was issued through, in the order the handshake carried them), each naming
    /// the next as its issuer, and returns the id of the first of them: the end-entity
    /// certificate's `issuerCertificateId` (webrtc-stats 8.22: "the stats object that contains
    /// the next certificate in the certificate chain"). Empty when the chain is one
    /// certificate, as a WebRTC certificate usually is.
    fn register_issuers(&mut self, chain: &[Vec<u8>], side: &str) -> Result<String> {
        let mut issuer_certificate_id = String::new();
        for der in chain.iter().skip(1).rev() {
            let fingerprint = self.sha256_fingerprint(der)?;
            let id = format!("{side}-issuer-certificate-{fingerprint}");
            self.stats.register_certificate(
                id.clone(),
                CertificateStatsAccumulator {
                    fingerprint,
                    fingerprint_algorithm: "sha-256".to_string(),
                    base64_certificate: base64_encode(der),
                    issuer_certificate_id,
                },
            );
            issuer_certificate_id = id;
        }
        Ok(issuer_certificate_id)
    }
}

impl<'a>
    sansio::Protocol<TaggedRTCMessageInternal, TaggedRTCMessageInternal, TaggedRTCEventInternal>
    for DtlsHandler<'a>
{
    type Rout = TaggedRTCMessageInternal;
    type Wout = TaggedRTCMessageInternal;
    type Eout = TaggedRTCEventInternal;
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("recv dtls RAW {:?}", msg.transport.peer_addr);

            // Once the transport is closed, by either side, or has failed, nothing more is
            // exchanged on it. A late datagram (the peer's close_notify reply, say) must not reach
            // an endpoint whose connection is gone, where a server would take it for a new
            // handshake.
            if matches!(
                self.ctx.dtls_transport.state,
                RTCDtlsTransportState::Closed | RTCDtlsTransportState::Failed
            ) {
                debug!(
                    "drop dtls datagram from {:?} on a closed transport",
                    msg.transport.peer_addr
                );
                return Ok(());
            }

            let mut messages = vec![];
            let mut peer_closed = false;
            // `Some` once the handshake completed: the SRTP contexts it keyed, or `None` for an
            // association without `use_srtp`.
            let mut handshake_complete = None;
            let mut handshake_error = None;
            let mut srtp_profile_for_stats: Option<SrtpProtectionProfile> = None;
            let mut peer_certificates_for_stats: Vec<Vec<u8>> = vec![];
            let mut dtls_cipher_for_stats: Option<String> = None;
            let mut dtls_version_for_stats = None;
            let mut application_protocol = None;

            // The server's handshake begins with the first datagram it reads for the
            // association (the client's begins with its first flight, `connect_client`).
            if self.ctx.dtls_transport.state != RTCDtlsTransportState::Connected
                && self.ctx.dtls_transport.handshake_began.is_none()
            {
                self.ctx.dtls_transport.handshake_began = Some(msg.now);
            }
            let round_trip_time = self.selected_pair_round_trip_time();
            if let Some(group) = self.ctx.dtls_transport.session_group() {
                group.observe(msg.now);
            }
            let srtp_required = self.ctx.dtls_transport.srtp_required;
            let dtls_endpoint = self
                .ctx
                .dtls_transport
                .dtls_endpoint
                .as_mut()
                .ok_or(Error::ErrDtlsTransportNotStarted)?;

            // The read's error is returned only after the datagrams the endpoint queued (the
            // fatal alert that answers a failed handshake, say) have been taken and a failure has
            // been recorded: the pipeline logs that error and goes on.
            let (events, read_error) = match dtls_endpoint.read(
                msg.now,
                msg.transport.peer_addr,
                msg.transport.ecn,
                dtls_message,
            ) {
                Ok(events) => (events, None),
                Err(err) => (vec![], Some(err)),
            };
            let failed = dtls_endpoint.is_connection_failed(&msg.transport.peer_addr);
            for message in events {
                match message {
                    EndpointEvent::HandshakeComplete => {
                        if let Some(state) =
                            dtls_endpoint.get_connection_state(msg.transport.peer_addr)
                        {
                            debug!("dtls handshake complete");

                            // RFC 5764 section 4.1: `use_srtp` is for associations that carry
                            // RTP. A peer that did not negotiate it (a data-channel-only
                            // stack) gives an association without SRTP keys: enough for data
                            // channels, not for a session with media sections (RFC 8827
                            // section 6.5), which fails here instead of sitting in
                            // `connecting`.
                            let srtp_contexts = if state.srtp_protection_profile()
                                == SrtpProtectionProfile::Unsupported
                            {
                                if srtp_required {
                                    Err(Error::ErrRequestedButNoSrtpExtension)
                                } else {
                                    Ok(None)
                                }
                            } else {
                                DtlsHandler::update_srtp_contexts(
                                    state,
                                    &self.ctx.dtls_transport.replay_protection,
                                    self.ctx.dtls_transport.srtp_key_lifetime,
                                    &self.ctx.dtls_transport.crypto_provider,
                                )
                                .map(Some)
                            };
                            match srtp_contexts {
                                Ok(srtp_contexts) => {
                                    // Save profile for stats update after borrow ends
                                    srtp_profile_for_stats = Some(state.srtp_protection_profile());

                                    // Save peer certificates for stats
                                    peer_certificates_for_stats = state.peer_certificates.clone();

                                    // Save DTLS cipher suite for stats
                                    dtls_cipher_for_stats =
                                        state.cipher_suite().map(|cs| cs.to_string());
                                    dtls_version_for_stats = state.negotiated_version();
                                    application_protocol =
                                        Some(state.application_protocol().map(str::to_owned));

                                    handshake_complete = Some(srtp_contexts);
                                }
                                // Reported after the queued datagrams have been taken, as a
                                // failed transport.
                                Err(err) => handshake_error = Some(err),
                            }
                        } else {
                            warn!(
                                "Unable to find connection state for {}",
                                msg.transport.peer_addr
                            );
                        }
                    }
                    EndpointEvent::ApplicationData(message) => {
                        debug!("recv dtls application RAW {:?}", msg.transport.peer_addr);
                        messages.push(message);
                    }
                    EndpointEvent::PeerClosed => {
                        debug!("dtls closed by peer {:?}", msg.transport.peer_addr);
                        peer_closed = true;
                    }
                    _ => {}
                }
            }
            // RFC 9147 section 9: "SHOULD request new CIDs for this purpose if path changes
            // are anticipated", and with ICE they are: a spare id is asked for as soon as a
            // DTLS 1.3 association that sends connection ids is up (refused, and nothing sent,
            // when it sends none or is DTLS 1.2).
            if handshake_complete.is_some() {
                let _ = dtls_endpoint.request_connection_ids(msg.now, msg.transport.peer_addr, 1);
            }

            while let Some(transmit) = dtls_endpoint.poll_transmit() {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
                });
            }

            if let Some(err) = handshake_error {
                self.fail_transport(msg.now);
                return Err(err);
            }

            if let Some(srtp_contexts) = handshake_complete {
                // What a re-keying needs, measured on this handshake
                // (`DtlsTransport::rekeying_handshake_time`).
                if let Some(began) = self.ctx.dtls_transport.handshake_began.take() {
                    let dtls = &mut self.ctx.dtls_transport;
                    // The ICE checks of the restart (a check and its nomination, two round
                    // trips) take no longer than the handshake's own round trips, so the
                    // handshake's duration counts twice.
                    dtls.rekeying_handshake_time = Some(
                        msg.now.saturating_duration_since(began) * 2
                            + dtls.flight_interval_rule.initial(round_trip_time),
                    );
                }
                self.ctx.dtls_transport.srtp_negotiated = Some(srtp_contexts.is_some());
                self.ctx
                    .dtls_transport
                    .state_change(RTCDtlsTransportState::Connected);
                if self.ctx.dtls_transport.dtls_role == RTCDtlsRole::Client
                    && let Some(group) = self.ctx.dtls_transport.session_group()
                {
                    // The others start now, or once the rest of the flight of tickets that
                    // began to come has come (at most a flight interval).
                    let ticket_wait = self
                        .ctx
                        .dtls_transport
                        .flight_interval
                        .unwrap_or(DTLS_SRTP_FLIGHT_INTERVAL);
                    group.leader_connected(
                        &self.ctx.dtls_transport.resumption_token,
                        msg.now,
                        dtls_version_for_stats == Some(dtls::config::DtlsVersion::Dtls1_3),
                        ticket_wait,
                    );
                }
                if let Err(err) = self.ctx.dtls_transport.leave_session_after_handshake() {
                    warn!("dtls: a later handshake may resume the session: {err}");
                }

                let (local_srtp_context, remote_srtp_context) = srtp_contexts.unzip();
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now: msg.now,
                    event: RTCEventInternal::DTLSHandshakeComplete(
                        local_srtp_context,
                        remote_srtp_context,
                    ),
                });
            }

            // A ticket for the connection's session may have come with this datagram.
            if let Some(group) = self.ctx.dtls_transport.session_group() {
                group.poll_leader(&self.ctx.dtls_transport.resumption_token, msg.now);
            }

            // RFC 8833 section 2: what ALPN selected; a peer that used none is taken as
            // `webrtc` by the application ("SHOULD assume ... "webrtc"").
            if let Some(application_protocol) = application_protocol {
                self.ctx.dtls_transport.application_protocol = application_protocol;
            }
            // Update stats after dtls_endpoint borrow ends
            if let Some(srtp_profile) = srtp_profile_for_stats {
                self.update_dtls_stats_from_profile(
                    srtp_profile,
                    &peer_certificates_for_stats,
                    dtls_cipher_for_stats,
                    dtls_version_for_stats,
                )?;
            }

            for message in messages {
                debug!("recv dtls application RAW {:?}", msg.transport.peer_addr);
                self.ctx.read_outs.push_back(TaggedRTCMessageInternal {
                    now: msg.now,
                    transport: msg.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(message)),
                });
            }

            // The peer closed the transport (close_notify). Its reply is already queued above.
            // The SCTP association and every data channel run over this transport, so they end
            // with it (rtc#255).
            if peer_closed {
                self.ctx
                    .dtls_transport
                    .state_change(RTCDtlsTransportState::Closed);
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now: msg.now,
                    event: RTCEventInternal::DTLSClosed,
                });
            } else if failed {
                self.fail_transport(msg.now);
            }

            if let Some(err) = read_error {
                return Err(err);
            }
        } else {
            // Bypass
            debug!("bypass dtls read {:?}", msg.transport.peer_addr);
            self.ctx.read_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.ctx.read_outs.pop_front()
    }

    fn handle_write(&mut self, msg: TaggedRTCMessageInternal) -> Result<()> {
        if let RTCMessageInternal::Dtls(DTLSMessage::Raw(dtls_message)) = msg.message {
            debug!("send dtls RAW {:?}", msg.transport.peer_addr);

            let dtls_endpoint = self
                .ctx
                .dtls_transport
                .dtls_endpoint
                .as_mut()
                .ok_or(Error::ErrDtlsTransportNotStarted)?;

            dtls_endpoint.write(msg.now, msg.transport.peer_addr, &dtls_message)?;
            while let Some(transmit) = dtls_endpoint.poll_transmit() {
                self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                    now: transmit.now,
                    transport: transmit.transport,
                    message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
                });
            }
        } else {
            // Bypass
            debug!("Bypass dtls write {:?}", msg.transport.peer_addr);
            self.ctx.write_outs.push_back(msg);
        }
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        if let Some((due, _)) = self.ctx.waiting_for_session
            && let Some(ready) = self
                .ctx
                .dtls_transport
                .session_group()
                .map_or(Some(due), |group| group.ready_at())
        {
            self.ctx.waiting_for_session = None;
            if let Err(err) = self.connect_client(ready.max(due), true) {
                warn!("failed to start the dtls handshake: {}", err);
            }
        }
        if let Some(now) = self.ctx.connect_requested.take()
            && let Err(err) = self.connect_client(now, true)
        {
            warn!("failed to start the dtls handshake: {}", err);
        }
        if let Some(now) = self.ctx.close_requested.take()
            && let Err(err) = self.queue_close_notify(now)
        {
            warn!("failed to queue dtls close_notify: {}", err);
        }
        self.ctx.write_outs.pop_front()
    }

    fn handle_event(&mut self, evt: TaggedRTCEventInternal) -> Result<()> {
        let now = evt.now;
        if let RTCEventInternal::ICESelectedCandidatePairChange = evt.event {
            self.connect_client(now, false)?;
            self.on_new_path(now);
        } else {
            self.ctx.event_outs.push_back(evt);
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        if let Some(group) = self.ctx.dtls_transport.session_group() {
            group.observe(now);
            group.poll_leader(&self.ctx.dtls_transport.resumption_token, now);
        }
        // The leader's handshake is not complete within the bound: a full handshake.
        if let Some((_, deadline)) = self.ctx.waiting_for_session
            && now >= deadline
        {
            debug!("dtls: the connection's first handshake is not complete; a full handshake");
            if let Err(err) = self.start_client_handshake(now, true) {
                warn!("failed to start the dtls handshake: {}", err);
            }
        }
        // The first flight left in the endpoint goes out below.
        self.ctx.first_flight_due = None;
        let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_mut() else {
            return Ok(());
        };

        // The DTLS handshake sets no deadline of its own (RFC 6347 section 4.2.4 and RFC 9147
        // section 5.8 define the retransmission timer and no total limit): while ICE says the
        // path is alive its flights are retransmitted, at most once a minute, and what ends a
        // handshake is ICE (consent expiry or failure, which fails the peer connection), a
        // fatal alert or a close. Only a deadline configured on the association fails it here.
        // That failure is reported as the transport's state, not as an error, so the other
        // handlers still get their timeout.
        let remotes: Vec<SocketAddr> = dtls_endpoint.get_connections_keys().copied().collect();
        let mut failed = false;
        let mut timeout_error = None;
        for remote in remotes {
            if let Err(err) = dtls_endpoint.handle_timeout(remote, now) {
                if dtls_endpoint.is_connection_failed(&remote) {
                    debug!("dtls handshake with {} gave up: {}", remote, err);
                    failed = true;
                } else if timeout_error.is_none() {
                    timeout_error = Some(err);
                }
            }
        }
        while let Some(transmit) = dtls_endpoint.poll_transmit() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
            });
        }

        if failed {
            self.fail_transport(now);
        }
        if let Some(err) = timeout_error {
            return Err(err);
        }
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Instant> {
        // The leader stops waiting for the rest of the session's tickets; a waiting transport
        // stops waiting for the leader.
        let leader = self
            .ctx
            .dtls_transport
            .session_group()
            .and_then(|group| group.leader_deadline(&self.ctx.dtls_transport.resumption_token));
        let waiter = self.ctx.waiting_for_session.map(|(_, deadline)| deadline);
        let deadline = [leader, waiter, self.ctx.first_flight_due]
            .into_iter()
            .flatten()
            .min();
        if let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_ref() {
            let mut eto = deadline;

            let remotes = dtls_endpoint.get_connections_keys();
            for remote in remotes {
                if let Some(timeout) = dtls_endpoint.poll_timeout(remote) {
                    eto = Some(eto.map_or(timeout, |e: Instant| e.min(timeout)));
                }
            }

            eto
        } else {
            deadline
        }
    }

    fn close(&mut self) -> Result<()> {
        self.ctx.dtls_transport.stop()
    }
}

impl<'a> DtlsHandler<'a> {
    /// W3C webrtc 5.5.1: the DTLS transport goes to "failed" when the association fails — a
    /// fatal alert sent or received (a certificate fingerprint mismatch included) or a handshake
    /// that gave up. The peer connection's state follows: `update_connection_state` reports
    /// "failed" once any DTLS transport has. The SCTP association and every data channel run
    /// over this transport, so they end with it, exactly as when the peer closes it: the
    /// `DTLSClosed` event is what tells the SCTP and data channel handlers, and it is also what
    /// makes the peer connection re-evaluate its state. A no-op once the transport is failed
    /// or closed.
    /// Fails the transport with `error`, as `fail_transport` does for a DTLS failure: what an
    /// SRTP key that reached its lifetime does to the transport that keyed it.
    pub(crate) fn fail_with(
        &mut self,
        now: Instant,
        error: crate::peer_connection::rtc_error::RTCError,
    ) {
        self.fail_transport(now);
        if self.ctx.dtls_transport.state == RTCDtlsTransportState::Failed {
            self.ctx.dtls_transport.failure = Some(error);
        }
    }

    fn fail_transport(&mut self, now: Instant) {
        if matches!(
            self.ctx.dtls_transport.state,
            RTCDtlsTransportState::Failed | RTCDtlsTransportState::Closed
        ) {
            return;
        }
        warn!("dtls transport failed");
        self.ctx.dtls_transport.failure = Some(self.ctx.dtls_transport.failure_error());
        self.ctx
            .dtls_transport
            .state_change(RTCDtlsTransportState::Failed);
        self.stats
            .transport
            .on_dtls_state_changed(RTCDtlsTransportState::Failed);
        self.ctx.event_outs.push_back(TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::DTLSClosed,
        });
    }

    /// The inbound SRTP replay window, in packets, unless the setting engine sets one.
    ///
    /// A NACK retransmission without RTX reuses the lost packet's sequence number, so it reaches
    /// the replay detector behind every packet sent since. It arrives a round trip plus the NACK
    /// interval late on the first try, and another interval later for each lost NACK or lost
    /// retransmission: at 200 packets/s a third try is already more than 64 packets behind, and
    /// a 64-packet window refused it as too old, losing the packet for good. 1024 matches the
    /// NACK responder's default send buffer and the sender's own index window
    /// (`SRTP_SEND_INDEX_WINDOW`), so any packet the sender can still retransmit is accepted,
    /// and is what libwebrtc uses for the same reason. RFC 3711 Section 3.3.2 sets 64 as the
    /// minimum. Replay protection is unchanged: a duplicate inside the window is still refused,
    /// and the cost is a 128-byte bitmap per SSRC (at most `MAX_SSRC_STATES` of them).
    const DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW: usize = 1024;
    const DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW: usize = 64;
    /// The lifetime of a DTLS-SRTP master key: 2^31 packets for the RFC 5764 profiles
    /// (section 4.1.2: "maximum_lifetime: 2^31"), what RFC 3711 allows otherwise (the AEAD
    /// profiles of RFC 7714: 2^48 SRTP, 2^31 SRTCP), unless the setting engine sets a shorter
    /// one.
    fn key_lifetime(
        profile: ProtectionProfile,
        configured: Option<srtp::keying::KeyLifetime>,
    ) -> srtp::keying::KeyLifetime {
        if let Some(lifetime) = configured {
            return lifetime;
        }
        if profile.is_aead() {
            srtp::keying::KeyLifetime::MAX
        } else {
            srtp::keying::KeyLifetime {
                srtp_packets: 1 << 31,
                srtcp_packets: 1 << 31,
            }
        }
    }

    pub(crate) fn update_srtp_contexts(
        state: &State,
        replay_protection: &ReplayProtection,
        key_lifetime: Option<srtp::keying::KeyLifetime>,
        crypto_provider: &Arc<dyn RTCCryptoProvider>,
    ) -> Result<(srtp::context::Context, srtp::context::Context)> {
        // The DTLS-SRTP code point names the profile (RFC 5764 section 4.1.2, RFC 7714
        // section 14.2). A NULL-cipher profile protects nothing from eavesdroppers and is
        // never taken (RFC 8827 section 6.5: media is encrypted).
        let profile = match state.srtp_protection_profile() {
            SrtpProtectionProfile::Unsupported => None,
            negotiated => ProtectionProfile::from_dtls_srtp_id(negotiated as u16),
        }
        .filter(|profile| !profile.is_null_cipher())
        .ok_or(Error::ErrNoSuchSrtpProfile)?;

        let mut srtp_config = srtp::config::Config {
            profile,
            ..Default::default()
        };
        if replay_protection.srtp != 0 {
            srtp_config.remote_rtp_options = Some(srtp::option::srtp_replay_protection(
                replay_protection.srtp,
            )?);
        }

        if replay_protection.srtcp != 0 {
            srtp_config.remote_rtcp_options = Some(srtp::option::srtcp_replay_protection(
                replay_protection.srtcp,
            )?);
        }

        let keying_material = state.export_keying_material(
            srtp::config::LABEL_EXTRACTOR_DTLS_SRTP,
            &[],
            srtp_config.keying_material_len(),
        )?;
        srtp_config
            .set_session_keys_from_keying_material(keying_material.as_ref(), state.is_client())?;

        let local_context = srtp::context::Context::new(
            &srtp_config.keys.local_master_key,
            &srtp_config.keys.local_master_salt,
            srtp_config.profile,
            srtp_config.local_rtp_options,
            srtp_config.local_rtcp_options,
            crypto_provider.crypto(),
        )?;

        let mut local_context = local_context;
        local_context.set_key_lifetime(Self::key_lifetime(profile, key_lifetime))?;

        let remote_context = srtp::context::Context::new(
            &srtp_config.keys.remote_master_key,
            &srtp_config.keys.remote_master_salt,
            srtp_config.profile,
            if srtp_config.remote_rtp_options.is_none() {
                Some(srtp_replay_protection(
                    Self::DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW,
                )?)
            } else {
                srtp_config.remote_rtp_options
            },
            if srtp_config.remote_rtcp_options.is_none() {
                Some(srtcp_replay_protection(
                    Self::DEFAULT_SESSION_SRTCP_REPLAY_PROTECTION_WINDOW,
                )?)
            } else {
                srtp_config.remote_rtcp_options
            },
            crypto_provider.crypto(),
        )?;
        let mut remote_context = remote_context;
        remote_context.set_key_lifetime(Self::key_lifetime(profile, key_lifetime))?;

        Ok((local_context, remote_context))
    }
}

#[cfg(test)]
mod tests {
    /// RFC 5764 section 4.1.2: a DTLS-SRTP key of the AES-CM profiles lives for 2^31 packets;
    /// the AEAD profiles (RFC 7714) for what RFC 3711 allows; a configured lifetime wins.
    #[test]
    fn dtls_srtp_keys_get_the_profiles_lifetime() {
        use srtp::keying::KeyLifetime;
        use srtp::protection_profile::ProtectionProfile;
        let rfc5764 = KeyLifetime {
            srtp_packets: 1 << 31,
            srtcp_packets: 1 << 31,
        };
        for profile in [
            ProtectionProfile::Aes128CmHmacSha1_80,
            ProtectionProfile::Aes128CmHmacSha1_32,
        ] {
            assert_eq!(DtlsHandler::key_lifetime(profile, None), rfc5764);
        }
        assert_eq!(
            DtlsHandler::key_lifetime(ProtectionProfile::AeadAes128Gcm, None),
            KeyLifetime::MAX
        );
        let configured = KeyLifetime {
            srtp_packets: 9,
            srtcp_packets: 9,
        };
        assert_eq!(
            DtlsHandler::key_lifetime(ProtectionProfile::AeadAes256Gcm, Some(configured)),
            configured
        );
        // The NULL-cipher profiles are never taken.
        assert!(ProtectionProfile::from_dtls_srtp_id(0x0005).is_some_and(|p| p.is_null_cipher()));
        assert!(
            !crate::peer_connection::transport::dtls::default_srtp_protection_profiles()
                .iter()
                .any(|p| matches!(*p as u16, 0x0005 | 0x0006))
        );
    }

    use super::*;
    use crate::peer_connection::transport::{RTCTransportId, TransportKind};
    use shared::marshal::Marshal;

    /// A NACK retransmission (no RTX) carries the lost packet's sequence number and arrives after
    /// every packet sent since. The session's default inbound window accepts it while it is
    /// within the window, and still refuses a duplicate and a packet older than the window.
    #[test]
    fn default_srtp_replay_window_accepts_a_late_retransmission() -> Result<()> {
        const WINDOW: u16 =
            DtlsHandler::<'static>::DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW as u16;
        // Repaired just inside the window: the newest packet is WINDOW - 1 ahead of it.
        const REPAIRED: u16 = 10;
        // Repaired just outside it: the newest packet is WINDOW ahead of it.
        const TOO_OLD: u16 = 20;
        const LAST: u16 = TOO_OLD + WINDOW;

        let provider =
            crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
        let key = [0x0du8; 16];
        let salt = [0x62u8; 14];
        let mut sender = srtp::context::Context::new(
            &key,
            &salt,
            ProtectionProfile::Aes128CmHmacSha1_80,
            None,
            None,
            provider.crypto(),
        )?;
        let mut receiver = srtp::context::Context::new(
            &key,
            &salt,
            ProtectionProfile::Aes128CmHmacSha1_80,
            Some(srtp_replay_protection(
                DtlsHandler::<'static>::DEFAULT_SESSION_SRTP_REPLAY_PROTECTION_WINDOW,
            )?),
            None,
            provider.crypto(),
        )?;

        let mut protect = |seq: u16| -> Result<Vec<u8>> {
            let packet = rtp::Packet {
                header: rtp::Header {
                    version: 2,
                    payload_type: 96,
                    sequence_number: seq,
                    timestamp: u32::from(seq) * 450,
                    ssrc: 0x1234_5678,
                    ..Default::default()
                },
                payload: bytes::Bytes::from(vec![0x10u8; 100]),
            };
            Ok(sender.encrypt_rtp(&packet.marshal()?)?.to_vec())
        };

        let mut repaired = None;
        let mut too_old = None;
        for seq in 1..=LAST {
            let protected = protect(seq)?;
            match seq {
                REPAIRED => repaired = Some(protected),
                TOO_OLD => too_old = Some(protected),
                _ => {
                    receiver.decrypt_rtp(&protected)?;
                }
            }
            if seq == REPAIRED + WINDOW - 1 {
                let retransmission = repaired.as_ref().expect("protected above");
                receiver.decrypt_rtp(retransmission).map_err(|e| {
                    Error::Other(format!(
                        "a retransmission {} packets late was refused: {e}",
                        WINDOW - 1
                    ))
                })?;
                assert!(
                    receiver.decrypt_rtp(retransmission).is_err(),
                    "a replayed packet inside the window is refused"
                );
            }
        }
        assert!(
            receiver
                .decrypt_rtp(too_old.as_ref().expect("protected above"))
                .is_err(),
            "a packet a full window behind the newest is refused"
        );
        Ok(())
    }

    /// A fixed nonce keeps test ids deterministic while still distinguishing the kinds.
    fn test_transport_id(kind: TransportKind) -> RTCTransportId {
        RTCTransportId::new(0xabcd_ef01_2345_6789, kind)
    }

    #[test]
    fn timeout_before_dtls_starts_is_a_noop() {
        let provider =
            crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
        let transport = DtlsTransport::new(
            crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
                id: test_transport_id(TransportKind::Dtls),
                ice_transport_id: test_transport_id(TransportKind::Ice),
                certificates: vec![],
                answering_dtls_role: Default::default(),
                srtp_protection_profiles: vec![],
                use_srtp_always: true,
                dtls_cipher_suites: vec![],
                allow_insecure_verification_algorithm: false,
                disable_certificate_fingerprint_verification: false,
                replay_protection: Default::default(),
                crypto_provider: provider,
            },
        )
        .expect("transport");
        let mut context = DtlsHandlerContext::new(transport);
        let mut stats = RTCStatsAccumulator::default();
        let mut handler = DtlsHandler::new(&mut context, &mut stats);

        sansio::Protocol::handle_timeout(&mut handler, Instant::now()).unwrap();
    }

    // The handshake path is the only writer of `remote_certificates`. A test that assigns the
    // field and reads it back would keep passing if this assignment were deleted, so drive the
    // writer instead.
    #[test]
    fn handshake_completion_retains_the_peer_certificate_chain() -> Result<()> {
        let provider =
            crypto::default_provider().expect("a built-in crypto provider is enabled for tests");
        let transport = DtlsTransport::new(
            crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
                id: test_transport_id(TransportKind::Dtls),
                ice_transport_id: test_transport_id(TransportKind::Ice),
                certificates: vec![],
                answering_dtls_role: Default::default(),
                srtp_protection_profiles: vec![],
                use_srtp_always: true,
                dtls_cipher_suites: vec![],
                allow_insecure_verification_algorithm: false,
                disable_certificate_fingerprint_verification: false,
                replay_protection: Default::default(),
                crypto_provider: provider,
            },
        )
        .expect("transport");
        let mut context = DtlsHandlerContext::new(transport);
        let mut stats = RTCStatsAccumulator::default();

        assert!(context.dtls_transport.get_remote_certificates().is_empty());

        // The fingerprint is hashed from these bytes, so any content works.
        let peer_chain = vec![
            vec![0x30u8, 0x82, 0x01, 0x0a],
            vec![0x30, 0x82, 0x02, 0x0b],
            vec![0x30, 0x82, 0x03, 0x0c],
        ];

        DtlsHandler::new(&mut context, &mut stats).update_dtls_stats_from_profile(
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            &peer_chain,
            None,
            None,
        )?;

        assert_eq!(
            peer_chain,
            context.dtls_transport.get_remote_certificates(),
            "the whole chain is retained, not just the first entry the stats path consumes"
        );

        // webrtc-stats 8.22 `issuerCertificateId`: every certificate of the chain has a stats
        // object, and each names the next one as its issuer; the last names none.
        assert_eq!(
            stats.certificates.len(),
            4,
            "the peer's three and the transport's own"
        );
        let mut id = stats.transport.remote_certificate_id.clone();
        for der in &peer_chain {
            let certificate = stats
                .certificates
                .get(&id)
                .unwrap_or_else(|| panic!("no certificate object {id}"));
            assert_eq!(certificate.base64_certificate, base64_encode(der));
            assert_eq!(certificate.fingerprint_algorithm, "sha-256");
            id = certificate.issuer_certificate_id.clone();
        }
        assert_eq!(id, "", "the last certificate of the chain names no issuer");
        Ok(())
    }

    /// A `DtlsHandler` whose transport is started in `role` (fingerprint verification off: the
    /// peer below is a bare DTLS endpoint with a certificate of its own), and a bare DTLS
    /// endpoint in the other role that offers or accepts the given SRTP profiles.
    struct HandlerAndPeer {
        context: DtlsHandlerContext,
        stats: RTCStatsAccumulator,
        peer: dtls::endpoint::Endpoint,
        now: Instant,
        events: Vec<RTCEventInternal>,
        /// What the handler sent the peer, in order.
        sent: Vec<bytes::BytesMut>,
    }

    impl HandlerAndPeer {
        fn new(
            role: RTCDtlsRole,
            peer_profiles: Vec<SrtpProtectionProfile>,
            srtp_required: bool,
        ) -> Result<Self> {
            Self::new_with(role, peer_profiles, srtp_required, |builder| builder)
        }

        /// As [`Self::new`], with the peer's configuration changed by `peer`.
        fn new_with(
            role: RTCDtlsRole,
            peer_profiles: Vec<SrtpProtectionProfile>,
            srtp_required: bool,
            peer: impl FnOnce(dtls::config::ConfigBuilder) -> dtls::config::ConfigBuilder,
        ) -> Result<Self> {
            Self::new_configured(role, peer_profiles, srtp_required, peer, |_| {})
        }

        /// As [`Self::new_with`], with the transport changed by `configure` before it starts.
        fn new_configured(
            role: RTCDtlsRole,
            peer_profiles: Vec<SrtpProtectionProfile>,
            srtp_required: bool,
            peer: impl FnOnce(dtls::config::ConfigBuilder) -> dtls::config::ConfigBuilder,
            configure: impl FnOnce(&mut DtlsTransport),
        ) -> Result<Self> {
            use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
            use crate::peer_connection::transport::ice::role::RTCIceRole;
            use dtls::config::{ConfigBuilder, ExtendedMasterSecretType};

            let provider = crypto::default_provider().expect("a built-in crypto provider");
            let mut transport = DtlsTransport::new(
                crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
                    id: test_transport_id(TransportKind::Dtls),
                    ice_transport_id: test_transport_id(TransportKind::Ice),
                    certificates: vec![],
                    answering_dtls_role: Default::default(),
                    srtp_protection_profiles: vec![],
                    use_srtp_always: true,
                    dtls_cipher_suites: vec![],
                    allow_insecure_verification_algorithm: false,
                    disable_certificate_fingerprint_verification: true,
                    replay_protection: Default::default(),
                    crypto_provider: provider.clone(),
                },
            )?;
            transport.srtp_required = srtp_required;
            configure(&mut transport);
            // The remote role is the inverse of the one the transport takes.
            let remote_role = if role == RTCDtlsRole::Client {
                RTCDtlsRole::Server
            } else {
                RTCDtlsRole::Client
            };
            transport.start(
                RTCIceRole::Controlling,
                RTCDtlsParameters {
                    role: remote_role,
                    fingerprints: vec![],
                },
            )?;
            assert_eq!(transport.role(), role);

            let peer_certificate = dtls::crypto::Certificate::generate_self_signed(
                vec!["peer".into()],
                provider.crypto(),
            )?;
            let peer_config = Arc::new(
                peer(
                    ConfigBuilder::default()
                        .with_crypto_provider(provider)
                        .with_certificates(vec![peer_certificate])
                        .with_srtp_protection_profiles(peer_profiles)
                        .with_insecure_skip_verify(true)
                        .with_extended_master_secret(ExtendedMasterSecretType::Require),
                )
                .build(role == RTCDtlsRole::Server, None)?,
            );
            // The handler's endpoint is tunnelled: it knows its peer by the placeholder
            // address. The peer knows the handler by an address of its own choosing.
            let handler_addr = Self::handler_addr();
            let peer_addr = TransportContext::default().peer_addr;
            let now = Instant::now();
            let peer = if role == RTCDtlsRole::Server {
                let mut peer =
                    dtls::endpoint::Endpoint::new(peer_addr, shared::TransportProtocol::UDP, None);
                peer.connect(now, handler_addr, peer_config, None)?;
                peer
            } else {
                dtls::endpoint::Endpoint::new(
                    peer_addr,
                    shared::TransportProtocol::UDP,
                    Some(peer_config),
                )
            };
            Ok(Self {
                context: DtlsHandlerContext::new(transport),
                stats: RTCStatsAccumulator::default(),
                peer,
                now,
                events: vec![],
                sent: vec![],
            })
        }

        fn handler_addr() -> SocketAddr {
            "10.0.0.1:4000".parse().unwrap()
        }

        /// Exchanges datagrams until neither side has any to send. Returns the first error
        /// the handler's `handle_read` gave.
        fn run(&mut self) -> Option<Error> {
            use sansio::Protocol;
            let mut first_error = None;
            let handler_addr = Self::handler_addr();
            let now = self.now;
            {
                let mut handler = DtlsHandler::new(&mut self.context, &mut self.stats);
                handler
                    .handle_event(TaggedRTCEventInternal {
                        now,
                        event: RTCEventInternal::ICESelectedCandidatePairChange,
                    })
                    .expect("the selected pair starts a client's handshake");
                // The client's first flight goes out with the next timeout.
                handler.handle_timeout(now).expect("no timeout error");
            }
            for _ in 0..20 {
                let mut progressed = false;
                while let Some(transmit) = self.peer.poll_transmit() {
                    progressed = true;
                    let mut handler = DtlsHandler::new(&mut self.context, &mut self.stats);
                    if let Err(err) = handler.handle_read(TaggedRTCMessageInternal {
                        now,
                        transport: TransportContext::default(),
                        message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
                    }) && first_error.is_none()
                    {
                        first_error = Some(err);
                    }
                }
                let mut handler = DtlsHandler::new(&mut self.context, &mut self.stats);
                while let Some(written) = handler.poll_write() {
                    progressed = true;
                    if let RTCMessageInternal::Dtls(DTLSMessage::Raw(message)) = written.message {
                        self.sent.push(message.clone());
                        let _ = self.peer.read(now, handler_addr, None, message);
                    }
                }
                while let Some(event) = handler.poll_event() {
                    self.events.push(event.event);
                }
                if !progressed {
                    break;
                }
            }
            first_error
        }
    }

    /// RFC 5764 section 4.1: `use_srtp` is for associations that carry RTP. A peer that does
    /// not negotiate it (a data-channel-only DTLS stack: it offers none as the client, or
    /// leaves it out of its ServerHello) is connected when the session has no media section:
    /// the transport reports `Connected` and the handshake completes without SRTP contexts.
    /// Before, the server side returned `ErrNoSuchSrtpProfile` and stayed in `Connecting`,
    /// and the client side aborted the handshake.
    #[test]
    fn a_peer_without_use_srtp_connects_a_session_without_media() -> Result<()> {
        for role in [RTCDtlsRole::Server, RTCDtlsRole::Client] {
            let mut pair = HandlerAndPeer::new(role, vec![], false)?;
            let error = pair.run();
            assert!(error.is_none(), "{role}: {error:?}");
            assert_eq!(
                pair.context.dtls_transport.state(),
                RTCDtlsTransportState::Connected,
                "{role}"
            );
            assert_eq!(pair.context.dtls_transport.srtp_negotiated, Some(false));
            assert!(
                pair.events.iter().any(|event| matches!(
                    event,
                    RTCEventInternal::DTLSHandshakeComplete(None, None)
                )),
                "{role}: the handshake completed without SRTP contexts"
            );
            assert_eq!(pair.stats.transport.srtp_cipher, "", "{role}");
            assert!(
                !pair
                    .context
                    .dtls_transport
                    .get_remote_certificates()
                    .is_empty()
            );
        }
        Ok(())
    }

    /// With `use_srtp` negotiated the handshake hands over both SRTP contexts, as before.
    #[test]
    fn a_peer_with_use_srtp_keys_the_srtp_contexts() -> Result<()> {
        for role in [RTCDtlsRole::Server, RTCDtlsRole::Client] {
            let mut pair = HandlerAndPeer::new(
                role,
                vec![SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80],
                true,
            )?;
            let error = pair.run();
            assert!(error.is_none(), "{role}: {error:?}");
            assert_eq!(
                pair.context.dtls_transport.state(),
                RTCDtlsTransportState::Connected
            );
            assert_eq!(pair.context.dtls_transport.srtp_negotiated, Some(true));
            assert!(pair.events.iter().any(|event| matches!(
                event,
                RTCEventInternal::DTLSHandshakeComplete(Some(_), Some(_))
            )));
            assert_eq!(
                pair.stats.transport.srtp_cipher,
                "SRTP_AES128_CM_HMAC_SHA1_80"
            );
        }
        Ok(())
    }

    /// A DTLS server transport taking part in its connection's session (RFC 5764 section 3:
    /// two server transports of the negotiation, the same remote fingerprints), and a peer
    /// client with a session store, its ClientHello queued.
    fn session_server_pair(
        store: &Arc<dtls::session::MemorySessionStore>,
    ) -> Result<(HandlerAndPeer, Arc<dtls::config::HandshakeConfig>)> {
        use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
        use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
        use crate::peer_connection::transport::dtls::resumption::DtlsSessionGroup;
        use crate::peer_connection::transport::ice::role::RTCIceRole;
        use dtls::config::{ConfigBuilder, ExtendedMasterSecretType};

        let provider = crypto::default_provider().expect("a built-in crypto provider");
        let group = Arc::new(DtlsSessionGroup::new(provider.as_ref())?);
        let params = RTCDtlsParameters {
            role: RTCDtlsRole::Client,
            fingerprints: vec![RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: "01".repeat(32),
            }],
        };
        let new_transport = || {
            let mut transport = DtlsTransport::new(
                crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
                    id: test_transport_id(TransportKind::Dtls),
                    ice_transport_id: test_transport_id(TransportKind::Ice),
                    certificates: vec![],
                    answering_dtls_role: Default::default(),
                    srtp_protection_profiles: vec![],
                    use_srtp_always: true,
                    dtls_cipher_suites: vec![],
                    allow_insecure_verification_algorithm: false,
                    disable_certificate_fingerprint_verification: true,
                    replay_protection: Default::default(),
                    crypto_provider: provider.clone(),
                },
            )?;
            transport.resumption = Some(group.clone());
            transport.start(RTCIceRole::Controlling, params.clone())?;
            Ok::<_, Error>(transport)
        };
        let _sibling = new_transport()?;
        let mut transport = new_transport()?;
        group.close_admission();
        transport.engage_session()?;
        assert!(transport.resumption_member, "it takes part");
        assert_eq!(transport.role(), RTCDtlsRole::Server);

        let peer_config = Arc::new(
            ConfigBuilder::default()
                .with_crypto_provider(provider.clone())
                .with_certificates(vec![dtls::crypto::Certificate::generate_self_signed(
                    vec!["peer".into()],
                    provider.crypto(),
                )?])
                .with_insecure_skip_verify(true)
                .with_extended_master_secret(ExtendedMasterSecretType::Require)
                .with_server_name("localhost".to_owned())
                .with_session_store(Some(store.clone() as Arc<dyn dtls::session::SessionStore>))
                .build(true, None)?,
        );
        let now = Instant::now();
        let mut peer = dtls::endpoint::Endpoint::new(
            TransportContext::default().peer_addr,
            shared::TransportProtocol::UDP,
            None,
        );
        peer.connect(
            now,
            HandlerAndPeer::handler_addr(),
            peer_config.clone(),
            None,
        )?;
        Ok((
            HandlerAndPeer {
                context: DtlsHandlerContext::new(transport),
                stats: RTCStatsAccumulator::default(),
                peer,
                now,
                events: vec![],
                sent: vec![],
            },
            peer_config,
        ))
    }

    /// A server transport of the connection's session accepts a resumption for its first
    /// handshake only (RFC 5764 section 3 is about establishing the associations): its first
    /// handshake issues the tickets, and a later handshake on the same transport within their
    /// lifetime (a peer that re-handshakes in place, RFC 6347 section 4.2.8), offering one of
    /// them, is a full one.
    #[test]
    fn a_server_transport_resumes_no_later_handshake_in_place() -> Result<()> {
        let store = Arc::new(dtls::session::MemorySessionStore::new());
        let (mut pair, peer_config) = session_server_pair(&store)?;
        assert!(pair.run().is_none());
        assert_eq!(
            pair.context.dtls_transport.state(),
            RTCDtlsTransportState::Connected
        );
        assert!(!handler_resumed(&pair));
        let tickets = store.len("localhost");
        assert!(
            tickets > 0,
            "the first handshake issued the session's tickets"
        );

        // The same peer, in place, offering one of them.
        let mut peer = dtls::endpoint::Endpoint::new(
            TransportContext::default().peer_addr,
            shared::TransportProtocol::UDP,
            None,
        );
        peer.connect(pair.now, HandlerAndPeer::handler_addr(), peer_config, None)?;
        assert_eq!(store.len("localhost"), tickets - 1, "a ticket is offered");
        pair.peer = peer;
        pair.events.clear();
        let _ = pair.run();
        assert!(
            pair.events
                .iter()
                .any(|event| matches!(event, RTCEventInternal::DTLSHandshakeComplete(..))),
            "the second handshake completed"
        );
        assert!(!handler_resumed(&pair), "as a full handshake");
        assert!(
            pair.peer
                .get_connection_state(HandlerAndPeer::handler_addr())
                .is_some_and(|state| !state.resumed()),
            "the peer sees a full handshake too"
        );
        Ok(())
    }

    /// Review F9: a client transport becomes the session's leader as it starts its handshake;
    /// when the handshake cannot start (here: no endpoint), it leads nothing, and the
    /// transports waiting for it start at once.
    #[test]
    fn a_leader_whose_handshake_cannot_start_holds_no_one_back() -> Result<()> {
        use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
        use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
        use crate::peer_connection::transport::dtls::resumption::DtlsSessionGroup;
        use crate::peer_connection::transport::ice::role::RTCIceRole;

        let provider = crypto::default_provider().expect("a built-in crypto provider");
        let group = Arc::new(DtlsSessionGroup::new(provider.as_ref())?);
        let params = RTCDtlsParameters {
            role: RTCDtlsRole::Server,
            fingerprints: vec![RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: "02".repeat(32),
            }],
        };
        let mut transports = vec![];
        for _ in 0..2 {
            let mut transport = DtlsTransport::new(
                crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
                    id: test_transport_id(TransportKind::Dtls),
                    ice_transport_id: test_transport_id(TransportKind::Ice),
                    certificates: vec![],
                    answering_dtls_role: Default::default(),
                    srtp_protection_profiles: vec![],
                    use_srtp_always: true,
                    dtls_cipher_suites: vec![],
                    allow_insecure_verification_algorithm: false,
                    disable_certificate_fingerprint_verification: true,
                    replay_protection: Default::default(),
                    crypto_provider: provider.clone(),
                },
            )?;
            transport.resumption = Some(group.clone());
            transport.start(RTCIceRole::Controlled, params.clone())?;
            transports.push(transport);
        }
        group.close_admission();
        for transport in &mut transports {
            transport.engage_session()?;
            assert!(transport.resumption_member);
            assert_eq!(transport.role(), RTCDtlsRole::Client);
        }
        use sansio::Protocol;
        let mut leader = DtlsHandlerContext::new(transports.remove(0));
        let mut other = DtlsHandlerContext::new(transports.remove(0));
        leader.dtls_transport.dtls_endpoint = None;
        let now = Instant::now();
        let mut stats = RTCStatsAccumulator::default();
        let pair_selected = || TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::ICESelectedCandidatePairChange,
        };
        assert!(
            DtlsHandler::new(&mut leader, &mut stats)
                .handle_event(pair_selected())
                .is_err(),
            "the leader's handshake cannot start"
        );
        assert_eq!(group.ready_at(), Some(now), "it leads nothing");
        let mut handler = DtlsHandler::new(&mut other, &mut stats);
        handler.handle_event(pair_selected())?;
        assert!(
            handler.ctx.waiting_for_session.is_none(),
            "the other does not wait"
        );
        assert!(
            handler.ctx.dtls_transport.dtls_handshake_config.is_none(),
            "it started its handshake"
        );
        Ok(())
    }

    /// Two client transports of one connection taking part in its DTLS session, as handler
    /// contexts: the one that will lead, and another.
    fn two_session_clients() -> Result<(
        Arc<crate::peer_connection::transport::dtls::resumption::DtlsSessionGroup>,
        DtlsHandlerContext,
        DtlsHandlerContext,
    )> {
        use crate::peer_connection::transport::dtls::fingerprint::RTCDtlsFingerprint;
        use crate::peer_connection::transport::dtls::parameters::RTCDtlsParameters;
        use crate::peer_connection::transport::dtls::resumption::DtlsSessionGroup;
        use crate::peer_connection::transport::ice::role::RTCIceRole;

        let provider = crypto::default_provider().expect("a built-in crypto provider");
        let group = Arc::new(DtlsSessionGroup::new(provider.as_ref())?);
        let params = RTCDtlsParameters {
            role: RTCDtlsRole::Server,
            fingerprints: vec![RTCDtlsFingerprint {
                algorithm: "sha-256".to_owned(),
                value: "03".repeat(32),
            }],
        };
        let mut contexts = vec![];
        for _ in 0..2 {
            let mut transport = DtlsTransport::new(
                crate::peer_connection::transport::dtls::RTCDtlsTransportConfig {
                    id: test_transport_id(TransportKind::Dtls),
                    ice_transport_id: test_transport_id(TransportKind::Ice),
                    certificates: vec![],
                    answering_dtls_role: Default::default(),
                    srtp_protection_profiles: vec![],
                    use_srtp_always: true,
                    dtls_cipher_suites: vec![],
                    allow_insecure_verification_algorithm: false,
                    disable_certificate_fingerprint_verification: true,
                    replay_protection: Default::default(),
                    crypto_provider: provider.clone(),
                },
            )?;
            transport.resumption = Some(group.clone());
            transport.start(RTCIceRole::Controlled, params.clone())?;
            contexts.push(transport);
        }
        group.close_admission();
        for transport in &mut contexts {
            transport.engage_session()?;
        }
        let leader = DtlsHandlerContext::new(contexts.remove(0));
        let other = DtlsHandlerContext::new(contexts.remove(0));
        Ok((group, leader, other))
    }

    /// Review F1: a client transport waits for the leader's handshake at most
    /// `LEADER_WAIT_FLIGHTS` of its initial flight intervals; then it starts a full
    /// handshake, whatever the leader does.
    #[test]
    fn a_waiting_transport_starts_after_the_bound_whatever_the_leader_does() -> Result<()> {
        use crate::peer_connection::transport::dtls::resumption::LEADER_WAIT_FLIGHTS;
        use sansio::Protocol;

        let (group, mut leader, mut other) = two_session_clients()?;
        let now = Instant::now();
        let mut stats = RTCStatsAccumulator::default();
        let pair_selected = || TaggedRTCEventInternal {
            now,
            event: RTCEventInternal::ICESelectedCandidatePairChange,
        };
        // The leader starts; its handshake never completes (nothing answers it).
        DtlsHandler::new(&mut leader, &mut stats).handle_event(pair_selected())?;
        let mut handler = DtlsHandler::new(&mut other, &mut stats);
        handler.handle_event(pair_selected())?;
        let bound = LEADER_WAIT_FLIGHTS
            * crate::peer_connection::transport::dtls::DTLS_SRTP_FLIGHT_INTERVAL;
        assert_eq!(
            handler.ctx.waiting_for_session,
            Some((now, now + bound)),
            "it waits, at most {bound:?} (no round trip measured: 400 ms flights)"
        );
        assert!(
            handler.poll_timeout().is_some_and(|at| at <= now + bound),
            "a timer for the bound"
        );
        handler.handle_timeout(now + bound - std::time::Duration::from_millis(1))?;
        while handler.poll_write().is_some() {}
        assert!(handler.ctx.waiting_for_session.is_some(), "still waiting");
        assert!(handler.ctx.dtls_transport.dtls_handshake_config.is_some());
        handler.handle_timeout(now + bound)?;
        assert!(handler.ctx.waiting_for_session.is_none());
        assert!(
            handler.ctx.dtls_transport.dtls_handshake_config.is_none(),
            "it started its handshake"
        );
        assert!(handler.poll_write().is_some(), "its ClientHello goes out");
        assert_eq!(group.ready_at(), None, "the leader is still not done");
        Ok(())
    }

    /// Review 2, R5: where ICE measured the round trip time of the waiting transport's pair,
    /// the bound is three flight intervals of 1.5 times it (4.5 round trips), and never more
    /// than `LEADER_WAIT_MAX` (3 s): one slow sample, which the peer controls, does not
    /// stretch the wait. With the libwebrtc flight rule (twice the round trip, up to 3 s a
    /// flight) the same cap holds. At the cap the transport starts a full handshake.
    #[test]
    fn the_wait_for_the_leader_is_capped_whatever_round_trip_ice_measured() -> Result<()> {
        use crate::peer_connection::configuration::setting_engine::DtlsFlightInterval;
        use crate::peer_connection::transport::dtls::resumption::LEADER_WAIT_MAX;
        use sansio::Protocol;
        use std::time::Duration;

        assert_eq!(
            LEADER_WAIT_MAX,
            Duration::from_secs(3),
            "the stated maximum"
        );
        for (rule, round_trip_time, expected) in [
            // 3 x 1.5 x 200 ms.
            (DtlsFlightInterval::Rfc9147, 0.2, Duration::from_millis(900)),
            // 3 x 1.5 x 600 ms = 2.7 s: under the cap.
            (
                DtlsFlightInterval::Rfc9147,
                0.6,
                Duration::from_millis(2700),
            ),
            // 3 x 1.5 x 2 s = 9 s uncapped.
            (DtlsFlightInterval::Rfc9147, 2.0, LEADER_WAIT_MAX),
            // 3 x 1.5 x 60 s = 4.5 minutes uncapped.
            (DtlsFlightInterval::Rfc9147, 60.0, LEADER_WAIT_MAX),
            // 3 x 3 s (the rule's own ceiling for a flight) = 9 s uncapped.
            (DtlsFlightInterval::Libwebrtc, 2.0, LEADER_WAIT_MAX),
        ] {
            let (group, mut leader, mut other) = two_session_clients()?;
            other.dtls_transport.flight_interval_rule = rule;
            let now = Instant::now();
            let mut stats = RTCStatsAccumulator::default();
            stats.transport.selected_candidate_pair_id = "pair".to_owned();
            stats.ice_candidate_pairs.insert(
                "pair".to_owned(),
                crate::statistics::accumulator::IceCandidatePairAccumulator {
                    current_round_trip_time: round_trip_time,
                    ..Default::default()
                },
            );
            let pair_selected = || TaggedRTCEventInternal {
                now,
                event: RTCEventInternal::ICESelectedCandidatePairChange,
            };
            DtlsHandler::new(&mut leader, &mut stats).handle_event(pair_selected())?;
            let mut handler = DtlsHandler::new(&mut other, &mut stats);
            handler.handle_event(pair_selected())?;
            assert_eq!(
                handler.ctx.waiting_for_session,
                Some((now, now + expected)),
                "{rule:?}, round trip {round_trip_time} s"
            );
            assert!(
                handler
                    .poll_timeout()
                    .is_some_and(|at| at <= now + expected),
                "{rule:?} {round_trip_time}: a timer for the bound"
            );
            handler.handle_timeout(now + expected - Duration::from_millis(1))?;
            while handler.poll_write().is_some() {}
            assert!(
                handler.ctx.waiting_for_session.is_some(),
                "{rule:?} {round_trip_time}: still waiting"
            );
            handler.handle_timeout(now + expected)?;
            assert!(
                handler.ctx.waiting_for_session.is_none()
                    && handler.ctx.dtls_transport.dtls_handshake_config.is_none(),
                "{rule:?} {round_trip_time}: it started its handshake at the bound"
            );
            assert!(handler.poll_write().is_some(), "its ClientHello goes out");
            assert_eq!(group.ready_at(), None, "the leader is still not done");
        }
        Ok(())
    }

    /// Whether the handler's association was resumed from a PSK.
    fn handler_resumed(pair: &HandlerAndPeer) -> bool {
        pair.context
            .dtls_transport
            .dtls_endpoint
            .as_ref()
            .and_then(|endpoint| {
                endpoint.get_connection_state(TransportContext::default().peer_addr)
            })
            .is_some_and(State::resumed)
    }

    /// The extension types of the first ClientHello in `datagrams`, put together from its
    /// fragments (with the hybrid post-quantum key share it takes two records) and read field
    /// by field (RFC 6347 section 4.2.2).
    fn client_hello_extensions(datagrams: &[bytes::BytesMut]) -> Vec<u16> {
        let mut body: Option<Vec<u8>> = None;
        let mut received = 0;
        'datagrams: for datagram in datagrams {
            let mut rest = &datagram[..];
            while rest.len() >= 13 + 12 {
                let length = usize::from(u16::from_be_bytes([rest[11], rest[12]]));
                let record = &rest[13..13 + length];
                rest = &rest[13 + length..];
                let u24 = |at: usize| {
                    (usize::from(record[at]) << 16)
                        | (usize::from(record[at + 1]) << 8)
                        | usize::from(record[at + 2])
                };
                if record.first() != Some(&1) || record[4..6] != [0, 0] {
                    continue;
                }
                let (total, offset, fragment_length) = (u24(1), u24(6), u24(9));
                let whole = body.get_or_insert_with(|| vec![0; total]);
                whole[offset..offset + fragment_length]
                    .copy_from_slice(&record[12..12 + fragment_length]);
                received += fragment_length;
                if received >= total {
                    break 'datagrams;
                }
            }
        }
        let body = body.expect("a ClientHello");
        let mut at = 2 + 32;
        at += 1 + usize::from(body[at]); // session_id
        at += 1 + usize::from(body[at]); // cookie
        at += 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]])); // cipher_suites
        at += 1 + usize::from(body[at]); // compression_methods
        let end = at + 2 + usize::from(u16::from_be_bytes([body[at], body[at + 1]]));
        at += 2;
        let mut types = vec![];
        while at < end {
            types.push(u16::from_be_bytes([body[at], body[at + 1]]));
            at += 4 + usize::from(u16::from_be_bytes([body[at + 2], body[at + 3]]));
        }
        types
    }

    /// RFC 8446 section 2.2 in WebRTC: the peer connection authenticates every association by
    /// the fingerprints of its SDP and makes a new one per session, so resumption is off. As
    /// the server the transport sends no NewSessionTicket to a client that asks for them, and
    /// a ticket offered to it (made by a server that issues them) gets a full handshake; as
    /// the client it offers no PSK and asks for no ticket (no psk_key_exchange_modes), so a
    /// server that issues them sends it none.
    #[test]
    fn the_peer_connection_neither_sends_nor_accepts_session_tickets() -> Result<()> {
        use dtls::session::{MemorySessionStore, SessionStore};
        let provider = crypto::default_provider().expect("a built-in crypto provider");
        let store = Arc::new(MemorySessionStore::new());

        // A ticket of another server for the name the peer client uses: none (a client with
        // no server name and no remote address keys its tickets under the empty name).
        {
            use dtls::config::ConfigBuilder;
            let certificate = dtls::crypto::Certificate::generate_self_signed(
                vec!["localhost".into()],
                provider.crypto(),
            )?;
            let issuing = Arc::new(
                ConfigBuilder::default()
                    .with_crypto_provider(provider.clone())
                    .with_certificates(vec![certificate])
                    .with_insecure_skip_verify(true)
                    .with_session_tickets(1)
                    .build(false, None)?,
            );
            let client = Arc::new(
                ConfigBuilder::default()
                    .with_crypto_provider(provider.clone())
                    .with_insecure_skip_verify(true)
                    .with_session_store(Some(store.clone()))
                    .build(true, None)?,
            );
            let (client_addr, server_addr): (SocketAddr, SocketAddr) =
                ("10.0.0.2:1".parse().unwrap(), "10.0.0.3:1".parse().unwrap());
            let mut a =
                dtls::endpoint::Endpoint::new(client_addr, shared::TransportProtocol::UDP, None);
            let mut b = dtls::endpoint::Endpoint::new(
                server_addr,
                shared::TransportProtocol::UDP,
                Some(issuing),
            );
            let now = Instant::now();
            a.connect(now, server_addr, client, None)?;
            for _ in 0..16 {
                while let Some(transmit) = a.poll_transmit() {
                    let _ = b.read(now, client_addr, None, transmit.message);
                }
                while let Some(transmit) = b.poll_transmit() {
                    let _ = a.read(now, server_addr, None, transmit.message);
                }
            }
        }
        assert_eq!(store.len(""), 1, "the issuing server's ticket");

        // The transport as the server, the peer a client with that store.
        let mut pair = HandlerAndPeer::new_with(RTCDtlsRole::Server, vec![], false, |builder| {
            builder.with_session_store(Some(store.clone()))
        })?;
        assert!(pair.run().is_none());
        assert_eq!(
            pair.context.dtls_transport.state(),
            RTCDtlsTransportState::Connected
        );
        assert!(
            !handler_resumed(&pair),
            "the ticket offered was not accepted"
        );
        assert_eq!(store.len(""), 0, "it was taken, and none came back");
        assert!(store.take("").is_none());

        // The transport as the client, the peer a server that issues tickets.
        let mut pair = HandlerAndPeer::new_with(RTCDtlsRole::Client, vec![], false, |builder| {
            builder.with_session_tickets(2)
        })?;
        assert!(pair.run().is_none());
        assert_eq!(
            pair.context.dtls_transport.state(),
            RTCDtlsTransportState::Connected
        );
        assert!(!handler_resumed(&pair));
        let extensions = client_hello_extensions(&pair.sent);
        assert!(
            extensions.contains(&43),
            "supported_versions: a DTLS 1.3 offer"
        );
        assert!(
            !extensions.contains(&41) && !extensions.contains(&45),
            "no pre_shared_key, no psk_key_exchange_modes: {extensions:?}"
        );
        Ok(())
    }

    /// RFC 8827 section 6.5: media is always protected with SRTP keyed by DTLS. A session with
    /// a media section whose peer negotiates no `use_srtp` cannot carry it: the transport
    /// fails (and the peer connection with it) instead of connecting without keys.
    #[test]
    fn a_peer_without_use_srtp_fails_a_session_with_media() -> Result<()> {
        for role in [RTCDtlsRole::Server, RTCDtlsRole::Client] {
            let mut pair = HandlerAndPeer::new(role, vec![], true)?;
            assert_eq!(
                pair.run(),
                Some(Error::ErrRequestedButNoSrtpExtension),
                "{role}"
            );
            assert_eq!(
                pair.context.dtls_transport.state(),
                RTCDtlsTransportState::Failed,
                "{role}"
            );
            assert!(
                !pair
                    .events
                    .iter()
                    .any(|event| matches!(event, RTCEventInternal::DTLSHandshakeComplete(_, _))),
                "{role}"
            );
            assert!(
                pair.events
                    .iter()
                    .any(|event| matches!(event, RTCEventInternal::DTLSClosed)),
                "{role}: the handlers above are told the transport is gone"
            );
        }
        Ok(())
    }

    /// RFC 9147 section 5.8.2: the client's retransmission timer starts at 400 ms, the value
    /// for DTLS-SRTP, unless ICE has measured the round trip time of the selected pair; then
    /// at 1.5 times that, and never under 100 ms.
    #[test]
    fn the_client_flight_interval_follows_the_ice_round_trip_time() -> Result<()> {
        use crate::peer_connection::configuration::setting_engine::DtlsFlightInterval;
        use std::time::Duration;
        for (rule, round_trip_time, expected) in [
            (
                DtlsFlightInterval::Rfc9147,
                None,
                Duration::from_millis(400),
            ),
            (
                DtlsFlightInterval::Rfc9147,
                Some(0.2),
                Duration::from_millis(300),
            ),
            (
                DtlsFlightInterval::Rfc9147,
                Some(0.01),
                Duration::from_millis(100),
            ),
            // libwebrtc's ComputeRetransmissionTimeout: twice the round trip, within 50 ms
            // and 3 s, and 50 ms without one.
            (
                DtlsFlightInterval::Libwebrtc,
                None,
                Duration::from_millis(50),
            ),
            (
                DtlsFlightInterval::Libwebrtc,
                Some(0.2),
                Duration::from_millis(400),
            ),
            (
                DtlsFlightInterval::Libwebrtc,
                Some(0.01),
                Duration::from_millis(50),
            ),
            (
                DtlsFlightInterval::Libwebrtc,
                Some(2.0),
                Duration::from_secs(3),
            ),
        ] {
            let mut pair = HandlerAndPeer::new_configured(
                RTCDtlsRole::Client,
                vec![],
                false,
                |builder| builder,
                |transport| transport.flight_interval_rule = rule,
            )?;
            if let Some(round_trip_time) = round_trip_time {
                pair.stats.transport.selected_candidate_pair_id = "pair".to_owned();
                pair.stats.ice_candidate_pairs.insert(
                    "pair".to_owned(),
                    crate::statistics::accumulator::IceCandidatePairAccumulator {
                        current_round_trip_time: round_trip_time,
                        ..Default::default()
                    },
                );
            }
            let error = pair.run();
            assert!(error.is_none(), "{rule:?} {round_trip_time:?}: {error:?}");
            assert_eq!(
                pair.context.dtls_transport.flight_interval,
                Some(expected),
                "{rule:?} {round_trip_time:?}"
            );
            assert_eq!(
                pair.context.dtls_transport.state(),
                RTCDtlsTransportState::Connected
            );
        }
        Ok(())
    }
}

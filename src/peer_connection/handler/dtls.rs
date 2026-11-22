use crate::peer_connection::configuration::setting_engine::ReplayProtection;
use crate::peer_connection::event::{RTCEventInternal, TaggedRTCEventInternal};
use crate::peer_connection::message::internal::{
    DTLSMessage, RTCMessageInternal, TaggedRTCMessageInternal,
};
use crate::peer_connection::transport::dtls::DtlsTransport;
use crate::peer_connection::transport::dtls::role::RTCDtlsRole;
use crate::peer_connection::transport::dtls::state::RTCDtlsTransportState;
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
    fn connect_client(&mut self, now: Instant) -> Result<()> {
        if self.ctx.dtls_transport.dtls_role != RTCDtlsRole::Client {
            return Ok(());
        }
        // dtls_endpoint only connect once when acts as DTLSRole::Client
        let Some(dtls_handshake_config) = self.ctx.dtls_transport.dtls_handshake_config.take()
        else {
            return Ok(());
        };
        let dtls_endpoint = self
            .ctx
            .dtls_transport
            .dtls_endpoint
            .as_mut()
            .ok_or(Error::ErrDtlsTransportNotStarted)?;
        dtls_endpoint.connect(
            now,
            TransportContext::default().peer_addr, // always use default for transport to make DTLS tunneled
            dtls_handshake_config,
            None,
        )?;
        while let Some(transmit) = dtls_endpoint.poll_transmit() {
            self.ctx.write_outs.push_back(TaggedRTCMessageInternal {
                now: transmit.now,
                transport: transmit.transport,
                message: RTCMessageInternal::Dtls(DTLSMessage::Raw(transmit.message)),
            });
        }
        Ok(())
    }

    pub(crate) fn name(&self) -> &'static str {
        "DtlsHandler"
    }

    /// Update stats when DTLS handshake completes
    fn update_dtls_stats_from_profile(
        &mut self,
        srtp_profile: SrtpProtectionProfile,
        peer_certificates: &[Vec<u8>],
        dtls_cipher: Option<String>,
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
        // ServerHello bytes; the DTLS stack speaks DTLS 1.2 only (RFC 6347 section 4.1,
        // `{254, 253}`).
        self.stats.transport.tls_version = "FEFD".to_string();

        // Update DTLS cipher from the negotiated cipher suite
        if let Some(cipher) = dtls_cipher {
            self.stats.transport.dtls_cipher = cipher;
        }

        // Register local certificate and set local_certificate_id
        if let Some(local_cert) = self.ctx.dtls_transport.certificates.first() {
            let fingerprints =
                local_cert.get_fingerprints(self.ctx.dtls_transport.crypto_provider.crypto())?;
            if let Some(fp) = fingerprints.first() {
                // Register certificate in accumulator, the DER base64-encoded (webrtc-stats
                // `base64Certificate`)
                if let Some(der) = local_cert.dtls_certificate.certificate.first() {
                    self.stats.register_certificate(
                        fp.value.clone(),
                        CertificateStatsAccumulator {
                            fingerprint: fp.value.clone(),
                            fingerprint_algorithm: fp.algorithm.clone(),
                            base64_certificate: base64_encode(der.as_ref()),
                            issuer_certificate_id: String::new(),
                        },
                    );
                }

                // Set local certificate ID in transport stats
                self.stats.transport.local_certificate_id = fp.value.clone();
            }
        }

        // Register remote certificate and set remote_certificate_id
        if let Some(peer_cert_der) = peer_certificates.first() {
            // Compute fingerprint from peer certificate
            let hash = self
                .ctx
                .dtls_transport
                .crypto_provider
                .crypto()
                .hash(crypto::HashAlgorithm::Sha256, peer_cert_der)
                .map_err(|error| Error::Crypto(error.to_string()))?;
            let fingerprint: String = hash
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(":");

            let cert_id = format!("remote-certificate-{}", &fingerprint[..8]);

            // Register remote certificate in accumulator
            self.stats.register_certificate(
                cert_id.clone(),
                CertificateStatsAccumulator {
                    fingerprint,
                    fingerprint_algorithm: "sha-256".to_string(),
                    base64_certificate: base64_encode(peer_cert_der),
                    issuer_certificate_id: String::new(),
                },
            );

            // Set remote certificate ID in transport stats
            self.stats.transport.remote_certificate_id = cert_id;
        }
        Ok(())
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
                self.ctx.dtls_transport.srtp_negotiated = Some(srtp_contexts.is_some());
                self.ctx
                    .dtls_transport
                    .state_change(RTCDtlsTransportState::Connected);

                let (local_srtp_context, remote_srtp_context) = srtp_contexts.unzip();
                self.ctx.event_outs.push_back(TaggedRTCEventInternal {
                    now: msg.now,
                    event: RTCEventInternal::DTLSHandshakeComplete(
                        local_srtp_context,
                        remote_srtp_context,
                    ),
                });
            }

            // Update stats after dtls_endpoint borrow ends
            if let Some(srtp_profile) = srtp_profile_for_stats {
                self.update_dtls_stats_from_profile(
                    srtp_profile,
                    &peer_certificates_for_stats,
                    dtls_cipher_for_stats,
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
        if let Some(now) = self.ctx.connect_requested.take()
            && let Err(err) = self.connect_client(now)
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
            self.connect_client(now)?;
        } else {
            self.ctx.event_outs.push_back(evt);
        }
        Ok(())
    }

    fn poll_event(&mut self) -> Option<Self::Eout> {
        self.ctx.event_outs.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<()> {
        let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_mut() else {
            return Ok(());
        };

        // A handshake whose retransmissions run out fails here. That failure is reported as the
        // transport's state, not as an error, so the other handlers still get their timeout.
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
        if let Some(dtls_endpoint) = self.ctx.dtls_transport.dtls_endpoint.as_ref() {
            let mut eto = None;

            let remotes = dtls_endpoint.get_connections_keys();
            for remote in remotes {
                if let Some(timeout) = dtls_endpoint.poll_timeout(remote) {
                    eto = Some(eto.map_or(timeout, |e: Instant| e.min(timeout)));
                }
            }

            eto
        } else {
            None
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
    fn fail_transport(&mut self, now: Instant) {
        if matches!(
            self.ctx.dtls_transport.state,
            RTCDtlsTransportState::Failed | RTCDtlsTransportState::Closed
        ) {
            return;
        }
        warn!("dtls transport failed");
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
    pub(crate) fn update_srtp_contexts(
        state: &State,
        replay_protection: &ReplayProtection,
        crypto_provider: &Arc<dyn RTCCryptoProvider>,
    ) -> Result<(srtp::context::Context, srtp::context::Context)> {
        let profile = match state.srtp_protection_profile() {
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm => ProtectionProfile::AeadAes128Gcm,
            SrtpProtectionProfile::Srtp_Aead_Aes_256_Gcm => ProtectionProfile::AeadAes256Gcm,
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80 => {
                ProtectionProfile::Aes128CmHmacSha1_80
            }
            SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32 => {
                ProtectionProfile::Aes128CmHmacSha1_32
            }
            _ => return Err(Error::ErrNoSuchSrtpProfile),
        };

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

        Ok((local_context, remote_context))
    }
}

#[cfg(test)]
mod tests {
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
                use_srtp: true,
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
                use_srtp: true,
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
        let peer_chain = vec![vec![0x30u8, 0x82, 0x01, 0x0a], vec![0x30, 0x82, 0x02, 0x0b]];

        DtlsHandler::new(&mut context, &mut stats).update_dtls_stats_from_profile(
            SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
            &peer_chain,
            None,
        )?;

        assert_eq!(
            peer_chain,
            context.dtls_transport.get_remote_certificates(),
            "the whole chain is retained, not just the first entry the stats path consumes"
        );
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
    }

    impl HandlerAndPeer {
        fn new(
            role: RTCDtlsRole,
            peer_profiles: Vec<SrtpProtectionProfile>,
            srtp_required: bool,
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
                    use_srtp: true,
                    dtls_cipher_suites: vec![],
                    allow_insecure_verification_algorithm: false,
                    disable_certificate_fingerprint_verification: true,
                    replay_protection: Default::default(),
                    crypto_provider: provider.clone(),
                },
            )?;
            transport.srtp_required = srtp_required;
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
                ConfigBuilder::default()
                    .with_crypto_provider(provider)
                    .with_certificates(vec![peer_certificate])
                    .with_srtp_protection_profiles(peer_profiles)
                    .with_insecure_skip_verify(true)
                    .with_extended_master_secret(ExtendedMasterSecretType::Require)
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
}

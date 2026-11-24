//! FEC as a separate stream (RFC 5109 section 14.1): a FEC session of its own.
//!
//! "The FEC stream and the payload stream SHOULD be sent through two separate RTP session"
//! and "MUST NOT be multiplexed by SSRC into one single RTP session since they always have the
//! same SSRC" (section 14.1; section 7.2: "The SSRC value SHALL be the same as the SSRC value
//! of the media stream it protects"). So a separate FEC stream is an m= section of its own,
//! outside the BUNDLE group, on a transport of its own, grouped with the media section by
//! `a=group:FEC-FR` (RFC 5956) or `a=group:FEC` (RFC 4756).
//!
//! RFC 8854 section 5.2 says of a WebRTC endpoint that such sections "SHOULD NOT be offered"
//! and that "Answerers SHOULD reject any FEC-only "m=" lines, unless they specifically know
//! how to handle such a thing". So nothing here happens by itself: an application offers a FEC
//! session with [`RTCPeerConnection::add_fec_session`], and one is accepted only with
//! `SettingEngineBuilder::with_separate_fec_sessions(true)`.
//!
//! # How it is carried
//!
//! - **JSEP.** The FEC session is a transceiver of the protected media's kind, flagged
//!   ([`FecSessionState`]): it has the section's mid, direction, rejection and rollback like
//!   any transceiver, never a track, and its section is written with the one `ulpfec` format
//!   (`sdp::fec_session`). It asks to stay out of every BUNDLE group, which gives it a
//!   transport (RFC 9143 section 7.5.2).
//! - **The chain.** One chain serves every RTP session and keys what it keeps on the SSRC, so
//!   inside it the FEC stream is known by `media SSRC XOR key`
//!   ([`interceptor::FecSessionSsrcMap`]); the map is applied to every RTP and RTCP packet of a
//!   FEC session's transport where the chain meets SRTP, in both directions
//!   (`InterceptorHandler::handle_read`, `RTCPeerConnection::flush_writes`). The protected
//!   sender's streams name the FEC stream ([`interceptor::StreamInfo::fec_session`]); what is
//!   read on the FEC session's transport is marked for the decoder
//!   ([`interceptor::FecSessionPacket`]).

use super::*;
use crate::peer_connection::sdp::fec_session::{FecSection, FecSessionSections};
use crate::rtp_transceiver::internal::{FecSessionFormat, FecSessionState};
use crate::rtp_transceiver::rtp_sender::internal::FecSessionBinding;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{is_repair_codec, repair_family};
use crate::rtp_transceiver::{PayloadType, RTCFecGroupSemantics, RTCRtpTransceiverId, SSRC};

/// The payload type a FEC session's section offers when the application registered no
/// `ulpfec` format for the kind: the section has one format, so any dynamic number is free.
const DEFAULT_FEC_SESSION_PAYLOAD_TYPE: PayloadType = 127;

/// A transport that carries a FEC session, as the pipeline needs to know it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FecSessionTransport {
    /// [`FecSessionState::token`]: finds the transceiver it protects.
    pub(crate) token: u64,
    /// The payload type FEC is received with: this side's section's.
    pub(crate) payload_type: PayloadType,
    /// The clock rate of the section's `ulpfec` format.
    pub(crate) clock_rate: u32,
    /// This side signalled `onelevelonly=1`.
    pub(crate) one_level_only: bool,
    /// The media kind of the section.
    pub(crate) kind: RtpCodecKind,
}

impl RTCPeerConnection {
    /// Offers a FEC session of its own for the media of the transceiver `protected` (RFC 5109
    /// section 14.1): the next offer has a second m= section that lists only `ulpfec`, outside
    /// the BUNDLE group and so on a transport of its own (its own candidates, which the
    /// application gathers, its own DTLS association and SRTP keys: section 11, "different
    /// encryption keys for media and FEC when sent in separate streams"), grouped with the
    /// media section by `a=group:<semantics> <media mid> <FEC mid>`. Once the answer accepts
    /// the section with the group, the ULPFEC of the protected sender's streams is sent there,
    /// each FEC stream with the SSRC of the media stream it protects (section 7.2), and what
    /// arrives there repairs the protected receiver's streams.
    ///
    /// The returned transceiver is the FEC session: it has the direction of `protected` (FEC
    /// is sent where media is sent), which the application may change, can be stopped like
    /// any transceiver, and never has a track. The payload type is the one a `ulpfec` format
    /// registered for the kind has ([`MIME_TYPE_ULP_FEC`]), else 127; the rate is the
    /// protected media's (section 13).
    ///
    /// The chain needs the ULPFEC interceptors
    /// ([`configure_ulpfec_sessions`](crate::peer_connection::configuration::interceptor_registry::configure_ulpfec_sessions)).
    /// The amount of FEC follows the loss the receiver reports and is taken out of the target
    /// the application encodes at (`FecRate`).
    ///
    /// Nothing calls this by itself: RFC 8854 section 5.2 has a WebRTC endpoint not offer
    /// FEC-only m= sections, and no browser accepts one. It is for a peer that implements RFC
    /// 5109 as written (this engine with `with_separate_fec_sessions(true)`).
    ///
    /// # Errors
    ///
    /// The connection is closed, `protected` is no transceiver, is stopped, is itself a FEC
    /// session or already has one, or is neither audio nor video.
    ///
    /// [`MIME_TYPE_ULP_FEC`]: crate::peer_connection::configuration::media_engine::MIME_TYPE_ULP_FEC
    pub fn add_fec_session(
        &mut self,
        protected: RTCRtpTransceiverId,
        semantics: RTCFecGroupSemantics,
    ) -> Result<RTCRtpTransceiverId> {
        if self.is_closed() {
            return Err(Error::ErrConnectionClosed);
        }
        let Some(transceiver) = self.rtp_transceivers.get(protected) else {
            return Err(Error::ErrRTPTransceiverNotExisted);
        };
        let kind = transceiver.kind();
        if transceiver.stopped()
            || transceiver.fec_session().is_some()
            || self.fec_session_of(protected).is_some()
            || !matches!(kind, RtpCodecKind::Audio | RtpCodecKind::Video)
        {
            return Err(Error::ErrOperationError(
                "a FEC session protects the media of one live audio or video transceiver"
                    .to_owned(),
            ));
        }
        let codecs = self.media_engine.get_codecs_by_kind(kind);
        let registered = codecs
            .iter()
            .find(|codec| repair_family(&codec.rtp_codec) == "ulpfec");
        // RFC 5109 section 13: the rate of the protected media, above 1000 Hz.
        let media_rate = codecs
            .iter()
            .find(|codec| !is_repair_codec(&codec.rtp_codec))
            .map(|codec| codec.rtp_codec.clock_rate)
            .filter(|rate| *rate > 1000)
            .unwrap_or(90_000);
        let local = FecSessionFormat {
            // RFC 5109 section 14.1: "dynamic payload type numbers MUST be used".
            payload_type: registered
                .map(|codec| codec.payload_type)
                .filter(|payload_type| *payload_type >= 96)
                .unwrap_or(DEFAULT_FEC_SESSION_PAYLOAD_TYPE),
            clock_rate: registered
                .map(|codec| codec.rtp_codec.clock_rate)
                .filter(|rate| *rate > 1000)
                .unwrap_or(media_rate),
            one_level_only: false,
        };
        let direction = match transceiver.direction() {
            direction @ (RTCRtpTransceiverDirection::Sendrecv
            | RTCRtpTransceiverDirection::Sendonly
            | RTCRtpTransceiverDirection::Recvonly
            | RTCRtpTransceiverDirection::Inactive) => direction,
            _ => RTCRtpTransceiverDirection::Sendrecv,
        };
        let token: u64 = rand::random();
        let mut session = RTCRtpTransceiverInternal::new(
            kind,
            None,
            RTCRtpTransceiverInit {
                direction,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        session.set_fec_session(Some(FecSessionState {
            token,
            semantics,
            local,
            remote: None,
        }));
        // A second RTP session: never in the media's BUNDLE group (RFC 5109 section 14.1),
        // and no m= section of a remote offer is this transceiver's but its own.
        session.set_bundle_request(Some(false));
        session.set_associable_with_remote_offer(false);
        self.rtp_transceivers[protected].set_protected_by(Some(token));
        self.fec_session_map();
        Ok(self.add_rtp_transceiver(session))
    }

    /// The transceiver that is the FEC session of the transceiver `protected`
    /// ([`Self::add_fec_session`], or an offered one this side accepted), while it lives.
    pub fn fec_session_of(&self, protected: RTCRtpTransceiverId) -> Option<RTCRtpTransceiverId> {
        let token = self.rtp_transceivers.get(protected)?.protected_by()?;
        self.rtp_transceivers.iter().position(|transceiver| {
            !transceiver.stopped()
                && transceiver
                    .fec_session()
                    .is_some_and(|session| session.token == token)
        })
    }

    /// The transceiver whose media the FEC session `session` protects, when `session` is a
    /// FEC session's transceiver.
    pub fn fec_session_protects(
        &self,
        session: RTCRtpTransceiverId,
    ) -> Option<RTCRtpTransceiverId> {
        let token = self.rtp_transceivers.get(session)?.fec_session()?.token;
        self.fec_protected_by(token)
    }

    fn fec_protected_by(&self, token: u64) -> Option<RTCRtpTransceiverId> {
        self.rtp_transceivers
            .iter()
            .position(|transceiver| transceiver.protected_by() == Some(token))
    }

    /// The map between the chain's SSRCs and the wire's for this connection's FEC sessions,
    /// made with the first one.
    pub(crate) fn fec_session_map(&mut self) -> interceptor::FecSessionSsrcMap {
        *self
            .pipeline_context
            .interceptor_handler_context
            .fec_session_map
            .get_or_insert_with(interceptor::FecSessionSsrcMap::random)
    }

    /// For each transceiver, what its m= section is when it is a FEC session's: `None` for
    /// any other transceiver.
    pub(crate) fn fec_sections(&self) -> Vec<Option<FecSection>> {
        self.rtp_transceivers
            .iter()
            .map(|transceiver| {
                let session = transceiver.fec_session()?;
                let protected = &self.rtp_transceivers[self.fec_protected_by(session.token)?];
                Some(FecSection {
                    protected_mid: protected.mid().clone()?,
                    semantics: session.semantics,
                    format: session.local,
                    direction: transceiver.direction(),
                })
            })
            .collect()
    }

    /// A FEC session whose protected transceiver is gone or stopped has nothing to protect:
    /// it is stopped, so the next offer rejects its section. Before a description is made.
    pub(crate) fn stop_fec_sessions_without_media(&mut self) -> Result<()> {
        let orphaned: Vec<usize> = self
            .rtp_transceivers
            .iter()
            .enumerate()
            .filter(|(_, transceiver)| !transceiver.stopped())
            .filter_map(|(index, transceiver)| {
                let session = transceiver.fec_session()?;
                let protected = self.fec_protected_by(session.token);
                protected
                    .is_none_or(|protected| self.rtp_transceivers[protected].stopped())
                    .then_some(index)
            })
            .collect();
        for index in orphaned {
            self.rtp_transceivers[index].stop(&self.media_engine, &mut self.interceptor)?;
        }
        Ok(())
    }

    /// A remote offer's FEC session, accepted (`with_separate_fec_sessions(true)`): the
    /// transceiver its section has, or a new one, flagged and holding the offered format.
    /// Returns the transceiver, and whether it was made now.
    pub(crate) fn apply_offered_fec_session(
        &mut self,
        offered: &FecSessionSections,
        kind: RtpCodecKind,
        existing: Option<usize>,
    ) -> Result<(usize, bool)> {
        // RFC 3264 section 6.1: the answer uses the offer's payload type for the format.
        let local = FecSessionFormat {
            one_level_only: false,
            ..offered.format
        };
        if let Some(index) = existing {
            let transceiver = &mut self.rtp_transceivers[index];
            match transceiver.fec_session_mut() {
                Some(session) => {
                    session.semantics = offered.semantics;
                    session.local = local;
                    session.remote = Some(offered.format);
                }
                None => {
                    transceiver.set_fec_session(Some(FecSessionState {
                        token: rand::random(),
                        semantics: offered.semantics,
                        local,
                        remote: Some(offered.format),
                    }));
                    transceiver.set_bundle_request(Some(false));
                }
            }
            return Ok((index, false));
        }
        let mut transceiver = RTCRtpTransceiverInternal::new(
            kind,
            None,
            RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Recvonly,
                streams: vec![],
                send_encodings: vec![],
            },
        );
        transceiver.set_mid(offered.fec_mid.clone())?;
        transceiver.set_fec_session(Some(FecSessionState {
            token: rand::random(),
            semantics: offered.semantics,
            local,
            remote: Some(offered.format),
        }));
        transceiver.set_bundle_request(Some(false));
        transceiver.set_associable_with_remote_offer(false);
        // Gone again if the offer is rolled back (RFC 9429 section 5.7).
        transceiver.set_created_by_remote_description(true);
        self.fec_session_map();
        Ok((self.add_rtp_transceiver(transceiver), true))
    }

    /// Pairs each accepted FEC session of a remote offer with the transceiver of the media
    /// section it protects. A session made for this offer takes that transceiver's direction:
    /// FEC is sent where media is sent.
    pub(crate) fn pair_offered_fec_sessions(
        &mut self,
        offered: &[FecSessionSections],
        made_now: &[usize],
    ) {
        for session in offered {
            let by_mid = |mid: &str| {
                self.rtp_transceivers
                    .iter()
                    .position(|t| t.mid().as_deref() == Some(mid))
            };
            let (Some(fec), Some(protected)) =
                (by_mid(&session.fec_mid), by_mid(&session.protected_mid))
            else {
                continue;
            };
            let Some(token) = self.rtp_transceivers[fec]
                .fec_session()
                .map(|state| state.token)
            else {
                continue;
            };
            // One session for a transceiver: an earlier pairing of the token goes.
            for transceiver in &mut self.rtp_transceivers {
                if transceiver.protected_by() == Some(token) {
                    transceiver.set_protected_by(None);
                }
            }
            self.rtp_transceivers[protected].set_protected_by(Some(token));
            if made_now.contains(&fec) {
                let direction = self.rtp_transceivers[protected].direction();
                if matches!(
                    direction,
                    RTCRtpTransceiverDirection::Sendrecv
                        | RTCRtpTransceiverDirection::Sendonly
                        | RTCRtpTransceiverDirection::Recvonly
                        | RTCRtpTransceiverDirection::Inactive
                ) {
                    self.rtp_transceivers[fec].set_direction(direction);
                }
            }
        }
    }

    /// The transport of a FEC session's section, when it is one no other section and no data
    /// channel uses: the FEC session is an RTP session of its own (RFC 5109 section 14.1).
    /// A section that ended up on a shared transport is not carried: there the FEC stream's
    /// SSRC would be the media stream's own.
    fn fec_session_transport_id(&self, index: usize) -> Option<TransportId> {
        let transports = &self.pipeline_context.transports;
        if transports.len() < 2 {
            return None;
        }
        let mid = self.rtp_transceivers[index].mid().as_deref()?;
        let id = transports.assignment(mid)?;
        let shared = id == transports.data_transport_id() && !self.data_channels.is_empty()
            || self.rtp_transceivers.iter().enumerate().any(|(other, t)| {
                other != index
                    && !t.stopped()
                    && t.mid()
                        .as_deref()
                        .is_some_and(|mid| transports.transport_id_for(mid) == id)
            });
        (!shared).then_some(id)
    }

    /// Brings the pipeline in line with the FEC sessions as negotiation left them: which
    /// transports carry one, and for each protected sender where its FEC goes
    /// ([`FecSessionBinding`]). Run before the senders' streams are bound.
    pub(crate) fn sync_fec_sessions(&mut self) {
        let map = self
            .pipeline_context
            .interceptor_handler_context
            .fec_session_map;
        let mut transports = std::collections::HashMap::new();
        let mut bindings: Vec<Option<FecSessionBinding>> = vec![None; self.rtp_transceivers.len()];
        if let Some(map) = map {
            for (index, transceiver) in self.rtp_transceivers.iter().enumerate() {
                let Some(session) = transceiver.fec_session() else {
                    continue;
                };
                if transceiver.stopped() {
                    continue;
                }
                let Some(id) = self.fec_session_transport_id(index) else {
                    continue;
                };
                transports.insert(
                    id.0,
                    FecSessionTransport {
                        token: session.token,
                        payload_type: session.local.payload_type,
                        clock_rate: session.local.clock_rate,
                        one_level_only: session.local.one_level_only,
                        kind: transceiver.kind(),
                    },
                );
                // Sent once the remote description accepted the session and this side's
                // negotiated direction sends.
                if let (Some(remote), Some(protected)) =
                    (session.remote, self.fec_protected_by(session.token))
                    && transceiver.current_direction().has_send()
                {
                    bindings[protected] = Some(FecSessionBinding {
                        key: map.key(),
                        payload_type: remote.payload_type,
                        one_level_only: remote.one_level_only,
                    });
                }
            }
        }
        for (transceiver, binding) in self.rtp_transceivers.iter_mut().zip(bindings) {
            if let Some(sender) = transceiver.sender_mut() {
                sender.set_fec_session(binding);
            }
        }
        let ctx = &mut self.pipeline_context.interceptor_handler_context;
        // The FEC streams read on a transport that carries a session no more leave the chain.
        let gone: Vec<interceptor::StreamInfo> = {
            let (kept, gone) = std::mem::take(&mut ctx.fec_session_remote_streams)
                .into_iter()
                .partition(|(transport, _)| transports.contains_key(transport));
            ctx.fec_session_remote_streams = kept;
            gone.into_iter().map(|(_, info)| info).collect()
        };
        ctx.fec_session_transports = transports;
        for info in gone {
            self.interceptor.unbind_remote_stream(&info);
        }
    }

    /// The SSRCs the chain knows the streams of the FEC session `index` by, local and remote:
    /// those of the protected transceiver's sender and receiver, mapped.
    pub(crate) fn fec_session_chain_ssrcs(&self, index: usize) -> Vec<SSRC> {
        let Some(map) = self
            .pipeline_context
            .interceptor_handler_context
            .fec_session_map
        else {
            return vec![];
        };
        let Some(protected) = self.rtp_transceivers[index]
            .fec_session()
            .and_then(|session| self.fec_protected_by(session.token))
        else {
            return vec![];
        };
        let protected = &self.rtp_transceivers[protected];
        let sent = protected.sender().iter().flat_map(|sender| {
            sender
                .send_encodings()
                .iter()
                .filter_map(|encoding| encoding.rtp_coding_parameters.ssrc)
        });
        let received = protected.receiver().iter().flat_map(|receiver| {
            receiver
                .get_coding_parameters()
                .iter()
                .filter_map(|coding| coding.ssrc)
        });
        sent.chain(received).map(|ssrc| map.map(ssrc)).collect()
    }

    /// The transport of the FEC session whose stream the chain knows by `ssrc`.
    pub(crate) fn fec_session_transport_of_ssrc(&self, ssrc: SSRC) -> Option<TransportId> {
        self.pipeline_context
            .interceptor_handler_context
            .fec_session_map?;
        (0..self.rtp_transceivers.len()).find_map(|index| {
            let transceiver = &self.rtp_transceivers[index];
            if transceiver.stopped() || transceiver.fec_session().is_none() {
                return None;
            }
            self.fec_session_chain_ssrcs(index)
                .contains(&ssrc)
                .then(|| self.fec_session_transport_id(index))
                .flatten()
        })
    }
}

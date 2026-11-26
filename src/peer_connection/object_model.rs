//! The W3C object model's bookkeeping behind the public methods of `RTCPeerConnection`: what
//! `addTrack`, `removeTrack`, `replaceTrack`, the direction setter and `stop()` do to the
//! sender, receiver and transceiver objects (webrtc-pc sections 5.1 to 5.4).

use super::RTCPeerConnection;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::event::{RTCPeerConnectionEvent, RTCTrackEvent};
use crate::peer_connection::state::peer_connection_state::RTCPeerConnectionState;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};
use crate::rtp_transceiver::{RTCRtpSenderId, RTCRtpTransceiverId};
use shared::error::{Error, Result};

impl RTCPeerConnection {
    /// W3C `[[IsClosed]]`.
    pub(crate) fn is_closed(&self) -> bool {
        self.peer_connection_state == RTCPeerConnectionState::Closed
    }

    /// Whether a sender of the connection already has a track with `track`'s id (W3C
    /// `addTrack`: "If an RTCRtpSender for track already exists in connection's set of
    /// transceivers, throw an InvalidAccessError").
    pub(super) fn has_sender_for_track(&self, track: &MediaStreamTrack) -> bool {
        self.rtp_transceivers.iter().any(|transceiver| {
            transceiver
                .sender()
                .as_ref()
                .and_then(|sender| sender.attached_track())
                .is_some_and(|attached| attached.track_id() == track.track_id())
        })
    }

    /// Encodings for a new sender of `kind`, each with its SSRC and, when the media engine
    /// can carry one, its RTX SSRC: `encodings` as given, or one default encoding when there
    /// are none. Also the codec preferences the encodings' own codecs imply.
    pub(super) fn new_send_encodings(
        &self,
        kind: RtpCodecKind,
        mut encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Result<(Vec<RTCRtpEncodingParameters>, Vec<RTCRtpCodecParameters>)> {
        if encodings.is_empty() {
            encodings.push(RTCRtpEncodingParameters {
                active: true,
                // W3C webrtc 5.2 "create an RTCRtpSender": a video sender's one default
                // encoding has scaleResolutionDownBy 1.0.
                scale_resolution_down_by: (kind == RtpCodecKind::Video).then_some(1.0),
                ..Default::default()
            });
        }
        self.refuse_taken_ssrcs(&encodings, None)?;
        let placeholder =
            MediaStreamTrack::new(String::new(), String::new(), String::new(), kind, vec![]);
        let (_, encodings, codec_preferences) =
            self.normalize_sender_track(placeholder, encodings)?;
        Ok((encodings, codec_preferences))
    }

    /// Gives the sender of transceiver `id` its encodings (SSRCs) when it has none yet: a
    /// sender made without a track for a transceiver that did not send.
    pub(crate) fn ensure_send_encodings(&mut self, id: RTCRtpTransceiverId) -> Result<()> {
        let Some(transceiver) = self.rtp_transceivers.get(id) else {
            return Err(Error::ErrRTPSenderNotExisted);
        };
        if transceiver
            .sender()
            .as_ref()
            .is_some_and(|sender| sender.has_send_encodings())
        {
            return Ok(());
        }
        let (encodings, _) = self.new_send_encodings(transceiver.kind(), vec![])?;
        if let Some(sender) = self.rtp_transceivers[id].sender_mut() {
            sender.set_send_encodings(encodings);
        }
        Ok(())
    }

    /// W3C `addTrack`, once the transceiver is chosen: its sender's track is `track` and its
    /// direction gains "send". The sender takes the track's own encodings (the SSRCs the
    /// application gave them) unless a description already carries the sender's.
    pub(super) fn attach_track_to_transceiver(
        &mut self,
        id: RTCRtpTransceiverId,
        track: MediaStreamTrack,
    ) -> Result<RTCRtpSenderId> {
        let send_encodings = self.send_encodings_from_track(&track);
        self.refuse_taken_ssrcs(&send_encodings, Some(id))?;
        let (track, send_encodings, codec_preferences) =
            self.normalize_sender_track(track, send_encodings)?;

        let transceiver = &mut self.rtp_transceivers[id];
        if transceiver.get_codec_preferences().is_empty() && !codec_preferences.is_empty() {
            transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
        }
        let preferences = transceiver.get_codec_preferences().to_vec();
        // Codecs a remote description gave the sender carry its payload types (RFC 9429
        // section 5.10) and stay; the transceiver's preferences carry this endpoint's.
        let send_codecs_from_remote = transceiver.send_codecs_from_remote();
        let streams = crate::rtp_transceiver::rtp_sender::internal::track_streams(&track);
        if let Some(sender) = transceiver.sender_mut() {
            if !sender.has_send_encodings() || !sender.is_negotiated() {
                sender.set_send_encodings(send_encodings);
            }
            sender.attach_track(track, streams);
            if !send_codecs_from_remote {
                sender.set_codec_preferences(preferences);
            }
        }
        transceiver.set_direction(RTCRtpTransceiverDirection::from_send_recv(
            true,
            transceiver.direction().has_recv(),
        ));
        // Touched by `addTrack`: a rollback keeps it (RFC 9429, Section 5.7).
        transceiver.set_created_by_remote_description(false);

        self.trigger_negotiation_needed();
        Ok(RTCRtpSenderId(id))
    }

    /// W3C `RTCRtpSender.replaceTrack`: see [`RTCRtpSender::replace_track`].
    ///
    /// [`RTCRtpSender::replace_track`]: crate::rtp_transceiver::rtp_sender::RTCRtpSender::replace_track
    pub(crate) fn replace_sender_track(
        &mut self,
        id: RTCRtpTransceiverId,
        track: Option<MediaStreamTrack>,
    ) -> Result<()> {
        let Some(transceiver) = self.rtp_transceivers.get(id) else {
            return Err(Error::ErrRTPSenderNotExisted);
        };
        if let Some(track) = track.as_ref()
            && track.kind() != transceiver.kind()
        {
            return Err(Error::ErrRTPSenderNewTrackHasIncorrectKind);
        }
        if transceiver.stopped() {
            return Err(Error::InvalidStateError);
        }
        // "If sending is true, and withTrack is not null, determine if withTrack can be sent
        // immediately by the sender without violating the sender's already-negotiated
        // envelope, and if it cannot ... InvalidModificationError" (W3C replaceTrack).
        let sending = matches!(
            transceiver.current_direction(),
            RTCRtpTransceiverDirection::Sendrecv | RTCRtpTransceiverDirection::Sendonly
        );
        if sending
            && let (Some(track), Some(sender)) = (track.as_ref(), transceiver.sender())
            && !sender.within_negotiated_envelope(track.codings())
        {
            return Err(Error::InvalidModificationError);
        }

        let Some(track) = track else {
            if let Some(sender) = self.rtp_transceivers[id].sender_mut()
                && sender.has_track()
            {
                sender.detach_track(&mut self.interceptor);
            }
            return Ok(());
        };

        // The new track's own encodings (its SSRCs) are taken only while no description
        // carries the sender's: afterwards they stay as negotiated.
        let adopts_encodings = transceiver.sender().as_ref().is_some_and(|sender| {
            !sender.has_send_encodings() || (!sender.has_track() && !sender.is_negotiated())
        });
        let (track, send_encodings) = if adopts_encodings && !track.codings().is_empty() {
            let send_encodings = self.send_encodings_from_track(&track);
            self.refuse_taken_ssrcs(&send_encodings, Some(id))?;
            let (track, send_encodings, codec_preferences) =
                self.normalize_sender_track(track, send_encodings)?;
            let transceiver = &mut self.rtp_transceivers[id];
            if transceiver.get_codec_preferences().is_empty() && !codec_preferences.is_empty() {
                transceiver.set_codec_preferences(codec_preferences, &self.media_engine)?;
            }
            (track, Some(send_encodings))
        } else {
            (track, None)
        };
        self.ensure_send_encodings(id)?;
        if let Some(sender) = self.rtp_transceivers[id].sender_mut() {
            match send_encodings {
                Some(send_encodings) => sender.set_send_encodings(send_encodings),
                // The sender's encodings stay; what the new track says it carries (the codec
                // of each of its codings) is what they are sent with from now on.
                None => sender.adopt_coding_codecs(track.codings()),
            }
            sender.replace_track(track)?;
        }
        // Without negotiation: a sender whose track had been removed is bound again, and one
        // whose encodings changed codec is re-bound, if a negotiation started them already.
        self.start_rtp_senders()
    }

    /// Announces that the track of transceiver `id`'s receiver ended
    /// ([`RTCTrackEvent::OnClose`]), when the application was told about the track.
    pub(crate) fn announce_receiver_track_ended(&mut self, id: RTCRtpTransceiverId) {
        let Some(receiver) = self
            .rtp_transceivers
            .get_mut(id)
            .and_then(|transceiver| transceiver.receiver_mut().as_mut())
        else {
            return;
        };
        if !receiver.take_unannounced_end() {
            return;
        }
        let track_id = receiver.track().track_id().clone();
        self.pipeline_context
            .event_outs
            .push_back(RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnClose(
                track_id,
            )));
    }
}

impl RTCPeerConnection {
    /// webrtc-extensions 4.1, an answer applied: each transceiver with a section in it sets
    /// `[[NegotiatedHeaderExtensions]]` and `[[HeaderExtensionsToNegotiate]]` from the
    /// section's `a=extmap` lines (reversed when `remote`; "stopped" for one left out).
    pub(super) fn apply_answer_header_extensions(
        &mut self,
        answer: &sdp::SessionDescription,
        remote: bool,
    ) {
        for media in &answer.media_descriptions {
            let Some(mid) = crate::peer_connection::sdp::get_mid_value(media) else {
                continue;
            };
            let Some(transceiver) = self
                .rtp_transceivers
                .iter_mut()
                .find(|t| t.mid().as_deref() == Some(mid))
            else {
                continue;
            };
            if transceiver.stopped() || media.media_name.port.value == 0 {
                continue;
            }
            let to_negotiate = transceiver.header_extensions_to_negotiate_list(&self.media_engine);
            let negotiated =
                crate::rtp_transceiver::header_extension_control::negotiated_from_answer(
                    &to_negotiate,
                    media,
                    remote,
                );
            transceiver.set_negotiated_header_extensions(negotiated);
        }
    }

    /// webrtc-extensions 4.1: a new transceiver's `[[HeaderExtensionsToNegotiate]]` is that of
    /// the first transceiver of its kind that is not stopping, when that one has a list of
    /// its own (otherwise both have the media engine's defaults).
    pub(super) fn inherit_header_extensions_to_negotiate(
        &self,
        transceiver: &mut crate::rtp_transceiver::internal::RTCRtpTransceiverInternal,
    ) {
        if let Some(first) = self
            .rtp_transceivers
            .iter()
            .find(|t| t.kind() == transceiver.kind() && !t.stopped())
            && first.has_header_extensions_to_negotiate()
        {
            transceiver.set_header_extensions_to_negotiate(
                first.header_extensions_to_negotiate_list(&self.media_engine),
            );
        }
    }
}

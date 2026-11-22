use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::interceptor_registry::create_stream_info;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::rtp_transceiver::SSRC;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_sender::MAX_SEND_ENCODINGS;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    RTCRtpCodec, RtpCodecKind, codec_dictionary_match, encoding_send_codec, find_fec_format,
    find_rtx_payload_type, is_repair_codec, repair_family,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpRidRestrictions;
use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_header_extension_capability::RTCRtpHeaderExtensionCapability;
use crate::rtp_transceiver::rtp_sender::rtp_send_parameters::RTCRtpSendParameters;
use crate::rtp_transceiver::rtp_sender::set_parameter_options::RTCSetParameterOptions;
use interceptor::{Interceptor, StreamInfo};
use shared::error::{Error, Result};
use shared::util::math_rand_alpha;

/// Internal RTP sender implementation.
///
/// This structure manages the state and configuration of an RTP sender,
/// including track association, encoding parameters, codec selection, and negotiation status.
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpSender
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcrtpsender-interface
#[derive(Default, Debug, Clone)]
pub(crate) struct RTCRtpSenderInternal {
    /// The codec kind (audio or video) for this sender
    kind: RtpCodecKind,
    /// What the sender is signalled and sent as: the ids of its `a=msid` lines, which
    /// `replaceTrack` leaves alone (W3C webrtc 5.2), and the codings (SSRCs) it sends now.
    /// It has the codings of `send_encodings`, and none once the track was removed
    /// (`track_removed`), so "has codings" is "sends": nothing is bound, routed or counted
    /// for a sender whose track was taken away.
    sender_track: MediaStreamTrack,
    /// The application set `[[SenderTrack]]` to null (`removeTrack`, `replaceTrack(null)`):
    /// the sender stopped sending and refuses RTP until it has a track again. A sender made
    /// without a track is not in this state: the engine makes no media of its own, so one
    /// created to send forwards what the application writes.
    track_removed: bool,
    /// W3C `[[SenderTrack]]`: the application's track, with the sender's codings; `None` is
    /// null (a transceiver made without a track, `removeTrack`, `replaceTrack(null)`).
    attached_track: Option<MediaStreamTrack>,
    /// W3C `[[AssociatedMediaStreamIds]]`: exactly what the application gave, without
    /// duplicates, possibly empty.
    associated_media_stream_ids: Vec<MediaStreamId>,
    /// The stream ids the `a=msid` lines carry: the associated ids, or `-` when there are
    /// none (RFC 9429 section 5.2.1).
    msid_stream_ids: Vec<MediaStreamId>,
    /// Encoding parameters for each simulcast/layered encoding
    send_encodings: Vec<RTCRtpEncodingParameters>,
    /// Negotiated codec parameters
    send_codecs: Vec<RTCRtpCodecParameters>,

    /// Cached parameters returned by get_parameters()
    last_returned_parameters: Option<RTCRtpSendParameters>,

    /// Whether SDP negotiation has occurred for this sender
    negotiated: bool,
    sent: bool,
    /// The streams this sender bound to the interceptors, as they were bound: a renegotiation
    /// that changes one unbinds exactly these before binding the new ones, and `stop` unbinds
    /// them whatever the parameters are by then.
    bound_streams: Vec<StreamInfo>,
    /// Reduced-size RTCP as negotiated for the media section (`RTCRtcpParameters::reduced_size`).
    rtcp_reduced_size: bool,
    /// The SSRCs of the simulcast encodings an answer removed (`apply_simulcast_answer`): the
    /// track still has them, but they are neither bound nor sent.
    removed_ssrcs: Vec<SSRC>,
}

impl RTCRtpSenderInternal {
    /// Creates a new RTP sender internal state.
    ///
    /// # Parameters
    ///
    /// * `kind` - The codec kind (audio or video)
    /// * `track` - The media track to send
    /// * `streams` - Media stream IDs to associate with the track. This crate's `add_track`
    ///   has no streams argument: a track names the one stream it is in, so an empty list
    ///   stands for that stream.
    /// * `send_encodings` - Initial encoding parameters for the sender
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: MediaStreamTrack,
        streams: Vec<MediaStreamId>,
        send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Self {
        let streams = if streams.is_empty() {
            vec![track.stream_id().to_string()]
        } else {
            streams
        };
        // Encodings left out are the track's own codings.
        let send_encodings = if send_encodings.is_empty() {
            track.codings().to_vec()
        } else {
            send_encodings
        };
        let mut sender = Self {
            kind,
            sender_track: track.clone(),
            attached_track: Some(track),
            send_encodings,
            ..Default::default()
        };
        sender.set_streams(streams);
        sender.sync_tracks();
        sender
    }

    /// A sender whose `[[SenderTrack]]` is null (W3C webrtc 5.2 "create an RTCRtpSender" with
    /// a kind): every transceiver has one, whether or not it ever sends.
    ///
    /// `send_encodings` may be empty: SSRCs are then allocated when the sender first needs
    /// them (a sending direction, a track).
    pub(crate) fn without_track(
        kind: RtpCodecKind,
        streams: Vec<MediaStreamId>,
        send_encodings: Vec<RTCRtpEncodingParameters>,
    ) -> Self {
        let mut sender = Self {
            kind,
            // Signalled as `a=msid:<stream or -> <id>`: an id of its own, as a browser gives a
            // sender without a track.
            sender_track: MediaStreamTrack::new(
                "-".to_owned(),
                math_rand_alpha(16),
                String::new(),
                kind,
                vec![],
            ),
            attached_track: None,
            send_encodings,
            ..Default::default()
        };
        sender.set_streams(streams);
        sender.sync_tracks();
        sender
    }

    /// What the sender is signalled and sent as: the msid ids, and the codings it sends now
    /// (none while `[[SenderTrack]]` is null).
    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.sender_track
    }

    /// W3C `[[SenderTrack]]`: the track the application attached, `None` for null.
    pub(crate) fn attached_track(&self) -> Option<&MediaStreamTrack> {
        self.attached_track.as_ref()
    }

    pub(crate) fn attached_track_mut(&mut self) -> Option<&mut MediaStreamTrack> {
        self.attached_track.as_mut()
    }

    pub(crate) fn has_track(&self) -> bool {
        self.attached_track.is_some()
    }

    /// Whether the application removed the sender's track: it sends nothing until it gets one.
    pub(crate) fn track_removed(&self) -> bool {
        self.track_removed
    }

    /// Gives the signalled track and the attached one the sender's codings: all of
    /// `send_encodings`, and none for the signalled one once the track was removed.
    fn sync_tracks(&mut self) {
        if let Some(track) = self.attached_track.as_mut() {
            track.set_codings(self.send_encodings.clone());
        }
        self.sender_track.set_codings(if self.track_removed {
            vec![]
        } else {
            self.send_encodings.clone()
        });
    }

    /// Whether the sender has encodings with SSRCs to describe and send with.
    pub(crate) fn has_send_encodings(&self) -> bool {
        !self.send_encodings.is_empty()
    }

    /// Gives a sender that has none its encodings (SSRCs allocated by the caller).
    pub(crate) fn set_send_encodings(&mut self, send_encodings: Vec<RTCRtpEncodingParameters>) {
        self.send_encodings = send_encodings;
        self.last_returned_parameters = None;
        self.sync_tracks();
    }

    /// Gives each encoding the codec the coding of a new track names for it (the coding with
    /// the same rid, or at the same place when there are no rids), when that codec is within
    /// what was negotiated: one of the send codecs, or any before negotiation. A coding that
    /// names no codec, or one that was not negotiated, leaves the encoding's codec alone (the
    /// envelope `replaceTrack` stays in). The SSRCs and rids are the sender's and stay.
    pub(crate) fn adopt_coding_codecs(&mut self, codings: &[RTCRtpEncodingParameters]) {
        for (i, encoding) in self.send_encodings.iter_mut().enumerate() {
            let rid = &encoding.rtp_coding_parameters.rid;
            let coding = if rid.is_empty() {
                codings.get(i)
            } else {
                codings
                    .iter()
                    .find(|coding| &coding.rtp_coding_parameters.rid == rid)
            };
            if let Some(coding) = coding
                && !coding.codec.mime_type.is_empty()
                && (self.send_codecs.is_empty()
                    || encoding_send_codec(&coding.codec, &self.send_codecs).is_some())
            {
                encoding.codec = coding.codec.clone();
            }
        }
        self.last_returned_parameters = None;
        self.sync_tracks();
    }

    /// W3C `addTrack` reusing this sender: the track becomes `[[SenderTrack]]` and what the
    /// sender is signalled as (its `a=msid`), `streams` its associated streams.
    pub(crate) fn attach_track(&mut self, track: MediaStreamTrack, streams: Vec<MediaStreamId>) {
        self.sender_track = track.clone();
        self.attached_track = Some(track);
        self.track_removed = false;
        self.set_streams(streams);
        self.sync_tracks();
    }

    /// W3C `removeTrack` / `replaceTrack(null)`: `[[SenderTrack]]` becomes null and the sender
    /// stops sending (an RTCP BYE goes out for each stream it sent, as the streams are
    /// unbound). The encodings, their SSRCs, the msid and the associated streams stay.
    pub(crate) fn detach_track(&mut self, interceptor: &mut dyn Interceptor) {
        self.attached_track = None;
        self.track_removed = true;
        self.unbind_local_streams(interceptor);
        self.sent = false;
        self.sync_tracks();
    }

    /// Returns the codec kind (audio or video) for this sender.
    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// Returns the negotiated codec parameters for this sender.
    ///
    /// These are the codecs that were negotiated during SDP exchange
    /// and are available for sending.
    pub(crate) fn get_send_codecs(&self) -> &[RTCRtpCodecParameters] {
        &self.send_codecs
    }

    /// The RTP capabilities of the engine for sending `kind` (W3C webrtc 5.2
    /// `RTCRtpSender.getCapabilities`, a static method: no negotiation state is read).
    ///
    /// # Returns
    ///
    /// `None` for a kind that is neither audio nor video.
    pub(crate) fn get_capabilities(
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        rtp_capabilities(kind, RTCRtpTransceiverDirection::Sendonly, media_engine)
    }

    /// Updates the sender's RTP send parameters.
    ///
    /// Validates and applies new encoding parameters including bitrate limits,
    /// frame rates, and resolution scaling.
    ///
    /// # Parameters
    ///
    /// * `parameters` - The new send parameters to apply
    /// * `_set_parameter_options` - Reserved for future options (currently unused)
    ///
    /// # Errors
    ///
    /// The setParameters validation steps (W3C webrtc 5.2):
    /// - `InvalidStateError` when `get_parameters` has not been called since the last
    ///   `set_parameters` (or since the codecs changed)
    /// - `InvalidModificationError` when the transaction id is not the one `get_parameters`
    ///   returned, the number of encodings or an encoding's rid differs, or a read-only member
    ///   (`header_extensions`, `rtcp`, `codecs`) was changed
    /// - `InvalidModificationError` when an encoding's SSRCs were changed, or its `codec` was
    ///   set to one that is not choosable
    /// - `RangeError` for a `scale_resolution_down_by` below 1.0 or a negative `max_framerate`
    pub(crate) fn set_parameters(
        &mut self,
        mut parameters: RTCRtpSendParameters,
        _set_parameter_options: Option<RTCSetParameterOptions>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        // Validate parameters by running the following setParameters validation steps:
        {
            let Some(last) = self.last_returned_parameters.as_ref() else {
                return Err(Error::InvalidStateError);
            };
            // Read-only members: the transaction id, the header extensions, RTCP and codecs.
            if parameters.transaction_id != last.transaction_id {
                return Err(Error::InvalidModificationError);
            }
            if parameters.rtp_parameters.header_extensions != last.rtp_parameters.header_extensions
                || parameters.rtp_parameters.rtcp != last.rtp_parameters.rtcp
                || parameters.rtp_parameters.codecs != last.rtp_parameters.codecs
            {
                return Err(Error::InvalidModificationError);
            }
            // The number of encodings and their order: an encoding is its rid and, in this
            // crate, the SSRCs it was given, none of which `setParameters` may change.
            if parameters.encodings.len() != self.send_encodings.len() {
                return Err(Error::InvalidModificationError);
            }
            for (p, s) in parameters.encodings.iter().zip(self.send_encodings.iter()) {
                let (p, s) = (&p.rtp_coding_parameters, &s.rtp_coding_parameters);
                if p.rid != s.rid
                    || p.ssrc != s.ssrc
                    || p.rtx.as_ref().map(|rtx| rtx.ssrc) != s.rtx.as_ref().map(|rtx| rtx.ssrc)
                    || p.fec.as_ref().map(|fec| fec.ssrc) != s.fec.as_ref().map(|fec| fec.ssrc)
                {
                    return Err(Error::InvalidModificationError);
                }
            }
            // An encoding's codec is one of the choosable codecs: the negotiated send codecs,
            // or before negotiation the codecs the engine can send. An encoding whose codec
            // was not touched passes, whatever it names (`addTransceiver` checked it).
            let choosable: Vec<RTCRtpCodec> = if self.send_codecs.is_empty() {
                media_engine
                    .get_codecs_by_kind(self.kind())
                    .into_iter()
                    .map(|codec| codec.rtp_codec)
                    .collect()
            } else {
                self.send_codecs
                    .iter()
                    .map(|codec| codec.rtp_codec.clone())
                    .collect()
            };
            for (p, s) in parameters.encodings.iter().zip(self.send_encodings.iter()) {
                if p.codec.mime_type.is_empty() || p.codec == s.codec {
                    continue;
                }
                if is_repair_codec(&p.codec)
                    || !choosable
                        .iter()
                        .any(|codec| codec_dictionary_match(&p.codec, codec))
                {
                    return Err(Error::InvalidModificationError);
                }
            }

            if self.kind() == RtpCodecKind::Video {
                parameters.encodings.iter_mut().for_each(|encoding| {
                    encoding.scale_resolution_down_by.get_or_insert(1.0);
                });

                if parameters.encodings.iter().any(|e| {
                    e.scale_resolution_down_by
                        .is_some_and(|v| v.is_nan() || v < 1.0)
                }) {
                    return Err(Error::RangeError(
                        "scaleResolutionDownBy must be >= 1.0".to_string(),
                    ));
                }
            } else {
                // Audio has no resolution or frame rate: those members are removed, not the
                // encodings that carry them (whose count is read-only).
                for encoding in &mut parameters.encodings {
                    encoding.scale_resolution_down_by = None;
                    encoding.max_framerate = None;
                }
            }
            if parameters
                .encodings
                .iter()
                .any(|e| e.max_framerate.is_some_and(|v| v.is_nan() || v < 0.0))
            {
                return Err(Error::RangeError(
                    "maxFramerate must not be negative".to_string(),
                ));
            }
        }

        self.send_encodings = parameters.encodings;
        self.last_returned_parameters = None;
        self.sync_tracks();

        Ok(())
    }

    /// Returns the sender's current RTP send parameters.
    ///
    /// Constructs and caches the send parameters including codecs, encodings,
    /// and header extensions. Subsequent calls return the cached version until
    /// `set_parameters` is called.
    ///
    /// # Parameters
    ///
    /// * `media_engine` - The media engine containing codec and extension information
    pub(crate) fn get_parameters(&mut self, media_engine: &MediaEngine) -> &RTCRtpSendParameters {
        if self.last_returned_parameters.is_none() {
            let mut rtp_parameters = media_engine
                .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Sendonly);

            rtp_parameters.codecs = self.send_codecs.clone();
            rtp_parameters.rtcp.reduced_size = self.rtcp_reduced_size;
            // RFC 7022 / RFC 8834 section 4.9: one CNAME for every stream of the connection.
            rtp_parameters.rtcp.cname = media_engine.rtcp_cname.clone();

            self.last_returned_parameters = Some(RTCRtpSendParameters {
                rtp_parameters,
                transaction_id: math_rand_alpha(16),
                encodings: self.send_encodings.clone(),
            });
        }

        self.last_returned_parameters.as_ref().unwrap()
    }

    /// Replaces the track the sender sends with another of the same kind, without
    /// negotiation: the encodings and their SSRCs, the `a=msid` the sender is signalled with
    /// and its associated streams all stay (W3C webrtc 5.2 `replaceTrack`).
    ///
    /// The caller checks the transceiver (stopping) and binds the streams when the sender
    /// had no track.
    ///
    /// # Errors
    ///
    /// Returns `Error::ErrRTPSenderNewTrackHasIncorrectKind` if the new track's kind
    /// doesn't match the sender's kind.
    ///
    /// ## Specifications
    ///
    /// * [W3C](https://www.w3.org/TR/webrtc/#dom-rtcrtpsender-replacetrack)
    pub(crate) fn replace_track(&mut self, track: MediaStreamTrack) -> Result<()> {
        if self.kind() != track.kind() {
            return Err(Error::ErrRTPSenderNewTrackHasIncorrectKind);
        }
        self.attached_track = Some(track);
        self.track_removed = false;
        self.sync_tracks();
        Ok(())
    }

    /// The stream ids of the sender's `a=msid` lines: its associated streams, or `-` when it
    /// has none (RFC 9429 section 5.2.1). What a description is compared with to tell whether
    /// `setStreams` needs negotiating.
    pub(crate) fn streams(&self) -> &[MediaStreamId] {
        &self.msid_stream_ids
    }

    /// W3C `[[AssociatedMediaStreamIds]]`.
    pub(crate) fn associated_streams(&self) -> &[MediaStreamId] {
        &self.associated_media_stream_ids
    }

    /// Sets the sender's associated stream ids to exactly `streams`, without duplicates; the
    /// list may be empty (W3C webrtc 5.2 `setStreams`).
    pub(crate) fn set_streams(&mut self, streams: Vec<MediaStreamId>) {
        let mut associated: Vec<MediaStreamId> = Vec::with_capacity(streams.len());
        for stream in streams {
            if !associated.contains(&stream) {
                associated.push(stream);
            }
        }
        self.msid_stream_ids = if associated.is_empty() {
            vec!["-".to_owned()]
        } else {
            associated.clone()
        };
        self.associated_media_stream_ids = associated;
        // The negotiation-needed flag is updated by `RTCRtpSender::set_streams`, which has the
        // peer connection.
    }

    /// Returns whether this sender has been negotiated via SDP.
    pub(crate) fn is_negotiated(&self) -> bool {
        self.negotiated
    }

    /// Marks this sender as having been negotiated.
    pub(crate) fn set_negotiated(&mut self) {
        self.negotiated = true;
    }

    pub(crate) fn has_sent(&self) -> bool {
        self.sent
    }
    pub(crate) fn set_sent(&mut self) {
        self.sent = true;
    }

    /// Stops the sender: its streams are unbound, which has the sender report interceptor
    /// say BYE for each (W3C webrtc 5.4 "stop sending and receiving").
    pub(crate) fn stop(
        &mut self,
        _media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<()> {
        self.unbind_local_streams(interceptor);

        self.negotiated = false;
        self.sent = false;

        Ok(())
    }

    /// Sets the preferred codecs for this sender.
    ///
    /// # Parameters
    ///
    /// * `codecs` - Vector of codec parameters in preference order
    pub(crate) fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) {
        self.send_codecs = codecs;
        self.last_returned_parameters = None;
    }

    /// Configures RTX (retransmission) and FEC (forward error correction) for all encodings.
    ///
    /// # Parameters
    ///
    /// * `is_rtx_enabled` - Whether to enable RTX
    /// * `is_fec_enabled` - Whether to enable FEC
    pub(crate) fn configure_rtx_and_fec(&mut self, is_rtx_enabled: bool, is_fec_enabled: bool) {
        for encoding in self.send_encodings.iter_mut() {
            if !is_rtx_enabled {
                encoding.rtp_coding_parameters.rtx = None;
            }
            if !is_fec_enabled {
                encoding.rtp_coding_parameters.fec = None;
            }
        }
        // The streams are bound from the track's codings (`local_stream_infos`), which carry
        // the same repair SSRCs: dropped there too, or a stream would bind an RTX / FEC SSRC
        // with no payload type to send it with.
        self.sync_tracks();
        self.last_returned_parameters = None;
    }

    pub(crate) fn set_rtcp_reduced_size(&mut self, reduced_size: bool) {
        if self.rtcp_reduced_size != reduced_size {
            self.rtcp_reduced_size = reduced_size;
            self.last_returned_parameters = None;
        }
    }

    /// The send codecs of the last stable state, and the repair (RTX / FEC) SSRCs a rolled-back
    /// offer took from the encodings (`configure_rtx_and_fec` drops them when the offer lacks
    /// the repair format), after a rollback. An encoding is found by its SSRC and rid, so one
    /// the application changed since is left alone.
    pub(crate) fn restore_negotiated_state(&mut self, saved: &RTCRtpSenderInternal) {
        self.send_codecs.clone_from(&saved.send_codecs);
        restore_repair_ssrcs(&mut self.send_encodings, &saved.send_encodings);
        self.sync_tracks();
        self.last_returned_parameters = None;
    }

    /// Keeps the simulcast encodings an applied answer accepted, `accepted` being their rids
    /// with the restrictions the answer gave them (see
    /// `RTCPeerConnection::apply_negotiated_simulcast`). Without any of them, the first
    /// encoding stays. A sender with one encoding is left as it is.
    pub(crate) fn apply_simulcast_answer(&mut self, accepted: &[(String, RTCRtpRidRestrictions)]) {
        if self.send_encodings.len() < 2 {
            return;
        }
        let restrictions_of = |rid: &str| {
            accepted
                .iter()
                .find(|(id, _)| id == rid)
                .map(|(_, restrictions)| restrictions)
        };
        let keeps_any = self
            .send_encodings
            .iter()
            .any(|encoding| restrictions_of(&encoding.rtp_coding_parameters.rid).is_some());
        let mut kept = Vec::with_capacity(self.send_encodings.len());
        for (index, mut encoding) in std::mem::take(&mut self.send_encodings)
            .into_iter()
            .enumerate()
        {
            let coding = &mut encoding.rtp_coding_parameters;
            match restrictions_of(&coding.rid) {
                Some(restrictions) => {
                    coding.rid_restrictions = restrictions.clone();
                    kept.push(encoding);
                }
                None if !keeps_any && index == 0 => kept.push(encoding),
                None => {
                    if let Some(ssrc) = coding.ssrc {
                        self.removed_ssrcs.push(ssrc);
                    }
                }
            }
        }
        self.send_encodings = kept;
        self.last_returned_parameters = None;
        self.sync_tracks();
    }

    /// Whether `ssrc` is the SSRC of an encoding an answer removed (`apply_simulcast_answer`).
    pub(crate) fn is_removed_ssrc(&self, ssrc: SSRC) -> bool {
        self.removed_ssrcs.contains(&ssrc)
    }

    /// The streams this sender sends, as the interceptors are to see them now: each coding's
    /// SSRCs with the codec it is sent with ([`encoding_send_codec`]), that codec's RTX
    /// payload type, the FEC payload type and the negotiated header extensions.
    ///
    /// Read from the negotiated state directly, not through `get_parameters`, so that neither
    /// its cache (header extensions do not invalidate it) nor its transaction id is touched.
    fn local_stream_infos(&self, media_engine: &MediaEngine) -> Vec<StreamInfo> {
        let codecs = &self.send_codecs;
        let header_extensions = media_engine
            .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Sendonly)
            .header_extensions;

        let mut infos = vec![];
        for coding in self.track().codings() {
            // An encoding without a codec of its own is sent with the codec negotiation picked,
            // and its stream is bound like any other: without it the interceptors never see the
            // stream (no sender reports, no NACK responder, no TWCC).
            if let Some(&ssrc) = coding.rtp_coding_parameters.ssrc.as_ref()
                && !self.is_removed_ssrc(ssrc)
                && let Some(codec) = encoding_send_codec(&coding.codec, codecs)
            {
                let payload_type_rtx = find_rtx_payload_type(codec.payload_type, codecs);
                let fec_format = find_fec_format(codecs);
                infos.push(create_stream_info(
                    ssrc,
                    // A repair SSRC goes with a repair payload type: without one negotiated it
                    // could not be sent, so the stream does not name it.
                    coding
                        .rtp_coding_parameters
                        .rtx
                        .as_ref()
                        .filter(|_| payload_type_rtx.is_some())
                        .map(|rtx| rtx.ssrc),
                    coding
                        .rtp_coding_parameters
                        .fec
                        .as_ref()
                        .filter(|_| fec_format.is_some())
                        .map(|fec| fec.ssrc),
                    codec.payload_type,
                    payload_type_rtx,
                    fec_format.as_ref(),
                    &codec.rtp_codec,
                    &header_extensions,
                ));
            }
        }
        infos
    }

    /// The sender's encodings as `set_parameters` last left them (their `active` flags are what
    /// the outbound streams' statistics report).
    pub(crate) fn send_encodings(&self) -> &[RTCRtpEncodingParameters] {
        &self.send_encodings
    }

    /// The streams this sender bound to the interceptors, as they were bound.
    pub(crate) fn bound_streams(&self) -> &[StreamInfo] {
        &self.bound_streams
    }

    /// Binds this sender's streams to the interceptors, as negotiation left them.
    pub(crate) fn bind_local_streams(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) {
        let infos = self.local_stream_infos(media_engine);
        for info in &infos {
            interceptor.bind_local_stream(info);
        }
        self.bound_streams = infos;
    }

    /// Re-binds this sender's streams when a renegotiation changed what they are bound with
    /// (the codec an encoding is sent with, so its payload type and clock rate, the RTX payload
    /// type or SSRC, the FEC flow, the header extensions). The SSRCs stay; each changed stream
    /// is unbound with the information it was bound with and bound again with the new.
    ///
    /// The sender report interceptor sees the unbind and bind back to back and keeps the
    /// stream (its packet and octet counts and timing carry on, no RTCP BYE is sent). Other
    /// interceptors reset what they keep for it: the NACK responder's buffer of sent packets is
    /// emptied (packets sent before the change are no longer resent), and the TWCC and
    /// congestion control send side forget the stream until its next packet.
    ///
    /// # Returns
    ///
    /// Whether anything was re-bound.
    pub(crate) fn rebind_local_streams(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> bool {
        let infos = self.local_stream_infos(media_engine);
        if infos == self.bound_streams {
            return false;
        }
        for info in &self.bound_streams {
            interceptor.unbind_local_stream(info);
        }
        for info in &infos {
            interceptor.bind_local_stream(info);
        }
        self.bound_streams = infos;
        true
    }

    /// Unbinds the streams this sender bound, with the information they were bound with.
    pub(crate) fn unbind_local_streams(&mut self, interceptor: &mut dyn Interceptor) {
        for info in std::mem::take(&mut self.bound_streams) {
            interceptor.unbind_local_stream(&info);
        }
    }
}

/// W3C webrtc 5.1 `addTransceiver`, the steps that take `sendEncodings`:
///
/// - a rid that is not `1*(alpha-numeric / "-" / "_")` (RFC 8851 section 10) is a `TypeError`,
///   as are a rid on some encodings only and a repeated rid;
/// - for audio `scaleResolutionDownBy` and `maxFramerate` are removed;
/// - a `scaleResolutionDownBy` below 1.0 and a negative `maxFramerate` are `RangeError`s;
/// - encodings past [`MAX_SEND_ENCODINGS`] are dropped from the end;
/// - video encodings without `scaleResolutionDownBy` get 1.0 when another has one, and
///   otherwise `2^(count - index - 1)`: each layer half the next;
/// - a single encoding loses its rid.
///
/// The codec of an encoding is checked where the encodings are given their SSRCs
/// (`codec_preferences_from_encodings`: one the engine cannot send is refused).
pub(crate) fn validate_send_encodings(
    kind: RtpCodecKind,
    encodings: &mut Vec<RTCRtpEncodingParameters>,
) -> Result<()> {
    let is_rid = |rid: &str| {
        rid.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if let Some(encoding) = encodings
        .iter()
        .find(|encoding| !is_rid(&encoding.rtp_coding_parameters.rid))
    {
        return Err(Error::TypeError(format!(
            "rid {:?} is not RFC 8851 syntax",
            encoding.rtp_coding_parameters.rid
        )));
    }
    let with_rid = encodings
        .iter()
        .filter(|encoding| !encoding.rtp_coding_parameters.rid.is_empty())
        .count();
    if with_rid != 0 && with_rid != encodings.len() {
        return Err(Error::ErrRTPSenderRidNil);
    }
    if encodings.iter().enumerate().any(|(i, encoding)| {
        !encoding.rtp_coding_parameters.rid.is_empty()
            && encodings[..i].iter().any(|earlier| {
                earlier.rtp_coding_parameters.rid == encoding.rtp_coding_parameters.rid
            })
    }) {
        return Err(Error::ErrRTPSenderRIDCollision);
    }

    if kind != RtpCodecKind::Video {
        for encoding in encodings.iter_mut() {
            encoding.scale_resolution_down_by = None;
            encoding.max_framerate = None;
        }
    }
    if encodings.iter().any(|e| {
        e.scale_resolution_down_by
            .is_some_and(|v| v.is_nan() || v < 1.0)
    }) {
        return Err(Error::RangeError(
            "scaleResolutionDownBy must be >= 1.0".to_string(),
        ));
    }
    if encodings
        .iter()
        .any(|e| e.max_framerate.is_some_and(|v| v.is_nan() || v < 0.0))
    {
        return Err(Error::RangeError(
            "maxFramerate must not be negative".to_string(),
        ));
    }

    encodings.truncate(MAX_SEND_ENCODINGS);

    if kind == RtpCodecKind::Video {
        if encodings
            .iter()
            .any(|encoding| encoding.scale_resolution_down_by.is_some())
        {
            for encoding in encodings.iter_mut() {
                encoding.scale_resolution_down_by.get_or_insert(1.0);
            }
        } else {
            let count = encodings.len();
            for (i, encoding) in encodings.iter_mut().enumerate() {
                encoding.scale_resolution_down_by =
                    Some(f64::from(1u32 << (count - i - 1).min(31)));
            }
        }
    }

    if let [encoding] = encodings.as_mut_slice() {
        encoding.rtp_coding_parameters.rid = String::new();
    }
    Ok(())
}

/// The codecs and header extensions the engine implements for `kind` in `direction` (W3C
/// webrtc 5.2.10 `RTCRtpCapabilities`): every registered codec once, the retransmission
/// format as a single entry without an `sdpFmtpLine` (it stands for every primary), and the
/// header extensions registered for the kind and direction.
pub(crate) fn rtp_capabilities(
    kind: RtpCodecKind,
    direction: RTCRtpTransceiverDirection,
    media_engine: &MediaEngine,
) -> Option<RTCRtpCapabilities> {
    if kind == RtpCodecKind::Unspecified {
        return None;
    }
    let mut codecs: Vec<RTCRtpCodec> = vec![];
    for codec in media_engine.get_codecs_by_kind(kind) {
        let mut codec = codec.rtp_codec;
        if is_repair_codec(&codec) && repair_family(&codec) == "rtx" {
            codec.sdp_fmtp_line = String::new();
            codec.rtcp_feedback = vec![];
        }
        if !codecs.contains(&codec) {
            codecs.push(codec);
        }
    }
    Some(RTCRtpCapabilities {
        codecs,
        header_extensions: media_engine
            .get_rtp_parameters_by_kind(kind, direction)
            .header_extensions
            .into_iter()
            .map(|h| RTCRtpHeaderExtensionCapability { uri: h.uri })
            .collect(),
    })
}

/// Gives each encoding of `encodings` that lost its RTX or FEC SSRC the one the encoding with
/// the same SSRC and rid has in `saved`.
pub(crate) fn restore_repair_ssrcs(
    encodings: &mut [RTCRtpEncodingParameters],
    saved: &[RTCRtpEncodingParameters],
) {
    for encoding in encodings {
        let parameters = &mut encoding.rtp_coding_parameters;
        let Some(saved) = saved
            .iter()
            .map(|e| &e.rtp_coding_parameters)
            .find(|saved| saved.ssrc == parameters.ssrc && saved.rid == parameters.rid)
        else {
            continue;
        };
        if parameters.rtx.is_none() {
            parameters.rtx.clone_from(&saved.rtx);
        }
        if parameters.fec.is_none() {
            parameters.fec.clone_from(&saved.fec);
        }
    }
}

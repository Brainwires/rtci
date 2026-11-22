use crate::media_stream::MediaStreamTrack;
use crate::peer_connection::configuration::media_engine::{
    MIME_TYPE_RTX, MediaEngine, RTCPacketTime, has_symmetric_configuration,
};
use crate::peer_connection::sdp::codecs_from_media_description;
use crate::rtp_transceiver::rtp_receiver::internal::RTCRtpReceiverInternal;
use crate::rtp_transceiver::rtp_sender::internal::RTCRtpSenderInternal;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, codec_dictionary_match, codec_parameters_fuzzy_search, find_rtx_payload_type,
    is_repair_codec, repair_family, rtcp_feedback_intersection,
};
use crate::rtp_transceiver::rtp_sender::{RTCRtpCodecParameters, RtpCodecKind};
use crate::rtp_transceiver::{
    PayloadType, RTCRemoteBandwidth, RTCRtpTransceiverDirection, RTCRtpTransceiverInit, fmtp,
};
use interceptor::Interceptor;
use log::trace;
use sdp::MediaDescription;
use shared::error::{Error, Result};
use std::fmt;
use unicase::UniCase;

/// Internal representation of an RTP transceiver.
///
/// Represents a permanent pairing of an RTP sender and RTP receiver that share a common mid.
/// The transceiver manages the direction of media flow and codec preferences.
///
/// # Specification
///
/// See [RTCRtpTransceiver](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver) in the W3C WebRTC specification.
#[derive(Default, Clone)]
pub(crate) struct RTCRtpTransceiverInternal {
    mid: Option<String>,
    kind: RtpCodecKind,
    sender: Option<RTCRtpSenderInternal>,
    receiver: Option<RTCRtpReceiverInternal>,
    direction: RTCRtpTransceiverDirection,
    current_direction: RTCRtpTransceiverDirection,
    preferred_codecs: Vec<RTCRtpCodecParameters>,
    /// W3C `[[Stopping]]`: `stop()` was called, or the transceiver is stopped. Its direction
    /// reads "stopped" and offers reject its m= section.
    stopping: bool,
    /// W3C `[[Stopped]]`: a description rejected the m= section (or a rollback removed the
    /// transceiver). Its current direction reads "stopped".
    stopped: bool,
    /// W3C `[[Receptive]]`: whether the last description applied has this transceiver
    /// receive (a local offer or any answer with a receiving direction).
    receptive: bool,
    /// W3C `[[FiredDirection]]`: the direction of the last remote description processed for
    /// remote tracks, `None` before the first.
    fired_direction: Option<RTCRtpTransceiverDirection>,
    /// Whether `[[CurrentDirection]]` ever was sendrecv or sendonly: such a transceiver's
    /// sender "has been used to send" and `addTrack` does not take it (W3C webrtc 5.1).
    used_to_send: bool,
    /// Whether this transceiver was implicitly created while applying a remote offer
    /// (as opposed to being created by the application via `add_track`/`add_transceiver_*`).
    /// Used by rollback (RFC 9429, Section 5.7): transceivers created by a remote offer that
    /// is subsequently rolled back must be stopped and removed, unless a track was later
    /// attached to them via `add_track`.
    created_by_remote_description: bool,
    /// Whether a remote offer's new media section may take this transceiver (RFC 9429,
    /// Section 5.10: only a transceiver "created by `addTrack`" is a candidate; one the
    /// application made with `addTransceiver` gets a media section of its own, in the next
    /// local offer). True by default, which is this crate's historical behaviour; a caller
    /// that tells the two kinds apart clears it with
    /// `RTCRtpTransceiver::set_associable_with_remote_offer`.
    associable_with_remote_offer: bool,
    /// The RTP header extensions (by URI) this transceiver's media section may carry
    /// (webrtc-extensions, `[[HeaderExtensionsToNegotiate]]` without the "stopped" ones).
    /// `None`, the default, is every extension the media engine negotiates; see
    /// `RTCRtpTransceiver::set_header_extensions_to_negotiate`.
    header_extensions_to_negotiate: Option<Vec<String>>,
    /// Reduced-size RTCP (RFC 5506) as the last answer negotiated it for this media section.
    rtcp_reduced_size: bool,
    /// The rids of the simulcast streams this transceiver's offers ask to receive
    /// (`RTCRtpTransceiver::set_receive_simulcast`, RFC 8853 section 5.3.1); empty for none.
    receive_simulcast: Vec<String>,
    /// The `b=` lines of this transceiver's section of the remote description.
    remote_bandwidth: RTCRemoteBandwidth,
    /// The `xr-format`s of the remote description's `a=rtcp-xr` for this section (RFC 3611
    /// section 5.1); `None` when it has no such attribute.
    remote_rtcp_xr: Option<Vec<String>>,
    /// The `a=ptime` / `a=maxptime` of this transceiver's section of the remote description.
    remote_packet_time: RTCPacketTime,
}

impl fmt::Debug for RTCRtpTransceiverInternal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RTCRtpTransceiver")
            .field("mid", &self.mid)
            .field("kind", &self.kind)
            //.field("sender", &self.sender)
            //.field("receiver", &self.receiver)
            .field("direction", &self.direction)
            .field("current_direction", &self.current_direction)
            .field("preferred_codecs", &self.preferred_codecs)
            .field("stopping", &self.stopping)
            .field("stopped", &self.stopped)
            .finish()
    }
}

impl RTCRtpTransceiverInternal {
    /// A transceiver with its sender and its receiver, which it has from the start and
    /// keeps (W3C webrtc 5.4 "create an RTCRtpTransceiver"): with `track`, a sender sending
    /// it; without, a sender whose track is null.
    pub(crate) fn new(
        kind: RtpCodecKind,
        track: Option<MediaStreamTrack>,
        init: RTCRtpTransceiverInit,
    ) -> Self {
        Self {
            mid: None,
            kind,
            sender: Some(match track {
                Some(track) => {
                    RTCRtpSenderInternal::new(kind, track, init.streams, init.send_encodings)
                }
                None => {
                    RTCRtpSenderInternal::without_track(kind, init.streams, init.send_encodings)
                }
            }),
            receiver: Some(RTCRtpReceiverInternal::new(kind, vec![])),
            direction: init.direction,
            current_direction: RTCRtpTransceiverDirection::Unspecified,
            preferred_codecs: vec![],
            stopping: false,
            stopped: false,
            receptive: false,
            fired_direction: None,
            used_to_send: false,
            created_by_remote_description: false,
            associable_with_remote_offer: true,
            header_extensions_to_negotiate: None,
            rtcp_reduced_size: false,
            receive_simulcast: vec![],
            remote_bandwidth: RTCRemoteBandwidth::default(),
            remote_rtcp_xr: None,
            remote_packet_time: RTCPacketTime::default(),
        }
    }

    /// Whether the sender is described in this transceiver's m= section (its `a=msid` and
    /// SSRC lines) and counts as sending there: it has a track, or the transceiver's direction
    /// sends (RFC 9429 section 5.2.1), and it has encodings to describe.
    pub(crate) fn describes_sender(&self) -> bool {
        self.sender.as_ref().is_some_and(|sender| {
            sender.has_send_encodings() && (sender.has_track() || self.direction.has_send())
        })
    }

    pub(crate) fn receptive(&self) -> bool {
        self.receptive
    }

    pub(crate) fn set_receptive(&mut self, receptive: bool) {
        self.receptive = receptive;
    }

    pub(crate) fn fired_direction(&self) -> Option<RTCRtpTransceiverDirection> {
        self.fired_direction
    }

    pub(crate) fn set_fired_direction(&mut self, direction: Option<RTCRtpTransceiverDirection>) {
        self.fired_direction = direction;
    }

    /// Whether the sender "has been used to send": `[[CurrentDirection]]` was once sendrecv
    /// or sendonly.
    pub(crate) fn used_to_send(&self) -> bool {
        self.used_to_send
    }

    pub(crate) fn associable_with_remote_offer(&self) -> bool {
        self.associable_with_remote_offer
    }

    pub(crate) fn set_associable_with_remote_offer(&mut self, associable: bool) {
        self.associable_with_remote_offer = associable;
    }

    pub(crate) fn header_extensions_to_negotiate(&self) -> Option<&[String]> {
        self.header_extensions_to_negotiate.as_deref()
    }

    pub(crate) fn set_header_extensions_to_negotiate(&mut self, uris: Option<Vec<String>>) {
        self.header_extensions_to_negotiate = uris;
    }

    /// Returns the media stream identification tag (mid) for this transceiver.
    ///
    /// The mid uniquely identifies the media description in the SDP. When not already set,
    /// this value will be assigned during `create_offer` or `create_answer`.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtptransceiver-mid).
    /// See [`Self::receive_simulcast`].
    pub(crate) fn set_receive_simulcast(&mut self, rids: Vec<String>) {
        self.receive_simulcast = rids;
    }

    /// The rids of the simulcast streams this transceiver's offers ask to receive.
    pub(crate) fn receive_simulcast(&self) -> &[String] {
        &self.receive_simulcast
    }

    pub(crate) fn mid(&self) -> &Option<String> {
        &self.mid
    }

    /// Returns the media kind (audio or video) of this transceiver.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.mid](https://www.w3.org/TR/webrtc/#dom-rtptransceiver-mid).
    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub(crate) fn sender(&self) -> &Option<RTCRtpSenderInternal> {
        &self.sender
    }
    /// sender returns the RTPTransceiver's RTPSender if it has one
    pub(crate) fn sender_mut(&mut self) -> &mut Option<RTCRtpSenderInternal> {
        &mut self.sender
    }

    /// receiver returns the RTPTransceiver's RTPReceiver if it has one
    pub(crate) fn receiver(&self) -> &Option<RTCRtpReceiverInternal> {
        &self.receiver
    }

    pub(crate) fn receiver_mut(&mut self) -> &mut Option<RTCRtpReceiverInternal> {
        &mut self.receiver
    }

    /// Returns the preferred direction of the transceiver.
    ///
    /// This indicates the direction that the application prefers for media flow.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub(crate) fn direction(&self) -> RTCRtpTransceiverDirection {
        self.direction
    }

    /// Sets the preferred direction of this transceiver.
    ///
    /// Changing the direction may trigger renegotiation to update the session description.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.direction](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction).
    pub(crate) fn set_direction(&mut self, direction: RTCRtpTransceiverDirection) {
        // The negotiation-needed flag is intentionally not updated here: this internal setter is
        // also invoked while applying a remote/local session description, where triggering
        // renegotiation would be incorrect. The public `RTCRtpTransceiver::set_direction` (which
        // maps to the spec's `direction` setter) performs that step.
        // See https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-direction
        self.direction = direction;
    }

    /// Returns the negotiated direction of the transceiver.
    ///
    /// This indicates the current direction as established by the most recent session description
    /// exchange. If this transceiver has never been negotiated or if it's stopped, this returns
    /// [`RTCRtpTransceiverDirection::Unspecified`].
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.currentDirection](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-currentdirection).
    pub(crate) fn current_direction(&self) -> RTCRtpTransceiverDirection {
        self.current_direction
    }

    /// W3C webrtc 5.4 "stop sending and receiving": the sender stops and says BYE for each
    /// stream it sent, the receiver stops and its track ends, `[[Direction]]` becomes
    /// inactive and `[[Stopping]]` true. What `RTCRtpTransceiver.stop()` does; the
    /// transceiver is stopped once a description rejects its m= section.
    ///
    /// # Returns
    ///
    /// Whether the receiver's track ended now (it was live), for the caller to announce.
    pub(crate) fn stop_sending_and_receiving(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<bool> {
        if self.stopping {
            return Ok(false);
        }
        self.stopping = true;

        if let Some(sender) = self.sender_mut() {
            sender.stop(media_engine, interceptor)?;
        }
        let mut ended = false;
        if let Some(receiver) = self.receiver_mut() {
            receiver.stop(media_engine, interceptor)?;
            ended = receiver.end_track();
        }

        self.direction = RTCRtpTransceiverDirection::Inactive;

        Ok(ended)
    }

    /// W3C webrtc 5.4 "stop the RTCRtpTransceiver": what a rejected m= section and a rollback
    /// do. Stops sending and receiving unless `stop()` already did, then `[[Stopped]]` is
    /// true, `[[Receptive]]` false and `[[CurrentDirection]]` null.
    ///
    /// # Returns
    ///
    /// Whether the receiver's track ended now, for the caller to announce.
    pub(crate) fn stop(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<bool> {
        let ended = self.stop_sending_and_receiving(media_engine, interceptor)?;
        self.stopped = true;
        self.receptive = false;
        self.current_direction = RTCRtpTransceiverDirection::Unspecified;
        Ok(ended)
    }

    /// Sets the preferred codec list for this transceiver.
    ///
    /// This overrides the default codec preferences from the media engine. If an empty list is
    /// provided, the transceiver resets to use the default codecs from the media engine.
    ///
    /// # Errors
    ///
    /// Returns an error if any codec in the list is not supported by the media engine.
    ///
    /// # Specification
    ///
    /// See [RTCRtpTransceiver.setCodecPreferences()](https://www.w3.org/TR/webrtc/#dom-rtcrtptransceiver-setcodecpreferences).
    pub(crate) fn set_codec_preferences(
        &mut self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        for codec in &codecs {
            let media_engine_codecs = media_engine.get_codecs_by_kind(self.kind());
            let (_, match_type) =
                codec_parameters_fuzzy_search(&codec.rtp_codec, &media_engine_codecs);
            if match_type == CodecMatch::None {
                return Err(Error::ErrRTPTransceiverCodecUnsupported);
            }
        }

        if let Some(sender) = self.sender_mut() {
            sender.set_codec_preferences(codecs.clone());
        }

        if let Some(receiver) = self.receiver_mut() {
            receiver.set_codec_preferences(codecs.clone());
        }

        self.preferred_codecs = codecs;

        Ok(())
    }

    /// W3C webrtc 5.4 `setCodecPreferences`, the steps before the codecs are stored:
    /// duplicates are removed, keeping the first; each codec has to match one the engine can
    /// send or receive for this kind (the codec dictionary match; the retransmission format
    /// matches by name, as `getCapabilities` lists it once, without an `apt`); and a list of
    /// nothing but RTX, RED, FEC and comfort noise formats is refused.
    pub(crate) fn validate_codec_preferences(
        &self,
        codecs: Vec<RTCRtpCodecParameters>,
        media_engine: &MediaEngine,
    ) -> Result<Vec<RTCRtpCodecParameters>> {
        if codecs.is_empty() {
            return Ok(codecs);
        }
        let mut unique: Vec<RTCRtpCodecParameters> = Vec::with_capacity(codecs.len());
        for codec in codecs {
            // The same codec twice: the same name, clock rate, channels and parameters.
            if !unique.iter().any(|kept| {
                let (kept, codec) = (&kept.rtp_codec, &codec.rtp_codec);
                kept.mime_type.eq_ignore_ascii_case(&codec.mime_type)
                    && kept.clock_rate == codec.clock_rate
                    && kept.channels == codec.channels
                    && kept.sdp_fmtp_line.trim() == codec.sdp_fmtp_line.trim()
            }) {
                unique.push(codec);
            }
        }
        let capabilities = media_engine.get_codecs_by_kind(self.kind());
        for codec in &unique {
            let is_rtx =
                is_repair_codec(&codec.rtp_codec) && repair_family(&codec.rtp_codec) == "rtx";
            let supported = capabilities.iter().any(|capability| {
                if is_rtx {
                    capability
                        .rtp_codec
                        .mime_type
                        .eq_ignore_ascii_case(&codec.rtp_codec.mime_type)
                        && capability.rtp_codec.clock_rate == codec.rtp_codec.clock_rate
                } else {
                    codec_dictionary_match(&codec.rtp_codec, &capability.rtp_codec)
                }
            });
            if !supported {
                return Err(Error::InvalidModificationError);
            }
        }
        let is_auxiliary = |codec: &RTCRtpCodecParameters| {
            is_repair_codec(&codec.rtp_codec)
                || codec
                    .rtp_codec
                    .mime_type
                    .rsplit('/')
                    .next()
                    .is_some_and(|subtype| subtype.eq_ignore_ascii_case("CN"))
        };
        if unique.iter().all(is_auxiliary) {
            return Err(Error::InvalidModificationError);
        }
        Ok(unique)
    }

    pub(crate) fn get_codec_preferences(&self) -> &[RTCRtpCodecParameters] {
        &self.preferred_codecs
    }

    /// Codecs returns list of supported codecs
    pub(crate) fn get_codecs(&self, media_engine: &MediaEngine) -> Vec<RTCRtpCodecParameters> {
        RTCRtpReceiverInternal::get_codecs(&self.preferred_codecs, self.kind(), media_engine)
    }

    /// set_mid sets the RTPTransceiver's mid. If it was already set, will return an error.
    pub(crate) fn set_mid(&mut self, mid: String) -> Result<()> {
        if self.mid.is_some() {
            return Err(Error::ErrRTPTransceiverCannotChangeMid);
        }

        self.mid = Some(mid);
        Ok(())
    }

    /// Whether the transceiver is stopping or stopped: an offer rejects its m= section, and
    /// it neither sends nor receives. What RFC 9429 calls a stopped RtpTransceiver. Stopping
    /// implies it (`stop()` sets both), so this reads `[[Stopping]]`, not `[[Stopped]]`.
    #[allow(clippy::misnamed_getters)]
    pub(crate) fn stopped(&self) -> bool {
        self.stopping || self.stopped
    }

    /// W3C `[[Stopped]]`.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped
    }

    /// Returns whether this transceiver was implicitly created while applying a remote offer.
    /// See [`RTCRtpTransceiverInternal::created_by_remote_description`].
    pub(crate) fn created_by_remote_description(&self) -> bool {
        self.created_by_remote_description
    }

    /// Marks this transceiver as having been implicitly created while applying a remote offer.
    pub(crate) fn set_created_by_remote_description(&mut self, created: bool) {
        self.created_by_remote_description = created;
    }

    /// Disassociates this transceiver from its "m=" section, as required by rollback
    /// (RFC 9429, Section 5.7). The mid is cleared and the negotiated (current) direction is
    /// reset so the transceiver can be re-associated by a subsequent offer/answer exchange.
    pub(crate) fn disassociate(&mut self) {
        self.mid = None;
        self.current_direction = RTCRtpTransceiverDirection::Unspecified;
    }

    /// Brings back what the last completed exchange negotiated for this transceiver, from the
    /// copy `saved` taken when the offer now rolled back was applied (W3C webrtc-pc "set a
    /// session description", rollback: `[[ReceiveCodecs]]` and the send encodings return to
    /// their last stable values): the codecs of the transceiver, its sender and its receiver,
    /// and the repair (RTX / FEC) flows the offer took from the sender's encodings. What the
    /// application did since (direction, track, stop, the mid, which the caller handles) stays.
    pub(crate) fn restore_negotiated_state(&mut self, saved: &RTCRtpTransceiverInternal) {
        self.preferred_codecs.clone_from(&saved.preferred_codecs);
        self.remote_bandwidth = saved.remote_bandwidth;
        self.remote_rtcp_xr.clone_from(&saved.remote_rtcp_xr);
        self.remote_packet_time = saved.remote_packet_time;
        if let (Some(sender), Some(saved)) = (self.sender.as_mut(), saved.sender.as_ref()) {
            sender.restore_negotiated_state(saved);
        }
        if let (Some(receiver), Some(saved)) = (self.receiver.as_mut(), saved.receiver.as_ref()) {
            receiver.restore_negotiated_state(saved);
        }
    }

    pub(crate) fn remote_rtcp_xr(&self) -> Option<&[String]> {
        self.remote_rtcp_xr.as_deref()
    }

    pub(crate) fn set_remote_rtcp_xr(&mut self, formats: Option<Vec<String>>) {
        self.remote_rtcp_xr = formats;
    }

    pub(crate) fn remote_packet_time(&self) -> RTCPacketTime {
        self.remote_packet_time
    }

    pub(crate) fn set_remote_packet_time(&mut self, packet_time: RTCPacketTime) {
        self.remote_packet_time = packet_time;
    }

    pub(crate) fn remote_bandwidth(&self) -> RTCRemoteBandwidth {
        self.remote_bandwidth
    }

    pub(crate) fn set_remote_bandwidth(&mut self, bandwidth: RTCRemoteBandwidth) {
        self.remote_bandwidth = bandwidth;
    }

    /// Whether the last answer negotiated reduced-size RTCP (RFC 5506) for this transceiver's
    /// media section.
    pub(crate) fn rtcp_reduced_size(&self) -> bool {
        self.rtcp_reduced_size
    }

    /// Records whether the last answer allows this transceiver's sender to mix one- and
    /// two-byte header extensions in a stream (RFC 8285 section 6).
    pub(crate) fn set_extmap_allow_mixed(&mut self, mixed: bool) {
        if let Some(sender) = self.sender.as_mut() {
            sender.set_extmap_allow_mixed(mixed);
        }
    }

    pub(crate) fn set_rtcp_reduced_size(&mut self, reduced_size: bool) {
        self.rtcp_reduced_size = reduced_size;
        if let Some(sender) = self.sender.as_mut() {
            sender.set_rtcp_reduced_size(reduced_size);
        }
        if let Some(receiver) = self.receiver.as_mut() {
            receiver.set_rtcp_reduced_size(reduced_size);
        }
    }

    pub(crate) fn set_current_direction(&mut self, d: RTCRtpTransceiverDirection) {
        let previous: RTCRtpTransceiverDirection = self.current_direction;
        self.current_direction = d;
        self.used_to_send |= d.has_send();

        if d != previous {
            trace!("Changing current direction of transceiver from {previous} to {d}",);
        }
    }

    // match codecs from remote description, used when remote is offerer and creating a transceiver
    // from remote description with the aim of keeping order of codecs in remote description.
    pub(crate) fn set_codec_preferences_from_remote_description(
        &mut self,
        media: &MediaDescription,
        media_engine: &MediaEngine,
    ) -> Result<()> {
        let remote_codecs = codecs_from_media_description(media)?;

        // Codec preferences the application set (W3C `setCodecPreferences`) constrain what is
        // negotiated (JSEP RFC 8829 §5.3.1), so they are matched first; the remote codecs then
        // replace them in the remote's order and with the engine's payload types. When nothing
        // the application preferred was offered, the whole engine is matched instead, as with no
        // preferences, rather than leaving the section with no codec at all.
        let mut filtered_codecs = if self.preferred_codecs.is_empty() {
            vec![]
        } else {
            Self::match_remote_codecs(remote_codecs.clone(), self.get_codecs(media_engine))
        };
        if filtered_codecs.is_empty() {
            filtered_codecs = Self::match_remote_codecs(
                remote_codecs,
                media_engine.get_codecs_by_kind(self.kind),
            );
        }

        self.set_codec_preferences(filtered_codecs, media_engine)
    }

    /// The remote codecs that match one of `left_codecs`, each with the matching local codec's
    /// payload type, exact matches first, and the RTX codecs that go with them.
    fn match_remote_codecs(
        mut remote_codecs: Vec<RTCRtpCodecParameters>,
        mut left_codecs: Vec<RTCRtpCodecParameters>,
    ) -> Vec<RTCRtpCodecParameters> {
        // find codec matches between what is in remote description and
        // the transceivers codecs and use payload type registered to
        // media engine.
        // For RTX re-mapping later. Ordered, not a map: the RTX pass below walks these in turn
        // and appends a codec per entry, so a `HashMap` would place the answer's rtx formats in
        // a different order on every run. Each pass fills its own list and hands it over, so the
        // whole stays in step with `filtered_codecs`: exact matches first, then partial, each in
        // the offer's order.
        let mut payload_mapping: Vec<(PayloadType, PayloadType)> = vec![];
        let mut filter_by_match = |match_filter: CodecMatch| -> Vec<RTCRtpCodecParameters> {
            let mut filtered_codecs = vec![];
            let mut pass_mapping = vec![];
            for remote_codec_idx in (0..remote_codecs.len()).rev() {
                let remote_codec = &mut remote_codecs[remote_codec_idx];
                if UniCase::new(remote_codec.rtp_codec.mime_type.as_str())
                    == UniCase::new(MIME_TYPE_RTX)
                {
                    continue;
                }

                let (match_codec, match_type) =
                    codec_parameters_fuzzy_search(&remote_codec.rtp_codec, &left_codecs);
                // A format whose parameters are its configuration (H.264, VP9, AV1) is not
                // matched by name alone: see `has_symmetric_configuration`.
                if match_type == CodecMatch::Partial
                    && has_symmetric_configuration(&remote_codec.rtp_codec)
                    && !match_codec.rtp_codec.sdp_fmtp_line.trim().is_empty()
                {
                    continue;
                }
                if match_type == match_filter {
                    pass_mapping.insert(0, (remote_codec.payload_type, match_codec.payload_type));

                    remote_codec.payload_type = match_codec.payload_type;
                    // Only the feedback both sides have is negotiated (RFC 4585 section 4.2):
                    // what a remote description lists beyond this endpoint's own, or an
                    // answer beyond the offer, is never enabled.
                    remote_codec.rtp_codec.rtcp_feedback = rtcp_feedback_intersection(
                        &match_codec.rtp_codec.rtcp_feedback,
                        &remote_codec.rtp_codec.rtcp_feedback,
                    );
                    // The scan runs backwards so that matched entries can be removed by index,
                    // so prepend to undo it: an answer must keep the offer's codec order (the
                    // offerer reads it back as our preference). Appending here would make the
                    // answer lead with the offer's *last* codec.
                    filtered_codecs.insert(0, remote_codec.clone());

                    // removed matched codec for next round
                    remote_codecs.remove(remote_codec_idx);

                    let needle_fmtp = fmtp::parse(
                        match_codec.rtp_codec.mime_type.as_str(),
                        //match_codec.RTPCodecCapability.ClockRate,
                        //match_codec.RTPCodecCapability.Channels,
                        match_codec.rtp_codec.sdp_fmtp_line.as_str(),
                    );

                    for left_codec_idx in (0..left_codecs.len()).rev() {
                        let left_codec = &left_codecs[left_codec_idx];
                        let left_codec_fmtp = fmtp::parse(
                            left_codec.rtp_codec.mime_type.as_str(),
                            //left_codec.RTPCodecCapability.ClockRate,
                            //left_codec.RTPCodecCapability.Channels,
                            left_codec.rtp_codec.sdp_fmtp_line.as_str(),
                        );

                        if needle_fmtp.match_fmtp(&*left_codec_fmtp) {
                            left_codecs.remove(left_codec_idx);
                            break;
                        }
                    }
                }
            }

            payload_mapping.extend(pass_mapping);
            filtered_codecs
        };

        let mut filtered_codecs = filter_by_match(CodecMatch::Exact);
        filtered_codecs.append(&mut filter_by_match(CodecMatch::Partial));

        // find RTX associations and add those
        for (remote_payload_type, media_engine_payload_type) in payload_mapping {
            let remote_rtx = find_rtx_payload_type(remote_payload_type, &remote_codecs);
            if remote_rtx.is_none() {
                continue;
            }

            if let Some(media_engine_rtx) =
                find_rtx_payload_type(media_engine_payload_type, &left_codecs)
            {
                for rtx_codec in &left_codecs {
                    if rtx_codec.payload_type == media_engine_rtx {
                        filtered_codecs.push(rtx_codec.clone());
                        break;
                    }
                }
            }
        }

        filtered_codecs
    }
}

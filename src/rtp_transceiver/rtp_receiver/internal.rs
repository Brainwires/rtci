use crate::media_stream::MediaStreamId;
use crate::media_stream::track::MediaStreamTrack;
use crate::peer_connection::configuration::interceptor_registry::create_stream_info;
use crate::peer_connection::configuration::media_engine::MediaEngine;
use crate::peer_connection::handler::endpoint::repair_flow_codec;
use crate::rtp_transceiver::direction::RTCRtpTransceiverDirection;
use crate::rtp_transceiver::rtp_receiver::rtp_contributing_source::{
    RTCRtpContributingSource, RTCRtpSynchronizationSource,
};
use crate::rtp_transceiver::rtp_sender::RTCRtpHeaderExtensionToNegotiate;
use crate::rtp_transceiver::rtp_sender::internal::rtp_capabilities;
use crate::rtp_transceiver::rtp_sender::rtp_capabilities::RTCRtpCapabilities;
use crate::rtp_transceiver::rtp_sender::rtp_codec::{
    CodecMatch, FecFormat, RtpCodecKind, codec_parameters_fuzzy_search, find_receive_fec_format,
    find_rtx_payload_type, is_repair_codec, parse_rtx_apt, repair_family,
};
use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
use crate::rtp_transceiver::rtp_sender::rtp_receiver_parameters::RTCRtpReceiveParameters;
use crate::rtp_transceiver::rtp_sender::{
    RTCRtpCodec, RTCRtpEncodingParameters, RTCRtpHeaderExtensionParameters,
};
use crate::rtp_transceiver::{PayloadType, SSRC};
use interceptor::{Interceptor, StreamInfo};
use shared::error::Result;
use shared::time::SystemInstant;
use std::time::{Duration, Instant};

/// How long a source stays in `get_contributing_sources` / `get_synchronization_sources`
/// after its last packet (W3C webrtc 5.3: sources of "the last 10 seconds").
pub(crate) const SOURCE_LIFETIME: Duration = Duration::from_secs(10);

/// The greatest `jitterBufferTarget` (W3C webrtc 5.3: a target above 4000 milliseconds is a
/// `RangeError`).
pub(crate) const MAX_JITTER_BUFFER_TARGET: Duration = Duration::from_millis(4000);

/// The most contributing sources a receiver lists; a packet carries at most 15 and a mixer
/// rotates through its participants, so the least recent make room past this.
pub(crate) const MAX_CONTRIBUTING_SOURCES: usize = 64;

/// The mixer-to-client audio level extension (RFC 6465 section 6): the level of each
/// contributing source of a mixed packet.
pub(crate) const CSRC_AUDIO_LEVEL_URI: &str = "urn:ietf:params:rtp-hdrext:csrc-audio-level";

/// The linear audio level (0 to 1) of an RFC 6464 / RFC 6465 level in -dBov, as W3C webrtc
/// 5.3 defines the conversion: 127 is silence, otherwise `10^(-level / 20)`.
pub(crate) fn linear_audio_level(level: u8) -> f64 {
    match level & 0x7F {
        127 => 0.0,
        level => 10f64.powf(-f64::from(level) / 20.0),
    }
}

/// The receive state a pending local offer adds to a receiver (RFC 3264 section 5.1: "Once
/// the offerer has sent the offer, it MUST be prepared to receive media for any recvonly
/// streams described by that offer", and for sendrecv ones; RFC 9429 section 4.1.11: "the
/// PeerConnection MUST be able to simultaneously support use of both the current and pending
/// local descriptions"). It is provisional: the final answer settles it
/// ([`RTCRtpReceiverInternal::settle_offered`]) and a rollback takes it back
/// ([`RTCRtpReceiverInternal::roll_back_offered`]).
#[derive(Default, Debug, Clone)]
pub(crate) struct OfferedReceive {
    /// The formats of the offer's m= section, as the offer states them, without RTCP
    /// feedback: a feedback mechanism is used once the answer has it (RFC 4585 section 4.2:
    /// "The offerer and answerer MUST only use feedback mechanisms negotiated in this way";
    /// RFC 9429 section 5.11 enables them when an answer is applied).
    codecs: Vec<RTCRtpCodecParameters>,
    /// Whether the receiver's receive codecs are a negotiated list (the section was
    /// answered before, or a provisional answer has been applied since the offer): they are
    /// then received as well, with what was negotiated for them, and come first.
    negotiated: bool,
    /// The receive codings and the track's codings as the offer found them: what a rollback
    /// returns to.
    prior_codings: Vec<RTCRtpCodingParameters>,
    prior_track_codings: Vec<crate::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters>,
    /// Whether the track was muted when the offer was applied.
    prior_muted: bool,
    /// The streams bound to the interceptors while the offer was pending, with what they were
    /// bound with; `None` when no stream arrived early.
    early_streams: Option<Vec<StreamInfo>>,
}

/// RTPReceiver allows an application to inspect the receipt of a TrackRemote
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCRtpReceiver
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcrtpreceiver-interface
#[derive(Default, Debug, Clone)]
pub(crate) struct RTCRtpReceiverInternal {
    kind: RtpCodecKind,
    track: MediaStreamTrack,
    contributing_sources: Vec<RTCRtpContributingSource>,
    synchronization_sources: Vec<RTCRtpSynchronizationSource>,
    jitter_buffer_target: Option<Duration>,

    receive_codings: Vec<RTCRtpCodingParameters>,
    /// The streams a remote description with `a=rid` declares by SSRC for the section (RFC
    /// 9143 section 9.2), without a rid. They are not codings until a packet of theirs that
    /// carries no RID arrives (`InterceptorHandler::bind_declared_in_rid_section`); a packet
    /// that carries a RID is bound by its rid, as without them.
    declared_codings: Vec<RTCRtpCodingParameters>,
    receive_codecs: Vec<RTCRtpCodecParameters>,
    /// What this endpoint's pending offer prepared the receiver for, which it must be ready
    /// to receive before the answer arrives (RFC 3264 section 5.1, RFC 9429 sections 4.1.11
    /// and 5.9); `None` outside `have-local-offer` and `have-remote-pranswer`.
    offered: Option<OfferedReceive>,
    /// The ids of the remote MediaStreams the track is in, as the remote description's
    /// `a=msid` lines name them (W3C `[[AssociatedRemoteMediaStreams]]`).
    associated_media_stream_ids: Vec<MediaStreamId>,
    /// Reduced-size RTCP as negotiated for the media section (`RTCRtcpParameters::reduced_size`).
    rtcp_reduced_size: bool,

    last_returned_parameters: Option<RTCRtpReceiveParameters>,
    /// What the public `getParameters` returns while the negotiated direction does not
    /// receive: the parameters without codecs (W3C [[ReceiveCodecs]] is empty then).
    not_receiving_parameters: Option<RTCRtpReceiveParameters>,
    /// The `a=fmtp` parameters of each format of the local description's section (W3C
    /// webrtc-pc 5.2.9: a receiver's codecs take their `sdpFmtpLine` from it).
    local_fmtp: Vec<(PayloadType, String)>,
    /// The last absolute capture time each synchronization source sent (webrtc-extensions
    /// 8), what packets without one are interpolated from.
    capture_references: Vec<CaptureReference>,

    /// The track id the remote description's `a=msid` gives the track (its appdata), which
    /// identifies the remote sender's track across descriptions. Not the id of this
    /// receiver's track: that one is the engine's own (W3C webrtc 5.3).
    remote_track_id: String,
    /// W3C `[[AssociatedRemoteMediaStreams]]`, as "process remote tracks" sets it.
    remote_streams: Vec<MediaStreamId>,
    /// W3C `[[LastStableStateAssociatedRemoteMediaStreams]]`.
    last_stable_remote_streams: Vec<MediaStreamId>,
    /// The track ended and the application has not been told yet
    /// ([`take_unannounced_end`](Self::take_unannounced_end)).
    end_unannounced: bool,
    /// When each video frame reported in the last second was received
    /// ([`report_received_frame`](Self::report_received_frame)), oldest first.
    received_frames: std::collections::VecDeque<Instant>,
    /// The SSRC and the CSRCs of the last packet received (webrtc-extensions 11).
    last_frame_sources: Option<(SSRC, Vec<SSRC>)>,
    /// The arrival, capture time and Dependency Descriptor of the frames delivered lately
    /// (webrtc-encoded-transform 4, `encoded_frame_metadata`).
    frames: super::frame_metadata::FrameRecords,
    /// The sequence number of the next Full Intra Request (RFC 5104 4.3.1.2).
    fir_sequence_number: u8,
}

impl RTCRtpReceiverInternal {
    pub(crate) fn new(kind: RtpCodecKind, receive_codings: Vec<RTCRtpCodingParameters>) -> Self {
        Self {
            kind,
            track: Default::default(),
            contributing_sources: vec![],
            synchronization_sources: vec![],
            jitter_buffer_target: None,
            receive_codings,
            declared_codings: vec![],

            receive_codecs: vec![],
            offered: None,
            associated_media_stream_ids: vec![],
            rtcp_reduced_size: false,
            last_returned_parameters: None,
            not_receiving_parameters: None,
            local_fmtp: Vec::new(),
            capture_references: vec![],
            remote_track_id: String::new(),
            remote_streams: vec![],
            last_stable_remote_streams: vec![],
            end_unannounced: false,
            received_frames: Default::default(),
            last_frame_sources: None,
            frames: Default::default(),
            fir_sequence_number: 0,
        }
        .with_own_track()
    }

    /// W3C webrtc 5.3 "create an RTCRtpReceiver": the receiver's track has an id the engine
    /// generates (not one a remote description names), is labelled "remote " + kind, and
    /// starts muted, live.
    fn with_own_track(mut self) -> Self {
        let mut track = MediaStreamTrack::new(
            String::new(),
            shared::util::math_rand_alpha(16),
            format!("remote {}", self.kind),
            self.kind,
            vec![],
        );
        track.set_muted(true);
        track.set_remote();
        self.track = track;
        self
    }

    /// Takes the track a remote description describes (its stream, codings and the msid
    /// track id) while keeping what makes it this receiver's track: its id, label, muted
    /// state and ready state (W3C webrtc 5.3: the track is created with the receiver and
    /// keeps its identity).
    pub(crate) fn set_remote_track(&mut self, mut track: MediaStreamTrack) {
        self.remote_track_id = std::mem::take(&mut track.track_id);
        track.track_id = self.track.track_id.clone();
        track.label = self.track.label.clone();
        track.set_muted(self.track.muted());
        track.set_remote();
        track.take_settings_from(&self.track);
        if self.track.ready_state()
            == crate::media_stream::track_state::MediaStreamTrackState::Ended
        {
            track.stop();
        }
        self.track = track;
    }

    /// The msid track id of the remote sender's track, as the last remote description named
    /// it; empty when none did.
    pub(crate) fn remote_track_id(&self) -> &str {
        &self.remote_track_id
    }

    /// W3C `[[AssociatedRemoteMediaStreams]]`.
    pub(crate) fn remote_streams(&self) -> &[MediaStreamId] {
        &self.remote_streams
    }

    /// W3C "set the associated remote streams": the streams become `msids` (deduplicated);
    /// returns the stream ids removed from and added to the track's streams.
    pub(crate) fn set_remote_streams(
        &mut self,
        msids: Vec<MediaStreamId>,
    ) -> (Vec<MediaStreamId>, Vec<MediaStreamId>) {
        let mut streams: Vec<MediaStreamId> = Vec::with_capacity(msids.len());
        for msid in msids {
            if !streams.contains(&msid) {
                streams.push(msid);
            }
        }
        let removed = self
            .remote_streams
            .iter()
            .filter(|stream| !streams.contains(stream))
            .cloned()
            .collect();
        let added = streams
            .iter()
            .filter(|stream| !self.remote_streams.contains(stream))
            .cloned()
            .collect();
        self.remote_streams = streams;
        (removed, added)
    }

    pub(crate) fn last_stable_remote_streams(&self) -> &[MediaStreamId] {
        &self.last_stable_remote_streams
    }

    /// Signaling is stable: the associated remote streams are what a rollback returns to.
    pub(crate) fn save_stable_remote_streams(&mut self) {
        self.last_stable_remote_streams = self.remote_streams.clone();
    }

    /// W3C "stop the RTCRtpTransceiver": no associated remote streams, now or after a
    /// rollback.
    pub(crate) fn clear_remote_streams(&mut self) {
        self.remote_streams.clear();
        self.last_stable_remote_streams.clear();
    }

    pub(crate) fn kind(&self) -> RtpCodecKind {
        self.kind
    }

    pub(crate) fn track(&self) -> &MediaStreamTrack {
        &self.track
    }

    /// The local description's formats of this receiver's section, with their parameters.
    pub(crate) fn set_local_fmtp(&mut self, local: Vec<(PayloadType, String)>) {
        self.local_fmtp = local;
    }

    /// Drops what [`Self::get_parameters`] returned last, so that the next call reads the
    /// negotiated state again.
    pub(crate) fn invalidate_parameters(&mut self) {
        self.last_returned_parameters = None;
        self.not_receiving_parameters = None;
    }

    pub(crate) fn set_rtcp_reduced_size(&mut self, reduced_size: bool) {
        if self.rtcp_reduced_size != reduced_size {
            self.rtcp_reduced_size = reduced_size;
            self.last_returned_parameters = None;
        }
    }

    pub(crate) fn streams(&self) -> &[MediaStreamId] {
        &self.associated_media_stream_ids
    }

    pub(crate) fn set_streams(&mut self, streams: Vec<MediaStreamId>) {
        self.associated_media_stream_ids = streams;
    }

    pub(crate) fn track_mut(&mut self) -> &mut MediaStreamTrack {
        &mut self.track
    }

    /// The RTP capabilities of the engine for receiving `kind` (W3C webrtc 5.3
    /// `RTCRtpReceiver.getCapabilities`, a static method); `None` for a kind that is neither
    /// audio nor video.
    pub(crate) fn get_capabilities(
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
    ) -> Option<RTCRtpCapabilities> {
        rtp_capabilities(kind, RTCRtpTransceiverDirection::Recvonly, media_engine)
    }

    /// W3C `[[JitterBufferTarget]]`: `None` is null, the engine's own choice.
    pub(crate) fn jitter_buffer_target(&self) -> Option<Duration> {
        self.jitter_buffer_target
    }

    pub(crate) fn set_jitter_buffer_target(&mut self, target: Option<Duration>) -> Result<()> {
        if target.is_some_and(|target| target > MAX_JITTER_BUFFER_TARGET) {
            return Err(shared::error::Error::RangeError(
                "jitterBufferTarget must be at most 4000 ms".to_string(),
            ));
        }
        self.jitter_buffer_target = target;
        Ok(())
    }

    pub(crate) fn get_parameters(
        &mut self,
        media_engine: &MediaEngine,
    ) -> &RTCRtpReceiveParameters {
        if self.last_returned_parameters.is_none() {
            let mut rtp_parameters = media_engine
                .get_rtp_parameters_by_kind(self.kind(), RTCRtpTransceiverDirection::Recvonly);

            rtp_parameters.codecs = RTCRtpReceiverInternal::get_codecs(
                &self.receive_codecs,
                self.kind(),
                media_engine,
                false,
            );
            rtp_parameters.rtcp.reduced_size = self.rtcp_reduced_size;

            self.last_returned_parameters = Some(RTCRtpReceiveParameters { rtp_parameters });
        }

        self.last_returned_parameters.as_ref().unwrap()
    }

    /// W3C `getParameters`: [`Self::get_parameters`], without codecs when the negotiated
    /// direction does not receive (`receiving` false), and with only the header extensions
    /// this transceiver's m= section negotiated for receiving (`negotiated_header_extensions`
    /// is its `[[NegotiatedHeaderExtensions]]`; none before an answer was applied).
    pub(crate) fn get_public_parameters(
        &mut self,
        media_engine: &MediaEngine,
        negotiated_header_extensions: &[RTCRtpHeaderExtensionToNegotiate],
        receiving: bool,
    ) -> &RTCRtpReceiveParameters {
        let mut parameters = self.get_parameters(media_engine).clone();
        if !receiving {
            parameters.rtp_parameters.codecs.clear();
        }
        crate::rtp_transceiver::header_extension_control::retain_negotiated(
            &mut parameters.rtp_parameters.header_extensions,
            negotiated_header_extensions,
            false,
        );
        for codec in &mut parameters.rtp_parameters.codecs {
            if let Some((_, fmtp)) = self
                .local_fmtp
                .iter()
                .find(|(payload_type, _)| *payload_type == codec.payload_type)
            {
                codec.rtp_codec.sdp_fmtp_line = fmtp.clone();
            }
        }
        self.not_receiving_parameters.insert(parameters)
    }

    /// Records the sources of an RTP packet delivered to this receiver's track: its SSRC as a
    /// synchronization source and each CSRC as a contributing source (RFC 3550 5.1; W3C
    /// webrtc 5.3 `getSynchronizationSources`, `getContributingSources`). One entry per
    /// source, the most recent packet's; entries older than [`SOURCE_LIFETIME`] are dropped.
    ///
    /// `audio_level` is the packet's RFC 6464 level (-dBov) when its header carries one, and
    /// `csrc_levels` its RFC 6465 levels, one per CSRC in the order of the CSRC list (a list
    /// of another length is not attributed); a source without a level reports none.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_sources(
        &mut self,
        now: Instant,
        wall_clock: SystemInstant,
        header: &rtp::Header,
        audio_level: Option<u8>,
        csrc_levels: Option<&[u8]>,
        vad: bool,
        capture: Option<rtp::extension::abs_capture_time_extension::AbsCaptureTimeExtension>,
        clock_rate: Option<u32>,
        dependency_descriptor: Option<&[u8]>,
    ) -> (bool, bool) {
        // webrtc-extensions 11: whether the SSRC, and the CSRCs, of the last frame changed.
        let changes = match &self.last_frame_sources {
            None => (true, !header.csrc.is_empty()),
            Some((ssrc, csrcs)) => (*ssrc != header.ssrc, *csrcs != header.csrc),
        };
        self.last_frame_sources = Some((header.ssrc, header.csrc.clone()));
        let timestamp = wall_clock.unix(now);
        let live = |source: &RTCRtpContributingSource| {
            timestamp.saturating_sub(source.timestamp) < SOURCE_LIFETIME
        };
        let entry = |source: u32, audio_level: Option<f64>| RTCRtpContributingSource {
            timestamp,
            source,
            audio_level,
            rtp_timestamp: header.timestamp,
            capture_timestamp: None,
            sender_capture_time_offset: None,
            voice_activity_flag: None,
        };
        let (capture_timestamp, sender_capture_time_offset) =
            self.capture_time_of(header, capture, clock_rate);

        self.synchronization_sources
            .retain(|source| source.source != header.ssrc && live(source));
        let mut synchronization = RTCRtpContributingSource {
            // RFC 6464 section 3: the V bit is the level octet's high bit.
            voice_activity_flag: audio_level.filter(|_| vad).map(|level| level & 0x80 != 0),
            ..entry(header.ssrc, audio_level.map(linear_audio_level))
        };
        synchronization.capture_timestamp = capture_timestamp;
        synchronization.sender_capture_time_offset = sender_capture_time_offset;
        self.frames.record(
            now,
            header,
            (capture_timestamp, sender_capture_time_offset),
            dependency_descriptor,
        );
        self.synchronization_sources.push(synchronization);
        let csrc_levels = csrc_levels.filter(|levels| levels.len() == header.csrc.len());

        self.contributing_sources
            .retain(|source| !header.csrc.contains(&source.source) && live(source));
        for (n, &csrc) in header.csrc.iter().enumerate() {
            if !self
                .contributing_sources
                .iter()
                .any(|source| source.source == csrc)
            {
                let level = csrc_levels.map(|levels| linear_audio_level(levels[n]));
                self.contributing_sources.push(entry(csrc, level));
            }
        }
        if self.contributing_sources.len() > MAX_CONTRIBUTING_SOURCES {
            let excess = self.contributing_sources.len() - MAX_CONTRIBUTING_SOURCES;
            self.contributing_sources.drain(..excess);
        }
        changes
    }

    /// webrtc-extensions 8: the capture time and the sender's clock offset of a packet of
    /// `header.ssrc`, in milliseconds. From the packet's `abs-capture-time` when it has one
    /// (remembered with its RTP timestamp); otherwise interpolated from the last one the
    /// source sent, by the RTP timestamp difference at `clock_rate`, and the last offset.
    fn capture_time_of(
        &mut self,
        header: &rtp::Header,
        capture: Option<rtp::extension::abs_capture_time_extension::AbsCaptureTimeExtension>,
        clock_rate: Option<u32>,
    ) -> (Option<f64>, Option<f64>) {
        // 32.32 fixed point seconds to milliseconds.
        let ms_of = |fixed: f64| fixed / 4_294_967_296.0 * 1000.0;
        let known = self
            .capture_references
            .iter()
            .position(|r| r.ssrc == header.ssrc);
        if let Some(capture) = capture {
            let offset = capture
                .estimated_capture_clock_offset
                .map(|o| ms_of(o as f64))
                .or_else(|| known.and_then(|i| self.capture_references[i].offset_ms));
            let reference = CaptureReference {
                ssrc: header.ssrc,
                capture_ms: ms_of(capture.timestamp as f64),
                rtp_timestamp: header.timestamp,
                offset_ms: offset,
            };
            let capture_ms = reference.capture_ms;
            match known {
                Some(i) => self.capture_references[i] = reference,
                None => {
                    if self.capture_references.len() >= MAX_CONTRIBUTING_SOURCES {
                        self.capture_references.remove(0);
                    }
                    self.capture_references.push(reference);
                }
            }
            return (Some(capture_ms), offset);
        }
        let Some(reference) = known.map(|i| &self.capture_references[i]) else {
            return (None, None);
        };
        let interpolated = clock_rate.filter(|rate| *rate > 0).map(|rate| {
            let elapsed = header.timestamp.wrapping_sub(reference.rtp_timestamp) as i32;
            reference.capture_ms + f64::from(elapsed) * 1000.0 / f64::from(rate)
        });
        (interpolated, reference.offset_ms)
    }

    /// The sequence number for a new Full Intra Request, one more than the last (RFC 5104
    /// 4.3.1.2: "incremented by 1 modulo 256" for each new request).
    pub(crate) fn next_fir_sequence_number(&mut self) -> u8 {
        let number = self.fir_sequence_number;
        self.fir_sequence_number = number.wrapping_add(1);
        number
    }

    /// What the receiver recorded of the frames it delivered.
    pub(crate) fn frame_records(&self) -> &super::frame_metadata::FrameRecords {
        &self.frames
    }

    pub(crate) fn frame_records_mut(&mut self) -> &mut super::frame_metadata::FrameRecords {
        &mut self.frames
    }

    /// A source said BYE (RFC 3550 6.6): it is no longer a source of this receiver.
    pub(crate) fn forget_source(&mut self, source: u32) {
        self.contributing_sources
            .retain(|entry| entry.source != source);
        self.synchronization_sources
            .retain(|entry| entry.source != source);
    }

    pub(crate) fn get_contributing_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpContributingSource> {
        // Kept oldest first (a source heard again moves to the end): W3C webrtc 5.3 lists
        // them in descending timestamp order.
        self.contributing_sources.iter().rev()
    }

    pub(crate) fn get_synchronization_sources(
        &self,
    ) -> impl Iterator<Item = &RTCRtpSynchronizationSource> {
        self.synchronization_sources.iter().rev()
    }

    /// The contributing sources heard in the [`SOURCE_LIFETIME`] before `now` (the wall-clock
    /// time since the Unix epoch, as the entries' timestamps are), most recent first. Entries
    /// are otherwise dropped only when a packet arrives, so a receiver that hears nothing
    /// more would keep listing its last sources.
    pub(crate) fn live_contributing_sources(
        &self,
        now: Duration,
    ) -> impl Iterator<Item = &RTCRtpContributingSource> {
        self.get_contributing_sources()
            .filter(move |source| now.saturating_sub(source.timestamp) < SOURCE_LIFETIME)
    }

    /// [`live_contributing_sources`](Self::live_contributing_sources) for the synchronization
    /// sources.
    pub(crate) fn live_synchronization_sources(
        &self,
        now: Duration,
    ) -> impl Iterator<Item = &RTCRtpSynchronizationSource> {
        self.get_synchronization_sources()
            .filter(move |source| now.saturating_sub(source.timestamp) < SOURCE_LIFETIME)
    }

    pub(crate) fn get_codecs(
        codecs: &[RTCRtpCodecParameters],
        kind: RtpCodecKind,
        media_engine: &MediaEngine,
        sframe: bool,
    ) -> Vec<RTCRtpCodecParameters> {
        // The section's numbering, SFrame or plain (draft-ietf-avtcore-rtp-sframe-03 section
        // 6): preferences that name an SFrame section's payload types are in its numbering.
        let sframe = sframe
            || codecs.iter().any(|codec| {
                media_engine
                    .sframe_payload_types
                    .contains(&codec.payload_type)
            });
        Self::preferred_among(codecs, media_engine.codecs_for_section(kind, sframe))
    }

    /// The formats of `media_engine_codecs` that the codec preferences `codecs` keep, in the
    /// preferences' order (all of them without preferences).
    pub(crate) fn preferred_among(
        codecs: &[RTCRtpCodecParameters],
        media_engine_codecs: Vec<RTCRtpCodecParameters>,
    ) -> Vec<RTCRtpCodecParameters> {
        if codecs.is_empty() {
            return media_engine_codecs;
        }
        let mut filtered_codecs = vec![];
        for codec in codecs {
            // A retransmission format without an `apt` (as getCapabilities() lists RTX) names
            // RTX for every primary; the loop below adds one per surviving primary.
            if is_repair_codec(&codec.rtp_codec)
                && repair_family(&codec.rtp_codec) == "rtx"
                && parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line).is_none()
            {
                continue;
            }
            let (c, match_type) =
                codec_parameters_fuzzy_search(&codec.rtp_codec, &media_engine_codecs);
            if match_type != CodecMatch::None
                && !filtered_codecs
                    .iter()
                    .any(|f: &RTCRtpCodecParameters| f.payload_type == c.payload_type)
            {
                filtered_codecs.push(c);
            }
        }

        // A repair format (RTX, RED, FEC) is kept when the preferences list its kind: W3C
        // setCodecPreferences() lets an application remove RTX or FEC by leaving them out
        // (webrtc-pc 5.4 "setCodecPreferences", and the RTX entry, which has no `apt`, stands
        // for all primaries). A sender's `a=ssrc-group` lines for a repair kind left out are
        // not written either (add_sender_sdp).
        let listed: Vec<&'static str> = codecs
            .iter()
            .filter(|c| is_repair_codec(&c.rtp_codec))
            .map(|c| repair_family(&c.rtp_codec))
            .collect();
        for codec in &media_engine_codecs {
            if !is_repair_codec(&codec.rtp_codec)
                || !listed.contains(&repair_family(&codec.rtp_codec))
                || filtered_codecs
                    .iter()
                    .any(|filtered| filtered.payload_type == codec.payload_type)
            {
                continue;
            }

            // An RTX codec repairs one specific primary (RFC 4588 `apt`), so it belongs here only
            // when that primary survived. FEC and RED are not bound to a payload type and always do.
            if let Some(apt) = parse_rtx_apt(&codec.rtp_codec.sdp_fmtp_line)
                && !filtered_codecs
                    .iter()
                    .any(|filtered| filtered.payload_type == apt)
            {
                continue;
            }

            filtered_codecs.push(codec.clone());
        }

        filtered_codecs
    }

    pub(crate) fn get_coding_parameters(&self) -> &[RTCRtpCodingParameters] {
        &self.receive_codings
    }

    pub(crate) fn get_coding_parameter_mut_by_rid(
        &mut self,
        rid: &str,
    ) -> Option<&mut RTCRtpCodingParameters> {
        self.receive_codings
            .iter_mut()
            .find(|coding| coding.rid.as_str() == rid)
    }

    pub(crate) fn set_coding_parameters(&mut self, receive_codings: Vec<RTCRtpCodingParameters>) {
        self.receive_codings = receive_codings;
        //TODO: if get_parameters is changed to use receive_codings to return it in RTCRtpReceiveParameters
        // self.last_returned_parameters = None;
    }

    /// The streams the remote description declares by SSRC beside its rids
    /// ([`Self::set_declared_codings`]).
    pub(crate) fn declared_codings(&self) -> &[RTCRtpCodingParameters] {
        &self.declared_codings
    }

    /// Sets the streams a remote description with `a=rid` declares by SSRC for the section:
    /// each a coding without a rid, with its declared repair flows.
    pub(crate) fn set_declared_codings(&mut self, declared: Vec<RTCRtpCodingParameters>) {
        self.declared_codings = declared;
    }

    /// A declared stream ([`Self::declared_codings`]) becomes a coding of this receiver and of
    /// its track, without a rid and with its codec still to be resolved. `false` when `ssrc`
    /// is not a declared primary or is a coding already.
    pub(crate) fn add_declared_coding(&mut self, ssrc: SSRC) -> bool {
        if self.receive_codings.iter().any(|c| c.ssrc == Some(ssrc)) {
            return false;
        }
        let Some(coding) = self
            .declared_codings
            .iter()
            .find(|c| c.ssrc == Some(ssrc))
            .cloned()
        else {
            return false;
        };
        self.receive_codings.push(coding.clone());
        self.track.add_coding(RTCRtpEncodingParameters {
            rtp_coding_parameters: coding,
            ..Default::default()
        });
        true
    }

    pub(crate) fn get_codec_preferences(&self) -> &[RTCRtpCodecParameters] {
        &self.receive_codecs
    }

    /// Prepares the receiver for the section a local offer lists it in with a receiving
    /// direction: `codecs` are the section's formats as the offer states them, `negotiated`
    /// whether the section was answered before (its receive codecs are then a negotiated list
    /// and stay receivable beside the offered formats, RFC 9429 section 4.1.11). An offer
    /// applied over a pending one replaces the formats and keeps what a rollback returns to.
    pub(crate) fn set_offered(&mut self, mut codecs: Vec<RTCRtpCodecParameters>, negotiated: bool) {
        for codec in &mut codecs {
            codec.rtp_codec.rtcp_feedback.clear();
        }
        match self.offered.as_mut() {
            Some(offered) => {
                offered.codecs = codecs;
                offered.negotiated = negotiated;
            }
            None => {
                self.offered = Some(OfferedReceive {
                    codecs,
                    negotiated,
                    prior_codings: self.receive_codings.clone(),
                    prior_track_codings: self.track.codings().to_vec(),
                    prior_muted: self.track.muted(),
                    early_streams: None,
                });
            }
        }
    }

    /// The payload types of the pending local offer's section.
    #[cfg(test)]
    pub(crate) fn offered_payload_types(&self) -> Vec<PayloadType> {
        self.offered
            .iter()
            .flat_map(|offered| offered.codecs.iter().map(|codec| codec.payload_type))
            .collect()
    }

    /// Forgets the pending offer, as the answer's settling does, for a test without one.
    #[cfg(test)]
    pub(crate) fn drop_offered(&mut self) {
        self.offered = None;
    }

    /// Whether a local offer is pending for this receiver ([`Self::set_offered`]).
    pub(crate) fn has_offered(&self) -> bool {
        self.offered.is_some()
    }

    /// A provisional answer was applied: the receive codecs are what it answered, received
    /// with what it negotiated for them; the other offered formats stay receivable until the
    /// final answer (RFC 9429 section 4.1.11: the dual processing "continues until
    /// setRemoteDescription is called with either (1) a final answer ... or (2) a rollback").
    pub(crate) fn mark_offered_answered(&mut self) {
        if let Some(offered) = self.offered.as_mut() {
            offered.negotiated = true;
        }
    }

    /// The simulcast streams a pending offer asks to receive (`a=rid:<id> recv`, RFC 8853
    /// section 5.3.1) on a receiver that has no stream yet: a coding per rid without an SSRC,
    /// which the first packet carrying the rid binds, as for the layers a remote description
    /// names.
    pub(crate) fn set_offered_layers(&mut self, rids: &[String]) {
        if self.offered.is_none() || !self.receive_codings.is_empty() {
            return;
        }
        let mut codings = vec![];
        for rid in rids {
            let rtp_coding_parameters = RTCRtpCodingParameters {
                rid: rid.clone(),
                ..Default::default()
            };
            self.receive_codings.push(rtp_coding_parameters.clone());
            codings.push(
                crate::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters {
                    rtp_coding_parameters,
                    ..Default::default()
                },
            );
        }
        self.track.set_codings(codings);
    }

    /// Whether the receiver's codings are only the layers a pending offer asked for
    /// ([`Self::set_offered_layers`]), none bound yet.
    pub(crate) fn offered_layers_unbound(&self) -> bool {
        self.offered
            .as_ref()
            .is_some_and(|offered| offered.prior_codings.is_empty())
            && !self.receive_codings.is_empty()
            && self
                .receive_codings
                .iter()
                .all(|coding| !coding.rid.is_empty() && coding.ssrc.is_none())
    }

    /// The offered layers give way to a stream that carries no rid: the remote side sends one
    /// stream where simulcast was offered (RFC 8853 section 5.3.2: an answerer may decline).
    pub(crate) fn drop_offered_layers(&mut self) {
        if self.offered_layers_unbound() {
            self.receive_codings.clear();
            self.track.set_codings(vec![]);
        }
    }

    /// The formats a packet may arrive with: the receive codecs, and while a local offer is
    /// pending every format it lists for the section (RFC 3264 section 5.1: "it MUST be
    /// prepared to receive media" as the offer describes it once the offer is sent; RFC 9429
    /// section 5.9: "For each specified media format, establish a mapping between the payload
    /// type and the actual media format"). For a section that was never answered the receive
    /// codecs are local preferences, not a negotiated list: the offer's formats alone count.
    pub(crate) fn receivable_codecs(&self) -> impl Iterator<Item = &RTCRtpCodecParameters> {
        let offered = self.offered.as_ref();
        let negotiated = offered.is_none_or(|offered| offered.negotiated);
        let listed = &self.receive_codecs;
        listed.iter().filter(move |_| negotiated).chain(
            offered
                .into_iter()
                .flat_map(|offered| offered.codecs.iter())
                .filter(move |codec| {
                    !negotiated
                        || !listed
                            .iter()
                            .any(|listed| listed.payload_type == codec.payload_type)
                }),
        )
    }

    /// [`Self::get_parameters`] as a stream is bound with: while a local offer is pending the
    /// codecs are the receivable ones ([`Self::receivable_codecs`]), the offered formats
    /// without feedback.
    pub(crate) fn stream_parameters(
        &mut self,
        media_engine: &MediaEngine,
    ) -> RTCRtpReceiveParameters {
        let mut parameters = self.get_parameters(media_engine).clone();
        if let Some(offered) = self.offered.as_ref() {
            if offered.negotiated {
                let extra: Vec<RTCRtpCodecParameters> = offered
                    .codecs
                    .iter()
                    .filter(|codec| {
                        !parameters
                            .rtp_parameters
                            .codecs
                            .iter()
                            .any(|listed| listed.payload_type == codec.payload_type)
                    })
                    .cloned()
                    .collect();
                parameters.rtp_parameters.codecs.extend(extra);
            } else {
                parameters.rtp_parameters.codecs.clone_from(&offered.codecs);
            }
        }
        parameters
    }

    pub(crate) fn set_codec_preferences(&mut self, codecs: Vec<RTCRtpCodecParameters>) {
        self.receive_codecs = codecs;
        self.last_returned_parameters = None;
    }

    /// The receive codecs of the last stable state, after a rollback (W3C webrtc-pc
    /// `[[LastStableStateReceiveCodecs]]`).
    pub(crate) fn restore_negotiated_state(&mut self, saved: &RTCRtpReceiverInternal) {
        self.receive_codecs.clone_from(&saved.receive_codecs);
        self.last_returned_parameters = None;
    }

    /// The SSRCs (media, RTX and FEC) of `codings`.
    fn coding_ssrcs(codings: &[RTCRtpCodingParameters]) -> Vec<SSRC> {
        codings
            .iter()
            .flat_map(|coding| {
                coding
                    .ssrc
                    .into_iter()
                    .chain(coding.rtx.as_ref().map(|rtx| rtx.ssrc))
                    .chain(coding.fec.as_ref().map(|fec| fec.ssrc))
            })
            .collect()
    }

    /// The streams of this receiver that the pending offer did not find (their SSRC is in
    /// none of the codings it found), as [`Self::remote_stream_infos`] describes them now.
    fn early_stream_infos(&mut self, media_engine: &MediaEngine) -> Vec<StreamInfo> {
        let prior = self
            .offered
            .as_ref()
            .map(|offered| Self::coding_ssrcs(&offered.prior_codings))
            .unwrap_or_default();
        self.remote_stream_infos(media_engine)
            .into_iter()
            .filter(|info| !prior.contains(&info.ssrc))
            .collect()
    }

    /// A stream was bound to the interceptors while a local offer is pending: the receiver
    /// remembers what its early streams are bound with, for the answer to compare with and a
    /// rollback to unbind. A no-op without a pending offer.
    pub(crate) fn note_early_streams(&mut self, media_engine: &MediaEngine) {
        if self.offered.is_none() {
            return;
        }
        let infos = self.early_stream_infos(media_engine);
        if let Some(offered) = self.offered.as_mut() {
            offered.early_streams = Some(infos);
        }
    }

    /// The pending offer's early streams were unbound by a rollback that was then undone (an
    /// implicit rollback whose remote offer was refused, which leaves the local offer
    /// pending): they are no longer established, and each one's next packet establishes it
    /// again, binding it and opening its statistics anew.
    pub(crate) fn reestablish_early_streams(&mut self) {
        let Some(offered) = self.offered.as_mut() else {
            return;
        };
        if offered.early_streams.is_none() {
            return;
        }
        offered.early_streams = Some(vec![]);
        let prior = Self::coding_ssrcs(&offered.prior_codings);
        let mut codings = self.track.codings().to_vec();
        for coding in &mut codings {
            if coding
                .rtp_coding_parameters
                .ssrc
                .is_some_and(|ssrc| !prior.contains(&ssrc))
            {
                coding.codec = Default::default();
            }
        }
        self.track.set_codings(codings);
    }

    /// Brings the interceptors' bindings of the early streams in line with the receiver's
    /// codings and codecs as they are now: a stream whose description changed is unbound with
    /// what it was bound with and bound again, one that is gone is unbound, a new one is
    /// bound; a stream that is described as before is left alone, with everything the
    /// interceptors keep for it. A no-op without a pending offer.
    pub(crate) fn resync_early_streams(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) {
        if self.offered.is_none() {
            return;
        }
        let now = self.early_stream_infos(media_engine);
        let Some(offered) = self.offered.as_mut() else {
            return;
        };
        let before = offered
            .early_streams
            .replace(now.clone())
            .unwrap_or_default();
        Self::rebind_remote_streams(interceptor, &before, &now);
    }

    fn rebind_remote_streams(
        interceptor: &mut dyn Interceptor,
        before: &[StreamInfo],
        now: &[StreamInfo],
    ) {
        for info in before {
            if !now.contains(info) {
                interceptor.unbind_remote_stream(info);
            }
        }
        for info in now {
            if !before.contains(info) {
                interceptor.bind_remote_stream(info);
            }
        }
    }

    /// The codings early media gave an SSRC and a codec while the offer was pending (the
    /// receive codings and the track's), for the answer to carry over
    /// ([`Self::adopt_early_codings`]); `None` when no stream arrived early.
    #[allow(clippy::type_complexity)]
    pub(crate) fn early_codings(
        &self,
    ) -> Option<(
        Vec<RTCRtpCodingParameters>,
        Vec<crate::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters>,
    )> {
        self.offered
            .as_ref()
            .filter(|offered| offered.early_streams.is_some())
            .map(|_| (self.receive_codings.clone(), self.track.codings().to_vec()))
    }

    /// The answer described the receiver's track anew (its SSRC, or its layers by rid, or
    /// neither): what early media already established stays. A layer keeps the SSRC, repair
    /// SSRCs and codec its rid was bound with; a declared SSRC that already arrived keeps its
    /// codec (the declared repair SSRCs are the answer's); an answer that declares neither
    /// keeps the stream the media itself placed (RFC 9143 section 9.2: `a=ssrc` lines are
    /// optional). An early stream the answer describes otherwise (another SSRC, no such rid)
    /// is not carried over.
    pub(crate) fn adopt_early_codings(
        &mut self,
        early: (
            Vec<RTCRtpCodingParameters>,
            Vec<crate::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters>,
        ),
    ) {
        let (early_codings, early_track_codings) = early;
        if self.receive_codings.is_empty() && self.track.codings().is_empty() {
            self.receive_codings = early_codings
                .into_iter()
                .filter(|coding| coding.rid.is_empty() && coding.ssrc.is_some())
                .collect();
            self.track.set_codings(
                early_track_codings
                    .into_iter()
                    .filter(|coding| {
                        coding.rtp_coding_parameters.rid.is_empty()
                            && coding.rtp_coding_parameters.ssrc.is_some()
                    })
                    .collect(),
            );
            return;
        }
        for coding in &mut self.receive_codings {
            if coding.rid.is_empty() {
                continue;
            }
            if let Some(early) = early_codings
                .iter()
                .find(|early| early.rid == coding.rid && early.ssrc.is_some())
            {
                coding.ssrc = early.ssrc;
                coding.rtx.clone_from(&early.rtx);
                coding.fec.clone_from(&early.fec);
            }
        }
        let mut track_codings = self.track.codings().to_vec();
        for coding in &mut track_codings {
            let parameters = &mut coding.rtp_coding_parameters;
            let early = if parameters.rid.is_empty() {
                early_track_codings.iter().find(|early| {
                    early.rtp_coding_parameters.rid.is_empty()
                        && early.rtp_coding_parameters.ssrc.is_some()
                        && early.rtp_coding_parameters.ssrc == parameters.ssrc
                })
            } else {
                early_track_codings.iter().find(|early| {
                    early.rtp_coding_parameters.rid == parameters.rid
                        && early.rtp_coding_parameters.ssrc.is_some()
                })
            };
            let Some(early) = early else {
                continue;
            };
            if !parameters.rid.is_empty() {
                parameters.ssrc = early.rtp_coding_parameters.ssrc;
                parameters.rtx.clone_from(&early.rtp_coding_parameters.rtx);
                parameters.fec.clone_from(&early.rtp_coding_parameters.fec);
            }
            coding.codec.clone_from(&early.codec);
        }
        self.track.set_codings(track_codings);
    }

    /// The final answer to the pending offer was applied: the offered formats it did not
    /// take stop being receivable (RFC 3264 section 8.3.2: "if the offered stream is
    /// rejected, the offer can cease being prepared to receive using any new formats as soon
    /// as the rejection is received"; the receive codecs are the answer's from here on), and
    /// each stream that arrived early is bound with what the answer negotiated: its feedback
    /// (RFC 9429 section 5.11), header extensions and repair flows. A stream the answer
    /// changes nothing for keeps its binding, and so what the interceptors hold for it; one
    /// that arrived in a format the answer left out is not established any more, and its
    /// next packet in a format of the answer establishes it again.
    ///
    /// # Returns
    ///
    /// Whether the receiver had streams that arrived early.
    pub(crate) fn settle_offered(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> bool {
        let Some(offered) = self.offered.take() else {
            return false;
        };
        self.last_returned_parameters = None;
        let Some(early) = offered.early_streams else {
            return false;
        };
        let prior = Self::coding_ssrcs(&offered.prior_codings);
        let codecs = self
            .get_parameters(media_engine)
            .rtp_parameters
            .codecs
            .clone();
        let mut codings = self.track.codings().to_vec();
        for coding in &mut codings {
            if coding
                .rtp_coding_parameters
                .ssrc
                .is_none_or(|ssrc| prior.contains(&ssrc))
                || coding.codec.mime_type.is_empty()
            {
                continue;
            }
            // The stream's codec is the negotiated format from here on, with its feedback.
            let (negotiated, match_type) = codec_parameters_fuzzy_search(&coding.codec, &codecs);
            coding.codec = if match_type == CodecMatch::None {
                Default::default()
            } else {
                negotiated.rtp_codec
            };
        }
        self.track.set_codings(codings);
        let now: Vec<StreamInfo> = self
            .remote_stream_infos(media_engine)
            .into_iter()
            .filter(|info| !prior.contains(&info.ssrc))
            .collect();
        Self::rebind_remote_streams(interceptor, &early, &now);
        true
    }

    /// The pending offer was rolled back (RFC 9429 section 5.7: "the state of the session is
    /// restored to the state it was in before the offer"): its formats are no longer
    /// receivable, the streams that arrived early are unbound, and the codings are the ones
    /// the offer found.
    ///
    /// # Returns
    ///
    /// The SSRCs of the streams that are gone, and whether the track, unmuted by early media,
    /// is muted again.
    pub(crate) fn roll_back_offered(
        &mut self,
        interceptor: &mut dyn Interceptor,
    ) -> (Vec<SSRC>, bool) {
        let Some(offered) = self.offered.take() else {
            return (vec![], false);
        };
        self.last_returned_parameters = None;
        let layers_offered = offered.prior_codings.is_empty() && !self.receive_codings.is_empty();
        let Some(early) = offered.early_streams else {
            if layers_offered {
                self.receive_codings = offered.prior_codings;
                self.track.set_codings(offered.prior_track_codings);
            }
            return (vec![], false);
        };
        for info in &early {
            interceptor.unbind_remote_stream(info);
        }
        self.receive_codings = offered.prior_codings;
        self.track.set_codings(offered.prior_track_codings);
        let muted_again = offered.prior_muted && !self.track.muted();
        if muted_again {
            self.track.set_muted(true);
        }
        (early.iter().map(|info| info.ssrc).collect(), muted_again)
    }

    pub(crate) fn set_track(&mut self, mut track: MediaStreamTrack) {
        track.set_remote();
        self.track = track;
    }

    /// webrtc-pc 9.3.1, the settings of a remote video track: the application (its decoder,
    /// or a depacketizer that reads the frame size from a key frame) reports each video frame
    /// it received, with its size. The track's `width`, `height` and `aspectRatio` are the
    /// latest frame's; `frameRate` is estimated from the frames of the last second: the frame
    /// intervals in it over the time they span, once there are two.
    pub(crate) fn report_received_frame(&mut self, now: Instant, width: u32, height: u32) {
        const WINDOW: Duration = Duration::from_secs(1);
        while self
            .received_frames
            .front()
            .is_some_and(|&first| now.saturating_duration_since(first) > WINDOW)
        {
            self.received_frames.pop_front();
        }
        self.received_frames.push_back(now);
        let frame_rate = match (self.received_frames.front(), self.received_frames.back()) {
            (Some(&first), Some(&last)) if self.received_frames.len() >= 2 && last > first => {
                Some((self.received_frames.len() - 1) as f64 / (last - first).as_secs_f64())
            }
            _ => None,
        };
        self.track.record_received_frame(width, height, frame_rate);
    }

    /// Ends the receiver's track (W3C webrtc 5.4 "stop sending and receiving").
    ///
    /// # Returns
    ///
    /// Whether the track was live, so that its end is announced once.
    pub(crate) fn end_track(&mut self) -> bool {
        use crate::media_stream::track_state::MediaStreamTrackState;
        if self.track.ready_state() == MediaStreamTrackState::Ended {
            return false;
        }
        self.track.stop();
        self.end_unannounced = true;
        true
    }

    /// A new track in place of the receiver's (ended) one, as a new msid-appdata names it
    /// (RFC 8830 section 3, `with_msid_appdata_change_renews_track`): a new id the engine
    /// generates, live and muted, with the old one's stream, codings and label.
    pub(crate) fn renew_track(&mut self) {
        let mut track = self.track.clone();
        track.track_id = shared::util::math_rand_alpha(16);
        track.renew();
        track.set_muted(true);
        self.track = track;
    }

    /// Whether the track ended since the application was last told (once: the flag is
    /// cleared).
    pub(crate) fn take_unannounced_end(&mut self) -> bool {
        std::mem::take(&mut self.end_unannounced)
    }

    pub(crate) fn stop(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
    ) -> Result<()> {
        self.interceptor_remote_streams_op(media_engine, interceptor, false);

        Ok(())
    }

    /// Binds or unbinds one remote stream, optionally carrying its repair-flow associations.
    ///
    /// RTX ([RFC 4588]) and FEC ([RFC 8888]/FlexFEC) both repair a media stream from a *separate*
    /// SSRC, so both are described the same way: the association travels on the media stream's
    /// `StreamInfo`, telling an interceptor which SSRC carries repair for it. This mirrors what
    /// the sender side already does in `local_stream_infos`.
    ///
    /// [RFC 4588]: https://datatracker.ietf.org/doc/html/rfc4588
    /// [RFC 8888]: https://datatracker.ietf.org/doc/html/rfc8888
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn interceptor_remote_stream_op(
        interceptor: &mut dyn Interceptor,
        is_binding: bool,
        ssrc: SSRC,
        ssrc_rtx: Option<SSRC>,
        ssrc_fec: Option<SSRC>,
        payload_type: PayloadType,
        payload_type_rtx: Option<PayloadType>,
        fec_format: Option<&FecFormat>,
        rtp_codec: &RTCRtpCodec,
        header_extensions: &[RTCRtpHeaderExtensionParameters],
        section_codecs: &[RTCRtpCodecParameters],
    ) {
        let stream_info = create_stream_info(
            ssrc,
            ssrc_rtx,
            ssrc_fec,
            payload_type,
            payload_type_rtx,
            fec_format,
            rtp_codec,
            header_extensions,
            section_codecs,
        );

        if is_binding {
            interceptor.bind_remote_stream(&stream_info);
        } else {
            interceptor.unbind_remote_stream(&stream_info);
        }
    }

    /// The streams of this receiver as the interceptors are told of them: for each coding
    /// of the track with an SSRC and a codec that is receivable, the media stream with its
    /// repair associations, then its RTX flow and its FEC flow as streams of their own.
    pub(crate) fn remote_stream_infos(&mut self, media_engine: &MediaEngine) -> Vec<StreamInfo> {
        let parameters = self.stream_parameters(media_engine);
        let mut infos = vec![];

        for coding in self.track().codings() {
            let (codec, match_type) =
                codec_parameters_fuzzy_search(&coding.codec, &parameters.rtp_parameters.codecs);
            if let Some(&ssrc) = coding.rtp_coding_parameters.ssrc.as_ref()
                && match_type != CodecMatch::None
            {
                // Both halves or neither, for each repair flow: a repair SSRC whose payload type
                // was never negotiated is not a usable association, and a half-filled one would
                // open an interceptor's bind gate on a flow it cannot actually demultiplex.
                let rtx = coding.rtp_coding_parameters.rtx.as_ref().and_then(|rtx| {
                    find_rtx_payload_type(codec.payload_type, &parameters.rtp_parameters.codecs)
                        .map(|payload_type| (rtx.ssrc, payload_type))
                });
                let fec = coding.rtp_coding_parameters.fec.as_ref().and_then(|fec| {
                    find_receive_fec_format(&parameters.rtp_parameters.codecs)
                        .map(|fec_format| (fec.ssrc, fec_format))
                });

                infos.push(create_stream_info(
                    ssrc,
                    rtx.map(|(ssrc_rtx, _)| ssrc_rtx),
                    fec.as_ref().map(|(ssrc_fec, _)| *ssrc_fec),
                    codec.payload_type,
                    rtx.map(|(_, payload_type_rtx)| payload_type_rtx),
                    fec.as_ref().map(|(_, fec_format)| fec_format),
                    &codec.rtp_codec,
                    &parameters.rtp_parameters.header_extensions,
                    &parameters.rtp_parameters.codecs,
                ));

                // Each repair flow is also bound in its own right, as it has been: it is a real
                // RTP stream with its own SSRC and sequence-number space, and an interceptor that
                // tracks arrival needs to know it exists. RTX and FEC are treated identically
                // here — they are the same shape of thing.
                if let Some((ssrc_rtx, payload_type_rtx)) = rtx {
                    infos.push(create_stream_info(
                        ssrc_rtx,
                        None,
                        None,
                        payload_type_rtx,
                        None,
                        None,
                        &repair_flow_codec(&codec.rtp_codec),
                        &parameters.rtp_parameters.header_extensions,
                        &[],
                    ));
                }

                if let Some((ssrc_fec, fec_format)) = fec {
                    infos.push(create_stream_info(
                        ssrc_fec,
                        None,
                        None,
                        fec_format.payload_type,
                        None,
                        None,
                        &repair_flow_codec(&codec.rtp_codec),
                        &parameters.rtp_parameters.header_extensions,
                        &[],
                    ));
                }
            }
        }
        infos
    }

    pub(crate) fn interceptor_remote_streams_op(
        &mut self,
        media_engine: &MediaEngine,
        interceptor: &mut dyn Interceptor,
        is_binding: bool,
    ) {
        for info in self.remote_stream_infos(media_engine) {
            if is_binding {
                interceptor.bind_remote_stream(&info);
            } else {
                interceptor.unbind_remote_stream(&info);
            }
        }
    }
}

#[cfg(test)]
mod repair_association_test {
    //! Repair-flow associations on remote streams (FEC-PRE-01).
    //!
    //! RTX ([RFC 4588]) and FEC (FlexFEC) both repair a media stream from a **separate SSRC**, so
    //! both are described the same way: the association travels on the media stream's
    //! `StreamInfo`. A receive-side FEC interceptor binds on the media stream and gates on the
    //! FEC SSRC and payload type both being present — so an association that never arrives means
    //! the interceptor silently never binds, which is invisible until recovery quietly does not
    //! happen.
    //!
    //! [RFC 4588]: https://datatracker.ietf.org/doc/html/rfc4588

    // Imported explicitly rather than with `use super::*`: the parent module has
    // `shared::error::Result` in scope, and the interceptor macros generate `Result<_, _>`.
    use super::{RTCRtpReceiverInternal, RtpCodecKind};
    use crate::media_stream::track::MediaStreamTrack;
    use crate::peer_connection::configuration::media_engine::{
        MIME_TYPE_FLEX_FEC, MIME_TYPE_FLEX_FEC03, MIME_TYPE_RTX, MIME_TYPE_VP8, MediaEngine,
    };
    use crate::rtp_transceiver::rtp_sender::rtp_codec_parameters::RTCRtpCodecParameters;
    use crate::rtp_transceiver::rtp_sender::rtp_coding_parameters::RTCRtpCodingParameters;
    use crate::rtp_transceiver::rtp_sender::rtp_encoding_parameters::RTCRtpEncodingParameters;
    use crate::rtp_transceiver::rtp_sender::{
        RTCRtpCodec, RTCRtpFecParameters, RTCRtpRtxParameters,
    };
    use crate::rtp_transceiver::{PayloadType, SSRC};
    use interceptor::{Interceptor, StreamInfo, TaggedPacket};
    use sansio::Protocol;
    use shared::error::Error;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    /// Records every remote stream bound and unbound, so a test can assert what the chain was
    /// told rather than what the caller intended.
    #[derive(Default)]
    struct Recorder {
        bound: Arc<Mutex<Vec<StreamInfo>>>,
        unbound: Arc<Mutex<Vec<StreamInfo>>>,
        read_queue: VecDeque<TaggedPacket>,
        write_queue: VecDeque<TaggedPacket>,
    }

    impl Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
        type Rout = TaggedPacket;
        type Wout = TaggedPacket;
        type Eout = ();
        type Error = Error;
        type Time = Instant;

        fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.read_queue.push_back(msg);
            Ok(())
        }

        fn poll_read(&mut self) -> Option<Self::Rout> {
            self.read_queue.pop_front()
        }

        fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
            self.write_queue.push_back(msg);
            Ok(())
        }

        fn poll_write(&mut self) -> Option<Self::Wout> {
            self.write_queue.pop_front()
        }
    }

    impl Interceptor for Recorder {
        fn bind_local_stream(&mut self, _info: &StreamInfo) {}
        fn unbind_local_stream(&mut self, _info: &StreamInfo) {}

        fn bind_remote_stream(&mut self, info: &StreamInfo) {
            self.bound.lock().unwrap().push(info.clone());
        }

        fn unbind_remote_stream(&mut self, info: &StreamInfo) {
            self.unbound.lock().unwrap().push(info.clone());
        }
    }

    fn codec(payload_type: PayloadType, mime_type: &str, fmtp: &str) -> RTCRtpCodecParameters {
        RTCRtpCodecParameters {
            rtp_codec: RTCRtpCodec {
                mime_type: mime_type.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: fmtp.to_owned(),
                rtcp_feedback: vec![],
            },
            payload_type,
        }
    }

    /// A media engine offering VP8, its RTX form, and FlexFEC-03.
    ///
    /// FlexFEC is registered explicitly rather than relying on defaults: `register_default_codecs`
    /// does not offer it yet (that is P3A-05, gated on recovery actually working), so a test that
    /// assumed the default would be asserting on a codec the engine never had.
    fn media_engine() -> MediaEngine {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec(96, MIME_TYPE_VP8, ""), RtpCodecKind::Video)
            .expect("vp8");
        media_engine
            .register_codec(codec(97, MIME_TYPE_RTX, "apt=96"), RtpCodecKind::Video)
            .expect("rtx");
        media_engine
            .register_codec(codec(98, MIME_TYPE_FLEX_FEC03, ""), RtpCodecKind::Video)
            .expect("flexfec");
        media_engine
    }

    /// A media engine that never negotiated FlexFEC.
    fn media_engine_without_fec() -> MediaEngine {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_codec(codec(96, MIME_TYPE_VP8, ""), RtpCodecKind::Video)
            .expect("vp8");
        media_engine
    }

    fn encoding(
        rid: &str,
        ssrc: SSRC,
        rtx_ssrc: Option<SSRC>,
        fec_ssrc: Option<SSRC>,
    ) -> RTCRtpEncodingParameters {
        RTCRtpEncodingParameters {
            rtp_coding_parameters: RTCRtpCodingParameters {
                rid: rid.to_owned(),
                ssrc: Some(ssrc),
                rtx: rtx_ssrc.map(|ssrc| RTCRtpRtxParameters { ssrc }),
                fec: fec_ssrc.map(|ssrc| RTCRtpFecParameters { ssrc }),
                ..Default::default()
            },
            codec: RTCRtpCodec {
                mime_type: MIME_TYPE_VP8.to_owned(),
                clock_rate: 90000,
                channels: 0,
                sdp_fmtp_line: String::new(),
                rtcp_feedback: vec![],
            },
            ..Default::default()
        }
    }

    /// Runs the bind (or unbind) pass and returns what the chain was told.
    fn run(
        media_engine: &MediaEngine,
        encodings: Vec<RTCRtpEncodingParameters>,
        is_binding: bool,
    ) -> Vec<StreamInfo> {
        let bound = Arc::new(Mutex::new(Vec::new()));
        let unbound = Arc::new(Mutex::new(Vec::new()));
        let mut interceptor = Recorder {
            bound: Arc::clone(&bound),
            unbound: Arc::clone(&unbound),
            ..Default::default()
        };

        let codings = encodings
            .iter()
            .map(|e| e.rtp_coding_parameters.clone())
            .collect();
        let mut receiver = RTCRtpReceiverInternal::new(RtpCodecKind::Video, codings);
        receiver.set_track(MediaStreamTrack::new(
            "stream".to_owned(),
            "track".to_owned(),
            "label".to_owned(),
            RtpCodecKind::Video,
            encodings,
        ));

        receiver.interceptor_remote_streams_op(media_engine, &mut interceptor, is_binding);

        let recorded = if is_binding { bound } else { unbound };

        recorded.lock().unwrap().clone()
    }

    /// RFC 7160 section 4.3 and RFC 8834 section 4.3: a remote stream is bound with the clock
    /// rate of every other media format its m= section negotiated, so a source that switches
    /// payload type is timed with each one's rate; the repair formats (RTX, FEC) are not media
    /// formats of the stream and stay out.
    #[test]
    fn a_remote_stream_carries_the_clock_rates_of_the_sections_other_formats() {
        let mut media_engine = media_engine();
        let mut other = codec(100, "video/H264", "");
        other.rtp_codec.clock_rate = 45_000;
        media_engine
            .register_codec(other, RtpCodecKind::Video)
            .expect("h264");
        let streams = run(
            &media_engine,
            vec![encoding("", 1000, Some(2000), None)],
            true,
        );
        assert_eq!(
            vec![(100, 45_000)],
            primary(&streams, 1000).payload_clock_rates
        );
    }

    fn primary(streams: &[StreamInfo], ssrc: SSRC) -> &StreamInfo {
        streams
            .iter()
            .find(|info| info.ssrc == ssrc)
            .unwrap_or_else(|| panic!("no stream bound for ssrc {ssrc}; bound: {streams:?}"))
    }

    /// The gap FEC-PRE-01 closes: without this the FEC fields are `None` and a receive-side FEC
    /// interceptor never binds.
    #[test]
    fn the_media_stream_carries_its_fec_association() {
        let streams = run(
            &media_engine(),
            vec![encoding("", 1000, None, Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(
            Some(3000),
            media.ssrc_fec,
            "the media stream must name the SSRC carrying its repair packets"
        );
        assert_eq!(
            Some(98),
            media.payload_type_fec,
            "and the FlexFEC payload type, which is the other half of the interceptor's gate"
        );
    }

    /// The stream says which FEC format its repair flow is, so the right coder binds: draft-03
    /// here, as negotiated.
    #[test]
    fn the_media_stream_names_its_fec_format() {
        let streams = run(
            &media_engine(),
            vec![encoding("", 1000, None, Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(MIME_TYPE_FLEX_FEC03, media.mime_type_fec);
        assert!(media.fec_is_flexfec03() && !media.fec_is_flexfec());
    }

    /// RFC 8627 section 7: with `video/flexfec` negotiated, the `FEC-FR` repair flow is bound as
    /// RFC 8627 FlexFEC, and its `repair-window` (section 5.1) goes with it.
    #[test]
    fn an_rfc_8627_repair_flow_is_bound_as_flexfec_with_its_repair_window() {
        let mut media_engine = media_engine_without_fec();
        media_engine
            .register_codec(
                codec(110, MIME_TYPE_FLEX_FEC, "repair-window=200000"),
                RtpCodecKind::Video,
            )
            .expect("flexfec");

        let streams = run(
            &media_engine,
            vec![encoding("", 1000, None, Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(
            (Some(3000), Some(110)),
            (media.ssrc_fec, media.payload_type_fec)
        );
        assert_eq!(MIME_TYPE_FLEX_FEC, media.mime_type_fec);
        assert_eq!("repair-window=200000", media.sdp_fmtp_line_fec);
        assert!(media.fec_is_flexfec() && !media.fec_is_flexfec03());
        assert!(
            streams.iter().any(|info| info.ssrc == 3000),
            "the repair flow is bound in its own right: {streams:?}"
        );
    }

    /// RTX and FEC are the same shape of thing — a repair flow on its own SSRC — and are reported
    /// identically. This is the property that keeps the two paths from drifting apart.
    #[test]
    fn rtx_and_fec_associations_are_reported_the_same_way() {
        let streams = run(
            &media_engine(),
            vec![encoding("", 1000, Some(2000), Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(
            (Some(2000), Some(97)),
            (media.ssrc_rtx, media.payload_type_rtx)
        );
        assert_eq!(
            (Some(3000), Some(98)),
            (media.ssrc_fec, media.payload_type_fec)
        );

        // Each repair flow is also bound in its own right, as a real RTP stream with its own
        // sequence-number space — again, both the same way.
        assert!(
            streams.iter().any(|info| info.ssrc == 2000),
            "the RTX flow is bound: {streams:?}"
        );
        assert!(
            streams.iter().any(|info| info.ssrc == 3000),
            "the FEC flow is bound: {streams:?}"
        );
    }

    /// Both halves or neither. A repair SSRC whose payload type was never negotiated is not a
    /// usable association: reporting the SSRC alone would open an interceptor's bind gate on a
    /// flow it cannot demultiplex.
    #[test]
    fn a_repair_ssrc_without_a_negotiated_payload_type_is_not_reported() {
        let streams = run(
            &media_engine_without_fec(),
            vec![encoding("", 1000, None, Some(3000))],
            true,
        );

        let media = primary(&streams, 1000);
        assert_eq!(None, media.ssrc_fec, "no FlexFEC codec was negotiated");
        assert_eq!(None, media.payload_type_fec);
        assert!(
            !streams.iter().any(|info| info.ssrc == 3000),
            "and the unusable repair flow is not bound either: {streams:?}"
        );
    }

    /// Simulcast: every layer has its own repair flow, so the association must be resolved per
    /// coding. Sharing one would point recovery at another layer's packets.
    #[test]
    fn each_simulcast_layer_carries_its_own_repair_flow() {
        let streams = run(
            &media_engine(),
            vec![
                encoding("hi", 1000, Some(2000), Some(3000)),
                encoding("lo", 1001, Some(2001), Some(3001)),
            ],
            true,
        );

        assert_eq!(Some(3000), primary(&streams, 1000).ssrc_fec);
        assert_eq!(Some(3001), primary(&streams, 1001).ssrc_fec);
        assert_eq!(Some(2000), primary(&streams, 1000).ssrc_rtx);
        assert_eq!(Some(2001), primary(&streams, 1001).ssrc_rtx);
    }

    /// Unbinding must describe the same streams binding did, or an interceptor keyed on the
    /// association cannot clean up what it created.
    #[test]
    fn unbinding_reports_the_same_associations() {
        let encodings = vec![encoding("", 1000, Some(2000), Some(3000))];
        let bound = run(&media_engine(), encodings.clone(), true);
        let unbound = run(&media_engine(), encodings, false);

        assert_eq!(
            bound.len(),
            unbound.len(),
            "every bound stream is unbound: bound={bound:?} unbound={unbound:?}"
        );
        let bound_media = primary(&bound, 1000);
        let unbound_media = primary(&unbound, 1000);
        assert_eq!(bound_media.ssrc_fec, unbound_media.ssrc_fec);
        assert_eq!(bound_media.payload_type_fec, unbound_media.payload_type_fec);
        assert_eq!(bound_media.ssrc_rtx, unbound_media.ssrc_rtx);
    }

    /// A stream with no repair flows reports none — the association fields are not filled in
    /// speculatively from whatever the media engine happens to offer.
    #[test]
    fn a_stream_without_repair_flows_reports_no_association() {
        let streams = run(&media_engine(), vec![encoding("", 1000, None, None)], true);

        assert_eq!(
            1,
            streams.len(),
            "only the media stream is bound: {streams:?}"
        );
        let media = primary(&streams, 1000);
        assert_eq!(None, media.ssrc_fec);
        assert_eq!(None, media.payload_type_fec);
        assert_eq!(None, media.ssrc_rtx);
        assert_eq!(None, media.payload_type_rtx);
    }
}

/// A synchronization source's last `abs-capture-time`: the capture time and the offset in
/// milliseconds, with the RTP timestamp of its packet.
#[derive(Debug, Clone, Copy)]
struct CaptureReference {
    ssrc: u32,
    capture_ms: f64,
    rtp_timestamp: u32,
    offset_ms: Option<f64>,
}

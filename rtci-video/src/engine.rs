//! The glue between the pipelines and the `rtci` peer connection (feature `engine`):
//! [`VideoReceiver`] for an `RTCRtpReceiver`, [`VideoSender`] for an `RTCRtpSender`.
//!
//! ```rust,ignore
//! // On RTCPeerConnectionEvent::OnTrack(RTCTrackEvent::OnOpen(init)) for video:
//! let mut video = VideoReceiver::new(&mut pc, init.receiver_id, ReceiveConfig::default())?;
//! // For each RTCMessage::RtpPacket(track, packet) of its track:
//! video.handle_rtp(now, &packet);
//! // Whenever poll_timeout says, and after packets:
//! video.poll(&mut pc, now)?;                       // timers, PLI
//! while let Some((ssrc, request)) = video.poll_frame(now) {
//!     let outcome = decode(&request.frame);       // the application's decoder
//!     video.on_decoded(&mut pc, now, ssrc, request.token, outcome);
//! }
//! // At each picture's render time:
//! video.on_rendered(ssrc, now);
//! // Now and then:
//! video.update_stats(&mut pc, now);               // getStats()
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rtci::media_stream::MediaStreamTrackId;
use rtci::peer_connection::RTCPeerConnection;
use rtci::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
use rtci::rtp::codec::dependency_descriptor::{
    DEPENDENCY_DESCRIPTOR_URI, DependencyDescriptorReader,
};
use rtci::rtp_transceiver::RTCRtpReceiverId;
use rtci::statistics::DecoderStatsUpdate;

use crate::frame::{Codec, VideoPacket};
use crate::keyframe::KeyFrameReason;
use crate::receive::{DecodeOutcome, DecodeRequest, ReceiveConfig, ReceivePipeline};
use crate::stats::ReceiveStats;

pub use crate::engine_send::{DEFAULT_RTP_MTU, RtpStart, VideoSender};

/// The playout-delay extension's URI (a webrtc.org experiment, no RFC).
pub const PLAYOUT_DELAY_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay";

/// Errors of the glue.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The receiver (or sender) is gone.
    #[error("no such receiver or sender")]
    NoReceiver,
    /// The engine refused an operation.
    #[error("engine: {0}")]
    Engine(String),
    /// The encoder failed ([`VideoSender`]).
    #[error(transparent)]
    Encode(#[from] crate::encoder::EncodeError),
}

struct Stream {
    pipeline: ReceivePipeline,
    descriptors: DependencyDescriptorReader,
    /// The NACK horizon last given to the engine.
    horizon_sent: Option<u16>,
}

/// The receive pipelines of one video `RTCRtpReceiver`: one per SSRC it receives.
pub struct VideoReceiver {
    receiver: RTCRtpReceiverId,
    track: MediaStreamTrackId,
    config: ReceiveConfig,
    codecs: HashMap<u8, Codec>,
    pli: bool,
    dd_id: Option<u8>,
    playout_delay_id: Option<u8>,
    streams: HashMap<u32, Stream>,
    plis_sent: u32,
    rtt: Option<Duration>,
}

impl VideoReceiver {
    /// Binds to `receiver` after negotiation.
    ///
    /// # Errors
    ///
    /// [`Error::NoReceiver`] when the receiver is gone.
    pub fn new(
        pc: &mut RTCPeerConnection,
        receiver: RTCRtpReceiverId,
        config: ReceiveConfig,
    ) -> Result<Self, Error> {
        let mut r = pc.rtp_receiver(receiver).ok_or(Error::NoReceiver)?;
        let track = r.track().track_id().clone();
        let params = r.get_parameters().rtp_parameters.clone();
        let mut codecs = HashMap::new();
        let mut pli = false;
        for c in &params.codecs {
            if let Some(codec) = Codec::from_mime_type(&c.rtp_codec.mime_type) {
                codecs.insert(c.payload_type, codec);
                pli |= c
                    .rtp_codec
                    .rtcp_feedback
                    .iter()
                    .any(|fb| fb.typ == "nack" && fb.parameter == "pli");
            }
        }
        let ext = |uri: &str| {
            params
                .header_extensions
                .iter()
                .find(|e| e.uri == uri)
                .and_then(|e| u8::try_from(e.id).ok())
        };
        Ok(Self {
            receiver,
            track,
            codecs,
            pli,
            dd_id: ext(DEPENDENCY_DESCRIPTOR_URI),
            playout_delay_id: ext(PLAYOUT_DELAY_URI),
            streams: HashMap::new(),
            config,
            plis_sent: 0,
            rtt: None,
        })
    }

    /// The track whose packets this receiver takes.
    pub fn track_id(&self) -> &MediaStreamTrackId {
        &self.track
    }

    /// PLIs sent.
    pub fn plis_sent(&self) -> u32 {
        self.plis_sent
    }

    /// The pipeline of `ssrc`.
    pub fn pipeline(&mut self, ssrc: u32) -> Option<&mut ReceivePipeline> {
        self.streams.get_mut(&ssrc).map(|s| &mut s.pipeline)
    }

    /// The SSRCs received.
    pub fn ssrcs(&self) -> Vec<u32> {
        self.streams.keys().copied().collect()
    }

    /// Takes an RTP packet of this receiver's track (`RTCMessage::RtpPacket`) that arrived at
    /// `now`. Packets of a payload type that is not a video codec (RTX, FEC: the engine has
    /// already repaired from them) are ignored.
    pub fn handle_rtp(&mut self, now: Instant, packet: &rtci::rtp::Packet) {
        let h = &packet.header;
        let Some(&codec) = self.codecs.get(&h.payload_type) else {
            return;
        };
        let config = self.config.clone();
        let rtt = self.rtt;
        let stream = self.streams.entry(h.ssrc).or_insert_with(|| {
            let mut pipeline = ReceivePipeline::new(codec, now, config);
            if let Some(rtt) = rtt {
                pipeline.set_rtt(rtt);
            }
            Stream {
                pipeline,
                descriptors: DependencyDescriptorReader::new(),
                horizon_sent: None,
            }
        });
        let mut dependency_descriptor = None;
        if let Some(id) = self.dd_id
            && let Some(bytes) = h.get_extension(id)
        {
            match stream.descriptors.read(&bytes) {
                Ok(Some(dd)) => dependency_descriptor = Some(dd),
                Ok(None) | Err(_) => {
                    stream.pipeline.on_missing_structure(now);
                    return;
                }
            }
        }
        let playout_delay_ms = self.playout_delay_id.and_then(|id| {
            let b = h.get_extension(id)?;
            if b.len() < 3 {
                return None;
            }
            let min = (u32::from(b[0]) << 4) | (u32::from(b[1]) >> 4);
            let max = ((u32::from(b[1]) & 0x0f) << 8) | u32::from(b[2]);
            Some((min, max))
        });
        stream.pipeline.insert_packet(VideoPacket {
            arrival: now,
            sequence_number: h.sequence_number,
            timestamp: h.timestamp,
            marker: h.marker,
            payload_type: h.payload_type,
            ssrc: h.ssrc,
            payload: packet.payload.clone(),
            dependency_descriptor,
            playout_delay_ms,
            retransmitted: false,
        });
    }

    /// The NACK horizon last given to the engine for `ssrc` (see [`poll`](Self::poll)).
    pub fn nack_horizon(&self, ssrc: u32) -> Option<u16> {
        self.streams.get(&ssrc).and_then(|s| s.horizon_sent)
    }

    /// Runs the timers due at `now`, sends the key-frame requests due (PLI, when `nack pli`
    /// was negotiated) and, with [`ReceiveConfig::nack_horizon`], moves each stream's NACK
    /// horizon on to the oldest packet still useful (`RTCRtpReceiver::set_nack_horizon`).
    /// Returns the reasons of the requests made.
    ///
    /// # Errors
    ///
    /// [`Error::Engine`] when the engine refuses the RTCP or the horizon.
    pub fn poll(
        &mut self,
        pc: &mut RTCPeerConnection,
        now: Instant,
    ) -> Result<Vec<KeyFrameReason>, Error> {
        let mut reasons = Vec::new();
        let mut packets: Vec<Box<dyn rtci::rtcp::Packet>> = Vec::new();
        for (&ssrc, s) in &mut self.streams {
            s.pipeline.handle_timeout(now);
            if let Some(reason) = s.pipeline.poll_key_frame_request() {
                reasons.push(reason);
                if self.pli {
                    packets.push(Box::new(PictureLossIndication {
                        sender_ssrc: 0,
                        media_ssrc: ssrc,
                    }));
                }
            }
        }
        if !packets.is_empty() {
            self.plis_sent += packets.len() as u32;
            let mut r = pc.rtp_receiver(self.receiver).ok_or(Error::NoReceiver)?;
            r.write_rtcp(now, packets)
                .map_err(|e| Error::Engine(e.to_string()))?;
        }
        if self.config.nack_horizon {
            let mut moved = Vec::new();
            for (&ssrc, s) in &mut self.streams {
                // The pipeline's extended sequence number, back to the 16 bits on the wire.
                let horizon = s.pipeline.nack_horizon().map(|seq| seq as u16);
                if horizon.is_some() && horizon != s.horizon_sent {
                    s.horizon_sent = horizon;
                    moved.push((ssrc, horizon));
                }
            }
            if !moved.is_empty() {
                let mut r = pc.rtp_receiver(self.receiver).ok_or(Error::NoReceiver)?;
                for (ssrc, horizon) in moved {
                    r.set_nack_horizon(now, ssrc, horizon)
                        .map_err(|e| Error::Engine(e.to_string()))?;
                }
            }
        }
        Ok(reasons)
    }

    /// The next picture due, of any of the receiver's streams.
    pub fn poll_frame(&mut self, now: Instant) -> Option<(u32, DecodeRequest)> {
        self.streams
            .iter_mut()
            .find_map(|(&ssrc, s)| s.pipeline.poll_frame(now).map(|r| (ssrc, r)))
    }

    /// The decoder's outcome; a decoded picture's size goes to the receiver's track
    /// (`report_received_frame`).
    pub fn on_decoded(
        &mut self,
        pc: &mut RTCPeerConnection,
        now: Instant,
        ssrc: u32,
        token: u64,
        outcome: DecodeOutcome,
    ) {
        if let Some(s) = self.streams.get_mut(&ssrc) {
            s.pipeline.on_decoded(now, token, outcome);
        }
        if let DecodeOutcome::Decoded { width, height, .. } = outcome
            && let Some(mut r) = pc.rtp_receiver(self.receiver)
        {
            r.report_received_frame(now, width, height);
        }
    }

    /// A picture of `ssrc` was rendered at `now`.
    pub fn on_rendered(&mut self, ssrc: u32, now: Instant) {
        if let Some(s) = self.streams.get_mut(&ssrc) {
            s.pipeline.on_rendered(now);
        }
    }

    /// The round-trip time, for the jitter estimate.
    pub fn set_rtt(&mut self, rtt: Duration) {
        self.rtt = Some(rtt);
        for s in self.streams.values_mut() {
            s.pipeline.set_rtt(rtt);
        }
    }

    /// When [`poll`](Self::poll) or [`poll_frame`](Self::poll_frame) is next needed.
    pub fn poll_timeout(&self, now: Instant) -> Option<Instant> {
        self.streams
            .values()
            .map(|s| s.pipeline.poll_timeout(now))
            .min()
    }

    /// The statistics of `ssrc`.
    pub fn stats(&mut self, ssrc: u32, now: Instant) -> Option<ReceiveStats> {
        self.streams.get_mut(&ssrc).map(|s| s.pipeline.stats(now))
    }

    /// Follows the receiver's `jitterBufferTarget` and hands the statistics to the engine's
    /// `getStats()`.
    pub fn update_stats(&mut self, pc: &mut RTCPeerConnection, now: Instant) {
        let target = pc
            .rtp_receiver(self.receiver)
            .and_then(|r| r.jitter_buffer_target());
        for (&ssrc, s) in &mut self.streams {
            s.pipeline.set_jitter_buffer_target(target);
            let st = s.pipeline.stats(now);
            pc.update_decoder_stats(
                ssrc,
                DecoderStatsUpdate {
                    frames_received: Some(st.frames_received),
                    frames_assembled_from_multiple_packets: Some(
                        st.frames_assembled_from_multiple_packets,
                    ),
                    total_assembly_time: Some(st.total_assembly_time),
                    frames_dropped: Some(st.frames_dropped),
                    frames_per_second: Some(st.frames_per_second),
                    frames_decoded: Some(st.frames_decoded),
                    key_frames_decoded: Some(st.key_frames_decoded),
                    frames_rendered: Some(st.frames_rendered),
                    frame_width: st.frame_size.map(|s| s.0),
                    frame_height: st.frame_size.map(|s| s.1),
                    qp_sum: st.qp_sum,
                    total_decode_time: Some(st.total_decode_time),
                    total_inter_frame_delay: Some(st.total_inter_frame_delay),
                    total_squared_inter_frame_delay: Some(st.total_squared_inter_frame_delay),
                    total_processing_delay: Some(st.total_processing_delay),
                    pause_count: Some(st.pause_count),
                    total_pauses_duration: Some(st.total_pauses_duration),
                    freeze_count: Some(st.freeze_count),
                    total_freezes_duration: Some(st.total_freezes_duration),
                    packets_discarded: Some(st.packets_discarded),
                    jitter_buffer_delay: Some(st.jitter_buffer_delay),
                    jitter_buffer_target_delay: Some(st.jitter_buffer_target_delay),
                    jitter_buffer_minimum_delay: Some(st.jitter_buffer_minimum_delay),
                    jitter_buffer_emitted_count: Some(st.jitter_buffer_emitted_count),
                    ..Default::default()
                },
            );
        }
    }
}

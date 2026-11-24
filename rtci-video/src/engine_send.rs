//! The glue between the send pipeline and an `RTCRtpSender` of the `rtci` peer connection
//! (feature `engine`).
//!
//! ```rust,ignore
//! // After negotiation, for the video sender:
//! let factory = |w, h, fps: f64, bps| -> Result<Box<dyn VideoEncoder>, EncodeError> {
//!     Ok(Box::new(Vp8Encoder::new(w, h, fps.round() as u32, bps)?))
//! };
//! let mut video = VideoSender::new(&mut pc, sender_id, Box::new(factory),
//!     RtpStart { first_sequence_number: random(), first_timestamp: random() },
//!     SendConfig::default())?;
//! // Every event of the peer connection (PLI / FIR, the pacer's discards):
//! video.handle_event(now, &event);
//! // Now and then (the engine's target moves every 100 ms or so) and before each picture:
//! video.poll(&mut pc, now);
//! // Each captured picture:
//! video.send_frame(&mut pc, now, captured_at, &picture.view())?;
//! // Now and then: round-trip time in, encoder statistics out (getStats()):
//! video.update_stats(&mut pc, now);
//! ```

use std::time::{Duration, Instant};

use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::event::RTCPeerConnectionEvent;
use rtci::rtp_transceiver::RTCRtpSenderId;
use rtci::statistics::StatsSelector;
use rtci::statistics::report::RTCStatsReportEntry;
use rtci::statistics::stats::RTCQualityLimitationReason;
use rtci::statistics::{EncoderStatsUpdate, QualityLimitationDurations};

use crate::encoder::EncoderFactory;
use crate::engine::Error;
use crate::picture::I420;
use crate::send::{
    FrameOutcome, KeyFrameDecision, KeyFrameTrigger, RtpStreamConfig, SendConfig, SendPipeline,
    SendStats,
};

/// The largest RTP packet the sender writes, header included (the engine's default MTU leaves
/// room for SRTP, the header extensions and an RTX header within 1280 octets of IPv6).
pub const DEFAULT_RTP_MTU: usize = 1200;

/// Where the RTP stream starts (RFC 3550 5.1: both random).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpStart {
    /// The first sequence number.
    pub first_sequence_number: u16,
    /// The RTP timestamp of the first picture.
    pub first_timestamp: u32,
}

/// The send pipeline of one video `RTCRtpSender` (its first encoding; simulcast is not built
/// yet).
pub struct VideoSender {
    sender: RTCRtpSenderId,
    ssrc: u32,
    pipeline: SendPipeline,
    last_target: Option<f64>,
    key_frame_requests: u32,
    pacer_discards: u32,
}

impl VideoSender {
    /// Binds to `sender` after negotiation: its SSRC, its negotiated codec's payload type and
    /// payloader (built by the connection, [`RTCRtpSender::payloader`], so its behaviour
    /// profile decides the VP8 packetization).
    ///
    /// [`RTCRtpSender::payloader`]: rtci::rtp_transceiver::rtp_sender::RTCRtpSender::payloader
    ///
    /// # Errors
    ///
    /// [`Error::NoReceiver`] when the sender is gone; [`Error::Engine`] when it has no SSRC or
    /// no negotiated video codec.
    pub fn new(
        pc: &mut RTCPeerConnection,
        sender: RTCRtpSenderId,
        factory: Box<dyn EncoderFactory>,
        start: RtpStart,
        config: SendConfig,
    ) -> Result<Self, Error> {
        let mut s = pc.rtp_sender(sender).ok_or(Error::NoReceiver)?;
        let ssrc = s
            .ssrcs()
            .next()
            .ok_or_else(|| Error::Engine("the sender has no SSRC".into()))?;
        let codec = s
            .get_parameters()
            .rtp_parameters
            .codecs
            .iter()
            .find(|c| crate::Codec::from_mime_type(&c.rtp_codec.mime_type).is_some())
            .cloned()
            .ok_or_else(|| Error::Engine("no negotiated video codec".into()))?;
        // The connection's packetization (its behaviour profile: VP8 partitions or not).
        let payloader = s
            .payloader(&codec.rtp_codec)
            .map_err(|e| Error::Engine(e.to_string()))?;
        let pipeline = SendPipeline::new(
            factory,
            payloader,
            RtpStreamConfig {
                ssrc,
                payload_type: codec.payload_type,
                first_sequence_number: start.first_sequence_number,
                first_timestamp: start.first_timestamp,
                mtu: DEFAULT_RTP_MTU,
            },
            config,
        );
        Ok(Self {
            sender,
            ssrc,
            pipeline,
            last_target: None,
            key_frame_requests: 0,
            pacer_discards: 0,
        })
    }

    /// The SSRC sent.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The pipeline.
    pub fn pipeline(&mut self) -> &mut SendPipeline {
        &mut self.pipeline
    }

    /// `OnKeyFrameRequest` events for this sender taken (PLI or FIR: the event does not say
    /// which, and both are served the same way), and `OnPacerDiscard` events.
    pub fn events_taken(&self) -> (u32, u32) {
        (self.key_frame_requests, self.pacer_discards)
    }

    /// Takes an event of the peer connection: a key-frame request (`OnKeyFrameRequest`) or a
    /// pacer discard (`OnPacerDiscard`) of this sender asks the pipeline for a key frame.
    /// Returns what became of it; `None` for any other event.
    pub fn handle_event(
        &mut self,
        now: Instant,
        event: &RTCPeerConnectionEvent,
    ) -> Option<KeyFrameDecision> {
        match event {
            RTCPeerConnectionEvent::OnKeyFrameRequest { sender, .. } if *sender == self.sender => {
                self.key_frame_requests += 1;
                Some(self.pipeline.request_key_frame(now, KeyFrameTrigger::Pli))
            }
            RTCPeerConnectionEvent::OnPacerDiscard { sender, .. } if *sender == self.sender => {
                self.pacer_discards += 1;
                Some(
                    self.pipeline
                        .request_key_frame(now, KeyFrameTrigger::PacerDiscard),
                )
            }
            _ => None,
        }
    }

    /// Follows the target the engine gives this stream (`RTCRtpSender::target_bitrates`: the
    /// congestion controller's target less the retransmission reserve, 0 in a pacer pause).
    /// Returns the target when it changed.
    pub fn poll(&mut self, pc: &mut RTCPeerConnection, now: Instant) -> Option<f64> {
        let target = pc
            .rtp_sender(self.sender)?
            .target_bitrates()
            .into_iter()
            .find(|(ssrc, _)| *ssrc == self.ssrc)
            .map(|(_, bps)| bps)?;
        if self.last_target == Some(target) {
            return None;
        }
        self.last_target = Some(target);
        self.pipeline.set_target_bitrate(now, target);
        Some(target)
    }

    /// Encodes `picture` (captured at `capture`) and writes its packets to the sender.
    ///
    /// # Errors
    ///
    /// [`Error::Encode`] from the encoder; [`Error::Engine`] when the sender refuses a packet.
    pub fn send_frame(
        &mut self,
        pc: &mut RTCPeerConnection,
        now: Instant,
        capture: Instant,
        picture: &I420<'_>,
    ) -> Result<FrameOutcome, Error> {
        let outcome = self.pipeline.send_frame(now, capture, picture)?;
        if let FrameOutcome::Sent(frame) = &outcome {
            let mut s = pc.rtp_sender(self.sender).ok_or(Error::NoReceiver)?;
            for packet in &frame.packets {
                s.write_rtp(now, packet.clone())
                    .map_err(|e| Error::Engine(e.to_string()))?;
            }
        }
        Ok(outcome)
    }

    /// Reads the round-trip time of the nominated candidate pair into the pipeline (for the
    /// key-frame rate limit) and hands the encoder statistics to the engine's `getStats()`.
    pub fn update_stats(&mut self, pc: &mut RTCPeerConnection, now: Instant) -> SendStats {
        let rtt = pc
            .get_stats(now, StatsSelector::None)
            .iter()
            .find_map(|entry| match entry {
                RTCStatsReportEntry::IceCandidatePair(pair) if pair.nominated => {
                    pair.current_round_trip_time
                }
                _ => None,
            });
        if let Some(rtt) = rtt.filter(|r| *r > 0.0) {
            self.pipeline.set_rtt(Duration::from_secs_f64(rtt));
        }
        let st = self.pipeline.stats(now);
        pc.update_encoder_stats(
            self.ssrc,
            EncoderStatsUpdate {
                frame_width: st.frame_size.map(|s| s.0),
                frame_height: st.frame_size.map(|s| s.1),
                frames_per_second: Some(st.framerate),
                frames_sent: Some(st.frames_encoded),
                frames_encoded: Some(st.frames_encoded),
                key_frames_encoded: Some(st.key_frames_encoded),
                qp_sum: st.qp_sum,
                target_bitrate: st.target_bitrate,
                quality_limitation_reason: Some(if st.quality_limited {
                    RTCQualityLimitationReason::Bandwidth
                } else {
                    RTCQualityLimitationReason::None
                }),
                quality_limitation_durations: Some(QualityLimitationDurations {
                    none: st.quality_limitation_none,
                    bandwidth: st.quality_limitation_bandwidth,
                    ..Default::default()
                }),
                quality_limitation_resolution_changes: Some(
                    st.quality_limitation_resolution_changes,
                ),
                encoder_implementation: st.encoder_implementation.clone(),
                ..Default::default()
            },
        );
        st
    }
}

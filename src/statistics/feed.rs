//! Statistics the engine cannot measure, supplied by the application.
//!
//! The engine is a transport. It counts packets, bytes, RTCP feedback and round trips; it never
//! encodes, decodes, captures or plays out media. The W3C members that describe those stages are
//! left out of [`get_stats`](RTCPeerConnection::get_stats) reports (webrtc-stats: a member the
//! implementation cannot measure is not present) until the application, which does that work,
//! supplies them here.
//!
//! Every update type has only `Option` fields, and an update is merged into what was supplied
//! before: a field left `None` keeps its previous value. So an application whose frame
//! assembler counts frames can send just the frame counts, and its decoder the rest.
//!
//! # Examples
//!
//! ```
//! use rtc::peer_connection::RTCPeerConnection;
//! use rtc::statistics::DecoderStatsUpdate;
//!
//! # fn example(pc: &mut RTCPeerConnection, ssrc: u32) {
//! // The frame assembler completed a frame made of 3 packets in 2 ms.
//! pc.update_decoder_stats(
//!     ssrc,
//!     DecoderStatsUpdate {
//!         frames_received: Some(1),
//!         frames_assembled_from_multiple_packets: Some(1),
//!         total_assembly_time: Some(0.002),
//!         ..Default::default()
//!     },
//! );
//! # }
//! ```

use crate::peer_connection::RTCPeerConnection;
use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
use crate::rtp_transceiver::{RTCRtpSenderId, SSRC};
use crate::statistics::accumulator::{
    AudioPlayoutStatsUpdate, AudioReceiverStatsUpdate, AudioSourceStatsUpdate, DecoderStatsUpdate,
    EncoderStatsUpdate, VideoSourceStatsUpdate,
};

impl RTCPeerConnection {
    /// Supplies receive-side video statistics for the inbound RTP stream `ssrc`: what the frame
    /// assembler, the decoder and the renderer measured (`framesReceived`, `framesDecoded`,
    /// `frameWidth`, `totalDecodeTime`, `freezeCount`, ...).
    ///
    /// Merged into what was supplied before. Returns `false`, and changes nothing, when no
    /// inbound stream has that SSRC (it has not received a packet yet, or has gone).
    pub fn update_decoder_stats(&mut self, ssrc: SSRC, update: DecoderStatsUpdate) -> bool {
        self.stats_mut().update_decoder_stats(ssrc, update)
    }

    /// Supplies receive-side audio and jitter buffer statistics for the inbound RTP stream
    /// `ssrc` (`totalSamplesReceived`, `concealedSamples`, `audioLevel`, `jitterBufferDelay`,
    /// ...).
    ///
    /// Merged into what was supplied before. Returns `false`, and changes nothing, when no
    /// inbound stream has that SSRC.
    pub fn update_audio_receiver_stats(
        &mut self,
        ssrc: SSRC,
        update: AudioReceiverStatsUpdate,
    ) -> bool {
        self.stats_mut().update_audio_receiver_stats(ssrc, update)
    }

    /// Supplies send-side statistics for the outbound RTP stream `ssrc`: what the encoder
    /// measured (`framesEncoded`, `framesSent`, `frameWidth`, `qpSum`, `encoderImplementation`,
    /// `qualityLimitationReason`, ...).
    ///
    /// Merged into what was supplied before. Returns `false`, and changes nothing, when no
    /// outbound stream has that SSRC (it is created when the sender starts after negotiation).
    pub fn update_encoder_stats(&mut self, ssrc: SSRC, update: EncoderStatsUpdate) -> bool {
        self.stats_mut().update_encoder_stats(ssrc, update)
    }

    /// Supplies capture statistics for the audio track `sender` sends: its `media-source` stats
    /// object (`audioLevel`, `totalAudioEnergy`, `echoReturnLoss`, ...), created on the first
    /// update and named by the sender's outbound streams as their `mediaSourceId`.
    ///
    /// Merged into what was supplied before. Returns `false`, and changes nothing, when there
    /// is no such sender or it does not send an audio track.
    pub fn update_audio_source_stats(
        &mut self,
        sender: RTCRtpSenderId,
        update: AudioSourceStatsUpdate,
    ) -> bool {
        match self.sender_track_for_stats(sender) {
            Some((transceiver_id, track_id, RtpCodecKind::Audio)) => {
                self.stats_mut()
                    .update_audio_source_stats(&track_id, transceiver_id, update);
                true
            }
            _ => false,
        }
    }

    /// Supplies capture statistics for the video track `sender` sends: its `media-source` stats
    /// object (`width`, `height`, `frames`, `framesPerSecond`), created on the first update and
    /// named by the sender's outbound streams as their `mediaSourceId`.
    ///
    /// Merged into what was supplied before. Returns `false`, and changes nothing, when there
    /// is no such sender or it does not send a video track.
    pub fn update_video_source_stats(
        &mut self,
        sender: RTCRtpSenderId,
        update: VideoSourceStatsUpdate,
    ) -> bool {
        match self.sender_track_for_stats(sender) {
            Some((transceiver_id, track_id, RtpCodecKind::Video)) => {
                self.stats_mut()
                    .update_video_source_stats(&track_id, transceiver_id, update);
                true
            }
            _ => false,
        }
    }

    /// Supplies audio playout statistics for the playout device the application names
    /// `playout_id`: its `media-playout` stats object (`synthesizedSamplesDuration`,
    /// `totalPlayoutDelay`, ...), created on the first update, which each inbound stream in
    /// `inbound_ssrcs` then names as its `playoutId`.
    ///
    /// `playout_id` is the stats object's id as the report gives it. Merged into what was
    /// supplied before.
    pub fn update_audio_playout_stats(
        &mut self,
        playout_id: &str,
        inbound_ssrcs: &[SSRC],
        update: AudioPlayoutStatsUpdate,
    ) {
        self.stats_mut()
            .update_audio_playout_stats(playout_id, inbound_ssrcs, update);
    }
}

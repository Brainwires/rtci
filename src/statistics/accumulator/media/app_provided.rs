//! Application-provided statistics update types.
//!
//! The engine is a transport: it never encodes, decodes, captures or plays out media, so the
//! W3C members that describe those stages are unknown to it. These types are how an application
//! that does that work hands its measurements over, through the `update_*_stats` methods of
//! [`RTCPeerConnection`](crate::peer_connection::RTCPeerConnection). Until a member has been
//! supplied it is `None` in the report and left out of the JSON (webrtc-stats: a member the
//! implementation cannot measure is not present).
//!
//! Every field is an `Option`, and an update is merged into what was supplied before: a field
//! left `None` keeps its previous value. An application that counts only frames can therefore
//! send only frame counts, and a decoder elsewhere can send the rest.

/// Copies every field that is `Some` in `update` onto `self`.
macro_rules! merge_fields {
    ($self:ident, $update:ident; $($field:ident),+ $(,)?) => {
        $(
            if $update.$field.is_some() {
                $self.$field = $update.$field;
            }
        )+
    };
}

/// Video receive-side statistics provided by the application: the frame assembler, the decoder
/// and the renderer (webrtc-stats `RTCInboundRtpStreamStats`, video members).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DecoderStatsUpdate {
    /// Complete frames received (`framesReceived`).
    pub frames_received: Option<u32>,
    /// Frames assembled from more than one RTP packet (`framesAssembledFromMultiplePackets`).
    pub frames_assembled_from_multiple_packets: Option<u32>,
    /// Total time spent assembling those frames, in seconds (`totalAssemblyTime`).
    pub total_assembly_time: Option<f64>,
    /// Frames dropped before decoding (`framesDropped`).
    pub frames_dropped: Option<u32>,
    /// Decoded frames per second over the last second (`framesPerSecond`).
    pub frames_per_second: Option<f64>,
    /// Total frames decoded (`framesDecoded`).
    pub frames_decoded: Option<u32>,
    /// Key frames decoded (`keyFramesDecoded`).
    pub key_frames_decoded: Option<u32>,
    /// Frames rendered (`framesRendered`).
    pub frames_rendered: Option<u32>,
    /// Width of the last decoded frame (`frameWidth`).
    pub frame_width: Option<u32>,
    /// Height of the last decoded frame (`frameHeight`).
    pub frame_height: Option<u32>,
    /// Sum of the QP values of decoded frames (`qpSum`).
    pub qp_sum: Option<u64>,
    /// Total time spent decoding, in seconds (`totalDecodeTime`).
    pub total_decode_time: Option<f64>,
    /// Sum of inter-frame delays, in seconds (`totalInterFrameDelay`).
    pub total_inter_frame_delay: Option<f64>,
    /// Sum of squared inter-frame delays (`totalSquaredInterFrameDelay`).
    pub total_squared_inter_frame_delay: Option<f64>,
    /// Total time from first packet to decoded frame, in seconds (`totalProcessingDelay`).
    pub total_processing_delay: Option<f64>,
    /// Number of pauses (`pauseCount`).
    pub pause_count: Option<u32>,
    /// Total duration of pauses, in seconds (`totalPausesDuration`).
    pub total_pauses_duration: Option<f64>,
    /// Number of freezes (`freezeCount`).
    pub freeze_count: Option<u32>,
    /// Total duration of freezes, in seconds (`totalFreezesDuration`).
    pub total_freezes_duration: Option<f64>,
    /// Packets the jitter buffer discarded (`packetsDiscarded`).
    pub packets_discarded: Option<u64>,
    /// Name of the decoder implementation (`decoderImplementation`).
    pub decoder_implementation: Option<String>,
    /// Whether the decoder is power efficient (`powerEfficientDecoder`).
    pub power_efficient_decoder: Option<bool>,
    /// Sum of the corruption probability measurements, each in 0.0..=1.0
    /// (`totalCorruptionProbability`).
    pub total_corruption_probability: Option<f64>,
    /// Sum of the squares of those measurements (`totalSquaredCorruptionProbability`).
    pub total_squared_corruption_probability: Option<f64>,
    /// Number of corruption probability measurements (`corruptionMeasurements`).
    pub corruption_measurements: Option<u64>,
    /// Cumulative jitter buffer delay, in seconds (`jitterBufferDelay`): for each frame, from
    /// its first packet's arrival to its exit from the jitter buffer. Takes precedence over
    /// the same member of [`AudioReceiverStatsUpdate`] for the stream.
    pub jitter_buffer_delay: Option<f64>,
    /// Cumulative jitter buffer target delay, in seconds (`jitterBufferTargetDelay`).
    pub jitter_buffer_target_delay: Option<f64>,
    /// Cumulative jitter buffer minimum delay, in seconds (`jitterBufferMinimumDelay`).
    pub jitter_buffer_minimum_delay: Option<f64>,
    /// Frames emitted from the jitter buffer (`jitterBufferEmittedCount`).
    pub jitter_buffer_emitted_count: Option<u64>,
}

impl DecoderStatsUpdate {
    /// Merges `update` into `self`: a field that is `Some` in `update` replaces the old value.
    pub(crate) fn merge(&mut self, update: DecoderStatsUpdate) {
        merge_fields!(self, update;
            frames_received,
            frames_assembled_from_multiple_packets,
            total_assembly_time,
            frames_dropped,
            frames_per_second,
            frames_decoded,
            key_frames_decoded,
            frames_rendered,
            frame_width,
            frame_height,
            qp_sum,
            total_decode_time,
            total_inter_frame_delay,
            total_squared_inter_frame_delay,
            total_processing_delay,
            pause_count,
            total_pauses_duration,
            freeze_count,
            total_freezes_duration,
            packets_discarded,
            total_corruption_probability,
            total_squared_corruption_probability,
            corruption_measurements,
            jitter_buffer_delay,
            jitter_buffer_target_delay,
            jitter_buffer_minimum_delay,
            jitter_buffer_emitted_count,
        );
        if update.decoder_implementation.is_some() {
            self.decoder_implementation = update.decoder_implementation;
        }
        if update.power_efficient_decoder.is_some() {
            self.power_efficient_decoder = update.power_efficient_decoder;
        }
    }
}

/// The cumulative PSNR of the frames an encoder produced, per colour component (webrtc-stats
/// `RTCOutboundRtpStreamStats.psnrSum`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PsnrSum {
    /// Sum of the luma PSNR values, in dB.
    pub y: f64,
    /// Sum of the first chroma component's PSNR values, in dB.
    pub u: f64,
    /// Sum of the second chroma component's PSNR values, in dB.
    pub v: f64,
}

/// The time a stream has spent in each quality limitation state, in seconds (webrtc-stats
/// `RTCOutboundRtpStreamStats.qualityLimitationDurations`: a record with an entry for every
/// `RTCQualityLimitationReason`, "none" included).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct QualityLimitationDurations {
    /// Seconds not limited.
    pub none: f64,
    /// Seconds limited by CPU.
    pub cpu: f64,
    /// Seconds limited by bandwidth.
    pub bandwidth: f64,
    /// Seconds limited for another reason.
    pub other: f64,
}

/// Send-side statistics provided by the application: the encoder (webrtc-stats
/// `RTCOutboundRtpStreamStats`, encoder members).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EncoderStatsUpdate {
    /// Width of the last encoded frame (`frameWidth`).
    pub frame_width: Option<u32>,
    /// Height of the last encoded frame (`frameHeight`).
    pub frame_height: Option<u32>,
    /// Encoded frames per second over the last second (`framesPerSecond`).
    pub frames_per_second: Option<f64>,
    /// Frames sent (`framesSent`).
    pub frames_sent: Option<u32>,
    /// Huge frames sent (`hugeFramesSent`).
    pub huge_frames_sent: Option<u32>,
    /// Total frames encoded (`framesEncoded`).
    pub frames_encoded: Option<u32>,
    /// Key frames encoded (`keyFramesEncoded`).
    pub key_frames_encoded: Option<u32>,
    /// Sum of the QP values of encoded frames (`qpSum`).
    pub qp_sum: Option<u64>,
    /// Total time spent encoding, in seconds (`totalEncodeTime`).
    pub total_encode_time: Option<f64>,
    /// The cumulative PSNR of the encoded frames (`psnrSum`).
    pub psnr_sum: Option<PsnrSum>,
    /// Number of frames `psnr_sum` covers (`psnrMeasurements`).
    pub psnr_measurements: Option<u64>,
    /// The encoder's current target for this stream, in bits per second (`targetBitrate`).
    /// Without it the report gives the congestion controller's estimate, and only while the
    /// connection sends a single stream: how an estimate is shared between several is the
    /// encoder's decision.
    pub target_bitrate: Option<f64>,
    /// The current quality limitation reason (`qualityLimitationReason`).
    pub quality_limitation_reason: Option<crate::statistics::stats::RTCQualityLimitationReason>,
    /// Time spent in each quality limitation state (`qualityLimitationDurations`).
    pub quality_limitation_durations: Option<QualityLimitationDurations>,
    /// Resolution changes made for quality limitation (`qualityLimitationResolutionChanges`).
    pub quality_limitation_resolution_changes: Option<u32>,
    /// Name of the encoder implementation (`encoderImplementation`).
    pub encoder_implementation: Option<String>,
    /// Whether the encoder is power efficient (`powerEfficientEncoder`).
    pub power_efficient_encoder: Option<bool>,
    /// Scalability mode, e.g. "L1T3" (`scalabilityMode`).
    pub scalability_mode: Option<String>,
}

impl EncoderStatsUpdate {
    /// Merges `update` into `self`: a field that is `Some` in `update` replaces the old value.
    pub(crate) fn merge(&mut self, update: EncoderStatsUpdate) {
        merge_fields!(self, update;
            frame_width,
            frame_height,
            frames_per_second,
            frames_sent,
            huge_frames_sent,
            frames_encoded,
            key_frames_encoded,
            qp_sum,
            total_encode_time,
            psnr_sum,
            psnr_measurements,
            target_bitrate,
            quality_limitation_reason,
            quality_limitation_durations,
            quality_limitation_resolution_changes,
            power_efficient_encoder,
        );
        if update.encoder_implementation.is_some() {
            self.encoder_implementation = update.encoder_implementation;
        }
        if update.scalability_mode.is_some() {
            self.scalability_mode = update.scalability_mode;
        }
    }
}

/// Audio receive-side statistics provided by the application: the jitter buffer, the decoder
/// and concealment (webrtc-stats `RTCInboundRtpStreamStats`, audio members; the jitter buffer,
/// playout position and FEC members apply to video too).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AudioReceiverStatsUpdate {
    /// Total audio samples received (`totalSamplesReceived`).
    pub total_samples_received: Option<u64>,
    /// Samples concealed (`concealedSamples`).
    pub concealed_samples: Option<u64>,
    /// Silent samples concealed (`silentConcealedSamples`).
    pub silent_concealed_samples: Option<u64>,
    /// Concealment events (`concealmentEvents`).
    pub concealment_events: Option<u64>,
    /// Samples inserted to slow playout down (`insertedSamplesForDeceleration`).
    pub inserted_samples_for_deceleration: Option<u64>,
    /// Samples removed to speed playout up (`removedSamplesForAcceleration`).
    pub removed_samples_for_acceleration: Option<u64>,
    /// Audio level, 0.0 to 1.0 (`audioLevel`).
    pub audio_level: Option<f64>,
    /// Total audio energy (`totalAudioEnergy`).
    pub total_audio_energy: Option<f64>,
    /// Total duration of received samples, in seconds (`totalSamplesDuration`).
    pub total_samples_duration: Option<f64>,
    /// Cumulative jitter buffer delay, in seconds (`jitterBufferDelay`).
    pub jitter_buffer_delay: Option<f64>,
    /// Cumulative jitter buffer target delay, in seconds (`jitterBufferTargetDelay`).
    pub jitter_buffer_target_delay: Option<f64>,
    /// Cumulative jitter buffer minimum delay, in seconds (`jitterBufferMinimumDelay`).
    pub jitter_buffer_minimum_delay: Option<f64>,
    /// Samples or frames emitted from the jitter buffer (`jitterBufferEmittedCount`).
    pub jitter_buffer_emitted_count: Option<u64>,
    /// The track's playout position on the sender's clock, as time since the Unix epoch: the
    /// NTP time of the last playable sample or frame, extrapolated with the time since it was
    /// ready to play (`estimatedPlayoutTimestamp`).
    pub estimated_playout_timestamp: Option<std::time::Duration>,
    /// FEC packets whose correction was not used: everything they protect had arrived or was
    /// already recovered, or they came too late (`fecPacketsDiscarded`).
    pub fec_packets_discarded: Option<u64>,
    /// FEC packets found inside the stream's own packets (in-band FEC, as Opus carries it),
    /// which only the decoder sees; added to the `fecPacketsReceived` the engine counts on a
    /// FEC SSRC.
    pub in_band_fec_packets_received: Option<u64>,
    /// The bytes of that in-band FEC, added to `fecBytesReceived`.
    pub in_band_fec_bytes_received: Option<u64>,
}

impl AudioReceiverStatsUpdate {
    /// Merges `update` into `self`: a field that is `Some` in `update` replaces the old value.
    pub(crate) fn merge(&mut self, update: AudioReceiverStatsUpdate) {
        merge_fields!(self, update;
            total_samples_received,
            concealed_samples,
            silent_concealed_samples,
            concealment_events,
            inserted_samples_for_deceleration,
            removed_samples_for_acceleration,
            audio_level,
            total_audio_energy,
            total_samples_duration,
            jitter_buffer_delay,
            jitter_buffer_target_delay,
            jitter_buffer_minimum_delay,
            jitter_buffer_emitted_count,
            estimated_playout_timestamp,
            fec_packets_discarded,
            in_band_fec_packets_received,
            in_band_fec_bytes_received,
        );
    }
}

/// Audio capture statistics provided by the application (webrtc-stats `RTCAudioSourceStats`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AudioSourceStatsUpdate {
    /// Audio level, 0.0 to 1.0 (`audioLevel`).
    pub audio_level: Option<f64>,
    /// Total audio energy (`totalAudioEnergy`).
    pub total_audio_energy: Option<f64>,
    /// Total duration of captured samples, in seconds (`totalSamplesDuration`).
    pub total_samples_duration: Option<f64>,
    /// Echo return loss in decibels (`echoReturnLoss`).
    pub echo_return_loss: Option<f64>,
    /// Echo return loss enhancement in decibels (`echoReturnLossEnhancement`).
    pub echo_return_loss_enhancement: Option<f64>,
}

/// Video capture statistics provided by the application (webrtc-stats `RTCVideoSourceStats`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoSourceStatsUpdate {
    /// Width of the last captured frame (`width`).
    pub width: Option<u32>,
    /// Height of the last captured frame (`height`).
    pub height: Option<u32>,
    /// Total frames captured (`frames`).
    pub frames: Option<u32>,
    /// Captured frames per second over the last second (`framesPerSecond`).
    pub frames_per_second: Option<f64>,
}

/// Audio playout statistics provided by the application (webrtc-stats `RTCAudioPlayoutStats`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AudioPlayoutStatsUpdate {
    /// Duration of synthesized samples, in seconds (`synthesizedSamplesDuration`).
    pub synthesized_samples_duration: Option<f64>,
    /// Number of synthesis events (`synthesizedSamplesEvents`).
    pub synthesized_samples_events: Option<u32>,
    /// Total duration of samples played, in seconds (`totalSamplesDuration`).
    pub total_samples_duration: Option<f64>,
    /// Total playout delay, in seconds (`totalPlayoutDelay`).
    pub total_playout_delay: Option<f64>,
    /// Total samples played (`totalSamplesCount`).
    pub total_samples_count: Option<u64>,
}

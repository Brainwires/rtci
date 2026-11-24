//! The glue between the pipelines and the `rtci` peer connection (feature `engine`).
//!
//! - [`AudioSender`] binds a [`SendPipeline`] to an `RTCRtpSender`: it configures the encoder
//!   from what negotiation chose (the codec, the remote side's Opus parameters and
//!   `a=ptime` / `a=maxptime`), packetizes with the engine's payloaders (Opus, G.711 / G.722,
//!   CN), writes each packet with its RFC 6464 audio level
//!   (`RTCRtpSender::write_rtp_with_audio_level`), optionally wrapped in RED (RFC 2198), and
//!   follows the congestion controller's share for the sender
//!   (`RTCRtpSender::target_bitrates`) and the loss the receiver reports in RTCP
//!   (`AudioSender::update_network`, from the engine's `remote-inbound-rtp` statistics).
//! - [`AudioReceiver`] binds a [`JitterBuffer`] to an `RTCRtpReceiver`: it registers a
//!   decoder for every negotiated audio format, takes the RTP packets `poll_read` hands the
//!   application for the receiver's track, follows the receiver's `jitterBufferTarget`, and
//!   feeds the buffer's statistics into the engine's `getStats()`.
//!
//! DTMF is sent with the engine's own `RTCRtpSender::dtmf()` (`insertDTMF`), which numbers
//! its event packets in the same stream; received events come out of
//! [`AudioReceiver::poll_event`].
//!
//! Neither type holds the peer connection: each call that needs it takes it, so the
//! application keeps its own event loop.

use std::time::Instant;

use rtci::media_stream::MediaStreamTrackId;
use rtci::peer_connection::RTCPeerConnection;
use rtci::peer_connection::configuration::media_engine::{
    MIME_TYPE_CN, MIME_TYPE_G722, MIME_TYPE_OPUS, MIME_TYPE_PCMA, MIME_TYPE_PCMU,
    MIME_TYPE_TELEPHONE_EVENT,
};
use rtci::rtp::packetizer::{Packetizer, new_packetizer};
use rtci::rtp_transceiver::rtp_sender::RTCRtpCodecParameters;
use rtci::rtp_transceiver::{RTCRtpReceiverId, RTCRtpSenderId, RTCRtpTransceiverId};
use rtci::statistics::{AudioReceiverStatsUpdate, AudioSourceStatsUpdate, EncoderStatsUpdate};

use crate::codec::fmtp::{OpusContent, OpusEncoderConfig, OpusFmtp};
use crate::codec::g711::{G711Decoder, Law};
use crate::codec::g722::G722Decoder;
use crate::frame::AudioFrame;
use crate::jitter::{JitterBuffer, JitterBufferConfig, ReceiveEvent, ReceiveStats};
use crate::processing::ProcessingConfig;
use crate::send::{PayloadKind, SendCodec, SendConfig, SendOutput, SendPipeline};
use crate::{Error, Result};

/// The MIME type of redundant audio (RFC 2198 section 5).
pub const MIME_TYPE_RED: &str = "audio/red";
/// The RTP MTU the sender packetizes for.
const MTU: usize = 1200;

fn engine(e: impl std::fmt::Display) -> Error {
    Error::Engine(e.to_string())
}

/// How an [`AudioSender`] is set up beyond what negotiation decided.
#[derive(Debug, Clone, PartialEq)]
pub struct AudioSenderOptions {
    /// The capture's rate.
    pub capture_rate: u32,
    /// The capture's channels.
    pub capture_channels: u16,
    /// The processing stages.
    pub processing: ProcessingConfig,
    /// Wrap packets in RED with one redundant copy, when `audio/red` was negotiated.
    pub red: bool,
    /// Use libopus for Opus (feature `libopus`).
    pub prefer_libopus: bool,
    /// What the stream carries, for the Opus ceiling when the receiver states no
    /// `maxaveragebitrate` (RFC 7587 section 6.1's default: 40 kbit/s for full-band speech,
    /// 64 for mono music, 128 for stereo music).
    pub content: OpusContent,
    /// An Opus ceiling of the application's (bits per second) in place of that default. It
    /// never raises the receiver's `maxaveragebitrate` (RFC 7587 section 7.1: the sender
    /// "MUST NOT send with an average bitrate higher").
    pub max_bitrate: Option<u32>,
}

impl Default for AudioSenderOptions {
    fn default() -> Self {
        Self {
            capture_rate: 48_000,
            capture_channels: 1,
            processing: ProcessingConfig::CALL,
            red: false,
            prefer_libopus: false,
            content: OpusContent::Speech,
            max_bitrate: None,
        }
    }
}

/// A send pipeline writing to an `RTCRtpSender`.
pub struct AudioSender {
    sender: RTCRtpSenderId,
    ssrc: u32,
    codec: RTCRtpCodecParameters,
    cn_payload_type: Option<u8>,
    red_payload_type: Option<u8>,
    red: Option<rtci::rtp::codec::red::RedEncoder>,
    packetizer: Box<dyn Packetizer>,
    pipeline: SendPipeline,
    packets_sent: u64,
    last_report: Option<(u64, u64)>,
}

impl std::fmt::Debug for AudioSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioSender")
            .field("ssrc", &self.ssrc)
            .field("codec", &self.codec.rtp_codec.mime_type)
            .field("pipeline", &self.pipeline)
            .finish()
    }
}

fn find_codec<'a>(
    codecs: &'a [RTCRtpCodecParameters],
    mime: &str,
) -> Option<&'a RTCRtpCodecParameters> {
    codecs
        .iter()
        .find(|c| c.rtp_codec.mime_type.eq_ignore_ascii_case(mime))
}

impl AudioSender {
    /// Binds a pipeline to `sender` after negotiation: the first negotiated codec this crate
    /// encodes is used, set up from the remote side's parameters.
    ///
    /// # Errors
    ///
    /// [`Error::Engine`] when the sender is gone or has no SSRC yet;
    /// [`Error::Unsupported`] when no negotiated codec is one this crate encodes.
    pub fn new(
        pc: &mut RTCPeerConnection,
        sender: RTCRtpSenderId,
        now: Instant,
        options: AudioSenderOptions,
    ) -> Result<Self> {
        let transceiver: RTCRtpTransceiverId = sender.into();
        let packet_time = pc
            .rtp_transceiver(transceiver)
            .map(|t| t.remote_packet_time())
            .ok_or_else(|| engine("no such transceiver"))?;
        let mut s = pc
            .rtp_sender(sender)
            .ok_or_else(|| engine("no such sender"))?;
        let params = s.get_parameters().clone();
        let ssrc = params
            .encodings
            .first()
            .and_then(|e| e.rtp_coding_parameters.ssrc)
            .ok_or_else(|| engine("the sender has no SSRC"))?;
        let codecs = &params.rtp_parameters.codecs;
        let codec = codecs
            .iter()
            .find(|c| {
                [
                    MIME_TYPE_OPUS,
                    MIME_TYPE_PCMU,
                    MIME_TYPE_PCMA,
                    MIME_TYPE_G722,
                ]
                .iter()
                .any(|m| c.rtp_codec.mime_type.eq_ignore_ascii_case(m))
            })
            .cloned()
            .ok_or_else(|| Error::Unsupported("no negotiated audio codec to encode".into()))?;
        let ptime = packet_time.ptime.unwrap_or(20).clamp(10, 120);
        let mime = codec.rtp_codec.mime_type.to_ascii_lowercase();
        let remote = OpusFmtp::parse(&codec.rtp_codec.sdp_fmtp_line);
        let (send_codec, payloader): (SendCodec, Box<dyn rtci::rtp::packetizer::Payloader>) =
            if mime == MIME_TYPE_OPUS.to_ascii_lowercase() {
                let mut config = OpusEncoderConfig::for_remote_content(
                    &remote,
                    packet_time.ptime,
                    packet_time.maxptime,
                    options.capture_channels,
                    options.content,
                );
                if let Some(ceiling) = options.max_bitrate {
                    let ceiling = remote
                        .max_average_bitrate
                        .map_or(ceiling, |stated| stated.min(ceiling))
                        .clamp(6000, 510_000);
                    config.max_bitrate = ceiling;
                    config.bitrate = config.bitrate.min(ceiling);
                }
                (
                    SendCodec::Opus(config),
                    Box::new(rtci::rtp::codec::opus::OpusPayloader),
                )
            } else if mime == MIME_TYPE_PCMU.to_ascii_lowercase() {
                (
                    SendCodec::Pcmu(ptime),
                    Box::new(rtci::rtp::codec::g7xx::G711Payloader::default()),
                )
            } else if mime == MIME_TYPE_PCMA.to_ascii_lowercase() {
                (
                    SendCodec::Pcma(ptime),
                    Box::new(rtci::rtp::codec::g7xx::G711Payloader::default()),
                )
            } else {
                (
                    SendCodec::G722(ptime),
                    Box::new(rtci::rtp::codec::g7xx::G722Payloader::default()),
                )
            };
        // RFC 3389 comfort noise for the codecs without DTX of their own, on the codec's clock
        // (RFC 7874 section 3: not with Opus).
        let cn_payload_type = (mime != MIME_TYPE_OPUS.to_ascii_lowercase())
            .then(|| find_codec(codecs, MIME_TYPE_CN))
            .flatten()
            .filter(|c| c.rtp_codec.clock_rate == codec.rtp_codec.clock_rate)
            .map(|c| c.payload_type);
        let red_payload_type = options
            .red
            .then(|| find_codec(codecs, MIME_TYPE_RED).map(|c| c.payload_type))
            .flatten();
        let fec_allowed = matches!(send_codec, SendCodec::Opus(_)) && remote.use_inband_fec;
        let pipeline = SendPipeline::new(SendConfig {
            codec: send_codec,
            capture_rate: options.capture_rate,
            capture_channels: options.capture_channels,
            processing: options.processing,
            comfort_noise: cn_payload_type.is_some(),
            fec_allowed,
            prefer_libopus: options.prefer_libopus,
            ..Default::default()
        })?;
        // The congestion controller's share is an upper bound for audio, never a target: what
        // the encoder cannot use goes to the other senders (libwebrtc clamps an audio stream's
        // allocation to its encoder's range, `AudioSendStream::OnBitrateUpdated`).
        pc.rtp_sender(sender)
            .ok_or_else(|| engine("no such sender"))?
            .set_encoder_max_bitrate(ssrc, Some(pipeline.max_allocation_bps()));
        let packetizer = new_packetizer(
            now,
            MTU,
            codec.payload_type,
            ssrc,
            payloader,
            Box::new(rtci::rtp::sequence::new_random_sequencer()),
            pipeline.rtp_clock_rate(),
        );
        Ok(Self {
            sender,
            ssrc,
            codec,
            cn_payload_type,
            red: red_payload_type.map(|_| rtci::rtp::codec::red::RedEncoder::new(1, MTU)),
            red_payload_type,
            packetizer: Box::new(packetizer),
            pipeline,
            packets_sent: 0,
            last_report: None,
        })
    }

    /// The SSRC the sender sends with.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// The codec in use (the negotiated entry: the remote payload type and fmtp line).
    pub fn codec(&self) -> &RTCRtpCodecParameters {
        &self.codec
    }

    /// The send pipeline.
    pub fn pipeline(&self) -> &SendPipeline {
        &self.pipeline
    }

    /// RTP packets written.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent
    }

    /// Takes audio about to be played locally (the echo canceller's reference).
    pub fn push_render(&mut self, frame: &AudioFrame) {
        self.pipeline.push_render(frame);
    }

    /// Takes captured audio and writes what it becomes to the sender. Returns the packets
    /// written.
    ///
    /// # Errors
    ///
    /// A pipeline error, or the engine's refusal to send (the sender stopped).
    pub fn push_capture(
        &mut self,
        pc: &mut RTCPeerConnection,
        now: Instant,
        frame: &AudioFrame,
    ) -> Result<usize> {
        let outputs = self.pipeline.push_capture(frame)?;
        let mut written = 0;
        for out in outputs {
            match out {
                SendOutput::Skip { rtp_duration } => self.packetizer.skip_samples(rtp_duration),
                SendOutput::Packet {
                    payload,
                    kind,
                    rtp_duration,
                    audio_level,
                    voice,
                } => {
                    let mut packets = self
                        .packetizer
                        .packetize(now, &payload, rtp_duration)
                        .map_err(engine)?;
                    for p in &mut packets {
                        match kind {
                            PayloadKind::ComfortNoise => {
                                if let Some(pt) = self.cn_payload_type {
                                    p.header.payload_type = pt;
                                }
                                // RFC 3389 section 4: CN packets do not set the marker.
                                p.header.marker = false;
                            }
                            PayloadKind::Media => {
                                if let (Some(red), Some(red_pt)) =
                                    (self.red.as_mut(), self.red_payload_type)
                                {
                                    p.payload = red
                                        .encode(
                                            self.codec.payload_type,
                                            p.header.timestamp,
                                            p.payload.clone(),
                                        )
                                        .map_err(engine)?;
                                    p.header.payload_type = red_pt;
                                }
                            }
                        }
                    }
                    let level = crate::dsp::level::linear_from_rfc6464(audio_level);
                    let mut sender = pc
                        .rtp_sender(self.sender)
                        .ok_or_else(|| engine("no such sender"))?;
                    for p in packets {
                        sender
                            .write_rtp_with_audio_level(now, p, level, Some(voice))
                            .map_err(engine)?;
                        written += 1;
                    }
                }
            }
        }
        self.packets_sent += written as u64;
        Ok(written)
    }

    /// Follows the congestion controller: the sender's share of its target, if it set one.
    pub fn update_bitrate(&mut self, pc: &mut RTCPeerConnection) {
        let Some(sender) = pc.rtp_sender(self.sender) else {
            return;
        };
        if let Some((_, bps)) = sender
            .target_bitrates()
            .into_iter()
            .find(|(ssrc, _)| *ssrc == self.ssrc)
        {
            self.pipeline.set_target_bitrate(bps);
        }
    }

    /// Follows the network: the congestion controller's share
    /// ([`update_bitrate`](Self::update_bitrate)) and the loss the receiver last reported,
    /// read from the engine's `remote-inbound-rtp` statistics for the sender's SSRC (the
    /// reception reports' fraction lost, RFC 3550 section 6.4.1), which turns FEC on and
    /// off. Call it every few hundred milliseconds.
    pub fn update_network(&mut self, pc: &mut RTCPeerConnection, now: Instant) {
        self.update_bitrate(pc);
        let report = pc.get_stats(now, rtci::statistics::StatsSelector::None);
        for entry in report.iter() {
            if let rtci::statistics::report::RTCStatsReportEntry::RemoteInboundRtp(r) = entry
                && r.received_rtp_stream_stats.rtp_stream_stats.ssrc == self.ssrc
            {
                // A new report changes what it says was received.
                let key = (
                    r.received_rtp_stream_stats.packets_received,
                    r.round_trip_time_measurements,
                );
                if self.last_report != Some(key) {
                    self.last_report = Some(key);
                    self.pipeline.on_packet_loss(r.fraction_lost as f32);
                }
            }
        }
    }

    /// Takes the RTCP packets `poll_read` delivered for the sender's track: the reception
    /// reports about this stream set the loss the encoder protects against.
    pub fn handle_rtcp(&mut self, packets: &[Box<dyn rtci::rtcp::Packet>]) {
        for p in packets {
            let any = p.as_any();
            let reports = if let Some(rr) =
                any.downcast_ref::<rtci::rtcp::receiver_report::ReceiverReport>()
            {
                &rr.reports
            } else if let Some(sr) = any.downcast_ref::<rtci::rtcp::sender_report::SenderReport>() {
                &sr.reports
            } else {
                continue;
            };
            for r in reports.iter().filter(|r| r.ssrc == self.ssrc) {
                self.pipeline
                    .on_packet_loss(f32::from(r.fraction_lost) / 256.0);
            }
        }
    }

    /// Hands the capture and encoder statistics to the engine's `getStats()`.
    pub fn update_stats(&self, pc: &mut RTCPeerConnection) {
        let level = self.pipeline.source_level();
        let processing = self.pipeline.processing_stats();
        pc.update_audio_source_stats(
            self.sender,
            AudioSourceStatsUpdate {
                audio_level: Some(level.audio_level()),
                total_audio_energy: Some(level.total_audio_energy()),
                total_samples_duration: Some(level.total_samples_duration()),
                echo_return_loss: processing.echo_return_loss,
                echo_return_loss_enhancement: processing.echo_return_loss_enhancement,
            },
        );
        pc.update_encoder_stats(
            self.ssrc,
            EncoderStatsUpdate {
                encoder_implementation: Some(self.pipeline.encoder_name().to_owned()),
                target_bitrate: self.pipeline.stats().target_bitrate.map(f64::from),
                ..Default::default()
            },
        );
    }
}

/// How an [`AudioReceiver`] decodes Opus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OpusBackend {
    /// opus-rs (feature `opus`).
    #[default]
    Rust,
    /// libopus (feature `libopus`).
    LibOpus,
}

/// A jitter buffer fed by an `RTCRtpReceiver`.
pub struct AudioReceiver {
    receiver: RTCRtpReceiverId,
    track: MediaStreamTrackId,
    buffer: JitterBuffer,
    ssrc: Option<u32>,
}

impl std::fmt::Debug for AudioReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AudioReceiver")
            .field("track", &self.track)
            .field("ssrc", &self.ssrc)
            .field("buffer", &self.buffer)
            .finish()
    }
}

fn opus_decoder(
    channels: u16,
    backend: OpusBackend,
) -> Result<Box<dyn crate::codec::AudioDecoder>> {
    let _ = (channels, backend);
    #[cfg(feature = "libopus")]
    if backend == OpusBackend::LibOpus {
        return Ok(Box::new(crate::codec::libopus::LibOpusDecoder::new(
            channels,
        )?));
    }
    #[cfg(feature = "opus")]
    {
        Ok(Box::new(crate::codec::opus::OpusDecoder::new(channels)?))
    }
    #[cfg(all(not(feature = "opus"), feature = "libopus"))]
    {
        Ok(Box::new(crate::codec::libopus::LibOpusDecoder::new(
            channels,
        )?))
    }
    #[cfg(not(any(feature = "opus", feature = "libopus")))]
    {
        Err(Error::Unsupported(
            "Opus needs the `opus` or `libopus` feature".into(),
        ))
    }
}

impl AudioReceiver {
    /// Binds a jitter buffer to `receiver` after negotiation, with a decoder for every
    /// negotiated audio format (Opus decoded in `opus_channels` channels).
    ///
    /// # Errors
    ///
    /// [`Error::Engine`] when the receiver is gone.
    pub fn new(
        pc: &mut RTCPeerConnection,
        receiver: RTCRtpReceiverId,
        config: JitterBufferConfig,
        opus_channels: u16,
        backend: OpusBackend,
    ) -> Result<Self> {
        let mut r = pc
            .rtp_receiver(receiver)
            .ok_or_else(|| engine("no such receiver"))?;
        let target = r.jitter_buffer_target();
        let track = r.track().track_id().clone();
        let codecs = r.get_parameters().rtp_parameters.codecs.clone();
        let mut buffer = JitterBuffer::new(JitterBufferConfig {
            target_delay: target.or(config.target_delay),
            ..config
        });
        for c in &codecs {
            let pt = c.payload_type;
            let mime = c.rtp_codec.mime_type.as_str();
            if mime.eq_ignore_ascii_case(MIME_TYPE_OPUS) {
                buffer.register_decoder(pt, opus_decoder(opus_channels, backend)?);
            } else if mime.eq_ignore_ascii_case(MIME_TYPE_PCMU) {
                buffer.register_decoder(pt, Box::new(G711Decoder::new(Law::Mu)));
            } else if mime.eq_ignore_ascii_case(MIME_TYPE_PCMA) {
                buffer.register_decoder(pt, Box::new(G711Decoder::new(Law::A)));
            } else if mime.eq_ignore_ascii_case(MIME_TYPE_G722) {
                buffer.register_decoder(pt, Box::new(G722Decoder::new()));
            } else if mime.eq_ignore_ascii_case(MIME_TYPE_CN) {
                buffer.register_comfort_noise(pt, c.rtp_codec.clock_rate);
            } else if mime.eq_ignore_ascii_case(MIME_TYPE_TELEPHONE_EVENT) {
                buffer.register_telephone_event(pt);
            } else if mime.eq_ignore_ascii_case(MIME_TYPE_RED) {
                buffer.register_red(pt);
            }
        }
        Ok(Self {
            receiver,
            track,
            buffer,
            ssrc: None,
        })
    }

    /// The track whose packets this receiver takes.
    pub fn track_id(&self) -> &MediaStreamTrackId {
        &self.track
    }

    /// The jitter buffer.
    pub fn buffer(&self) -> &JitterBuffer {
        &self.buffer
    }

    /// The statistics so far.
    pub fn stats(&self) -> &ReceiveStats {
        self.buffer.stats()
    }

    /// Takes an RTP packet `poll_read` delivered (as `RTCMessage::RtpPacket(track, packet)`)
    /// for this receiver's track, arrived at `now`.
    pub fn handle_rtp(&mut self, now: Instant, packet: &rtci::rtp::Packet) {
        self.ssrc.get_or_insert(packet.header.ssrc);
        let _ = self.buffer.insert(now, &packet.header, &packet.payload);
    }

    /// The next 10 ms of audio.
    pub fn pull(&mut self, now: Instant) -> AudioFrame {
        self.buffer.pull(now)
    }

    /// The next event (telephone events).
    pub fn poll_event(&mut self) -> Option<ReceiveEvent> {
        self.buffer.poll_event()
    }

    /// Follows the receiver's `jitterBufferTarget` and hands the statistics to the engine's
    /// `getStats()` (the inbound stream's audio and jitter buffer members).
    pub fn update_stats(&mut self, pc: &mut RTCPeerConnection) {
        if let Some(r) = pc.rtp_receiver(self.receiver) {
            self.buffer.set_target_delay(r.jitter_buffer_target());
        }
        let Some(ssrc) = self.ssrc else {
            return;
        };
        let s = self.buffer.stats();
        pc.update_audio_receiver_stats(
            ssrc,
            AudioReceiverStatsUpdate {
                total_samples_received: Some(s.total_samples_received),
                concealed_samples: Some(s.concealed_samples),
                silent_concealed_samples: Some(s.silent_concealed_samples),
                concealment_events: Some(s.concealment_events),
                inserted_samples_for_deceleration: Some(s.inserted_samples_for_deceleration),
                removed_samples_for_acceleration: Some(s.removed_samples_for_acceleration),
                audio_level: Some(s.audio_level),
                total_audio_energy: Some(s.total_audio_energy),
                total_samples_duration: Some(s.total_samples_duration),
                jitter_buffer_delay: Some(s.jitter_buffer_delay),
                jitter_buffer_target_delay: Some(s.jitter_buffer_target_delay),
                jitter_buffer_minimum_delay: Some(s.jitter_buffer_minimum_delay),
                jitter_buffer_emitted_count: Some(s.jitter_buffer_emitted_count),
                fec_packets_discarded: Some(
                    s.fec_packets_received
                        .saturating_sub(s.fec_frames_recovered),
                ),
                in_band_fec_packets_received: Some(s.fec_packets_received),
                ..Default::default()
            },
        );
    }
}

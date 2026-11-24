//! The send pipeline: capture frames in, RTP payloads out.
//!
//! capture (any rate, mono or stereo) → 48 kHz → [`AudioProcessing`] (mono) → voice activity
//! and level → the codec's rate → encoder → [`SendOutput`]: a payload to packetize, with
//! the RFC 6464 level and voice flag for its header extension, or a silence to skip (DTX).
//!
//! - **Bitrate**: [`SendPipeline::set_target_bitrate`] takes the share of the congestion
//!   controller's target the engine gives the sender (`RTCRtpSender::target_bitrates`),
//!   takes off the packets' own overhead (RTP, SRTP, UDP and IP headers and the header
//!   extensions, [`SendConfig::overhead_bytes`] a packet) and gives the rest to the encoder,
//!   within the receiver's `maxaveragebitrate`.
//! - **FEC**: [`SendPipeline::on_packet_loss`] takes the loss the receiver reports (RTCP
//!   reception reports' fraction lost), smoothed; Opus in-band FEC is turned on above 1 %
//!   (off again below 0.5 %) when the receiver accepts it (`useinbandfec=1`), and the encoder
//!   is told the loss rate, which sets how much redundancy it spends.
//! - **DTX**: with Opus DTX the encoder's TOC-only packets are skipped after the first
//!   (libwebrtc's rule: the first tells the receiver DTX began); codecs without DTX send an
//!   RFC 3389 SID at the start of silence and every 100 ms while it lasts, when comfort noise
//!   was negotiated ([`SendConfig::comfort_noise`]), and nothing else.
//!
//! Stereo sending (the receiver asked for `stereo=1` and the capture is stereo) bypasses the
//! processing, which is mono: stereo is for music, where RFC 7874 section 4 asks for no
//! automatic level changes.

use bytes::Bytes;

use crate::codec::AudioEncoder;
use crate::codec::fmtp::OpusEncoderConfig;
use crate::codec::g711::{G711Encoder, Law};
use crate::codec::g722::G722Encoder;
use crate::dsp::cng;
use crate::dsp::level::{LevelMeter, rfc6464_level};
use crate::dsp::resample::MultiResampler;
use crate::frame::{AudioFrame, convert_channels};
use crate::processing::{AudioProcessing, FRAME, ProcessingConfig, ProcessingStats};
use crate::{Error, PIPELINE_RATE, Result};

/// The codec a send pipeline encodes with.
#[derive(Debug, Clone, PartialEq)]
pub enum SendCodec {
    /// Opus (opus-rs, or libopus with the `libopus` feature and `prefer_libopus`).
    Opus(OpusEncoderConfig),
    /// G.711 mu-law, packets of this many milliseconds.
    Pcmu(u32),
    /// G.711 A-law.
    Pcma(u32),
    /// G.722 at 64 kbit/s.
    G722(u32),
}

/// How a send pipeline is set up.
#[derive(Debug, Clone, PartialEq)]
pub struct SendConfig {
    /// The codec.
    pub codec: SendCodec,
    /// The capture's rate.
    pub capture_rate: u32,
    /// The capture's channels.
    pub capture_channels: u16,
    /// The processing stages.
    pub processing: ProcessingConfig,
    /// Send RFC 3389 comfort noise during silence (codecs without DTX of their own; only
    /// when the CN format was negotiated).
    pub comfort_noise: bool,
    /// Whether the receiver accepts in-band FEC (its `useinbandfec`).
    pub fec_allowed: bool,
    /// Bytes each packet costs besides its payload: RTP header 12, SRTP tag 10, UDP 8, IPv4
    /// 20, header extensions about 8.
    pub overhead_bytes: u32,
    /// Use libopus rather than opus-rs for Opus (needs the `libopus` feature).
    pub prefer_libopus: bool,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            codec: SendCodec::Opus(OpusEncoderConfig::default()),
            capture_rate: PIPELINE_RATE,
            capture_channels: 1,
            processing: ProcessingConfig::CALL,
            comfort_noise: false,
            fec_allowed: true,
            overhead_bytes: 58,
            prefer_libopus: false,
        }
    }
}

/// What the payload of a [`SendOutput::Packet`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    /// The codec's.
    Media,
    /// An RFC 3389 SID (sent with the CN payload type).
    ComfortNoise,
}

/// What the pipeline makes of the capture.
#[derive(Debug, Clone, PartialEq)]
pub enum SendOutput {
    /// A payload to send.
    Packet {
        /// The payload.
        payload: Bytes,
        /// The codec's, or comfort noise.
        kind: PayloadKind,
        /// The RTP timestamp units it spans (what the next packet's timestamp is ahead).
        rtp_duration: u32,
        /// Its RFC 6464 level, -dBov.
        audio_level: u8,
        /// Whether it holds speech (the RFC 6464 V flag).
        voice: bool,
    },
    /// Nothing is sent for this much RTP time (DTX): the packetizer skips it, and the next
    /// packet starts a talkspurt.
    Skip {
        /// The RTP timestamp units skipped.
        rtp_duration: u32,
    },
}

/// Send-side counters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SendStats {
    /// Frames encoded.
    pub frames_encoded: u64,
    /// Packets produced (media and comfort noise).
    pub packets: u64,
    /// Payload bytes produced.
    pub bytes: u64,
    /// Frames not sent for DTX.
    pub frames_skipped: u64,
    /// The encoder's bitrate now, bits per second.
    pub target_bitrate: Option<u32>,
    /// Whether in-band FEC is on now.
    pub fec: bool,
    /// The smoothed loss the receiver reports.
    pub loss: f32,
}

/// Capture frames in, payloads out (see the module docs).
pub struct SendPipeline {
    config: SendConfig,
    encoder: Box<dyn AudioEncoder>,
    processing: Option<AudioProcessing>,
    capture_resampler: Option<MultiResampler>,
    render_resampler: Option<MultiResampler>,
    codec_resampler: Option<MultiResampler>,
    pipeline: Vec<f32>,
    render: Vec<f32>,
    pending: Vec<f32>,
    frame_voice: bool,
    frame_power: f64,
    frame_count: usize,
    last_was_dtx: bool,
    silence_rtp: u32,
    sid_due: u32,
    level: LevelMeter,
    stats: SendStats,
    loss: f32,
}

impl std::fmt::Debug for SendPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SendPipeline")
            .field("config", &self.config)
            .field("encoder", &self.encoder.name())
            .field("stats", &self.stats)
            .finish()
    }
}

fn make_encoder(config: &SendConfig) -> Result<Box<dyn AudioEncoder>> {
    Ok(match &config.codec {
        SendCodec::Opus(opus) => {
            let _ = config.prefer_libopus;
            #[cfg(feature = "libopus")]
            if config.prefer_libopus {
                return Ok(Box::new(crate::codec::libopus::LibOpusEncoder::new(
                    opus.clone(),
                )?));
            }
            #[cfg(feature = "opus")]
            {
                Box::new(crate::codec::opus::OpusEncoder::new(opus.clone())?)
            }
            #[cfg(all(not(feature = "opus"), feature = "libopus"))]
            {
                Box::new(crate::codec::libopus::LibOpusEncoder::new(opus.clone())?)
            }
            #[cfg(not(any(feature = "opus", feature = "libopus")))]
            {
                let _ = opus;
                return Err(Error::Unsupported(
                    "Opus needs the `opus` or `libopus` feature".into(),
                ));
            }
        }
        SendCodec::Pcmu(ptime) => Box::new(G711Encoder::new(Law::Mu, *ptime)?),
        SendCodec::Pcma(ptime) => Box::new(G711Encoder::new(Law::A, *ptime)?),
        SendCodec::G722(ptime) => Box::new(G722Encoder::new(*ptime)?),
    })
}

impl SendPipeline {
    /// A pipeline for `config`.
    pub fn new(config: SendConfig) -> Result<Self> {
        let encoder = make_encoder(&config)?;
        if config.capture_rate == 0 || !(1..=2).contains(&config.capture_channels) {
            return Err(Error::Config(format!(
                "capture at {} Hz, {} channels",
                config.capture_rate, config.capture_channels
            )));
        }
        let channels = encoder.channels();
        let processing = (channels == 1).then(|| AudioProcessing::new(config.processing));
        let capture_resampler = (config.capture_rate != PIPELINE_RATE)
            .then(|| MultiResampler::new(config.capture_rate, PIPELINE_RATE, channels));
        let codec_resampler = (encoder.sample_rate() != PIPELINE_RATE)
            .then(|| MultiResampler::new(PIPELINE_RATE, encoder.sample_rate(), channels));
        let fec = encoder_fec(&config);
        let mut p = Self {
            config,
            encoder,
            processing,
            capture_resampler,
            render_resampler: None,
            codec_resampler,
            pipeline: Vec::new(),
            render: Vec::new(),
            pending: Vec::new(),
            frame_voice: false,
            frame_power: 0.0,
            frame_count: 0,
            last_was_dtx: false,
            silence_rtp: 0,
            sid_due: 0,
            level: LevelMeter::new(),
            stats: SendStats::default(),
            loss: 0.0,
        };
        p.stats.fec = fec;
        p.encoder.set_fec(fec);
        p.stats.target_bitrate = p.encoder.target_bitrate();
        Ok(p)
    }

    /// The encoder's name (`encoderImplementation`).
    pub fn encoder_name(&self) -> &'static str {
        self.encoder.name()
    }

    /// The encoder's RTP clock rate.
    pub fn rtp_clock_rate(&self) -> u32 {
        self.encoder.rtp_clock_rate()
    }

    /// The RTP units of one packet.
    pub fn packet_rtp_duration(&self) -> u32 {
        self.encoder.frame_rtp_duration()
    }

    /// The counters.
    pub fn stats(&self) -> &SendStats {
        &self.stats
    }

    /// The processing's echo and gain measurements.
    pub fn processing_stats(&self) -> ProcessingStats {
        self.processing
            .as_ref()
            .map(|p| p.stats())
            .unwrap_or_default()
    }

    /// The capture level meter (W3C `RTCAudioSourceStats` `audioLevel`, `totalAudioEnergy`,
    /// `totalSamplesDuration`), measured on the processed audio.
    pub fn source_level(&self) -> &LevelMeter {
        &self.level
    }

    /// Sets the bitrate available to this stream, all overhead included (bits per second).
    pub fn set_target_bitrate(&mut self, allocated_bps: f64) {
        let packets_per_second = f64::from(self.encoder.rtp_clock_rate())
            / f64::from(self.encoder.frame_rtp_duration().max(1));
        let overhead = f64::from(self.config.overhead_bytes) * 8.0 * packets_per_second;
        let payload = (allocated_bps - overhead).max(0.0) as u32;
        self.encoder.set_target_bitrate(payload);
        self.stats.target_bitrate = self.encoder.target_bitrate();
    }

    /// Takes the loss fraction (0 to 1) of a reception report.
    pub fn on_packet_loss(&mut self, fraction: f32) {
        // Smooth as libwebrtc does: the last few reports count.
        self.loss = 0.7 * self.loss + 0.3 * fraction.clamp(0.0, 1.0);
        self.stats.loss = self.loss;
        self.encoder.set_packet_loss(self.loss);
        if self.config.fec_allowed {
            let on = if self.stats.fec {
                self.loss >= 0.005
            } else {
                self.loss >= 0.01
            };
            if on != self.stats.fec {
                self.stats.fec = on;
                self.encoder.set_fec(on);
            }
        }
    }

    /// Takes audio about to be played on this device (the echo canceller's reference).
    pub fn push_render(&mut self, frame: &AudioFrame) {
        let Some(processing) = self.processing.as_mut() else {
            return;
        };
        let mut mono = Vec::new();
        if convert_channels(&frame.samples, frame.channels, 1, &mut mono).is_err() {
            return;
        }
        if frame.sample_rate != PIPELINE_RATE {
            let rebuild = self
                .render_resampler
                .as_ref()
                .is_none_or(|r| r.from_rate() != frame.sample_rate);
            if rebuild {
                self.render_resampler =
                    Some(MultiResampler::new(frame.sample_rate, PIPELINE_RATE, 1));
            }
            let mut out = Vec::new();
            if let Some(r) = self.render_resampler.as_mut() {
                r.process(&mono, &mut out);
            }
            mono = out;
        }
        self.render.extend(mono);
        while self.render.len() >= FRAME {
            let f: Vec<f32> = self.render.drain(..FRAME).collect();
            processing.process_render(&f);
        }
    }

    /// Takes captured audio (any length, at the configured rate and channels); returns what
    /// to send.
    pub fn push_capture(&mut self, frame: &AudioFrame) -> Result<Vec<SendOutput>> {
        if frame.sample_rate != self.config.capture_rate
            || frame.channels != self.config.capture_channels
        {
            return Err(Error::Format(format!(
                "capture configured at {} Hz x {}, got {} Hz x {}",
                self.config.capture_rate,
                self.config.capture_channels,
                frame.sample_rate,
                frame.channels
            )));
        }
        let channels = self.encoder.channels();
        let mut converted = Vec::with_capacity(frame.samples.len());
        convert_channels(&frame.samples, frame.channels, channels, &mut converted)?;
        if let Some(r) = self.capture_resampler.as_mut() {
            let mut out = Vec::new();
            r.process(&converted, &mut out);
            converted = out;
        }
        self.pipeline.extend(converted);
        let ch = usize::from(channels);
        let mut outputs = Vec::new();
        while self.pipeline.len() >= FRAME * ch {
            let mut f: Vec<f32> = self.pipeline.drain(..FRAME * ch).collect();
            let voice = match self.processing.as_mut() {
                Some(p) => p.process_capture(&mut f).voice,
                None => true,
            };
            self.level.process(&f, channels, PIPELINE_RATE);
            self.frame_voice |= voice;
            self.frame_power += f.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>();
            self.frame_count += f.len();
            match self.codec_resampler.as_mut() {
                Some(r) => r.process(&f, &mut self.pending),
                None => self.pending.extend(f),
            }
            let need = self.encoder.frame_samples() * ch;
            while self.pending.len() >= need {
                let pcm: Vec<f32> = self.pending.drain(..need).collect();
                outputs.push(self.encode(&pcm)?);
            }
        }
        Ok(outputs)
    }

    fn encode(&mut self, pcm: &[f32]) -> Result<SendOutput> {
        let voice = std::mem::take(&mut self.frame_voice);
        let power = std::mem::take(&mut self.frame_power)
            / std::mem::take(&mut self.frame_count).max(1) as f64;
        let audio_level = if power <= 0.0 {
            127
        } else {
            (-10.0 * power.log10()).round().clamp(0.0, 127.0) as u8
        };
        let rtp_duration = self.encoder.frame_rtp_duration();
        self.stats.frames_encoded += 1;
        // RFC 3389 for codecs without their own DTX: SID on silence, then quiet.
        if self.config.comfort_noise && !self.encoder.has_dtx() && !voice {
            let first = self.silence_rtp == 0;
            self.silence_rtp = self.silence_rtp.saturating_add(rtp_duration);
            let interval = self.encoder.rtp_clock_rate() / 10; // 100 ms
            if first || self.silence_rtp >= self.sid_due {
                self.sid_due = self.silence_rtp.saturating_add(interval);
                let mono: Vec<f32> = if self.encoder.channels() == 1 {
                    pcm.to_vec()
                } else {
                    pcm.as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| 0.5 * (p[0] + p[1]))
                        .collect()
                };
                let sid = cng::analyze(&mono);
                let payload = rtp::codec::comfort_noise::marshal_channels(&[sid])
                    .map_err(|e| Error::Codec(e.to_string()))?;
                self.stats.packets += 1;
                self.stats.bytes += payload.len() as u64;
                return Ok(SendOutput::Packet {
                    payload,
                    kind: PayloadKind::ComfortNoise,
                    rtp_duration,
                    audio_level: rfc6464_level(&mono),
                    voice: false,
                });
            }
            self.stats.frames_skipped += 1;
            return Ok(SendOutput::Skip { rtp_duration });
        }
        self.silence_rtp = 0;
        self.sid_due = 0;
        let mut payload = Vec::new();
        self.encoder.encode(pcm, &mut payload)?;
        let dtx = self.encoder.has_dtx() && payload.len() <= 2;
        if dtx && self.last_was_dtx {
            self.stats.frames_skipped += 1;
            return Ok(SendOutput::Skip { rtp_duration });
        }
        self.last_was_dtx = dtx;
        self.stats.packets += 1;
        self.stats.bytes += payload.len() as u64;
        Ok(SendOutput::Packet {
            payload: Bytes::from(payload),
            kind: PayloadKind::Media,
            rtp_duration,
            audio_level,
            voice,
        })
    }
}

fn encoder_fec(config: &SendConfig) -> bool {
    match &config.codec {
        // Off until loss is reported, as `on_packet_loss` decides.
        SendCodec::Opus(c) => c.fec && config.fec_allowed && c.packet_loss_percent >= 1,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::SpeechLike;

    fn speech(rate: u32, secs: f64, seed: u64) -> Vec<f32> {
        let mut x = vec![0.0f32; (f64::from(rate) * secs) as usize];
        SpeechLike::new(rate, seed).fill(&mut x);
        x
    }

    fn feed(p: &mut SendPipeline, x: &[f32], rate: u32) -> Vec<SendOutput> {
        let mut out = Vec::new();
        for chunk in x.chunks(rate as usize / 100) {
            out.extend(
                p.push_capture(&AudioFrame {
                    samples: chunk.to_vec(),
                    sample_rate: rate,
                    channels: 1,
                })
                .unwrap(),
            );
        }
        out
    }

    #[test]
    fn capture_at_any_rate_becomes_one_packet_per_ptime() {
        for rate in [16_000u32, 44_100, 48_000] {
            let mut p = SendPipeline::new(SendConfig {
                capture_rate: rate,
                processing: ProcessingConfig::OFF,
                ..Default::default()
            })
            .unwrap();
            let out = feed(&mut p, &speech(rate, 2.0, 1), rate);
            // 2 s of 20 ms packets, less the resampler's start-up.
            assert!((98..=100).contains(&out.len()), "{rate}: {}", out.len());
            assert!(out.iter().all(|o| matches!(
                o,
                SendOutput::Packet {
                    rtp_duration: 960,
                    ..
                }
            )));
        }
    }

    #[cfg(feature = "opus")]
    #[test]
    fn opus_dtx_skips_all_but_the_first_silent_packet() {
        let mut p = SendPipeline::new(SendConfig {
            codec: SendCodec::Opus(OpusEncoderConfig {
                dtx: true,
                ..Default::default()
            }),
            processing: ProcessingConfig::OFF,
            ..Default::default()
        })
        .unwrap();
        let mut x = speech(48_000, 1.0, 2);
        x.extend(vec![0.0f32; 48_000 * 3]);
        let out = feed(&mut p, &x, 48_000);
        let skipped = out
            .iter()
            .filter(|o| matches!(o, SendOutput::Skip { .. }))
            .count();
        assert!(skipped > 100, "{skipped} of {}", out.len());
        let tiny_sent = out
            .iter()
            .filter(|o| matches!(o, SendOutput::Packet { payload, .. } if payload.len() <= 2))
            .count();
        assert!(tiny_sent >= 1);
        assert!(tiny_sent < skipped / 4);
    }

    #[test]
    fn g711_silence_sends_comfort_noise_every_100_ms() {
        let mut p = SendPipeline::new(SendConfig {
            codec: SendCodec::Pcmu(20),
            capture_rate: 8000,
            comfort_noise: true,
            processing: ProcessingConfig::OFF,
            ..Default::default()
        })
        .unwrap();
        let mut x = speech(8000, 1.0, 3);
        x.extend(vec![0.0f32; 8000 * 2]);
        // A noise floor the VAD can track.
        let mut n = vec![0.0f32; x.len()];
        crate::signal::Noise::new(4, 0.001).fill(&mut n);
        for (a, b) in x.iter_mut().zip(&n) {
            *a += b;
        }
        let out = feed(&mut p, &x, 8000);
        let sids = out
            .iter()
            .filter(|o| {
                matches!(
                    o,
                    SendOutput::Packet {
                        kind: PayloadKind::ComfortNoise,
                        ..
                    }
                )
            })
            .count();
        let skips = out
            .iter()
            .filter(|o| matches!(o, SendOutput::Skip { .. }))
            .count();
        // About 1.7 s of silence after the hangover: a SID each 100 ms, the rest skipped.
        assert!((14..=30).contains(&sids), "{sids}");
        assert!(skips > 3 * sids, "{skips}");
    }

    #[cfg(feature = "opus")]
    #[test]
    fn bitrate_and_fec_follow_the_network() {
        let mut p = SendPipeline::new(SendConfig::default()).unwrap();
        assert!(!p.stats().fec);
        // 60 kbit/s allocated, 50 packets a second of 58 bytes overhead: 36.8 kbit/s left.
        p.set_target_bitrate(60_000.0);
        assert_eq!(p.stats().target_bitrate, Some(36_800));
        // A floor of 6 kbit/s.
        p.set_target_bitrate(1000.0);
        assert_eq!(p.stats().target_bitrate, Some(6000));
        for _ in 0..5 {
            p.on_packet_loss(0.05);
        }
        assert!(p.stats().fec);
        for _ in 0..20 {
            p.on_packet_loss(0.0);
        }
        assert!(!p.stats().fec);
        // Without the receiver's consent there is no FEC.
        let mut q = SendPipeline::new(SendConfig {
            fec_allowed: false,
            ..Default::default()
        })
        .unwrap();
        for _ in 0..5 {
            q.on_packet_loss(0.2);
        }
        assert!(!q.stats().fec);
    }

    #[test]
    fn the_audio_level_and_voice_flag_describe_each_packet() {
        let mut p = SendPipeline::new(SendConfig {
            codec: SendCodec::Pcma(20),
            capture_rate: 8000,
            processing: ProcessingConfig::OFF,
            ..Default::default()
        })
        .unwrap();
        // 0.1 RMS (-20 dBov) square-ish tone.
        let x: Vec<f32> = (0..8000)
            .map(|i| if (i / 20) % 2 == 0 { 0.1 } else { -0.1 })
            .collect();
        let out = feed(&mut p, &x, 8000);
        let levels: Vec<u8> = out
            .iter()
            .filter_map(|o| match o {
                SendOutput::Packet { audio_level, .. } => Some(*audio_level),
                _ => None,
            })
            .collect();
        assert!(
            levels[5..].iter().all(|l| (19..=21).contains(l)),
            "{levels:?}"
        );
    }
}

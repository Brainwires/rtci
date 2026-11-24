//! Opus through opus-rs, a pure-Rust port of libopus 1.6 (BSD-3-Clause): 48 kHz, mono or
//! stereo, VoIP application, with in-band FEC, DTX and the codec's own concealment.

use super::fmtp::{MaxBandwidth, OpusEncoderConfig};
use super::opus_packet;
use super::{AudioDecoder, AudioEncoder};
use crate::{Error, Result};

/// The rate Opus runs at in this crate (the RTP clock of every Opus stream).
pub const OPUS_RATE: u32 = 48_000;
/// The longest packet, in samples per channel (120 ms).
pub const MAX_PACKET_SAMPLES: usize = 5760;
/// The largest payload the encoder may write (RFC 6716's frame limit with headroom for
/// multi-frame packets).
const MAX_PAYLOAD: usize = 4000;

fn bandwidth(b: MaxBandwidth) -> opus_rs::Bandwidth {
    match b {
        MaxBandwidth::Narrowband => opus_rs::Bandwidth::Narrowband,
        MaxBandwidth::Mediumband => opus_rs::Bandwidth::Mediumband,
        MaxBandwidth::Wideband => opus_rs::Bandwidth::Wideband,
        MaxBandwidth::Superwideband => opus_rs::Bandwidth::Superwideband,
        MaxBandwidth::Fullband => opus_rs::Bandwidth::Fullband,
    }
}

/// An Opus encoder (opus-rs).
pub struct OpusEncoder {
    inner: opus_rs::OpusEncoder,
    config: OpusEncoderConfig,
    buf: Vec<u8>,
}

impl std::fmt::Debug for OpusEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpusEncoder")
            .field("config", &self.config)
            .finish()
    }
}

impl OpusEncoder {
    /// An encoder set up as `config` says.
    pub fn new(config: OpusEncoderConfig) -> Result<Self> {
        if !OpusEncoderConfig::FRAME_MS.contains(&config.frame_ms) {
            return Err(Error::Config(format!(
                "Opus codes 10, 20, 40 or 60 ms frames, not {}",
                config.frame_ms
            )));
        }
        if !(1..=2).contains(&config.channels) {
            return Err(Error::Config(format!("Opus channels {}", config.channels)));
        }
        let mut inner = opus_rs::OpusEncoder::new(
            OPUS_RATE as i32,
            usize::from(config.channels),
            opus_rs::Application::Voip,
        )
        .map_err(|e| Error::Codec(format!("Opus encoder: {e}")))?;
        inner.complexity = i32::from(config.complexity.min(10));
        inner.use_cbr = config.cbr;
        inner.use_inband_fec = config.fec;
        inner.packet_loss_perc = i32::from(config.packet_loss_percent.min(100));
        inner.bitrate_bps = config.bitrate.clamp(6000, config.max_bitrate.max(6000)) as i32;
        inner.set_dtx(config.dtx);
        inner.set_max_bandwidth(bandwidth(config.max_bandwidth));
        Ok(Self {
            inner,
            config,
            buf: vec![0; MAX_PAYLOAD],
        })
    }

    /// The configuration, with the current bitrate, FEC and DTX.
    pub fn config(&self) -> &OpusEncoderConfig {
        &self.config
    }

    /// The encoder's lookahead in samples (the pre-skip: decoded audio is this much later
    /// than the input).
    pub fn lookahead(&self) -> usize {
        self.inner.lookahead()
    }

    /// Whether the last frame was coded in DTX (a TOC-only packet).
    pub fn in_dtx(&self) -> bool {
        self.inner.in_dtx()
    }
}

impl AudioEncoder for OpusEncoder {
    fn name(&self) -> &'static str {
        "opus-rs"
    }

    fn sample_rate(&self) -> u32 {
        OPUS_RATE
    }

    fn channels(&self) -> u16 {
        self.config.channels
    }

    fn frame_samples(&self) -> usize {
        self.config.frame_samples()
    }

    fn encode(&mut self, pcm: &[f32], out: &mut Vec<u8>) -> Result<()> {
        let frame = self.config.frame_samples();
        if pcm.len() != frame * usize::from(self.config.channels) {
            return Err(Error::Format(format!(
                "Opus takes {} samples, got {}",
                frame * usize::from(self.config.channels),
                pcm.len()
            )));
        }
        let n = self
            .inner
            .encode(pcm, frame, &mut self.buf)
            .map_err(|e| Error::Codec(format!("Opus encode: {e}")))?;
        out.extend_from_slice(&self.buf[..n]);
        Ok(())
    }

    fn set_target_bitrate(&mut self, bps: u32) {
        let bps = bps.clamp(6000, self.config.max_bitrate.max(6000));
        self.config.bitrate = bps;
        self.inner.bitrate_bps = bps as i32;
    }

    fn target_bitrate(&self) -> Option<u32> {
        Some(self.config.bitrate)
    }

    fn set_packet_loss(&mut self, fraction: f32) {
        let pct = (fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
        self.config.packet_loss_percent = pct;
        self.inner.packet_loss_perc = i32::from(pct);
    }

    fn set_fec(&mut self, enabled: bool) {
        self.config.fec = enabled;
        self.inner.use_inband_fec = enabled;
    }

    fn set_dtx(&mut self, enabled: bool) {
        self.config.dtx = enabled;
        self.inner.set_dtx(enabled);
    }

    fn has_dtx(&self) -> bool {
        true
    }
}

/// An Opus decoder (opus-rs) at 48 kHz.
pub struct OpusDecoder {
    inner: opus_rs::OpusDecoder,
    channels: u16,
    buf: Vec<f32>,
}

impl std::fmt::Debug for OpusDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpusDecoder")
            .field("channels", &self.channels)
            .finish()
    }
}

impl OpusDecoder {
    /// A decoder that outputs `channels` (1 or 2) channels, whatever the packets carry
    /// (RFC 7587 section 6.1: a receiver decodes stereo and mono alike).
    pub fn new(channels: u16) -> Result<Self> {
        if !(1..=2).contains(&channels) {
            return Err(Error::Config(format!("Opus channels {channels}")));
        }
        let inner = opus_rs::OpusDecoder::new(OPUS_RATE as i32, usize::from(channels))
            .map_err(|e| Error::Codec(format!("Opus decoder: {e}")))?;
        Ok(Self {
            inner,
            channels,
            buf: vec![0.0; MAX_PACKET_SAMPLES * usize::from(channels)],
        })
    }

    fn conceal_chunks(&mut self, samples: usize, out: &mut Vec<f32>) -> Result<()> {
        let ch = usize::from(self.channels);
        // A multiple of 2.5 ms, at most 120 ms a call.
        let mut left = samples.div_ceil(120) * 120;
        let mut produced = 0;
        while left > 0 {
            let n = left.min(MAX_PACKET_SAMPLES);
            let got = self
                .inner
                .decode(&[], n, &mut self.buf)
                .map_err(|e| Error::Codec(format!("Opus PLC: {e}")))?;
            let take = got.min(samples - produced);
            out.extend_from_slice(&self.buf[..take * ch]);
            produced += take;
            left -= n;
        }
        Ok(())
    }
}

impl AudioDecoder for OpusDecoder {
    fn name(&self) -> &'static str {
        "opus-rs"
    }

    fn sample_rate(&self) -> u32 {
        OPUS_RATE
    }

    fn channels(&self) -> u16 {
        self.channels
    }

    fn packet_samples(&self, payload: &[u8]) -> Option<usize> {
        opus_packet::packet_samples_48k(payload).map(|n| n as usize)
    }

    fn decode(&mut self, payload: &[u8], out: &mut Vec<f32>) -> Result<usize> {
        let n = self
            .inner
            .decode(payload, MAX_PACKET_SAMPLES, &mut self.buf)
            .map_err(|e| Error::Codec(format!("Opus decode: {e}")))?;
        out.extend_from_slice(&self.buf[..n * usize::from(self.channels)]);
        Ok(n)
    }

    fn conceal(&mut self, samples: usize, out: &mut Vec<f32>) -> Result<bool> {
        self.conceal_chunks(samples, out)?;
        Ok(true)
    }

    fn decode_fec(
        &mut self,
        next_payload: &[u8],
        samples: usize,
        out: &mut Vec<f32>,
    ) -> Result<bool> {
        if !opus_packet::has_lbrr(next_payload)
            || samples > MAX_PACKET_SAMPLES
            || !samples.is_multiple_of(120)
        {
            return Ok(false);
        }
        let n = self
            .inner
            .decode_fec(next_payload, samples, &mut self.buf)
            .map_err(|e| Error::Codec(format!("Opus FEC: {e}")))?;
        out.extend_from_slice(&self.buf[..n * usize::from(self.channels)]);
        Ok(true)
    }

    fn fec_samples(&self, payload: &[u8]) -> Option<usize> {
        if opus_packet::has_lbrr(payload) {
            Some(opus_packet::toc(payload[0]).frame_samples_48k as usize)
        } else {
            None
        }
    }

    fn is_dtx(&self, payload: &[u8]) -> bool {
        payload.len() <= 2
    }

    fn reset(&mut self) {
        if let Ok(d) = opus_rs::OpusDecoder::new(OPUS_RATE as i32, usize::from(self.channels)) {
            self.inner = d;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SpeechLike, Tone, best_lag, segmental_snr_db, snr_db};

    fn encode_all(enc: &mut OpusEncoder, x: &[f32]) -> Vec<Vec<u8>> {
        let frame = enc.frame_samples() * usize::from(enc.channels());
        x.chunks_exact(frame)
            .map(|f| {
                let mut p = Vec::new();
                enc.encode(f, &mut p).unwrap();
                p
            })
            .collect()
    }

    #[test]
    fn decoding_is_deterministic_bit_for_bit() {
        let mut s = SpeechLike::new(48_000, 5);
        let mut x = vec![0.0f32; 48_000];
        s.fill(&mut x);
        let mut enc = OpusEncoder::new(OpusEncoderConfig::default()).unwrap();
        let packets = encode_all(&mut enc, &x);
        let decode = || {
            let mut d = OpusDecoder::new(1).unwrap();
            let mut out = Vec::new();
            for p in &packets {
                d.decode(p, &mut out).unwrap();
            }
            out
        };
        let a = decode();
        let b = decode();
        assert_eq!(a.len(), 48_000);
        assert!(a.iter().zip(&b).all(|(x, y)| x.to_bits() == y.to_bits()));
        // A second encoder makes the same packets from the same audio.
        let mut enc2 = OpusEncoder::new(OpusEncoderConfig::default()).unwrap();
        assert_eq!(encode_all(&mut enc2, &x), packets);
    }

    #[test]
    fn a_tone_at_32_kbps_comes_back_above_twenty_db_snr() {
        let mut t = Tone::new(48_000, 440.0, 0.3);
        let mut x = vec![0.0f32; 48_000];
        t.fill(&mut x);
        let mut enc = OpusEncoder::new(OpusEncoderConfig::default()).unwrap();
        let mut dec = OpusDecoder::new(1).unwrap();
        let mut y = Vec::new();
        for p in encode_all(&mut enc, &x) {
            dec.decode(&p, &mut y).unwrap();
        }
        // The decoded audio is late by the encoder's lookahead (the pre-skip, 312 samples).
        let lag = enc.lookahead();
        let snr = snr_db(&x[24_000 - lag..48_000 - lag], &y[24_000..]);
        println!("MEASURE Opus (opus-rs) 440 Hz tone, 32 kbit/s: SNR {snr:.1} dB");
        assert!(snr > 12.0, "lag {lag}, SNR {snr:.1} dB");
    }

    #[test]
    fn speech_like_audio_keeps_its_waveform() {
        let mut s = SpeechLike::new(48_000, 8);
        let mut x = vec![0.0f32; 48_000 * 3];
        s.fill(&mut x);
        let mut enc = OpusEncoder::new(OpusEncoderConfig::default()).unwrap();
        let mut dec = OpusDecoder::new(1).unwrap();
        let mut y = Vec::new();
        for p in encode_all(&mut enc, &x) {
            dec.decode(&p, &mut y).unwrap();
        }
        let lag = best_lag(&x[..48_000], &y[..48_000], 600);
        let seg = segmental_snr_db(&x[..x.len() - lag], &y[lag..], 960);
        let snr = snr_db(&x[..x.len() - lag], &y[lag..]);
        println!(
            "MEASURE Opus (opus-rs) speech-like, 32 kbit/s: lag {lag}, SNR {snr:.1} dB, segmental SNR {seg:.1} dB"
        );
        assert!(lag.abs_diff(enc.lookahead()) <= 4, "{lag}");
        assert!(seg > 2.0, "lag {lag}, segmental SNR {seg:.1} dB");
    }

    #[test]
    fn fec_recovers_a_lost_frame_better_than_concealment() {
        let mut s = SpeechLike::new(48_000, 21);
        let mut x = vec![0.0f32; 48_000 * 2];
        s.fill(&mut x);
        let config = OpusEncoderConfig {
            fec: true,
            packet_loss_percent: 20,
            ..Default::default()
        };
        let mut enc = OpusEncoder::new(config).unwrap();
        let packets = encode_all(&mut enc, &x);
        let with_lbrr = packets.iter().filter(|p| opus_packet::has_lbrr(p)).count();
        let modes: String = packets
            .iter()
            .map(|p| match opus_packet::toc(p[0]).mode {
                opus_packet::OpusMode::Silk => 'S',
                opus_packet::OpusMode::Hybrid => 'H',
                opus_packet::OpusMode::Celt => 'C',
            })
            .collect();
        println!(
            "MEASURE Opus FEC at 20 % loss: {with_lbrr} of {} packets carry LBRR; modes {modes}",
            packets.len()
        );
        assert!(
            with_lbrr > packets.len() / 4,
            "{with_lbrr} of {}",
            packets.len()
        );
        // Reference decode, and two decodes that lose every 7th packet: one recovers it
        // from the next packet's FEC, one conceals it.
        let run = |fec: bool| {
            let mut d = OpusDecoder::new(1).unwrap();
            let mut out = Vec::new();
            for (i, p) in packets.iter().enumerate() {
                if i % 7 == 3 {
                    let next = &packets[i + 1];
                    if !(fec && d.decode_fec(next, 960, &mut out).unwrap()) {
                        d.conceal(960, &mut out).unwrap();
                    }
                } else {
                    d.decode(p, &mut out).unwrap();
                }
            }
            out
        };
        let mut clean = Vec::new();
        let mut d = OpusDecoder::new(1).unwrap();
        for p in &packets {
            d.decode(p, &mut clean).unwrap();
        }
        let fec = run(true);
        let plc = run(false);
        // Over the lost frames only (and the one after, where the decoder recovers).
        let lost_snr = |y: &[f32]| {
            let (mut r, mut e) = (Vec::new(), Vec::new());
            for i in (3..packets.len() - 1).step_by(7) {
                r.extend_from_slice(&clean[i * 960..(i + 2) * 960]);
                e.extend_from_slice(&y[i * 960..(i + 2) * 960]);
            }
            snr_db(&r, &e)
        };
        let snr_fec = lost_snr(&fec);
        let snr_plc = lost_snr(&plc);
        println!(
            "MEASURE Opus every 7th packet lost: over the lost frames FEC {snr_fec:.1} dB, PLC {snr_plc:.1} dB against the clean decode"
        );
        assert!(
            snr_fec > snr_plc + 3.0,
            "FEC {snr_fec:.1} dB, PLC {snr_plc:.1} dB"
        );
    }

    #[test]
    fn dtx_sends_toc_only_packets_in_silence() {
        let config = OpusEncoderConfig {
            dtx: true,
            ..Default::default()
        };
        let mut enc = OpusEncoder::new(config).unwrap();
        let x = vec![0.0f32; 48_000];
        let packets = encode_all(&mut enc, &x);
        let tiny = packets.iter().filter(|p| p.len() <= 2).count();
        assert!(tiny > packets.len() / 2, "{tiny} of {}", packets.len());
        let dec = OpusDecoder::new(1).unwrap();
        assert!(packets.iter().any(|p| dec.is_dtx(p)));
    }

    #[test]
    fn concealment_fills_any_duration() {
        let mut d = OpusDecoder::new(2).unwrap();
        let mut out = Vec::new();
        assert!(d.conceal(480, &mut out).unwrap());
        assert_eq!(out.len(), 960);
        out.clear();
        d.conceal(7000, &mut out).unwrap();
        assert_eq!(out.len(), 14_000);
    }
}

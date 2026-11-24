//! Opus through the reference libopus (C, BSD-3-Clause), built from the source bundled in
//! opusic-sys (BSD-3-Clause) with CMake. Opt-in (`libopus`): the default build is pure Rust.
//! Behaves as [`super::opus`], so the two can be swapped and compared.

use super::fmtp::{MaxBandwidth, OpusEncoderConfig};
use super::opus_packet;
use super::{AudioDecoder, AudioEncoder};
use crate::{Error, Result};
use opusic_sys as sys;

/// The rate Opus runs at in this crate.
pub const OPUS_RATE: u32 = 48_000;
const MAX_PACKET_SAMPLES: usize = 5760;
const MAX_PAYLOAD: usize = 4000;

fn bandwidth(b: MaxBandwidth) -> i32 {
    match b {
        MaxBandwidth::Narrowband => sys::OPUS_BANDWIDTH_NARROWBAND,
        MaxBandwidth::Mediumband => sys::OPUS_BANDWIDTH_MEDIUMBAND,
        MaxBandwidth::Wideband => sys::OPUS_BANDWIDTH_WIDEBAND,
        MaxBandwidth::Superwideband => sys::OPUS_BANDWIDTH_SUPERWIDEBAND,
        MaxBandwidth::Fullband => sys::OPUS_BANDWIDTH_FULLBAND,
    }
}

/// A libopus encoder.
pub struct LibOpusEncoder {
    st: *mut sys::OpusEncoder,
    config: OpusEncoderConfig,
    buf: Vec<u8>,
}

// SAFETY: the encoder state is owned by this value alone and libopus keeps no thread-local
// state; it may move between threads, never be shared (no `Sync`).
unsafe impl Send for LibOpusEncoder {}

impl LibOpusEncoder {
    /// An encoder set up as `config` says.
    pub fn new(config: OpusEncoderConfig) -> Result<Self> {
        if !OpusEncoderConfig::FRAME_MS.contains(&config.frame_ms)
            || !(1..=2).contains(&config.channels)
        {
            return Err(Error::Config(format!("libopus: {config:?}")));
        }
        let mut err = 0;
        // SAFETY: valid arguments; the result is checked before use.
        let st = unsafe {
            sys::opus_encoder_create(
                OPUS_RATE as i32,
                i32::from(config.channels),
                sys::OPUS_APPLICATION_VOIP,
                &mut err,
            )
        };
        if st.is_null() || err != sys::OPUS_OK {
            return Err(Error::Codec(format!("libopus encoder: error {err}")));
        }
        let mut e = Self {
            st,
            config: config.clone(),
            buf: vec![0; MAX_PAYLOAD],
        };
        e.ctl(
            sys::OPUS_SET_COMPLEXITY_REQUEST,
            i32::from(config.complexity.min(10)),
        );
        e.ctl(sys::OPUS_SET_VBR_REQUEST, i32::from(!config.cbr));
        e.ctl(sys::OPUS_SET_INBAND_FEC_REQUEST, i32::from(config.fec));
        e.ctl(sys::OPUS_SET_DTX_REQUEST, i32::from(config.dtx));
        e.ctl(
            sys::OPUS_SET_PACKET_LOSS_PERC_REQUEST,
            i32::from(config.packet_loss_percent.min(100)),
        );
        e.ctl(
            sys::OPUS_SET_MAX_BANDWIDTH_REQUEST,
            bandwidth(config.max_bandwidth),
        );
        e.ctl(
            sys::OPUS_SET_BITRATE_REQUEST,
            config.bitrate.clamp(6000, config.max_bitrate.max(6000)) as i32,
        );
        Ok(e)
    }

    fn ctl(&mut self, request: i32, value: i32) {
        // SAFETY: `st` is a live encoder and every request used takes one `opus_int32`.
        unsafe {
            sys::opus_encoder_ctl(self.st, request, value);
        }
    }
}

impl Drop for LibOpusEncoder {
    fn drop(&mut self) {
        // SAFETY: created by `opus_encoder_create`, destroyed once.
        unsafe { sys::opus_encoder_destroy(self.st) }
    }
}

impl AudioEncoder for LibOpusEncoder {
    fn name(&self) -> &'static str {
        "libopus"
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
                "libopus takes {} samples",
                frame * usize::from(self.config.channels)
            )));
        }
        // SAFETY: `pcm` holds `frame * channels` samples, `buf` MAX_PAYLOAD bytes.
        let n = unsafe {
            sys::opus_encode_float(
                self.st,
                pcm.as_ptr(),
                frame as i32,
                self.buf.as_mut_ptr(),
                MAX_PAYLOAD as i32,
            )
        };
        if n < 0 {
            return Err(Error::Codec(format!("libopus encode: error {n}")));
        }
        out.extend_from_slice(&self.buf[..n as usize]);
        Ok(())
    }

    fn set_target_bitrate(&mut self, bps: u32) {
        let bps = bps.clamp(6000, self.config.max_bitrate.max(6000));
        self.config.bitrate = bps;
        self.ctl(sys::OPUS_SET_BITRATE_REQUEST, bps as i32);
    }

    fn target_bitrate(&self) -> Option<u32> {
        Some(self.config.bitrate)
    }

    fn set_packet_loss(&mut self, fraction: f32) {
        let pct = (fraction.clamp(0.0, 1.0) * 100.0).round() as u8;
        self.config.packet_loss_percent = pct;
        self.ctl(sys::OPUS_SET_PACKET_LOSS_PERC_REQUEST, i32::from(pct));
    }

    fn set_fec(&mut self, enabled: bool) {
        self.config.fec = enabled;
        self.ctl(sys::OPUS_SET_INBAND_FEC_REQUEST, i32::from(enabled));
    }

    fn set_dtx(&mut self, enabled: bool) {
        self.config.dtx = enabled;
        self.ctl(sys::OPUS_SET_DTX_REQUEST, i32::from(enabled));
    }

    fn has_dtx(&self) -> bool {
        true
    }
}

/// A libopus decoder at 48 kHz.
pub struct LibOpusDecoder {
    st: *mut sys::OpusDecoder,
    channels: u16,
    buf: Vec<f32>,
}

// SAFETY: as for `LibOpusEncoder`.
unsafe impl Send for LibOpusDecoder {}

impl LibOpusDecoder {
    /// A decoder of `channels` (1 or 2) output channels.
    pub fn new(channels: u16) -> Result<Self> {
        if !(1..=2).contains(&channels) {
            return Err(Error::Config(format!("libopus channels {channels}")));
        }
        let mut err = 0;
        // SAFETY: valid arguments; the result is checked before use.
        let st =
            unsafe { sys::opus_decoder_create(OPUS_RATE as i32, i32::from(channels), &mut err) };
        if st.is_null() || err != sys::OPUS_OK {
            return Err(Error::Codec(format!("libopus decoder: error {err}")));
        }
        Ok(Self {
            st,
            channels,
            buf: vec![0.0; MAX_PACKET_SAMPLES * usize::from(channels)],
        })
    }

    fn run(&mut self, data: Option<&[u8]>, frame: usize, fec: bool) -> Result<usize> {
        let (ptr, len) = match data {
            Some(d) => (d.as_ptr(), d.len() as i32),
            None => (std::ptr::null(), 0),
        };
        // SAFETY: `buf` holds MAX_PACKET_SAMPLES * channels samples and `frame` is at most
        // MAX_PACKET_SAMPLES; a null packet asks for concealment.
        let n = unsafe {
            sys::opus_decode_float(
                self.st,
                ptr,
                len,
                self.buf.as_mut_ptr(),
                frame.min(MAX_PACKET_SAMPLES) as i32,
                i32::from(fec),
            )
        };
        if n < 0 {
            return Err(Error::Codec(format!("libopus decode: error {n}")));
        }
        Ok(n as usize)
    }
}

impl Drop for LibOpusDecoder {
    fn drop(&mut self) {
        // SAFETY: created by `opus_decoder_create`, destroyed once.
        unsafe { sys::opus_decoder_destroy(self.st) }
    }
}

impl AudioDecoder for LibOpusDecoder {
    fn name(&self) -> &'static str {
        "libopus"
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
        let n = self.run(Some(payload), MAX_PACKET_SAMPLES, false)?;
        out.extend_from_slice(&self.buf[..n * usize::from(self.channels)]);
        Ok(n)
    }

    fn conceal(&mut self, samples: usize, out: &mut Vec<f32>) -> Result<bool> {
        let ch = usize::from(self.channels);
        let mut left = samples.div_ceil(120) * 120;
        let mut produced = 0;
        while left > 0 {
            let n = left.min(MAX_PACKET_SAMPLES);
            let got = self.run(None, n, false)?;
            let take = got.min(samples - produced);
            out.extend_from_slice(&self.buf[..take * ch]);
            produced += take;
            left -= n;
        }
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
        let n = self.run(Some(next_payload), samples, true)?;
        out.extend_from_slice(&self.buf[..n * usize::from(self.channels)]);
        Ok(true)
    }

    fn fec_samples(&self, payload: &[u8]) -> Option<usize> {
        opus_packet::has_lbrr(payload)
            .then(|| opus_packet::toc(payload[0]).frame_samples_48k as usize)
    }

    fn is_dtx(&self, payload: &[u8]) -> bool {
        payload.len() <= 2
    }

    fn reset(&mut self) {
        // SAFETY: OPUS_RESET_STATE takes no argument.
        unsafe {
            sys::opus_decoder_ctl(self.st, sys::OPUS_RESET_STATE);
        }
    }
}

/// libopus's own LBRR test, for checking [`opus_packet::has_lbrr`] against the reference.
pub fn reference_has_lbrr(packet: &[u8]) -> bool {
    // SAFETY: reads `packet.len()` bytes.
    unsafe { sys::opus_packet_has_lbrr(packet.as_ptr(), packet.len() as i32) > 0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SpeechLike, snr_db};

    #[test]
    fn both_backends_decode_each_others_packets_alike() {
        let mut s = SpeechLike::new(48_000, 2);
        let mut x = vec![0.0f32; 96_000];
        s.fill(&mut x);
        let config = OpusEncoderConfig {
            fec: true,
            packet_loss_percent: 10,
            ..Default::default()
        };
        let mut rust_enc = crate::codec::opus::OpusEncoder::new(config.clone()).unwrap();
        let mut c_enc = LibOpusEncoder::new(config).unwrap();
        let mut packets = (Vec::new(), Vec::new());
        for f in x.as_chunks::<960>().0 {
            let mut p = Vec::new();
            rust_enc.encode(f, &mut p).unwrap();
            packets.0.push(p);
            let mut p = Vec::new();
            c_enc.encode(f, &mut p).unwrap();
            packets.1.push(p);
        }
        // The LBRR parser agrees with libopus on every packet of both encoders.
        for p in packets.0.iter().chain(&packets.1) {
            assert_eq!(opus_packet::has_lbrr(p), reference_has_lbrr(p));
        }
        // Each encoder's stream decodes to the same audio in both decoders.
        for stream in [&packets.0, &packets.1] {
            let mut a = crate::codec::opus::OpusDecoder::new(1).unwrap();
            let mut b = LibOpusDecoder::new(1).unwrap();
            let (mut ya, mut yb) = (Vec::new(), Vec::new());
            for p in stream {
                a.decode(p, &mut ya).unwrap();
                b.decode(p, &mut yb).unwrap();
            }
            assert!(snr_db(&yb, &ya) > 40.0, "{}", snr_db(&yb, &ya));
        }
    }
}

/// opus-rs against the reference libopus, both ways: every packet one implementation encodes
/// decodes in the other with the same final range-coder state (RFC 6716 section 6's
/// conformance criterion, as `opus_demo` checks it), at every bitrate the send pipeline can
/// reach and with libopus in the modes browsers encode in.
#[cfg(test)]
mod opus_interop {
    use super::*;
    use crate::codec::fmtp::{OpusEncoderConfig, OpusFmtp};
    use crate::processing::ProcessingConfig;
    use crate::send::{SendCodec, SendConfig, SendOutput, SendPipeline};
    use crate::signal::Tone;

    fn rms(x: &[f32]) -> f64 {
        (x.iter().map(|v| f64::from(*v).powi(2)).sum::<f64>() / x.len().max(1) as f64).sqrt()
    }

    fn final_range_of_decoder(d: &LibOpusDecoder) -> u32 {
        let mut r: u32 = 0;
        // SAFETY: a live decoder; the request writes one opus_uint32.
        unsafe {
            sys::opus_decoder_ctl(d.st, sys::OPUS_GET_FINAL_RANGE_REQUEST, &mut r as *mut u32)
        };
        r
    }

    fn final_range_of_encoder(e: &LibOpusEncoder) -> u32 {
        let mut r: u32 = 0;
        // SAFETY: a live encoder; the request writes one opus_uint32.
        unsafe {
            sys::opus_encoder_ctl(e.st, sys::OPUS_GET_FINAL_RANGE_REQUEST, &mut r as *mut u32)
        };
        r
    }

    /// 3 s of a 440 Hz tone in 20 ms frames.
    fn tone_frames(amplitude: f32) -> Vec<Vec<f32>> {
        let mut tone = Tone::new(48_000, 440.0, amplitude);
        (0..150)
            .map(|_| {
                let mut x = vec![0f32; 960];
                tone.fill(&mut x);
                x
            })
            .collect()
    }

    #[test]
    fn opus_rs_packets_decode_bit_exactly_in_libopus_up_to_510_kbps() {
        for amplitude in [0.25f32, 1.0] {
            for fec in [false, true] {
                for bitrate in [16_000, 32_000, 64_000, 128_000, 343_200, 510_000] {
                    let mut enc =
                        opus_rs::OpusEncoder::new(48_000, 1, opus_rs::Application::Voip).unwrap();
                    enc.bitrate_bps = bitrate;
                    enc.use_inband_fec = fec;
                    enc.packet_loss_perc = if fec { 10 } else { 0 };
                    let mut dec = LibOpusDecoder::new(2).unwrap();
                    let (mut out, mut y) = (vec![0u8; MAX_PAYLOAD], Vec::new());
                    for (i, x) in tone_frames(amplitude).iter().enumerate() {
                        let n = enc.encode(x, 960, &mut out).unwrap();
                        dec.decode(&out[..n], &mut y).unwrap();
                        assert_eq!(
                            final_range_of_decoder(&dec),
                            enc.final_range(),
                            "packet {i} at {bitrate} bit/s, amplitude {amplitude}, FEC {fec}"
                        );
                    }
                    // Stereo output of a mono stream: both channels carry the tone.
                    let level = rms(&y[y.len() / 2..]);
                    let want = f64::from(amplitude) / 2f64.sqrt();
                    assert!(
                        (level / want - 1.0).abs() < 0.12,
                        "{bitrate} bit/s, amplitude {amplitude}: RMS {level}, want {want}"
                    );
                }
            }
        }
    }

    /// The interop peer's sender in train 13 round 5: the receiver's fmtp as Chromium offers
    /// it, processing off, and the congestion controller's share for one audio stream (Chromium
    /// counted 858-byte payloads). libopus, Chromium's decoder, hears the tone.
    #[test]
    fn the_send_pipeline_at_a_high_congestion_target_decodes_with_energy_in_libopus() {
        let mut p = SendPipeline::new(SendConfig {
            codec: SendCodec::Opus(OpusEncoderConfig::for_remote(
                &OpusFmtp::parse("minptime=10;useinbandfec=1"),
                None,
                None,
                1,
            )),
            processing: ProcessingConfig::OFF,
            ..Default::default()
        })
        .unwrap();
        p.set_target_bitrate(366_400.0);
        assert_eq!(p.stats().target_bitrate, Some(343_200));
        let mut tone = Tone::new(48_000, 440.0, 0.25);
        let mut dec = LibOpusDecoder::new(2).unwrap();
        let (mut y, mut packets, mut bytes) = (Vec::new(), 0, 0);
        for _ in 0..300 {
            let mut samples = vec![0f32; 480];
            tone.fill(&mut samples);
            let frame = crate::AudioFrame {
                samples,
                sample_rate: 48_000,
                channels: 1,
            };
            for o in p.push_capture(&frame).unwrap() {
                if let SendOutput::Packet { payload, .. } = o {
                    packets += 1;
                    bytes += payload.len();
                    dec.decode(&payload, &mut y).unwrap();
                }
            }
        }
        assert_eq!(packets, 150);
        assert!(bytes / packets > 800, "{} bytes a packet", bytes / packets);
        let level = rms(&y[y.len() / 2..]);
        assert!(level > 0.15, "libopus decoded RMS {level}");
    }

    #[test]
    fn libopus_packets_decode_bit_exactly_in_opus_rs() {
        for amplitude in [0.25f32, 1.0] {
            for application in [sys::OPUS_APPLICATION_VOIP, sys::OPUS_APPLICATION_AUDIO] {
                for (fec, loss) in [(false, 0), (true, 10)] {
                    for bitrate in [24_000u32, 32_000, 64_000, 128_000] {
                        let mut enc = LibOpusEncoder::new(OpusEncoderConfig {
                            bitrate,
                            fec,
                            packet_loss_percent: loss,
                            ..Default::default()
                        })
                        .unwrap();
                        enc.ctl(sys::OPUS_SET_APPLICATION_REQUEST, application);
                        let mut dec = opus_rs::OpusDecoder::new(48_000, 1).unwrap();
                        let (mut buf, mut y) = (vec![0f32; MAX_PACKET_SAMPLES], Vec::new());
                        for (i, x) in tone_frames(amplitude).iter().enumerate() {
                            let mut p = Vec::new();
                            enc.encode(x, &mut p).unwrap();
                            let n = dec.decode(&p, MAX_PACKET_SAMPLES, &mut buf).unwrap();
                            y.extend_from_slice(&buf[..n]);
                            assert_eq!(
                                dec.final_range(),
                                final_range_of_encoder(&enc),
                                "packet {i}: application {application}, {bitrate} bit/s, FEC {fec}"
                            );
                        }
                        let level = rms(&y[y.len() / 2..]);
                        let want = f64::from(amplitude) / 2f64.sqrt();
                        assert!(
                            (level / want - 1.0).abs() < 0.12,
                            "{bitrate} bit/s: RMS {level}, want {want}"
                        );
                    }
                }
            }
        }
    }

    /// What a browser sends from a silent source: libopus's packets of digital silence decode
    /// in opus-rs to an RMS of about 2.7e-6 (-111 dBFS), the `decodedRms` the interop peer
    /// reported for Firefox in train 13 round 5, five orders below the full-scale tone.
    #[test]
    fn libopus_digital_silence_decodes_in_opus_rs_far_below_a_tone() {
        for (amplitude, low, high) in [(0.0f32, 0.0, 1e-5), (1.0, 0.5, 1.0)] {
            let mut enc = LibOpusEncoder::new(OpusEncoderConfig {
                bitrate: 32_000,
                fec: true,
                ..Default::default()
            })
            .unwrap();
            let mut dec = crate::codec::opus::OpusDecoder::new(1).unwrap();
            let mut y = Vec::new();
            for x in tone_frames(amplitude) {
                let mut p = Vec::new();
                enc.encode(&x, &mut p).unwrap();
                dec.decode(&p, &mut y).unwrap();
            }
            let level = rms(&y);
            assert!(
                (low..=high).contains(&level),
                "amplitude {amplitude}: RMS {level}"
            );
        }
    }
}

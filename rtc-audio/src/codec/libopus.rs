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

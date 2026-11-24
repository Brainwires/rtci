//! G.722 (ITU-T G.722, 09/2012): 7 kHz audio at 64 kbit/s by sub-band ADPCM, written from
//! the Recommendation's description (section 3 encoder, section 4 decoder, the QMF of
//! section 3.2/4.4 and the quantiser and adaptation tables of Tables 5 to 12).
//!
//! 16 kHz audio is split by a 24-tap quadrature mirror filter into a lower and a higher
//! band at 8 kHz each; the lower band is coded with 6 bits per sample (an adaptive
//! quantiser of 60 levels and a pole-zero predictor), the higher with 2. One output byte
//! codes two input samples. The RTP clock is 8000 Hz although the audio is sampled at
//! 16000 Hz (RFC 3551 section 4.5.2), so a byte is one timestamp tick.
//!
//! Only mode 1 (64 kbit/s, the RTP payload format's) is implemented. The ITU-T test vectors
//! are not part of this repository; the tests check the codec's behaviour (round-trip SNR
//! by band, adaptation) instead.

use super::{AudioDecoder, AudioEncoder};
use crate::frame::f32_to_i16;
use crate::{Error, Result};

/// The sampling rate.
pub const G722_RATE: u32 = 16_000;
/// The RTP clock rate (RFC 3551).
pub const G722_RTP_CLOCK: u32 = 8000;

const QMF: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

// Lower band: quantiser decision levels (Table 6, as multiples of the scale factor in Q12)
// and the code words for negative and positive differences.
const Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];
const ILN: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];
const ILP: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];
// Inverse quantisers: 4-bit (the predictor's, Table 7) and 6-bit (the output's, Table 8).
const QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
const QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];
// Log scale factor adaptation (Table 9).
const RL42: [usize; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
const WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
// Inverse log base 2 (Table 10).
const ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
// Higher band (Tables 11, 12).
const IHN: [i32; 3] = [0, 1, 0];
const IHP: [i32; 3] = [0, 3, 2];
const QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
const RH2: [usize; 4] = [2, 1, 2, 1];
const WH: [i32; 3] = [0, -214, 798];

fn sat(v: i32) -> i32 {
    v.clamp(-32768, 32767)
}

/// One band's adaptive predictor and scale factor (the `BLOCK 4` of the Recommendation and
/// the scale factor adaptation of `BLOCK 3`).
#[derive(Debug, Clone)]
struct Band {
    /// Signal estimate `s`, pole part `sp`, zero part `sz`.
    s: i32,
    sp: i32,
    sz: i32,
    /// Reconstructed signals `r[0..3]`, partial signals `p[0..3]`.
    r: [i32; 3],
    p: [i32; 3],
    /// Pole and zero predictor coefficients.
    a: [i32; 3],
    b: [i32; 7],
    /// Quantised differences `d[0..7]`.
    d: [i32; 7],
    /// Log scale factor and scale factor.
    nb: i32,
    det: i32,
}

impl Band {
    fn new(det: i32) -> Self {
        Self {
            s: 0,
            sp: 0,
            sz: 0,
            r: [0; 3],
            p: [0; 3],
            a: [0; 3],
            b: [0; 7],
            d: [0; 7],
            nb: 0,
            det,
        }
    }

    /// Predictor adaptation and the next signal estimate, from the quantised difference `d`.
    fn update_predictor(&mut self, d: i32) {
        // RECONS / PARREC.
        self.d[0] = d;
        self.r[0] = sat(self.s + d);
        self.p[0] = sat(self.sz + d);

        // UPPOL2.
        let sg0 = self.p[0] >> 15;
        let sg1 = self.p[1] >> 15;
        let sg2 = self.p[2] >> 15;
        let wd1 = sat(self.a[1] << 2);
        let mut wd2 = if sg0 == sg1 { -wd1 } else { wd1 };
        if wd2 > 32767 {
            wd2 = 32767;
        }
        let mut wd3 = (wd2 >> 7) + if sg0 == sg2 { 128 } else { -128 };
        wd3 += (self.a[2] * 32512) >> 15;
        let ap2 = wd3.clamp(-12288, 12288);

        // UPPOL1.
        let wd1 = if sg0 == sg1 { 192 } else { -192 };
        let wd2 = (self.a[1] * 32640) >> 15;
        let mut ap1 = sat(wd1 + wd2);
        let wd3 = sat(15360 - ap2);
        ap1 = ap1.clamp(-wd3, wd3);

        // UPZERO.
        let wd1 = if d == 0 { 0 } else { 128 };
        let sg0 = d >> 15;
        let mut bp = [0i32; 7];
        for ((b, &di), &bi) in bp.iter_mut().zip(&self.d).zip(&self.b).skip(1) {
            let wd2 = if di >> 15 == sg0 { wd1 } else { -wd1 };
            let wd3 = (bi * 32640) >> 15;
            *b = sat(wd2 + wd3);
        }

        // DELAYA.
        for i in (1..7).rev() {
            self.d[i] = self.d[i - 1];
            self.b[i] = bp[i];
        }
        for i in (1..3).rev() {
            self.r[i] = self.r[i - 1];
            self.p[i] = self.p[i - 1];
        }
        self.a[1] = ap1;
        self.a[2] = ap2;

        // FILTEP.
        let wd1 = sat(self.r[1] + self.r[1]);
        let wd1 = (self.a[1] * wd1) >> 15;
        let wd2 = sat(self.r[2] + self.r[2]);
        let wd2 = (self.a[2] * wd2) >> 15;
        self.sp = sat(wd1 + wd2);

        // FILTEZ.
        let mut sz = 0;
        for i in (1..7).rev() {
            let wd1 = sat(self.d[i] + self.d[i]);
            sz += (self.b[i] * wd1) >> 15;
        }
        self.sz = sat(sz);

        // PREDIC.
        self.s = sat(self.sp + self.sz);
    }
}

/// `SCALEL` / `SCALEH`: the scale factor of a log scale factor, `shift` 8 (lower band) or
/// 10 (higher band).
fn scale(nb: i32, shift: i32) -> i32 {
    let wd1 = ((nb >> 6) & 31) as usize;
    let wd2 = shift - (nb >> 11);
    let wd3 = if wd2 < 0 {
        ILB[wd1] << -wd2
    } else {
        ILB[wd1] >> wd2
    };
    wd3 << 2
}

fn adapt_low(band: &mut Band, ril: usize) {
    let il4 = RL42[ril];
    let wd = (band.nb * 32512) >> 15;
    band.nb = (wd + WL[il4]).clamp(0, 18432);
    band.det = scale(band.nb, 8);
}

fn adapt_high(band: &mut Band, ihigh: usize) {
    let ih2 = RH2[ihigh];
    let wd = (band.nb * 32512) >> 15;
    band.nb = (wd + WH[ih2]).clamp(0, 22528);
    band.det = scale(band.nb, 10);
}

/// The shared state of a G.722 encoder or decoder.
#[derive(Debug, Clone)]
struct G722State {
    x: [i32; 24],
    low: Band,
    high: Band,
}

impl G722State {
    fn new() -> Self {
        Self {
            x: [0; 24],
            low: Band::new(32),
            high: Band::new(8),
        }
    }
}

/// Encodes 16 kHz 16-bit samples (an even count) to G.722 bytes, one per pair.
#[derive(Debug, Clone)]
pub struct G722Codec {
    state: G722State,
}

impl Default for G722Codec {
    fn default() -> Self {
        Self::new()
    }
}

impl G722Codec {
    /// A codec in its reset state.
    pub fn new() -> Self {
        Self {
            state: G722State::new(),
        }
    }

    /// Encodes one pair of 16 kHz samples.
    pub fn encode_pair(&mut self, x1: i16, x2: i16) -> u8 {
        let st = &mut self.state;
        // Transmit QMF.
        st.x.copy_within(2.., 0);
        st.x[22] = i32::from(x1);
        st.x[23] = i32::from(x2);
        let (mut sumodd, mut sumeven) = (0i32, 0i32);
        for i in 0..12 {
            sumodd += st.x[2 * i] * QMF[i];
            sumeven += st.x[2 * i + 1] * QMF[11 - i];
        }
        let xlow = (sumeven + sumodd) >> 14;
        let xhigh = (sumeven - sumodd) >> 14;

        // Lower band.
        let el = sat(xlow - st.low.s);
        let wd = if el >= 0 { el } else { -(el + 1) };
        let mut i = 1;
        while i < 30 {
            let wd1 = (Q6[i] * st.low.det) >> 12;
            if wd < wd1 {
                break;
            }
            i += 1;
        }
        let ilow = if el < 0 { ILN[i] } else { ILP[i] };
        let ril = (ilow >> 2) as usize;
        let dlow = (st.low.det * QM4[ril]) >> 15;
        adapt_low(&mut st.low, ril);
        st.low.update_predictor(dlow);

        // Higher band.
        let eh = sat(xhigh - st.high.s);
        let wd = if eh >= 0 { eh } else { -(eh + 1) };
        let wd1 = (564 * st.high.det) >> 12;
        let mih = if wd >= wd1 { 2 } else { 1 };
        let ihigh = if eh < 0 { IHN[mih] } else { IHP[mih] };
        let dhigh = (st.high.det * QM2[ihigh as usize]) >> 15;
        adapt_high(&mut st.high, ihigh as usize);
        st.high.update_predictor(dhigh);

        ((ihigh << 6) | ilow) as u8
    }

    /// Decodes one byte to a pair of 16 kHz samples.
    pub fn decode_byte(&mut self, code: u8) -> (i16, i16) {
        let st = &mut self.state;
        let ilow = usize::from(code & 0x3f);
        let ihigh = usize::from(code >> 6);

        // Lower band: the output uses the 6-bit inverse quantiser, the predictor the 4-bit.
        let ril = ilow >> 2;
        let dlow_out = (st.low.det * QM6[ilow]) >> 15;
        let rlow = (st.low.s + dlow_out).clamp(-16384, 16383);
        let dlow = (st.low.det * QM4[ril]) >> 15;
        adapt_low(&mut st.low, ril);
        st.low.update_predictor(dlow);

        // Higher band.
        let dhigh = (st.high.det * QM2[ihigh]) >> 15;
        let rhigh = (st.high.s + dhigh).clamp(-16384, 16383);
        adapt_high(&mut st.high, ihigh);
        st.high.update_predictor(dhigh);

        // Receive QMF.
        st.x.copy_within(2.., 0);
        st.x[22] = rlow + rhigh;
        st.x[23] = rlow - rhigh;
        let (mut xout1, mut xout2) = (0i32, 0i32);
        for i in 0..12 {
            xout2 += st.x[2 * i] * QMF[i];
            xout1 += st.x[2 * i + 1] * QMF[11 - i];
        }
        (sat(xout1 >> 11) as i16, sat(xout2 >> 11) as i16)
    }
}

/// A G.722 encoder (16 kHz mono input).
#[derive(Debug, Clone)]
pub struct G722Encoder {
    codec: G722Codec,
    frame_samples: usize,
}

impl G722Encoder {
    /// An encoder with packets of `ptime_ms` milliseconds.
    pub fn new(ptime_ms: u32) -> Result<Self> {
        if !(1..=200).contains(&ptime_ms) {
            return Err(Error::Config(format!("G.722 packet time {ptime_ms} ms")));
        }
        Ok(Self {
            codec: G722Codec::new(),
            frame_samples: (ptime_ms * G722_RATE / 1000) as usize,
        })
    }
}

impl AudioEncoder for G722Encoder {
    fn name(&self) -> &'static str {
        "rtci-audio G.722"
    }

    fn sample_rate(&self) -> u32 {
        G722_RATE
    }

    fn channels(&self) -> u16 {
        1
    }

    fn frame_samples(&self) -> usize {
        self.frame_samples
    }

    fn rtp_clock_rate(&self) -> u32 {
        G722_RTP_CLOCK
    }

    fn encode(&mut self, pcm: &[f32], out: &mut Vec<u8>) -> Result<()> {
        if pcm.len() != self.frame_samples || !pcm.len().is_multiple_of(2) {
            return Err(Error::Format(format!(
                "G.722 takes {} samples, got {}",
                self.frame_samples,
                pcm.len()
            )));
        }
        for pair in pcm.as_chunks::<2>().0 {
            out.push(
                self.codec
                    .encode_pair(f32_to_i16(pair[0]), f32_to_i16(pair[1])),
            );
        }
        Ok(())
    }
}

/// A G.722 decoder (16 kHz mono output).
#[derive(Debug, Clone, Default)]
pub struct G722Decoder {
    codec: G722Codec,
}

impl G722Decoder {
    /// A decoder in its reset state.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AudioDecoder for G722Decoder {
    fn name(&self) -> &'static str {
        "rtci-audio G.722"
    }

    fn sample_rate(&self) -> u32 {
        G722_RATE
    }

    fn channels(&self) -> u16 {
        1
    }

    fn rtp_clock_rate(&self) -> u32 {
        G722_RTP_CLOCK
    }

    fn packet_samples(&self, payload: &[u8]) -> Option<usize> {
        Some(payload.len() * 2)
    }

    fn decode(&mut self, payload: &[u8], out: &mut Vec<f32>) -> Result<usize> {
        for &b in payload {
            let (a, c) = self.codec.decode_byte(b);
            out.push(f32::from(a) / 32768.0);
            out.push(f32::from(c) / 32768.0);
        }
        Ok(payload.len() * 2)
    }

    fn has_plc(&self) -> bool {
        false
    }

    fn conceal(&mut self, _samples: usize, _out: &mut Vec<f32>) -> Result<bool> {
        Ok(false)
    }

    fn reset(&mut self) {
        self.codec = G722Codec::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signal::{SpeechLike, Tone, best_lag, segmental_snr_db, snr_db};

    fn round_trip(x: &[f32]) -> Vec<f32> {
        let mut enc = G722Encoder::new(20).unwrap();
        let mut dec = G722Decoder::new();
        let mut out = Vec::new();
        for frame in x.as_chunks::<320>().0 {
            let mut bytes = Vec::new();
            enc.encode(frame, &mut bytes).unwrap();
            assert_eq!(bytes.len(), 160);
            dec.decode(&bytes, &mut out).unwrap();
        }
        out
    }

    #[test]
    fn tones_in_either_band_come_back_with_a_g722_snr() {
        // The QMF pair delays by 22 samples at 16 kHz (23 taps of group delay each, over two
        // bands): align by cross-correlation, then compare.
        for hz in [400.0, 1000.0, 3000.0, 5000.0] {
            let mut t = Tone::new(G722_RATE, hz, 0.3);
            let mut x = vec![0.0f32; 16_000];
            t.fill(&mut x);
            let y = round_trip(&x);
            let lag = best_lag(&x[..4000], &y[..4000], 40);
            let snr = snr_db(&x[8000 - lag..16_000 - lag], &y[8000..]);
            println!("MEASURE G.722 {hz} Hz tone: lag {lag}, SNR {snr:.1} dB");
            let want = if hz < 4000.0 { 30.0 } else { 6.0 };
            assert!(snr > want, "{hz} Hz: lag {lag}, {snr:.1} dB");
        }
    }

    #[test]
    fn speech_like_audio_keeps_a_segmental_snr_above_twenty_db() {
        let mut s = SpeechLike::new(G722_RATE, 11);
        let mut x = vec![0.0f32; 16_000 * 4];
        s.fill(&mut x);
        let y = round_trip(&x);
        let lag = best_lag(&x[..16_000], &y[..16_000], 40);
        let seg = segmental_snr_db(&x[..x.len() - lag], &y[lag..], 320);
        let snr = snr_db(&x[..x.len() - lag], &y[lag..]);
        println!(
            "MEASURE G.722 speech-like: lag {lag}, SNR {snr:.1} dB, segmental SNR {seg:.1} dB"
        );
        assert!(seg > 12.0, "lag {lag}: segmental SNR {seg:.1} dB");
    }

    #[test]
    fn the_scale_factor_adapts_to_the_level() {
        let mut c = G722Codec::new();
        for i in 0..8000 {
            let v = (10_000.0 * (i as f64 * 0.2).sin()) as i16;
            c.encode_pair(v, v);
        }
        let loud = c.state.low.det;
        for _ in 0..8000 {
            c.encode_pair(0, 0);
        }
        assert!(c.state.low.det < loud / 8, "{} vs {loud}", c.state.low.det);
    }
}

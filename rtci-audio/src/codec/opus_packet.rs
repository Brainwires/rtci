//! Reading an Opus packet without decoding it (RFC 6716): its mode, bandwidth, channels and
//! duration from the TOC byte, the first frame's offset, and whether that frame carries
//! SILK's in-band FEC (LBRR), which takes the first few range-coded bits.

/// The coding mode (RFC 6716 section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusMode {
    /// SILK only (configurations 0 to 11).
    Silk,
    /// SILK and CELT (12 to 15).
    Hybrid,
    /// CELT only (16 to 31).
    Celt,
}

/// The audio bandwidth (RFC 6716 Table 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpusBandwidth {
    /// 4 kHz (8 kHz sampling).
    Narrowband,
    /// 6 kHz.
    Mediumband,
    /// 8 kHz.
    Wideband,
    /// 12 kHz.
    Superwideband,
    /// 20 kHz.
    Fullband,
}

/// What the TOC byte says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toc {
    /// The mode.
    pub mode: OpusMode,
    /// The bandwidth.
    pub bandwidth: OpusBandwidth,
    /// Samples per frame at 48 kHz.
    pub frame_samples_48k: u32,
    /// Stereo (`s` bit).
    pub stereo: bool,
    /// The frame count code `c` (0 to 3).
    pub code: u8,
}

/// Parses the TOC byte.
pub fn toc(byte: u8) -> Toc {
    let config = byte >> 3;
    let (mode, bandwidth, frame) = match config {
        0..=11 => {
            let bw = match config / 4 {
                0 => OpusBandwidth::Narrowband,
                1 => OpusBandwidth::Mediumband,
                _ => OpusBandwidth::Wideband,
            };
            (
                OpusMode::Silk,
                bw,
                [480, 960, 1920, 2880][usize::from(config & 3)],
            )
        }
        12..=15 => {
            let bw = if config < 14 {
                OpusBandwidth::Superwideband
            } else {
                OpusBandwidth::Fullband
            };
            (OpusMode::Hybrid, bw, [480, 960][usize::from(config & 1)])
        }
        _ => {
            let bw = match (config - 16) / 4 {
                0 => OpusBandwidth::Narrowband,
                1 => OpusBandwidth::Wideband,
                2 => OpusBandwidth::Superwideband,
                _ => OpusBandwidth::Fullband,
            };
            (
                OpusMode::Celt,
                bw,
                [120, 240, 480, 960][usize::from(config & 3)],
            )
        }
    };
    Toc {
        mode,
        bandwidth,
        frame_samples_48k: frame,
        stereo: byte & 0x4 != 0,
        code: byte & 0x3,
    }
}

/// The packet's duration at 48 kHz (its RTP timestamp span, RFC 7587 section 4.1).
pub fn packet_samples_48k(packet: &[u8]) -> Option<u32> {
    rtp::codec::opus::opus_packet_samples(packet)
}

/// The offset and length of the packet's first frame (RFC 6716 section 3.2).
pub fn first_frame(packet: &[u8]) -> Option<(usize, usize)> {
    let t = toc(*packet.first()?);
    let len = packet.len();
    match t.code {
        0 => Some((1, len - 1)),
        1 => {
            let rest = len - 1;
            rest.is_multiple_of(2).then_some((1, rest / 2))
        }
        2 => {
            let b0 = usize::from(*packet.get(1)?);
            let (size, bytes) = if b0 < 252 {
                (b0, 1)
            } else {
                (b0 + 4 * usize::from(*packet.get(2)?), 2)
            };
            let start = 1 + bytes;
            (start + size <= len).then_some((start, size))
        }
        _ => {
            let fc = *packet.get(1)?;
            let frames = usize::from(fc & 0x3f);
            let vbr = fc & 0x80 != 0;
            let padded = fc & 0x40 != 0;
            if frames == 0 {
                return None;
            }
            let mut pos = 2;
            let mut padding = 0usize;
            if padded {
                loop {
                    let p = usize::from(*packet.get(pos)?);
                    pos += 1;
                    if p == 255 {
                        padding += 254;
                    } else {
                        padding += p;
                        break;
                    }
                }
            }
            let payload_end = len.checked_sub(padding)?;
            if vbr {
                let mut first = None;
                for _ in 0..frames - 1 {
                    let b0 = usize::from(*packet.get(pos)?);
                    let size = if b0 < 252 {
                        pos += 1;
                        b0
                    } else {
                        let s = b0 + 4 * usize::from(*packet.get(pos + 1)?);
                        pos += 2;
                        s
                    };
                    first.get_or_insert(size);
                }
                let size = first.unwrap_or(payload_end.checked_sub(pos)?);
                (pos + size <= payload_end).then_some((pos, size))
            } else {
                let data = payload_end.checked_sub(pos)?;
                (data % frames == 0).then_some((pos, data / frames))
            }
        }
    }
}

/// The start of a range decoder (RFC 6716 section 4.1), enough to read the first bits.
struct RangeDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
    rng: u32,
    val: u32,
    rem: u32,
}

impl<'a> RangeDecoder<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let mut d = Self {
            buf,
            pos: 0,
            rng: 128,
            val: 0,
            rem: 0,
        };
        d.rem = d.read();
        d.val = d.rng - 1 - (d.rem >> 1);
        d.normalize();
        d
    }

    fn read(&mut self) -> u32 {
        let b = self.buf.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        u32::from(b)
    }

    fn normalize(&mut self) {
        while self.rng <= 1 << 23 {
            self.rng <<= 8;
            let sym = self.rem;
            self.rem = self.read();
            let sym = ((sym << 8) | self.rem) >> 1;
            self.val = ((self.val << 8) + (255 & !sym)) & ((1u32 << 31) - 1);
        }
    }

    /// `ec_dec_bit_logp`: a bit whose probability of being 1 is `1 / 2^logp`.
    fn bit_logp(&mut self, logp: u32) -> bool {
        let s = self.rng >> logp;
        let one = self.val < s;
        if one {
            self.rng = s;
        } else {
            self.val -= s;
            self.rng -= s;
        }
        self.normalize();
        one
    }
}

/// Whether the packet's first frame carries SILK LBRR (in-band FEC) data for the frame
/// before it: SILK-only and Hybrid packets only (RFC 6716 section 4.2.4; libopus
/// `opus_packet_has_lbrr`).
pub fn has_lbrr(packet: &[u8]) -> bool {
    let Some(&byte) = packet.first() else {
        return false;
    };
    let t = toc(byte);
    if t.mode == OpusMode::Celt {
        return false;
    }
    let Some((start, size)) = first_frame(packet) else {
        return false;
    };
    if size == 0 {
        return false;
    }
    // SILK frames per Opus frame: 20 ms frames, a 10 ms Opus frame is one 10 ms SILK frame.
    let silk_frames = (t.frame_samples_48k / 960).max(1);
    let mut rd = RangeDecoder::new(&packet[start..start + size]);
    let channels = if t.stereo { 2 } else { 1 };
    let mut lbrr = false;
    for _ in 0..channels {
        for _ in 0..silk_frames {
            rd.bit_logp(1); // VAD flag
        }
        lbrr |= rd.bit_logp(1);
    }
    lbrr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_toc_says_mode_bandwidth_and_duration() {
        // Config 1: SILK NB 20 ms.
        let t = toc(1 << 3);
        assert_eq!(
            (t.mode, t.bandwidth, t.frame_samples_48k),
            (OpusMode::Silk, OpusBandwidth::Narrowband, 960)
        );
        let t = toc((15 << 3) | 0x4);
        assert_eq!(
            (t.mode, t.bandwidth, t.frame_samples_48k, t.stereo),
            (OpusMode::Hybrid, OpusBandwidth::Fullband, 960, true)
        );
        let t = toc(31 << 3);
        assert_eq!(
            (t.mode, t.bandwidth, t.frame_samples_48k),
            (OpusMode::Celt, OpusBandwidth::Fullband, 960)
        );
    }

    #[test]
    fn the_first_frame_is_found_for_every_frame_count_code() {
        assert_eq!(first_frame(&[0x08, 1, 2, 3]), Some((1, 3)));
        assert_eq!(first_frame(&[0x09, 1, 2, 3, 4]), Some((1, 2)));
        assert_eq!(first_frame(&[0x09, 1, 2, 3]), None);
        assert_eq!(first_frame(&[0x0a, 2, 9, 9, 8]), Some((2, 2)));
        // Code 3, CBR, 2 frames, no padding.
        assert_eq!(first_frame(&[0x0b, 0x02, 1, 2, 3, 4]), Some((2, 2)));
        // Code 3, VBR, 2 frames, padding 1: first frame 1 byte.
        assert_eq!(first_frame(&[0x0b, 0xc2, 1, 1, 7, 8, 9, 0]), Some((4, 1)));
    }

    #[test]
    fn a_celt_packet_never_has_lbrr() {
        assert!(!has_lbrr(&[31 << 3, 0xff, 0xff, 0xff]));
        assert!(!has_lbrr(&[]));
        assert!(!has_lbrr(&[0x08]));
    }
}

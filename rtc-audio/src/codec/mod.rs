//! Audio codecs behind two traits, [`AudioEncoder`] and [`AudioDecoder`].
//!
//! | Codec | Module | Feature | Notes |
//! |---|---|---|---|
//! | Opus | [`opus`] | `opus` (default) | opus-rs, pure Rust (a port of libopus 1.6): FEC, DTX, PLC |
//! | Opus | [`libopus`] | `libopus` | the reference C libopus (bundled, through opusic-sys) |
//! | PCMU / PCMA | [`g711`] | - | ITU-T G.711, this crate's |
//! | G.722 | [`g722`] | - | ITU-T G.722 at 64 kbit/s, this crate's |
//!
//! The pipeline's PLC covers codecs without their own ([`AudioDecoder::conceal`] returns
//! `false`); comfort noise for those that have no DTX is RFC 3389 ([`crate::dsp::cng`]).

pub mod fmtp;
pub mod g711;
pub mod g722;
#[cfg(feature = "libopus")]
pub mod libopus;
#[cfg(feature = "opus")]
pub mod opus;
pub mod opus_packet;

use crate::Result;

/// Decodes one stream's payloads to interleaved `f32` PCM.
pub trait AudioDecoder: Send {
    /// The implementation's name (the W3C `decoderImplementation`).
    fn name(&self) -> &'static str;
    /// The rate of the decoded audio.
    fn sample_rate(&self) -> u32;
    /// The channels of the decoded audio.
    fn channels(&self) -> u16;
    /// The RTP clock rate of the payload format (timestamps count at this rate).
    fn rtp_clock_rate(&self) -> u32 {
        self.sample_rate()
    }
    /// The samples per channel `payload` decodes to, at [`sample_rate`](Self::sample_rate),
    /// if the payload says.
    fn packet_samples(&self, payload: &[u8]) -> Option<usize>;
    /// Decodes `payload`, appending interleaved samples to `out`. Returns the samples per
    /// channel appended.
    fn decode(&mut self, payload: &[u8], out: &mut Vec<f32>) -> Result<usize>;
    /// Whether the codec has concealment of its own ([`conceal`](Self::conceal)); without it
    /// the pipeline repeats the last pitch period.
    fn has_plc(&self) -> bool {
        true
    }
    /// Conceals `samples` samples per channel of lost audio with the codec's own concealment,
    /// appending them to `out`. `Ok(false)`, appending nothing, when the codec has none and
    /// the pipeline's generic concealment is to be used.
    fn conceal(&mut self, samples: usize, out: &mut Vec<f32>) -> Result<bool>;
    /// Recovers the audio just before `next_payload` from the redundant copy that
    /// `next_payload` carries (Opus in-band FEC, RFC 7587 section 3.3), `samples` per
    /// channel, appending to `out`. `Ok(false)` when there is none.
    fn decode_fec(
        &mut self,
        _next_payload: &[u8],
        _samples: usize,
        _out: &mut Vec<f32>,
    ) -> Result<bool> {
        Ok(false)
    }
    /// How much audio before `payload` its redundant copy covers, in samples per channel:
    /// `Some` when `payload` carries in-band FEC.
    fn fec_samples(&self, _payload: &[u8]) -> Option<usize> {
        None
    }
    /// Whether `payload` starts discontinuous transmission (Opus: a packet of the TOC byte
    /// alone, RFC 7587 section 3.1.3). The decoder then makes comfort noise of its own
    /// through [`conceal`](Self::conceal) until the next packet.
    fn is_dtx(&self, _payload: &[u8]) -> bool {
        false
    }
    /// Forgets all state (a new stream).
    fn reset(&mut self);
}

/// Encodes PCM frames to payloads.
pub trait AudioEncoder: Send {
    /// The implementation's name (the W3C `encoderImplementation`).
    fn name(&self) -> &'static str;
    /// The rate of the input audio.
    fn sample_rate(&self) -> u32;
    /// The channels of the input audio.
    fn channels(&self) -> u16;
    /// The samples per channel of each frame [`encode`](Self::encode) takes (the packet time).
    fn frame_samples(&self) -> usize;
    /// The RTP clock rate of the payload format.
    fn rtp_clock_rate(&self) -> u32 {
        self.sample_rate()
    }
    /// The RTP timestamp units one frame spans.
    fn frame_rtp_duration(&self) -> u32 {
        (self.frame_samples() as u64 * u64::from(self.rtp_clock_rate())
            / u64::from(self.sample_rate().max(1))) as u32
    }
    /// Encodes one frame (`frame_samples() * channels()` interleaved samples), appending the
    /// payload to `out`.
    fn encode(&mut self, pcm: &[f32], out: &mut Vec<u8>) -> Result<()>;
    /// Sets the target bitrate in bits per second (codecs of fixed rate ignore it).
    fn set_target_bitrate(&mut self, _bps: u32) {}
    /// The bitrate the encoder aims at, if it has one to choose.
    fn target_bitrate(&self) -> Option<u32> {
        None
    }
    /// Tells the encoder the packet loss the receiver reports (0 to 1).
    fn set_packet_loss(&mut self, _fraction: f32) {}
    /// Turns in-band FEC on or off (where the codec has it).
    fn set_fec(&mut self, _enabled: bool) {}
    /// Turns the codec's own DTX on or off (where it has one).
    fn set_dtx(&mut self, _enabled: bool) {}
    /// Whether the codec has its own discontinuous transmission.
    fn has_dtx(&self) -> bool {
        false
    }
}

//! The `audio/tone` payload format: telephony tones described by their frequencies (RFC 4733
//! section 4).
//!
//! A tone packet stands alone: unlike a telephone event it carries no history, so a tone
//! longer than one packet is a run of packets whose timestamps follow on from each other
//! ([`ToneSender`]).

#[cfg(test)]
mod tone_test;

use bytes::{BufMut, Bytes, BytesMut};
use shared::error::{Error, Result};

/// The default clock rate of `audio/tone` (RFC 4733 section 4.3.4).
pub const TONE_DEFAULT_CLOCK_RATE: u32 = 8000;

/// The largest modulation frequency, 9 bits (RFC 4733 section 4.3.3).
const MAX_MODULATION: u16 = 0x01FF;
/// The largest volume, 6 bits: 0 to -63 dBm0.
const MAX_VOLUME: u8 = 0x3F;
/// The largest frequency, 12 bits.
const MAX_FREQUENCY: u16 = 0x0FFF;

/// One tone report (RFC 4733 section 4.3.3, Figure 2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tone {
    /// The modulation frequency in Hz, 9 bits; 0 for none.
    pub modulation: u16,
    /// Whether the modulation frequency is to be divided by three (the T bit).
    pub modulation_divided_by_three: bool,
    /// The power level in dBm0 with the sign dropped, 0 to 63.
    pub volume: u8,
    /// How long the tone lasts from the packet's timestamp, in timestamp units. Never 0.
    pub duration: u16,
    /// The frequencies added together, in Hz, 12 bits each; 0 is silence, none is a period
    /// of silence.
    pub frequencies: Vec<u16>,
}

impl Tone {
    /// The payload. The reserved bits before each frequency are zero (section 4.3.3: "The
    /// sender MUST set it to zero"). A field out of its range, or a duration of 0 ("not
    /// permitted"), is refused.
    pub fn marshal(&self) -> Result<Bytes> {
        if self.modulation > MAX_MODULATION
            || self.volume > MAX_VOLUME
            || self.duration == 0
            || self.frequencies.iter().any(|f| *f > MAX_FREQUENCY)
        {
            return Err(Error::Other(format!("not a valid tone: {self:?}")));
        }
        let mut out = BytesMut::with_capacity(4 + 2 * self.frequencies.len());
        out.put_u16(
            (self.modulation << 7)
                | (u16::from(self.modulation_divided_by_three) << 6)
                | u16::from(self.volume),
        );
        out.put_u16(self.duration);
        for frequency in &self.frequencies {
            out.put_u16(*frequency);
        }
        Ok(out.freeze())
    }

    /// The tone in `payload`, the reserved bits ignored (section 4.3.3: "the receiver MUST
    /// ignore it"). `None` for a payload too short or of an odd length, and for a tone of
    /// duration 0, which "SHOULD be ignored".
    pub fn unmarshal(payload: &[u8]) -> Option<Tone> {
        if payload.len() < 4 || !payload.len().is_multiple_of(2) {
            return None;
        }
        let first = u16::from_be_bytes([payload[0], payload[1]]);
        let duration = u16::from_be_bytes([payload[2], payload[3]]);
        if duration == 0 {
            return None;
        }
        Some(Tone {
            modulation: first >> 7,
            modulation_divided_by_three: first & 0x40 != 0,
            volume: (first & 0x3F) as u8,
            duration,
            frequencies: payload[4..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair) & MAX_FREQUENCY)
                .collect(),
        })
    }
}

/// One packet of a tone: its RTP timestamp, marker bit and payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonePacket {
    /// The RTP timestamp.
    pub timestamp: u32,
    /// The marker bit: set on the first packet of a tone.
    pub marker: bool,
    /// The payload.
    pub payload: Bytes,
}

/// Cuts a tone into packets (RFC 4733 section 4.4.1): "The RTP timestamp MUST be updated for
/// each packet generated ... the RTP timestamp in each subsequent packet MUST equal the sum of
/// the timestamp and the duration in the preceding packet"; the first packet has the marker
/// set and the rest not (section 4.3.2).
#[derive(Debug, Clone, Copy)]
pub struct ToneSender {
    /// The duration of one packet in timestamp units.
    pub packet_duration: u16,
}

impl ToneSender {
    /// The packets of `tone` lasting `total` timestamp units from `timestamp`: each covers
    /// `packet_duration` or what is left, and starts where the one before ended.
    pub fn packets(&self, tone: &Tone, timestamp: u32, total: u32) -> Result<Vec<TonePacket>> {
        let step = u32::from(self.packet_duration.max(1));
        let mut packets = vec![];
        let mut at = 0u32;
        while at < total {
            let duration = (total - at).min(step) as u16;
            let report = Tone {
                duration,
                ..tone.clone()
            };
            packets.push(TonePacket {
                timestamp: timestamp.wrapping_add(at),
                marker: packets.is_empty(),
                payload: report.marshal()?,
            });
            at += u32::from(duration);
        }
        Ok(packets)
    }
}

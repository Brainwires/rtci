#[cfg(test)]
mod opus_test;

use crate::packetizer::{Depacketizer, MarkerRule, Payloader};
use shared::error::{Error, Result};

use bytes::Bytes;

/// The RTP clock rate of Opus, whatever the audio bandwidth coded (RFC 7587 section 4.1).
pub const OPUS_CLOCK_RATE: u32 = 48000;
/// The longest Opus packet, in samples at 48 kHz: 120 ms (RFC 6716 section 3.2.5).
pub const OPUS_MAX_PACKET_SAMPLES: u32 = 5760;
/// What DTX timestamp gaps are multiples of, in samples at 48 kHz: 2.5 ms, the shortest Opus
/// frame (RFC 7587 section 3.1.3).
pub const OPUS_DTX_TIMESTAMP_STEP: u32 = 120;

/// The duration of an Opus packet in samples at 48 kHz, which is its length in RTP timestamp
/// units (RFC 7587 section 4.1), read from the TOC byte and the frame count (RFC 6716 section
/// 3.1 and 3.2).
///
/// `None` for an empty packet, a code 3 packet without its frame count byte, a frame count of
/// zero, or a packet longer than 120 ms: none of them is an Opus packet (RFC 6716 section 3.4,
/// R1 and R5).
pub fn opus_packet_samples(packet: &[u8]) -> Option<u32> {
    let toc = *packet.first()?;
    let config = toc >> 3;
    // Samples per frame at 48 kHz, by configuration number (RFC 6716 Table 2).
    let frame_samples: u32 = match config {
        // SILK-only: 10, 20, 40, 60 ms.
        0..=11 => [480, 960, 1920, 2880][usize::from(config & 0x3)],
        // Hybrid: 10, 20 ms.
        12..=15 => [480, 960][usize::from(config & 0x1)],
        // CELT-only: 2.5, 5, 10, 20 ms.
        _ => [120, 240, 480, 960][usize::from(config & 0x3)],
    };
    let frames = match toc & 0x3 {
        0 => 1,
        1 | 2 => 2,
        _ => u32::from(*packet.get(1)? & 0x3F),
    };
    let samples = frame_samples * frames;
    (frames > 0 && samples <= OPUS_MAX_PACKET_SAMPLES).then_some(samples)
}

#[derive(Default, Debug, Copy, Clone)]
/// Packetizes Opus audio: one RTP payload per Opus packet, never fragmented and never
/// aggregated, whatever the MTU (RFC 7587 section 4.2).
///
/// The marker bit follows RFC 3551 (RFC 7587 section 4.1): set on the first packet after a
/// silence the caller skipped with
/// [`Packetizer::skip_samples`](crate::packetizer::Packetizer::skip_samples), which is how a
/// DTX gap is sent, and clear otherwise.
pub struct OpusPayloader;

impl Payloader for OpusPayloader {
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        Ok(vec![payload.clone()])
    }

    /// Audio: the marker is for the first packet of a talkspurt (RFC 7587 section 4.1).
    fn marker_rule(&self) -> MarkerRule {
        MarkerRule::FirstPacketOfTalkspurt
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

/// OpusPacket represents the Opus header that is stored in the payload of an RTP Packet
#[derive(PartialEq, Eq, Debug, Default, Clone)]
pub struct OpusPacket;

impl Depacketizer for OpusPacket {
    fn depacketize(&mut self, packet: &Bytes) -> Result<Bytes> {
        if packet.is_empty() {
            Err(Error::ErrShortPacket)
        } else {
            Ok(packet.clone())
        }
    }

    fn is_partition_head(&self, _payload: &Bytes) -> bool {
        true
    }

    fn is_partition_tail(&self, _marker: bool, _payload: &Bytes) -> bool {
        true
    }
}

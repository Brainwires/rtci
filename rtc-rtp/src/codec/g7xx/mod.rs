#[cfg(test)]
mod g7xx_test;

use crate::packetizer::{MarkerRule, Payloader};
use shared::error::Result;

use bytes::Bytes;

/// G711Payloader payloads G711 packets
pub type G711Payloader = G7xxPayloader;
/// G722Payloader payloads G722 packets
pub type G722Payloader = G7xxPayloader;

/// The static payload type of PCMU, G.711 mu-law at 8000 Hz (RFC 3551 section 6, Table 4).
pub const PCMU_PAYLOAD_TYPE: u8 = 0;
/// The static payload type of PCMA, G.711 A-law at 8000 Hz (RFC 3551 section 6, Table 4).
pub const PCMA_PAYLOAD_TYPE: u8 = 8;
/// The static payload type of G722 (RFC 3551 section 6, Table 4).
pub const G722_PAYLOAD_TYPE: u8 = 9;
/// The RTP clock rate of PCMU, PCMA and G722. G.722 samples at 16000 Hz, and its RTP clock is
/// 8000 Hz all the same (RFC 3551 section 4.5.2).
pub const G7XX_CLOCK_RATE: u32 = 8000;

#[derive(Default, Debug, Copy, Clone)]
/// Packetizes G.711/G.722 audio (RFC 3551 sections 4.5.2 and 4.5.14).
///
/// These are sample-based encodings (RFC 3551 section 4.3): a packet holds any whole number of
/// octets, so a buffer larger than the MTU is cut at the MTU and nothing else is needed. One
/// octet is one tick of the 8000 Hz RTP clock for one channel (a G.711 sample; half a G.722
/// sample pair), which is what gives each of those packets its own timestamp.
pub struct G7xxPayloader;

impl Payloader for G7xxPayloader {
    /// Payload fragments an G7xx packet across one or more byte arrays
    fn payload(&mut self, mtu: usize, payload: &Bytes) -> Result<Vec<Bytes>> {
        if payload.is_empty() || mtu == 0 {
            return Ok(vec![]);
        }

        let mut payload_data_remaining = payload.len();
        let mut payload_data_index = 0;
        let mut payloads = Vec::with_capacity(payload_data_remaining / mtu);
        while payload_data_remaining > 0 {
            let current_fragment_size = std::cmp::min(mtu, payload_data_remaining);
            payloads.push(
                payload.slice(payload_data_index..payload_data_index + current_fragment_size),
            );

            payload_data_remaining -= current_fragment_size;
            payload_data_index += current_fragment_size;
        }

        Ok(payloads)
    }

    /// Audio: the marker is for the first packet of a talkspurt (RFC 3551 section 4.1).
    fn marker_rule(&self) -> MarkerRule {
        MarkerRule::FirstPacketOfTalkspurt
    }

    /// One octet per tick of the 8000 Hz clock (single channel).
    fn payload_duration(&self, payload: &Bytes) -> Option<u32> {
        u32::try_from(payload.len()).ok()
    }

    fn clone_to(&self) -> Box<dyn Payloader> {
        Box::new(*self)
    }
}

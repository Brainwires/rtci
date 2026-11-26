//! What an interceptor wrote on the first transmission of a packet, for the packet that
//! passes again.
//!
//! Without a retransmission format (RFC 4588) the NACK responder answers a request with the
//! packet again as it was sent: the media SSRC, the same sequence number. Under SRTP that is
//! the packet index of the first transmission, and a packet index protects one packet (RFC
//! 3711 section 3.3.1: a sender must not reuse an index with the same key; RFC 7714 section
//! 8.1 for the AEAD nonce): the SRTP sender protects the same packet again, which yields the
//! same bytes, and refuses a different one. The responder holds the packet as the application
//! wrote it, and sits application-ward of the interceptors that write a header extension per
//! transmission (the transport-wide sequence number, the abs-send-time stamp, the RFC 6051
//! timestamp). Each of them therefore gives a packet that passes again, marked
//! [`Attribute::Retransmission`](crate::Attribute::Retransmission) under an SSRC and sequence
//! number it has seen, what it gave the first transmission, so the packet reaches the SRTP
//! sender byte for byte as it first left. An RTX retransmission never matches: it is a new
//! packet of the retransmission stream, with a sequence number of its own.

use std::collections::{HashMap, VecDeque};

/// How many recent packets of a stream are remembered: the NACK responder's own send buffer
/// holds 1024 packets by default, and nothing older can be asked for again.
const REMEMBERED: usize = crate::twcc::sender::REMEMBERED;

/// What was written on recent packets of one stream, by sequence number.
#[derive(Debug)]
struct Stream<V> {
    values: HashMap<u16, V>,
    /// The sequence numbers remembered, oldest first.
    order: VecDeque<u16>,
}

/// What an interceptor wrote on the first transmission of each recent packet, by SSRC and
/// sequence number.
#[derive(Debug)]
pub(crate) struct FirstTransmissions<V> {
    streams: HashMap<u32, Stream<V>>,
}

impl<V> Default for FirstTransmissions<V> {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }
}

impl<V> FirstTransmissions<V> {
    /// Remembers `value` as what the packet `sequence_number` of `ssrc` was given.
    pub(crate) fn remember(&mut self, ssrc: u32, sequence_number: u16, value: V) {
        let stream = self.streams.entry(ssrc).or_insert_with(|| Stream {
            values: HashMap::new(),
            order: VecDeque::new(),
        });
        if stream.values.insert(sequence_number, value).is_none() {
            stream.order.push_back(sequence_number);
            if stream.order.len() > REMEMBERED
                && let Some(oldest) = stream.order.pop_front()
            {
                stream.values.remove(&oldest);
            }
        }
    }

    /// What the packet `sequence_number` of `ssrc` was given when it first passed, if it is
    /// still remembered.
    pub(crate) fn of(&self, ssrc: u32, sequence_number: u16) -> Option<&V> {
        self.streams
            .get(&ssrc)
            .and_then(|stream| stream.values.get(&sequence_number))
    }

    /// Forgets the stream `ssrc`.
    pub(crate) fn forget(&mut self, ssrc: u32) {
        self.streams.remove(&ssrc);
    }

    /// How many packets are remembered, over all streams.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.streams
            .values()
            .map(|stream| stream.values.len().max(stream.order.len()))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream remembers its most recent packets only, however many pass.
    #[test]
    fn the_oldest_packets_are_forgotten() {
        let mut first = FirstTransmissions::default();
        for sequence_number in 0..3000u16 {
            first.remember(7, sequence_number, sequence_number);
            // The same packet again changes nothing.
            first.remember(7, sequence_number, sequence_number);
        }
        assert_eq!(REMEMBERED, first.len());
        assert_eq!(None, first.of(7, 0));
        assert_eq!(Some(&2999), first.of(7, 2999));
        assert_eq!(
            Some(&(3000 - REMEMBERED as u16)),
            first.of(7, 3000 - REMEMBERED as u16)
        );
        assert_eq!(None, first.of(8, 2999));
        first.forget(7);
        assert_eq!(0, first.len());
    }
}

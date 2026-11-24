//! Tags outgoing RTP packets with transport-wide sequence numbers.

use super::{flow_ssrcs, stream_supports_twcc};
use crate::Interceptor;
use crate::cc::feedback::{CongestionFeedbackFormat, negotiated_congestion_feedback};
use crate::stream_info::StreamInfo;
use crate::{Packet, TaggedPacket};
use sansio::Protocol;
use shared::error::Error;
use shared::marshal::Marshal;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::Instant;

/// Builder for the [`TwccSenderInterceptor`].
///
/// # Example
///
/// ```
/// use rtci_interceptor::{Slot, Registry, TwccSenderBuilder};
///
/// let chain = Registry::new()
///     .with(Slot::TwccSender, TwccSenderBuilder::new().build())
///     .build();
/// ```
#[derive(Default)]
pub struct TwccSenderBuilder {
    /// The first transport-wide sequence number to hand out.
    initial_sequence_number: u16,
}

impl TwccSenderBuilder {
    /// Create a new builder with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the first transport-wide sequence number to hand out.
    ///
    /// Defaults to zero. The counter is shared across every local stream and wraps, so the
    /// starting point only matters to a test that wants to pin the numbers it asserts on, or to
    /// a session resuming a numbering it had already begun.
    pub fn with_initial_sequence_number(mut self, sequence_number: u16) -> Self {
        self.initial_sequence_number = sequence_number;
        self
    }

    /// Build the interceptor.
    pub fn build(self) -> TwccSenderInterceptor {
        TwccSenderInterceptor::new(self.initial_sequence_number)
    }
}

/// How many recently numbered packets a stream remembers, to recognise one that passes again.
///
/// A retransmission follows its original by a few NACK rounds; the NACK responder's own send
/// buffer holds 1024 packets by default, and nothing older can be asked for again.
pub(crate) const REMEMBERED: usize = 1024;

/// Per-stream state.
struct LocalStream {
    /// Header extension ID for transport-wide CC.
    hdr_ext_id: u8,
    /// RTP sequence number → the transport-wide number it was given, for the last
    /// [`REMEMBERED`] packets of the stream.
    numbers: HashMap<u16, u16>,
    /// The same packets in the order they were numbered, oldest first.
    order: VecDeque<u16>,
}

impl LocalStream {
    fn new(hdr_ext_id: u8) -> Self {
        Self {
            hdr_ext_id,
            numbers: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn remember(&mut self, rtp_sequence_number: u16, transport_sequence: u16) {
        if self.order.len() == REMEMBERED
            && let Some(oldest) = self.order.pop_front()
        {
            self.numbers.remove(&oldest);
        }
        self.numbers.insert(rtp_sequence_number, transport_sequence);
        self.order.push_back(rtp_sequence_number);
    }
}

/// Numbers every departing RTP packet so the remote can report on it
/// ([`draft-holmer-rmcat-transport-wide-cc-extensions-01`]).
///
/// # Where this belongs in the chain
///
/// **Between the pacer and the send history**, near the wire. Numbering identifies a
/// *transmission*, not a packet, so it has to happen after the pacer has decided what actually
/// leaves and before the history records it — a retransmission is a separate transmission and gets
/// its own number.
///
/// Under the nested chain this could not hold: a retransmission left from the NACK responder's own
/// queue and never reached the tagger at all.
///
/// [`draft-holmer-rmcat-transport-wide-cc-extensions-01`]: http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
#[derive(Default)]
pub struct TwccSenderInterceptor {
    /// Transport-wide sequence number counter, shared across all streams.
    next_sequence_number: u16,
    streams: HashMap<u32, LocalStream>,
    /// Inbound packets ready for the next interceptor.
    read_queue: VecDeque<TaggedPacket>,
    /// Outbound packets ready for the next interceptor: what passed through, plus
    /// anything this one generated.
    write_queue: VecDeque<TaggedPacket>,
}

impl TwccSenderInterceptor {
    /// A tagger with no streams bound yet.
    fn new(initial_sequence_number: u16) -> Self {
        Self {
            next_sequence_number: initial_sequence_number,
            ..Default::default()
        }
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TwccSenderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        self.read_queue.push_back(msg);
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        if let Packet::Rtp(ref mut rtp_packet) = msg.message.packet
            && let Some(stream) = self.streams.get_mut(&rtp_packet.header.ssrc)
        {
            // A packet of this stream with a sequence number that was numbered a moment ago
            // is that packet again: a retransmission sent as it was (no RTX negotiated). It
            // keeps its number. A new number would change its header extension, and the SRTP
            // sender refuses a second, different packet under one index, so the
            // retransmission would be dropped below this interceptor, after the congestion
            // controller recorded it as sent. An RTX retransmission never comes here with the
            // original's SSRC and sequence number: it is a new packet and gets a new number.
            let seq = match stream.numbers.get(&rtp_packet.header.sequence_number) {
                Some(seq) => *seq,
                None => {
                    let seq = self.next_sequence_number;
                    self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
                    stream.remember(rtp_packet.header.sequence_number, seq);
                    seq
                }
            };

            let tcc_ext = rtp::extension::transport_cc_extension::TransportCcExtension {
                transport_sequence: seq,
            };
            if let Ok(ext_data) = tcc_ext.marshal() {
                // The number goes on every packet of the stream, so when its negotiated ID
                // needs the two-byte form (an ID above 14, RFC 8285 section 4.2) every packet
                // is converted and the stream stays in one form (section 4.1.2).
                let _ = rtp_packet
                    .header
                    .set_extension_upgrading(stream.hdr_ext_id, ext_data.freeze());
            }
        }
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
        Ok(())
    }

    fn poll_timeout(&mut self) -> Option<Self::Time> {
        None
    }
}

impl Interceptor for TwccSenderInterceptor {
    /// The media SSRC and the repair flows that go with it: the retransmission (RTX) SSRC and
    /// the FEC SSRC. The number is attached to every packet sent on the transport
    /// (draft-holmer-rmcat-transport-wide-cc-extensions-01 section 2.2), and a retransmission or
    /// a repair packet is as much a packet on the path as the media it protects: left
    /// unnumbered, its bytes are invisible to the receiver's feedback and to the sender's
    /// congestion controller.
    fn bind_local_stream(&mut self, info: &StreamInfo) {
        // A stream whose feedback is RFC 8888 is reported against its RTP sequence numbers:
        // numbering it as well would invite a second report of every packet
        // (RFC 8888 section 6: one congestion control feedback mechanism).
        if negotiated_congestion_feedback(info) != Some(CongestionFeedbackFormat::TransportCc) {
            for ssrc in flow_ssrcs(info) {
                self.streams.remove(&ssrc);
            }
            return;
        }
        if let Some(hdr_ext_id) = stream_supports_twcc(info)
            && hdr_ext_id != 0
        {
            for ssrc in flow_ssrcs(info) {
                self.streams.insert(ssrc, LocalStream::new(hdr_ext_id));
            }
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.streams.remove(&ssrc);
        }
    }

    fn bind_remote_stream(&mut self, _info: &StreamInfo) {}

    fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AttributedPacket;
    use crate::chain::Chain;
    use crate::stream_info::RTPHeaderExtension;
    use sansio::Protocol;
    use shared::TransportContext;
    use shared::marshal::Unmarshal;
    use std::time::Instant;

    const TWCC_URI: &str =
        "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01";

    fn stream_info(ssrc: u32, ext_id: u16) -> StreamInfo {
        StreamInfo {
            ssrc,
            rtp_header_extensions: vec![RTPHeaderExtension {
                uri: TWCC_URI.to_owned(),
                id: ext_id,
            }],
            ..Default::default()
        }
    }

    fn packet(sequence_number: u16, ssrc: u32) -> TaggedPacket {
        TaggedPacket {
            now: Instant::now(),
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtp(rtp::Packet {
                header: rtp::header::Header {
                    version: 2,
                    sequence_number,
                    ssrc,
                    ..Default::default()
                },
                payload: vec![0u8; 4].into(),
            })),
        }
    }

    fn tag_of(msg: &TaggedPacket, ext_id: u8) -> Option<u16> {
        let Packet::Rtp(rtp) = &msg.message.packet else {
            return None;
        };
        let data = rtp.header.get_extension(ext_id)?;
        rtp::extension::transport_cc_extension::TransportCcExtension::unmarshal(&mut data.as_ref())
            .ok()
            .map(|e| e.transport_sequence)
    }

    fn chain() -> Chain {
        let mut chain = Chain::new(vec![Box::new(TwccSenderBuilder::new().build())]);
        chain.bind_local_stream(&stream_info(1, 5));
        chain
    }

    #[test]
    fn a_bound_stream_is_numbered_consecutively() {
        let mut chain = chain();
        let mut tags = Vec::new();
        for sequence_number in 0..3 {
            chain.handle_write(packet(sequence_number, 1)).unwrap();
            while let Some(out) = chain.poll_write() {
                tags.push(tag_of(&out, 5));
            }
        }
        assert_eq!(vec![Some(0), Some(1), Some(2)], tags);
    }

    #[test]
    fn an_unbound_stream_is_left_alone() {
        let mut chain = chain();
        chain.handle_write(packet(0, 999)).unwrap();
        let out = chain.poll_write().expect("passes through");
        assert_eq!(None, tag_of(&out, 5), "no extension added");
    }

    #[test]
    fn unbinding_stops_the_numbering() {
        let mut chain = chain();
        chain.unbind_local_stream(&stream_info(1, 5));
        chain.handle_write(packet(0, 1)).unwrap();
        let out = chain.poll_write().expect("passes through");
        assert_eq!(None, tag_of(&out, 5));
    }

    /// A packet that passes again unchanged (a NACK retransmission without RTX) keeps the
    /// number it was first given, so that it is byte for byte the packet SRTP protected the
    /// first time. With a new number its header extension differs, and the SRTP sender, which
    /// protects one packet per index (RFC 3711 3.3.1, RFC 7714 8.1), refuses it: every
    /// retransmission is then dropped after the congestion controller has counted it as sent.
    #[test]
    fn a_repeated_packet_keeps_its_number() {
        use shared::marshal::Marshal;
        let mut chain = chain();
        let mut sent = Vec::new();
        // Packets 10, 11, 12, then 11 again (the peer NACKed it), then 13.
        for sequence_number in [10u16, 11, 12, 11, 13] {
            chain.handle_write(packet(sequence_number, 1)).unwrap();
            while let Some(out) = chain.poll_write() {
                let Packet::Rtp(rtp) = &out.message.packet else {
                    panic!("an RTP packet");
                };
                sent.push((sequence_number, tag_of(&out, 5), rtp.marshal().unwrap()));
            }
        }
        let tags: Vec<Option<u16>> = sent.iter().map(|s| s.1).collect();
        assert_eq!(
            vec![Some(0), Some(1), Some(2), Some(1), Some(3)],
            tags,
            "the retransmission of 11 carries 11's number; new packets go on counting"
        );
        assert_eq!(sent[1].2, sent[3].2, "and is the same bytes");
    }

    /// Only a recent packet is recognised: an RTP sequence number that comes round again
    /// after a wrap is a new packet.
    #[test]
    fn a_sequence_number_seen_long_ago_is_a_new_packet() {
        let mut chain = chain();
        let mut tags = Vec::new();
        chain.handle_write(packet(7, 1)).unwrap();
        for sequence_number in 0..(REMEMBERED as u16 + 8) {
            chain
                .handle_write(packet(1000 + sequence_number, 1))
                .unwrap();
        }
        chain.handle_write(packet(7, 1)).unwrap();
        while let Some(out) = chain.poll_write() {
            tags.push(tag_of(&out, 5).unwrap());
        }
        assert_eq!(tags.first(), Some(&0));
        assert_eq!(tags.last(), Some(&(REMEMBERED as u16 + 9)));
    }

    /// The counter is transport-wide: one sequence across every stream, not one per SSRC.
    #[test]
    fn the_counter_is_shared_across_streams() {
        let mut chain = chain();
        chain.bind_local_stream(&stream_info(2, 5));

        let mut tags = Vec::new();
        // (Each stream's own sequence numbers advance: the same number again on one stream
        // would be that packet again, which keeps its number.)
        for (sequence_number, ssrc) in [(0, 1), (0, 2), (1, 1)] {
            chain.handle_write(packet(sequence_number, ssrc)).unwrap();
            while let Some(out) = chain.poll_write() {
                tags.push(tag_of(&out, 5));
            }
        }
        assert_eq!(vec![Some(0), Some(1), Some(2)], tags);
    }

    /// An interceptor wireward of the tagger sees the number, which is what lets a send history key on it.
    #[test]
    fn a_stage_closer_to_the_wire_sees_the_tag() {
        #[derive(Default)]
        struct Recorder {
            seen: Vec<Option<u16>>,
            write_queue: VecDeque<TaggedPacket>,
        }
        impl Protocol<TaggedPacket, TaggedPacket, ()> for Recorder {
            type Rout = TaggedPacket;
            type Wout = TaggedPacket;
            type Eout = ();
            type Error = Error;
            type Time = Instant;

            fn handle_write(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
                self.seen.push(tag_of(&msg, 5));
                self.write_queue.push_back(msg);
                Ok(())
            }

            fn poll_write(&mut self) -> Option<Self::Wout> {
                self.write_queue.pop_front()
            }

            fn handle_read(&mut self, _msg: TaggedPacket) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_read(&mut self) -> Option<Self::Rout> {
                None
            }

            fn handle_timeout(&mut self, _now: Instant) -> Result<(), Self::Error> {
                Ok(())
            }

            fn poll_timeout(&mut self) -> Option<Self::Time> {
                None
            }
        }
        impl Interceptor for Recorder {
            fn bind_local_stream(&mut self, _info: &StreamInfo) {}
            fn unbind_local_stream(&mut self, _info: &StreamInfo) {}
            fn bind_remote_stream(&mut self, _info: &StreamInfo) {}
            fn unbind_remote_stream(&mut self, _info: &StreamInfo) {}
        }
        // index 0 = wireward of the tagger at index 1, so it acts *after* on the write walk.
        let mut chain = Chain::new(vec![
            Box::new(Recorder::default()),
            Box::new(TwccSenderBuilder::new().build()),
        ]);
        chain.bind_local_stream(&stream_info(1, 5));

        chain.handle_write(packet(0, 1)).unwrap();
        let out = chain.poll_write().expect("reaches the driver");
        assert_eq!(Some(0), tag_of(&out, 5), "the packet leaves tagged");
    }
}

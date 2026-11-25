//! Tags outgoing RTP packets with transport-wide sequence numbers.

use super::{flow_ssrcs, stream_supports_twcc};
use crate::Interceptor;
use crate::cc::feedback::{CongestionFeedbackFormat, negotiated_congestion_feedback};
use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc;
use sansio::Protocol;
use shared::TransportContext;
use shared::error::Error;
use shared::marshal::Marshal;
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// One retransmission the feedback reported on: the SSRC it left on, the sequence number of the
/// packet it repairs (the original sequence number on an RTX stream, RFC 4588 section 4; the
/// key the pacer's [`RetransmissionsLeft`](crate::RetransmissionsLeft) uses), and when that
/// retransmission was made. A 16-bit sequence number names a different packet every cycle;
/// the instant lets the reader tell a report on a retransmission of the packet it holds now
/// from one on an earlier packet of the same number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReportedRetransmission {
    /// The SSRC the retransmission left on.
    pub ssrc: u32,
    /// The sequence number of the packet it repairs.
    pub sequence_number: u16,
    /// When the retransmission was made (the instant on the packet as it was numbered).
    pub sent: Instant,
}

/// What transport-wide feedback reported on the retransmissions this interceptor numbered,
/// since the last notice. The TWCC sender sends it application-ward on an empty RTCP carrier
/// when a feedback packet reports on one; the NACK responder does not repair again a packet
/// whose repair arrived, and answers at once a request for one whose repair was lost. Probe
/// padding (no payload) is not reported. Read with
/// [`AttributedPacket::custom`](crate::AttributedPacket::custom).
///
/// A transport-wide number is a retransmission's only until it is handed out again
/// (65536 packets later), until the numbering is half a cycle past it, and for
/// [`RETRANSMISSION_REPORT_HORIZON`] at most: feedback that names the number after that is
/// about another packet, or too late to mean anything, and is not reported.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RetransmissionsReported {
    /// The receiver got the retransmission.
    pub received: Vec<ReportedRetransmission>,
    /// The receiver reported it missing.
    pub lost: Vec<ReportedRetransmission>,
}

/// The most retransmissions whose transport-wide number is remembered for the feedback.
const REMEMBERED_RETRANSMISSIONS: usize = REMEMBERED;

/// How long after a retransmission was made the feedback on it still counts: longer than the
/// pacer's queue time bound (2 s by default) and a round trip of a path in real-time use
/// together. The clock is the engine's (the instant on every packet and timeout that passes),
/// not the arrival of a later report: a number whose feedback was lost is forgotten all the
/// same.
pub const RETRANSMISSION_REPORT_HORIZON: Duration = Duration::from_secs(4);

/// Half the cycle of transport-wide numbers: a number this far behind the newest can no
/// longer be told from one ahead of it.
const HALF_CYCLE: u16 = 1 << 15;

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
    /// The retransmission (RTX) SSRCs of the numbered streams.
    repair_flows: HashSet<u32>,
    /// Transport-wide number → the retransmission it was given to, as
    /// [`RetransmissionsReported`] names it; the numbers with the instant each was
    /// remembered, oldest first, in `retransmission_order`.
    retransmissions: HashMap<u16, ReportedRetransmission>,
    retransmission_order: VecDeque<(u16, Instant)>,
}

impl TwccSenderInterceptor {
    /// A tagger with no streams bound yet.
    fn new(initial_sequence_number: u16) -> Self {
        Self {
            next_sequence_number: initial_sequence_number,
            ..Default::default()
        }
    }

    /// Forgets the retransmissions whose feedback can no longer be told from another
    /// packet's: older than [`RETRANSMISSION_REPORT_HORIZON`] at `now`, or numbered half a
    /// cycle of transport-wide numbers ago.
    fn forget_old_retransmissions(&mut self, now: Instant) {
        while let Some(&(number, sent)) = self.retransmission_order.front() {
            let old = now.saturating_duration_since(sent) >= RETRANSMISSION_REPORT_HORIZON
                || self.next_sequence_number.wrapping_sub(number) >= HALF_CYCLE
                || self.retransmission_order.len() > REMEMBERED_RETRANSMISSIONS;
            if !old {
                break;
            }
            self.retransmission_order.pop_front();
            // The number may have been given to a later retransmission since (one sent as it
            // was keeps its original's number): that one has its own place in the order.
            if self
                .retransmissions
                .get(&number)
                .is_some_and(|entry| entry.sent == sent)
            {
                self.retransmissions.remove(&number);
            }
        }
    }

    /// How many retransmissions are remembered for the feedback.
    #[cfg(test)]
    fn remembered_retransmissions(&self) -> usize {
        self.retransmissions
            .len()
            .max(self.retransmission_order.len())
    }
}

impl Protocol<TaggedPacket, TaggedPacket, ()> for TwccSenderInterceptor {
    type Rout = TaggedPacket;
    type Wout = TaggedPacket;
    type Eout = ();
    type Error = Error;
    type Time = Instant;

    /// Transport-wide feedback passes on to the congestion controller's readers as it is; what
    /// it reports on the retransmissions numbered here follows it on a carrier of its own
    /// ([`RetransmissionsReported`]).
    fn handle_read(&mut self, msg: TaggedPacket) -> Result<(), Self::Error> {
        let now = msg.now;
        self.forget_old_retransmissions(now);
        let mut report = RetransmissionsReported::default();
        if !self.retransmissions.is_empty()
            && let Packet::Rtcp(ref packets) = msg.message.packet
        {
            for feedback in packets
                .iter()
                .filter_map(|packet| packet.as_any().downcast_ref::<TransportLayerCc>())
            {
                for acknowledgement in crate::rtpfb::convert::convert_twcc(feedback) {
                    if let Some(key) = self
                        .retransmissions
                        .remove(&acknowledgement.sequence_number)
                    {
                        if acknowledgement.arrived {
                            report.received.push(key);
                        } else {
                            report.lost.push(key);
                        }
                    }
                }
            }
        }
        self.read_queue.push_back(msg);
        if !report.received.is_empty() || !report.lost.is_empty() {
            let retransmissions = &self.retransmissions;
            self.retransmission_order.retain(|(number, sent)| {
                retransmissions
                    .get(number)
                    .is_some_and(|entry| entry.sent == *sent)
            });
            self.read_queue.push_back(TaggedPacket {
                now,
                transport: TransportContext::default(),
                message: AttributedPacket::new(Packet::Rtcp(vec![]))
                    .with(Attribute::Custom(Arc::new(report))),
            });
        }
        Ok(())
    }

    fn poll_read(&mut self) -> Option<Self::Rout> {
        self.read_queue.pop_front()
    }

    fn handle_write(&mut self, mut msg: TaggedPacket) -> Result<(), Self::Error> {
        let retransmission = msg.message.has(&Attribute::Retransmission);
        let now = msg.now;
        self.forget_old_retransmissions(now);
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
                    // The number is this packet's now: feedback that names it is no longer
                    // about the retransmission that had it a cycle ago.
                    self.retransmissions.remove(&seq);
                    seq
                }
            };

            // A retransmission with media in it (probe padding has none): remembered under its
            // number, for the feedback to report on.
            if retransmission {
                let ssrc = rtp_packet.header.ssrc;
                let repaired = if self.repair_flows.contains(&ssrc) {
                    rtp_packet
                        .payload
                        .get(..2)
                        .map(|osn| u16::from_be_bytes([osn[0], osn[1]]))
                } else {
                    Some(rtp_packet.header.sequence_number)
                };
                if let Some(sequence_number) = repaired {
                    self.retransmissions.insert(
                        seq,
                        ReportedRetransmission {
                            ssrc,
                            sequence_number,
                            sent: now,
                        },
                    );
                    self.retransmission_order.push_back((seq, now));
                }
            }

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
        // Over the count, or the numbering now half a cycle on: the oldest go.
        self.forget_old_retransmissions(now);
        self.write_queue.push_back(msg);
        Ok(())
    }

    fn poll_write(&mut self) -> Option<Self::Wout> {
        self.write_queue.pop_front()
    }

    fn handle_timeout(&mut self, now: Instant) -> Result<(), Self::Error> {
        self.forget_old_retransmissions(now);
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
            self.repair_flows.extend(info.ssrc_rtx);
        }
    }

    fn unbind_local_stream(&mut self, info: &StreamInfo) {
        for ssrc in flow_ssrcs(info) {
            self.streams.remove(&ssrc);
        }
        if let Some(ssrc_rtx) = info.ssrc_rtx {
            self.repair_flows.remove(&ssrc_rtx);
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
    use std::time::{Duration, Instant};

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

    fn retransmission(sequence_number: u16, ssrc: u32, now: Instant) -> TaggedPacket {
        let mut tagged = packet(sequence_number, ssrc);
        tagged.now = now;
        tagged.message.add(Attribute::Retransmission);
        tagged
    }

    /// Transport-wide feedback: `number` arrived.
    fn arrived(number: u16, now: Instant) -> TaggedPacket {
        use rtcp::transport_feedbacks::transport_layer_cc::{
            PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, SymbolTypeTcc,
        };
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![Box::new(TransportLayerCc {
                sender_ssrc: 9,
                media_ssrc: 1,
                base_sequence_number: number,
                packet_status_count: 1,
                reference_time: 1,
                fb_pkt_count: 0,
                packet_chunks: vec![PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                    type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                    packet_status_symbol: SymbolTypeTcc::PacketReceivedSmallDelta,
                    run_length: 1,
                })],
                recv_deltas: vec![RecvDelta {
                    type_tcc_packet: SymbolTypeTcc::PacketReceivedSmallDelta,
                    delta: 1000,
                }],
            })])),
        }
    }

    /// The reports on retransmissions `sender` passes on for `feedback`.
    fn reports(
        sender: &mut TwccSenderInterceptor,
        feedback: TaggedPacket,
    ) -> Vec<RetransmissionsReported> {
        sender.handle_read(feedback).unwrap();
        let mut reports = Vec::new();
        while let Some(read) = sender.poll_read() {
            if let Some(report) = read.message.custom::<RetransmissionsReported>() {
                reports.push(report.clone());
            }
        }
        reports
    }

    /// However many retransmissions pass with no feedback on any (it is lost, or the receiver
    /// sends none), the numbers remembered for the feedback stay within their count, and the
    /// engine's clock alone ends them: four seconds after the last, at a timeout, none is left.
    #[test]
    fn the_retransmissions_remembered_are_bounded_and_end_by_the_clock_alone() {
        let mut sender = TwccSenderBuilder::new().build();
        sender.bind_local_stream(&stream_info(1, 5));
        let base = Instant::now();
        let mut most = 0;
        for sent in 0..5_000u16 {
            let now = base + Duration::from_micros(100) * u32::from(sent);
            sender.handle_write(retransmission(sent, 1, now)).unwrap();
            while sender.poll_write().is_some() {}
            most = most.max(sender.remembered_retransmissions());
        }
        assert_eq!(REMEMBERED_RETRANSMISSIONS, most);
        let last = base + Duration::from_micros(100) * 4_999;
        sender
            .handle_timeout(last + RETRANSMISSION_REPORT_HORIZON - Duration::from_millis(1))
            .unwrap();
        assert_eq!(
            10,
            sender.remembered_retransmissions(),
            "the last millisecond's"
        );
        sender
            .handle_timeout(last + RETRANSMISSION_REPORT_HORIZON)
            .unwrap();
        assert_eq!(0, sender.remembered_retransmissions());
    }

    /// A transport-wide number handed out again is the new packet's, whatever else is still
    /// remembered. A retransmission sent as it was (no RTX) keeps its original's number,
    /// which can be most of a cycle old while a younger retransmission is remembered ahead of
    /// it: when the numbering comes round to that number, feedback on it is about the packet
    /// that has it now.
    #[test]
    fn a_number_kept_by_a_retransmission_is_the_next_packets_once_handed_out_again() {
        let mut sender = TwccSenderBuilder::new().build();
        sender.bind_local_stream(&stream_info(1, 5));
        sender.bind_local_stream(&stream_info(2, 5));
        let now = Instant::now();
        let write = |sender: &mut TwccSenderInterceptor, tagged: TaggedPacket| -> u16 {
            sender.handle_write(tagged).unwrap();
            let mut number = None;
            while let Some(out) = sender.poll_write() {
                number = tag_of(&out, 5);
            }
            number.expect("numbered")
        };
        let mut original = packet(7, 1);
        original.now = now;
        assert_eq!(0, write(&mut sender, original));
        let mut other = 0u16;
        let mut on_the_other_stream = |sender: &mut TwccSenderInterceptor, count: u32| -> u16 {
            let mut number = 0;
            for _ in 0..count {
                let mut tagged = packet(other, 2);
                tagged.now = now;
                other = other.wrapping_add(1);
                number = write(sender, tagged);
            }
            number
        };
        assert_eq!(40_000, on_the_other_stream(&mut sender, 40_000));
        // A retransmission with a number of its own, then packet 7 again as it was.
        assert_eq!(40_001, write(&mut sender, retransmission(500, 1, now)));
        assert_eq!(0, write(&mut sender, retransmission(7, 1, now)));
        // The numbering comes round: the 25 535th packet from here has number 0.
        assert_eq!(0, on_the_other_stream(&mut sender, 25_535));
        let reported = reports(&mut sender, arrived(0, now));
        assert!(
            reported.is_empty(),
            "feedback on the packet now numbered 0 was reported as the old retransmission's: \
             {reported:?}"
        );
        // The younger retransmission is still reported on.
        assert_eq!(
            vec![RetransmissionsReported {
                received: vec![ReportedRetransmission {
                    ssrc: 1,
                    sequence_number: 500,
                    sent: now,
                }],
                lost: vec![],
            }],
            reports(&mut sender, arrived(40_001, now))
        );
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

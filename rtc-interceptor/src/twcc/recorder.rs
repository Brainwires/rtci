//! TWCC Recorder - tracks packet arrival times and builds feedback packets.

use super::arrival_time_map::PacketArrivalTimeMap;
use rtcp::transport_feedbacks::transport_layer_cc::{
    PacketStatusChunk, RecvDelta, RunLengthChunk, StatusChunkTypeTcc, StatusVectorChunk,
    SymbolSizeTypeTcc, SymbolTypeTcc, TransportLayerCc,
};

/// Window for packet timestamps in microseconds (500ms).
const PACKET_WINDOW_MICROSECONDS: i64 = 500_000;

/// Maximum number of missing sequence numbers to include in feedback.
const MAX_MISSING_SEQUENCE_NUMBERS: i64 = 0x7FFE;

/// Scale factor for TWCC deltas (250 microseconds).
const TYPE_TCC_DELTA_SCALE_FACTOR: i64 = 250;

/// Chunk capacity limits.
const MAX_RUN_LENGTH_CAP: usize = 0x1fff; // 13 bits
const MAX_ONE_BIT_CAP: usize = 14;
const MAX_TWO_BIT_CAP: usize = 7;

/// The most octets one feedback packet takes (draft-holmer-rmcat-transport-wide-cc-extensions-01
/// section 3.1.5: a feedback packet stays within the path MTU; what does not fit continues in
/// the next). 1100 leaves room for SRTCP and the minimal compound packet around it within the
/// 1200 octets the engine keeps RTCP under.
pub const MAX_FEEDBACK_OCTETS: usize = 1100;

/// Sequence number unwrapper to handle 16-bit wraparound.
struct SequenceUnwrapper {
    last_unwrapped: Option<i64>,
}

impl SequenceUnwrapper {
    fn new() -> Self {
        Self {
            last_unwrapped: None,
        }
    }

    fn unwrap(&mut self, seq: u16) -> i64 {
        match self.last_unwrapped {
            None => {
                self.last_unwrapped = Some(seq as i64);
                seq as i64
            }
            Some(last) => {
                // Calculate the difference, handling wraparound
                let seq_i64 = seq as i64;
                let last_seq = last & 0xFFFF;
                let mut diff = seq_i64 - last_seq;

                // Handle wraparound
                if diff > 0x8000 {
                    diff -= 0x10000;
                } else if diff < -0x8000 {
                    diff += 0x10000;
                }

                let unwrapped = last + diff;
                self.last_unwrapped = Some(unwrapped);
                unwrapped
            }
        }
    }
}

/// Records incoming RTP packets and their arrival times, building TWCC feedback.
pub(crate) struct Recorder {
    arrival_time_map: PacketArrivalTimeMap,
    sequence_unwrapper: SequenceUnwrapper,
    /// The first sequence number that will be included in the next feedback packet.
    start_sequence_number: Option<i64>,
    sender_ssrc: u32,
    media_ssrc: u32,
    fb_pkt_cnt: u8,
    packets_held: usize,
    /// Whether a packet already reported as received is reported received again when the
    /// base moves back over it (libwebrtc), rather than "not received" (the draft).
    rereport_received: bool,
    /// The packets reported as received in an earlier feedback message, while they are in
    /// the arrival window.
    reported: std::collections::BTreeSet<i64>,
}

impl Recorder {
    /// Create a new Recorder with the given sender SSRC.
    pub(crate) fn new(sender_ssrc: u32) -> Self {
        Self {
            arrival_time_map: PacketArrivalTimeMap::new(),
            sequence_unwrapper: SequenceUnwrapper::new(),
            start_sequence_number: None,
            sender_ssrc,
            media_ssrc: 0,
            fb_pkt_cnt: 0,
            packets_held: 0,
            rereport_received: false,
            reported: std::collections::BTreeSet::new(),
        }
    }

    /// Report a packet that an earlier feedback message reported as received as received
    /// again when the window moves back over it, as libwebrtc does. Off by default:
    /// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1.1 has it reported "not
    /// received", with no delta.
    pub(crate) fn with_rereport_received(mut self, rereport_received: bool) -> Self {
        self.rereport_received = rereport_received;
        self
    }

    /// Record a packet arrival.
    pub(crate) fn record(&mut self, media_ssrc: u32, sequence_number: u16, arrival_time: i64) {
        self.media_ssrc = media_ssrc;

        // Unwrap the sequence number to get a monotonically increasing value.
        let unwrapped_sn = self.sequence_unwrapper.unwrap(sequence_number);
        self.maybe_cull_old_packets(unwrapped_sn, arrival_time);

        if self.start_sequence_number.is_none()
            || unwrapped_sn < self.start_sequence_number.unwrap()
        {
            self.start_sequence_number = Some(unwrapped_sn);
        }

        // We are only interested in the first time a packet is received.
        if self.arrival_time_map.has_received(unwrapped_sn) {
            return;
        }

        self.arrival_time_map.add_packet(unwrapped_sn, arrival_time);
        self.packets_held += 1;

        // Limit the range of sequence numbers to send feedback for.
        if let Some(start) = self.start_sequence_number
            && start < self.arrival_time_map.begin_sequence_number()
        {
            self.start_sequence_number = Some(self.arrival_time_map.begin_sequence_number());
        }
    }

    fn maybe_cull_old_packets(&mut self, sequence_number: i64, arrival_time: i64) {
        if let Some(start) = self.start_sequence_number
            && start >= self.arrival_time_map.end_sequence_number()
            && arrival_time >= PACKET_WINDOW_MICROSECONDS
        {
            self.arrival_time_map
                .remove_old_packets(sequence_number, arrival_time - PACKET_WINDOW_MICROSECONDS);
        }
    }

    /// Returns the number of received packets currently held.
    #[allow(dead_code)]
    pub(crate) fn packets_held(&self) -> usize {
        self.packets_held
    }

    /// Build TWCC feedback packets for all recorded arrivals.
    pub(crate) fn build_feedback_packet(&mut self) -> Vec<Box<dyn rtcp::Packet>> {
        let Some(mut start_sn) = self.start_sequence_number else {
            return Vec::new();
        };

        let end_sn = self.arrival_time_map.end_sequence_number();
        let mut feedbacks: Vec<Box<dyn rtcp::Packet>> = Vec::new();

        while start_sn < end_sn {
            let Some(feedback) = self.maybe_build_feedback_packet(start_sn, end_sn) else {
                break;
            };
            start_sn = self.start_sequence_number.unwrap_or(end_sn);
            feedbacks.push(Box::new(feedback.get_rtcp()));
        }
        self.packets_held = 0;

        feedbacks
    }

    fn maybe_build_feedback_packet(
        &mut self,
        begin_seq_inclusive: i64,
        end_seq_exclusive: i64,
    ) -> Option<Feedback> {
        let start_sn_inclusive = self.arrival_time_map.clamp(begin_seq_inclusive);
        let end_sn_exclusive = self.arrival_time_map.clamp(end_seq_exclusive);

        let mut fb: Option<Feedback> = None;
        let mut next_sequence_number = begin_seq_inclusive;

        let mut seq = start_sn_inclusive;
        while seq < end_sn_exclusive {
            let Some((found_seq, arrival_time)) = self.arrival_time_map.find_next_at_or_after(seq)
            else {
                break;
            };
            seq = found_seq;
            if seq >= end_sn_exclusive {
                break;
            }
            // Draft section 3.1.1: "In the case the base sequence number is decreased,
            // creating a window overlapping the previous feedback messages, the status for
            // any packets previously reported as received must be marked as 'Packet not
            // received' and thus no delta included for that symbol."
            if !self.rereport_received && self.reported.contains(&seq) {
                next_sequence_number = seq + 1;
                seq += 1;
                continue;
            }

            if let Some(feedback) = fb.as_mut() {
                if !feedback.add_received(seq as u16, arrival_time) {
                    // Could not add timestamp. Packet may be full.
                    break;
                }
            } else {
                let mut new_fb = Feedback::new(self.sender_ssrc, self.media_ssrc, self.fb_pkt_cnt);
                self.fb_pkt_cnt = self.fb_pkt_cnt.wrapping_add(1);

                // Calculate base sequence number, limiting how far back we report missing packets.
                let base_sequence_number =
                    begin_seq_inclusive.max(seq - MAX_MISSING_SEQUENCE_NUMBERS);

                new_fb.set_base(base_sequence_number as u16, arrival_time);

                if !new_fb.add_received(seq as u16, arrival_time) {
                    // Could not add a single received packet.
                    self.start_sequence_number = Some(seq);
                    return None;
                }
                fb = Some(new_fb);
            }

            self.reported.insert(seq);
            next_sequence_number = seq + 1;
            seq += 1;
        }

        // What has left the arrival window can no longer be reported again.
        let begin = self.arrival_time_map.begin_sequence_number();
        self.reported = self.reported.split_off(&begin);
        self.start_sequence_number = Some(next_sequence_number);
        fb
    }
}

/// Helper struct to build a single TransportLayerCC feedback packet.
struct Feedback {
    sender_ssrc: u32,
    media_ssrc: u32,
    fb_pkt_cnt: u8,
    base_sequence_number: u16,
    ref_timestamp_64ms: i64,
    last_timestamp_us: i64,
    next_sequence_number: u16,
    sequence_number_count: u16,
    len: usize,
    last_chunk: Chunk,
    chunks: Vec<PacketStatusChunk>,
    deltas: Vec<RecvDelta>,
}

impl Feedback {
    fn new(sender_ssrc: u32, media_ssrc: u32, fb_pkt_cnt: u8) -> Self {
        Self {
            sender_ssrc,
            media_ssrc,
            fb_pkt_cnt,
            base_sequence_number: 0,
            ref_timestamp_64ms: 0,
            last_timestamp_us: 0,
            next_sequence_number: 0,
            sequence_number_count: 0,
            len: 0,
            last_chunk: Chunk::new(),
            chunks: Vec::new(),
            deltas: Vec::new(),
        }
    }

    fn set_base(&mut self, sequence_number: u16, time_us: i64) {
        self.base_sequence_number = sequence_number;
        self.next_sequence_number = sequence_number;
        self.ref_timestamp_64ms = time_us / 64_000;
        self.last_timestamp_us = self.ref_timestamp_64ms * 64_000;
    }

    fn get_rtcp(mut self) -> TransportLayerCc {
        // Flush remaining chunk
        while !self.last_chunk.deltas.is_empty() {
            self.chunks.push(self.last_chunk.encode());
        }

        TransportLayerCc {
            sender_ssrc: self.sender_ssrc,
            media_ssrc: self.media_ssrc,
            base_sequence_number: self.base_sequence_number,
            packet_status_count: self.sequence_number_count,
            reference_time: self.ref_timestamp_64ms as u32,
            fb_pkt_count: self.fb_pkt_cnt,
            packet_chunks: self.chunks,
            recv_deltas: self.deltas,
        }
    }

    fn add_received(&mut self, sequence_number: u16, timestamp_us: i64) -> bool {
        let delta_us = timestamp_us - self.last_timestamp_us;
        let delta_250us = if delta_us >= 0 {
            (delta_us + TYPE_TCC_DELTA_SCALE_FACTOR / 2) / TYPE_TCC_DELTA_SCALE_FACTOR
        } else {
            (delta_us - TYPE_TCC_DELTA_SCALE_FACTOR / 2) / TYPE_TCC_DELTA_SCALE_FACTOR
        };

        // delta doesn't fit into 16 bit, need to create new packet
        if delta_250us < i16::MIN as i64 || delta_250us > i16::MAX as i64 {
            return false;
        }
        let delta_us_rounded = delta_250us * TYPE_TCC_DELTA_SCALE_FACTOR;

        // Add "not received" entries for missing packets
        while self.next_sequence_number != sequence_number {
            if !self.last_chunk.can_add(SymbolTypeTcc::PacketNotReceived) {
                self.chunks.push(self.last_chunk.encode());
            }
            self.last_chunk.add(SymbolTypeTcc::PacketNotReceived);
            self.sequence_number_count += 1;
            self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
        }

        let large = !(0..=0xff).contains(&delta_250us);
        // What the packet would be with this arrival (and the not-received run before it): the
        // fixed 20 octets, the chunks (one more for the open one and one for a run that may
        // start), the deltas, padding.
        let missing = usize::from(sequence_number.wrapping_sub(self.next_sequence_number));
        let would_be = 20
            + 2 * (self.chunks.len() + 2 + missing / MAX_RUN_LENGTH_CAP)
            + self.len
            + if large { 2 } else { 1 }
            + 3;
        if self.sequence_number_count > 0 && would_be > MAX_FEEDBACK_OCTETS {
            return false;
        }

        let recv_delta = if large {
            self.len += 2;
            SymbolTypeTcc::PacketReceivedLargeDelta
        } else {
            self.len += 1;
            SymbolTypeTcc::PacketReceivedSmallDelta
        };

        if !self.last_chunk.can_add(recv_delta) {
            self.chunks.push(self.last_chunk.encode());
        }
        self.last_chunk.add(recv_delta);
        self.deltas.push(RecvDelta {
            type_tcc_packet: recv_delta,
            delta: delta_us_rounded,
        });
        self.last_timestamp_us += delta_us_rounded;
        self.sequence_number_count += 1;
        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);

        true
    }
}

/// Helper struct for building status chunks.
struct Chunk {
    has_large_delta: bool,
    has_different_types: bool,
    deltas: Vec<SymbolTypeTcc>,
}

impl Chunk {
    fn new() -> Self {
        Self {
            has_large_delta: false,
            has_different_types: false,
            deltas: Vec::new(),
        }
    }

    fn can_add(&self, delta: SymbolTypeTcc) -> bool {
        if self.deltas.len() < MAX_TWO_BIT_CAP {
            return true;
        }
        if self.deltas.len() < MAX_ONE_BIT_CAP
            && !self.has_large_delta
            && delta != SymbolTypeTcc::PacketReceivedLargeDelta
        {
            return true;
        }
        if self.deltas.len() < MAX_RUN_LENGTH_CAP
            && !self.has_different_types
            && delta == self.deltas[0]
        {
            return true;
        }
        false
    }

    fn add(&mut self, delta: SymbolTypeTcc) {
        if !self.deltas.is_empty() && delta != self.deltas[0] {
            self.has_different_types = true;
        }
        self.has_large_delta =
            self.has_large_delta || delta == SymbolTypeTcc::PacketReceivedLargeDelta;
        self.deltas.push(delta);
    }

    fn encode(&mut self) -> PacketStatusChunk {
        if !self.has_different_types {
            let chunk = PacketStatusChunk::RunLengthChunk(RunLengthChunk {
                type_tcc: StatusChunkTypeTcc::RunLengthChunk,
                packet_status_symbol: self.deltas[0],
                run_length: self.deltas.len() as u16,
            });
            self.reset();
            return chunk;
        }

        if self.deltas.len() == MAX_ONE_BIT_CAP {
            let chunk = PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
                type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
                symbol_size: SymbolSizeTypeTcc::OneBit,
                symbol_list: self.deltas.clone(),
            });
            self.reset();
            return chunk;
        }

        let min_cap = MAX_TWO_BIT_CAP.min(self.deltas.len());
        let chunk = PacketStatusChunk::StatusVectorChunk(StatusVectorChunk {
            type_tcc: StatusChunkTypeTcc::StatusVectorChunk,
            symbol_size: SymbolSizeTypeTcc::TwoBit,
            symbol_list: self.deltas[..min_cap].to_vec(),
        });
        self.deltas = self.deltas[min_cap..].to_vec();
        self.has_different_types = false;
        self.has_large_delta = false;

        if !self.deltas.is_empty() {
            let first = self.deltas[0];
            for &d in &self.deltas {
                if d != first {
                    self.has_different_types = true;
                }
                if d == SymbolTypeTcc::PacketReceivedLargeDelta {
                    self.has_large_delta = true;
                }
            }
        }

        chunk
    }

    fn reset(&mut self) {
        self.deltas.clear();
        self.has_large_delta = false;
        self.has_different_types = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequence_unwrapper() {
        let mut unwrapper = SequenceUnwrapper::new();

        assert_eq!(unwrapper.unwrap(0), 0);
        assert_eq!(unwrapper.unwrap(1), 1);
        assert_eq!(unwrapper.unwrap(100), 100);

        // Test wraparound
        let mut unwrapper = SequenceUnwrapper::new();
        assert_eq!(unwrapper.unwrap(65534), 65534);
        assert_eq!(unwrapper.unwrap(65535), 65535);
        assert_eq!(unwrapper.unwrap(0), 65536);
        assert_eq!(unwrapper.unwrap(1), 65537);
    }

    #[test]
    fn test_recorder_basic() {
        let mut recorder = Recorder::new(5000);

        recorder.record(1234, 0, 64000);
        recorder.record(1234, 1, 64250);
        recorder.record(1234, 2, 64500);

        let packets = recorder.build_feedback_packet();
        assert_eq!(packets.len(), 1);
    }

    /// The received sequence numbers of a feedback message, by its own reading.
    fn received(packet: &dyn rtcp::Packet) -> Vec<u16> {
        let feedback = packet
            .as_any()
            .downcast_ref::<TransportLayerCc>()
            .expect("transport-wide feedback");
        let mut seq = feedback.base_sequence_number;
        let mut out = vec![];
        for chunk in &feedback.packet_chunks {
            let symbols: Vec<SymbolTypeTcc> = match chunk {
                PacketStatusChunk::RunLengthChunk(run) => {
                    vec![run.packet_status_symbol; run.run_length as usize]
                }
                PacketStatusChunk::StatusVectorChunk(vector) => vector.symbol_list.clone(),
            };
            for symbol in symbols {
                if seq
                    == feedback
                        .base_sequence_number
                        .wrapping_add(feedback.packet_status_count)
                {
                    break;
                }
                if symbol != SymbolTypeTcc::PacketNotReceived {
                    out.push(seq);
                }
                seq = seq.wrapping_add(1);
            }
        }
        out
    }

    /// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1.1: when a late packet
    /// moves the base sequence number back over packets an earlier feedback message reported
    /// as received, those are now "not received", with no delta; the late one is received.
    /// `with_rereport_received(true)` reports them received again, as libwebrtc does.
    #[test]
    fn packets_reported_before_are_not_received_when_the_base_moves_back() {
        for rereport in [false, true] {
            let mut recorder = Recorder::new(5000).with_rereport_received(rereport);
            recorder.record(1234, 0, 64_000);
            recorder.record(1234, 2, 64_500);
            recorder.record(1234, 3, 64_750);
            let first = recorder.build_feedback_packet();
            assert_eq!(vec![0, 2, 3], received(first[0].as_ref()));

            // 1 arrives late, then 4.
            recorder.record(1234, 1, 65_000);
            recorder.record(1234, 4, 65_250);
            let second = recorder.build_feedback_packet();
            let got = received(second[0].as_ref());
            if rereport {
                assert_eq!(vec![1, 2, 3, 4], got);
            } else {
                assert_eq!(vec![1, 4], got);
            }
        }
    }

    /// draft-holmer-rmcat-transport-wide-cc-extensions-01 section 3.1.5: a receive delta holds
    /// +/-8191.75 ms; a packet further from the one before starts a new feedback message,
    /// whose reference time takes the gap.
    #[test]
    fn a_delta_beyond_its_range_starts_a_new_feedback_message() {
        let mut recorder = Recorder::new(5000);
        recorder.record(1234, 0, 64_000);
        recorder.record(1234, 1, 64_000 + 9_000_000);
        let packets = recorder.build_feedback_packet();
        assert_eq!(2, packets.len());
        let feedback = |i: usize| {
            packets[i]
                .as_any()
                .downcast_ref::<TransportLayerCc>()
                .unwrap()
                .clone()
        };
        let (first, second) = (feedback(0), feedback(1));
        assert_eq!(vec![0], received(&first));
        assert_eq!(vec![1], received(&second));
        assert_eq!(1, second.base_sequence_number);
        // Reference times count 64 ms: the second is about 9 s after the first.
        let gap = (second.reference_time - first.reference_time) as i64 * 64;
        assert!((8_900..=9_100).contains(&gap), "{gap} ms");
    }

    #[test]
    fn test_recorder_with_gaps() {
        let mut recorder = Recorder::new(5000);

        recorder.record(1234, 0, 64000);
        recorder.record(1234, 5, 65000); // Gap: 1-4 missing

        let packets = recorder.build_feedback_packet();
        assert_eq!(packets.len(), 1);
    }

    #[test]
    fn test_chunk_run_length() {
        let mut chunk = Chunk::new();

        // Fill with same type
        for _ in 0..10 {
            assert!(chunk.can_add(SymbolTypeTcc::PacketReceivedSmallDelta));
            chunk.add(SymbolTypeTcc::PacketReceivedSmallDelta);
        }

        assert!(!chunk.has_different_types);

        let encoded = chunk.encode();
        match encoded {
            PacketStatusChunk::RunLengthChunk(rlc) => {
                assert_eq!(
                    rlc.packet_status_symbol,
                    SymbolTypeTcc::PacketReceivedSmallDelta
                );
                assert_eq!(rlc.run_length, 10);
            }
            _ => panic!("Expected RunLengthChunk"),
        }
    }

    #[test]
    fn test_chunk_status_vector() {
        let mut chunk = Chunk::new();

        // Mix of types
        chunk.add(SymbolTypeTcc::PacketReceivedSmallDelta);
        chunk.add(SymbolTypeTcc::PacketNotReceived);
        chunk.add(SymbolTypeTcc::PacketReceivedLargeDelta);

        assert!(chunk.has_different_types);
        assert!(chunk.has_large_delta);
    }

    #[test]
    fn test_feedback_add_received() {
        let mut fb = Feedback::new(5000, 1234, 0);
        fb.set_base(0, 64000);

        // Add packet 0
        assert!(fb.add_received(0, 64000));
        assert_eq!(fb.sequence_number_count, 1);
        assert_eq!(fb.next_sequence_number, 1);

        // Add packet 2 (skip 1)
        assert!(fb.add_received(2, 64500));
        assert_eq!(fb.sequence_number_count, 3); // 0, 1 (not received), 2
        assert_eq!(fb.next_sequence_number, 3);
    }

    /// Section 3.1.5: a reporting window too long for one packet continues in the next, each
    /// within `MAX_FEEDBACK_OCTETS`, every packet reported once.
    #[test]
    fn a_long_window_is_split_within_the_mtu() {
        let mut recorder = Recorder::new(5000);
        // 700 packets in 490 ms, every other one arriving before its predecessor (a large
        // delta), so each needs about two octets.
        for n in 0..700i64 {
            let arrival = 64_000 + n * 700 - if n % 2 == 1 { 5_000 } else { 0 };
            recorder.record(1234, n as u16, arrival);
        }
        let packets = recorder.build_feedback_packet();
        assert!(packets.len() >= 2, "{} packets", packets.len());
        let mut covered = 0usize;
        for packet in &packets {
            assert!(
                packet.marshal_size() <= MAX_FEEDBACK_OCTETS,
                "{}",
                packet.marshal_size()
            );
            let twcc = packet
                .as_any()
                .downcast_ref::<rtcp::transport_feedbacks::transport_layer_cc::TransportLayerCc>()
                .unwrap();
            covered += usize::from(twcc.packet_status_count);
        }
        assert_eq!(700, covered);
    }
}

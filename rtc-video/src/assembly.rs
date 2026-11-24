//! The packet buffer: RTP packets of one stream in, complete frames out.
//!
//! libwebrtc's `modules/video_coding/packet_buffer.cc` (a222406d) is the model: packets kept by
//! sequence number, a duplicate dropped, a frame found by walking back from a packet that may
//! complete one to the packet that starts it with no gap, the buffer cleared (and a key frame
//! needed) when it would hold more than its capacity, and cleared without that when the
//! sequence numbers jump back by half of it. The frame boundaries are the payload formats'
//! (`payload::read_position`); an H.264 or H.265 frame starts after a packet of another RTP
//! timestamp, or after the last packet of a frame already completed.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use bytes::Bytes;
use rtp::codec::dependency_descriptor::DependencyDescriptor;

use crate::frame::{AssembledFrame, Codec, CodecHeader, VideoPacket};
use crate::payload::{PacketPosition, depacketize_frame, read_position};
use crate::seq::Unwrapper;

/// libwebrtc's largest packet buffer (`kPacketBufferMaxSize`,
/// `video/rtp_video_stream_receiver2.cc:111`).
pub const DEFAULT_MAX_PACKETS: usize = 2048;

#[derive(Debug, Clone)]
struct Stored {
    sequence_number: u16,
    timestamp: u32,
    payload_type: u8,
    ssrc: u32,
    payload: Bytes,
    arrival: Instant,
    retransmitted: bool,
    marker: bool,
    playout_delay_ms: Option<(u32, u32)>,
    /// `None` for a padding-only packet.
    position: Option<PacketPosition>,
}

impl Stored {
    fn is_padding(&self) -> bool {
        self.position.is_none()
    }
}

/// What one packet changed.
#[derive(Debug, Default)]
pub struct InsertOutcome {
    /// Frames the packet completed, in the order they completed.
    pub frames: Vec<AssembledFrame>,
    /// The extended sequence number of a padding-only packet (it closes a sequence gap).
    pub padding: Option<i64>,
    /// The buffer was full and emptied itself: a key frame is needed.
    pub buffer_cleared: bool,
    /// The packet was a copy of one held already.
    pub duplicate: bool,
    /// The packet was refused as too late (its frame was decoded or given up).
    pub late: bool,
    /// Frames whose packets were complete but whose payload did not parse.
    pub unparsable_frames: usize,
}

/// The packet buffer of one stream.
#[derive(Debug)]
pub struct PacketBuffer {
    codec: Codec,
    max_packets: usize,
    packets: BTreeMap<i64, Stored>,
    unwrapper: Unwrapper,
    /// Packets at or before this one are refused: their frames were decoded or given up.
    cleared_to: Option<i64>,
    /// Last packets of the frames completed (bounded), for the H.264 / H.265 frame starts.
    frame_ends: BTreeSet<i64>,
    emitted_any: bool,
}

impl PacketBuffer {
    /// A buffer for a stream of `codec` holding at most `max_packets` packets.
    pub fn new(codec: Codec, max_packets: usize) -> Self {
        Self {
            codec,
            max_packets: max_packets.max(16),
            packets: BTreeMap::new(),
            unwrapper: Unwrapper::sequence(),
            cleared_to: None,
            frame_ends: BTreeSet::new(),
            emitted_any: false,
        }
    }

    /// The codec.
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// Packets held.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Whether no packet is held.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    /// The extended sequence number `sequence_number` would get, without taking it.
    pub fn peek_sequence(&self, sequence_number: u16) -> i64 {
        self.unwrapper.peek(u32::from(sequence_number))
    }

    /// Takes a packet.
    pub fn insert(&mut self, packet: VideoPacket) -> InsertOutcome {
        let mut out = InsertOutcome::default();
        let seq = self.unwrapper.unwrap(u32::from(packet.sequence_number));
        if self.cleared_to.is_some_and(|c| seq <= c) {
            out.late = true;
            return out;
        }
        if let Some((&oldest, _)) = self.packets.first_key_value()
            && oldest - seq >= (self.max_packets / 2) as i64
        {
            // A large backward jump: start again from this packet.
            self.clear();
        }
        if self.packets.contains_key(&seq) {
            out.duplicate = true;
            return out;
        }
        let span_after = match (
            self.packets.first_key_value(),
            self.packets.last_key_value(),
        ) {
            (Some((&lo, _)), Some((&hi, _))) => hi.max(seq) - lo.min(seq) + 1,
            _ => 1,
        };
        if span_after > self.max_packets as i64 {
            log::warn!("packet buffer full: cleared, a key frame is needed");
            self.clear();
            out.buffer_cleared = true;
            return out;
        }
        let position = read_position(self.codec, packet.marker, &packet.payload)
            .map(|p| with_descriptor(p, packet.dependency_descriptor.as_ref()));
        let padding = position.is_none();
        self.packets.insert(
            seq,
            Stored {
                sequence_number: packet.sequence_number,
                timestamp: packet.timestamp,
                payload_type: packet.payload_type,
                ssrc: packet.ssrc,
                payload: packet.payload,
                arrival: packet.arrival,
                retransmitted: packet.retransmitted,
                marker: packet.marker,
                playout_delay_ms: packet.playout_delay_ms,
                position,
            },
        );
        if padding {
            out.padding = Some(seq);
        }
        let mut candidates = vec![seq, seq + 1];
        while let Some(s) = candidates.pop() {
            if let Some(result) = self.try_complete(s) {
                match result {
                    Ok(frame) => {
                        let end = frame.last_sequence;
                        out.frames.push(frame);
                        candidates.push(end + 1);
                    }
                    Err(end) => {
                        out.unparsable_frames += 1;
                        candidates.push(end + 1);
                    }
                }
            }
        }
        out
    }

    /// Drops every packet at or before `seq` and refuses such packets from now on: their
    /// frames were decoded or given up (libwebrtc `PacketBuffer::ClearTo`).
    pub fn clear_to(&mut self, seq: i64) {
        if self.cleared_to.is_some_and(|c| c >= seq) {
            return;
        }
        self.cleared_to = Some(seq);
        self.packets = self.packets.split_off(&(seq + 1));
        let keep_from = seq - 1;
        self.frame_ends = self.frame_ends.split_off(&keep_from);
    }

    /// Empties the buffer.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.frame_ends.clear();
        self.emitted_any = false;
        self.cleared_to = None;
    }

    /// The oldest packet held, extended.
    pub fn oldest(&self) -> Option<i64> {
        self.packets.first_key_value().map(|(k, _)| *k)
    }

    fn is_start(&self, seq: i64) -> bool {
        let Some(p) = self.packets.get(&seq) else {
            return false;
        };
        let Some(position) = &p.position else {
            return false;
        };
        if let Some(starts) = position.starts_frame {
            return starts;
        }
        // H.264 / H.265: a frame starts after a frame completed, a padding packet, or a packet
        // of another timestamp; the stream's first frame at the first packet held, when it
        // begins a NAL unit.
        if self.frame_ends.contains(&(seq - 1)) {
            return true;
        }
        match self.packets.get(&(seq - 1)) {
            Some(prev) => prev.is_padding() || prev.timestamp != p.timestamp,
            None => {
                !self.emitted_any
                    && self.packets.range(..seq).next().is_none()
                    && h26x_starts_nal(self.codec, &p.payload)
            }
        }
    }

    /// Finds the frame `seq` belongs to and returns it if it is complete: `Ok(frame)`, or
    /// `Err(last)` when it was complete but did not parse (its packets are dropped).
    fn try_complete(&mut self, seq: i64) -> Option<Result<AssembledFrame, i64>> {
        let p = self.packets.get(&seq)?;
        if p.is_padding() {
            return None;
        }
        let timestamp = p.timestamp;
        let mut start = seq;
        while !self.is_start(start) {
            let prev = self.packets.get(&(start - 1))?;
            if prev.is_padding() || prev.timestamp != timestamp {
                return None;
            }
            start -= 1;
        }
        let mut end = seq;
        loop {
            let cur = self.packets.get(&end)?;
            if cur.timestamp != timestamp || cur.is_padding() {
                return None;
            }
            if cur.position.as_ref().is_some_and(|p| p.ends_frame) {
                break;
            }
            end += 1;
        }
        let packets: Vec<Stored> = (start..=end)
            .filter_map(|s| self.packets.remove(&s))
            .collect();
        self.frame_ends.insert(end);
        while self.frame_ends.len() > 64 {
            self.frame_ends.pop_first();
        }
        self.emitted_any = true;
        Some(self.build(start, end, packets).ok_or(end))
    }

    fn build(&self, start: i64, end: i64, packets: Vec<Stored>) -> Option<AssembledFrame> {
        let first = packets.first()?;
        let payloads: Vec<(u16, Bytes)> = packets
            .iter()
            .map(|p| (p.sequence_number, p.payload.clone()))
            .collect();
        let data = depacketize_frame(self.codec, &payloads)?;
        let first_position = first.position.clone().unwrap_or_default();
        let keyframe = match self.codec {
            Codec::H264 | Codec::H265 => packets
                .iter()
                .any(|p| p.position.as_ref().is_some_and(|q| q.keyframe)),
            _ => first_position.keyframe,
        };
        let header = match (&first_position.header, self.codec) {
            // A VP9 frame ends where its last packet had E; the descriptor is the first's.
            (CodecHeader::Vp9 { .. }, _) => {
                let mut h = first_position.header.clone();
                if let CodecHeader::Vp9 {
                    end_of_layer_frame, ..
                } = &mut h
                {
                    *end_of_layer_frame = true;
                }
                h
            }
            _ => first_position.header.clone(),
        };
        Some(AssembledFrame {
            codec: self.codec,
            payload_type: first.payload_type,
            ssrc: first.ssrc,
            rtp_timestamp: first.timestamp,
            first_sequence: start,
            last_sequence: end,
            packet_count: packets.len(),
            first_arrival: packets.iter().map(|p| p.arrival).min()?,
            last_arrival: packets.iter().map(|p| p.arrival).max()?,
            retransmitted: packets.iter().any(|p| p.retransmitted),
            end_of_picture: packets.last().is_some_and(|p| p.marker),
            keyframe,
            resolution: packets
                .iter()
                .find_map(|p| p.position.as_ref().and_then(|q| q.resolution)),
            header,
            playout_delay_ms: packets.iter().find_map(|p| p.playout_delay_ms),
            data,
        })
    }
}

/// Applies a Dependency Descriptor: its start and end of frame are the frame boundaries, and
/// the frame's first packet carries it as the header.
fn with_descriptor(
    mut position: PacketPosition,
    descriptor: Option<&DependencyDescriptor>,
) -> PacketPosition {
    if let Some(dd) = descriptor {
        position.starts_frame = Some(dd.start_of_frame);
        position.ends_frame = dd.end_of_frame;
        if dd.start_of_frame {
            position.header = CodecHeader::Generic(dd.clone());
        }
    }
    position
}

/// Whether an H.264 / H.265 payload begins a NAL unit (not a later fragment).
fn h26x_starts_nal(codec: Codec, payload: &[u8]) -> bool {
    match codec {
        Codec::H264 => match payload.first().map(|b| b & 0x1f) {
            Some(28) | Some(29) => payload.get(1).is_some_and(|fu| fu & 0x80 != 0),
            Some(_) => true,
            None => false,
        },
        Codec::H265 => match payload.first().map(|b| (b >> 1) & 0x3f) {
            Some(49) => payload.get(2).is_some_and(|fu| fu & 0x80 != 0),
            Some(_) => true,
            None => false,
        },
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::vp8_packet;
    use std::time::Duration;

    #[test]
    fn a_frame_completes_whatever_order_its_packets_arrive_in() {
        let t0 = Instant::now();
        let mut b = PacketBuffer::new(Codec::Vp8, DEFAULT_MAX_PACKETS);
        let packets = [
            vp8_packet(t0, 10, 900, true, false, false, 0),
            vp8_packet(t0, 11, 900, false, false, false, 0),
            vp8_packet(t0, 12, 900, false, false, true, 0),
        ];
        assert!(b.insert(packets[2].clone()).frames.is_empty());
        assert!(b.insert(packets[0].clone()).frames.is_empty());
        let out = b.insert(packets[1].clone());
        assert_eq!(out.frames.len(), 1);
        let f = &out.frames[0];
        assert_eq!(
            (f.first_sequence, f.last_sequence, f.packet_count),
            (10, 12, 3)
        );
        assert!(f.keyframe);
        assert!(b.is_empty());
    }

    #[test]
    fn a_duplicate_is_dropped_and_a_late_packet_refused() {
        let t0 = Instant::now();
        let mut b = PacketBuffer::new(Codec::Vp8, DEFAULT_MAX_PACKETS);
        b.insert(vp8_packet(t0, 5, 0, true, false, false, 0));
        assert!(
            b.insert(vp8_packet(t0, 5, 0, true, false, false, 0))
                .duplicate
        );
        b.clear_to(5);
        assert!(b.insert(vp8_packet(t0, 4, 0, true, false, true, 0)).late);
        assert!(b.is_empty());
    }

    #[test]
    fn a_full_buffer_clears_itself_and_asks_for_a_key_frame() {
        let t0 = Instant::now();
        let mut b = PacketBuffer::new(Codec::Vp8, 64);
        // Frames that never complete (their last packet is lost).
        for s in 0..64u16 {
            let o = b.insert(vp8_packet(t0, s, u32::from(s), true, false, false, 0));
            assert!(!o.buffer_cleared);
        }
        let o = b.insert(vp8_packet(t0, 64, 64, true, true, true, 0));
        assert!(o.buffer_cleared);
        assert!(b.is_empty());
    }

    #[test]
    fn a_frame_with_a_missing_middle_packet_waits_for_it() {
        let t0 = Instant::now();
        let mut b = PacketBuffer::new(Codec::Vp8, DEFAULT_MAX_PACKETS);
        b.insert(vp8_packet(t0, 1, 3000, true, false, false, 0));
        let o = b.insert(vp8_packet(t0, 3, 3000, false, false, true, 0));
        assert!(o.frames.is_empty());
        let late = t0 + Duration::from_millis(80);
        let o = b.insert(VideoPacket {
            retransmitted: true,
            ..vp8_packet(late, 2, 3000, false, false, false, 0)
        });
        assert_eq!(o.frames.len(), 1);
        assert!(o.frames[0].retransmitted);
        assert_eq!(o.frames[0].last_arrival, late);
    }

    #[test]
    fn h264_frames_are_split_on_the_timestamp() {
        let t0 = Instant::now();
        let mut b = PacketBuffer::new(Codec::H264, DEFAULT_MAX_PACKETS);
        let nal = |seq: u16, ts: u32, marker: bool, first: u8| VideoPacket {
            arrival: t0,
            sequence_number: seq,
            timestamp: ts,
            marker,
            payload_type: 102,
            ssrc: 1,
            payload: Bytes::from(vec![first, 0x88, 0x84]),
            dependency_descriptor: None,
            playout_delay_ms: None,
            retransmitted: false,
        };
        // An IDR in two NAL units, then a P frame of one.
        assert!(b.insert(nal(100, 0, false, 0x65)).frames.is_empty());
        let o = b.insert(nal(101, 0, true, 0x65));
        assert_eq!(o.frames.len(), 1);
        assert!(o.frames[0].keyframe);
        assert!(o.frames[0].data.starts_with(&[0, 0, 0, 1, 0x65]));
        let o = b.insert(nal(102, 3000, true, 0x41));
        assert_eq!(o.frames.len(), 1);
        assert!(!o.frames[0].keyframe);
        // A P frame whose first packet is lost cannot be told complete.
        let o = b.insert(nal(104, 6000, true, 0x41));
        assert!(o.frames.is_empty());
    }
}

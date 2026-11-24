//! The frame buffer: frames with known references in, the next decodable picture out.
//!
//! libwebrtc's `api/video/frame_buffer.cc` (a222406d) is the model. A frame whose references
//! are not all older is refused; a frame at or before the last decoded one is refused, unless
//! it is a key frame with a newer timestamp, which clears the buffer (`InsertFrame`, lines
//! 76-126); a full buffer takes only a key frame, by clearing itself. The next decodable
//! temporal unit (the frames of one picture) is the first whose references were all decoded
//! or lie inside it (`FindNextAndLastDecodableTemporalUnit`); taking it drops every frame
//! before it. Limits are libwebrtc's: 800 frames held, 8192 decoded ids remembered
//! (`video/video_stream_buffer_controller.cc:46-48`).

use std::collections::{BTreeMap, BTreeSet};

use crate::frame::EncodedFrame;

/// Frames held (libwebrtc `kMaxFramesBuffered`).
pub const DEFAULT_MAX_FRAMES: usize = 800;
/// Decoded frame ids remembered (libwebrtc `kMaxFramesHistory`).
pub const DECODED_HISTORY: usize = 1 << 13;

/// What became of an inserted frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inserted {
    /// Held.
    Held,
    /// Held after the buffer was cleared for it (a key frame into a full buffer, or one newer
    /// than the last decoded frame whose id is older).
    HeldAfterClear,
    /// Refused: a reference is not older than the frame.
    InvalidReferences,
    /// Refused: decoding has passed it.
    Old,
    /// Refused: the buffer is full and the frame is not a key frame.
    Full,
    /// Refused: the same id is held already.
    Duplicate,
}

/// The next picture that can be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodableUnit {
    /// Its first and last frame id.
    pub first_id: i64,
    /// See `first_id`.
    pub last_id: i64,
    /// Its RTP timestamp.
    pub rtp_timestamp: u32,
    /// Whether it starts with a key frame.
    pub keyframe: bool,
    /// Whether a later decodable picture is held too.
    pub more_decodable: bool,
}

/// The frame buffer of one stream.
#[derive(Debug)]
pub struct FrameBuffer {
    frames: BTreeMap<i64, EncodedFrame>,
    max_frames: usize,
    decoded: BTreeSet<i64>,
    last_decoded: Option<(i64, i64)>,
    dropped_frames: u64,
    dropped_packets: u64,
}

impl Default for FrameBuffer {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAMES)
    }
}

impl FrameBuffer {
    /// A buffer holding at most `max_frames` frames.
    pub fn new(max_frames: usize) -> Self {
        Self {
            frames: BTreeMap::new(),
            max_frames: max_frames.max(1),
            decoded: BTreeSet::new(),
            last_decoded: None,
            dropped_frames: 0,
            dropped_packets: 0,
        }
    }

    /// Frames held.
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    /// Whether no frame is held.
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Frames that left the buffer without being decoded (W3C `framesDropped`).
    pub fn dropped_frames(&self) -> u64 {
        self.dropped_frames
    }

    /// Packets of those frames (W3C `packetsDiscarded`).
    pub fn dropped_packets(&self) -> u64 {
        self.dropped_packets
    }

    /// The id and extended timestamp of the last frame decoded.
    pub fn last_decoded(&self) -> Option<(i64, i64)> {
        self.last_decoded
    }

    /// The first sequence number of the oldest frame held.
    pub fn oldest_sequence(&self) -> Option<i64> {
        self.frames.values().map(|f| f.frame.first_sequence).min()
    }

    /// Takes a frame.
    pub fn insert(&mut self, frame: EncodedFrame) -> Inserted {
        if frame.references.iter().any(|r| *r >= frame.id) {
            return Inserted::InvalidReferences;
        }
        let mut cleared = false;
        if let Some((last_id, last_ts)) = self.last_decoded
            && frame.id <= last_id
        {
            if frame.is_keyframe() && frame.unwrapped_timestamp > last_ts {
                self.clear();
                cleared = true;
            } else {
                return Inserted::Old;
            }
        }
        if self.frames.len() >= self.max_frames {
            if frame.is_keyframe() {
                self.clear();
                cleared = true;
            } else {
                return Inserted::Full;
            }
        }
        if self.frames.contains_key(&frame.id) {
            return Inserted::Duplicate;
        }
        self.frames.insert(frame.id, frame);
        if cleared {
            Inserted::HeldAfterClear
        } else {
            Inserted::Held
        }
    }

    fn was_decoded(&self, id: i64) -> bool {
        self.decoded.contains(&id)
    }

    /// The pictures that can be decoded now, in order; with `keyframe_only` the first that
    /// starts with a key frame and those after it.
    fn decodable_units(&self, keyframe_only: bool, limit: usize) -> Vec<DecodableUnit> {
        let mut units = Vec::new();
        let mut iter = self.frames.values().peekable();
        while let Some(first) = iter.next() {
            let ts = first.unwrapped_timestamp;
            let first_id = first.id;
            let mut last = first;
            let mut decodable = true;
            let check = |f: &EncodedFrame, decodable: &mut bool, me: &Self| {
                for r in &f.references {
                    let inside = *r >= first_id && me.frames.contains_key(r);
                    if !inside && !me.was_decoded(*r) {
                        *decodable = false;
                    }
                }
            };
            check(first, &mut decodable, self);
            let mut complete = first.frame.end_of_picture;
            while let Some(next) = iter.peek() {
                if next.unwrapped_timestamp != ts {
                    complete = true;
                    break;
                }
                let next = iter.next().expect("peeked");
                check(next, &mut decodable, self);
                complete = next.frame.end_of_picture;
                last = next;
            }
            if !decodable || !complete {
                continue;
            }
            if keyframe_only && units.is_empty() && !first.is_keyframe() {
                continue;
            }
            units.push(DecodableUnit {
                first_id,
                last_id: last.id,
                rtp_timestamp: first.frame.rtp_timestamp,
                keyframe: first.is_keyframe(),
                more_decodable: false,
            });
            if units.len() >= limit {
                break;
            }
        }
        units
    }

    /// The next picture that can be decoded.
    pub fn next_decodable(&self, keyframe_only: bool) -> Option<DecodableUnit> {
        let units = self.decodable_units(keyframe_only, 2);
        let mut first = *units.first()?;
        first.more_decodable = units.len() > 1;
        Some(first)
    }

    /// Takes the picture `unit` out for decoding: its frames, in id order. Every frame before
    /// it is dropped.
    pub fn extract(&mut self, unit: &DecodableUnit) -> Vec<EncodedFrame> {
        let rest = self.frames.split_off(&(unit.last_id + 1));
        let taken = std::mem::replace(&mut self.frames, rest);
        let mut out = Vec::new();
        for (id, f) in taken {
            if id >= unit.first_id {
                self.decoded.insert(id);
                self.last_decoded = Some((id, f.unwrapped_timestamp));
                out.push(f);
            } else {
                self.count_drop(&f);
            }
        }
        while self.decoded.len() > DECODED_HISTORY {
            self.decoded.pop_first();
        }
        out
    }

    /// Drops the picture `unit` (it missed its time) and every frame before it.
    pub fn drop_unit(&mut self, unit: &DecodableUnit) {
        let rest = self.frames.split_off(&(unit.last_id + 1));
        let taken = std::mem::replace(&mut self.frames, rest);
        for (_, f) in taken {
            self.count_drop(&f);
        }
        // A dropped picture is not decoded: what depends on it stays undecodable.
    }

    /// Empties the buffer and forgets what was decoded.
    pub fn clear(&mut self) {
        let taken = std::mem::take(&mut self.frames);
        for f in taken.values() {
            self.count_drop(f);
        }
        self.decoded.clear();
        self.last_decoded = None;
    }

    fn count_drop(&mut self, f: &EncodedFrame) {
        self.dropped_frames += 1;
        self.dropped_packets += f.frame.packet_count as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::CodecHeader;
    use crate::test_util::assembled;

    fn frame(id: i64, refs: Vec<i64>, key: bool) -> EncodedFrame {
        EncodedFrame {
            frame: assembled(id, key, CodecHeader::None),
            id,
            references: refs,
            spatial_id: 0,
            temporal_id: 0,
            unwrapped_timestamp: id * 3000,
            layer_ids: Vec::new(),
        }
    }

    #[test]
    fn a_frame_is_decodable_once_its_references_are_decoded() {
        let mut b = FrameBuffer::default();
        assert_eq!(b.insert(frame(2, vec![1], false)), Inserted::Held);
        assert_eq!(b.next_decodable(false), None);
        b.insert(frame(1, vec![], true));
        let u = b.next_decodable(false).unwrap();
        assert_eq!((u.first_id, u.keyframe, u.more_decodable), (1, true, false));
        assert_eq!(b.extract(&u).len(), 1);
        let u = b.next_decodable(false).unwrap();
        assert_eq!(u.first_id, 2);
    }

    #[test]
    fn a_later_key_frame_skips_an_undecodable_chain_and_counts_it_dropped() {
        let mut b = FrameBuffer::default();
        b.insert(frame(1, vec![], true));
        let u = b.next_decodable(false).unwrap();
        b.extract(&u);
        // 2 is lost; 3 depends on it; 4 is a key frame.
        b.insert(frame(3, vec![2], false));
        b.insert(frame(4, vec![], true));
        let u = b.next_decodable(false).unwrap();
        assert_eq!(u.first_id, 4);
        b.extract(&u);
        assert_eq!(b.dropped_frames(), 1);
        assert_eq!(b.insert(frame(3, vec![2], false)), Inserted::Old);
    }

    #[test]
    fn keyframe_only_passes_over_decodable_delta_frames() {
        let mut b = FrameBuffer::default();
        b.insert(frame(1, vec![], true));
        let u = b.next_decodable(false).unwrap();
        b.extract(&u);
        b.insert(frame(2, vec![1], false));
        b.insert(frame(3, vec![], true));
        assert_eq!(b.next_decodable(true).unwrap().first_id, 3);
        assert_eq!(b.next_decodable(false).unwrap().first_id, 2);
    }

    #[test]
    fn a_full_buffer_takes_only_a_key_frame_by_clearing() {
        let mut b = FrameBuffer::new(2);
        b.insert(frame(5, vec![4], false));
        b.insert(frame(6, vec![5], false));
        assert_eq!(b.insert(frame(7, vec![6], false)), Inserted::Full);
        assert_eq!(b.insert(frame(8, vec![], true)), Inserted::HeldAfterClear);
        assert_eq!(b.len(), 1);
        assert_eq!(b.dropped_frames(), 2);
    }

    #[test]
    fn references_must_be_older() {
        let mut b = FrameBuffer::default();
        assert_eq!(
            b.insert(frame(5, vec![5], false)),
            Inserted::InvalidReferences
        );
    }
}

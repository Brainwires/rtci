//! The frame reference finder: which frames each frame is predicted from.
//!
//! The dispatch is libwebrtc's (`modules/video_coding/rtp_frame_reference_finder.cc:62-115`,
//! a222406d): a Dependency Descriptor wins; VP8 with TID and TL0PICIDX uses the temporal-layer
//! finder, VP8 with a PictureID only the picture-id finder, VP8 without one the sequence-number
//! finder; VP9 the same with its own finder; H.264 and H.265 sequence numbers only. The
//! references come from the payload formats: RFC 7741 section 4.2 (VP8), RFC 9628 section 4.2
//! (VP9 flexible P_DIFF, non-flexible picture groups), the AV1 RTP specification appendix A
//! (frame_number, fdiffs).
//!
//! Frame ids are extended (`i64`) and increase in decode order. When the finder in use changes
//! (a stream starts or stops sending a descriptor) the new finder's ids are moved past the old
//! one's, so ids never go back.

use std::collections::{BTreeMap, BTreeSet};

use crate::frame::{AssembledFrame, CodecHeader, EncodedFrame, PictureGroup};
use crate::seq::Unwrapper;

/// Frames held back because their references are not known yet (libwebrtc
/// `kMaxStashedFrames`, `rtp_vp8_ref_finder.h:42`).
pub const MAX_STASHED_FRAMES: usize = 100;
/// TL0 indices whose layer state is kept (libwebrtc `kMaxLayerInfo`).
pub const MAX_LAYER_INFO: i64 = 50;
/// Frame ids a VP9 picture spans: one per spatial layer (libwebrtc `kMaxSpatialLayers`).
pub const MAX_SPATIAL_LAYERS: i64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    SequenceNumber,
    PictureId,
    Vp8,
    Vp9,
    Generic,
}

fn kind_of(frame: &AssembledFrame) -> Kind {
    match &frame.header {
        CodecHeader::Generic(_) => Kind::Generic,
        CodecHeader::Vp8 {
            picture_id,
            tl0_pic_idx,
            temporal_id,
            ..
        } => match (picture_id, tl0_pic_idx, temporal_id) {
            (Some(_), Some(_), Some(_)) => Kind::Vp8,
            (Some(_), _, _) => Kind::PictureId,
            _ => Kind::SequenceNumber,
        },
        CodecHeader::Vp9 {
            picture_id,
            temporal_id,
            ..
        } => match (picture_id, temporal_id) {
            (Some(_), Some(_)) => Kind::Vp9,
            (Some(_), None) => Kind::PictureId,
            _ => Kind::SequenceNumber,
        },
        CodecHeader::None => Kind::SequenceNumber,
    }
}

/// A finder's verdict on a frame.
enum Decision {
    HandOff(EncodedFrame),
    Stash(AssembledFrame),
    Drop,
}

/// The reference finder of one stream.
#[derive(Debug)]
pub struct ReferenceFinder {
    finder: Option<Finder>,
    /// Added to the finder's ids so that they keep increasing across finders.
    offset: i64,
    /// The largest id handed out.
    last_id: Option<i64>,
    /// Set when a new finder took over: the offset is fixed at its first frame.
    rebase: bool,
    timestamps: Unwrapper,
    dropped: u64,
}

impl Default for ReferenceFinder {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceFinder {
    /// A finder that has seen nothing.
    pub fn new() -> Self {
        Self {
            finder: None,
            offset: 0,
            last_id: None,
            rebase: false,
            timestamps: Unwrapper::timestamp(),
            dropped: 0,
        }
    }

    /// Frames the finders refused (references in the past, a key frame on an upper layer,
    /// stash overflow).
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Takes a complete frame; returns the frames whose references are now known, in the
    /// order they became known.
    pub fn manage(&mut self, frame: AssembledFrame) -> Vec<EncodedFrame> {
        let kind = kind_of(&frame);
        if self.finder.as_ref().map(Finder::kind) != Some(kind) {
            self.finder = Some(Finder::new(kind));
            self.rebase = self.last_id.is_some();
        }
        let ts = self.timestamps.unwrap(frame.rtp_timestamp);
        let finder = self.finder.as_mut().expect("set above");
        let mut out = finder.manage(frame, ts);
        self.dropped += finder.take_dropped();
        self.finish(&mut out);
        out
    }

    /// A padding-only packet closed a sequence gap.
    pub fn padding(&mut self, seq: i64) -> Vec<EncodedFrame> {
        let Some(Finder::SequenceNumber(f)) = &mut self.finder else {
            return Vec::new();
        };
        let mut out = f.padding(seq);
        self.finish(&mut out);
        out
    }

    /// Forgets stashed frames that start at or before `seq`: they will not be decoded.
    pub fn clear_to(&mut self, seq: i64) {
        if let Some(f) = &mut self.finder {
            f.clear_to(seq);
        }
    }

    fn finish(&mut self, out: &mut [EncodedFrame]) {
        if self.rebase
            && let (Some(first), Some(last)) = (out.first(), self.last_id)
        {
            self.offset = last + 1 - first.id;
            self.rebase = false;
        }
        for f in out.iter_mut() {
            f.id += self.offset;
            for r in &mut f.references {
                *r += self.offset;
            }
            self.last_id = Some(self.last_id.map_or(f.id, |l| l.max(f.id)));
        }
    }
}

#[derive(Debug)]
enum Finder {
    SequenceNumber(SeqNumFinder),
    PictureId(PictureIdFinder),
    Vp8(Vp8Finder),
    Vp9(Vp9Finder),
    Generic(GenericFinder),
}

impl Finder {
    fn new(kind: Kind) -> Self {
        match kind {
            Kind::SequenceNumber => Self::SequenceNumber(SeqNumFinder::default()),
            Kind::PictureId => Self::PictureId(PictureIdFinder::default()),
            Kind::Vp8 => Self::Vp8(Vp8Finder::default()),
            Kind::Vp9 => Self::Vp9(Vp9Finder::default()),
            Kind::Generic => Self::Generic(GenericFinder::default()),
        }
    }

    fn kind(&self) -> Kind {
        match self {
            Self::SequenceNumber(_) => Kind::SequenceNumber,
            Self::PictureId(_) => Kind::PictureId,
            Self::Vp8(_) => Kind::Vp8,
            Self::Vp9(_) => Kind::Vp9,
            Self::Generic(_) => Kind::Generic,
        }
    }

    fn take_dropped(&mut self) -> u64 {
        let d = match self {
            Self::SequenceNumber(f) => &mut f.stash.dropped,
            Self::PictureId(f) => &mut f.dropped,
            Self::Vp8(f) => &mut f.stash.dropped,
            Self::Vp9(f) => &mut f.stash.dropped,
            Self::Generic(f) => &mut f.dropped,
        };
        std::mem::take(d)
    }

    fn manage(&mut self, frame: AssembledFrame, ts: i64) -> Vec<EncodedFrame> {
        match self {
            Self::SequenceNumber(f) => f.manage(frame, ts),
            Self::PictureId(f) => f.manage(frame, ts),
            Self::Vp8(f) => f.manage(frame, ts),
            Self::Vp9(f) => f.manage(frame, ts),
            Self::Generic(f) => f.manage(frame, ts),
        }
    }

    fn clear_to(&mut self, seq: i64) {
        match self {
            Self::SequenceNumber(f) => f.stash.clear_to(seq),
            Self::Vp8(f) => f.stash.clear_to(seq),
            Self::Vp9(f) => f.stash.clear_to(seq),
            Self::PictureId(_) | Self::Generic(_) => {}
        }
    }
}

fn encoded(
    frame: AssembledFrame,
    id: i64,
    references: Vec<i64>,
    spatial_id: u8,
    temporal_id: u8,
    ts: i64,
) -> EncodedFrame {
    EncodedFrame {
        frame,
        id,
        references,
        spatial_id,
        temporal_id,
        unwrapped_timestamp: ts,
        layer_ids: Vec::new(),
    }
}

/// Frames waiting for their references, retried after every frame handed off.
#[derive(Debug, Default)]
struct Stash {
    frames: Vec<(AssembledFrame, i64)>,
    dropped: u64,
}

impl Stash {
    fn push(&mut self, frame: AssembledFrame, ts: i64) {
        if self.frames.len() >= MAX_STASHED_FRAMES {
            self.frames.remove(0);
            self.dropped += 1;
        }
        self.frames.push((frame, ts));
    }

    fn clear_to(&mut self, seq: i64) {
        let before = self.frames.len();
        self.frames.retain(|(f, _)| f.first_sequence > seq);
        self.dropped += (before - self.frames.len()) as u64;
    }

    /// Runs `decide` over the stash until nothing more is handed off.
    fn retry(
        &mut self,
        out: &mut Vec<EncodedFrame>,
        mut decide: impl FnMut(AssembledFrame, i64) -> Decision,
    ) {
        loop {
            let mut progressed = false;
            let pending = std::mem::take(&mut self.frames);
            for (frame, ts) in pending {
                match decide(frame, ts) {
                    Decision::HandOff(f) => {
                        out.push(f);
                        progressed = true;
                    }
                    Decision::Stash(frame) => self.frames.push((frame, ts)),
                    Decision::Drop => self.dropped += 1,
                }
            }
            if !progressed {
                break;
            }
        }
    }
}

/// Streams with no frame numbering (H.264, H.265, VP8 / VP9 without a PictureID): a delta
/// frame refers to the frame whose last packet precedes its first, padding included
/// (libwebrtc `rtp_seq_num_only_ref_finder.cc`). Frame ids are last sequence numbers.
#[derive(Debug, Default)]
struct SeqNumFinder {
    /// Id of the last frame of the chain, and the last sequence number it covers with padding.
    chain: Option<(i64, i64)>,
    padding: BTreeSet<i64>,
    stash: Stash,
}

impl SeqNumFinder {
    fn decide(chain: &mut Option<(i64, i64)>, frame: AssembledFrame, ts: i64) -> Decision {
        let id = frame.last_sequence;
        if frame.keyframe {
            if chain.is_some_and(|(last, _)| id <= last) {
                return Decision::Drop;
            }
            *chain = Some((id, id));
            return Decision::HandOff(encoded(frame, id, Vec::new(), 0, 0, ts));
        }
        let Some((last, covered)) = *chain else {
            return Decision::Stash(frame);
        };
        if frame.first_sequence <= covered {
            return Decision::Drop;
        }
        if frame.first_sequence != covered + 1 {
            return Decision::Stash(frame);
        }
        *chain = Some((id, id));
        Decision::HandOff(encoded(frame, id, vec![last], 0, 0, ts))
    }

    fn absorb_padding(&mut self) {
        if let Some((last, mut covered)) = self.chain {
            while self.padding.remove(&(covered + 1)) {
                covered += 1;
            }
            self.padding = self.padding.split_off(&covered);
            self.chain = Some((last, covered));
        }
    }

    fn manage(&mut self, frame: AssembledFrame, ts: i64) -> Vec<EncodedFrame> {
        let mut out = Vec::new();
        match Self::decide(&mut self.chain, frame, ts) {
            Decision::HandOff(f) => out.push(f),
            Decision::Stash(f) => {
                self.stash.push(f, ts);
                return out;
            }
            Decision::Drop => {
                self.stash.dropped += 1;
                return out;
            }
        }
        self.absorb_padding();
        self.retry(&mut out);
        out
    }

    fn padding(&mut self, seq: i64) -> Vec<EncodedFrame> {
        self.padding.insert(seq);
        while self.padding.len() > 1000 {
            self.padding.pop_first();
        }
        self.absorb_padding();
        let mut out = Vec::new();
        self.retry(&mut out);
        out
    }

    fn retry(&mut self, out: &mut Vec<EncodedFrame>) {
        loop {
            let before = out.len();
            let chain = &mut self.chain;
            self.stash.retry(out, |f, ts| Self::decide(chain, f, ts));
            if out.len() == before {
                break;
            }
            self.absorb_padding();
        }
    }
}

/// Streams with a PictureID and no layer information: a delta frame refers to the picture
/// before it (libwebrtc `RtpFrameIdOnlyRefFinder`).
#[derive(Debug, Default)]
struct PictureIdFinder {
    unwrapper: Option<(Unwrapper, bool)>,
    dropped: u64,
}

impl PictureIdFinder {
    fn manage(&mut self, frame: AssembledFrame, ts: i64) -> Vec<EncodedFrame> {
        let Some((pid, wide)) = picture_id(&frame.header) else {
            self.dropped += 1;
            return Vec::new();
        };
        let id = unwrap_picture_id(&mut self.unwrapper, pid, wide);
        let (spatial_id, temporal_id) = layers(&frame.header);
        let refs = if frame.keyframe { vec![] } else { vec![id - 1] };
        vec![encoded(frame, id, refs, spatial_id, temporal_id, ts)]
    }
}

fn picture_id(header: &CodecHeader) -> Option<(u16, bool)> {
    match header {
        CodecHeader::Vp8 { picture_id, .. } | CodecHeader::Vp9 { picture_id, .. } => *picture_id,
        _ => None,
    }
}

fn layers(header: &CodecHeader) -> (u8, u8) {
    match header {
        CodecHeader::Vp8 { temporal_id, .. } => (0, temporal_id.unwrap_or(0)),
        CodecHeader::Vp9 {
            spatial_id,
            temporal_id,
            ..
        } => (*spatial_id, temporal_id.unwrap_or(0)),
        CodecHeader::Generic(dd) => (dd.spatial_id, dd.temporal_id),
        CodecHeader::None => (0, 0),
    }
}

/// Extends a PictureID, whose width (7 or 15 bits) may change mid-stream (RFC 7741 section
/// 4.2): a change of width restarts the extension from the last extended value.
fn unwrap_picture_id(state: &mut Option<(Unwrapper, bool)>, pid: u16, wide: bool) -> i64 {
    let bits = if wide { 15 } else { 7 };
    match state {
        Some((u, w)) if *w == wide => u.unwrap(u32::from(pid)),
        Some((u, w)) => {
            // Continue from the last value: the new width's nearest value above it.
            let last = u.peek(u32::from(pid) & ((1 << bits) - 1));
            let mut nu = Unwrapper::new(bits);
            nu.unwrap(u32::from(pid));
            *w = wide;
            *u = nu;
            last
        }
        None => {
            let mut u = Unwrapper::new(bits);
            let v = u.unwrap(u32::from(pid));
            *state = Some((u, wide));
            v
        }
    }
}

/// VP8 with temporal layers (libwebrtc `rtp_vp8_ref_finder.cc`): per TL0PICIDX, the last
/// picture of each temporal layer. A base-layer frame refers to the previous base-layer frame;
/// a layer-sync frame (Y) to the base layer only; any other frame to the last frame of its own
/// and every lower layer, and waits while a picture between them has not arrived.
#[derive(Debug, Default)]
struct Vp8Finder {
    pid: Option<(Unwrapper, bool)>,
    tl0: Option<Unwrapper>,
    layer_info: BTreeMap<i64, [i64; 4]>,
    newest_pid: Option<i64>,
    not_received: BTreeSet<i64>,
    stash: Stash,
}

impl Vp8Finder {
    fn manage(&mut self, frame: AssembledFrame, ts: i64) -> Vec<EncodedFrame> {
        let CodecHeader::Vp8 {
            picture_id: Some((pid, wide)),
            tl0_pic_idx: Some(tl0),
            ..
        } = frame.header
        else {
            return Vec::new();
        };
        let pid = unwrap_picture_id(&mut self.pid, pid, wide);
        let tl0 = self
            .tl0
            .get_or_insert_with(|| Unwrapper::new(8))
            .unwrap(u32::from(tl0));
        match self.newest_pid {
            Some(newest) if pid > newest => {
                for missing in newest + 1..pid {
                    self.not_received.insert(missing);
                }
                self.newest_pid = Some(pid);
            }
            None => self.newest_pid = Some(pid),
            _ => {}
        }
        // Keep the state of the last MAX_LAYER_INFO base-layer frames.
        if let Some((&newest_tl0, _)) = self.layer_info.last_key_value() {
            self.layer_info = self.layer_info.split_off(&(newest_tl0 - MAX_LAYER_INFO));
        }
        if let Some(newest) = self.newest_pid {
            self.not_received = self.not_received.split_off(&(newest - 1000));
        }
        let mut out = Vec::new();
        match self.decide(frame, pid, tl0, ts) {
            Decision::HandOff(f) => out.push(f),
            Decision::Stash(f) => {
                self.stash.push(f, ts);
                return out;
            }
            Decision::Drop => {
                self.stash.dropped += 1;
                return out;
            }
        }
        let mut stash = std::mem::take(&mut self.stash);
        stash.retry(&mut out, |f, ts| {
            let (pid, tl0) = self.peek_ids(&f);
            self.decide(f, pid, tl0, ts)
        });
        self.stash = stash;
        out
    }

    fn peek_ids(&self, frame: &AssembledFrame) -> (i64, i64) {
        let CodecHeader::Vp8 {
            picture_id: Some((pid, _)),
            tl0_pic_idx: Some(tl0),
            ..
        } = frame.header
        else {
            return (i64::MIN, i64::MIN);
        };
        let pid = self
            .pid
            .as_ref()
            .map_or(i64::from(pid), |(u, _)| u.peek(u32::from(pid)));
        let tl0 = self
            .tl0
            .as_ref()
            .map_or(i64::from(tl0), |u| u.peek(u32::from(tl0)));
        (pid, tl0)
    }

    fn decide(&mut self, frame: AssembledFrame, pid: i64, tl0: i64, ts: i64) -> Decision {
        let (tid, sync) = match frame.header {
            CodecHeader::Vp8 {
                temporal_id,
                layer_sync,
                ..
            } => (usize::from(temporal_id.unwrap_or(0)).min(3), layer_sync),
            _ => return Decision::Drop,
        };
        if frame.keyframe {
            if tid != 0 {
                return Decision::Drop;
            }
            self.layer_info.insert(tl0, [-1; 4]);
            self.update(pid, tl0, tid);
            return Decision::HandOff(encoded(frame, pid, vec![], 0, 0, ts));
        }
        let key = if tid == 0 { tl0 - 1 } else { tl0 };
        let Some(info) = self.layer_info.get(&key).copied() else {
            return Decision::Stash(frame);
        };
        if tid == 0 {
            self.layer_info.insert(tl0, info);
            if info[0] >= pid {
                return Decision::Drop;
            }
            self.update(pid, tl0, tid);
            return Decision::HandOff(encoded(frame, pid, vec![info[0]], 0, 0, ts));
        }
        if sync {
            if info[tid] != -1 && info[tid] >= pid {
                return Decision::Drop;
            }
            self.update(pid, tl0, tid);
            return Decision::HandOff(encoded(frame, pid, vec![info[0]], 0, tid as u8, ts));
        }
        let mut refs = Vec::new();
        for &last in info.iter().take(tid + 1) {
            if last == -1 {
                return Decision::Stash(frame);
            }
            if last >= pid {
                return Decision::Drop;
            }
            if self.not_received.range(last + 1..pid).next().is_some() {
                return Decision::Stash(frame);
            }
            refs.push(last);
        }
        self.update(pid, tl0, tid);
        Decision::HandOff(encoded(frame, pid, refs, 0, tid as u8, ts))
    }

    fn update(&mut self, pid: i64, mut tl0: i64, tid: usize) {
        while let Some(info) = self.layer_info.get_mut(&tl0) {
            if info[tid] != -1 && info[tid] > pid {
                break;
            }
            info[tid] = pid;
            tl0 += 1;
        }
        self.not_received.remove(&pid);
    }
}

/// VP9 (RFC 9628 section 4.2). A frame's id is `picture * MAX_SPATIAL_LAYERS + SID`. Flexible
/// mode: the references are the P_DIFFs on the same spatial layer, and the lower layer of the
/// same picture when D is set. Non-flexible mode: the picture group of the last scalability
/// structure gives each picture's P_DIFFs, by its position after the picture that carried it;
/// without one, the picture before on the same layer.
#[derive(Debug, Default)]
struct Vp9Finder {
    pid: Option<(Unwrapper, bool)>,
    /// The picture group and the picture that carried it.
    gof: Option<(i64, PictureGroup)>,
    stash: Stash,
}

impl Vp9Finder {
    fn manage(&mut self, frame: AssembledFrame, ts: i64) -> Vec<EncodedFrame> {
        let CodecHeader::Vp9 {
            picture_id: Some((pid, wide)),
            flexible,
            inter_picture_predicted,
            temporal_id,
            spatial_id,
            inter_layer_dependency,
            ref p_diff,
            ref gof,
            ..
        } = frame.header
        else {
            return Vec::new();
        };
        let picture = unwrap_picture_id(&mut self.pid, pid, wide);
        if let Some(g) = gof
            && !g.is_empty()
        {
            self.gof = Some((picture, g.clone()));
        }
        let tid = temporal_id.unwrap_or(0);
        let sid = i64::from(spatial_id);
        let id = picture * MAX_SPATIAL_LAYERS + sid;
        let mut refs = Vec::new();
        if inter_picture_predicted {
            let diffs: Vec<u8> = if flexible {
                p_diff.clone()
            } else if let Some((start, g)) = &self.gof {
                let index = (picture - start).rem_euclid(g.len() as i64) as usize;
                if picture > *start {
                    g[index].1.clone()
                } else {
                    vec![1]
                }
            } else {
                vec![1]
            };
            for d in diffs {
                refs.push((picture - i64::from(d)) * MAX_SPATIAL_LAYERS + sid);
            }
        }
        if inter_layer_dependency && sid > 0 {
            refs.push(picture * MAX_SPATIAL_LAYERS + sid - 1);
        }
        refs.sort_unstable();
        refs.dedup();
        if refs.iter().any(|r| *r >= id) {
            self.stash.dropped += 1;
            return Vec::new();
        }
        let spatial = spatial_id;
        vec![encoded(frame, id, refs, spatial, tid, ts)]
    }
}

/// The Dependency Descriptor (AV1 RTP specification appendix A): the frame number extended,
/// the references `frame_number - fdiff`.
#[derive(Debug, Default)]
struct GenericFinder {
    unwrapper: Option<Unwrapper>,
    dropped: u64,
}

impl GenericFinder {
    fn manage(&mut self, frame: AssembledFrame, ts: i64) -> Vec<EncodedFrame> {
        let CodecHeader::Generic(dd) = &frame.header else {
            self.dropped += 1;
            return Vec::new();
        };
        let id = self
            .unwrapper
            .get_or_insert_with(|| Unwrapper::new(16))
            .unwrap(u32::from(dd.frame_number));
        let refs: Vec<i64> = dd.fdiffs.iter().map(|d| id - i64::from(*d)).collect();
        let (s, t) = (dd.spatial_id, dd.temporal_id);
        vec![encoded(frame, id, refs, s, t, ts)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::assembled;

    fn vp8(pid: u16, tl0: u8, tid: u8, sync: bool) -> CodecHeader {
        CodecHeader::Vp8 {
            picture_id: Some((pid, true)),
            tl0_pic_idx: Some(tl0),
            temporal_id: Some(tid),
            layer_sync: sync,
        }
    }

    fn ids(frames: &[EncodedFrame]) -> Vec<(i64, Vec<i64>)> {
        frames
            .iter()
            .map(|f| (f.id, f.references.clone()))
            .collect()
    }

    #[test]
    fn vp8_l1t3_references_follow_the_layer_pattern() {
        // The usual three-layer pattern: 0 2 1 2 0 2 1 2, TL0PICIDX counting base frames.
        let mut r = ReferenceFinder::new();
        let pattern = [
            (0u8, false),
            (2, true),
            (1, true),
            (2, false),
            (0, false),
            (2, true),
        ];
        let mut tl0 = 0u8;
        let mut got = Vec::new();
        for (i, (tid, sync)) in pattern.iter().enumerate() {
            if *tid == 0 && i > 0 {
                tl0 += 1;
            }
            let f = assembled(i as i64 * 2, i == 0, vp8(i as u16, tl0, *tid, *sync));
            got.extend(r.manage(f));
        }
        assert_eq!(
            ids(&got),
            vec![
                (0, vec![]),
                (1, vec![0]),
                (2, vec![0]),
                (3, vec![0, 2, 1]),
                (4, vec![0]),
                (5, vec![4]),
            ]
        );
    }

    #[test]
    fn a_vp8_frame_waits_for_a_missing_picture_of_its_layers() {
        let mut r = ReferenceFinder::new();
        assert_eq!(r.manage(assembled(0, true, vp8(0, 0, 0, false))).len(), 1);
        // Picture 1 (TL1, not sync) is late; picture 2 (TL1) depends on it.
        assert!(
            r.manage(assembled(4, false, vp8(2, 0, 1, false)))
                .is_empty()
        );
        let got = r.manage(assembled(2, false, vp8(1, 0, 1, true)));
        assert_eq!(ids(&got), vec![(1, vec![0]), (2, vec![0, 1])]);
    }

    #[test]
    fn sequence_number_chain_waits_for_a_gap_and_padding_closes_it() {
        let mut r = ReferenceFinder::new();
        let got = r.manage(assembled(10, true, CodecHeader::None));
        assert_eq!(ids(&got), vec![(10, vec![])]);
        // Next frame starts at 12: 11 is missing.
        assert!(r.manage(assembled(12, false, CodecHeader::None)).is_empty());
        let got = r.padding(11);
        assert_eq!(ids(&got), vec![(12, vec![10])]);
    }

    #[test]
    fn dependency_descriptor_references_are_frame_number_differences() {
        use rtp::codec::dependency_descriptor::DependencyDescriptor;
        let dd = |n: u16, fdiffs: Vec<u16>| {
            CodecHeader::Generic(DependencyDescriptor {
                start_of_frame: true,
                end_of_frame: true,
                frame_number: n,
                fdiffs,
                ..Default::default()
            })
        };
        let mut r = ReferenceFinder::new();
        let mut got = r.manage(assembled(0, true, dd(65_535, vec![])));
        got.extend(r.manage(assembled(1, false, dd(0, vec![1]))));
        got.extend(r.manage(assembled(2, false, dd(2, vec![2, 1]))));
        assert_eq!(
            ids(&got),
            vec![
                (65_535, vec![]),
                (65_536, vec![65_535]),
                (65_538, vec![65_536, 65_537])
            ]
        );
    }

    #[test]
    fn vp9_flexible_mode_and_inter_layer_references() {
        let vp9 = |pid: u16, sid: u8, p: bool, d: bool, p_diff: Vec<u8>| CodecHeader::Vp9 {
            picture_id: Some((pid, true)),
            flexible: true,
            inter_picture_predicted: p,
            temporal_id: Some(0),
            spatial_id: sid,
            inter_layer_dependency: d,
            tl0_pic_idx: None,
            p_diff,
            gof: None,
            end_of_layer_frame: true,
        };
        let mut r = ReferenceFinder::new();
        let mut got = r.manage(assembled(0, true, vp9(10, 0, false, false, vec![])));
        got.extend(r.manage(assembled(1, false, vp9(10, 1, false, true, vec![]))));
        got.extend(r.manage(assembled(2, false, vp9(11, 0, true, false, vec![1]))));
        got.extend(r.manage(assembled(3, false, vp9(11, 1, true, true, vec![1]))));
        assert_eq!(
            ids(&got),
            vec![
                (50, vec![]),
                (51, vec![50]),
                (55, vec![50]),
                (56, vec![51, 55])
            ]
        );
    }

    #[test]
    fn ids_keep_increasing_when_the_stream_changes_finder() {
        let mut r = ReferenceFinder::new();
        let a = r.manage(assembled(500, true, CodecHeader::None));
        let b = r.manage(assembled(501, true, vp8(3, 0, 0, false)));
        assert!(b[0].id > a[0].id);
    }
}

//! Forwarding by decode target.

use std::collections::{HashMap, VecDeque};

use super::{
    DecodeTargetIndication, DependencyDescriptor, DependencyDescriptorReader,
    FrameDependencyStructure,
};

/// How many frames back the selector remembers what it did with a frame.
const HISTORY: usize = 1024;

/// What the selector remembers of a frame it has seen.
#[derive(Debug, Clone, Copy)]
struct FrameRecord {
    forwarded: bool,
    /// Per chain (a bit each): the receiver was sent the previous frame of the chain, and all
    /// of the chain before it.
    chains_forwarded: u32,
}

/// Decides, in a forwarder, which frames of a stream to forward to one receiver, from the
/// Dependency Descriptor alone (AV1 RTP specification A.1, A.5 to A.7).
///
/// The receiver's target is a spatial and a temporal layer; the selector maps it to the best
/// active decode target of the structure in force and forwards the frames that are part of
/// it. Give it every packet's descriptor in RTP sequence number order, after the
/// [`DependencyDescriptorReader`] has read it.
///
/// * A frame is forwarded when it is part of the decode target in use (its indication is not
///   "not present") and none of the frames it refers to was withheld from this receiver.
/// * The decode target changes at a frame with a Switch indication for the wanted target, or
///   at any frame of it when the chain that protects the wanted target is intact for this
///   receiver, that is every frame of the chain was forwarded to it (A.7).
/// * [`chain_intact`](Self::chain_intact) says whether the forwarder itself has received every
///   frame of the chain that protects the target in use. When it has not, a frame the target
///   needs was lost on the way in (A.6), and the forwarder asks for it (NACK) or for a key
///   frame.
#[derive(Debug, Clone)]
pub struct DecodeTargetSelector {
    target_spatial_id: u8,
    target_temporal_id: u8,
    /// The decode target forwarded at the moment.
    current: Option<usize>,
    /// The frames seen lately, by frame number, and the order they came in.
    frames: HashMap<u16, FrameRecord>,
    order: VecDeque<u16>,
    /// Per chain: a frame of it that later frames point to and that has not been seen.
    missing: Vec<Option<u16>>,
    /// The first frame seen of the coded video sequence in progress: what is older was never
    /// this selector's to see.
    first_seen: Option<u16>,
}

impl DecodeTargetSelector {
    /// A selector for a receiver that wants spatial layer `spatial_id` and the temporal layers
    /// up to `temporal_id`.
    pub fn new(spatial_id: u8, temporal_id: u8) -> Self {
        Self {
            target_spatial_id: spatial_id,
            target_temporal_id: temporal_id,
            current: None,
            frames: HashMap::new(),
            order: VecDeque::new(),
            missing: vec![],
            first_seen: None,
        }
    }

    /// Changes the layers the receiver wants. It takes effect at the next frame the stream
    /// allows a switch at.
    pub fn set_target(&mut self, spatial_id: u8, temporal_id: u8) {
        self.target_spatial_id = spatial_id;
        self.target_temporal_id = temporal_id;
    }

    /// The layers the receiver wants.
    pub fn target(&self) -> (u8, u8) {
        (self.target_spatial_id, self.target_temporal_id)
    }

    /// The decode target being forwarded, once a frame has been.
    pub fn current_decode_target(&self) -> Option<usize> {
        self.current
    }

    /// The decode target the receiver's layers map to in `structure`, among those active in
    /// `active_decode_targets`: the one of exactly these layers, or the best below them.
    pub fn wanted_decode_target(
        &self,
        structure: &FrameDependencyStructure,
        active_decode_targets: u32,
    ) -> Option<usize> {
        structure
            .decode_target_layers()
            .into_iter()
            .enumerate()
            .filter(|(dt, (s, t))| {
                (active_decode_targets >> dt) & 1 == 1
                    && *s <= self.target_spatial_id
                    && *t <= self.target_temporal_id
            })
            .max_by_key(|(dt, (s, t))| (*s, *t, std::cmp::Reverse(*dt)))
            .map(|(dt, _)| dt)
    }

    /// Whether the decode target in use is not the wanted one: the stream has not offered a
    /// switch point yet. A forwarder that cannot wait asks the sender for a key frame.
    pub fn switch_pending(&self, reader: &DependencyDescriptorReader) -> bool {
        let Some(structure) = reader.structure() else {
            return true;
        };
        self.current != self.wanted_decode_target(structure, reader.active_decode_targets())
    }

    /// Whether every frame of the chain that protects the decode target in use has been seen
    /// by this selector, as far as the descriptors seen so far tell. `false` after a loss on
    /// the way in that the target cannot do without, until the missing frame arrives or the
    /// chain starts again. `true` when the structure has no chains, or before anything was
    /// forwarded.
    pub fn chain_intact(&self, reader: &DependencyDescriptorReader) -> bool {
        let (Some(structure), Some(current)) = (reader.structure(), self.current) else {
            return true;
        };
        match structure.decode_target_protected_by.get(current) {
            Some(chain) => self
                .missing
                .get(*chain as usize)
                .is_none_or(|missing| missing.is_none()),
            None => true,
        }
    }

    /// Decides whether to forward the packet `descriptor` was read from. `reader` is the
    /// reader that read it (for the structure in force and the active decode targets).
    pub fn forward(
        &mut self,
        descriptor: &DependencyDescriptor,
        reader: &DependencyDescriptorReader,
    ) -> bool {
        let frame_number = descriptor.frame_number;
        // One decision per frame: the frame's other packets, and a repeated packet, get the
        // one its first packet got.
        if let Some(record) = self.frames.get(&frame_number) {
            return record.forwarded;
        }
        let Some(structure) = reader.structure() else {
            return false;
        };
        if descriptor.attached_structure.is_some() {
            // A new coded video sequence: nothing before it matters any more.
            self.frames.clear();
            self.order.clear();
            self.current = None;
            self.missing.clear();
            self.first_seen = None;
        }
        self.missing.resize(structure.num_chains, None);
        let first_seen = *self.first_seen.get_or_insert(frame_number);

        // What the receiver has of each chain, and what this forwarder has.
        let mut chains_forwarded = 0u32;
        for (chain, chain_fdiff) in descriptor.chain_fdiffs.iter().enumerate().take(32) {
            if self.missing[chain] == Some(frame_number) {
                self.missing[chain] = None;
            }
            if *chain_fdiff == 0 {
                // "A value of 0 indicates no previous frames are needed for the Chain."
                chains_forwarded |= 1 << chain;
                self.missing[chain] = None;
                continue;
            }
            let previous = descriptor.referred_frame_number(*chain_fdiff as u16);
            match self.frames.get(&previous) {
                Some(record) => {
                    if record.forwarded && (record.chains_forwarded >> chain) & 1 == 1 {
                        chains_forwarded |= 1 << chain;
                    }
                }
                // The previous frame of the chain should have come by now and did not. (One
                // from before this selector started watching is not its loss to report.)
                None => {
                    let watched = previous.wrapping_sub(first_seen) < 0x8000;
                    if watched && reader.chain_has_active_decode_target(chain) {
                        self.missing[chain] = Some(previous);
                    }
                }
            }
        }

        // A frame is decodable for this receiver unless a frame it refers to was withheld.
        let decodable = descriptor.fdiffs.iter().all(|fdiff| {
            self.frames
                .get(&descriptor.referred_frame_number(*fdiff))
                .is_none_or(|record| record.forwarded)
        });
        let dti = |dt: usize| {
            descriptor
                .dtis
                .get(dt)
                .copied()
                .unwrap_or(DecodeTargetIndication::NotPresent)
        };

        // Switching (A.7).
        let wanted = self.wanted_decode_target(structure, reader.active_decode_targets());
        if let Some(wanted) = wanted
            && self.current != Some(wanted)
            && decodable
            && dti(wanted).is_present()
        {
            let chain_intact = structure
                .decode_target_protected_by
                .get(wanted)
                .is_some_and(|chain| (chains_forwarded >> chain) & 1 == 1);
            if dti(wanted) == DecodeTargetIndication::Switch || chain_intact {
                self.current = Some(wanted);
            }
        }
        if wanted.is_none() {
            // Nothing active fits the receiver's layers.
            self.current = None;
        }

        let forward = decodable
            && self
                .current
                .is_some_and(|current| dti(current).is_present());

        if self.order.len() == HISTORY
            && let Some(oldest) = self.order.pop_front()
        {
            self.frames.remove(&oldest);
        }
        if self
            .frames
            .insert(
                frame_number,
                FrameRecord {
                    forwarded: forward,
                    chains_forwarded,
                },
            )
            .is_none()
        {
            self.order.push_back(frame_number);
        }
        forward
    }
}

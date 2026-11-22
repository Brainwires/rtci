//! The send side of the Dependency Descriptor.

use std::sync::Arc;

use bytes::Bytes;
use shared::error::Result;

use super::{DependencyDescriptor, FrameDependencyStructure, FrameDependencyTemplate, invalid};

/// The send side of the Dependency Descriptor for one RTP stream (AV1 RTP specification A.4,
/// A.8.3).
///
/// For each frame, in decode order, [`next_frame`](Self::next_frame) takes what the encoder
/// says about it and returns a [`FrameDescriptor`], which writes the header extension of each
/// of the frame's packets. The writer
///
/// * numbers the frames (`frame_number`, one more per frame, wrapping after 65535);
/// * picks, among the structure's templates of the frame's layer, the one that needs the
///   fewest custom bits (none, when the frame follows a template);
/// * attaches the structure to the first packet of a coded video sequence and to no other;
/// * signals the active decode targets when they change, on every packet until
///   [`active_decode_targets_acknowledged`](Self::active_decode_targets_acknowledged) or a new
///   coded video sequence with all of them active.
#[derive(Debug, Clone)]
pub struct DependencyDescriptorWriter {
    structure: Arc<FrameDependencyStructure>,
    /// The structure has not gone out yet: the next frame has to start a coded video sequence.
    structure_pending: bool,
    next_frame_number: u16,
    active_decode_targets: u32,
    /// The receiver may not know the active decode targets.
    signal_active_decode_targets: bool,
}

impl DependencyDescriptorWriter {
    /// A writer for a stream with this structure. `initial_frame_number` is the first frame's
    /// number, which "MAY start on a random number".
    ///
    /// # Errors
    ///
    /// A structure that does not [validate](FrameDependencyStructure::validate).
    pub fn new(structure: FrameDependencyStructure, initial_frame_number: u16) -> Result<Self> {
        structure.validate()?;
        let active_decode_targets = structure.all_decode_targets();
        Ok(Self {
            structure: Arc::new(structure),
            structure_pending: true,
            next_frame_number: initial_frame_number,
            active_decode_targets,
            signal_active_decode_targets: false,
        })
    }

    /// The structure in force.
    pub fn structure(&self) -> &FrameDependencyStructure {
        &self.structure
    }

    /// The number the next frame gets.
    pub fn next_frame_number(&self) -> u16 {
        self.next_frame_number
    }

    /// Replaces the structure, for the coded video sequence the next frame starts. All decode
    /// targets of the new structure are active.
    ///
    /// Its `template_id_offset` SHOULD keep its template ids clear of the current structure's
    /// ([`FrameDependencyStructure::next_template_id_offset`] gives one that does), so that a
    /// receiver that missed the new structure does not read the old templates into the new
    /// ids.
    ///
    /// # Errors
    ///
    /// A structure that does not validate, or one with the current `template_id_offset` and
    /// anything else different: "when template_id_offset of a new
    /// template_dependency_structure is the same as in the existing
    /// template_dependency_structure, all fields in both template_dependency_structures MUST
    /// have identical values".
    pub fn set_structure(&mut self, structure: FrameDependencyStructure) -> Result<()> {
        structure.validate()?;
        if structure.template_id_offset == self.structure.template_id_offset
            && structure != *self.structure
        {
            return invalid("a different structure needs a different template_id_offset");
        }
        self.active_decode_targets = structure.all_decode_targets();
        self.signal_active_decode_targets = false;
        self.structure = Arc::new(structure);
        self.structure_pending = true;
        Ok(())
    }

    /// The active decode targets, as a bitmask.
    pub fn active_decode_targets(&self) -> u32 {
        self.active_decode_targets
    }

    /// Changes the set of active decode targets (bit `i` for decode target `i`), for example
    /// when the encoder stops producing a spatial layer. "Whenever the set of active Decode
    /// targets changes, the sender MUST signal the new set": from the next packet on every
    /// descriptor carries the bitmask.
    ///
    /// # Errors
    ///
    /// A bitmask with bits beyond the structure's decode targets.
    pub fn set_active_decode_targets(&mut self, bitmask: u32) -> Result<()> {
        if bitmask & !self.structure.all_decode_targets() != 0 {
            return invalid("the bitmask names decode targets the structure does not have");
        }
        if bitmask != self.active_decode_targets {
            self.active_decode_targets = bitmask;
            self.signal_active_decode_targets = true;
        }
        Ok(())
    }

    /// Stops repeating the bitmask: the receiver is known to have a packet that carried it
    /// (a receiver report acknowledged one). One of the techniques A.4 names.
    pub fn active_decode_targets_acknowledged(&mut self) {
        self.signal_active_decode_targets = false;
    }

    /// Describes the next frame in decode order.
    ///
    /// `frame` holds the frame's own layer, decode target indications, frame differences
    /// (how many frames back each frame it refers to is, in the frames given to this writer)
    /// and chain differences. `starts_coded_video_sequence` is set for the first frame of a
    /// coded video sequence (a key frame the stream can be joined at): its first packet
    /// carries the structure.
    ///
    /// # Errors
    ///
    /// The stream's first frame, or the first after [`set_structure`](Self::set_structure),
    /// does not start a coded video sequence (the receiver would never get the structure); the
    /// structure has no template of the frame's layer; or the frame's values are ones
    /// [`DependencyDescriptor::marshal`] refuses.
    pub fn next_frame(
        &mut self,
        frame: &FrameDependencyTemplate,
        starts_coded_video_sequence: bool,
    ) -> Result<FrameDescriptor> {
        if self.structure_pending && !starts_coded_video_sequence {
            return invalid(
                "the structure has to go out on a frame that starts a coded video sequence",
            );
        }
        let structure = &self.structure;
        // The template of the frame's layer that costs the fewest bits to correct.
        let best = structure
            .templates
            .iter()
            .enumerate()
            .filter(|(_, t)| (t.spatial_id, t.temporal_id) == (frame.spatial_id, frame.temporal_id))
            .min_by_key(|(_, t)| {
                let mut bits = 0;
                if t.dtis != frame.dtis {
                    bits += 2 * structure.num_decode_targets;
                }
                if t.fdiffs != frame.fdiffs {
                    bits += 2 + frame
                        .fdiffs
                        .iter()
                        .map(|d| match d.saturating_sub(1) {
                            0..=0xF => 6,
                            0x10..=0xFF => 10,
                            _ => 14,
                        })
                        .sum::<usize>();
                }
                if t.chain_fdiffs != frame.chain_fdiffs {
                    bits += 8 * structure.num_chains;
                }
                bits
            });
        let Some((template_index, _)) = best else {
            return invalid("the structure has no template of the frame's layer");
        };

        if starts_coded_video_sequence
            && self.active_decode_targets == structure.all_decode_targets()
        {
            // The structure says all decode targets are active.
            self.signal_active_decode_targets = false;
        }
        let descriptor = DependencyDescriptor {
            frame_number: self.next_frame_number,
            template_id: structure.template_id(template_index),
            active_decode_targets_bitmask: self
                .signal_active_decode_targets
                .then_some(self.active_decode_targets),
            spatial_id: frame.spatial_id,
            temporal_id: frame.temporal_id,
            dtis: frame.dtis.clone(),
            fdiffs: frame.fdiffs.clone(),
            chain_fdiffs: frame.chain_fdiffs.clone(),
            resolution: structure
                .resolutions
                .get(frame.spatial_id as usize)
                .copied(),
            ..Default::default()
        };
        // Refuse now what no packet of the frame could carry.
        descriptor.marshal(structure)?;

        self.next_frame_number = self.next_frame_number.wrapping_add(1);
        self.structure_pending = false;
        Ok(FrameDescriptor {
            descriptor,
            structure: Arc::clone(&self.structure),
            attach_structure: starts_coded_video_sequence,
        })
    }
}

/// The Dependency Descriptor of one frame, ready to be written on each of its packets.
#[derive(Debug, Clone)]
pub struct FrameDescriptor {
    descriptor: DependencyDescriptor,
    structure: Arc<FrameDependencyStructure>,
    attach_structure: bool,
}

impl FrameDescriptor {
    /// The frame's number.
    pub fn frame_number(&self) -> u16 {
        self.descriptor.frame_number
    }

    /// The frame's descriptor, without the per-packet fields (`start_of_frame`,
    /// `end_of_frame`, the attached structure).
    pub fn descriptor(&self) -> &DependencyDescriptor {
        &self.descriptor
    }

    /// Whether the frame starts a coded video sequence, so that its first packet carries the
    /// structure.
    pub fn starts_coded_video_sequence(&self) -> bool {
        self.attach_structure
    }

    /// The header extension payload for one packet of the frame: `first` for the packet whose
    /// payload begins the frame (`start_of_frame`), `last` for the frame's final packet
    /// (`end_of_frame`). Every packet has the frame's `frame_number` and template id; the
    /// structure is on the first packet of a frame that starts a coded video sequence only.
    pub fn packet(&self, first: bool, last: bool) -> Result<Bytes> {
        let mut descriptor = self.descriptor.clone();
        descriptor.start_of_frame = first;
        descriptor.end_of_frame = last;
        if first && self.attach_structure {
            descriptor.attached_structure = Some((*self.structure).clone());
        }
        descriptor.marshal(&self.structure)
    }
}

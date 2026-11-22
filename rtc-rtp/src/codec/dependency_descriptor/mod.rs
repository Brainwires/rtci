//! The Dependency Descriptor RTP header extension (AV1 RTP specification, appendix A).
//!
//! The descriptor tells a forwarder which frame a packet belongs to, which frames that frame
//! depends on and which decode targets (a spatial and temporal fidelity) it is part of,
//! without the forwarder reading the payload. It was designed for AV1 and is used with other
//! codecs as well.
//!
//! * [`DependencyDescriptor`] is one descriptor: [`DependencyDescriptor::marshal`] writes the
//!   extension's bytes, [`DependencyDescriptor::unmarshal`] reads them.
//! * [`FrameDependencyStructure`] is the template dependency structure a key frame's first
//!   packet carries, and every later descriptor refers to.
//! * [`DependencyDescriptorWriter`] is the send side: it numbers frames, picks the template
//!   that costs the fewest bits, attaches the structure where the specification requires it
//!   and signals the active decode targets.
//! * [`DependencyDescriptorReader`] is the receive side: it keeps the structure and the active
//!   decode targets from packet to packet.
//! * [`DecodeTargetSelector`] decides, in a forwarder, which frames to forward for a decode
//!   target, and tells whether the chain that protects it is intact.
//!
//! The extension is negotiated with `a=extmap` and the URI [`DEPENDENCY_DESCRIPTOR_URI`]. Its
//! bytes are the payload of an RTP header extension element: set them with
//! `Header::set_extension` under the negotiated id. A descriptor that carries a structure is
//! usually longer than 16 bytes, which needs the two-byte header form (RFC 8285).

mod bits;
#[cfg(test)]
pub(crate) mod dependency_descriptor_test;
mod selector;
#[cfg(test)]
mod selector_test;
mod writer;
#[cfg(test)]
mod writer_test;

pub use selector::DecodeTargetSelector;
pub use writer::{DependencyDescriptorWriter, FrameDescriptor};

use bits::{BitReader, BitWriter};
use bytes::Bytes;
use shared::error::{Error, Result};

/// The `a=extmap` URI of the Dependency Descriptor (AV1 RTP specification A.9).
pub const DEPENDENCY_DESCRIPTOR_URI: &str =
    "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension";

/// The most decode targets a structure can have (`dt_cnt_minus_one` is five bits).
pub const MAX_DECODE_TARGETS: usize = 32;
/// The most templates a structure can have (`frame_dependency_template_id` is six bits).
pub const MAX_TEMPLATES: usize = 64;
/// The largest frame difference a descriptor can carry (`fdiff_minus_one` is at most twelve
/// bits).
pub const MAX_FRAME_DIFF: u16 = 4096;
/// The largest frame difference a template can carry (`fdiff_minus_one` is four bits there).
pub const MAX_TEMPLATE_FRAME_DIFF: u16 = 16;
/// The largest chain difference a template can carry (four bits).
pub const MAX_TEMPLATE_CHAIN_DIFF: u8 = 15;

fn invalid<T>(what: &str) -> Result<T> {
    Err(Error::Other(format!("dependency descriptor: {what}")))
}

/// How a frame relates to a decode target (AV1 RTP specification, table A.1).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DecodeTargetIndication {
    /// `-`: the frame is not part of the decode target.
    #[default]
    NotPresent = 0,
    /// `D`: the frame is part of the decode target, and no frame of the target refers to it.
    Discardable = 1,
    /// `S`: the frame is part of the decode target, and when it is decodable every later frame
    /// of the target is: a forwarder can switch a receiver to the target here.
    Switch = 2,
    /// `R`: the frame is part of the decode target, and neither of the above.
    Required = 3,
}

impl DecodeTargetIndication {
    fn from_bits(bits: u32) -> Self {
        match bits & 0x3 {
            0 => Self::NotPresent,
            1 => Self::Discardable,
            2 => Self::Switch,
            _ => Self::Required,
        }
    }

    /// The symbol the specification's tables use: `-`, `D`, `S` or `R`.
    pub fn symbol(self) -> char {
        match self {
            Self::NotPresent => '-',
            Self::Discardable => 'D',
            Self::Switch => 'S',
            Self::Required => 'R',
        }
    }

    /// The indications a string of the specification's symbols stands for, one per decode
    /// target (`"SD-"`). `None` if a character is not one of `-`, `D`, `S`, `R`.
    pub fn from_symbols(symbols: &str) -> Option<Vec<Self>> {
        symbols
            .chars()
            .map(|c| match c {
                '-' => Some(Self::NotPresent),
                'D' => Some(Self::Discardable),
                'S' => Some(Self::Switch),
                'R' => Some(Self::Required),
                _ => None,
            })
            .collect()
    }

    /// Whether the frame is part of the decode target at all.
    pub fn is_present(self) -> bool {
        self != Self::NotPresent
    }
}

/// A frame dependency template: what many frames of a stream have in common (AV1 RTP
/// specification A.8.1).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FrameDependencyTemplate {
    /// The spatial layer of the frames that use the template.
    pub spatial_id: u8,
    /// Their temporal layer.
    pub temporal_id: u8,
    /// `template_dti`: one indication per decode target.
    pub dtis: Vec<DecodeTargetIndication>,
    /// `TemplateFdiff`: for each frame referred to, how many frame numbers back it is (1 to
    /// 16).
    pub fdiffs: Vec<u16>,
    /// `template_chain_fdiff`: for each chain, how many frame numbers back the previous frame
    /// of the chain is (0 to 15; 0 when no earlier frame is needed).
    pub chain_fdiffs: Vec<u8>,
}

/// The largest size the frames of a spatial layer are rendered at (`render_resolutions`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenderResolution {
    /// Width in pixels, 1 to 65536.
    pub width: u32,
    /// Height in pixels, 1 to 65536.
    pub height: u32,
}

/// The frame dependency structure of a coded video sequence (`template_dependency_structure`,
/// AV1 RTP specification A.8.2): the decode targets, the templates and the chains.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FrameDependencyStructure {
    /// `template_id_offset`: the `frame_dependency_template_id` of the first template (0 to
    /// 63). A new structure SHOULD use ids the one before it did not.
    pub template_id_offset: u8,
    /// `DtCnt`: the number of decode targets, 1 to 32.
    pub num_decode_targets: usize,
    /// `chain_cnt`: the number of chains, 0 to `num_decode_targets`.
    pub num_chains: usize,
    /// `decode_target_protected_by`: for each decode target the chain that protects it. Empty
    /// when there are no chains; otherwise one entry per decode target.
    pub decode_target_protected_by: Vec<u8>,
    /// `render_resolutions`: one per spatial layer, lowest first, or empty.
    pub resolutions: Vec<RenderResolution>,
    /// The templates, ordered by spatial then temporal layer (the syntax can only step a layer
    /// up from one template to the next).
    pub templates: Vec<FrameDependencyTemplate>,
}

impl FrameDependencyStructure {
    /// Checks that the structure can be written: everything the syntax of A.8.2 can carry and
    /// the rules of A.8.3 require.
    pub fn validate(&self) -> Result<()> {
        if self.template_id_offset as usize >= MAX_TEMPLATES {
            return invalid("template_id_offset is six bits");
        }
        if self.num_decode_targets == 0 || self.num_decode_targets > MAX_DECODE_TARGETS {
            return invalid("1 to 32 decode targets");
        }
        if self.templates.is_empty() || self.templates.len() > MAX_TEMPLATES {
            return invalid("1 to 64 templates");
        }
        if self.num_chains > self.num_decode_targets {
            return invalid("no more chains than decode targets");
        }
        if self.num_chains == 0 {
            if !self.decode_target_protected_by.is_empty() {
                return invalid("decode_target_protected_by without chains");
            }
        } else if self.decode_target_protected_by.len() != self.num_decode_targets
            || self
                .decode_target_protected_by
                .iter()
                .any(|c| *c as usize >= self.num_chains)
        {
            // "When chain_cnt > 0, each Decode target MUST be protected by exactly one Chain."
            return invalid("each decode target is protected by one of the chains");
        }

        let mut previous = (0u8, 0u8);
        for (i, template) in self.templates.iter().enumerate() {
            let layer = (template.spatial_id, template.temporal_id);
            // template_layers(): the first template is of layer (0, 0); the next one has the
            // same layer, the next temporal layer, or temporal layer 0 of the next spatial one.
            let reachable = if i == 0 {
                layer == (0, 0)
            } else {
                layer == previous
                    || layer == (previous.0, previous.1.wrapping_add(1))
                    || (template.spatial_id == previous.0.wrapping_add(1)
                        && template.temporal_id == 0)
            };
            if !reachable {
                return invalid(
                    "templates are ordered by spatial then temporal layer, without gaps",
                );
            }
            previous = layer;

            if template.dtis.len() != self.num_decode_targets {
                return invalid("one decode target indication per decode target");
            }
            if template
                .fdiffs
                .iter()
                .any(|d| *d == 0 || *d > MAX_TEMPLATE_FRAME_DIFF)
            {
                return invalid("a template's frame differences are 1 to 16");
            }
            if template.chain_fdiffs.len() != self.num_chains
                || template
                    .chain_fdiffs
                    .iter()
                    .any(|d| *d > MAX_TEMPLATE_CHAIN_DIFF)
            {
                return invalid("a template has one chain difference per chain, 0 to 15");
            }
        }

        if !self.resolutions.is_empty() {
            if self.resolutions.len() != self.max_spatial_id() as usize + 1 {
                return invalid("one resolution per spatial layer, or none");
            }
            if self
                .resolutions
                .iter()
                .any(|r| r.width == 0 || r.width > 65536 || r.height == 0 || r.height > 65536)
            {
                return invalid("a resolution is 1 to 65536 in each dimension");
            }
        }
        Ok(())
    }

    /// `MaxSpatialId`: the highest spatial layer a template is of.
    pub fn max_spatial_id(&self) -> u8 {
        self.templates.last().map_or(0, |t| t.spatial_id)
    }

    /// `MaxTemporalId`: the highest temporal layer a template is of.
    pub fn max_temporal_id(&self) -> u8 {
        self.templates
            .iter()
            .map(|t| t.temporal_id)
            .max()
            .unwrap_or(0)
    }

    /// `decode_target_layers()`: for each decode target the highest spatial and temporal layer
    /// of the frames that are part of it, which is the fidelity it stands for.
    pub fn decode_target_layers(&self) -> Vec<(u8, u8)> {
        (0..self.num_decode_targets.min(MAX_DECODE_TARGETS))
            .map(|dt| {
                let mut spatial_id = 0;
                let mut temporal_id = 0;
                for template in &self.templates {
                    if template.dtis.get(dt).is_some_and(|dti| dti.is_present()) {
                        spatial_id = spatial_id.max(template.spatial_id);
                        temporal_id = temporal_id.max(template.temporal_id);
                    }
                }
                (spatial_id, temporal_id)
            })
            .collect()
    }

    /// The decode target that stands for the given spatial and temporal layer: the one whose
    /// layers are exactly those, or failing that the best one that does not exceed them.
    pub fn decode_target_for(&self, spatial_id: u8, temporal_id: u8) -> Option<usize> {
        self.decode_target_layers()
            .into_iter()
            .enumerate()
            .filter(|(_, (s, t))| *s <= spatial_id && *t <= temporal_id)
            .max_by_key(|(dt, (s, t))| (*s, *t, std::cmp::Reverse(*dt)))
            .map(|(dt, _)| dt)
    }

    /// The index of the template a `frame_dependency_template_id` names, if it is one of this
    /// structure's.
    pub fn template_index(&self, template_id: u8) -> Option<usize> {
        let index = (template_id as usize + MAX_TEMPLATES - self.template_id_offset as usize)
            % MAX_TEMPLATES;
        (index < self.templates.len()).then_some(index)
    }

    /// The `frame_dependency_template_id` of the template at `index`.
    pub fn template_id(&self, index: usize) -> u8 {
        ((self.template_id_offset as usize + index) % MAX_TEMPLATES) as u8
    }

    /// The bitmask with every decode target active.
    pub fn all_decode_targets(&self) -> u32 {
        if self.num_decode_targets >= 32 {
            u32::MAX
        } else {
            (1u32 << self.num_decode_targets) - 1
        }
    }

    /// A `template_id_offset` for a structure that replaces this one: the first id after this
    /// structure's range, so the two do not overlap (A.8.3) as long as the new one has no
    /// more than `64 - self.templates.len()` templates.
    pub fn next_template_id_offset(&self) -> u8 {
        self.template_id(self.templates.len())
    }

    /// `template_dependency_structure()`.
    fn write(&self, w: &mut BitWriter) {
        w.f(6, self.template_id_offset as u32);
        w.f(5, self.num_decode_targets as u32 - 1);
        // template_layers()
        for (i, template) in self.templates.iter().enumerate() {
            let next_layer_idc = match self.templates.get(i + 1) {
                None => 3,
                Some(next) if next.spatial_id != template.spatial_id => 2,
                Some(next) if next.temporal_id != template.temporal_id => 1,
                Some(_) => 0,
            };
            w.f(2, next_layer_idc);
        }
        // template_dtis()
        for template in &self.templates {
            for dti in &template.dtis {
                w.f(2, *dti as u32);
            }
        }
        // template_fdiffs()
        for template in &self.templates {
            for fdiff in &template.fdiffs {
                w.flag(true); // fdiff_follows_flag
                w.f(4, *fdiff as u32 - 1);
            }
            w.flag(false);
        }
        // template_chains()
        w.ns(self.num_decode_targets as u32 + 1, self.num_chains as u32);
        if self.num_chains > 0 {
            for chain in &self.decode_target_protected_by {
                w.ns(self.num_chains as u32, *chain as u32);
            }
            for template in &self.templates {
                for chain_fdiff in &template.chain_fdiffs {
                    w.f(4, *chain_fdiff as u32);
                }
            }
        }
        // resolutions_present_flag, render_resolutions()
        w.flag(!self.resolutions.is_empty());
        for resolution in &self.resolutions {
            w.f(16, resolution.width - 1);
            w.f(16, resolution.height - 1);
        }
    }

    /// `template_dependency_structure()`.
    fn read(r: &mut BitReader<'_>) -> Result<Self> {
        let template_id_offset = r.f(6)? as u8;
        let num_decode_targets = r.f(5)? as usize + 1;

        // template_layers()
        let mut templates: Vec<FrameDependencyTemplate> = vec![];
        let (mut spatial_id, mut temporal_id) = (0u8, 0u8);
        loop {
            // A template id is six bits: a 65th template could never be named.
            if templates.len() == MAX_TEMPLATES {
                return invalid("more than 64 templates");
            }
            templates.push(FrameDependencyTemplate {
                spatial_id,
                temporal_id,
                ..Default::default()
            });
            match r.f(2)? {
                0 => {}
                1 => temporal_id += 1,
                2 => {
                    temporal_id = 0;
                    spatial_id += 1;
                }
                _ => break,
            }
        }
        // template_dtis()
        for template in &mut templates {
            template.dtis.reserve_exact(num_decode_targets);
            for _ in 0..num_decode_targets {
                template
                    .dtis
                    .push(DecodeTargetIndication::from_bits(r.f(2)?));
            }
        }
        // template_fdiffs()
        for template in &mut templates {
            while r.flag()? {
                template.fdiffs.push(r.f(4)? as u16 + 1);
            }
        }
        // template_chains()
        let num_chains = r.ns(num_decode_targets as u32 + 1)? as usize;
        let mut decode_target_protected_by = vec![];
        if num_chains > 0 {
            for _ in 0..num_decode_targets {
                decode_target_protected_by.push(r.ns(num_chains as u32)? as u8);
            }
            for template in &mut templates {
                for _ in 0..num_chains {
                    template.chain_fdiffs.push(r.f(4)? as u8);
                }
            }
        }
        // resolutions_present_flag, render_resolutions()
        let mut resolutions = vec![];
        if r.flag()? {
            for _ in 0..=spatial_id {
                resolutions.push(RenderResolution {
                    width: r.f(16)? + 1,
                    height: r.f(16)? + 1,
                });
            }
        }

        Ok(Self {
            template_id_offset,
            num_decode_targets,
            num_chains,
            decode_target_protected_by,
            resolutions,
            templates,
        })
    }
}

/// One Dependency Descriptor: what one RTP packet says about its frame (AV1 RTP specification
/// A.8).
///
/// The fields from `spatial_id` on are the frame dependency definition. On the wire they are
/// taken from the template `template_id` names unless the descriptor overrides them; here
/// they always hold the frame's own values, and [`DependencyDescriptor::marshal`] works out
/// which of them need the custom fields.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DependencyDescriptor {
    /// `start_of_frame`: the packet's payload begins a frame.
    pub start_of_frame: bool,
    /// `end_of_frame`: the packet is the last of its frame.
    pub end_of_frame: bool,
    /// `frame_number`: the same on every packet of a frame, one more for each frame in decode
    /// order, wrapping after 65535.
    pub frame_number: u16,
    /// `frame_dependency_template_id`: the template the frame uses, the same on every packet
    /// of the frame.
    pub template_id: u8,
    /// The structure this packet carries (`template_dependency_structure`): on the first
    /// packet of a coded video sequence, and on no other.
    pub attached_structure: Option<FrameDependencyStructure>,
    /// `active_decode_targets_bitmask`, when the packet carries one: bit `i` is set when
    /// decode target `i` is available. A packet with a structure and without a bitmask means
    /// all of them are.
    pub active_decode_targets_bitmask: Option<u32>,
    /// The frame's spatial layer (`FrameSpatialId`).
    pub spatial_id: u8,
    /// The frame's temporal layer (`FrameTemporalId`).
    pub temporal_id: u8,
    /// `frame_dti`: the frame's indication for each decode target.
    pub dtis: Vec<DecodeTargetIndication>,
    /// `FrameFdiff`: for each frame this one refers to, how many frame numbers back it is (1
    /// to 4096).
    pub fdiffs: Vec<u16>,
    /// `frame_chain_fdiff`: for each chain, how many frame numbers back the previous frame of
    /// the chain is; 0 when no earlier frame is needed.
    pub chain_fdiffs: Vec<u8>,
    /// `FrameMaxWidth` / `FrameMaxHeight`, when the structure has resolutions. Derived when
    /// reading; not written.
    pub resolution: Option<RenderResolution>,
}

impl DependencyDescriptor {
    /// A descriptor for a frame that uses the template at `template_index` of `structure`
    /// exactly: the frame dependency definition is the template's.
    pub fn from_template(
        structure: &FrameDependencyStructure,
        template_index: usize,
        frame_number: u16,
    ) -> Option<Self> {
        let template = structure.templates.get(template_index)?;
        Some(Self {
            frame_number,
            template_id: structure.template_id(template_index),
            spatial_id: template.spatial_id,
            temporal_id: template.temporal_id,
            dtis: template.dtis.clone(),
            fdiffs: template.fdiffs.clone(),
            chain_fdiffs: template.chain_fdiffs.clone(),
            resolution: structure
                .resolutions
                .get(template.spatial_id as usize)
                .copied(),
            ..Default::default()
        })
    }

    /// The frame number of a frame this one refers to (`fdiff` is one of
    /// [`fdiffs`](Self::fdiffs)) or of the previous frame of a chain (one of
    /// [`chain_fdiffs`](Self::chain_fdiffs)): "the calculation is done modulo the size of the
    /// frame_number field".
    pub fn referred_frame_number(&self, fdiff: u16) -> u16 {
        self.frame_number.wrapping_sub(fdiff)
    }

    /// Writes the descriptor: the payload of the header extension element.
    ///
    /// `structure` is the structure in force for the frame; when the descriptor attaches one
    /// it is that one. The frame's indications, frame differences and chain differences are
    /// compared with the template `template_id` names, and written as custom fields
    /// (`frame_dtis`, `frame_fdiffs`, `frame_chain_fdiff`) only where they differ. A
    /// descriptor with no structure, no bitmask and nothing custom is three bytes.
    ///
    /// # Errors
    ///
    /// What A.8.3 forbids or the syntax cannot carry: a `template_id` outside the structure's
    /// range; a spatial or temporal layer other than the template's; a wrong number of
    /// indications or chain differences; a frame difference outside 1 to 4096; a bitmask with
    /// bits beyond the decode targets; an attached structure that is not `structure` or does
    /// not [validate](FrameDependencyStructure::validate).
    pub fn marshal(&self, structure: &FrameDependencyStructure) -> Result<Bytes> {
        if let Some(attached) = &self.attached_structure {
            if attached != structure {
                return invalid("the attached structure is not the one in force");
            }
            attached.validate()?;
        }
        if structure.num_decode_targets == 0 || structure.num_decode_targets > MAX_DECODE_TARGETS {
            return invalid("1 to 32 decode targets");
        }
        let Some(template_index) = structure.template_index(self.template_id) else {
            // "MUST be in the range of template_id_offset to (template_id_offset +
            // TemplateCnt - 1), inclusive."
            return invalid("frame_dependency_template_id is not one of the structure's");
        };
        let template = &structure.templates[template_index];
        if (template.spatial_id, template.temporal_id) != (self.spatial_id, self.temporal_id) {
            return invalid("the frame's layer is not its template's");
        }
        if self.dtis.len() != structure.num_decode_targets {
            return invalid("one decode target indication per decode target");
        }
        if self.chain_fdiffs.len() != structure.num_chains {
            return invalid("one chain difference per chain");
        }
        if self.fdiffs.iter().any(|d| *d == 0 || *d > MAX_FRAME_DIFF) {
            return invalid("a frame difference is 1 to 4096");
        }
        let all_active = structure.all_decode_targets();
        if let Some(bitmask) = self.active_decode_targets_bitmask
            && bitmask & !all_active != 0
        {
            return invalid("the bitmask names decode targets the structure does not have");
        }

        let custom_dtis = self.dtis != template.dtis;
        let custom_fdiffs = self.fdiffs != template.fdiffs;
        let custom_chains = self.chain_fdiffs != template.chain_fdiffs;
        // A structure makes every decode target active; the bitmask is only needed to say
        // otherwise.
        let active_decode_targets = self
            .active_decode_targets_bitmask
            .filter(|bitmask| self.attached_structure.is_none() || *bitmask != all_active);

        let mut w = BitWriter::default();
        // mandatory_descriptor_fields()
        w.flag(self.start_of_frame);
        w.flag(self.end_of_frame);
        w.f(6, self.template_id as u32);
        w.f(16, self.frame_number as u32);

        let extended = self.attached_structure.is_some()
            || active_decode_targets.is_some()
            || custom_dtis
            || custom_fdiffs
            || custom_chains;
        if extended {
            // extended_descriptor_fields(): present when the descriptor is longer than three
            // bytes, which the five flags alone make it.
            w.flag(self.attached_structure.is_some());
            w.flag(active_decode_targets.is_some());
            w.flag(custom_dtis);
            w.flag(custom_fdiffs);
            w.flag(custom_chains);
            if let Some(attached) = &self.attached_structure {
                attached.write(&mut w);
            }
            if let Some(bitmask) = active_decode_targets {
                w.f(structure.num_decode_targets, bitmask);
            }
            // frame_dependency_definition()
            if custom_dtis {
                for dti in &self.dtis {
                    w.f(2, *dti as u32);
                }
            }
            if custom_fdiffs {
                for fdiff in &self.fdiffs {
                    let fdiff_minus_one = *fdiff as u32 - 1;
                    let next_fdiff_size = match fdiff_minus_one {
                        0..=0xF => 1,
                        0x10..=0xFF => 2,
                        _ => 3,
                    };
                    w.f(2, next_fdiff_size);
                    w.f(4 * next_fdiff_size as usize, fdiff_minus_one);
                }
                w.f(2, 0);
            }
            if custom_chains {
                for chain_fdiff in &self.chain_fdiffs {
                    w.f(8, *chain_fdiff as u32);
                }
            }
        }
        // zero_padding: the writer leaves the rest of the last byte 0.
        Ok(Bytes::from(w.finish()))
    }

    /// Reads the mandatory fields, which every descriptor has and which need no structure:
    /// `(start_of_frame, end_of_frame, frame_dependency_template_id, frame_number)`.
    ///
    /// # Errors
    ///
    /// Fewer than three bytes.
    pub fn unmarshal_mandatory(data: &[u8]) -> Result<(bool, bool, u8, u16)> {
        let mut r = BitReader::new(data);
        Ok((r.flag()?, r.flag()?, r.f(6)? as u8, r.f(16)? as u16))
    }

    /// Reads a descriptor: `data` is the payload of the header extension element and
    /// `structure` the structure in force before this packet, if one is known.
    ///
    /// Returns `Ok(None)` when the descriptor cannot be interpreted because the structure it
    /// refers to is not known: it carries none and `structure` is `None`, or its template id
    /// is outside the known structure's range, which per A.8.3 means "a packet with the new
    /// template dependency structure was lost or delayed". The mandatory fields of such a
    /// packet are still readable with [`unmarshal_mandatory`](Self::unmarshal_mandatory).
    ///
    /// `zero_padding` is ignored, whatever it holds.
    ///
    /// # Errors
    ///
    /// A descriptor that ends before its fields do, or a structure with more than 64
    /// templates.
    pub fn unmarshal(
        data: &[u8],
        structure: Option<&FrameDependencyStructure>,
    ) -> Result<Option<Self>> {
        let mut r = BitReader::new(data);
        // mandatory_descriptor_fields()
        let mut descriptor = Self {
            start_of_frame: r.flag()?,
            end_of_frame: r.flag()?,
            template_id: r.f(6)? as u8,
            frame_number: r.f(16)? as u16,
            ..Default::default()
        };

        let mut custom_dtis = false;
        let mut custom_fdiffs = false;
        let mut custom_chains = false;
        let mut active_decode_targets_present = false;
        if data.len() > 3 {
            // extended_descriptor_fields()
            let structure_present = r.flag()?;
            active_decode_targets_present = r.flag()?;
            custom_dtis = r.flag()?;
            custom_fdiffs = r.flag()?;
            custom_chains = r.flag()?;
            if structure_present {
                descriptor.attached_structure = Some(FrameDependencyStructure::read(&mut r)?);
            }
        }
        let Some(structure) = descriptor.attached_structure.as_ref().or(structure) else {
            return Ok(None);
        };
        if active_decode_targets_present {
            descriptor.active_decode_targets_bitmask = Some(r.f(structure.num_decode_targets)?);
        }

        // frame_dependency_definition()
        let Some(template_index) = structure.template_index(descriptor.template_id) else {
            return Ok(None);
        };
        let template = &structure.templates[template_index];
        descriptor.spatial_id = template.spatial_id;
        descriptor.temporal_id = template.temporal_id;
        if custom_dtis {
            for _ in 0..structure.num_decode_targets {
                descriptor
                    .dtis
                    .push(DecodeTargetIndication::from_bits(r.f(2)?));
            }
        } else {
            descriptor.dtis = template.dtis.clone();
        }
        if custom_fdiffs {
            loop {
                let next_fdiff_size = r.f(2)? as usize;
                if next_fdiff_size == 0 {
                    break;
                }
                descriptor.fdiffs.push(r.f(4 * next_fdiff_size)? as u16 + 1);
            }
        } else {
            descriptor.fdiffs = template.fdiffs.clone();
        }
        if custom_chains {
            for _ in 0..structure.num_chains {
                descriptor.chain_fdiffs.push(r.f(8)? as u8);
            }
        } else {
            descriptor.chain_fdiffs = template.chain_fdiffs.clone();
        }
        descriptor.resolution = structure
            .resolutions
            .get(descriptor.spatial_id as usize)
            .copied();
        Ok(Some(descriptor))
    }
}

/// The receive side of the Dependency Descriptor: reads the descriptors of one RTP stream,
/// keeping the structure and the active decode targets from packet to packet (AV1 RTP
/// specification A.4, A.8).
///
/// Give it the descriptors in RTP sequence number order: "when an update to the set of active
/// decode targets is received it is valid until the next update in RTP packet sequence number
/// order".
#[derive(Debug, Default, Clone)]
pub struct DependencyDescriptorReader {
    structure: Option<FrameDependencyStructure>,
    active_decode_targets: u32,
}

impl DependencyDescriptorReader {
    /// A reader that has seen no structure yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads the next packet's descriptor. `Ok(None)` when it refers to a structure this
    /// reader does not have (see [`DependencyDescriptor::unmarshal`]): the packet that carried
    /// it was lost, and the stream cannot be interpreted until a new one arrives (a key
    /// frame).
    ///
    /// # Errors
    ///
    /// A malformed descriptor.
    pub fn read(&mut self, data: &[u8]) -> Result<Option<DependencyDescriptor>> {
        let Some(descriptor) = DependencyDescriptor::unmarshal(data, self.structure.as_ref())?
        else {
            return Ok(None);
        };
        if let Some(structure) = &descriptor.attached_structure {
            // "Implicitly ... in which case all Decode targets are active."
            self.active_decode_targets = structure.all_decode_targets();
            self.structure = Some(structure.clone());
        }
        if let Some(bitmask) = descriptor.active_decode_targets_bitmask {
            self.active_decode_targets = bitmask;
        }
        Ok(Some(descriptor))
    }

    /// The structure in force: the last one a packet carried.
    pub fn structure(&self) -> Option<&FrameDependencyStructure> {
        self.structure.as_ref()
    }

    /// The decode targets available at the moment, as a bitmask (bit `i` for decode target
    /// `i`): the last update received.
    pub fn active_decode_targets(&self) -> u32 {
        self.active_decode_targets
    }

    /// Whether a chain protects a decode target that is active (`ChainHasActiveDecodeTarget`
    /// of A.6). "Chains protecting no active Decode targets MUST be ignored."
    pub fn chain_has_active_decode_target(&self, chain: usize) -> bool {
        chain_has_active_decode_target(self.structure.as_ref(), self.active_decode_targets, chain)
    }

    /// Whether the frame `descriptor` describes is part of an active chain
    /// (`PartOfActiveChain` of A.6): when a packet of the frame is lost, the frame is one the
    /// chain's decode targets cannot do without.
    pub fn part_of_active_chain(&self, descriptor: &DependencyDescriptor, chain: usize) -> bool {
        let Some(structure) = &self.structure else {
            return false;
        };
        if !self.chain_has_active_decode_target(chain) {
            return false;
        }
        structure
            .decode_target_protected_by
            .iter()
            .enumerate()
            .filter(|(_, protected_by)| **protected_by as usize == chain)
            .all(|(dt, _)| {
                !matches!(
                    descriptor.dtis.get(dt),
                    None | Some(
                        DecodeTargetIndication::NotPresent | DecodeTargetIndication::Discardable
                    )
                )
            })
    }
}

/// `ChainHasActiveDecodeTarget` of A.6.
fn chain_has_active_decode_target(
    structure: Option<&FrameDependencyStructure>,
    active_decode_targets: u32,
    chain: usize,
) -> bool {
    structure.is_some_and(|structure| {
        structure
            .decode_target_protected_by
            .iter()
            .enumerate()
            .any(|(dt, protected_by)| {
                *protected_by as usize == chain
                    && active_decode_targets.checked_shr(dt as u32).unwrap_or(0) & 1 == 1
            })
    })
}

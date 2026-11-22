//! Scalable video coding: the scalability modes of the W3C "Scalable Video Coding (SVC)
//! Extension for WebRTC" and the layer structure of each.
//!
//! * [`ScalabilityMode`] is the `scalabilityMode` of an encoding: every identifier of the
//!   specification's table (section 5), with its number of spatial and temporal layers, its
//!   resolution ratio and its kind of inter-layer dependency, and which codecs can carry it.
//! * [`ScalabilityPattern`] is the dependency structure of a mode (the diagrams of section 9)
//!   as a generator: for each picture it gives one [`LayerFrame`] per spatial layer, saying
//!   what the frame depends on and which decode targets it is part of. An encoder that
//!   follows the pattern is described on the wire by handing each `LayerFrame` to the
//!   codec's payloader:
//!   [`Vp8Payloader::payload_frame`](crate::codec::vp8::Vp8Payloader::payload_frame) with
//!   [`LayerFrame::vp8_info`],
//!   [`Vp9Payloader::payload_layer_frame`](crate::codec::vp9::Vp9Payloader::payload_layer_frame)
//!   with [`LayerFrame::vp9_info`], and for AV1 (or any codec, next to its payload format) the
//!   Dependency Descriptor: [`ScalabilityPattern::dependency_structure`] and
//!   [`LayerFrame::dependencies`] into a
//!   [`DependencyDescriptorWriter`](crate::codec::dependency_descriptor::DependencyDescriptorWriter).
//!
//! An encoder with a structure of its own does not need the pattern: the payloaders take the
//! same per-frame information from anywhere.
//!
//! The receive side, for a forwarder, is one type per signalling:
//! [`Vp8TemporalLayerFilter`](crate::codec::vp8::Vp8TemporalLayerFilter),
//! [`Vp9LayerFilter`](crate::codec::vp9::Vp9LayerFilter) and
//! [`DecodeTargetSelector`](crate::codec::dependency_descriptor::DecodeTargetSelector).

#[cfg(test)]
mod svc_mode_test;
#[cfg(test)]
mod svc_pattern_test;

use std::fmt;
use std::str::FromStr;

use shared::error::{Error, Result};

use crate::codec::dependency_descriptor::{
    DecodeTargetIndication, FrameDependencyStructure, FrameDependencyTemplate, RenderResolution,
};
use crate::codec::vp8::{Vp8FrameInfo, Vp8TemporalLayer};
use crate::codec::vp9::{Vp9FrameInfo, Vp9PictureGroupEntry, Vp9ScalabilityStructure};

/// How the spatial layers of a mode depend on each other (the "Inter-layer dependency" column
/// of the specification's table, and its `_KEY` suffix).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterLayerPrediction {
    /// `LxTy`: every frame of a spatial layer predicts from the frame of the layer below in
    /// the same picture. A single spatial layer is this case too.
    Full,
    /// `LxTy_KEY` (K-SVC): spatial layers depend on lower ones at a key frame only.
    KeyPicture,
    /// `SxTy`: none. The spatial layers are simulcast encodings carried in one RTP stream.
    None,
}

/// The ratio between the resolutions of two neighbouring spatial layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolutionRatio {
    /// 2:1, the default.
    TwoToOne,
    /// 1.5:1, the modes whose name ends in `h`.
    OneAndAHalfToOne,
}

macro_rules! scalability_modes {
    ($(($variant:ident, $name:literal, $spatial:literal, $temporal:literal, $prediction:ident, $ratio:ident, $shift:literal)),* $(,)?) => {
        /// A scalability mode: a value of `RTCRtpEncodingParameters.scalabilityMode` (W3C
        /// webrtc-svc, section 5). The identifiers are case sensitive and limited to the
        /// specification's table; [`FromStr`] accepts exactly those.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[allow(non_camel_case_types)]
        pub enum ScalabilityMode {
            $(
                #[doc = concat!("`\"", $name, "\"`.")]
                $variant,
            )*
        }

        impl ScalabilityMode {
            /// Every mode of the specification's table, in its order.
            pub const ALL: &'static [ScalabilityMode] = &[$(ScalabilityMode::$variant,)*];

            /// The mode's identifier, as it is written in `scalabilityMode`.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(ScalabilityMode::$variant => $name,)*
                }
            }

            /// (spatial layers, temporal layers, inter-layer prediction, 1.5:1 ratio,
            /// temporal shift)
            fn properties(&self) -> (u8, u8, InterLayerPrediction, ResolutionRatio, bool) {
                match self {
                    $(ScalabilityMode::$variant => (
                        $spatial,
                        $temporal,
                        InterLayerPrediction::$prediction,
                        ResolutionRatio::$ratio,
                        $shift,
                    ),)*
                }
            }
        }
    };
}

scalability_modes![
    (L1T1, "L1T1", 1, 1, Full, TwoToOne, false),
    (L1T2, "L1T2", 1, 2, Full, TwoToOne, false),
    (L1T3, "L1T3", 1, 3, Full, TwoToOne, false),
    (L2T1, "L2T1", 2, 1, Full, TwoToOne, false),
    (L2T2, "L2T2", 2, 2, Full, TwoToOne, false),
    (L2T3, "L2T3", 2, 3, Full, TwoToOne, false),
    (L3T1, "L3T1", 3, 1, Full, TwoToOne, false),
    (L3T2, "L3T2", 3, 2, Full, TwoToOne, false),
    (L3T3, "L3T3", 3, 3, Full, TwoToOne, false),
    (L2T1h, "L2T1h", 2, 1, Full, OneAndAHalfToOne, false),
    (L2T2h, "L2T2h", 2, 2, Full, OneAndAHalfToOne, false),
    (L2T3h, "L2T3h", 2, 3, Full, OneAndAHalfToOne, false),
    (L3T1h, "L3T1h", 3, 1, Full, OneAndAHalfToOne, false),
    (L3T2h, "L3T2h", 3, 2, Full, OneAndAHalfToOne, false),
    (L3T3h, "L3T3h", 3, 3, Full, OneAndAHalfToOne, false),
    (S2T1, "S2T1", 2, 1, None, TwoToOne, false),
    (S2T2, "S2T2", 2, 2, None, TwoToOne, false),
    (S2T3, "S2T3", 2, 3, None, TwoToOne, false),
    (S2T1h, "S2T1h", 2, 1, None, OneAndAHalfToOne, false),
    (S2T2h, "S2T2h", 2, 2, None, OneAndAHalfToOne, false),
    (S2T3h, "S2T3h", 2, 3, None, OneAndAHalfToOne, false),
    (S3T1, "S3T1", 3, 1, None, TwoToOne, false),
    (S3T2, "S3T2", 3, 2, None, TwoToOne, false),
    (S3T3, "S3T3", 3, 3, None, TwoToOne, false),
    (S3T1h, "S3T1h", 3, 1, None, OneAndAHalfToOne, false),
    (S3T2h, "S3T2h", 3, 2, None, OneAndAHalfToOne, false),
    (S3T3h, "S3T3h", 3, 3, None, OneAndAHalfToOne, false),
    (L2T2_KEY, "L2T2_KEY", 2, 2, KeyPicture, TwoToOne, false),
    (
        L2T2_KEY_SHIFT,
        "L2T2_KEY_SHIFT",
        2,
        2,
        KeyPicture,
        TwoToOne,
        true
    ),
    (L2T3_KEY, "L2T3_KEY", 2, 3, KeyPicture, TwoToOne, false),
    (
        L2T3_KEY_SHIFT,
        "L2T3_KEY_SHIFT",
        2,
        3,
        KeyPicture,
        TwoToOne,
        true
    ),
    (L3T1_KEY, "L3T1_KEY", 3, 1, KeyPicture, TwoToOne, false),
    (L3T2_KEY, "L3T2_KEY", 3, 2, KeyPicture, TwoToOne, false),
    (
        L3T2_KEY_SHIFT,
        "L3T2_KEY_SHIFT",
        3,
        2,
        KeyPicture,
        TwoToOne,
        true
    ),
    (L3T3_KEY, "L3T3_KEY", 3, 3, KeyPicture, TwoToOne, false),
    (
        L3T3_KEY_SHIFT,
        "L3T3_KEY_SHIFT",
        3,
        3,
        KeyPicture,
        TwoToOne,
        true
    ),
];

impl ScalabilityMode {
    /// The number of spatial layers (for an "S" mode, of simulcast encodings).
    pub fn spatial_layers(&self) -> u8 {
        self.properties().0
    }

    /// The number of temporal layers.
    pub fn temporal_layers(&self) -> u8 {
        self.properties().1
    }

    /// How the spatial layers depend on each other.
    pub fn inter_layer_prediction(&self) -> InterLayerPrediction {
        self.properties().2
    }

    /// The ratio between neighbouring spatial layers' resolutions; `None` for a mode with one
    /// spatial layer.
    pub fn resolution_ratio(&self) -> Option<ResolutionRatio> {
        (self.spatial_layers() > 1).then_some(self.properties().3)
    }

    /// Whether the temporal layers of the spatial layers are shifted against each other (the
    /// `_SHIFT` modes), so that the frames of one picture are of different temporal layers.
    pub fn has_temporal_shift(&self) -> bool {
        self.properties().4
    }

    /// Whether this is an "S" mode: simulcast encodings transported in one RTP stream. The
    /// specification allows no more than one active encoding next to an active "S" mode
    /// encoding (sections 3.2.1 and 3.2.2).
    pub fn is_simulcast(&self) -> bool {
        self.inter_layer_prediction() == InterLayerPrediction::None
    }

    /// Whether the mode turns scalable coding off: `"L1T1"` (section 3.2.2).
    pub fn is_single_layer(&self) -> bool {
        self.spatial_layers() == 1 && self.temporal_layers() == 1
    }

    /// Whether a codec can carry the mode, by its MIME type (`"video/VP9"`, compared without
    /// regard to case). Section 5: AV1 and VP9 support every mode of the table; VP8, H.264
    /// and H.265 "only support temporal scalability" and "only permit transport of simulcast
    /// on distinct SSRCs". For any other codec only `"L1T1"`, which is no scalability.
    pub fn supported_by(&self, mime_type: &str) -> bool {
        let codec = mime_type.to_ascii_lowercase();
        match codec.as_str() {
            "video/av1" | "video/vp9" => true,
            "video/vp8" | "video/h264" | "video/h265" => self.spatial_layers() == 1,
            other => other.starts_with("video/") && self.is_single_layer(),
        }
    }

    /// The modes a codec can carry, in the table's order: what a capability report lists as
    /// the codec's `scalabilityModes`.
    pub fn supported_modes(mime_type: &str) -> Vec<ScalabilityMode> {
        Self::ALL
            .iter()
            .copied()
            .filter(|mode| mode.supported_by(mime_type))
            .collect()
    }

    /// The resolution of spatial layer `spatial_id` when the highest layer is `width` by
    /// `height`: each layer below is smaller by the mode's ratio.
    pub fn layer_resolution(&self, spatial_id: u8, width: u32, height: u32) -> (u32, u32) {
        let steps = (self.spatial_layers() - 1).saturating_sub(spatial_id) as u32;
        let (numerator, denominator) = match self.properties().3 {
            ResolutionRatio::TwoToOne => (1u64, 2u64.pow(steps)),
            ResolutionRatio::OneAndAHalfToOne => (2u64.pow(steps), 3u64.pow(steps)),
        };
        let scale = |v: u32| ((v as u64 * numerator / denominator).max(1)) as u32;
        (scale(width), scale(height))
    }
}

impl fmt::Display for ScalabilityMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScalabilityMode {
    type Err = Error;

    /// Parses a `scalabilityMode` value. The identifiers are case sensitive, and only those
    /// of the specification's table are modes.
    fn from_str(s: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|mode| mode.as_str() == s)
            .ok_or_else(|| Error::Other(format!("\"{s}\" is not a scalability mode")))
    }
}

/// The most spatial layers a mode has.
const MAX_SPATIAL: usize = 3;
/// The most temporal layers a mode has.
const MAX_TEMPORAL: usize = 3;

/// One frame of a picture of a [`ScalabilityPattern`]: one spatial layer's frame, with what
/// it depends on and how it relates to each decode target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerFrame {
    /// The frame's spatial layer.
    pub spatial_id: u8,
    /// The frame's temporal layer.
    pub temporal_id: u8,
    /// The frame is of a key picture: the picture a coded video sequence starts with.
    pub key_picture: bool,
    /// The frame depends on no other frame: a key frame.
    pub key_frame: bool,
    /// How many pictures back the frame of the same spatial layer this one predicts from is;
    /// `None` when it predicts from no earlier picture.
    pub temporal_reference: Option<u8>,
    /// The frame predicts from the frame of the spatial layer below in the same picture.
    pub inter_layer_dependency: bool,
    /// A frame of a spatial layer above, in this picture or a later one, depends on this
    /// frame.
    pub referenced_by_upper_layers: bool,
    /// No other frame depends on this one.
    pub discardable: bool,
    /// The frame depends on frames of temporal layer 0 only (and is not of that layer): a
    /// receiver can start its temporal layer here (VP8's layer sync).
    pub layer_sync: bool,
    /// How many frames back, in the order the pattern gives them, each frame this one depends
    /// on is: the Dependency Descriptor's frame differences.
    pub fdiffs: Vec<u16>,
    /// The frame's indication for each decode target (see
    /// [`ScalabilityPattern::decode_target_layers`] for their order).
    pub dtis: Vec<DecodeTargetIndication>,
    /// For each chain (one per spatial layer), how many frames back the previous frame of
    /// the chain is; 0 when there is none.
    pub chain_fdiffs: Vec<u8>,
    /// The frame is its picture's last.
    pub end_of_picture: bool,
}

impl LayerFrame {
    /// Whether the frame starts a coded video sequence: the first frame of a key picture. Its
    /// first packet carries the Dependency Descriptor's structure, and VP9's scalability
    /// structure.
    pub fn starts_coded_video_sequence(&self) -> bool {
        self.key_picture && self.spatial_id == 0
    }

    /// The frame as the Dependency Descriptor describes it, for
    /// [`DependencyDescriptorWriter::next_frame`](crate::codec::dependency_descriptor::DependencyDescriptorWriter::next_frame).
    pub fn dependencies(&self) -> FrameDependencyTemplate {
        FrameDependencyTemplate {
            spatial_id: self.spatial_id,
            temporal_id: self.temporal_id,
            dtis: self.dtis.clone(),
            fdiffs: self.fdiffs.clone(),
            chain_fdiffs: self.chain_fdiffs.clone(),
        }
    }

    /// The frame as the VP8 payload descriptor describes it (RFC 7741 section 4.2), for
    /// [`Vp8Payloader::payload_frame`](crate::codec::vp8::Vp8Payloader::payload_frame). VP8
    /// has temporal layers only; `mode` says whether there is more than one.
    pub fn vp8_info(&self, mode: ScalabilityMode) -> Vp8FrameInfo {
        Vp8FrameInfo {
            non_reference: self.discardable,
            temporal: (mode.temporal_layers() > 1).then_some(Vp8TemporalLayer {
                tid: self.temporal_id,
                layer_sync: self.layer_sync,
            }),
            key_idx: None,
        }
    }

    /// The frame as the VP9 payload descriptor describes it (RFC 9628 section 4.2), for
    /// [`Vp9Payloader::payload_layer_frame`](crate::codec::vp9::Vp9Payloader::payload_layer_frame).
    /// The pattern is the authority on the frame's dependencies, so they are stated rather
    /// than left to the frame's header (which an end-to-end encrypted frame hides).
    pub fn vp9_info(&self) -> Vp9FrameInfo {
        Vp9FrameInfo {
            temporal_id: self.temporal_id,
            spatial_id: self.spatial_id,
            // In these patterns a frame never predicts from one of its own temporal layer or
            // a higher one, except in temporal layer 0.
            switching_up_point: true,
            inter_layer_dependency: self.inter_layer_dependency,
            not_reference_for_upper_layers: !self.referenced_by_upper_layers,
            end_of_picture: self.end_of_picture,
            key_frame: Some(self.key_frame),
            inter_picture_predicted: Some(self.temporal_reference.is_some()),
            reference_diffs: self.temporal_reference.into_iter().collect(),
        }
    }
}

/// The dependency structure of a [`ScalabilityMode`], as a generator of pictures.
///
/// The structure is the one of the specification's dependency diagrams (webrtc-svc section 9)
/// and of the AV1 RTP specification's examples (A.10.2), which give the same structures as
/// tables:
///
/// * temporal layers: with two, pictures alternate between layers 0 and 1; with three, the
///   layers go 0, 2, 1, 2. A frame predicts from the latest frame of its spatial layer in a
///   lower temporal layer (in layer 0: the latest of layer 0);
/// * `LxTy`: in addition every frame predicts from the frame of the spatial layer below in
///   its picture;
/// * `LxTy_KEY`: it does so in the key picture only;
/// * `LxTy_KEY_SHIFT`: as `_KEY`, and after the key picture the temporal pattern of spatial
///   layer `s` of `S` starts `(s + 1) mod S` pictures late, so the layers' base layer frames
///   fall in different pictures;
/// * `SxTy`: the spatial layers are independent, each with its own key frame.
///
/// Decode targets are one per spatial and temporal layer, highest spatial layer first and
/// within it highest temporal layer first (the order of the AV1 RTP specification's tables).
/// There is one chain per spatial layer, protecting that layer's decode targets.
#[derive(Debug, Clone)]
pub struct ScalabilityPattern {
    mode: ScalabilityMode,
    /// Pictures since the key picture; `None` before the first picture.
    picture: Option<u64>,
    /// Frames given out so far.
    frames: u64,
    /// Per spatial and temporal layer: the latest frame (its number and its picture).
    latest: [[Option<(u64, u64)>; MAX_TEMPORAL]; MAX_SPATIAL],
    /// Per chain: its latest frame.
    chain_latest: [Option<u64>; MAX_SPATIAL],
}

impl ScalabilityPattern {
    /// The pattern of `mode`, before its first picture.
    pub fn new(mode: ScalabilityMode) -> Self {
        Self {
            mode,
            picture: None,
            frames: 0,
            latest: [[None; MAX_TEMPORAL]; MAX_SPATIAL],
            chain_latest: [None; MAX_SPATIAL],
        }
    }

    /// The mode.
    pub fn mode(&self) -> ScalabilityMode {
        self.mode
    }

    /// The spatial and temporal layer each decode target stands for, in decode target order.
    pub fn decode_target_layers(&self) -> Vec<(u8, u8)> {
        let (spatial, temporal) = (self.mode.spatial_layers(), self.mode.temporal_layers());
        (0..spatial)
            .rev()
            .flat_map(|s| (0..temporal).rev().map(move |t| (s, t)))
            .collect()
    }

    /// The temporal layer of spatial layer `s` in the picture `picture` pictures after the
    /// key picture.
    fn temporal_id(&self, s: u8, picture: u64) -> u8 {
        if picture == 0 {
            return 0;
        }
        let sequence: &[u8] = match self.mode.temporal_layers() {
            1 => &[0],
            2 => &[0, 1],
            _ => &[0, 2, 1, 2],
        };
        let shift = if self.mode.has_temporal_shift() {
            ((s + 1) % self.mode.spatial_layers()) as i64
        } else {
            0
        };
        sequence[(picture as i64 - shift).rem_euclid(sequence.len() as i64) as usize]
    }

    /// The frames of the next picture, lowest spatial layer first. `key_picture` starts a new
    /// coded video sequence (the first picture always does): ask for one when a receiver
    /// asks for a key frame.
    pub fn next_picture(&mut self, key_picture: bool) -> Vec<LayerFrame> {
        let picture = match self.picture {
            Some(picture) if !key_picture => picture + 1,
            _ => {
                self.latest = [[None; MAX_TEMPORAL]; MAX_SPATIAL];
                self.chain_latest = [None; MAX_SPATIAL];
                0
            }
        };
        self.picture = Some(picture);
        let key_picture = picture == 0;
        let mode = self.mode;
        let prediction = mode.inter_layer_prediction();
        let (spatial, temporal) = (mode.spatial_layers(), mode.temporal_layers());

        let mut frames = Vec::with_capacity(spatial as usize);
        for s in 0..spatial {
            let t = self.temporal_id(s, picture);
            let number = self.frames;

            // The frame of this spatial layer it predicts from: the latest one of a lower
            // temporal layer, or in temporal layer 0 the latest of that layer.
            let candidates = if t == 0 { 0..1 } else { 0..t as usize };
            let temporal_reference = self.latest[s as usize][candidates]
                .iter()
                .flatten()
                .max_by_key(|(_, picture)| *picture)
                .copied();
            let inter_layer_dependency = s > 0
                && match prediction {
                    InterLayerPrediction::Full => true,
                    InterLayerPrediction::KeyPicture => key_picture,
                    InterLayerPrediction::None => false,
                };
            let mut fdiffs = vec![];
            if let Some((reference, _)) = temporal_reference {
                fdiffs.push((number - reference) as u16);
            }
            if inter_layer_dependency {
                // The frame given out just before this one.
                fdiffs.push(1);
            }

            let referenced_by_upper_layers = s + 1 < spatial
                && match prediction {
                    InterLayerPrediction::Full => true,
                    InterLayerPrediction::KeyPicture => key_picture,
                    InterLayerPrediction::None => false,
                };
            // A frame of the highest temporal layer is no reference within its spatial layer.
            let discardable = temporal > 1 && t == temporal - 1 && !referenced_by_upper_layers;
            let layer_sync = t > 0
                && temporal_reference.is_some_and(|(reference, _)| {
                    self.latest[s as usize][0].is_some_and(|(base, _)| base == reference)
                });

            // The indication for each decode target (ds, dt).
            let dtis = self
                .decode_target_layers()
                .into_iter()
                .map(|(ds, dt)| {
                    let own_layer = if t > dt {
                        DecodeTargetIndication::NotPresent
                    } else if t == dt && t > 0 {
                        DecodeTargetIndication::Discardable
                    } else {
                        DecodeTargetIndication::Switch
                    };
                    match prediction {
                        InterLayerPrediction::Full if s > ds || t > dt => {
                            DecodeTargetIndication::NotPresent
                        }
                        InterLayerPrediction::Full if s == ds => own_layer,
                        // A lower layer's frame is needed by the target; at a key picture
                        // the target can be joined.
                        InterLayerPrediction::Full if key_picture => DecodeTargetIndication::Switch,
                        InterLayerPrediction::Full => DecodeTargetIndication::Required,
                        InterLayerPrediction::KeyPicture if key_picture => {
                            if s <= ds {
                                DecodeTargetIndication::Switch
                            } else {
                                DecodeTargetIndication::NotPresent
                            }
                        }
                        InterLayerPrediction::KeyPicture | InterLayerPrediction::None => {
                            if s == ds {
                                own_layer
                            } else {
                                DecodeTargetIndication::NotPresent
                            }
                        }
                    }
                })
                .collect();

            // Chain c is the frames spatial layer c cannot do without: its temporal layer 0
            // frames, and the frames of the layers below that those depend on.
            let mut chain_fdiffs = Vec::with_capacity(spatial as usize);
            for chain in 0..spatial {
                chain_fdiffs.push(
                    self.chain_latest[chain as usize]
                        .map_or(0, |latest| (number - latest).min(u8::MAX as u64) as u8),
                );
                let in_chain = match prediction {
                    InterLayerPrediction::Full => t == 0 && s <= chain,
                    InterLayerPrediction::KeyPicture if key_picture => s <= chain,
                    InterLayerPrediction::KeyPicture | InterLayerPrediction::None => {
                        t == 0 && s == chain
                    }
                };
                if in_chain {
                    self.chain_latest[chain as usize] = Some(number);
                }
            }

            frames.push(LayerFrame {
                spatial_id: s,
                temporal_id: t,
                key_picture,
                key_frame: fdiffs.is_empty(),
                temporal_reference: temporal_reference
                    .map(|(_, reference_picture)| (picture - reference_picture) as u8),
                inter_layer_dependency,
                referenced_by_upper_layers,
                discardable,
                layer_sync,
                fdiffs,
                dtis,
                chain_fdiffs,
                end_of_picture: s + 1 == spatial,
            });
            self.latest[s as usize][t as usize] = Some((number, picture));
            self.frames += 1;
        }
        frames
    }

    /// The mode's frame dependency structure for the Dependency Descriptor (AV1 RTP
    /// specification A.8): one template for every kind of frame the pattern produces, so that
    /// each frame's descriptor is three bytes. `resolution` is the highest spatial layer's
    /// width and height, when the structure should carry the layers' resolutions.
    ///
    /// For `"L1T3"`, `"L3T3"` and `"L3T3_KEY_SHIFT"` this is the structure the specification
    /// gives as an example (A.10.2.1 to A.10.2.3), template for template.
    pub fn dependency_structure(
        mode: ScalabilityMode,
        resolution: Option<(u32, u32)>,
    ) -> FrameDependencyStructure {
        // Run the pattern until it repeats and keep each distinct frame once, in the order
        // the syntax needs: by spatial layer, then temporal layer, then first appearance.
        let mut pattern = Self::new(mode);
        let mut templates: Vec<FrameDependencyTemplate> = vec![];
        for _ in 0..=4 * 4 {
            for frame in pattern.next_picture(false) {
                let template = frame.dependencies();
                if !templates.contains(&template) {
                    templates.push(template);
                }
            }
        }
        templates.sort_by_key(|t| (t.spatial_id, t.temporal_id));

        let spatial = mode.spatial_layers();
        FrameDependencyStructure {
            template_id_offset: 0,
            num_decode_targets: spatial as usize * mode.temporal_layers() as usize,
            num_chains: spatial as usize,
            decode_target_protected_by: pattern
                .decode_target_layers()
                .into_iter()
                .map(|(s, _)| s)
                .collect(),
            resolutions: resolution
                .map(|(width, height)| {
                    (0..spatial)
                        .map(|s| {
                            let (width, height) = mode.layer_resolution(s, width, height);
                            RenderResolution { width, height }
                        })
                        .collect()
                })
                .unwrap_or_default(),
            templates,
        }
    }

    /// The mode's VP9 scalability structure (RFC 9628 section 4.2.1), for
    /// [`Vp9Payloader::set_scalability_structure`](crate::codec::vp9::Vp9Payloader::set_scalability_structure).
    /// `resolution` is the highest spatial layer's width and height, when the SS should carry
    /// the layers' resolutions.
    ///
    /// For non-flexible mode (`flexible_mode` false) it has the picture group that declares
    /// the temporal structure; in flexible mode each packet carries its own references and
    /// the SS has none.
    ///
    /// # Errors
    ///
    /// Non-flexible mode for a mode with shifted temporal layers: there "all frames follow the
    /// same inter-picture dependency structure" (RFC 9628 section 4.2.1), which a shifted
    /// pattern does not; and a resolution that does not fit 16 bits.
    pub fn vp9_scalability_structure(
        mode: ScalabilityMode,
        resolution: Option<(u32, u32)>,
        flexible_mode: bool,
    ) -> Result<Vp9ScalabilityStructure> {
        let mut resolutions = vec![];
        if let Some((width, height)) = resolution {
            for s in 0..mode.spatial_layers() {
                let (width, height) = mode.layer_resolution(s, width, height);
                match (u16::try_from(width), u16::try_from(height)) {
                    (Ok(width), Ok(height)) => resolutions.push((width, height)),
                    _ => {
                        return Err(Error::Other(format!(
                            "VP9 scalability structure: {width}x{height} does not fit 16 bits"
                        )));
                    }
                }
            }
        }
        let mut picture_group = vec![];
        if !flexible_mode {
            if mode.has_temporal_shift() {
                return Err(Error::Other(format!(
                    "VP9 non-flexible mode cannot carry {mode}: its spatial layers have different temporal structures"
                )));
            }
            // (TID, P_DIFF) of each picture of one period, from the key picture on.
            let group: &[(u8, u8)] = match mode.temporal_layers() {
                1 => &[(0, 1)],
                2 => &[(0, 2), (1, 1)],
                _ => &[(0, 4), (2, 1), (1, 2), (2, 1)],
            };
            picture_group = group
                .iter()
                .map(|(temporal_id, reference_diff)| Vp9PictureGroupEntry {
                    temporal_id: *temporal_id,
                    switching_up_point: true,
                    reference_diffs: vec![*reference_diff],
                })
                .collect();
        }
        Ok(Vp9ScalabilityStructure {
            spatial_layers: mode.spatial_layers(),
            resolutions,
            picture_group,
        })
    }
}

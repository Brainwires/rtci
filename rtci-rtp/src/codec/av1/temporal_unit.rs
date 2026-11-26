//! An AV1 temporal unit split into the data of its spatial layers (AV1 specification 7.5: the
//! OBUs of a temporal unit's frames carry their layer in the OBU extension header). RFC 9605
//! section 6.1.3 needs each layer in its own SFrame ciphertext, so a spatially scalable
//! temporal unit is split before encryption; after decryption the layers' data, lowest first,
//! is concatenated again.

#[cfg(test)]
#[path = "temporal_unit_test.rs"]
mod temporal_unit_test;

use bytes::Bytes;
use shared::error::{Error, Result};

use crate::codec::av1::leb128::read_leb128;
use crate::codec::av1::obu::{
    OBU_TYPE_TEMPORAL_DELIMITER, obu_has_extension, obu_has_size, obu_type,
};

/// The OBUs of one spatial layer of a temporal unit, as they were in the unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Av1LayerData {
    /// `spatial_id` of the layer's OBUs (0 when none has an extension header).
    pub spatial_id: u8,
    /// `temporal_id` of the layer's OBUs (0 when none has an extension header).
    pub temporal_id: u8,
    /// The OBUs, byte for byte (headers and size fields included).
    pub data: Bytes,
}

/// The spatial layers of `temporal_unit` (low overhead bitstream format, AV1 specification
/// 5.2), lowest first, each with its OBUs unchanged. OBUs without an extension header (the
/// temporal delimiter, a sequence header, metadata) go with the layer whose OBUs follow them,
/// those at the end with the last layer. A unit without extension headers is one layer.
///
/// # Errors
///
/// A header or a size past the end, a temporal delimiter after the first OBU (a second
/// temporal unit), or a spatial layer that comes after a higher one. An OBU without a size
/// field runs to the end of the unit.
pub fn split_temporal_unit(temporal_unit: &Bytes) -> Result<Vec<Av1LayerData>> {
    let fail = |what: &str| Err(Error::Other(format!("AV1 temporal unit: {what}")));
    let mut layers: Vec<Av1LayerData> = vec![];
    // The current layer: where its data starts, its spatial and temporal id.
    let mut current: Option<(usize, u8, u8)> = None;
    // Where the OBUs of no layer since the current layer's last OBU start.
    let mut pending: Option<usize> = None;
    let mut offset = 0usize;
    while offset < temporal_unit.len() {
        let header = temporal_unit[offset];
        let header_size = if obu_has_extension(header) { 2 } else { 1 };
        if offset + header_size > temporal_unit.len() {
            return fail("an OBU header past the end");
        }
        let end = if obu_has_size(header) {
            let (size, leb128_size) = read_leb128(&temporal_unit[offset + header_size..])
                .ok_or(Error::ErrPayloadTooSmallForObuPayloadSize)?;
            let end = offset + header_size + leb128_size + size as usize;
            if end > temporal_unit.len() {
                return fail("an OBU size past the end");
            }
            end
        } else {
            temporal_unit.len()
        };
        if obu_type(header) == OBU_TYPE_TEMPORAL_DELIMITER && offset > 0 {
            return fail("more than one temporal unit");
        }
        if !obu_has_extension(header) {
            pending.get_or_insert(offset);
            offset = end;
            continue;
        }
        let extension = temporal_unit[offset + 1];
        let (temporal_id, spatial_id) = (extension >> 5, (extension >> 3) & 0b11);
        match current {
            None => current = Some((0, spatial_id, temporal_id)),
            Some((_, current_spatial_id, _)) if current_spatial_id == spatial_id => {}
            Some((_, current_spatial_id, _)) if current_spatial_id > spatial_id => {
                return fail("a spatial layer after a higher one");
            }
            Some((start, current_spatial_id, current_temporal_id)) => {
                // The OBUs of no layer just before this one lead it.
                let boundary = pending.unwrap_or(offset);
                layers.push(Av1LayerData {
                    spatial_id: current_spatial_id,
                    temporal_id: current_temporal_id,
                    data: temporal_unit.slice(start..boundary),
                });
                current = Some((boundary, spatial_id, temporal_id));
            }
        }
        pending = None;
        offset = end;
    }
    let (start, spatial_id, temporal_id) = current.unwrap_or((0, 0, 0));
    if start < temporal_unit.len() {
        layers.push(Av1LayerData {
            spatial_id,
            temporal_id,
            data: temporal_unit.slice(start..),
        });
    }
    Ok(layers)
}

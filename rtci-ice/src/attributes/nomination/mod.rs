//! libwebrtc's `NOMINATION` attribute (0xC001), by which a controlling agent renominates.
//!
//! RFC 8445 has one nomination per component: the controlling agent sets `USE-CANDIDATE` on a
//! pair and the controlled agent uses it. libwebrtc's controlling agent can move the session to
//! another pair later (draft-thatcher-ice-renomination): each nomination carries a growing
//! 32-bit value, and the controlled agent uses the pair with the highest value it has seen. A
//! request with `USE-CANDIDATE` and no `NOMINATION` counts as value 1, as libwebrtc counts it.
#[cfg(test)]
mod nomination_test;

use shared::error::*;
use stun::attributes::{
    ATTR_MESSAGE_INTEGRITY, ATTR_MESSAGE_INTEGRITY_SHA256, ATTR_USE_CANDIDATE, AttrType,
};
use stun::checks::*;
use stun::message::*;

/// The `NOMINATION` attribute type, from libwebrtc's comprehension-optional range.
pub const ATTR_NOMINATION: AttrType = AttrType(0xC001);

const NOMINATION_SIZE: usize = 4; // 32 bit

/// The `NOMINATION` attribute: the renomination value of a connectivity check.
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
pub struct NominationAttr(pub u32);

impl Setter for NominationAttr {
    /// Adds the `NOMINATION` attribute to the message.
    fn add_to(&self, m: &mut Message) -> Result<()> {
        m.add(ATTR_NOMINATION, &self.0.to_be_bytes());
        Ok(())
    }
}

impl NominationAttr {
    /// Decodes the `NOMINATION` attribute from the message.
    pub fn get_from(&mut self, m: &Message) -> Result<()> {
        let v = m.get(ATTR_NOMINATION)?;
        check_size(ATTR_NOMINATION, v.len(), NOMINATION_SIZE)?;
        self.0 = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
        Ok(())
    }
}

/// The nomination a Binding request carries: the `NOMINATION` value when there is one, else 1
/// for `USE-CANDIDATE`, else 0 (no nomination).
///
/// Only attributes ahead of MESSAGE-INTEGRITY count: anything after it is not covered by the
/// integrity check (RFC 8489 Section 14.5), so an on-path party could have appended it. A
/// `NOMINATION` attribute that is not 4 bytes long is ignored.
#[must_use]
pub fn nomination_of(m: &Message) -> u32 {
    let mut use_candidate = false;
    let mut nomination = None;
    for attr in &m.attributes.0 {
        if attr.typ == ATTR_MESSAGE_INTEGRITY || attr.typ == ATTR_MESSAGE_INTEGRITY_SHA256 {
            break;
        }
        if attr.typ == ATTR_USE_CANDIDATE {
            use_candidate = true;
        } else if attr.typ == ATTR_NOMINATION
            && nomination.is_none()
            && attr.value.len() == NOMINATION_SIZE
        {
            nomination = Some(u32::from_be_bytes([
                attr.value[0],
                attr.value[1],
                attr.value[2],
                attr.value[3],
            ]));
        }
    }
    match nomination {
        Some(value) => value,
        None => u32::from(use_candidate),
    }
}

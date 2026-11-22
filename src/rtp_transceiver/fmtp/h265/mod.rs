#[cfg(test)]
mod h265_test;

use super::*;

/// `level-id` of a format without one: level 3.1 (RFC 7798 section 7.1: "When not present,
/// the value of level-id is inferred to be equal to 93").
pub(crate) const DEFAULT_LEVEL_ID: u8 = 93;

/// The fmtp parameters of H.265 (RFC 7798 section 7.1).
///
/// Two H.265 formats are the same format when the parameters that identify a media format
/// configuration are, except `level-id` (section 7.2.2: "profile-space, profile-id,
/// tier-flag, level-id, interop-constraints, profile-compatibility-indicator, and tx-mode.
/// These media configuration parameters, except level-id, MUST be used symmetrically"), each
/// with its section 7.1 default when absent. The `sprop-*` parameters describe a sender's
/// stream and the others are capabilities: they never make a mismatch.
#[derive(Debug, PartialEq)]
pub(crate) struct H265Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl H265Fmtp {
    fn number(&self, key: &str, absent: u32) -> Option<u32> {
        match self.parameters.get(key) {
            None => Some(absent),
            Some(value) => value.trim().parse().ok(),
        }
    }

    /// `profile-space`, 0 when absent; `profile-id`, 1 (Main) when absent (section 7.1).
    fn profile(&self) -> Option<(u32, u32)> {
        Some((
            self.number("profile-space", 0)?,
            self.number("profile-id", 1)?,
        ))
    }

    /// `tier-flag`, 0 when absent.
    fn tier_flag(&self) -> Option<u32> {
        self.number("tier-flag", 0)
    }

    /// `level-id`, [`DEFAULT_LEVEL_ID`] when absent.
    pub(crate) fn level_id(&self) -> Option<u8> {
        match self.parameters.get("level-id") {
            None => Some(DEFAULT_LEVEL_ID),
            Some(value) => value.trim().parse().ok(),
        }
    }

    /// `interop-constraints`, six bytes; when absent "progressive_source_flag = 1,
    /// interlaced_source_flag = 0, non_packed_constraint_flag = 1, frame_only_constraint_flag
    /// = 1, reserved_zero_44bits = 0" (section 7.1).
    fn interop_constraints(&self) -> Option<u64> {
        match self.parameters.get("interop-constraints") {
            None => Some(0xB000_0000_0000),
            Some(value) => {
                let value = value.trim();
                (value.len() == 12)
                    .then(|| u64::from_str_radix(value, 16).ok())
                    .flatten()
            }
        }
    }

    /// `profile-compatibility-indicator`, four bytes, bit j the j-th
    /// `general_profile_compatibility_flag` (bit 0 first); when absent only the bit of
    /// `profile-id` is set (section 7.1).
    fn profile_compatibility_indicator(&self) -> Option<u32> {
        match self.parameters.get("profile-compatibility-indicator") {
            None => {
                let (_, profile_id) = self.profile()?;
                (profile_id < 32).then(|| 1u32 << (31 - profile_id))
            }
            Some(value) => {
                let value = value.trim();
                (value.len() == 8)
                    .then(|| u32::from_str_radix(value, 16).ok())
                    .flatten()
            }
        }
    }

    /// `tx-mode`: `SRST`, `MRST` or `MRMT`, `SRST` when absent (section 7.1); `None` for
    /// another value.
    pub(crate) fn tx_mode(&self) -> Option<&'static str> {
        match self.parameters.get("tx-mode") {
            None => Some("SRST"),
            Some(value) => ["SRST", "MRST", "MRMT"]
                .into_iter()
                .find(|mode| value.trim().eq_ignore_ascii_case(mode)),
        }
    }

    /// The configuration that must be used symmetrically, `None` when a value is malformed.
    #[allow(clippy::type_complexity)]
    fn configuration(&self) -> Option<((u32, u32), u32, u64, u32, &'static str)> {
        Some((
            self.profile()?,
            self.tier_flag()?,
            self.interop_constraints()?,
            self.profile_compatibility_indicator()?,
            self.tx_mode()?,
        ))
    }
}

impl Fmtp for H265Fmtp {
    fn mime_type(&self) -> &str {
        "video/h265"
    }

    /// Match returns true if both describe the same H.265 configuration (section 7.2.2).
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<H265Fmtp>() else {
            return false;
        };
        matches!((self.configuration(), c.configuration()), (Some(a), Some(b)) if a == b)
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<H265Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

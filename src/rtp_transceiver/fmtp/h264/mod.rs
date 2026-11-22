#[cfg(test)]
mod h264_test;

use super::*;

/// `profile-level-id` of a format without one (RFC 6184 section 8.1: "the Baseline profile,
/// without additional constraints at Level 1, MUST be inferred").
const DEFAULT_PROFILE_LEVEL_ID: &str = "42000a";

/// `packetization-mode` of a format without one (RFC 6184 section 8.1: "When the value of
/// packetization-mode is equal to 0 or packetization-mode is not present, the single NAL mode
/// MUST be used").
const DEFAULT_PACKETIZATION_MODE: &str = "0";

/// RFC 6184 section 8.1, Table 5: the combinations of `profile_idc` and `profile-iop` that
/// stand for the full set of coding tools of one profile, as (profile, profile_idc, mask,
/// value): a `profile-iop` byte `iop` is one of them when `iop & mask == value` (the bits
/// marked `x` in the table are not in the mask). Constrained Baseline is listed first: its
/// patterns are narrower than Baseline's.
const PROFILES: &[(&str, u8, u8, u8)] = &[
    ("CB", 0x42, 0b0100_1111, 0b0100_0000),
    ("CB", 0x4D, 0b1000_1111, 0b1000_0000),
    ("CB", 0x58, 0b1100_1111, 0b1100_0000),
    ("B", 0x42, 0b0100_1111, 0b0000_0000),
    ("B", 0x58, 0b1100_1111, 0b1000_0000),
    ("M", 0x4D, 0b1010_1111, 0b0000_0000),
    ("E", 0x58, 0b1100_1111, 0b0000_0000),
    ("H", 0x64, 0xFF, 0b0000_0000),
    ("H10", 0x6E, 0xFF, 0b0000_0000),
    ("H42", 0x7A, 0xFF, 0b0000_0000),
    ("H44", 0xF4, 0xFF, 0b0000_0000),
    ("H10I", 0x6E, 0xFF, 0b0001_0000),
    ("H42I", 0x7A, 0xFF, 0b0001_0000),
    ("H44I", 0xF4, 0xFF, 0b0001_0000),
    ("C44I", 0x2C, 0xFF, 0b0001_0000),
];

/// The Table 5 profile a `profile_idc` / `profile-iop` pair stands for, if any.
fn table_5_profile(profile_idc: u8, profile_iop: u8) -> Option<&'static str> {
    PROFILES
        .iter()
        .find(|(_, idc, mask, value)| *idc == profile_idc && profile_iop & mask == *value)
        .map(|(profile, ..)| *profile)
}

/// Whether two `profile-level-id` values name the same sub-profile (RFC 6184 section 8.2.2:
/// the level part is not compared). Pairs of Table 5 compare as the profile they stand for,
/// so `42e01f` (Constrained Baseline as Baseline with constraint_set1) is the same as `4d801f`
/// (as Main with constraint_set0); any other pair compares as its two bytes.
fn profile_level_id_matches(a: &str, b: &str) -> bool {
    let decode = |value: &str| -> Option<(u8, u8)> {
        let bytes = hex::decode(value.trim()).ok()?;
        (bytes.len() == 3).then(|| (bytes[0], bytes[1]))
    };
    let (Some((a_idc, a_iop)), Some((b_idc, b_iop))) = (decode(a), decode(b)) else {
        return false;
    };
    match (table_5_profile(a_idc, a_iop), table_5_profile(b_idc, b_iop)) {
        (Some(a), Some(b)) => a == b,
        _ => a_idc == b_idc && a_iop == b_iop,
    }
}

#[derive(Debug, PartialEq)]
pub(crate) struct H264Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl Fmtp for H264Fmtp {
    fn mime_type(&self) -> &str {
        "video/h264"
    }

    /// Match returns true if h and b are compatible fmtp descriptions
    /// Based on RFC6184 Section 8.2.2:
    ///   The parameters identifying a media format configuration for H.264
    ///   are profile-level-id and packetization-mode.  These media format
    ///   configuration parameters (except for the level part of profile-
    ///   level-id) MUST be used symmetrically; that is, the answerer MUST
    ///   either maintain all configuration parameters or remove the media
    ///   format (payload type) completely if one or more of the parameter
    ///   values are not supported.
    ///     Informative note: The requirement for symmetric use does not
    ///     apply for the level part of profile-level-id and does not apply
    ///     for the other stream properties and capability parameters.
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<H264Fmtp>() else {
            return false;
        };
        // RFC 6184 section 8.1: an absent parameter has its default value.
        let get = |fmtp: &H264Fmtp, key: &str, default: &'static str| -> String {
            fmtp.parameters
                .get(key)
                .map_or_else(|| default.to_owned(), |v| v.trim().to_owned())
        };
        // RFC 6184 section 8.1: "packetization-mode ... MUST be equal to 0, 1, or 2"; a
        // format with another value is no format this endpoint can send or receive.
        let mode = get(self, "packetization-mode", DEFAULT_PACKETIZATION_MODE);
        ["0", "1", "2"].contains(&mode.as_str())
            && mode == get(c, "packetization-mode", DEFAULT_PACKETIZATION_MODE)
            && profile_level_id_matches(
                &get(self, "profile-level-id", DEFAULT_PROFILE_LEVEL_ID),
                &get(c, "profile-level-id", DEFAULT_PROFILE_LEVEL_ID),
            )
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<H264Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

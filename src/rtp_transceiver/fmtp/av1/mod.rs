#[cfg(test)]
mod av1_test;

use super::*;

/// The fmtp parameters of AV1 (AV1 RTP payload format section 7.2).
///
/// Two AV1 formats are the same format when their `profile` is: the profile is what the
/// bitstream is, and is used symmetrically (section 7.2.3). `level-idx` and `tier` are what
/// each side declares it can take, so they never make a mismatch (section 7.2.3: "the
/// answerer MAY declare its own"), and other parameters are ignored.
#[derive(Debug, PartialEq)]
pub(crate) struct Av1Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl Av1Fmtp {
    fn number(&self, key: &str, absent: u8) -> Option<u8> {
        match self.parameters.get(key) {
            None => Some(absent),
            Some(value) => value.trim().parse().ok(),
        }
    }

    /// `profile`, 0 when absent (section 7.2: "If the profile parameter is not present, it
    /// MUST be inferred to be 0"); `None` for a value that is not a number.
    pub(crate) fn profile(&self) -> Option<u8> {
        self.number("profile", 0)
    }

    /// `level-idx`, 5 when absent (section 7.2: "it MUST be inferred to be 5", level 3.1).
    pub(crate) fn level_idx(&self) -> Option<u8> {
        self.number("level-idx", 5)
    }

    /// `tier`, 0 when absent (section 7.2: "it MUST be inferred to be 0", the main tier).
    pub(crate) fn tier(&self) -> Option<u8> {
        self.number("tier", 0)
    }
}

impl Fmtp for Av1Fmtp {
    fn mime_type(&self) -> &str {
        "video/av1"
    }

    /// Match returns true if both describe the same AV1 profile.
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<Av1Fmtp>() else {
            return false;
        };
        matches!((self.profile(), c.profile()), (Some(a), Some(b)) if a == b)
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<Av1Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

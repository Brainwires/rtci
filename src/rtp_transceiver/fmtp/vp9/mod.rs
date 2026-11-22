#[cfg(test)]
mod vp9_test;

use super::*;

/// The VP9 profile of a format without `profile-id` (RFC 9628 section 6: "If no profile-id is
/// present, Profile 0 MUST be inferred").
const DEFAULT_PROFILE_ID: &str = "0";

/// The fmtp parameters of VP9 (RFC 9628 section 6).
///
/// Two VP9 formats are the same format when their `profile-id` is: it is the only parameter
/// that changes what the bitstream is. `max-fr` and `max-fs` are capabilities each receiver
/// states for itself (section 6.1.2), so they never make a mismatch, and a receiver ignores
/// any other parameter.
#[derive(Debug, PartialEq)]
pub(crate) struct Vp9Fmtp {
    pub(crate) parameters: HashMap<String, String>,
}

impl Vp9Fmtp {
    /// `profile-id`, 0 when absent.
    fn profile_id(&self) -> &str {
        self.parameters
            .get("profile-id")
            .map(|v| v.trim())
            .unwrap_or(DEFAULT_PROFILE_ID)
    }
}

impl Fmtp for Vp9Fmtp {
    fn mime_type(&self) -> &str {
        "video/vp9"
    }

    /// Match returns true if both describe the same VP9 profile.
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        let Some(c) = f.as_any().downcast_ref::<Vp9Fmtp>() else {
            return false;
        };
        let (a, b) = (self.profile_id(), c.profile_id());
        match (a.parse::<u32>(), b.parse::<u32>()) {
            (Ok(a), Ok(b)) => a == b,
            _ => a.eq_ignore_ascii_case(b),
        }
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<Vp9Fmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

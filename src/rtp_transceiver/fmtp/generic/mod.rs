#[cfg(test)]
mod generic_test;

use unicase::UniCase;

use super::*;

/// fmtp_consist checks that two FMTP parameters are not inconsistent.
fn fmtp_consist(a: &HashMap<String, String>, b: &HashMap<String, String>) -> bool {
    for (k, v) in a {
        if let Some(vb) = b.get(k)
            && UniCase::new(v) != UniCase::new(vb)
        {
            return false;
        }
    }
    for (k, v) in b {
        if let Some(va) = a.get(k)
            && UniCase::new(v) != UniCase::new(va)
        {
            return false;
        }
    }
    true
}

#[derive(Debug, PartialEq)]
pub(crate) struct GenericFmtp {
    pub(crate) mime_type: String,
    pub(crate) parameters: HashMap<String, String>,
}

impl Fmtp for GenericFmtp {
    fn mime_type(&self) -> &str {
        self.mime_type.as_str()
    }

    /// Match returns true if g and b are compatible fmtp descriptions
    /// The generic implementation is used for MimeTypes that are not defined
    fn match_fmtp(&self, f: &dyn Fmtp) -> bool {
        if let Some(c) = f.as_any().downcast_ref::<GenericFmtp>() {
            if self.mime_type.to_lowercase() != c.mime_type().to_lowercase() {
                return false;
            }

            // RFC 4588 section 8.1: `rtx-time` is how long that side's sender keeps packets,
            // each endpoint's own figure. Two retransmission formats that differ in it alone
            // are the same format (the `apt` decides).
            if self
                .mime_type
                .rsplit('/')
                .next()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rtx"))
            {
                let without_rtx_time = |parameters: &HashMap<String, String>| {
                    let mut parameters = parameters.clone();
                    parameters.remove("rtx-time");
                    parameters
                };
                return fmtp_consist(
                    &without_rtx_time(&self.parameters),
                    &without_rtx_time(&c.parameters),
                );
            }

            // RFC 8627 section 5.2.1 (draft-03 section 5.2.1): `repair-window` is the time the
            // repair packets span; a receiver takes any window it can support (the media
            // engine refuses a longer one than it registered), so two FlexFEC formats that
            // differ in it alone are the same format.
            if self.mime_type.rsplit('/').next().is_some_and(|subtype| {
                subtype.eq_ignore_ascii_case("flexfec")
                    || subtype.eq_ignore_ascii_case("flexfec-03")
            }) {
                let without_window = |parameters: &HashMap<String, String>| {
                    let mut parameters = parameters.clone();
                    parameters.remove("repair-window");
                    parameters
                };
                return fmtp_consist(
                    &without_window(&self.parameters),
                    &without_window(&c.parameters),
                );
            }

            // RFC 7741 section 6.2.2: VP8's `max-fr` and `max-fs` are receiver capabilities,
            // "declarative", each side's own: they do not make two VP8 formats different.
            if self
                .mime_type
                .rsplit('/')
                .next()
                .is_some_and(|subtype| subtype.eq_ignore_ascii_case("vp8"))
            {
                let without_limits = |parameters: &HashMap<String, String>| {
                    let mut parameters = parameters.clone();
                    parameters.remove("max-fr");
                    parameters.remove("max-fs");
                    parameters
                };
                return fmtp_consist(
                    &without_limits(&self.parameters),
                    &without_limits(&c.parameters),
                );
            }

            fmtp_consist(&self.parameters, &c.parameters)
        } else {
            false
        }
    }

    fn parameter(&self, key: &str) -> Option<&String> {
        self.parameters.get(key)
    }

    fn equal(&self, other: &dyn Fmtp) -> bool {
        other.as_any().downcast_ref::<GenericFmtp>() == Some(self)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

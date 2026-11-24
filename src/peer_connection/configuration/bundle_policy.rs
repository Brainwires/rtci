use std::fmt;

use serde::{Deserialize, Serialize};

/// Media bundling policy for ICE candidate gathering and transport usage.
///
/// Bundle policy determines how media tracks are multiplexed onto ICE transports
/// when the remote endpoint may or may not support bundling. Bundling multiple
/// media streams onto a single transport reduces overhead and improves performance.
///
/// # This engine has one transport
///
/// A peer connection here has exactly one ICE and DTLS transport, and every m= section runs on it:
/// every offer groups all of its non-rejected m= sections in one `a=group:BUNDLE` (RFC 9143). The
/// policy decides which m= sections of an initial offer are `a=bundle-only`, and which sections of
/// an offer without a BUNDLE group an answer accepts (RFC 9429 section 4.1.1). It may not be
/// changed by `set_configuration` (W3C webrtc-pc "set the configuration").
///
/// # `max-bundle` and `must-bundle`
///
/// W3C webrtc-pc section 4.2.5 defines `max-bundle`; RFC 9429 section 4.1.1 deprecates that
/// name and introduces "an identically defined 'must-bundle' policy". Both select the same
/// policy here. RFC 9429 also has implementations "ignore attempts by the application to
/// select" `max-bundle` (a SHOULD):
/// `SettingEngineBuilder::with_max_bundle_as_must_bundle(false)` does that, and
/// [`RTCBundlePolicy::MaxBundle`] then behaves as the default (`balanced`).
///
/// # Examples
///
/// ```
/// use rtci::peer_connection::configuration::{RTCConfigurationBuilder, RTCBundlePolicy};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = RTCConfigurationBuilder::new()
///     .with_bundle_policy(RTCBundlePolicy::MustBundle)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Specifications
///
/// * [W3C RTCBundlePolicy](https://www.w3.org/TR/webrtc/#rtcbundlepolicy-enum)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCBundlePolicy {
    /// Unspecified - not a W3C value. Behaves as the default, "balanced", which is what
    /// [`Default`] gives (W3C webrtc-pc 4.2.1).
    Unspecified = 0,

    /// Gather ICE candidates for each media type (audio, video, data).
    ///
    /// If the remote endpoint is not bundle-aware, negotiate only one audio
    /// and one video track on separate transports. This provides a balance
    /// between compatibility and efficiency.
    ///
    /// **Use when:** Connecting to peers that may not support bundling
    ///
    /// **In this engine:** the default. In an initial offer the second and later m= section
    /// of each media type is `a=bundle-only`; every section shares one transport.
    #[default]
    #[serde(rename = "balanced")]
    Balanced = 1,

    /// Gather ICE candidates for each track individually.
    ///
    /// If the remote endpoint is not bundle-aware, negotiate all media tracks
    /// on separate transports. This maximizes compatibility at the cost of
    /// performance and resource usage.
    ///
    /// **Use when:** Maximum compatibility with legacy systems is required
    ///
    /// **In this engine:** no m= section is `a=bundle-only`, but there is one transport:
    /// every section carries the same ICE credentials.
    #[serde(rename = "max-compat")]
    MaxCompat = 2,

    /// Gather ICE candidates for only one track (recommended).
    ///
    /// All media is bundled onto a single transport. If the remote endpoint
    /// is not bundle-aware, only negotiate one media track. This provides
    /// the best performance by minimizing overhead.
    ///
    /// **In this engine:** the W3C webrtc-pc name of [`RTCBundlePolicy::MustBundle`]. RFC
    /// 9429 section 4.1.1 deprecates the name;
    /// `SettingEngineBuilder::with_max_bundle_as_must_bundle(false)` has it ignored (the
    /// default policy then applies).
    #[serde(rename = "max-bundle")]
    MaxBundle = 3,

    /// RFC 9429 section 4.1.1 `must-bundle`: "the JSEP implementation will mark all 'm='
    /// sections other than the first as bundle-only"; an answer to an offer without a BUNDLE
    /// group accepts the first m= section only.
    #[serde(rename = "must-bundle")]
    MustBundle = 4,
}

/// This is done this way because of a linter.
const BUNDLE_POLICY_BALANCED_STR: &str = "balanced";
const BUNDLE_POLICY_MAX_COMPAT_STR: &str = "max-compat";
const BUNDLE_POLICY_MAX_BUNDLE_STR: &str = "max-bundle";
const BUNDLE_POLICY_MUST_BUNDLE_STR: &str = "must-bundle";

impl From<&str> for RTCBundlePolicy {
    /// NewSchemeType defines a procedure for creating a new SchemeType from a raw
    /// string naming the scheme type.
    fn from(raw: &str) -> Self {
        match raw {
            BUNDLE_POLICY_BALANCED_STR => RTCBundlePolicy::Balanced,
            BUNDLE_POLICY_MAX_COMPAT_STR => RTCBundlePolicy::MaxCompat,
            BUNDLE_POLICY_MAX_BUNDLE_STR => RTCBundlePolicy::MaxBundle,
            BUNDLE_POLICY_MUST_BUNDLE_STR => RTCBundlePolicy::MustBundle,
            _ => RTCBundlePolicy::Unspecified,
        }
    }
}

impl fmt::Display for RTCBundlePolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RTCBundlePolicy::Balanced => write!(f, "{BUNDLE_POLICY_BALANCED_STR}"),
            RTCBundlePolicy::MaxCompat => write!(f, "{BUNDLE_POLICY_MAX_COMPAT_STR}"),
            RTCBundlePolicy::MaxBundle => write!(f, "{BUNDLE_POLICY_MAX_BUNDLE_STR}"),
            RTCBundlePolicy::MustBundle => write!(f, "{BUNDLE_POLICY_MUST_BUNDLE_STR}"),
            _ => write!(
                f,
                "{}",
                crate::peer_connection::configuration::UNSPECIFIED_STR
            ),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_bundle_policy() {
        let tests = vec![
            ("Unspecified", RTCBundlePolicy::Unspecified),
            ("balanced", RTCBundlePolicy::Balanced),
            ("max-compat", RTCBundlePolicy::MaxCompat),
            ("max-bundle", RTCBundlePolicy::MaxBundle),
            ("must-bundle", RTCBundlePolicy::MustBundle),
        ];

        for (policy_string, expected_policy) in tests {
            assert_eq!(RTCBundlePolicy::from(policy_string), expected_policy);
        }
    }

    #[test]
    fn test_bundle_policy_string() {
        let tests = vec![
            (RTCBundlePolicy::Unspecified, "Unspecified"),
            (RTCBundlePolicy::Balanced, "balanced"),
            (RTCBundlePolicy::MaxCompat, "max-compat"),
            (RTCBundlePolicy::MaxBundle, "max-bundle"),
            (RTCBundlePolicy::MustBundle, "must-bundle"),
        ];

        for (policy, expected_string) in tests {
            assert_eq!(policy.to_string(), expected_string);
        }
    }
}

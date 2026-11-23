use std::fmt;

use serde::{Deserialize, Serialize};

/// RTCP multiplexing policy controlling ICE candidate gathering for RTCP.
///
/// RTCP (RTP Control Protocol) carries statistics and control information for RTP streams.
/// This policy determines whether RTCP is sent on the same port as RTP (multiplexed) or
/// on a separate port.
///
/// # Recommendations
///
/// - **Require** - Recommended for all modern WebRTC applications (standard since 2013)
/// - **Negotiate** - Only use if you need compatibility with very old implementations
///
/// Modern browsers always support RTCP multiplexing, so `Require` is the best choice.
///
/// # Examples
///
/// ```
/// use rtc::peer_connection::configuration::{RTCConfigurationBuilder, RTCRtcpMuxPolicy};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Recommended: Require RTCP multiplexing
/// let config = RTCConfigurationBuilder::new()
///     .with_rtcp_mux_policy(RTCRtcpMuxPolicy::Require)
///     .build();
/// # Ok(())
/// # }
/// ```
///
/// ## Specifications
///
/// * [W3C RTCRtcpMuxPolicy](https://www.w3.org/TR/webrtc/#rtcrtcpmuxpolicy-enum)
/// * [RFC 5761 - Multiplexing RTP and RTCP](https://datatracker.ietf.org/doc/html/rfc5761)
#[derive(Default, Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCRtcpMuxPolicy {
    /// Unspecified - not a W3C value. Behaves as the default, "require", which is what
    /// [`Default`] gives (W3C webrtc-pc 4.2.1).
    Unspecified = 0,

    /// Gather ICE candidates for both RTP and RTCP.
    ///
    /// If the remote endpoint supports RTCP multiplexing, use the RTP candidates
    /// for both RTP and RTCP. If not, use separate candidates for RTCP.
    ///
    /// This provides maximum compatibility but uses more resources and gathers
    /// more ICE candidates.
    ///
    /// **Use when:** Compatibility with legacy systems is required
    ///
    /// Not a W3C value: webrtc-pc 4.2.5 has `"require"` only, and a W3C API layer offers no
    /// other. This is RFC 9429 section 4.1.1's `negotiate` policy, an engine setting: the
    /// offer leaves out `a=rtcp-mux-only`, and a section the answer does not multiplex is
    /// rejected (the engine always multiplexes).
    #[serde(rename = "negotiate")]
    Negotiate = 1,

    /// Only gather ICE candidates for RTP, multiplex RTCP on same port (recommended).
    ///
    /// Gather ICE candidates only for RTP and always multiplex RTCP on the RTP port.
    /// If the remote endpoint doesn't support RTCP multiplexing, session negotiation
    /// will fail.
    ///
    /// This is more efficient and is the standard for modern WebRTC. All current
    /// browsers support this mode.
    ///
    /// **Use when:** Connecting to modern WebRTC implementations (recommended)
    #[default]
    #[serde(rename = "require")]
    Require = 2,
}

const RTCP_MUX_POLICY_NEGOTIATE_STR: &str = "negotiate";
const RTCP_MUX_POLICY_REQUIRE_STR: &str = "require";

impl From<&str> for RTCRtcpMuxPolicy {
    fn from(raw: &str) -> Self {
        match raw {
            RTCP_MUX_POLICY_NEGOTIATE_STR => RTCRtcpMuxPolicy::Negotiate,
            RTCP_MUX_POLICY_REQUIRE_STR => RTCRtcpMuxPolicy::Require,
            _ => RTCRtcpMuxPolicy::Unspecified,
        }
    }
}

impl fmt::Display for RTCRtcpMuxPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            RTCRtcpMuxPolicy::Negotiate => RTCP_MUX_POLICY_NEGOTIATE_STR,
            RTCRtcpMuxPolicy::Require => RTCP_MUX_POLICY_REQUIRE_STR,
            RTCRtcpMuxPolicy::Unspecified => crate::peer_connection::configuration::UNSPECIFIED_STR,
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_new_rtcp_mux_policy() {
        let tests = vec![
            ("Unspecified", RTCRtcpMuxPolicy::Unspecified),
            ("negotiate", RTCRtcpMuxPolicy::Negotiate),
            ("require", RTCRtcpMuxPolicy::Require),
        ];

        for (policy_string, expected_policy) in tests {
            assert_eq!(RTCRtcpMuxPolicy::from(policy_string), expected_policy);
        }
    }

    #[test]
    fn test_rtcp_mux_policy_string() {
        let tests = vec![
            (RTCRtcpMuxPolicy::Unspecified, "Unspecified"),
            (RTCRtcpMuxPolicy::Negotiate, "negotiate"),
            (RTCRtcpMuxPolicy::Require, "require"),
        ];

        for (policy, expected_string) in tests {
            assert_eq!(policy.to_string(), expected_string);
        }
    }
}

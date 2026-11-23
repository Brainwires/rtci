use serde::{Deserialize, Serialize};
use std::fmt;

use super::candidate_type::RTCIceCandidateType;
use super::protocol::RTCIceProtocol;
use ice::tcp_type::TcpType;
use shared::error::{Error, Result};

pub use ice::candidate::{
    Candidate, CandidateConfig, candidate_host::CandidateHostConfig,
    candidate_peer_reflexive::CandidatePeerReflexiveConfig, candidate_relay::CandidateRelayConfig,
    candidate_server_reflexive::CandidateServerReflexiveConfig,
};

/// The role an ICE-TCP candidate takes when a pair is checked (RFC 6544 §4.5).
///
/// Carried by [`RTCIceCandidate::tcp_type`]; meaningless for UDP candidates, which leave it
/// [`Unspecified`](RTCIceTcpCandidateType::Unspecified).
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCIceTcpCandidateType {
    /// Not a TCP candidate, or the type was absent.
    #[default]
    Unspecified,

    /// Opens the connection. Its port is the discard placeholder 9, not a bound one, since an
    /// active candidate listens on nothing.
    #[serde(rename = "active")]
    Active,

    /// Accepts the connection; its port is the local listener's.
    #[serde(rename = "passive")]
    Passive,

    /// Both ends open simultaneously.
    #[serde(rename = "so")]
    SimultaneousOpen,
}

impl From<TcpType> for RTCIceTcpCandidateType {
    fn from(t: TcpType) -> Self {
        match t {
            TcpType::Unspecified => RTCIceTcpCandidateType::Unspecified,
            TcpType::Active => RTCIceTcpCandidateType::Active,
            TcpType::Passive => RTCIceTcpCandidateType::Passive,
            TcpType::SimultaneousOpen => RTCIceTcpCandidateType::SimultaneousOpen,
            _ => RTCIceTcpCandidateType::Unspecified,
        }
    }
}

impl RTCIceTcpCandidateType {
    /// Converts to the ICE agent's own representation.
    pub fn to_ice(self) -> TcpType {
        match self {
            RTCIceTcpCandidateType::Unspecified => TcpType::Unspecified,
            RTCIceTcpCandidateType::Active => TcpType::Active,
            RTCIceTcpCandidateType::Passive => TcpType::Passive,
            RTCIceTcpCandidateType::SimultaneousOpen => TcpType::SimultaneousOpen,
        }
    }
}

/// The protocol used to reach the STUN/TURN server that produced a candidate.
///
/// Carried by [`RTCIceCandidate::relay_protocol`]; only meaningful for relay candidates.
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RTCIceServerTransportProtocol {
    /// Not a relay candidate, or the protocol was absent.
    #[default]
    Unspecified,

    /// Reached over UDP.
    #[serde(rename = "udp")]
    Udp,
    /// Reached over TCP.
    #[serde(rename = "tcp")]
    Tcp,
    /// Reached over TLS.
    #[serde(rename = "tls")]
    Tls,
}

/// ICECandidate represents a ice candidate
///
/// ## Specifications
///
/// * [MDN]
/// * [W3C]
///
/// [MDN]: https://developer.mozilla.org/en-US/docs/Web/API/RTCIceCandidate
/// [W3C]: https://www.w3.org/TR/webrtc/#rtcicecandidate-interface
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RTCIceCandidate {
    /// The unique identifier of this candidate.
    pub id: String,
    /// The foundation of the candidate, used to group candidates of the same type.
    pub foundation: String,
    /// The priority of this candidate.
    pub priority: u32,
    /// The IP address of the candidate.
    pub address: String,
    /// The transport protocol (UDP or TCP) used by this candidate.
    pub protocol: RTCIceProtocol,
    /// The port number of the candidate.
    pub port: u16,
    /// The candidate type (host, srflx, prflx, relay).
    pub typ: RTCIceCandidateType,
    /// The ICE component (1 for RTP, 2 for RTCP).
    pub component: u16,
    /// The related IP address, if this is a reflexive or relay candidate.
    pub related_address: String,
    /// The related port number, if this is a reflexive or relay candidate.
    pub related_port: u16,
    /// The TCP candidate type (active, passive, so), if this is a TCP candidate.
    pub tcp_type: RTCIceTcpCandidateType,
    /// The relay protocol (UDP, TCP, TLS), if this is a relay candidate.
    pub relay_protocol: RTCIceServerTransportProtocol,
    /// The URL of the STUN/TURN server used to gather this candidate, if any.
    pub url: Option<String>,
    /// The username fragment of the ICE generation the candidate belongs to (W3C
    /// `RTCIceCandidate.usernameFragment`; RFC 8838 section 9: a trickled candidate is tied to
    /// its ICE session, so that one that arrives after an ICE restart is recognised and
    /// ignored). Set on the local candidates the peer connection announces.
    #[serde(default)]
    pub username_fragment: Option<String>,
    /// W3C `RTCIceCandidate.sdpMid`: the mid of the media section whose transport the
    /// candidate belongs to. Set on the local candidates the peer connection announces (the
    /// section of the BUNDLE transport), `None` otherwise.
    #[serde(default)]
    pub sdp_mid: Option<String>,
    /// W3C `RTCIceCandidate.sdpMLineIndex`: the index, from 0, of that media section.
    #[serde(default)]
    pub sdp_mline_index: Option<u16>,
    /// Whether this is the end-of-candidates indication of a generation (W3C webrtc-pc section
    /// 5.6, "the ICE agent has finished gathering"): a candidate whose `candidate` attribute is
    /// the empty string. See [`RTCIceCandidate::end_of_candidates`].
    #[serde(default)]
    pub end_of_candidates: bool,
}

/// Conversion for ice_candidates
pub(crate) fn rtc_ice_candidates_from_ice_candidates(
    ice_candidates: &[Candidate],
) -> Vec<RTCIceCandidate> {
    ice_candidates.iter().map(|c| c.into()).collect()
}

impl From<&Candidate> for RTCIceCandidate {
    fn from(c: &Candidate) -> Self {
        let typ: RTCIceCandidateType = c.candidate_type().into();
        let protocol = RTCIceProtocol::from(c.network_type().network_short().as_str());
        // What is signalled: a base hidden behind an mDNS name is not (mDNS draft 3.1.2.2).
        let (related_address, related_port) = if let Some(ra) = c.signalled_related_address() {
            (ra.address, ra.port)
        } else {
            (String::new(), 0)
        };

        RTCIceCandidate {
            id: c.id().to_string(),
            foundation: c.foundation(),
            priority: c.priority(),
            address: c.address().to_string(),
            protocol,
            port: c.port(),
            component: c.component(),
            typ,
            tcp_type: c.tcp_type().into(),
            related_address,
            related_port,
            relay_protocol: Default::default(),
            url: c.url().map(|u| u.to_string()),
            username_fragment: None,
            sdp_mid: None,
            sdp_mline_index: None,
            end_of_candidates: false,
        }
    }
}

impl RTCIceCandidate {
    pub(crate) fn to_ice(&self) -> Result<Candidate> {
        let candidate_id = self.id.clone();
        let base_config = CandidateConfig {
            candidate_id,
            network: self.protocol.to_string(),
            address: self.address.clone(),
            port: self.port,
            component: self.component,
            foundation: self.foundation.clone(),
            priority: self.priority,
        };

        let mut c = match self.typ {
            RTCIceCandidateType::Host => {
                let config = CandidateHostConfig {
                    base_config,
                    tcp_type: self.tcp_type.to_ice(),
                };
                config.new_candidate_host()?
            }
            RTCIceCandidateType::Srflx => {
                let config = CandidateServerReflexiveConfig {
                    base_config,
                    rel_addr: self.related_address.clone(),
                    rel_port: self.related_port,
                    url: self.url.clone(),
                };
                config.new_candidate_server_reflexive()?
            }
            RTCIceCandidateType::Prflx => {
                let config = CandidatePeerReflexiveConfig {
                    base_config,
                    rel_addr: self.related_address.clone(),
                    rel_port: self.related_port,
                };
                config.new_candidate_peer_reflexive()?
            }
            RTCIceCandidateType::Relay => {
                let config = CandidateRelayConfig {
                    base_config,
                    rel_addr: self.related_address.clone(),
                    rel_port: self.related_port,
                    url: self.url.clone(),
                };
                config.new_candidate_relay()?
            }
            _ => return Err(Error::ErrICECandidateTypeUnknown),
        };
        // RFC 6544 section 4.5: a TCP candidate of any type has a `tcptype`.
        if self.typ != RTCIceCandidateType::Host {
            c.set_tcp_type(self.tcp_type.to_ice());
        }

        Ok(c)
    }

    /// Converts this candidate into an [`RTCIceCandidateInit`] suitable for signaling.
    ///
    /// # Errors
    ///
    /// Returns an error if this candidate's type is not one this crate can serialize
    /// (`ErrICECandidateTypeUnknown`), or if its address cannot be re-encoded.
    ///
    /// # Specification
    ///
    /// See [RTCIceCandidate.toJSON()](https://www.w3.org/TR/webrtc/#dom-rtcicecandidate-tojson)
    ///
    /// `candidate`, `sdpMid`, `sdpMLineIndex` and `usernameFragment` are the candidate's own.
    /// A candidate that knows no media section (one built by hand) has `sdp_mid` `None` and
    /// `sdp_mline_index` `0` (the first m-section, the one a BUNDLE group's transport belongs
    /// to): an empty `sdp_mid` would name a section no description has, and
    /// `add_remote_candidate` matches `sdp_mid` before `sdp_mline_index` (W3C
    /// `addIceCandidate`), so the remote side would refuse it. The end-of-candidates
    /// indication gives an empty `candidate`.
    pub fn to_json(&self) -> Result<RTCIceCandidateInit> {
        let sdp_mline_index = if self.sdp_mid.is_none() && self.sdp_mline_index.is_none() {
            Some(0u16)
        } else {
            self.sdp_mline_index
        };
        Ok(RTCIceCandidateInit {
            candidate: self.candidate()?,
            sdp_mid: self.sdp_mid.clone(),
            sdp_mline_index,
            username_fragment: self.username_fragment.clone(),
            url: None,
            relay_protocol: None,
        })
    }

    /// W3C `RTCIceCandidate.candidate`: the `candidate-attribute` (RFC 8839 section 5.1),
    /// `candidate:` included; the empty string for the end-of-candidates indication.
    ///
    /// # Errors
    ///
    /// When the candidate's members do not make a candidate (an unknown type, say).
    pub fn candidate(&self) -> Result<String> {
        if self.end_of_candidates {
            return Ok(String::new());
        }
        Ok(format!("candidate:{}", self.to_ice()?.marshal()))
    }

    /// The end-of-candidates indication of the ICE generation `username_fragment` names, for
    /// the media section `sdp_mid` / `sdp_mline_index` (W3C webrtc-pc section 5.6: "a new
    /// RTCIceCandidate whose candidate attribute is set to an empty string"). Every other
    /// member is empty.
    pub fn end_of_candidates_for(
        username_fragment: Option<String>,
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
    ) -> Self {
        Self {
            username_fragment,
            sdp_mid,
            sdp_mline_index,
            end_of_candidates: true,
            ..Default::default()
        }
    }
}

impl fmt::Display for RTCIceCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}:{}{}",
            self.protocol, self.typ, self.address, self.port, self.related_address,
        )
    }
}

/// ICECandidateInit is used to serialize ice candidates
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RTCIceCandidateInit {
    /// The candidate-attribute string as defined in RFC 8839 §5.1.
    pub candidate: String,
    /// The identifier of the "m=" section in the SDP that this candidate is associated with.
    pub sdp_mid: Option<String>,
    /// The index of the "m=" section in the SDP that this candidate is associated with.
    #[serde(rename = "sdpMLineIndex")]
    pub sdp_mline_index: Option<u16>,
    /// The username fragment used for ICE authentication.
    pub username_fragment: Option<String>,
    /// The URL of the STUN or TURN server used to gather this candidate.
    ///
    /// Per W3C spec, this field is only meaningful for local candidates of type
    /// "srflx" (server reflexive) or "relay". For other candidate types, this
    /// field should be `None`.
    ///
    /// This is a sansio extension - since gathering happens externally in the
    /// sansio architecture, the application must provide this URL when adding
    /// local candidates that were gathered from STUN/TURN servers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// W3C `RTCLocalIceCandidateInit.relayProtocol` (webrtc-pc section 4.8.1): for a local
    /// relay candidate, the protocol this endpoint reaches its TURN server over (RFC 8656
    /// section 3.1). The application does the gathering, so it says; when it does not, the
    /// TURN URL in `url` decides (`turns:` is TLS, `?transport=tcp` TCP, otherwise UDP).
    /// Ignored for every other candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_protocol: Option<RTCIceServerTransportProtocol>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ice_candidate_serialization() {
        let tests = vec![
            (
                RTCIceCandidateInit {
                    candidate: "candidate:abc123".to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: Some("def".to_string()),
                    url: None,
                    relay_protocol: None,
                },
                r#"{"candidate":"candidate:abc123","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":"def"}"#,
            ),
            (
                RTCIceCandidateInit {
                    candidate: "candidate:abc123".to_string(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                    username_fragment: None,
                    url: None,
                    relay_protocol: None,
                },
                r#"{"candidate":"candidate:abc123","sdpMid":null,"sdpMLineIndex":null,"usernameFragment":null}"#,
            ),
            (
                RTCIceCandidateInit {
                    candidate: "candidate:relay123".to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                    url: Some("turn:turn.example.com:3478".to_string()),
                    relay_protocol: None,
                },
                r#"{"candidate":"candidate:relay123","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":null,"url":"turn:turn.example.com:3478"}"#,
            ),
            (
                RTCIceCandidateInit {
                    candidate: "candidate:relay124".to_string(),
                    sdp_mid: Some("0".to_string()),
                    sdp_mline_index: Some(0),
                    username_fragment: None,
                    url: Some("turns:turn.example.com:5349".to_string()),
                    relay_protocol: Some(RTCIceServerTransportProtocol::Tls),
                },
                r#"{"candidate":"candidate:relay124","sdpMid":"0","sdpMLineIndex":0,"usernameFragment":null,"url":"turns:turn.example.com:5349","relayProtocol":"tls"}"#,
            ),
        ];

        for (candidate_init, expected_string) in tests {
            let result = serde_json::to_string(&candidate_init);
            assert!(result.is_ok(), "testCase: marshal err: {result:?}");
            let candidate_data = result.unwrap();
            assert_eq!(candidate_data, expected_string, "string is not expected");

            let result = serde_json::from_str::<RTCIceCandidateInit>(&candidate_data);
            assert!(result.is_ok(), "testCase: unmarshal err: {result:?}");
            if let Ok(actual_candidate_init) = result {
                assert_eq!(actual_candidate_init, candidate_init);
            }
        }
    }
}

#[cfg(test)]
mod to_json_section_tests {
    use super::*;
    use ice::candidate::{CandidateConfig, candidate_host::CandidateHostConfig};

    /// A candidate built from a bare ICE candidate names the first m-section by index and no
    /// mid: `add_remote_candidate` matches a mid first, and an empty one matches nothing.
    #[test]
    fn to_json_names_the_first_section_by_index() {
        let candidate = CandidateHostConfig {
            base_config: CandidateConfig {
                network: "udp".to_owned(),
                address: "192.0.2.1".to_owned(),
                port: 5000,
                component: 1,
                ..Default::default()
            },
            ..Default::default()
        }
        .new_candidate_host()
        .unwrap();
        let init = RTCIceCandidate::from(&candidate).to_json().unwrap();
        assert_eq!(init.sdp_mid, None);
        assert_eq!(init.sdp_mline_index, Some(0));
    }
}

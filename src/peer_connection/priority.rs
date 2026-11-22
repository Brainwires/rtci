//! WebRTC Priority Control (W3C webrtc-priority) and the DSCP values of RFC 8837: the
//! `RTCPriorityType` of encodings and data channels, and the Differentiated Services codepoint
//! each outgoing datagram is to be marked with.
//!
//! The engine performs no I/O, so it does not mark anything itself:
//! [`RTCPeerConnection::dscp`](crate::peer_connection::RTCPeerConnection::dscp) tells the
//! socket layer which codepoint to set (`IP_TOS` / `IPV6_TCLASS`, the upper six bits) on a
//! datagram `poll_write` returned.

use serde::{Deserialize, Serialize};
use std::fmt;

/// W3C webrtc-priority `RTCPriorityType`: the relative priority of a flow.
#[derive(
    Default, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum RTCPriorityType {
    /// `very-low` (DCEP "below normal", 128).
    #[serde(rename = "very-low")]
    VeryLow,
    /// `low`, the default (DCEP "normal", 256).
    #[default]
    #[serde(rename = "low")]
    Low,
    /// `medium` (DCEP "high", 512).
    #[serde(rename = "medium")]
    Medium,
    /// `high` (DCEP "extra high", 1024).
    #[serde(rename = "high")]
    High,
}

impl RTCPriorityType {
    /// The DCEP priority value of this class (W3C webrtc-priority 4.3; RFC 8832 section 5.1).
    pub fn dcep_priority(self) -> u16 {
        match self {
            Self::VeryLow => 128,
            Self::Low => 256,
            Self::Medium => 512,
            Self::High => 1024,
        }
    }

    /// The class of a DCEP priority value (W3C webrtc-priority 4.3: 0 to 128 is very-low, 129
    /// to 256 low, 257 to 512 medium, above that high).
    pub fn from_dcep_priority(priority: u16) -> Self {
        match priority {
            0..=128 => Self::VeryLow,
            129..=256 => Self::Low,
            257..=512 => Self::Medium,
            _ => Self::High,
        }
    }
}

impl fmt::Display for RTCPriorityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::VeryLow => "very-low",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

/// The flow types of RFC 8837 Table 1.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RTCFlowType {
    /// Audio.
    Audio,
    /// Interactive video, with or without audio: all WebRTC video (RFC 8837 section 5).
    InteractiveVideo,
    /// Non-interactive video: video known not to be interactive (a playback application).
    /// RFC 8837 section 5: "Browsers MUST NOT use the AF3x DSCP values ... Non-browser
    /// implementations of WebRTC MAY use [them]".
    NonInteractiveVideo,
    /// Data channels.
    Data,
}

/// Lower Effort (RFC 8622): DSCP 1. RFC 8837 section 5: used for very-low priority, not CS1.
pub const DSCP_LE: u8 = 1;
/// Default Forwarding: DSCP 0.
pub const DSCP_DF: u8 = 0;
/// Expedited Forwarding: DSCP 46.
pub const DSCP_EF: u8 = 46;

/// RFC 8837 Table 1: the DSCP of a flow of `flow` type at `priority`. Where the table gives two
/// codepoints (video at medium and high priority), the first: the lower drop precedence.
pub fn dscp_for(flow: RTCFlowType, priority: RTCPriorityType) -> u8 {
    match (priority, flow) {
        (RTCPriorityType::VeryLow, _) => DSCP_LE,
        (RTCPriorityType::Low, _) => DSCP_DF,
        (_, RTCFlowType::Audio) => DSCP_EF,
        (RTCPriorityType::Medium, RTCFlowType::InteractiveVideo) => 36, // AF42
        (RTCPriorityType::High, RTCFlowType::InteractiveVideo) => 34,   // AF41
        (RTCPriorityType::Medium, RTCFlowType::NonInteractiveVideo) => 28, // AF32
        (RTCPriorityType::High, RTCFlowType::NonInteractiveVideo) => 26, // AF31
        (RTCPriorityType::Medium, RTCFlowType::Data) => 10,             // AF11
        (RTCPriorityType::High, RTCFlowType::Data) => 18,               // AF21
    }
}

impl crate::peer_connection::RTCPeerConnection {
    /// The DSCP (RFC 8837 Table 1) a datagram [`poll_write`](sansio::Protocol::poll_write)
    /// returned is to be marked with: the socket layer sets it in the upper six bits of
    /// `IP_TOS` / `IPV6_TCLASS`, beside the ECN bits the datagram's transport context gives.
    ///
    /// The flow is told by the datagram (RFC 7983): an RTP packet is its sender's encoding's
    /// (`network_priority`, else `priority`; audio or interactive video), DTLS records carry
    /// the SCTP association, whose data channels share the codepoint of the highest-priority
    /// one (RFC 8837 section 5: "All data channel packets of an SCTP association carry one
    /// DSCP", RECOMMENDED the highest priority's). Over TCP (ICE-TCP, TURN over TCP) every
    /// flow of the connection shares one codepoint, the highest of them (RFC 8837 section 5,
    /// a MUST). STUN, RTCP and what the engine cannot place go with Default Forwarding.
    ///
    /// Video is interactive video unless
    /// [`SettingEngineBuilder::with_non_interactive_video`] says otherwise (the AF3x values
    /// RFC 8837 section 5 lets a non-browser use for playback).
    ///
    /// [`SettingEngineBuilder::with_non_interactive_video`]: crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_non_interactive_video
    pub fn dscp(&self, datagram: &shared::TaggedBytesMut) -> u8 {
        if datagram.transport.transport_protocol == shared::TransportProtocol::TCP {
            return self.highest_dscp();
        }
        let mut bytes: &[u8] = &datagram.message;
        // TURN ChannelData (RFC 8656 section 12.4): the payload follows a four-byte header.
        if bytes.first().is_some_and(|b| (64..=79).contains(b)) && bytes.len() > 4 {
            bytes = &bytes[4..];
        }
        match bytes.first() {
            // RTP or RTCP (RFC 7983); RTCP packet types are 192 to 223 (RFC 5761 section 4).
            Some(128..=191) if bytes.len() >= 12 && !(192..=223).contains(&bytes[1]) => {
                let ssrc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
                self.rtp_dscp(ssrc).unwrap_or(DSCP_DF)
            }
            // DTLS: the SCTP association, under DTLS 1.2 or 1.3 records.
            Some(20..=63) => self.data_dscp().unwrap_or(DSCP_DF),
            _ => DSCP_DF,
        }
    }

    fn video_flow(&self) -> RTCFlowType {
        if self.setting_engine.non_interactive_video {
            RTCFlowType::NonInteractiveVideo
        } else {
            RTCFlowType::InteractiveVideo
        }
    }

    /// The DSCP of the encoding that sends (or repairs) `ssrc`.
    fn rtp_dscp(&self, ssrc: u32) -> Option<u8> {
        use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
        self.rtp_transceivers.iter().find_map(|transceiver| {
            let sender = transceiver.sender().as_ref()?;
            let encoding = sender.send_encodings().iter().find(|encoding| {
                let coding = &encoding.rtp_coding_parameters;
                coding.ssrc == Some(ssrc)
                    || coding.rtx.as_ref().is_some_and(|rtx| rtx.ssrc == ssrc)
                    || coding.fec.as_ref().is_some_and(|fec| fec.ssrc == ssrc)
            })?;
            let flow = if sender.kind() == RtpCodecKind::Audio {
                RTCFlowType::Audio
            } else {
                self.video_flow()
            };
            Some(dscp_for(
                flow,
                encoding.network_priority.unwrap_or(encoding.priority),
            ))
        })
    }

    /// The DSCP of the SCTP association: that of its highest-priority data channel.
    fn data_dscp(&self) -> Option<u8> {
        self.data_channels
            .values()
            .map(|dc| RTCPriorityType::from_dcep_priority(dc.priority))
            .max()
            .map(|priority| dscp_for(RTCFlowType::Data, priority))
    }

    /// The codepoint every flow over one TCP connection shares: the highest-priority flow's.
    fn highest_dscp(&self) -> u8 {
        use crate::rtp_transceiver::rtp_sender::RtpCodecKind;
        let media = self
            .rtp_transceivers
            .iter()
            .filter_map(|t| t.sender().as_ref())
            .flat_map(|sender| {
                let flow = if sender.kind() == RtpCodecKind::Audio {
                    RTCFlowType::Audio
                } else {
                    self.video_flow()
                };
                sender
                    .send_encodings()
                    .iter()
                    .map(move |e| (e.network_priority.unwrap_or(e.priority), flow))
                    .collect::<Vec<_>>()
            });
        let data = self.data_channels.values().map(|dc| {
            (
                RTCPriorityType::from_dcep_priority(dc.priority),
                RTCFlowType::Data,
            )
        });
        media
            .chain(data)
            .max_by_key(|(priority, flow)| (*priority, *flow == RTCFlowType::Audio))
            .map_or(DSCP_DF, |(priority, flow)| dscp_for(flow, priority))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8837 Table 1, cell by cell; LE, not CS1, for very-low.
    #[test]
    fn dscp_values_follow_rfc_8837_table_1() {
        use RTCFlowType::*;
        use RTCPriorityType::*;
        let rows = [
            (Audio, [1, 0, 46, 46]),
            (InteractiveVideo, [1, 0, 36, 34]),
            (NonInteractiveVideo, [1, 0, 28, 26]),
            (Data, [1, 0, 10, 18]),
        ];
        for (flow, values) in rows {
            for (priority, value) in [VeryLow, Low, Medium, High].into_iter().zip(values) {
                assert_eq!(dscp_for(flow, priority), value, "{flow:?} {priority}");
            }
        }
    }

    /// W3C webrtc-priority 4.3: the DCEP integer of each class, and the class of any integer.
    #[test]
    fn priority_classes_map_to_and_from_dcep_values() {
        use RTCPriorityType::*;
        for class in [VeryLow, Low, Medium, High] {
            assert_eq!(
                RTCPriorityType::from_dcep_priority(class.dcep_priority()),
                class
            );
        }
        for (value, class) in [
            (0, VeryLow),
            (128, VeryLow),
            (129, Low),
            (256, Low),
            (257, Medium),
            (512, Medium),
            (513, High),
            (u16::MAX, High),
        ] {
            assert_eq!(RTCPriorityType::from_dcep_priority(value), class, "{value}");
        }
        assert_eq!(RTCPriorityType::default(), Low);
    }
}

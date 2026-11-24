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
    /// implementations of WebRTC MAY use \[them\]".
    NonInteractiveVideo,
    /// Data channels.
    Data,
}

/// How a connection marks its datagrams
/// ([`SettingEngineBuilder::with_dscp_marking`](crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_dscp_marking)).
#[derive(Default, Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RTCDscpMarking {
    /// RFC 8837 Table 1, and a media flow whose marked packets do not get through goes back to
    /// Default Forwarding (RFC 8835 section 4.2 MAY): a flow that was sent with a codepoint
    /// other than DF and that the peer never reported on in its receiver reports on that
    /// transport ([`DSCP_BLOCKED_REPORTS`] of them, at least [`DSCP_BLOCKED_AFTER`] after the
    /// flow began) is marked DSCP 0 from then on, its retransmission and FEC streams with it.
    /// The other flows keep their codepoints ("Other flows on the same transport, using
    /// different DSCPs, don't need to change"). Only the start of a flow is watched: a flow
    /// reported on once is not watched again (later failures are the transport's, RFC 8835
    /// section 4.2). The default.
    #[default]
    Rfc8837,
    /// RFC 8837 Table 1, never turned back.
    WithoutFallback,
    /// Nothing is marked: DSCP 0 (Default Forwarding) for every datagram and connection.
    Off,
}

/// How long a marked media flow is sent before the DSCP fallback may judge it blocked.
pub const DSCP_BLOCKED_AFTER: std::time::Duration = std::time::Duration::from_secs(2);

/// How many sender or receiver reports from the peer, on the flow's transport and none about
/// the flow, judge it blocked (the first may have been sent before the flow's first packet
/// arrived).
pub const DSCP_BLOCKED_REPORTS: u64 = 3;

/// The DSCP fallback's state (RFC 8835 section 4.2).
#[derive(Debug, Default)]
pub(crate) struct DscpFallback {
    /// Marked flows not yet reported on, by SSRC: when they were first seen sent, and the
    /// transport's report count then.
    watched: std::collections::HashMap<u32, (std::time::Instant, u64)>,
    /// Flows reported on: never watched again.
    delivered: std::collections::HashSet<u32>,
    /// Flows turned back to Default Forwarding, by their encoding's SSRC.
    blocked: std::collections::HashSet<u32>,
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

/// The share of a flow at `priority` against the other flows under the same congestion
/// control (RFC 8835 section 4.1, W3C webrtc-priority 3.2): each level gets "approximately
/// twice the transmission capacity" of the level below, so very-low : low : medium : high
/// is 1 : 2 : 4 : 8.
pub fn bandwidth_weight(priority: RTCPriorityType) -> f64 {
    match priority {
        RTCPriorityType::VeryLow => 1.0,
        RTCPriorityType::Low => 2.0,
        RTCPriorityType::Medium => 4.0,
        RTCPriorityType::High => 8.0,
    }
}

/// Divides `total` bits per second among flows by their weights (`bandwidth_weight`), none
/// above its cap (an encoding's `maxBitrate`): a capped flow gets its cap, and what it leaves
/// goes to the others in proportion to their weights (weighted max-min fairness). Returns
/// one share per flow, in order; with every flow capped below its share, the rest of
/// `total` is left unallocated.
pub fn allocate_bandwidth(total: f64, flows: &[(f64, Option<f64>)]) -> Vec<f64> {
    let mut shares = vec![0.0; flows.len()];
    let mut open: Vec<usize> = (0..flows.len()).filter(|&i| flows[i].0 > 0.0).collect();
    let mut remaining = total.max(0.0);
    while !open.is_empty() {
        let weights: f64 = open.iter().map(|&i| flows[i].0).sum();
        let capped: Vec<usize> = open
            .iter()
            .copied()
            .filter(|&i| {
                flows[i]
                    .1
                    .is_some_and(|cap| cap <= remaining * flows[i].0 / weights)
            })
            .collect();
        if capped.is_empty() {
            for &i in &open {
                shares[i] = remaining * flows[i].0 / weights;
            }
            break;
        }
        for &i in &capped {
            let cap = flows[i].1.unwrap_or_default().max(0.0);
            shares[i] = cap;
            remaining -= cap;
        }
        open.retain(|i| !capped.contains(i));
    }
    shares
}

/// Divides the congestion controller's target among the encodings the connection sends
/// (W3C webrtc-priority 3.2: "the priority ... influences the bandwidth allocation among
/// RTCRtpSenders"; webrtc 5.2.5 `maxBitrate` caps an encoding): every active encoding with
/// an SSRC of a transceiver that is not stopped and has a sending direction takes a share by
/// its `priority` (`bandwidth_weight`), capped at its `maxBitrate`. Each sender keeps its
/// encodings' shares (`RTCRtpSender::target_bitrates`); returns them by SSRC.
#[cfg(test)]
pub(crate) fn allocate_target_bitrate(
    transceivers: &mut [crate::rtp_transceiver::internal::RTCRtpTransceiverInternal],
    total: f64,
) -> std::collections::HashMap<u32, f64> {
    allocate_target_bitrate_on(
        transceivers,
        total,
        |_| true,
        &std::collections::BTreeSet::new(),
    )
}

/// [`allocate_target_bitrate`] among the encodings of the m= sections `on_transport` accepts
/// (by MID): one transport's congestion controller's target is divided among the senders that
/// transport carries (RFC 8836 section 2: each path has its own capacity).
///
/// An encoding whose media SSRC is in `ceased` takes no share: the RTP circuit breaker
/// stopped it (RFC 8083 section 4.5), nothing of it leaves, and what it would have had goes to
/// the encodings that still send. It has its share again when it is restarted.
pub(crate) fn allocate_target_bitrate_on(
    transceivers: &mut [crate::rtp_transceiver::internal::RTCRtpTransceiverInternal],
    total: f64,
    on_transport: impl Fn(&str) -> bool,
    ceased: &std::collections::BTreeSet<u32>,
) -> std::collections::HashMap<u32, f64> {
    let mut flows = Vec::new();
    let mut owners = Vec::new();
    for (index, transceiver) in transceivers.iter().enumerate() {
        if !on_transport(transceiver.mid().as_deref().unwrap_or_default()) {
            continue;
        }
        if transceiver.stopped() || !transceiver.direction().has_send() {
            continue;
        }
        let Some(sender) = transceiver.sender() else {
            continue;
        };
        for encoding in sender.send_encodings() {
            let Some(ssrc) = encoding.rtp_coding_parameters.ssrc else {
                continue;
            };
            if !encoding.active || ceased.contains(&ssrc) {
                continue;
            }
            flows.push((
                bandwidth_weight(encoding.priority),
                (encoding.max_bitrate > 0).then_some(f64::from(encoding.max_bitrate)),
            ));
            owners.push((index, ssrc));
        }
    }
    let shares = allocate_bandwidth(total, &flows);
    let mut by_ssrc = std::collections::HashMap::new();
    for transceiver in transceivers.iter_mut() {
        if let Some(sender) = transceiver.sender_mut() {
            sender.set_allocated_bitrates(vec![]);
        }
    }
    for ((index, ssrc), share) in owners.into_iter().zip(shares) {
        by_ssrc.insert(ssrc, share);
        if let Some(sender) = transceivers[index].sender_mut() {
            let mut current = sender.allocated_bitrates().to_vec();
            current.push((ssrc, share));
            sender.set_allocated_bitrates(current);
        }
    }
    by_ssrc
}

impl crate::peer_connection::RTCPeerConnection {
    /// Divides the congestion controller's last target among the encodings again
    /// (`allocate_target_bitrate`), after a change of their parameters. Nothing before the
    /// first target.
    pub(crate) fn reallocate_target_bitrate(&mut self) {
        let targets = self
            .pipeline_context
            .interceptor_handler_context
            .transport_targets
            .clone();
        let ceased = self
            .pipeline_context
            .interceptor_handler_context
            .ceased_flows
            .clone();
        for (key, total) in targets {
            let stats = &self.pipeline_context.stats;
            let shares = allocate_target_bitrate_on(
                &mut self.rtp_transceivers,
                total,
                |mid| stats.section_transport_key(mid) == key,
                &ceased,
            );
            self.pipeline_context
                .stats
                .on_target_bitrate(key, total, &shares);
        }
    }

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
    /// Under [`RTCDscpMarking::Rfc8837`] (the default) a media flow whose marked packets the
    /// network blocks goes back to DSCP 0 ([`dscp_blocked_flows`](Self::dscp_blocked_flows));
    /// under [`RTCDscpMarking::Off`] every datagram is DSCP 0
    /// ([`SettingEngineBuilder::with_dscp_marking`]).
    ///
    /// [`SettingEngineBuilder::with_non_interactive_video`]: crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_non_interactive_video
    /// [`SettingEngineBuilder::with_dscp_marking`]: crate::peer_connection::configuration::setting_engine::SettingEngineBuilder::with_dscp_marking
    pub fn dscp(&self, datagram: &shared::TaggedBytesMut) -> u8 {
        if self.setting_engine.dscp_marking == RTCDscpMarking::Off {
            return DSCP_DF;
        }
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

    /// The whole IPv4 TOS / IPv6 Traffic Class byte to send `datagram` with: its
    /// [`dscp`](Self::dscp) in the upper six bits (RFC 2474 section 3) and the ECN codepoint
    /// of its transport context in the lower two (RFC 3168 section 5). What a driver sets with
    /// `IP_TOS` / `IPV6_TCLASS` on the socket before sending the datagram.
    pub fn traffic_class(&self, datagram: &shared::TaggedBytesMut) -> u8 {
        (self.dscp(datagram) << 2) | datagram.transport.ecn.map_or(0, |ecn| ecn as u8)
    }

    fn video_flow(&self) -> RTCFlowType {
        if self.setting_engine.non_interactive_video {
            RTCFlowType::NonInteractiveVideo
        } else {
            RTCFlowType::InteractiveVideo
        }
    }

    /// The SSRCs whose media flows the DSCP fallback turned back to Default Forwarding
    /// (RFC 8835 section 4.2; [`RTCDscpMarking::Rfc8837`]): each the SSRC of an encoding whose
    /// marked packets the peer never reported receiving. Its retransmission and FEC streams
    /// are unmarked with it.
    pub fn dscp_blocked_flows(&self) -> Vec<u32> {
        let mut ssrcs: Vec<u32> = self.dscp_fallback.blocked.iter().copied().collect();
        ssrcs.sort_unstable();
        ssrcs
    }

    /// The DSCP of the encoding that sends (or repairs) `ssrc`: its RFC 8837 codepoint, or DF
    /// once the fallback turned the flow back.
    fn rtp_dscp(&self, ssrc: u32) -> Option<u8> {
        let (primary, dscp) = self.flow_dscp(ssrc)?;
        Some(if self.dscp_fallback.blocked.contains(&primary) {
            DSCP_DF
        } else {
            dscp
        })
    }

    /// The SSRC of the encoding that sends (or repairs) `ssrc`, and its RFC 8837 codepoint.
    fn flow_dscp(&self, ssrc: u32) -> Option<(u32, u8)> {
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
            Some((
                coding_ssrc(encoding).unwrap_or(ssrc),
                dscp_for(flow, encoding.network_priority.unwrap_or(encoding.priority)),
            ))
        })
    }

    /// RFC 8835 section 4.2: "The implementation MAY turn off use of DSCP markings if it
    /// detects symptoms of unexpected behavior such as ... blocking of packets with certain
    /// DSCP markings." Under [`RTCDscpMarking::Rfc8837`], each media flow sent with a
    /// codepoint other than DF is watched from its first packet until the peer reports on it
    /// (a report block about its SSRC, RFC 3550 6.4); a flow the peer's sender and receiver
    /// reports on its transport keep leaving out ([`DSCP_BLOCKED_REPORTS`] of them, at least
    /// [`DSCP_BLOCKED_AFTER`] after the flow began) is blocked by its marking, and goes with
    /// DSCP 0 from then on, the whole flow (its retransmission and FEC streams too: "one has
    /// to switch the whole media flow to DSCP 0, since all traffic for a single media flow
    /// needs to be on the same queue").
    pub(crate) fn detect_blocked_dscp(&mut self, now: std::time::Instant) {
        if self.setting_engine.dscp_marking != RTCDscpMarking::Rfc8837 {
            return;
        }
        let mut flows = Vec::new();
        for transceiver in &self.rtp_transceivers {
            let Some(sender) = transceiver.sender().as_ref() else {
                continue;
            };
            let mid = transceiver.mid().clone().unwrap_or_default();
            for encoding in sender.send_encodings() {
                if let Some(ssrc) = coding_ssrc(encoding) {
                    flows.push((ssrc, mid.clone()));
                }
            }
        }
        for (ssrc, mid) in flows {
            let fallback = &self.dscp_fallback;
            if fallback.blocked.contains(&ssrc) || fallback.delivered.contains(&ssrc) {
                continue;
            }
            if self.flow_dscp(ssrc).is_none_or(|(_, dscp)| dscp == DSCP_DF) {
                self.dscp_fallback.watched.remove(&ssrc);
                continue;
            }
            let stats = &self.pipeline_context.stats;
            let Some(stream) = stats.outbound_rtp_streams.get(&ssrc) else {
                continue;
            };
            if stream.packets_sent == 0 {
                continue;
            }
            if stream.remote_reports_received > 0 {
                self.dscp_fallback.watched.remove(&ssrc);
                self.dscp_fallback.delivered.insert(ssrc);
                continue;
            }
            let reports = stats
                .reception_report_packets
                .get(&stats.section_transport_key(&mid))
                .copied()
                .unwrap_or(0);
            let (since, at) = *self
                .dscp_fallback
                .watched
                .entry(ssrc)
                .or_insert((now, reports));
            if now >= since + DSCP_BLOCKED_AFTER && reports >= at + DSCP_BLOCKED_REPORTS {
                log::warn!(
                    "RFC 8835 4.2: the peer reported none of SSRC {ssrc}'s marked packets in {} reports; the flow goes with DSCP 0",
                    reports - at
                );
                self.dscp_fallback.watched.remove(&ssrc);
                self.dscp_fallback.blocked.insert(ssrc);
            }
        }
    }

    /// The codepoint of the connection's stream transmits: every TCP connection carries one
    /// (RFC 8837 section 5 MUST), the highest-priority flow's.
    pub(crate) fn stream_dscp(&self) -> u8 {
        if self.setting_engine.dscp_marking == RTCDscpMarking::Off {
            DSCP_DF
        } else {
            self.highest_dscp()
        }
    }

    /// The DSCP of the SCTP association: that of its highest-priority data channel.
    fn data_dscp(&self) -> Option<u8> {
        if self.setting_engine.dscp_marking == RTCDscpMarking::Off {
            return None;
        }
        self.data_channels
            .values()
            .map(|dc| RTCPriorityType::from_dcep_priority(dc.priority))
            .max()
            .map(|priority| dscp_for(RTCFlowType::Data, priority))
    }

    /// RFC 8837 section 5: "if the DSCP of an SCTP association is changed, the congestion
    /// controller MUST be reset" (an association whose packets carry another codepoint may
    /// take another queue, another path in effect). The data channels' codepoint
    /// ([`Self::data_dscp`]) is compared with the one last seen; when it changed, each live
    /// association's congestion control and RTO start over, as on a path change (RFC 9260
    /// section 7.2.5).
    pub(crate) fn restart_sctp_congestion_control_on_dscp_change(
        &mut self,
        now: std::time::Instant,
    ) {
        let dscp = self.data_dscp();
        let previous = std::mem::replace(&mut self.last_data_dscp, dscp);
        if previous.is_none() || previous == dscp {
            return;
        }
        for association in self.sctp_transport_mut().sctp_associations.values_mut() {
            if !association.is_ended() {
                association.on_path_change(now);
            }
        }
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

/// The SSRC of an encoding's media.
fn coding_ssrc(
    encoding: &crate::rtp_transceiver::rtp_sender::RTCRtpEncodingParameters,
) -> Option<u32> {
    encoding.rtp_coding_parameters.ssrc
}

#[cfg(test)]
mod tests {
    use super::{allocate_bandwidth, bandwidth_weight};

    /// RFC 8835 4.1: each level twice the one below; high gets eight times very-low.
    #[test]
    fn each_priority_level_gets_twice_the_share_of_the_level_below() {
        let flows: Vec<(f64, Option<f64>)> = [
            RTCPriorityType::VeryLow,
            RTCPriorityType::Low,
            RTCPriorityType::Medium,
            RTCPriorityType::High,
        ]
        .into_iter()
        .map(|p| (bandwidth_weight(p), None))
        .collect();
        let shares = allocate_bandwidth(1_500_000.0, &flows);
        assert_eq!(shares, vec![100_000.0, 200_000.0, 400_000.0, 800_000.0]);
    }

    /// W3C webrtc 5.2.5 maxBitrate: a flow never gets more than its cap; what it leaves is
    /// shared among the others by weight; all capped leaves the rest unallocated.
    #[test]
    fn a_capped_flow_gets_its_cap_and_the_rest_goes_to_the_others() {
        let shares = allocate_bandwidth(
            1_000_000.0,
            &[(8.0, Some(100_000.0)), (2.0, None), (2.0, None)],
        );
        assert_eq!(shares, vec![100_000.0, 450_000.0, 450_000.0]);
        let shares = allocate_bandwidth(
            1_000_000.0,
            &[(2.0, Some(300_000.0)), (2.0, Some(200_000.0))],
        );
        assert_eq!(shares, vec![300_000.0, 200_000.0]);
        // A cap above the fair share does not bind.
        let shares = allocate_bandwidth(600_000.0, &[(2.0, Some(500_000.0)), (2.0, None)]);
        assert_eq!(shares, vec![300_000.0, 300_000.0]);
        assert!(allocate_bandwidth(1.0, &[]).is_empty());
    }

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

    /// W3C webrtc-priority 3.2 and webrtc 5.2.5, through the senders: the connection's target
    /// is divided among the sending encodings by priority, each capped at its maxBitrate; a
    /// setParameters that changes a priority or a maxBitrate divides it again; a recvonly
    /// transceiver's sender gets nothing.
    #[test]
    fn the_target_is_divided_among_the_senders_by_priority_and_max_bitrate() {
        use crate::peer_connection::RTCPeerConnectionBuilder;
        use crate::peer_connection::configuration::media_engine::MediaEngine;
        use crate::rtp_transceiver::rtp_sender::{RTCRtpEncodingParameters, RtpCodecKind};
        use crate::rtp_transceiver::{
            RTCRtpSenderId, RTCRtpTransceiverDirection, RTCRtpTransceiverInit,
        };
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs().unwrap();
        let mut pc = RTCPeerConnectionBuilder::new()
            .with_media_engine(media_engine)
            .build(std::time::Instant::now())
            .unwrap();
        let add = |pc: &mut crate::peer_connection::RTCPeerConnection,
                   priority: RTCPriorityType,
                   direction: RTCRtpTransceiverDirection| {
            RTCRtpSenderId::from(
                pc.add_transceiver_from_kind(
                    RtpCodecKind::Video,
                    Some(RTCRtpTransceiverInit {
                        direction,
                        streams: vec![],
                        send_encodings: vec![RTCRtpEncodingParameters {
                            active: true,
                            priority,
                            ..Default::default()
                        }],
                    }),
                )
                .unwrap(),
            )
        };
        let high = add(
            &mut pc,
            RTCPriorityType::High,
            RTCRtpTransceiverDirection::Sendonly,
        );
        let low = add(
            &mut pc,
            RTCPriorityType::Low,
            RTCRtpTransceiverDirection::Sendonly,
        );
        let receiving = add(
            &mut pc,
            RTCPriorityType::High,
            RTCRtpTransceiverDirection::Recvonly,
        );
        let shares = |pc: &mut crate::peer_connection::RTCPeerConnection, id| {
            pc.rtp_sender(id)
                .unwrap()
                .target_bitrates()
                .iter()
                .map(|&(_, bps)| bps)
                .collect::<Vec<f64>>()
        };
        assert!(shares(&mut pc, high).is_empty(), "no target yet");

        pc.pipeline_context
            .interceptor_handler_context
            .transport_targets
            .insert(0, 1_000_000.0);
        pc.reallocate_target_bitrate();
        assert_eq!(shares(&mut pc, high), vec![800_000.0], "8 : 2");
        assert_eq!(shares(&mut pc, low), vec![200_000.0]);
        assert!(
            shares(&mut pc, receiving).is_empty(),
            "a recvonly transceiver sends nothing"
        );

        // maxBitrate on the high one: capped, the rest to the other.
        let mut sender = pc.rtp_sender(high).unwrap();
        let mut parameters = sender.get_parameters().clone();
        parameters.encodings[0].max_bitrate = 300_000;
        sender.set_parameters(parameters, None).unwrap();
        assert_eq!(shares(&mut pc, high), vec![300_000.0]);
        assert_eq!(shares(&mut pc, low), vec![700_000.0]);

        // The low one raised to high and capped too: both at their caps.
        let mut sender = pc.rtp_sender(low).unwrap();
        let mut parameters = sender.get_parameters().clone();
        parameters.encodings[0].priority = RTCPriorityType::High;
        parameters.encodings[0].max_bitrate = 100_000;
        sender.set_parameters(parameters, None).unwrap();
        assert_eq!(shares(&mut pc, high), vec![300_000.0]);
        assert_eq!(shares(&mut pc, low), vec![100_000.0]);
    }
}

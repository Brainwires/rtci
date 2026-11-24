//! NACK interceptors (internal module).
//!
//! `NackGeneratorInterceptor` and `NackResponderInterceptor` are re-exported from the crate
//! root, where the user-facing documentation and examples live so that rustdoc renders them.
//!
//! # References
//!
//! - [RFC 4585](https://datatracker.ietf.org/doc/html/rfc4585) - RTP/AVPF (NACK feedback)
//! - [RFC 4588](https://datatracker.ietf.org/doc/html/rfc4588) - RTP Retransmission (RTX)
pub(crate) mod generator;
pub(crate) mod receive_log;
pub(crate) mod responder;
pub(crate) mod send_buffer;

use crate::stream_info::StreamInfo;
use crate::{Attribute, AttributedPacket, Packet, TaggedPacket};
use shared::TransportContext;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// What a session description negotiated for retransmission (RFC 4588), told to the NACK
/// interceptors while they run.
///
/// It travels as an [`Attribute::Custom`] on an empty RTCP packet written into the chain
/// ([`NackControl::into_packet`]). Each NACK interceptor reads what is its own and hands the
/// packet on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NackControl {
    /// The `rtx-time` (RFC 4588 8.1) this endpoint announced for its retransmission format
    /// `payload_type_rtx`: how long the [`NackResponderInterceptor`](crate::NackResponderInterceptor)
    /// keeps a sent packet of a stream repaired under that payload type available. It replaces
    /// the builder's `with_max_packet_age` for those streams; `None` returns them to it.
    LocalRtxTime {
        /// The payload type of the retransmission format.
        payload_type_rtx: u8,
        /// The announced `rtx-time`.
        rtx_time: Option<Duration>,
    },
    /// The `rtx-time` the remote endpoint announced for its retransmission format
    /// `payload_type_rtx`: past it the remote sender no longer has the packet, so the
    /// [`NackGeneratorInterceptor`](crate::NackGeneratorInterceptor) stops asking for a packet
    /// of a stream repaired under that payload type that has been missing for longer, or for
    /// longer than the builder's `with_max_packet_age`, whichever is shorter. `None` leaves
    /// the builder's value alone.
    RemoteRtxTime {
        /// The payload type of the retransmission format.
        payload_type_rtx: u8,
        /// The announced `rtx-time`.
        rtx_time: Option<Duration>,
    },
    /// The oldest sequence number of the remote stream `media_ssrc` that the receiving
    /// application can still use (RFC 4588 6.3: "the receiver should generally assess whether
    /// the retransmitted packet would still be useful at the time it is received"): its video
    /// pipeline released or gave up every frame before it. The
    /// [`NackGeneratorInterceptor`](crate::NackGeneratorInterceptor) asks for no missing packet
    /// older than `oldest_useful` from then on, and forgets the requests it had for them.
    /// `None` removes the horizon. Sequence numbers compare with wrap-around (RFC 3550 A.1):
    /// a packet up to 32767 behind the horizon is older; the application moves the horizon
    /// on as it plays out, so it never lags that far.
    Horizon {
        /// The SSRC of the remote stream.
        media_ssrc: u32,
        /// The oldest sequence number still useful.
        oldest_useful: Option<u16>,
    },
}

impl NackControl {
    /// The packet that carries this to the NACK interceptors when written into the chain at
    /// `now`.
    pub fn into_packet(self, now: Instant) -> TaggedPacket {
        TaggedPacket {
            now,
            transport: TransportContext::default(),
            message: AttributedPacket::new(Packet::Rtcp(vec![]))
                .with(Attribute::Custom(Arc::new(self))),
        }
    }
}

/// Check if a stream supports NACK feedback.
///
/// Returns `true` if the stream has an RTCPFeedback entry with `type: "nack"`
/// and empty `parameter`.
pub(crate) fn stream_supports_nack(info: &StreamInfo) -> bool {
    info.rtcp_feedback
        .iter()
        .any(|fb| fb.typ == "nack" && fb.parameter.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::RTCPFeedback;

    #[test]
    fn test_stream_supports_nack() {
        // Stream with nack support
        let info_with_nack = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        assert!(stream_supports_nack(&info_with_nack));

        // Stream with nack-pli (not generic nack)
        let info_with_nack_pli = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "nack".to_string(),
                parameter: "pli".to_string(),
            }],
            ..Default::default()
        };
        assert!(!stream_supports_nack(&info_with_nack_pli));

        // Stream without nack
        let info_without_nack = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![RTCPFeedback {
                typ: "goog-remb".to_string(),
                parameter: "".to_string(),
            }],
            ..Default::default()
        };
        assert!(!stream_supports_nack(&info_without_nack));

        // Stream with no feedback
        let info_no_feedback = StreamInfo {
            ssrc: 12345,
            rtcp_feedback: vec![],
            ..Default::default()
        };
        assert!(!stream_supports_nack(&info_no_feedback));
    }
}

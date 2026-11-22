//! Which congestion control feedback one stream runs on.

use crate::rfc8888::sender::stream_supports_ccfb;
use crate::stream_info::StreamInfo;
use crate::twcc::stream_supports_twcc;

/// The per-packet feedback format a stream's arrivals are reported in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CongestionFeedbackFormat {
    /// RTCP congestion control feedback, RFC 8888 (`a=rtcp-fb:<pt> ack ccfb`).
    Rfc8888,
    /// Transport-wide congestion control, draft-holmer-rmcat-transport-wide-cc-extensions-01
    /// (`a=rtcp-fb:<pt> transport-cc` and its header extension).
    TransportCc,
}

/// The one feedback format a stream uses, from what was negotiated for it.
///
/// An offer may name several congestion control feedback mechanisms "that offer substantially
/// the same semantics" (RFC 8888 section 6), and the answer SHOULD keep one. Whatever the answer
/// kept, a stream is reported in exactly one format, or the sender's estimator counts every
/// packet twice: RFC 8888 when `ack ccfb` is among the stream's negotiated feedback, otherwise
/// transport-wide congestion control when its header extension was negotiated, otherwise
/// none. Every interceptor that numbers, records or reads per-packet feedback decides with this
/// function, so both directions of both endpoints agree.
pub fn negotiated_congestion_feedback(info: &StreamInfo) -> Option<CongestionFeedbackFormat> {
    if stream_supports_ccfb(info) {
        Some(CongestionFeedbackFormat::Rfc8888)
    } else if stream_supports_twcc(info).is_some_and(|id| id != 0) {
        Some(CongestionFeedbackFormat::TransportCc)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_info::{RTCPFeedback, RTPHeaderExtension};

    fn info(twcc: bool, ccfb: bool) -> StreamInfo {
        StreamInfo {
            ssrc: 1,
            rtp_header_extensions: if twcc {
                vec![RTPHeaderExtension {
                    uri: crate::twcc::TRANSPORT_CC_URI.to_string(),
                    id: 5,
                }]
            } else {
                vec![]
            },
            rtcp_feedback: if ccfb {
                vec![RTCPFeedback {
                    typ: "ack".to_owned(),
                    parameter: "ccfb".to_owned(),
                }]
            } else {
                vec![]
            },
            ..Default::default()
        }
    }

    #[test]
    fn rfc8888_is_used_when_the_peer_accepted_it_and_transport_cc_otherwise() {
        assert_eq!(
            Some(CongestionFeedbackFormat::Rfc8888),
            negotiated_congestion_feedback(&info(true, true)),
            "both negotiated: RFC 8888, and only it"
        );
        assert_eq!(
            Some(CongestionFeedbackFormat::Rfc8888),
            negotiated_congestion_feedback(&info(false, true))
        );
        assert_eq!(
            Some(CongestionFeedbackFormat::TransportCc),
            negotiated_congestion_feedback(&info(true, false))
        );
        assert_eq!(None, negotiated_congestion_feedback(&info(false, false)));
    }
}

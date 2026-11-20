//! Only FlexFEC draft-03 is implemented, so only `video/flexfec-03` selects it. RFC 8627's
//! `video/flexfec` is a different wire format and must never reach the draft-03 coder.

use super::*;

fn codec(payload_type: PayloadType, mime_type: &str) -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: mime_type.to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type,
    }
}

#[test]
fn rfc_8627_flexfec_is_not_the_draft_03_coder() {
    assert_eq!(
        None,
        find_fec_payload_type(&[codec(96, "video/VP8"), codec(110, "video/flexfec")])
    );
}

#[test]
fn draft_03_is_found_whatever_its_case() {
    assert_eq!(
        Some(111),
        find_fec_payload_type(&[codec(110, "video/flexfec"), codec(111, "video/FlexFEC-03"),])
    );
}

#[test]
fn the_mime_type_match_is_exact() {
    assert!(is_flexfec03_mime_type("video/flexfec-03"));
    assert!(!is_flexfec03_mime_type("video/flexfec"));
    assert!(!is_flexfec03_mime_type("video/flexfec-030"));
    assert!(!is_flexfec03_mime_type("audio/flexfec-03"));
}

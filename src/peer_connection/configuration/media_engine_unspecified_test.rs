//! A remote codec of an unspecified kind is an error to match, not a panic.

use super::*;

#[test]
fn matching_a_codec_of_an_unspecified_kind_is_an_error() {
    let media_engine = MediaEngine::default();
    let remote = RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "video/VP8".to_owned(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: String::new(),
            rtcp_feedback: vec![],
        },
        payload_type: 96,
    };

    assert!(matches!(
        media_engine.match_remote_codec(&remote, RtpCodecKind::Unspecified, &[], &[]),
        Err(Error::ErrCodecNotFound)
    ));
}

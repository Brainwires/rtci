//! RFC 6184 6.2 / 8.1: the H.264 payloader follows the negotiated `packetization-mode`.

use super::*;
use bytes::Bytes;

fn h264(fmtp: &str) -> RTCRtpCodec {
    RTCRtpCodec {
        mime_type: MIME_TYPE_H264.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    }
}

#[test]
fn the_mode_is_read_from_the_fmtp_line() {
    assert_eq!(
        1,
        h264_packetization_mode(
            "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
        )
    );
    assert_eq!(0, h264_packetization_mode("packetization-mode=0"));
    assert_eq!(1, h264_packetization_mode(" Packetization-Mode = 1 "));
    assert_eq!(
        0,
        h264_packetization_mode("profile-level-id=42e01f"),
        "absent means 0"
    );
    assert_eq!(0, h264_packetization_mode(""));
}

#[test]
fn a_mode_0_codec_never_fragments() {
    let mut nalu = vec![0, 0, 0, 1, 0x65];
    nalu.extend(std::iter::repeat_n(0xAB, 3000));
    let frame = Bytes::from(nalu);

    let mut mode_0 = h264("packetization-mode=0").payloader().unwrap();
    assert!(mode_0.payload(1200, &frame).is_err());

    let mut mode_1 = h264("packetization-mode=1").payloader().unwrap();
    assert!(mode_1.payload(1200, &frame).unwrap().len() > 1);
}

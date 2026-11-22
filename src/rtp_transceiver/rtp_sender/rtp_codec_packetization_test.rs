//! RFC 6184 6.2 / 8.1: the H.264 payloader follows the negotiated `packetization-mode`.

use super::*;
use bytes::Bytes;
use rtp::packetizer::Depacketizer;

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

/// RFC 6184 section 8.1: "packetization-mode ... MUST be equal to 0, 1, or 2": a codec with
/// another value has no payloader (it was taken as mode 1); mode 2 is the interleaved mode
/// (section 6.4), whose packets are STAP-B and FU-B / FU-A only.
#[test]
fn a_mode_2_codec_interleaves_and_a_mode_above_2_has_no_payloader() {
    assert!(h264("packetization-mode=3").payloader().is_err());
    assert!(h264("packetization-mode=300").payloader().is_err());
    assert!(h264("packetization-mode=3").h264_depacketizer().is_err());

    let frame = Bytes::from_static(&[0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x65, 0x88]);
    let payloads = h264("packetization-mode=2")
        .payloader()
        .unwrap()
        .payload(1200, &frame)
        .unwrap();
    assert!(!payloads.is_empty());
    for payload in payloads {
        assert!([25, 28, 29].contains(&(payload[0] & 0x1F)), "{payload:?}");
    }
}

/// RFC 6184 section 7.2.2: a receiver of an interleaved stream passes NAL units on in
/// decoding order; the depacketizer of a mode 2 codec buffers `sprop-interleaving-depth` + 1
/// VCL NAL units and puts them in DON order.
#[test]
fn a_mode_2_codecs_depacketizer_puts_nal_units_in_decoding_order() {
    let slice = |tag: u8| Bytes::from(vec![0x41, tag]);
    let later = rtp::codec::h264::stap_b(1, &[slice(0xB1)]).unwrap();
    let first = rtp::codec::h264::stap_b(0, &[slice(0xA0)]).unwrap();

    let mut depacketizer = h264("packetization-mode=2;sprop-interleaving-depth=1")
        .h264_depacketizer()
        .unwrap();
    assert!(depacketizer.depacketize(&later).unwrap().is_empty());
    assert_eq!(
        &[0, 0, 0, 1, 0x41, 0xA0][..],
        &depacketizer.depacketize(&first).unwrap()[..]
    );
    assert_eq!(
        &[0, 0, 0, 1, 0x41, 0xB1][..],
        &depacketizer.flush_deinterleaving()[..]
    );
}

/// RFC 7798 section 7.1: `sprop-max-don-diff` above 0 means the NAL units carry DONL; the
/// depacketizer of such a codec reads it (one without would take the DONL for payload), and
/// a `tx-mode` other than SRST is refused.
#[test]
fn an_h265_codecs_depacketizer_reads_donl_when_the_sender_says_so() {
    let codec = |fmtp: &str| RTCRtpCodec {
        mime_type: MIME_TYPE_HEVC.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: fmtp.to_owned(),
        rtcp_feedback: vec![],
    };
    // A single NAL unit packet: header (type 1), DONL 0, two payload bytes.
    let packet = Bytes::from_static(&[0x02, 0x01, 0x00, 0x00, 0xAA, 0xBB]);
    let mut without_donl = codec("sprop-max-don-diff=0").h265_depacketizer().unwrap();
    assert_eq!(
        &[0, 0, 0, 1, 0x02, 0x01, 0x00, 0x00, 0xAA, 0xBB][..],
        &without_donl.depacketize(&packet).unwrap()[..],
        "no DONL without sprop-max-don-diff"
    );
    let mut with_donl = codec("sprop-max-don-diff=1;sprop-depack-buf-nalus=0")
        .h265_depacketizer()
        .unwrap();
    let out = with_donl.depacketize(&packet).unwrap();
    let out = [out, with_donl.flush_depacketization_buffer()].concat();
    assert_eq!(&[0, 0, 0, 1, 0x02, 0x01, 0xAA, 0xBB][..], &out[..]);

    assert!(codec("tx-mode=MRST").h265_depacketizer().is_err());
    assert!(codec("tx-mode=SRST").h265_depacketizer().is_ok());
}

/// RFC 6184 section 8.1 and RFC 7798 section 7.1: the out-of-band parameter sets are base64
/// NAL units, comma-separated for H.264, one parameter per kind for H.265.
#[test]
fn sprop_parameter_sets_are_decoded_in_order() {
    let sets = h264("packetization-mode=1;sprop-parameter-sets=Z0LAHw==,aM48gA==")
        .sprop_parameter_sets()
        .unwrap();
    assert_eq!(
        vec![
            Bytes::from_static(&[0x67, 0x42, 0xC0, 0x1F]),
            Bytes::from_static(&[0x68, 0xCE, 0x3C, 0x80])
        ],
        sets
    );
    assert!(
        h264("packetization-mode=1")
            .sprop_parameter_sets()
            .unwrap()
            .is_empty()
    );
    assert!(
        h264("sprop-parameter-sets=***")
            .sprop_parameter_sets()
            .is_err()
    );

    let h265 = RTCRtpCodec {
        mime_type: MIME_TYPE_HEVC.to_owned(),
        clock_rate: 90000,
        channels: 0,
        sdp_fmtp_line: "sprop-pps=RAHA;sprop-vps=QAE=;sprop-sps=QgE=".to_owned(),
        rtcp_feedback: vec![],
    };
    assert_eq!(
        vec![
            Bytes::from_static(&[0x40, 0x01]),
            Bytes::from_static(&[0x42, 0x01]),
            Bytes::from_static(&[0x44, 0x01, 0xC0])
        ],
        h265.sprop_parameter_sets().unwrap(),
        "VPS, SPS, PPS"
    );
}
